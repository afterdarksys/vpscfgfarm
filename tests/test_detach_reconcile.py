"""W2: detached mutation steps survive a dropped SSH session, and
`vpsexec reconcile` is the human release valve for a retained lock.

No ssh anywhere: the "host" is a local bash run against temp directories that
stand in for /run/vpscfg-ops and /run/vpscfg.lock. Never ~/.vpscfg, never the
estate.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import detach, journal, lock, telemetry, vpsexec, vpsexecgrant  # noqa: E402
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

HOST = "fixture"


def _local(host, cmd, timeout=None, connect_timeout=None):
    r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                       timeout=timeout or 60)
    return r.returncode, r.stdout, r.stderr


_local.detached = True


def dead_pid():
    """A pid that ran and exited (reaped): kill(pid, 0) says it is gone."""
    p = subprocess.Popen(["true"])
    p.wait()
    return p.pid


class TTY:
    def isatty(self):
        return True

    def fileno(self):
        raise ValueError("not a real terminal")


class NoTTY(io.StringIO):
    def isatty(self):
        return False


def _governor(posture="frozen", mutation=True, mode="test"):
    return {"version": 1, "mode": mode, "mutation_enabled": mutation,
            "allowed_verbs": ["exec"], "scopes": {"unlocked": [], "tested": []},
            "hosts": {HOST: {"posture": posture}}, "deny_always": list(DENY_ALWAYS_FLOOR),
            "limits": {"command_timeout_sec": 120, "max_parallel_hosts": 5}}


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.saved = (detach.OPS_DIR, lock.LOCK_DIR, journal.JOURNAL_DIR,
                      telemetry.push_event, detach._sleep, detach._clock,
                      vpsexec.sshconfig.load, vpsexec.sshconfig.machines,
                      vpsexecgrant._is_controlling_tty, vpsexecgrant.flush_input)
        detach.OPS_DIR = str(root / "ops")
        lock.LOCK_DIR = str(root / "lock")
        (root / "journal").mkdir()
        journal.JOURNAL_DIR = root / "journal"
        telemetry.push_event = lambda *a, **k: False
        detach._sleep = lambda s: time.sleep(0.02)
        vpsexec.sshconfig.load = lambda *a, **k: {HOST: {}}
        vpsexec.sshconfig.machines = lambda *a, **k: {HOST: {"aliases": [HOST], "user": None}}
        self.flushed = []
        vpsexecgrant.flush_input = lambda stream: self.flushed.append(stream)
        self.go = root / "GO"
        # A lock taken here stands for one taken by a door that has since
        # died (the case reconcile exists for): its controller is a pid that
        # no longer runs. Tests of a LIVE controller set it explicitly.
        self.saved_controller = lock.controller
        dead = dead_pid()
        lock.controller = lambda: dict(self.saved_controller(), pid=dead)

    def restore_controller(self):
        lock.controller = self.saved_controller

    def tearDown(self):
        lock.controller = self.saved_controller
        self.go.touch()  # release any step still waiting
        (detach.OPS_DIR, lock.LOCK_DIR, journal.JOURNAL_DIR, telemetry.push_event,
         detach._sleep, detach._clock, vpsexec.sshconfig.load, vpsexec.sshconfig.machines,
         vpsexecgrant._is_controlling_tty, vpsexecgrant.flush_input) = self.saved
        time.sleep(0.3)
        self.tmp.cleanup()

    def events(self, name=None):
        p = Path(journal.JOURNAL_DIR) / "vpsexec.jsonl"
        recs = [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
        return [r for r in recs if name is None or r.get("event") == name]

    def run_host(self, cmd, ssh, unmanaged=True):
        """The fixture "host" is this machine, which runs no systemd: the
        governor opts it in (allow_unmanaged_steps) unless a test says not."""
        plan = vpsexec.build_plan([HOST], cmd, {}, "mutating", None)
        guard = Guard({"deny_always": list(DENY_ALWAYS_FLOOR), "hosts": {HOST: {}},
                       "allow_unmanaged_steps": [HOST] if unmanaged else []}, True)
        with contextlib.redirect_stderr(io.StringIO()):
            return vpsexec._run_one_host(HOST, plan, guard, "test", ssh, 30, False)

    def wait_for(self, path, seconds=10):
        end = time.time() + seconds
        while not Path(path).exists():
            if time.time() > end:
                self.fail("timed out waiting for %s" % path)
            time.sleep(0.05)


class Dropping:
    """Runs the launch for real and THEN loses the session (the 2026-10-12
    shape: the command reached the host, the client never heard back), then
    fails `drops` polls before letting them through."""

    detached = True

    def __init__(self, drops):
        self.drops, self.launches = drops, 0

    def __call__(self, host, cmd, timeout=None, connect_timeout=None):
        if detach.LAUNCHED in cmd:
            self.launches += 1
            _local(host, cmd, timeout)
            raise OSError("SSH connection lost; remote completion is unknown")
        if "VPSCFG-STATE" in cmd and self.drops:
            self.drops -= 1
            raise OSError("SSH connection lost")
        return _local(host, cmd, timeout)


class DetachedStepTest(_Base):
    def test_drop_mid_step_reattaches_and_reads_the_true_rc(self):
        ssh = Dropping(drops=3)
        result = self.run_host("echo hello; echo 'FAIL: driver says no' >&2; exit 3", ssh)
        self.assertEqual(ssh.launches, 1)
        self.assertEqual(result["rc"], 3)
        self.assertNotIn("unknown", result["error"] or "")
        self.assertNotIn("lock retained", result["error"] or "")
        self.assertFalse(Path(lock.LOCK_DIR).exists(), "a known outcome releases the lock")
        step = self.events("step")[-1]
        self.assertEqual(step["rc"], 3)
        self.assertIn("hello", step["stdout"])
        self.assertIn("FAIL: driver says no", step["stderr"])
        self.assertIn("FAIL: driver says no", step["detail"])
        self.assertRegex(step["operation_id"], r"^[0-9a-f]{64}$")

    def test_drop_that_never_recovers_retains_the_lock(self):
        now = [0.0]
        detach._clock = lambda: now[0]
        detach._sleep = lambda s: now.__setitem__(0, now[0] + s)
        ssh = Dropping(drops=10 ** 6)
        result = self.run_host("echo started", ssh)
        self.assertNotEqual(result["rc"], 0)
        self.assertIn("remote completion is unknown", result["error"])
        self.assertIn("lock retained", result["error"])
        self.assertIn("vpsexec reconcile %s" % HOST, result["error"])
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())
        self.assertGreaterEqual(now[0], 30, "kept trying for the whole timeout")
        step = self.events("step")[-1]
        self.assertTrue(step["uncertain"])
        self.assertIsNone(step["rc"])

    def test_step_never_launches_without_its_lock(self):
        token = lock.acquire(HOST, "op", "test", runner=_local)
        with self.assertRaises(Refused):
            detach.run(HOST, token, 1, "touch %s" % self.go, "f" * 64, _local, 10)
        time.sleep(0.2)
        self.assertFalse(self.go.exists())
        self.assertFalse(Path(detach.op_dir(token), "1.sh").exists())

    def test_stderr_captured_and_masked(self):
        result = self.run_host("echo DB_PASSWORD=hunter2 >&2; echo 'FAIL: x' >&2; "
                               "echo API_TOKEN=s3cr3tvalue; exit 1", _local)
        self.assertEqual(result["rc"], 1)
        step = self.events("step")[-1]
        # The command text itself is journaled as typed (as before W2); the
        # OUTPUT fields are what the masker must cover.
        blob = json.dumps([step["stdout"], step["stderr"], step["detail"]])
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("s3cr3tvalue", blob)
        self.assertIn("FAIL: x", step["stderr"])
        self.assertIn("<masked>", step["stderr"])
        self.assertIn("FAIL: x", step["detail"])
        self.assertIn("API_TOKEN=<masked>", step["stdout"])

    def test_garbled_poll_is_a_failed_poll_not_an_rc(self):
        for text in ("VPSCFG-STATE started running=no rc=0 out=1 err=0 how=nohup\n"
                     "VPSCFG-OUT !!\nVPSCFG-ERR \n",
                     "rc=0\n", "VPSCFG-STATE started running=no rc=0; out=0 err=0 how=x\n"):
            with self.assertRaises(detach.PollError):
                detach.parse_poll(text)

    def test_vpsrun_halt_names_the_reconcile_command(self):
        loader = importlib.machinery.SourceFileLoader("vpsrun_w2", str(REPO / "vpsrun"))
        spec = importlib.util.spec_from_loader("vpsrun_w2", loader)
        vpsrun = importlib.util.module_from_spec(spec)
        loader.exec_module(vpsrun)
        play_path = Path(self.tmp.name) / "p.yaml"
        play_path.write_text('version: 1\nreason: "w2"\nsteps:\n  - hosts: edge1\n'
                             '    cmd: "systemctl restart x"\n    why: "go"\n')

        def door(argv):
            if "--run" not in argv:
                return 0, "--approve=%s\n" % ("a" * 64)
            return 1, ("transport: SSH connection lost [BLOCKED: lock retained; reconcile "
                       "operation abc — next: vpsexec reconcile edge1]")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = vpsrun.run_play(vpsrun.load_play(play_path), door,
                                 lambda m: m.split("Type ", 1)[1].split(" ", 1)[0], TTY())
        self.assertEqual(rc, 1)
        self.assertIn("PLAY HALTED", out.getvalue())
        self.assertIn("  vpsexec reconcile edge1\n", out.getvalue())


class ReconcileTest(_Base):
    def setUp(self):
        super().setUp()
        vpsexecgrant._is_controlling_tty = lambda stream: stream.isatty()
        self.prompts = []

    def reconcile(self, answer=None, ssh=_local, stream=None, governor=None):
        def prompt(msg):
            self.prompts.append(msg)
            if callable(answer):
                return answer(msg)
            return answer if answer is not None else msg.split("Type ", 1)[1].split(" ", 1)[0]
        guard = Guard(governor or _governor(), True)
        policy = {"groups": {}, "runbooks": [], "deny_extra": [], "risky_extra": [],
                  "files": []}
        with contextlib.redirect_stdout(io.StringIO()) as out:
            try:
                rc = vpsexec.reconcile([HOST], guard, policy, ssh=ssh,
                                       stream=stream or TTY(), prompt=prompt)
            except Refused as r:
                return r, out.getvalue()
        return rc, out.getvalue()

    def locked_op(self, cmd):
        token = lock.acquire(HOST, "alice", "inventory recreate", runner=_local)
        rc, out, _ = _local(HOST, detach.launch_cmd(token, 1, cmd, token, unmanaged_ok=True))
        self.assertIn(detach.LAUNCHED, out)
        return token

    def test_completed_op_is_released_after_the_phrase(self):
        token = self.locked_op("echo container healthy; echo 'FAIL: nothing' >&2; exit 0")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        rc, out = self.reconcile()
        self.assertEqual(rc, 0, out)
        self.assertIn("VERDICT: COMPLETED rc=0", out)
        self.assertIn("container healthy", out)
        self.assertIn("FAIL: nothing", out)
        self.assertIn("RECONCILE:%s:%s" % (HOST, token[:8]), self.prompts[0])
        self.assertTrue(self.flushed, "tty input flushed before the phrase")
        self.assertFalse(Path(lock.LOCK_DIR).exists())
        done = self.events("reconciled")[-1]
        self.assertEqual(done["operation_id"], token)
        self.assertEqual(done["verdict"], "COMPLETED")
        self.assertEqual(done["rc"], 0)
        self.assertEqual(done["owner"]["operator"], "alice")
        self.assertIn("container healthy", done["steps"][0]["stdout_tail"])

    def test_wrong_phrase_keeps_the_lock(self):
        token = self.locked_op("true")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        res, _ = self.reconcile(answer="RECONCILE:%s:00000000" % HOST)
        self.assertIsInstance(res, Refused)
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())
        self.assertFalse(self.events("reconciled"))

    def test_still_running_op_is_refused_and_never_prompted(self):
        token = self.locked_op("while test ! -e %s; do sleep 0.1; done" % self.go)
        self.wait_for(Path(detach.op_dir(token), "1.pid"))
        time.sleep(0.2)
        res, out = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertIn("STILL RUNNING", str(res))
        self.assertIn("VERDICT: STILL RUNNING", out)
        self.assertEqual(self.prompts, [])
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())
        self.go.touch()
        self.wait_for(Path(detach.op_dir(token), "1.rc"))

    def test_unknown_op_needs_the_phrase_then_releases(self):
        token = lock.acquire(HOST, "alice", "x", runner=_local)
        d = Path(detach.op_dir(token))
        d.mkdir(parents=True)
        (d / "1.sh").write_text("docker compose up -d\n")  # written, never started
        rc, out = self.reconcile()
        self.assertEqual(rc, 0, out)
        self.assertIn("VERDICT: UNKNOWN", out)
        self.assertIn("NO exit file", out)
        self.assertEqual(len(self.prompts), 1)
        self.assertFalse(Path(lock.LOCK_DIR).exists())
        self.assertEqual(self.events("reconciled")[-1]["verdict"], "UNKNOWN")

    def test_lock_without_op_dir_is_unknown_and_warns(self):
        lock.acquire(HOST, "alice", "vpscfg deploy", runner=_local)
        res, out = self.reconcile(answer="no")
        self.assertIsInstance(res, Refused)
        self.assertIn("NO OP DIR", out)
        self.assertIn("VERDICT: UNKNOWN", out)
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())

    def test_owner_and_token_that_disagree_are_refused(self):
        lock.acquire(HOST, "alice", "x", runner=_local)
        Path(lock.LOCK_DIR, "token").write_text("e" * 64 + "\n")
        res, _ = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertIn("do not agree", str(res))
        self.assertEqual(self.prompts, [])
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())

    def test_never_releases_a_different_operations_lock(self):
        token = self.locked_op("true")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        swapped = {}

        def answer(msg):
            # Between reading the evidence and releasing, another operation
            # takes the host: release must leave ITS lock alone.
            self.assertTrue(lock.release(HOST, runner=_local, token=token))
            swapped["token"] = lock.acquire(HOST, "someone", "other op", runner=_local)
            return msg.split("Type ", 1)[1].split(" ", 1)[0]
        res, _ = self.reconcile(answer=answer)
        self.assertIsInstance(res, Refused)
        self.assertIn("no longer matches", str(res))
        self.assertEqual(Path(lock.LOCK_DIR, "token").read_text().strip(), swapped["token"])
        self.assertTrue(self.events("reconcile_failed"))
        self.assertFalse(self.events("reconciled"))

    def test_no_tty_refuses_before_any_host_contact(self):
        calls = []

        def ssh(host, cmd, timeout=None):
            calls.append(cmd)
            return 0, "", ""
        vpsexecgrant._is_controlling_tty = self.saved[8]  # the real check
        res, _ = self.reconcile(ssh=ssh, stream=NoTTY())
        self.assertIsInstance(res, Refused)
        self.assertIn("real terminal", str(res))
        self.assertEqual(calls, [])

    def test_master_switch_off_refuses(self):
        lock.acquire(HOST, "alice", "x", runner=_local)
        res, _ = self.reconcile(governor=_governor(mutation=False))
        self.assertIsInstance(res, Refused)
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())

    def test_free_host_has_nothing_to_reconcile(self):
        rc, out = self.reconcile()
        self.assertEqual(rc, 0)
        self.assertIn("free", out)
        self.assertEqual(self.prompts, [])


class _BytesHost:
    """The fixture host for a stdin-fed probe: `data` must be bytes (the real
    transport is binary-mode), a SqlCheck's `docker exec -i ...` answers with
    `sql_out`, `sh -s` runs the script for real (or answers `token_out`), and
    everything else is local bash."""

    detached = True

    def __init__(self, sql_out="@@@check\nVPSCFG-DONE\n", token_out=None):
        self.sql_out, self.token_out, self.stdin = sql_out, token_out, []

    def __call__(self, host, cmd, timeout=None, connect_timeout=None, data=None):
        if data is not None:
            if not isinstance(data, bytes):
                raise TypeError("the transport takes bytes on stdin, got %s"
                                % type(data).__name__)
            self.stdin.append((cmd, data))
            if cmd.startswith("docker exec -i "):
                return 0, self.sql_out.encode(), b""
            if cmd == "sh -s" and self.token_out is not None:
                return 0, self.token_out.encode(), b""
            r = subprocess.run(["bash", "-c", cmd], input=data, capture_output=True,
                               timeout=timeout or 60)
            return r.returncode, r.stdout, r.stderr
        return _local(host, cmd, timeout)


class ActionReconcileTest(_Base):
    """H2: a retained lock left by a typed action whose verify is a SqlCheck
    (ensure_owner) or a token-only check (ensure_secret) reaches a verdict and
    the RECONCILE phrase: the verify is re-expanded from the journaled
    canonical and run through the run's own gate and runner, never classified
    from the plan's heredoc text (which raised Refused and aborted
    reconcile)."""

    def setUp(self):
        super().setUp()
        vpsexecgrant._is_controlling_tty = lambda stream: stream.isatty()
        self.prompts = []

    reconcile = ReconcileTest.reconcile
    locked_op = ReconcileTest.locked_op

    def journal_op(self, token, command, verify_text):
        journal.append("vpsexec", {"event": "mutation_attempt", "hosts": [HOST],
                                   "command": command, "placement": "host",
                                   "targets": {HOST: []}, "verify": {HOST: verify_text},
                                   "tier": "risky"})
        journal.append("vpsexec", {"event": "step", "host": HOST, "operation_id": token,
                                   "idx": 1, "rc": None, "uncertain": True})

    def retained(self, exp, body="echo done; exit 0"):
        token = self.locked_op(body)
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        self.journal_op(token, exp.canonical, exp.verify_text())
        return token

    def test_the_plan_text_alone_would_have_aborted(self):
        # The regression's cause: a SqlCheck's / TokenCheck's text is a
        # heredoc the plain classifier refuses outright.
        from vpscfg import actions
        for exp in (actions.expand("ensure_owner", {"container": "pg-main", "db": "shop",
                                                    "role": "app_owner", "schema": "sales"},
                                   HOST),
                    actions.expand("ensure_secret", {"file": "/srv/shop/.env",
                                                     "key": "SESSION_SECRET"}, HOST)):
            with self.assertRaises(Refused):
                vpsexec.classify(exp.verify_text(), list(DENY_ALWAYS_FLOOR))

    def test_ensure_owner_retained_lock_reaches_a_verdict_and_releases(self):
        from vpscfg import actions
        exp = actions.expand("ensure_owner", {"container": "pg-main", "db": "shop",
                                              "role": "app_owner", "schema": "sales"}, HOST)
        token = self.retained(exp)
        host = _BytesHost()
        rc, out = self.reconcile(ssh=host)
        self.assertEqual(rc, 0, out)
        self.assertIn("SQL check in pg-main/shop (action ensure_owner@1, re-expanded) -> ok",
                      out)
        self.assertIn("VERDICT: COMPLETED rc=0", out)
        self.assertIn("RECONCILE:%s:%s" % (HOST, token[:8]), self.prompts[0])
        self.assertFalse(Path(lock.LOCK_DIR).exists())
        self.assertEqual(len(host.stdin), 1, "the SqlCheck ran once, its script on stdin")
        self.assertEqual(self.events("reconciled")[-1]["verify_rc"], 0)

    def test_ensure_owner_needed_is_reported_failed_and_still_offers_the_phrase(self):
        from vpscfg import actions
        exp = actions.expand("ensure_owner", {"container": "pg-main", "db": "shop",
                                              "role": "app_owner", "schema": "sales"}, HOST)
        self.retained(exp)
        rc, out = self.reconcile(ssh=_BytesHost(sql_out="@@@check\nVPSCFG-NEEDED\n"))
        self.assertEqual(rc, 0, out)
        self.assertIn("FAILED rc=1 VPSCFG-NEEDED", out)
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_ensure_secret_retained_lock_reaches_a_verdict_and_releases(self):
        from vpscfg import actions
        env = Path(self.tmp.name) / "shop.env"
        env.write_text("SESSION_SECRET=%s\nJWT_SECRET=%s\n" % ("a" * 48, "b" * 48))
        exp = actions.expand("ensure_secret", {"file": str(env), "key": "SESSION_SECRET",
                                               "distinct_from": ["JWT_SECRET"]}, HOST)
        token = self.retained(exp)
        host = _BytesHost()
        rc, out = self.reconcile(ssh=host)
        self.assertEqual(rc, 0, out)
        self.assertIn("token-only check ensure_secret@3 (action ensure_secret@3, re-expanded) "
                      "-> ok VPSCFG-DONE", out)
        self.assertIn("VERDICT: COMPLETED rc=0", out)
        self.assertIn("RECONCILE:%s:%s" % (HOST, token[:8]), self.prompts[0])
        self.assertFalse(Path(lock.LOCK_DIR).exists())
        self.assertEqual([c for c, _ in host.stdin], ["sh -s"])

    def test_ensure_secret_output_is_withheld_when_the_host_prints_a_value(self):
        from vpscfg import actions
        leaked = "f00dfacecafe" * 4
        exp = actions.expand("ensure_secret", {"file": "/srv/shop/.env",
                                               "key": "SESSION_SECRET"}, HOST)
        self.retained(exp)
        rc, out = self.reconcile(ssh=_BytesHost(token_out=leaked + "\nVPSCFG-DONE\n"))
        self.assertEqual(rc, 0, out)
        self.assertIn("token-only verify: output withheld", out)
        self.assertNotIn(leaked, out)
        self.assertNotIn(leaked, (Path(journal.JOURNAL_DIR) / "vpsexec.jsonl").read_text())

    def test_an_action_this_door_cannot_expand_still_reaches_the_phrase(self):
        canonical = "vpscfg-action ensure_secret@1 '{\"file\":\"/srv/shop/.env\"}'"
        token = self.locked_op("true")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        self.journal_op(token, canonical, "sh -s <<'VPSCFG'\n$(id)\nVPSCFG")
        rc, out = self.reconcile(ssh=_BytesHost())
        self.assertEqual(rc, 0, out)
        self.assertIn("cannot re-expand the action", out)
        self.assertIn("not run", out)
        self.assertIn("VERDICT: COMPLETED rc=0", out)
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_reexpand_refuses_a_canonical_that_does_not_round_trip(self):
        # The journal is a file on this machine: only a string this door's
        # own expand() reproduces byte for byte stands for an action.
        from vpscfg import actions
        exp = actions.expand("ensure_secret", {"file": "/srv/shop/.env",
                                               "key": "SESSION_SECRET"}, HOST)
        good = exp.canonical
        again = vpsexec._reexpand_action(good, HOST)
        self.assertEqual(again.canonical, good)
        self.assertEqual((again.name, again.version), (exp.name, exp.version))
        name_word, json_word = good.split(" ", 2)[1:]
        params = json.loads(json_word.strip("'"))
        reordered = json.dumps(dict(reversed(list(params.items()))), separators=(",", ":"))
        self.assertNotEqual(reordered, json_word.strip("'"))
        differs = "re-expands to a different string"
        bad = {
            "reordered JSON keys": ("vpscfg-action %s '%s'" % (name_word, reordered), differs),
            "extra whitespace": (good.replace(" '", "  '", 1), differs),
            "spaced JSON": ("vpscfg-action %s '%s'" % (name_word, json.dumps(params)), differs),
            "trailing words": (good + " --now", "not one canonical action string"),
            "wrong version": (good.replace("@3 ", "@2 ", 1), "@2 is not something it can expand"),
            "unknown param": ("vpscfg-action %s '%s'" % (
                name_word, json.dumps(dict(params, surprise=1), sort_keys=True,
                                      separators=(",", ":"))), "unknown parameter"),
            "bad JSON": ("vpscfg-action %s '{\"file\":'" % name_word, "not valid JSON"),
            "unbalanced quote": ("vpscfg-action %s '{}" % name_word, "does not parse"),
            "not an action": ("vpscfg-run %s %s" % (name_word, json_word),
                              "not one canonical action string"),
        }
        self.assertIn("@3 ", good, "the wrong-version case needs ensure_secret@3")
        for why, (canonical, fragment) in bad.items():
            with self.subTest(why=why), self.assertRaises(Refused) as cm:
                vpsexec._reexpand_action(canonical, HOST)
            self.assertIn(fragment, str(cm.exception), why)

    def test_plain_cmd_with_an_unclassifiable_verify_still_reaches_the_phrase(self):
        token = self.locked_op("true")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        self.journal_op(token, "systemctl restart shop-web", "cat <<'X'\n$(id)\nX")
        calls = []

        def ssh(host, cmd, timeout=None, connect_timeout=None):
            calls.append(cmd)
            return _local(host, cmd, timeout)
        rc, out = self.reconcile(ssh=ssh)
        self.assertEqual(rc, 0, out)
        self.assertIn("is not a plain read", out)
        self.assertIn("VERDICT: COMPLETED rc=0", out)
        self.assertFalse([c for c in calls if "$(id)" in c], "the verify never ran")
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_plain_cmd_with_a_read_verify_runs_it(self):
        token = self.locked_op("true")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        self.journal_op(token, "systemctl restart shop-web", "uname -a")
        rc, out = self.reconcile()
        self.assertEqual(rc, 0, out)
        self.assertIn("verify    : uname -a (the op's plan) -> ok", out)
        self.assertFalse(Path(lock.LOCK_DIR).exists())


class OuterDoorReconcileTest(unittest.TestCase):
    """The outer door judges reconcile as a mutation (master switch, mode,
    journal-or-refuse) but not by posture: break-glass is what took the lock."""

    def setUp(self):
        loader = importlib.machinery.SourceFileLoader("vpsexec_door_w2", str(REPO / "vpsexec"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.door = importlib.util.module_from_spec(spec)
        loader.exec_module(self.door)
        self.door.refuse = self._refuse

    @staticmethod
    def _refuse(reason, code=2):
        raise Refused(reason)

    def test_frozen_host_is_judged_a_mutation_without_break_glass(self):
        j = self.door.judge(_governor(posture="frozen"), ["reconcile", HOST])
        self.assertFalse(j["read_only"])
        self.assertEqual(j["hosts"], [HOST])
        self.assertEqual(j["introspect"], "reconcile")

    def test_master_switch_lockdown_and_shape_refuse(self):
        for gov, argv in ((_governor(mutation=False), ["reconcile", HOST]),
                          (_governor(mode="lockdown"), ["reconcile", HOST]),
                          (_governor(), ["reconcile"]),
                          (_governor(), ["reconcile", "@all"]),
                          (_governor(), ["reconcile", HOST, "--yes"])):
            with self.assertRaises(Refused):
                self.door.judge(gov, argv)


if __name__ == "__main__":
    unittest.main()
