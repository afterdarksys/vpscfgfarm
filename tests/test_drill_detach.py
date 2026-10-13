"""P4: `vpscfg drill detach <host>` — the automated scratch-host drill for the
detached-step machinery (docs/RECOVERY.md).

No ssh anywhere: the "host" is a local bash run against temp directories that
stand in for /run/vpscfg-ops and /run/vpscfg.lock, exactly like
tests/test_detach_reconcile.py. Never ~/.vpscfg, never the estate, never a
real host. Fictional names only.
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

from vpscfg import detach, drilldetach, journal, lock, telemetry, vpsexec, vpsexecgrant  # noqa: E402
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

HOST = "edge1"
FROZEN = "web1"
FROZEN_ALIAS = "web1.example.internal"
OPERATOR = "alice"


def _local(host, cmd, timeout=None):
    r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                       timeout=timeout or 60)
    return r.returncode, r.stdout, r.stderr


def dead_pid():
    """A pid that ran and exited (reaped): kill(pid, 0) says it is gone."""
    p = subprocess.Popen(["true"])
    p.wait()
    return p.pid


class _FakeTTY:
    def isatty(self):
        return True

    def fileno(self):
        raise ValueError("not a real terminal")


class _CountingRunner:
    """Stands in for a transport whose dial count the refusal tests assert
    stays at zero."""

    def __init__(self, inner=None):
        self.calls = 0
        self.inner = inner

    def __call__(self, host, cmd, timeout=None):
        self.calls += 1
        if self.inner:
            return self.inner(host, cmd, timeout=timeout)
        return 0, "", ""


def _governor(**over):
    base = {
        "version": 1, "mode": "test", "mutation_enabled": True,
        "allowed_verbs": ["drill"],
        "scopes": {"unlocked": []},
        "hosts": {HOST: {"posture": "test"}},
        "drill_hosts": [HOST],
        "allow_unmanaged_steps": [HOST],
        "deny_always": list(DENY_ALWAYS_FLOOR),
    }
    base.update(over)
    return base


def _human_prompt(log):
    def prompt(msg):
        log.append(msg)
        return msg.split("Type ", 1)[1].split(" ", 1)[0]
    return prompt


# ---------------------------------------------------------------------------
# adversarial item 11: every disallowed case refuses before any dial
# ---------------------------------------------------------------------------

class AuthorizeRefusalTest(unittest.TestCase):
    def _refused_no_dial(self, policy, host=HOST):
        guard = Guard(policy, True)
        counter = _CountingRunner()
        with self.assertRaises(Refused):
            drilldetach.cli(guard, ["detach", host, "--run", "--reason", "x"],
                            runner=counter)
        self.assertEqual(counter.calls, 0)

    def test_frozen_host_refused(self):
        self._refused_no_dial(_governor(hosts={HOST: {"posture": "frozen"}}))

    def test_lockdown_host_refused(self):
        self._refused_no_dial(_governor(hosts={HOST: {"posture": "lockdown"}}))

    def test_released_host_refused(self):
        self._refused_no_dial(_governor(hosts={HOST: {"posture": "released"}}))

    def test_test_host_absent_from_drill_hosts_refused(self):
        self._refused_no_dial(_governor(drill_hosts=[]))

    def test_missing_drill_hosts_key_refused(self):
        policy = _governor()
        del policy["drill_hosts"]
        self._refused_no_dial(policy)

    def test_drill_hosts_wrong_type_refused(self):
        self._refused_no_dial(_governor(drill_hosts=HOST))

    def test_drill_hosts_with_non_string_entries_refused(self):
        self._refused_no_dial(_governor(drill_hosts=[HOST, 1]))

    def test_alias_of_frozen_host_refused(self):
        policy = _governor(
            hosts={FROZEN: {"posture": "frozen"},
                  FROZEN_ALIAS: {"posture": "frozen", "alias_of": FROZEN}},
            drill_hosts=[FROZEN])
        self._refused_no_dial(policy, host=FROZEN_ALIAS)

    def test_unknown_host_refused(self):
        self._refused_no_dial(_governor(), host="nope")

    def test_lockdown_mode_refused(self):
        self._refused_no_dial(_governor(mode="lockdown"))

    def test_master_switch_off_refused(self):
        self._refused_no_dial(_governor(mutation_enabled=False))

    def test_verb_not_released_refused(self):
        self._refused_no_dial(_governor(allowed_verbs=[]))

    def test_test_posture_and_listed_authorizes(self):
        guard = Guard(_governor(), True)
        self.assertEqual(drilldetach._authorize(guard, HOST), HOST)

    def test_alias_resolves_to_canonical_before_the_check(self):
        policy = _governor(
            hosts={HOST: {"posture": "test"},
                  "edge1-alt": {"posture": "test", "alias_of": HOST}},
            drill_hosts=[HOST])
        guard = Guard(policy, True)
        self.assertEqual(drilldetach._authorize(guard, "edge1-alt"), HOST)


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------

class CliTest(unittest.TestCase):
    def test_plan_mode_prints_scenarios_and_never_dials(self):
        guard = Guard(_governor(), True)
        counter = _CountingRunner()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = drilldetach.cli(guard, ["detach", HOST], runner=counter)
        self.assertEqual(rc, 0)
        self.assertEqual(counter.calls, 0)
        for name, _desc in drilldetach.SCENARIOS:
            self.assertIn(name, out.getvalue())

    def test_bad_subcommand_refused(self):
        guard = Guard(_governor(), True)
        with self.assertRaises(Refused):
            drilldetach.cli(guard, ["restore", HOST])

    def test_run_without_reason_refused(self):
        guard = Guard(_governor(), True)
        with self.assertRaises(Refused):
            drilldetach.cli(guard, ["detach", HOST, "--run"], runner=_local)

    def test_unverified_run_refused(self):
        guard = Guard(_governor(), False)
        with self.assertRaises(Refused):
            drilldetach.cli(guard, ["detach", HOST, "--run", "--reason", "x"],
                            runner=_local)

    def test_unknown_flag_refused(self):
        guard = Guard(_governor(), True)
        with self.assertRaises(Refused):
            drilldetach.cli(guard, ["detach", HOST, "--bogus"])


# ---------------------------------------------------------------------------
# safety: the generated vocabulary, and the fact this module never builds a
# reconcile/stop phrase itself
# ---------------------------------------------------------------------------

class SafetyTest(unittest.TestCase):
    def test_assert_safe_step_accepts_generated_bodies(self):
        drilldetach._assert_safe_step("true && touch /tmp/vpscfg-drill-abc123/x")
        drilldetach._assert_safe_step(
            "while test ! -e /tmp/vpscfg-drill-abc123/x ; do sleep 0.1 ; done")
        drilldetach._assert_safe_step(
            "( while test ! -e /tmp/vpscfg-drill-abc123/x ; do sleep 0.1 ; done ) & true")

    def test_assert_safe_step_refuses_anything_else(self):
        for bad in ("rm -rf /", "docker compose down -v", "curl http://evil",
                   "true; cat /etc/passwd", "sleep 1 && echo hi",
                   "touch /tmp/not-a-drill-dir/x", ""):
            with self.assertRaises(Refused):
                drilldetach._assert_safe_step(bad)


class SourceHygieneTest(unittest.TestCase):
    def test_never_constructs_a_reconcile_or_stop_phrase(self):
        """The module reads the two phrases vpsexec.reconcile already prints
        (a plain substring check, to count prompts in a scenario's own
        evidence) but never BUILDS either phrase — only vpsexec.reconcile
        does that, with its own %-template. This greps for that template
        shape, not for the substring itself (drilldetach.py legitimately
        contains plain "RECONCILE:"/"STOP:" substring checks)."""
        source = Path(drilldetach.__file__).read_text()
        self.assertNotIn('"RECONCILE:%', source)
        self.assertNotIn('"STOP:%', source)
        self.assertNotIn(".stdin.write", source)
        self.assertNotIn("sys.stdin", source)


# ---------------------------------------------------------------------------
# scenarios, against the fake (local) host
# ---------------------------------------------------------------------------

class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.saved = (detach.OPS_DIR, lock.LOCK_DIR, journal.JOURNAL_DIR,
                      telemetry.push_event, detach._sleep,
                      vpsexec.sshconfig.load, vpsexec.sshconfig.machines,
                      vpsexecgrant._is_controlling_tty, vpsexecgrant.flush_input)
        detach.OPS_DIR = str(root / "ops")
        lock.LOCK_DIR = str(root / "lock")
        (root / "journal").mkdir()
        journal.JOURNAL_DIR = root / "journal"
        telemetry.push_event = lambda *a, **k: False
        # Real elapsed time still governs timeouts/LOG_GRACE (detach._clock is
        # untouched); only the BACKOFF between polls is capped, so a 30s step
        # cap costs no real seconds when the step finishes quickly.
        detach._sleep = lambda s: time.sleep(min(s, 0.05))
        vpsexec.sshconfig.load = lambda *a, **k: {HOST: {}}
        vpsexec.sshconfig.machines = lambda *a, **k: {HOST: {"aliases": [HOST], "user": None}}
        vpsexecgrant._is_controlling_tty = lambda stream: stream.isatty()
        self.flushed = []
        vpsexecgrant.flush_input = lambda stream: self.flushed.append(stream)
        self.saved_controller = lock.controller
        dead = dead_pid()
        lock.controller = lambda: dict(self.saved_controller(), pid=dead)
        self.guard = Guard(_governor(), True)

    def tearDown(self):
        lock.controller = self.saved_controller
        (detach.OPS_DIR, lock.LOCK_DIR, journal.JOURNAL_DIR, telemetry.push_event,
         detach._sleep, vpsexec.sshconfig.load, vpsexec.sshconfig.machines,
         vpsexecgrant._is_controlling_tty, vpsexecgrant.flush_input) = self.saved
        time.sleep(0.2)
        self.tmp.cleanup()

    def events(self, name=None):
        p = Path(journal.JOURNAL_DIR) / "drill.jsonl"
        recs = [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
        return [r for r in recs if name is None or r.get("event") == name]

    def scratch(self):
        return drilldetach._make_scratch(HOST, _local)


class ScenarioTest(_Base):
    def test_normal(self):
        out = drilldetach._scenario_normal(HOST, self.guard, _local, self.scratch(),
                                           OPERATOR, "drill test", True)
        self.assertTrue(out["ok"], out)
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_slow_start_needs_more_than_one_poll(self):
        out = drilldetach._scenario_slow_start(HOST, self.guard, _local, self.scratch(),
                                               OPERATOR, "drill test", True)
        self.assertTrue(out["ok"], out)
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_failing_releases_the_lock(self):
        out = drilldetach._scenario_failing(HOST, self.guard, _local, self.scratch(),
                                            OPERATOR, "drill test", True)
        self.assertTrue(out["ok"], out)
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_lost_ssh_reattaches_and_reads_the_real_rc(self):
        out = drilldetach._scenario_lost_ssh(HOST, self.guard, _local, self.scratch(),
                                             OPERATOR, "drill test", True)
        self.assertTrue(out["ok"], out)
        self.assertIn("killed=True", out["detail"])
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_timeout_then_rc_143(self):
        out = drilldetach._scenario_timeout(HOST, self.guard, _local, self.scratch(),
                                            OPERATOR, "drill test", True)
        self.assertTrue(out["ok"], out)
        self.assertIn("rc=143", out["detail"])
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_competing_operation_refused(self):
        out = drilldetach._scenario_competing(HOST, self.guard, _local, self.scratch(),
                                              OPERATOR, "drill test", True)
        self.assertTrue(out["ok"], out)
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_reconcile_still_running_then_completed(self):
        prompts = []
        out = drilldetach._scenario_reconcile_running_then_completed(
            HOST, self.guard, _local, self.scratch(), OPERATOR, "drill test", True,
            prompt=_human_prompt(prompts), stream=_FakeTTY())
        self.assertTrue(out["ok"], out)
        self.assertEqual(len(prompts), 1, prompts)
        self.assertIn("RECONCILE:", prompts[0])
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_reconcile_still_running_never_prompts_before_it_ends(self):
        # The evidence this scenario is built on: the FIRST reconcile call,
        # against a step that is still running, must refuse before ever
        # calling prompt (vpsexec.reconcile's own, pre-existing guarantee).
        prompts = []
        drilldetach._scenario_reconcile_running_then_completed(
            HOST, self.guard, _local, self.scratch(), OPERATOR, "drill test", True,
            prompt=_human_prompt(prompts), stream=_FakeTTY())
        # Exactly one prompt total (the COMPLETED call) proves the STILL
        # RUNNING call made zero.
        self.assertEqual(len(prompts), 1)

    def test_reconcile_stop(self):
        prompts = []
        out = drilldetach._scenario_reconcile_stop(
            HOST, self.guard, _local, self.scratch(), OPERATOR, "drill test", True,
            prompt=_human_prompt(prompts), stream=_FakeTTY())
        self.assertTrue(out["ok"], out)
        self.assertEqual(len(prompts), 2, prompts)
        self.assertTrue(any("STOP:" in p for p in prompts))
        self.assertTrue(any("RECONCILE:" in p for p in prompts))
        self.assertFalse(Path(lock.LOCK_DIR).exists())


class UnknownOutcomeRetainsTheLockTest(_Base):
    """L5: when detach.run raises on an unknown outcome, the scenario's
    finally must NOT release its lock — it stays for `vpsexec reconcile`."""

    def _raising(self, exc):
        real = detach.run

        def run(*a, **k):
            raise exc
        detach.run = run
        self.addCleanup(setattr, detach, "run", real)

    def test_every_detach_scenario_retains_the_lock_on_an_unknown_outcome(self):
        for fn in (drilldetach._scenario_normal, drilldetach._scenario_slow_start,
                   drilldetach._scenario_failing, drilldetach._scenario_lost_ssh):
            for exc in (detach.DetachUnknown("SSH connection lost; remote completion is "
                                             "unknown"),
                        OSError("transport lost"), Refused("lock vanished mid-step")):
                with self.subTest(fn=fn.__name__, exc=type(exc).__name__):
                    self._raising(exc)
                    with contextlib.redirect_stderr(io.StringIO()) as err:
                        with self.assertRaises(type(exc)):
                            fn(HOST, self.guard, _local, self.scratch(), OPERATOR,
                               "drill test", True)
                    self.assertTrue(Path(lock.LOCK_DIR, "token").exists(),
                                    "%s released on an unknown outcome" % fn.__name__)
                    self.assertIn("RETAINED", err.getvalue())
                    self.assertIn("vpsexec reconcile %s" % HOST, err.getvalue())
                    # settle it by hand, as reconcile would, for the next case
                    self.assertTrue(lock.release(HOST, runner=_local, token=Path(
                        lock.LOCK_DIR, "token").read_text().strip()))

    def test_timeout_retains_the_lock_when_the_step_never_settles(self):
        real_stop = detach.stop_cmd
        detach.stop_cmd = lambda token: "true"  # the TERM never lands
        self.addCleanup(setattr, detach, "stop_cmd", real_stop)
        scratch = self.scratch()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            out = drilldetach._scenario_timeout(HOST, self.guard, _local, scratch,
                                                OPERATOR, "drill test", True)
        self.assertFalse(out["ok"], out)
        self.assertIn("running=True", out["detail"])
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists(), "retained while running")
        self.assertIn("RETAINED", err.getvalue())
        # the step is really still waiting: end it, then settle by hand
        Path(scratch, "timeout.release").touch()
        token = Path(lock.LOCK_DIR, "token").read_text().strip()
        deadline = time.monotonic() + 10
        while detach.poll(HOST, token, 1, _local)["running"] and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertTrue(lock.release(HOST, runner=_local, token=token))


class StartJournaledFirstTest(_Base):
    def test_drill_detach_start_is_journaled_before_any_host_contact(self):
        seen = []

        def runner(host, cmd, timeout=None):
            if not seen:
                seen.append([e["event"] for e in self.events()])
            return _local(host, cmd, timeout=timeout)
        original = list(drilldetach._SCENARIO_FNS)
        drilldetach._SCENARIO_FNS[:] = []
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                drilldetach.execute(self.guard, HOST, HOST, "start first", runner=runner,
                                    prompt=_human_prompt([]), stream=_FakeTTY())
        finally:
            drilldetach._SCENARIO_FNS[:] = original
        self.assertEqual(seen[0], ["drill_detach_start"])
        start = self.events("drill_detach_start")[0]
        self.assertEqual((start["host"], start["reason"]), (HOST, "start first"))
        self.assertEqual(len(start["scenarios"]), 8)

    def test_an_unjournalable_start_contacts_nothing(self):
        counter = _CountingRunner(_local)
        real = journal.append

        def broken(stream, entry):
            raise OSError("journal has an incomplete tail")
        journal.append = broken
        try:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                rc = drilldetach.execute(self.guard, HOST, HOST, "x", runner=counter,
                                         prompt=_human_prompt([]), stream=_FakeTTY())
        finally:
            journal.append = real
        self.assertEqual(rc, 1)
        self.assertEqual(counter.calls, 0)
        self.assertIn("start was not journaled", err.getvalue())


class ExecuteEndToEndTest(_Base):
    def test_full_happy_path_all_scenarios_pass(self):
        prompts = []
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = drilldetach.execute(self.guard, HOST, HOST, "e2e drill",
                                     runner=_local, prompt=_human_prompt(prompts),
                                     stream=_FakeTTY())
        self.assertEqual(rc, 0, out.getvalue())
        receipt = self.events("drill_detach_receipt")[-1]
        self.assertTrue(receipt["verified"], receipt)
        self.assertEqual(len(receipt["scenarios"]), 8)
        for s in receipt["scenarios"]:
            self.assertTrue(s["ok"], s)
        self.assertEqual(len(self.events("drill_detach_scenario")), 8)
        self.assertFalse(Path(lock.LOCK_DIR).exists())
        # One RECONCILE phrase (scenario 7) plus one STOP and one RECONCILE
        # phrase (scenario 8) — never typed by this module itself.
        self.assertEqual(len(prompts), 3)

    def test_mismatch_exits_nonzero_and_marks_the_receipt(self):
        original = drilldetach._SCENARIO_FNS[0]

        def sabotaged(*a, **k):
            out = original(*a, **k)
            out = dict(out, ok=False)
            return out

        drilldetach._SCENARIO_FNS[0] = sabotaged
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = drilldetach.execute(
                    self.guard, HOST, HOST, "e2e drill", runner=_local,
                    prompt=_human_prompt([]), stream=_FakeTTY())
        finally:
            drilldetach._SCENARIO_FNS[0] = original
        self.assertEqual(rc, 1)
        receipt = self.events("drill_detach_receipt")[-1]
        self.assertFalse(receipt["verified"])
        self.assertFalse(Path(lock.LOCK_DIR).exists())


# ---------------------------------------------------------------------------
# adversarial item 12: public hygiene
# ---------------------------------------------------------------------------

class ExporterScanTest(unittest.TestCase):
    """tools/public-denylist.txt is estate-specific and deliberately NOT
    committed to this repo (committing the list of real names to scrub would
    itself leak them, so this file names none either). This runs the REAL
    scan_text() from tools/export-public.py with a FICTIONAL term list, first
    proving the scan bites on a planted line, then over the files this
    workstream touched (adversarial item 12). With VPSCFG_PUBLIC_DENYLIST set
    to the path of the real list, a second test scans the same files with it
    (skipped when unset, as in CI)."""

    DENYLIST = ["examplecorp-estate", "web1.examplecorp.net", "shop-prod.example.net"]
    # Every file phase 2 (typed actions, P0-P4) added or changed. This file is
    # scanned only by the real-denylist test: it names the fictional terms.
    FILES = (
        "docs/ACTIONS.md", "docs/INDEX.md", "docs/README.md", "docs/RECOVERY.md",
        "docs/VPSEXEC.md", "plays/README.md", "tools/public-allowlist.txt", "vpsrun",
        "vpscfg/actions/__init__.py", "vpscfg/actions/base.py",
        "vpscfg/actions/container.py", "vpscfg/actions/db.py", "vpscfg/actions/expand.py",
        "vpscfg/actions/file.py", "vpscfg/actions/secret.py", "vpscfg/actions/types.py",
        "vpscfg/cli.py", "vpscfg/drilldetach.py", "vpscfg/hostindex.py",
        "vpscfg/indexstore.py", "vpscfg/releasenew.py", "vpscfg/runbookcheck.py",
        "vpscfg/vpsexec.py", "vpscfg/vpsexecpolicy.py",
        "tests/test_action_grants.py", "tests/test_actions_container.py",
        "tests/test_actions_core.py", "tests/test_actions_db.py",
        "tests/test_actions_secret.py", "tests/test_detach_reconcile.py",
        "tests/test_hostindex.py", "tests/test_iacgate.py", "tests/test_policy_remote.py",
        "tests/test_preflight_index.py", "tests/test_release_e2e.py",
        "tests/test_release_new.py", "tests/test_runbookcheck.py",
        "tests/test_token_check.py", "tests/test_vpsrun_actions.py",
    ) + tuple(sorted(str(p.relative_to(REPO))  # the golden files, whatever their versions
                     for p in (REPO / "tests" / "golden" / "actions").glob("*.json")))
    SELF = "tests/test_drill_detach.py"

    def setUp(self):
        loader = importlib.machinery.SourceFileLoader(
            "export_public_drill_detach_test", str(REPO / "tools" / "export-public.py"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.exporter = importlib.util.module_from_spec(spec)
        loader.exec_module(self.exporter)
        self.terms = [t.lower() for t in self.DENYLIST]

    def _denylist_hits(self, path, terms=None):
        text = path.read_text()
        # The repo-relative path, as the exporter sees it (never this
        # checkout's absolute location, which is not part of the export).
        return [h for h in self.exporter.scan_text(str(path.relative_to(REPO)), text,
                                                   self.terms if terms is None else terms)
                if h[1] == "denylist"]

    def test_the_scan_bites_on_a_planted_term(self):
        hits = self.exporter.scan_text("docs/x.md", "ssh web1.ExampleCorp.net\n", self.terms)
        self.assertEqual([h[1:3] for h in hits], [("denylist", "web1.examplecorp.net")])

    def test_new_and_changed_files_pass_the_denylist_scan(self):
        for rel in self.FILES:
            hits = self._denylist_hits(REPO / rel)
            self.assertEqual(hits, [], "denylist hit in %s: %r" % (rel, hits))

    def test_new_and_changed_files_pass_the_full_scan(self):
        # Every pattern the exporter applies (IPs, e-mail, tokens, secret
        # assignments, private keys), not only the denylist.
        for rel in self.FILES + (self.SELF,):
            path = REPO / rel
            hits = self.exporter.scan_text(rel, path.read_text(), [])
            self.assertEqual(hits, [], "exporter hit in %s: %r" % (rel, hits))

    def test_the_real_denylist_when_given(self):
        path = os.environ.get("VPSCFG_PUBLIC_DENYLIST")
        if not path:
            self.skipTest("VPSCFG_PUBLIC_DENYLIST is not set (the estate list is not in "
                          "this repo)")
        terms = self.exporter.load_terms(path)
        self.assertTrue(terms, "the denylist at VPSCFG_PUBLIC_DENYLIST is empty")
        for rel in self.FILES + (self.SELF,):
            hits = self._denylist_hits(REPO / rel, terms)
            # Never print the matched term: it is the thing being kept private.
            self.assertEqual(len(hits), 0, "%d denylist hit(s) in %s" % (len(hits), rel))


if __name__ == "__main__":
    unittest.main()
