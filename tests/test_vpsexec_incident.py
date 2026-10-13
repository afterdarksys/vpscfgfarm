"""Incident override (`vpsexec incident`, `--incident`).

Hermetic: the harness is the grant tests' (ssh, docker ps, ~/.ssh/config, the
journal, telemetry, the grant directory and key are all injected or
redirected into temporary directories). Nothing here reaches a fleet host.

Each hard limit has its own test class:
  HumanOnlyTest      only a human at a TTY opens, closes or uses one
  FloorTest          the deny-always floor (and deny_extra, the map, the
                     governor) cannot be reached through an incident
  ScopeTest          never a host it does not list; never after expiry/close
  ForgeryTest        a tampered or forged incident file refuses
"""
import contextlib
import datetime
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402  (modules, not names: no re-collection)
import test_vpsexec_grant as tg  # noqa: E402
from vpscfg import journal, vpsexec, vpsexecgrant, vpsexecincident  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CMD = "systemctl restart redis"   # risky, and in no runbook
HOSTS_CFG = tv._policy()["hosts"]


def _go(msg):
    """Type exactly the phrase the prompt names (GO:<host> / GO:<plan[:6]>)."""
    return msg.split("Type ", 1)[1].split(" ", 1)[0]


def _utc(**delta):
    return (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(**delta)).replace(microsecond=0)


class _IncidentHarness(tg._GrantHarness):

    def open(self, hosts="web1", ttl="1h", reason="OUTAGE-7 checkout down",
             stream=None, prompt=None, now=None):
        phrase = "INCIDENT:%s:%s" % (",".join(vpsexecincident.parse_hosts(
            hosts, HOSTS_CFG)), ttl)
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecincident.cli(["open", "--hosts", hosts, "--ttl", ttl,
                                 "--reason", reason], HOSTS_CFG,
                                stream=stream or tg._TTY(), now=now,
                                prompt=prompt or (lambda m: phrase))
        return self.incident_ids()[-1]

    def open_at(self, now, hosts=("web1",), ttl="1h"):
        fields = vpsexecincident.fields_for(list(hosts), ttl, "past outage", now=now)
        with contextlib.redirect_stdout(io.StringIO()):
            _, inc = vpsexecincident.mint(fields)
        return inc["incident_id"]

    def incident_ids(self):
        if not self.grant_dir.exists():
            return []
        return sorted((p.name for p in self.grant_dir.iterdir()
                       if vpsexecincident.ID_RE.match(p.name)),
                      key=lambda n: os.path.getmtime(self.grant_dir / n))

    def run_cmd(self, hosts, iid, cmd=CMD, prompt=None, stream=None, extra=(),
                gov=None, mapdoc=None, run=True, break_glass=True):
        argv = [hosts, cmd]
        if break_glass:
            argv.append("--break-glass")
        if iid is not None:
            argv += ["--incident", iid]
        argv += ["--reason", "OUTAGE-7 restart"] + (["--run"] if run else [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexec.dispatch(
                argv + list(extra), guard=tv._guard(gov), prober=self.prober(),
                policy=self.policy, ssh=self.fake_ssh(), stream=stream or tg._TTY(),
                prompt=prompt or _go,
                blackout_runner=self.blackout_runner(unavailable=True), mapdoc=mapdoc)
        return rc, out.getvalue()

    def refused(self, *a, needle="", **kw):
        with self.assertRaises(Refused) as cm:
            self.run_cmd(*a, **kw)
        self.assertIn(needle, str(cm.exception))
        self.assertEqual(self.ran(), [], "a refused incident command reached a host")
        self.assertFalse(self.of("incident_command"))
        return str(cm.exception)

    def of(self, event):
        return [e for e in self.events() if e.get("event") == event]

    def close(self, iid, stream=None, prompt=None, now=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexecincident.cli(["close", iid], HOSTS_CFG, stream=stream or tg._TTY(),
                                prompt=prompt or (lambda m: "CLOSE:%s" % iid[:11]),
                                now=now)
        return out.getvalue()

    def ran(self):
        return [(h, c) for h, c in self.ssh_calls if "systemctl" in c]


# ===========================================================================
# opening
# ===========================================================================

class OpenTest(_IncidentHarness):

    def test_open_writes_private_signed_file_and_journals(self):
        iid = self.open("web1,dns1", ttl="30m")
        path = self.grant_dir / iid
        self.assertRegex(iid, r"^ic_[0-9a-f]{32}$")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.grant_dir).st_mode & 0o777, 0o700)
        inc = json.loads(path.read_text())
        self.assertEqual(set(inc), vpsexecincident.TOP_KEYS)
        self.assertEqual(inc["hosts"], ["web1", "dns1"])
        self.assertEqual(inc["ttl"], "30m")
        opened = self.of("incident_opened")
        self.assertEqual([e["incident"] for e in opened], [iid])
        # A grant listing never mistakes an incident for a grant.
        self.assertEqual(list(self.grant_dir.glob("*.json")), [])

    def test_ttl_is_capped_at_four_hours(self):
        for ttl in ("6h", "24h", "5h", "90m", "4h1m", ""):
            with self.subTest(ttl=ttl):
                with self.assertRaises(Refused):
                    self.open(ttl=ttl)
        self.assertEqual(self.incident_ids(), [])
        self.open(ttl="4h")
        self.assertEqual(len(self.incident_ids()), 1)

    def test_hosts_must_be_named_explicitly(self):
        for spec in ("@web", "@all", "all", "ALL", "web*", "*", "web[1]", "web?",
                     "web1,@dns", "", ",", "nosuchhost", "web1;id"):
            with self.subTest(spec=spec):
                with self.assertRaises(Refused):
                    self.open(spec, prompt=lambda m: self.fail("prompted"))
        self.assertEqual(self.incident_ids(), [])
        self.assertFalse(self.of("incident_opened"))

    def test_reason_is_required_and_one_line(self):
        for reason in ("", "   ", "two\nlines", "x" * 501):
            with self.subTest(reason=reason[:10]):
                with self.assertRaises(Refused):
                    self.open(reason=reason)
        self.assertEqual(self.incident_ids(), [])


# ===========================================================================
# hard limit: only a human at a TTY opens, closes, extends or uses one
# ===========================================================================

_PIPE_CHILD = r"""
import json, sys
sys.path.insert(0, %r)
from pathlib import Path
from vpscfg import journal, telemetry, vpsexecgrant, vpsexecincident
from vpscfg.gates import Refused
tmp = Path(sys.argv[1])
vpsexecgrant.GRANT_DIR = tmp / "grants"
vpsexecgrant.KEY_PATH = tmp / "grant.key"
journal.JOURNAL_DIR = tmp / "journal"
telemetry.push_event = lambda *a, **k: False
hosts = {"web1": {"posture": "frozen"}}
results = []
try:  # an agent can type the phrase; it cannot be the controlling terminal
    vpsexecincident.cli(["open", "--hosts", "web1", "--ttl", "1h", "--reason", "x"],
                        hosts, stream=sys.stdin, prompt=lambda m: "INCIDENT:web1:1h")
    results.append("OPENED")
except Refused:
    results.append("REFUSED")
try:
    inc = {"incident_id": "ic_" + "0" * 32, "expires_at": "2999-01-01T00:00:00Z",
           "hosts": ["web1"]}
    vpsexecincident.approve(inc, sys.stdin, prompt=lambda m: "GO")
    results.append("APPROVED")
except Refused:
    results.append("REFUSED")
print("RESULT:" + ",".join(results))
print("FILES:" + str(sorted(p.name for p in (tmp / "grants").glob("*"))
                     if (tmp / "grants").exists() else "FILES:none"))
sys.stdout.flush()
""" % str(REPO)


class HumanOnlyTest(_IncidentHarness):

    def test_open_without_a_tty_refuses_and_writes_nothing(self):
        with self.assertRaises(Refused) as cm:
            self.open(stream=tg._NoTTY(), prompt=lambda m: self.fail("prompted"))
        self.assertIn("real terminal", str(cm.exception))
        self.assertFalse(self.grant_dir.exists())
        self.assertFalse(self.key_path.exists())
        self.assertFalse(self.of("incident_opened"))

    def test_open_with_the_wrong_phrase_refuses(self):
        for typed in ("INCIDENT:web1:4h", "INCIDENT:web1", "yes", "GO", ""):
            with self.subTest(typed=typed):
                with self.assertRaises(Refused):
                    self.open(prompt=lambda m: typed)
        self.assertEqual(self.incident_ids(), [])

    def test_real_pipe_cannot_open_or_approve(self):
        """No fake stream: the real controlling-terminal check, from a process
        whose stdin is a pipe — exactly what an agent or cron job has."""
        with tempfile.TemporaryDirectory() as tmp:
            out = subprocess.run([sys.executable, "-c", _PIPE_CHILD, tmp], input="",
                                 capture_output=True, text=True, timeout=30)
        self.assertIn("RESULT:REFUSED,REFUSED", out.stdout, out.stderr)
        self.assertNotIn("ic_", out.stdout)

    def test_use_without_a_tty_refuses_before_running(self):
        iid = self.open()
        self.refused("web1", iid, stream=tg._NoTTY(), prompt=lambda m: self.fail("p"),
                     needle="real terminal")

    def test_approve_and_contract_are_refused_with_incident(self):
        iid = self.open()
        self.refused("web1", iid, extra=("--approve=" + "0" * 64,), needle="typed GO")
        self.refused("web1", iid, extra=("--approval-contract=/nonexistent",),
                     needle="typed GO")

    def test_wrong_go_aborts(self):
        iid = self.open()
        # M8: a bare GO no longer approves; the phrase names the target.
        for typed in ("GO", "go", "GO:dns1", "yes", "BREAK-GLASS:1", "web1", ""):
            with self.subTest(typed=typed):
                self.refused("web1", iid, prompt=lambda m: typed, needle="did not match")

    def test_close_needs_a_tty_and_the_phrase(self):
        iid = self.open()
        with self.assertRaises(Refused):
            self.close(iid, stream=tg._NoTTY(), prompt=lambda m: self.fail("prompted"))
        with self.assertRaises(Refused):
            self.close(iid, prompt=lambda m: "CLOSE")
        self.assertFalse(self.of("incident_closed"))
        # Still open: the refused closes changed nothing.
        rc, _ = self.run_cmd("web1", iid)
        self.assertEqual(rc, 0)

    def test_no_extend_verb(self):
        iid = self.open()
        with self.assertRaises(Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexecincident.cli(["extend", iid, "--ttl", "4h"], HOSTS_CFG,
                                    stream=tg._TTY(), prompt=lambda m: "GO")

    def test_outer_door_judges_incident_verbs_as_local(self):
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader("vpsexec_door", str(REPO / "vpsexec"))
        spec = importlib.util.spec_from_loader("vpsexec_door", loader)
        door = importlib.util.module_from_spec(spec)
        loader.exec_module(door)
        gov = tv._policy()
        judged = door.judge(gov, ["incident", "open", "--hosts", "web1", "--ttl", "1h"])
        self.assertEqual((judged["hosts"], judged["read_only"], judged["introspect"]),
                         ([], True, "incident"))
        # A command run under an incident is a mutation at this door, and a
        # frozen host still needs --break-glass here.
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                door.judge(gov, ["web1", CMD, "--incident", "ic_" + "0" * 32, "--run"])
        self.assertIn("incident", vpsexec.RESERVED_VERBS)


# ===========================================================================
# what an incident lifts, and what it does not
# ===========================================================================

class UseTest(_IncidentHarness):

    def test_without_incident_the_same_command_refuses(self):
        self.refused("web1", None, needle="not authorised")

    def test_frozen_host_runs_without_a_runbook(self):
        iid = self.open("web1,dns1")
        rc, out = self.run_cmd("web1,dns1", iid)
        self.assertEqual(rc, 0)
        self.assertEqual(self.ran(), [("web1", CMD), ("dns1", CMD)])
        self.assertIn("INCIDENT %s OPEN" % iid, out)
        self.assertGreaterEqual(out.count("INCIDENT %s OPEN" % iid), 2,
                                "banner on the plan and on the result")
        cmds = self.of("incident_command")
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0]["incident"], iid)
        self.assertEqual(cmds[0]["hosts"], ["web1", "dns1"])
        self.assertEqual(cmds[0]["elevated"], ["dns1", "web1"])
        attempt = self.of("mutation_attempt")[0]
        self.assertEqual(attempt["approval"], "incident:%s" % iid)
        self.assertEqual(attempt["incident"], iid)
        self.assertEqual(self.of("mutation_complete")[0]["incident"], iid)
        self.assertEqual(self.of("break_glass")[0]["incident"], iid)

    def test_plan_only_prompts_nothing_runs_nothing(self):
        iid = self.open()
        rc, out = self.run_cmd("web1", iid, run=False,
                               prompt=lambda m: self.fail("prompted"))
        self.assertEqual(rc, 0)
        self.assertIn("INCIDENT: %s" % iid, out)
        self.assertIn("Plan only", out)
        self.assertEqual(self.ran(), [])

    def test_plan_hash_binds_the_incident(self):
        plan = {"hosts": ["web1"], "command": CMD, "placement": "host",
                "per_host": {"web1": {"targets": []}}, "tier": "risky",
                "break_glass": True, "override_sha256": None}
        bare = vpsexec.plan_hash(plan)
        a = vpsexec.plan_hash(dict(plan, incident="ic_" + "a" * 32))
        b = vpsexec.plan_hash(dict(plan, incident="ic_" + "b" * 32))
        self.assertEqual(len({bare, a, b}), 3)

    def test_frozen_host_still_needs_break_glass_flag(self):
        iid = self.open()
        self.refused("web1", iid, break_glass=False, needle="refuse mutations by posture")

    def test_reason_still_required(self):
        iid = self.open()
        with self.assertRaises(Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(["web1", CMD, "--break-glass", "--incident", iid,
                                  "--run"], guard=tv._guard(), prober=self.prober(),
                                 policy=self.policy, ssh=self.fake_ssh(),
                                 stream=tg._TTY(), prompt=_go,
                                 blackout_runner=self.blackout_runner(unavailable=True))
        self.assertEqual(self.ran(), [])

    def test_reads_are_unchanged_and_refuse_the_flag(self):
        iid = self.open()
        rc, _ = self.run_cmd("web1", None, cmd="uptime", run=False, break_glass=False)
        self.assertEqual(rc, 0)
        with self.assertRaises(Refused) as cm:
            self.run_cmd("web1", iid, cmd="uptime", run=False, break_glass=False)
        self.assertIn("applies to mutations", str(cm.exception))

    def test_secret_output_is_still_masked(self):
        iid = self.open()
        secret = "PGPASSWORD=" + "s3cr3tvalue" * 2
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexec.dispatch(["web1", CMD, "--break-glass", "--incident", iid, "--run",
                              "--reason", "r"], guard=tv._guard(), prober=self.prober(),
                             policy=self.policy, ssh=self.fake_ssh(out=secret),
                             stream=tg._TTY(), prompt=_go,
                             blackout_runner=self.blackout_runner(unavailable=True))
        self.assertNotIn("s3cr3tvalue", out.getvalue())


# ===========================================================================
# hard limit: the floor (and every other gate) cannot be reached
# ===========================================================================

class FloorTest(_IncidentHarness):

    def test_floor_refuses_under_an_incident(self):
        iid = self.open("web1,edge1")
        for cmd in ("docker system prune -af", "docker volume rm pgdata",
                    "rm -rf /", "psql -c 'DROP TABLE users'", "mkfs.ext4 /dev/sdb",
                    "dd if=/dev/zero of=/dev/sda", "uptime && docker volume prune -f"):
            for hosts in ("web1", "edge1"):
                with self.subTest(cmd=cmd, hosts=hosts):
                    self.refused(hosts, iid, cmd=cmd, needle="deny-always")

    def test_deny_extra_refuses_under_an_incident(self):
        iid = self.open()
        (self.policy_dir / "deny.yaml").write_text(
            'version: 1\nreason: "t"\ndeny_extra: ["restart redis"]\n')
        self.write_runbook()
        self.refused("web1", iid, needle="restart redis")

    def test_map_forbidding_break_glass_refuses_incident(self):
        iid = self.open()
        mapdoc = {"path": "/x/.vpscfgfarm.map",
                  "constraints": {"deny_extra": [], "risky_extra": [],
                                  "forbid_break_glass": True,
                                  "require_blackout": False}}
        for bg in (True, False):
            with self.subTest(break_glass=bg):
                self.refused("web1", iid, mapdoc=mapdoc, break_glass=bg,
                             needle="forbids --break-glass")

    def test_master_switch_and_lockdown_mode_still_refuse(self):
        iid = self.open()
        for gov in (tv._policy(mutation=False), tv._policy(mode="lockdown")):
            with self.subTest(gov=gov["mode"]):
                self.refused("web1", iid, gov=gov,
                             needle="master switch" if not gov["mutation_enabled"]
                             else "lockdown")


# ===========================================================================
# hard limit: listed hosts only, and only while open
# ===========================================================================

class ScopeTest(_IncidentHarness):

    def test_unlisted_host_refuses_the_whole_plan(self):
        iid = self.open("web1")
        self.refused("dns1", iid, needle="does not cover dns1")
        self.refused("web1,dns1", iid, needle="does not cover dns1")
        self.refused("edge1", iid, needle="does not cover edge1")

    def test_expired_incident_refuses(self):
        iid = self.open_at(_utc(hours=-2), ttl="1h")
        self.refused("web1", iid, prompt=lambda m: self.fail("prompted"),
                     needle="expired")

    def test_closed_incident_refuses(self):
        iid = self.open()
        self.close(iid)
        self.refused("web1", iid, prompt=lambda m: self.fail("prompted"),
                     needle="is closed")

    def test_closed_while_the_prompt_waited_refuses(self):
        iid = self.open()

        def close_then_go(msg):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexecincident.close(iid)
            return _go(msg)
        self.refused("web1", iid, prompt=close_then_go, needle="is closed")

    def test_unknown_or_malformed_id_refuses(self):
        self.open()
        for iid in ("ic_" + "0" * 32, "ic_123", "../grant.key", "ic_" + "G" * 32,
                    "/etc/passwd"):
            with self.subTest(iid=iid):
                self.refused("web1", iid)

    def test_closed_list_that_cannot_be_trusted_fails_closed(self):
        iid = self.open()
        closed = self.grant_dir / vpsexecincident.CLOSED
        closed.write_text("not json\n")
        os.chmod(closed, 0o600)
        self.refused("web1", iid, needle="failing closed")
        closed.write_text("")
        os.chmod(closed, 0o644)
        self.refused("web1", iid, needle="failing closed")


# ===========================================================================
# hard limit: tampered or forged files refuse
# ===========================================================================

class ForgeryTest(_IncidentHarness):

    def _rewrite(self, iid, mutate, reseal_with=None):
        path = self.grant_dir / iid
        inc = json.loads(path.read_text())
        mutate(inc)
        if reseal_with is not None:
            inc["mac"] = vpsexecgrant._mac(reseal_with, inc)
        path.write_text(json.dumps(inc))
        os.chmod(path, 0o600)

    def test_widened_hosts_without_the_key_refuse(self):
        iid = self.open("web1")
        self._rewrite(iid, lambda i: i["hosts"].append("dns1"))
        self.refused("dns1", iid, needle="failed its MAC")
        self.refused("web1", iid, needle="failed its MAC")

    def test_extended_expiry_refuses(self):
        iid = self.open("web1")
        self._rewrite(iid, lambda i: i.update(expires_at="2999-01-01T00:00:00Z"))
        self.refused("web1", iid, needle="failed its MAC")

    def test_sealed_with_another_key_refuses(self):
        iid = self.open("web1")
        self._rewrite(iid, lambda i: None, reseal_with=os.urandom(32))
        self.refused("web1", iid, needle="failed its MAC")

    def test_a_correctly_sealed_bad_window_still_refuses(self):
        """Behind the MAC: someone holding the key still cannot mint a 24h
        incident or one whose ttl disagrees with its window."""
        iid = self.open("web1")
        key = vpsexecgrant.load_key()
        self._rewrite(iid, lambda i: i.update(ttl="24h"), reseal_with=key)
        self.refused("web1", iid, needle="ttl")

    def test_a_grant_cannot_pass_as_an_incident(self):
        grant = self.mint()
        iid = "ic_" + "a" * 32
        (self.grant_dir / iid).write_bytes(Path(grant).read_bytes())
        os.chmod(self.grant_dir / iid, 0o600)
        self.refused("web1", iid, needle="key set is wrong")

    def test_kind_and_id_are_bound(self):
        iid = self.open("web1")
        key = vpsexecgrant.load_key()
        self._rewrite(iid, lambda i: i.update(kind="grant"), reseal_with=key)
        self.refused("web1", iid, needle="kind")
        other = self.open("web1")
        copy = "ic_" + "b" * 32
        (self.grant_dir / copy).write_bytes((self.grant_dir / other).read_bytes())
        os.chmod(self.grant_dir / copy, 0o600)
        self.refused("web1", copy, needle="its own id")

    def test_loose_mode_symlink_and_duplicate_keys_refuse(self):
        iid = self.open("web1")
        path = self.grant_dir / iid
        os.chmod(path, 0o644)
        self.refused("web1", iid, needle="mode")
        os.chmod(path, 0o600)
        link = "ic_" + "c" * 32
        os.symlink(path, self.grant_dir / link)
        self.refused("web1", link)
        raw = path.read_text()
        path.write_text(raw.replace('"ttl": "1h"', '"ttl": "1h", "ttl": "1h"'))
        os.chmod(path, 0o600)
        self.refused("web1", iid, needle="duplicate")

    def test_oversized_file_refuses(self):
        iid = self.open("web1")
        path = self.grant_dir / iid
        path.write_text(" " * (vpsexecincident.MAX_BYTES + 1))
        os.chmod(path, 0o600)
        self.refused("web1", iid, needle="exceeds")


# ===========================================================================
# close, report, backfill, status
# ===========================================================================

class CloseTest(_IncidentHarness):

    def _backfill(self, text):
        block = text.split("```yaml\n", 1)[1].split("```", 1)[0]
        return yaml.safe_load(block)

    def test_close_reports_every_command_and_drafts_a_backfill(self):
        iid = self.open("web1,dns1")
        self.run_cmd("web1", iid)
        self.run_cmd("web1,dns1", iid, cmd="systemctl restart nginx")
        self.run_cmd("web1", iid)  # a repeat: reported twice, backfilled once
        out = self.close(iid)
        path = Path(journal.JOURNAL_DIR) / "incidents" / ("%s.md" % iid)
        self.assertTrue(path.exists())
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        text = path.read_text()
        self.assertIn(text.strip(), out)
        self.assertIn("commands run: 3", text)
        self.assertEqual(text.count("cmd: `%s`" % CMD), 2)
        self.assertIn('"web1": 0', text)
        doc = self._backfill(text)
        self.assertEqual(doc["version"], 1)
        rb = doc["runbooks"]
        self.assertEqual([(r["hosts"], r["cmd"], r["where"], r["break_glass"]) for r in rb],
                         [(["web1"], CMD, "host", True),
                          (["web1", "dns1"], "systemctl restart nginx", "host", True)])
        self.assertTrue(all(iid in r["why"] for r in rb))
        closed = self.of("incident_closed")
        self.assertEqual([(e["incident"], e["early"]) for e in closed], [(iid, True)])

    def test_close_after_expiry_still_reports(self):
        iid = self.open_at(_utc(hours=-2), ttl="15m")
        out = self.close(iid)
        self.assertIn("after expiry", out)
        self.assertIn("(none", out)
        self.assertEqual(self.of("incident_closed")[0]["early"], False)

    def test_close_twice_refuses(self):
        iid = self.open()
        self.close(iid)
        with self.assertRaises(Refused):
            self.close(iid)

    def test_report_only_carries_its_own_incident(self):
        a, b = self.open("web1"), self.open("dns1")
        self.run_cmd("web1", a)
        self.run_cmd("dns1", b, cmd="systemctl restart nginx")
        text = self.close(a)
        self.assertIn(CMD, text)
        self.assertNotIn("restart nginx", text)

    def test_status_lists_open_and_unclosed_expired(self):
        live = self.open("web1,dns1")
        stale = self.open_at(_utc(hours=-3), ttl="1h")
        done = self.open("web1")
        self.close(done)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexecincident.cli(["status"], HOSTS_CFG)
        text = out.getvalue()
        self.assertIn("INCIDENT %s OPEN" % live, text)
        self.assertIn("web1, dns1", text)
        self.assertIn("EXPIRED %s" % stale, text)
        self.assertNotIn(done, text)

    def test_status_with_nothing_open(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexecincident.cli(["status"], HOSTS_CFG)
        self.assertIn("no open incidents", out.getvalue())


if __name__ == "__main__":
    unittest.main()
