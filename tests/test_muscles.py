"""Tests for the muscle modules: drift, syncplan, verify, outage, sshconfig.

Hermetic — network-facing functions get injected doubles; nothing here can
reach a fleet host.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import drift, lint, outage, playbook, sshconfig, syncplan, telemetry, traefikmap, verify  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402


class DriftPathValidationTest(unittest.TestCase):
    def test_refuses_traversal(self):
        for bad in ("../etc/passwd", "a/../../b", "src/../.."):
            with self.assertRaises(Refused):
                drift.validate_relpath(bad)

    def test_refuses_metacharacters(self):
        for bad in ("a;rm", "a|b", "a b", "$(x)", "a`b`", "a&b", "-flag"):
            with self.assertRaises(Refused):
                drift.validate_relpath(bad)

    def test_accepts_normal_paths(self):
        for ok in ("server.js", "routes/orgs.js", "a/b/c.d-e_f", "migrations"):
            self.assertEqual(drift.validate_relpath(ok), ok)


class DriftCompareTest(unittest.TestCase):
    def test_classification(self):
        local = {"a.js": "h1", "b.js": "h2", "gone.js": "h3", ".env.production": "hx"}
        remote = {"a.js": "h1", "b.js": "DIFFERENT", "extra.js": "h9",
                  ".env.production": "hy", "gone.js": None}
        report = drift.compare(local, remote, [".env.production"])
        self.assertEqual(report["in_sync"], ["a.js"])
        self.assertEqual(report["drifted"], ["b.js"])
        self.assertEqual(report["missing_on_host"], ["gone.js"])
        self.assertEqual(report["missing_in_git"], ["extra.js"])
        self.assertEqual(report["expected_diverged"], [".env.production"])

    def test_never_covers_directories(self):
        report = drift.compare({"conf/secret.key": "h"}, {"conf/secret.key": "DIFF"},
                               ["conf"])
        self.assertEqual(report["expected_diverged"], ["conf/secret.key"])
        self.assertEqual(report["drifted"], [])

    def test_local_hashes_walks_and_hashes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "routes").mkdir()
            (root / "server.js").write_text("hello")
            (root / "routes" / "x.js").write_text("world")
            hashes = drift.local_hashes(d, ["server.js", "routes/"])
            self.assertIn("server.js", hashes)
            self.assertIn("routes/x.js", hashes)
            self.assertEqual(len(hashes["server.js"]), 32)

    def test_local_hashes_refuses_bad_repo(self):
        with self.assertRaises(Refused):
            drift.local_hashes("/nonexistent/dir/xyz", ["a"])


class SyncPlanTest(unittest.TestCase):
    CONTRACT = {
        "service": "s", "host": "edge1", "deploy_dir": "/opt/s",
        "repo": "/tmp/repo",
        "sync": {"include": ["server.js", "routes/"],
                 "never": [".env.production", "Dockerfile"]},
        "verify": [],
    }

    def test_never_list_becomes_excludes(self):
        argv = syncplan.rsync_argv(self.CONTRACT, dry_run=True)
        self.assertIn("--dry-run", argv)
        self.assertEqual(argv.count("--exclude"), 3)  # protected paths plus default exclusion
        self.assertIn(".env.production", argv)
        self.assertIn("Dockerfile", argv)
        self.assertEqual(argv[-1], "edge1:/opt/s/")

    def test_real_run_omits_dry_run_flag_only(self):
        dry = syncplan.rsync_argv(self.CONTRACT, dry_run=True)
        wet = syncplan.rsync_argv(self.CONTRACT, dry_run=False)
        self.assertEqual([a for a in dry if a != "--dry-run"], wet)

    def test_refuses_contract_without_repo(self):
        c = dict(self.CONTRACT)
        del c["repo"]
        with self.assertRaises(Refused):
            syncplan.rsync_argv(c)

    def test_refuses_relative_deploy_dir(self):
        c = dict(self.CONTRACT, deploy_dir="opt/s")
        with self.assertRaises(Refused):
            syncplan.rsync_argv(c)

    def test_refuses_hostile_include(self):
        c = dict(self.CONTRACT)
        c = {**c, "sync": {"include": ["$(rm x)"], "never": ["n"]}}
        with self.assertRaises(Refused):
            syncplan.rsync_argv(c)


class VerifyTest(unittest.TestCase):
    def test_http_pass_and_fail(self):
        contract = {"verify": [{"http": {"url": "https://x/health", "expect": 200}},
                               {"http": {"url": "https://x/orgs", "expect": 401}}]}
        ok, results = verify.run_checks(contract, "web1", fetch=lambda u, t: 200)
        self.assertFalse(ok)  # second check wanted 401, got 200
        self.assertTrue(results[0]["ok"])
        self.assertFalse(results[1]["ok"])

    def test_http_unreachable_is_failure_not_crash(self):
        def boom(u, t):
            raise OSError("connection refused")
        contract = {"verify": [{"http": {"url": "https://x/", "expect": 200}}]}
        ok, results = verify.run_checks(contract, "web1", fetch=boom)
        self.assertFalse(ok)
        self.assertIn("unreachable", results[0]["detail"])

    def test_refuses_non_http_url(self):
        contract = {"verify": [{"http": {"url": "file:///etc/passwd"}}]}
        with self.assertRaises(Refused):
            verify.run_checks(contract, "web1", fetch=lambda u, t: 200)

    def test_container_check_via_injected_runner(self):
        contract = {"verify": [{"container": {"name": "svc-1", "state": "healthy"}}]}
        ok, _ = verify.run_checks(contract, "web1",
                                  runner=lambda h, n: (0, "running healthy"))
        self.assertTrue(ok)
        ok, _ = verify.run_checks(contract, "web1",
                                  runner=lambda h, n: (0, "running unhealthy"))
        self.assertFalse(ok)

    def test_refuses_hostile_container_name(self):
        contract = {"verify": [{"container": {"name": "x; rm -rf"}}]}
        with self.assertRaises(Refused):
            verify.run_checks(contract, "web1", runner=lambda h, n: (0, "running"))

    def test_unknown_check_type_fails_closed(self):
        ok, results = verify.run_checks({"verify": [{"quantum": {}}]}, "web1")
        self.assertFalse(ok)


class OutageTest(unittest.TestCase):
    def test_volume_twin_prevents(self):
        contract = {"blast_radius": {"volumes": ["acmedns_postgres-data"]}}
        a = outage.assess(contract, [], ["acmedns_postgres_data"])
        self.assertTrue(a["prevent"])
        self.assertIn("volume_twin", [k for k, _ in a["findings"]])

    def test_databases_surface_in_findings(self):
        containers = [{"name": "acme-postgres-primary", "image": "postgres:16-alpine"},
                      {"name": "web", "image": "nginx:alpine"}]
        a = outage.assess({}, containers, [])
        kinds = [k for k, _ in a["findings"]]
        self.assertIn("databases_present", kinds)
        self.assertFalse(a["prevent"])  # informative, not preventive

    def test_no_failover_flagged(self):
        a = outage.assess({}, [], [], host_meta={"failover": False})
        self.assertIn("no_failover", [k for k, _ in a["findings"]])


class SshConfigTest(unittest.TestCase):
    SAMPLE = """
Host web1.example.internal
  User root
Host edge1 edge1.example.internal
  HostName 198.51.100.5
  User root
Host authdns1 dns1 dns1.example.org
  HostName 198.51.100.27
  User root
Host *
  ServerAliveInterval 60
"""

    def _path(self):
        f = tempfile.NamedTemporaryFile("w", delete=False, suffix="sshcfg")
        f.write(self.SAMPLE)
        f.close()
        return f.name

    def test_aliases_collapse_to_machines(self):
        m = sshconfig.machines(self._path())
        self.assertIn("198.51.100.5", m)
        self.assertEqual(sorted(m["198.51.100.5"]["aliases"]),
                         ["edge1", "edge1.example.internal"])
        self.assertIn("web1.example.internal", m)

    def test_wildcards_ignored(self):
        hosts = sshconfig.load(self._path())
        self.assertNotIn("*", hosts)

    def test_missing_file_returns_empty(self):
        self.assertEqual(sshconfig.load("/nonexistent/cfg"), {})


if __name__ == "__main__":
    unittest.main()


class ReleasedSequenceTest(unittest.TestCase):
    """Pins the post-pin order BEFORE the pin exists. If the sequence ever
    changes, this fails and the change gets a conscious review."""
    def test_order_is_lock_backup_sync_build_verify_drift_unlock(self):
        from vpscfg.executor import released_sequence
        contract = {"pre": [{"backup": "tar czf x"}], "build": "compose up"}
        steps = [s["step"] for s in released_sequence(contract, "edge1")]
        self.assertEqual(steps, ["lock", "backup", "sync", "build",
                                 "verify", "drift_confirm", "unlock"])

    def test_verify_failure_rolls_back(self):
        from vpscfg.executor import released_sequence
        seq = released_sequence({}, "edge1")
        verify_step = [s for s in seq if s["step"] == "verify"][0]
        self.assertEqual(verify_step["on_fail"], "rollback")


class LockTest(unittest.TestCase):
    def test_acquire_wins_when_mkdir_succeeds(self):
        from vpscfg import lock
        self.assertTrue(lock.acquire("edge1", "op", "test",
                                     runner=lambda h, c: (0, "", "")))

    def test_acquire_refuses_and_names_owner_when_locked(self):
        from vpscfg import lock
        from vpscfg.gates import Refused
        calls = []
        def runner(h, c):
            calls.append(c)
            if "mkdir" in c:
                return (1, "", "exists")
            return (0, '{"operator": "cat", "reason": "chaos"}', "")
        with self.assertRaises(Refused) as ctx:
            lock.acquire("edge1", "op", "test", runner=runner)
        self.assertIn("cat", str(ctx.exception))

    def test_release_reports_failure_without_raising(self):
        from vpscfg import lock
        self.assertFalse(lock.release("edge1", runner=lambda h, c: (1, "", "err")))


class ReasonTest(unittest.TestCase):
    def test_mutation_without_reason_refused(self):
        import hashlib, json as _json, tempfile as _tf
        from pathlib import Path as _P
        from vpscfg.control import Guard
        from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused
        from vpscfg import executor
        policy = {"version": 1, "mode": "test", "mutation_enabled": True,
                  "allowed_verbs": ["deploy"],
                  "scopes": {"unlocked": ["service:edge1/s"]},
                  "hosts": {"edge1": {"posture": "test"}},
                  "deny_always": list(DENY_ALWAYS_FLOOR)}
        f = _tf.NamedTemporaryFile("w", suffix=".json", delete=False)
        _json.dump(policy, f); f.close()
        token = hashlib.sha256(_P(f.name).read_bytes()).hexdigest()
        guard = Guard.load(path=f.name, token=token)
        contract = {"service": "s", "host": "edge1", "deploy_dir": "/opt/s",
                    "sync": {"include": [], "never": ["x"]}, "verify": []}
        with self.assertRaises(Refused) as ctx:
            executor.apply(guard, contract, "deploy", "edge1", "service:edge1/s",
                           ["echo hi"], reason=None)
        self.assertIn("--reason", str(ctx.exception))


class PlaybookShowTest(unittest.TestCase):
    KNOWN = {"edge1", "web2", "web3"}

    def test_argv_always_carries_check_and_diff(self):
        argv = playbook.show_argv("edge1", "baseline", known_hosts=self.KNOWN)
        self.assertTrue(argv[0].endswith("ansible-playbook"))
        self.assertIn("--check", argv)
        self.assertIn("--diff", argv)
        self.assertIn("--limit", argv)
        self.assertIn("edge1,", argv)  # single-host inline inventory

    def test_refuses_unknown_host(self):
        with self.assertRaises(Refused):
            playbook.show_argv("web1", "baseline", known_hosts=self.KNOWN)

    def test_refuses_hostile_playbook_names(self):
        for bad in ("../evil", "a;b", "a b", "", None, ".hidden", "x/../y"):
            with self.assertRaises(Refused):
                playbook.show_argv("edge1", bad, known_hosts=self.KNOWN)

    def test_refuses_missing_playbook(self):
        with self.assertRaises(Refused) as ctx:
            playbook.show_argv("edge1", "no-such-playbook", known_hosts=self.KNOWN)
        self.assertIn("no playbook", str(ctx.exception))

    def test_playbook_path_stays_inside_playbooks_dir(self):
        argv = playbook.show_argv("edge1", "baseline", known_hosts=self.KNOWN)
        self.assertTrue(argv[-1].startswith(str(playbook.PLAYBOOK_DIR)))


def _contract(include, repo="/tmp"):
    return {"service": "s", "host": "edge1", "deploy_dir": "/opt/s", "repo": repo,
            "sync": {"include": include, "never": [".env"]}, "verify": []}


class SyncRenameTest(unittest.TestCase):
    def test_plain_includes_still_one_argv(self):
        argvs = syncplan.rsync_argvs(_contract(["a.txt", "dirb/"]))
        self.assertEqual(len(argvs), 1)
        self.assertIn("--dry-run", argvs[0])

    def test_rename_gets_dedicated_transfer_to_dest_name(self):
        argvs = syncplan.rsync_argvs(_contract(
            ["plain.txt", {"src": "app/index.html", "dest": "app-frontend.html"}]))
        self.assertEqual(len(argvs), 2)
        self.assertTrue(argvs[1][-1].endswith(":/opt/s/app-frontend.html"))
        self.assertTrue(argvs[1][-2].endswith("/app/index.html"))

    def test_rename_refuses_directories_and_partial_mappings(self):
        for bad in ({"src": "a/", "dest": "b"}, {"src": "a"}, {"dest": "b"},
                    {"src": "a", "dest": "b", "extra": 1}):
            with self.assertRaises(Refused):
                syncplan.rsync_argvs(_contract([bad]))

    def test_rsync_argv_backcompat_refuses_renames(self):
        with self.assertRaises(Refused):
            syncplan.rsync_argv(_contract(
                [{"src": "a.txt", "dest": "b.txt"}]))

    def test_drift_hashes_rename_under_dest_name(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app").mkdir()
            (Path(d) / "app" / "index.html").write_text("hello")
            hashes = drift.local_hashes(d, [{"src": "app/index.html",
                                             "dest": "app-frontend.html"}])
            self.assertIn("app-frontend.html", hashes)
            self.assertNotIn("app/index.html", hashes)
            self.assertIsNotNone(hashes["app-frontend.html"])


class LintTest(unittest.TestCase):
    def test_flags_weak_contract(self):
        raw = "repo: /x\n# TODO fill in"
        contract = {"service": "s", "host": "h", "deploy_dir": "/opt/s",
                    "repo": "/x", "sync": {"include": [], "never": ["x"]},
                    "verify": []}
        findings = lint.lint_contract("s", raw, contract)
        levels = [f[0] for f in findings]
        msgs = " | ".join(f[1] for f in findings)
        self.assertIn("E", levels)          # empty verify
        self.assertIn("TODO", msgs)
        self.assertIn("http", msgs)
        self.assertIn("sync.include", msgs)

    def test_clean_contract_passes(self):
        contract = {"service": "s", "host": "h", "deploy_dir": "/opt/s",
                    "repo": "/x",
                    "sync": {"include": ["a"], "never": ["x"]},
                    "verify": [{"http": {"url": "https://x/", "expect": 200}}],
                    "blast_radius": {"volumes": ["v"]}}
        self.assertEqual(lint.lint_contract("s", "clean", contract), [])


class TelemetryTest(unittest.TestCase):
    def test_disabled_without_key_never_raises(self):
        old = dict(os.environ)
        os.environ.pop("VPSCFG_TELEMETRY_KEY", None)
        try:
            orig = telemetry.KEY_FILE
            telemetry.KEY_FILE = Path("/nonexistent/key.txt")
            self.assertFalse(telemetry.enabled())
            self.assertFalse(telemetry.push_event({"event": "x"}))
            telemetry.KEY_FILE = orig
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_push_failure_is_swallowed(self):
        old = dict(os.environ)
        os.environ["VPSCFG_TELEMETRY_KEY"] = "k"
        real = telemetry.integrations.telemetry_url
        # The endpoint comes from the governor only; nothing listens here.
        telemetry.integrations.telemetry_url = lambda: "https://127.0.0.1:1"
        try:
            self.assertFalse(telemetry.push_event({"event": "x"}, timeout=1))
        finally:
            telemetry.integrations.telemetry_url = real
            os.environ.clear(); os.environ.update(old)


class TraefikMapTest(unittest.TestCase):
    DOC = """
http:
  routers:
    api-router:
      rule: "Host(`api.example.com`)"
      service: api-svc
    dead-router:
      rule: "PathPrefix(`/x`)"
      service: missing-svc
  services:
    api-svc:
      loadBalancer:
        servers:
          - url: "http://acme-api:3000"
          - url: "http://172.17.0.5:3000"
"""
    def test_parse_and_suggest(self):
        routes = traefikmap.parse(self.DOC)
        self.assertEqual(len(routes), 2)
        sugg = traefikmap.suggestions(routes)
        self.assertIn("acme-api", sugg)
        self.assertNotIn("172.17.0.5", sugg)
        self.assertEqual(sugg["acme-api"][0]["http"]["url"],
                         "https://api.example.com/")

    def test_empty_doc_is_fine(self):
        self.assertEqual(traefikmap.parse(""), [])
        self.assertEqual(traefikmap.suggestions([]), {})
