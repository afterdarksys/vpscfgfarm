"""k3s apply mode: schema, the executor's released sequence, preflight's
k3s checks, and the blackout export reader. Hermetic — every transport is
injected, the journal lives in a tmpdir, no test dials a host or runs docker."""
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import blackout, contracts, executor, journal, k3sapply, preflight  # noqa: E402
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

HOST, SVC = "edge1", "demo-web"
SCOPE = "pod:edge1/demo-web"
OLD = "registry.example.com/demo/web:vpscfg-0000000000000000"


def _policy(unlocked=(SCOPE,)):
    return {"version": 1, "mode": "test", "mutation_enabled": True,
            "allowed_verbs": ["deploy", "rollback"], "scopes": {"unlocked": list(unlocked)},
            "hosts": {HOST: {"posture": "test"}}, "deny_always": list(DENY_ALWAYS_FLOOR)}


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = journal.JOURNAL_DIR
        journal.JOURNAL_DIR = Path(self._tmp.name) / "journal"
        self._tel = mock.patch("vpscfg.telemetry.push_event")
        self._tel.start()
        self.repo = Path(self._tmp.name) / "repo"
        (self.repo / "app").mkdir(parents=True)
        (self.repo / "app" / "main.py").write_text("print('v2')\n")
        (self.repo / "Dockerfile").write_text("FROM python:3.12-slim\nCOPY app /app\n")
        self.git("init", "-q")
        self.commit("v2")
        self.contract = {
            "service": SVC, "host": HOST, "scope_kind": "pod", "repo": str(self.repo),
            "apply": {"mode": "k3s", "namespace": "demo", "deployment": "demo-web",
                      "container": "web", "image": "registry.example.com/demo/web",
                      "dockerfile": "Dockerfile", "rollout_timeout": "60s"},
            "sync": {"include": ["app/", "Dockerfile"], "never": []},
            "verify": [{"http": {"url": "https://demo.example.com/health", "expect": 200}}],
            "blast_radius": {"volumes": ["demo-cache"]},
            "freeze": False,
        }
        contracts._validate(self.contract, "test")

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        subprocess.run(["git", "-C", str(self.repo)] + list(args), check=True,
                       capture_output=True, env=env)

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)

    def tearDown(self):
        journal.JOURNAL_DIR = self._orig
        self._tel.stop()
        self._tmp.cleanup()

    def ref(self):
        return k3sapply.image_ref(self.contract, preflight._source_manifest(self.contract))


class SchemaTest(Base):
    def _v(self, **apply_changes):
        c = json.loads(json.dumps(self.contract))
        c["apply"].update(apply_changes)
        for k, v in list(c["apply"].items()):
            if v is None:
                del c["apply"][k]
        contracts._validate(c, "test")

    def test_valid_k3s_contract_needs_no_deploy_dir(self):
        self.assertNotIn("deploy_dir", self.contract)
        self._v(context=".", platform="linux/arm64", rollout_timeout="5m")

    def test_non_k3s_contract_still_requires_deploy_dir(self):
        c = dict(self.contract)
        del c["apply"]
        c["scope_kind"] = "container"
        with self.assertRaises(Refused):
            contracts._validate(c, "test")

    def test_refusals(self):
        for bad in ({"namespace": "kube-system"}, {"namespace": "cert-manager"},
                    {"namespace": "default"}, {"namespace": "Demo"},
                    {"deployment": "x;rm"}, {"container": ""},
                    {"image": "registry.example.com/demo/web:latest"},
                    {"image": "registry.example.com/demo/web@sha256:abc"},
                    {"image": "web"}, {"dockerfile": "../Dockerfile"},
                    {"context": "../.."}, {"platform": "windows/amd64"},
                    {"rollout_timeout": "2h"}, {"rollout_timeout": "soon"},
                    {"mode": "helm"}, {"command": "kubectl apply -f x"}):
            with self.assertRaises(Refused, msg=bad):
                self._v(**bad)

    def test_scope_kind_must_be_pod(self):
        for kind in ("container", "service", None):
            c = dict(self.contract, scope_kind=kind)
            if kind is None:
                del c["scope_kind"]
            with self.assertRaises(Refused):
                contracts._validate(c, "test")

    def test_free_form_build_refused(self):
        with self.assertRaises(Refused):
            contracts._validate(dict(self.contract, build="docker build ."), "test")

    def test_image_ref_is_content_addressed(self):
        a = self.ref()
        self.assertTrue(a.startswith("registry.example.com/demo/web:vpscfg-"))
        self.assertEqual(a, self.ref())
        (self.repo / "app" / "main.py").write_text("print('v3')\n")
        self.commit("v3")
        self.assertNotEqual(a, self.ref())

    def test_dockerfile_change_changes_the_tag(self):
        """The Dockerfile is outside sync.include here on purpose: the tag
        must still move, because it binds the commit."""
        self.contract["sync"]["include"] = ["app/"]
        a = self.ref()
        (self.repo / "Dockerfile").write_text("FROM python:3.13-slim\nCOPY app /app\n")
        self.commit("base bump")
        self.assertNotEqual(a, self.ref())

    def test_dirty_tree_refused(self):
        for change in (lambda: (self.repo / "Dockerfile").write_text("FROM scratch\n"),
                       lambda: (self.repo / "untracked.txt").write_text("x")):
            change()
            with self.assertRaises(Refused) as cm:
                self.ref()
            self.assertIn("uncommitted", str(cm.exception))
            self.git("checkout", "-q", "--", ".")
            self.git("clean", "-qfd")

    def test_not_a_git_repo_refused(self):
        import shutil
        shutil.rmtree(self.repo / ".git")
        with self.assertRaises(Refused):
            self.ref()

    def test_read_state_command_and_parse(self):
        argv = shlex.split(k3sapply.read_state_cmd(self.contract))
        self.assertEqual(argv[:6], ["k3s", "kubectl", "-n", "demo", "get", "deployment"])
        self.assertIn('?(@.name=="web")', argv[-1])
        st = k3sapply.parse_state("%s\tIfNotPresent\t2\t2" % OLD)
        self.assertEqual((st["image"], st["replicas"], st["ready"]), (OLD, 2, 2))
        self.assertEqual(k3sapply.parse_state("%s\tNever\t1\t" % OLD)["ready"], 0)
        for bad in ("\t1\t1", "", "a\tb", "img\tIfNotPresent\tx\t1", "img\t\t1\t1",
                    "img\tSometimes\t1\t1"):
            with self.assertRaises(Refused):
                k3sapply.parse_state(bad)

    def test_commands_clear_the_deny_floor_and_never_apply_manifests(self):
        from vpscfg.gates import deny_scan
        for cmd in k3sapply.planned(self.contract, self.ref()):
            deny_scan(cmd, DENY_ALWAYS_FLOOR)
            self.assertNotIn("apply", cmd.split())
            self.assertNotIn("delete", cmd.split())


class Fleet(object):
    """Fake edge1 + local docker. `live` is the deployment's current image."""

    def __init__(self, test):
        self.t = test
        self.live = OLD
        self.policy = "IfNotPresent"
        self.calls = []
        self.fail = set()   # step names to fail: build, save, import, set, rollout, restore
        self.verify_results = [True]
        self.pending = None

    def ssh(self, host, cmd, timeout=120):
        self.calls.append(("ssh", cmd))
        if "mkdir" in cmd or "rmdir" in cmd:
            return 0, "", ""
        if "docker ps" in cmd or "docker volume ls" in cmd:
            return 0, "", ""
        if "get deployment" in cmd:
            return 0, "%s\t%s\t1\t1" % (self.live, self.policy), ""
        if " set image " in cmd:
            new = cmd.rsplit("=", 1)[1].strip("'")
            restoring = new == self.pending
            if ("restore" if restoring else "set") in self.fail:
                return 1, "", "boom"
            if "ignore_set" not in self.fail:
                self.live = new
            return 0, "", ""
        if "rollout status" in cmd:
            key = "restore_rollout" if self.live == self.pending else "rollout"
            return (1, "", "timed out") if key in self.fail else (0, "rolled out", "")
        if "rollout undo" in cmd:
            return 0, "", ""
        raise AssertionError("unexpected ssh command %r" % cmd)

    def local(self, argv, timeout=300):
        self.calls.append(("local", argv))
        step = "build" if argv[1] == "build" else "save"
        if step in self.fail:
            return 1, "", "%s failed" % step
        if step == "save":
            Path(argv[3]).write_bytes(b"tar")
            self.tar_dir = os.path.dirname(argv[3])
        return 0, "", ""

    def ssh_stdin(self, host, cmd, path):
        self.calls.append(("import", cmd, Path(path).read_bytes()))
        return (1, "", "import failed") if "import" in self.fail else (0, "unpacked", "")

    def checks(self, contract, host):
        ok = self.verify_results.pop(0) if self.verify_results else True
        return ok, [{"check": "http", "url": "u", "ok": ok, "detail": "x"}]


class ExecutorTest(Base):
    def setUp(self):
        super().setUp()
        self.f = Fleet(self)
        self.f.pending = OLD

    def apply(self, verb="deploy", unlocked=(SCOPE,)):
        with redirect_stdout(io.StringIO()):
            return executor.apply(Guard(_policy(unlocked), True), self.contract, verb, HOST, SCOPE,
                                  k3sapply.planned(self.contract, self.ref()), reason="test",
                                  ssh=self.f.ssh, run_local=self.f.local, checks=self.f.checks,
                                  ssh_stdin=self.f.ssh_stdin)

    def kinds(self):
        out = []
        for c in self.f.calls:
            if c[0] == "local":
                out.append("local:" + c[1][1])
            elif c[0] == "import":
                out.append("import")
            elif "get deployment" in c[1]:
                out.append("state")
            elif " set image " in c[1]:
                out.append("set-image")
            elif "rollout status" in c[1]:
                out.append("rollout")
            elif "mkdir" in c[1]:
                out.append("lock")
            elif "rmdir" in c[1]:
                out.append("unlock")
        return out

    def events(self):
        path = journal.JOURNAL_DIR / "executor.jsonl"
        return [json.loads(l) for l in path.read_text().splitlines()]

    def test_released_sequence_order(self):
        self.assertEqual(self.apply(), 0)
        k = self.kinds()
        order = ["lock", "state", "local:build", "local:save", "import", "set-image",
                 "rollout", "state", "unlock"]
        self.assertEqual([x for x in k if x in order], order)
        self.assertEqual(self.f.live, self.ref())
        self.assertFalse(os.path.exists(self.f.tar_dir))  # local tarball cleaned up
        self.assertTrue(any(e["event"] == "mutation_complete" for e in self.events()))
        build = next(c[1] for c in self.f.calls if c[0] == "local" and c[1][1] == "build")
        self.assertEqual(build[:4], ["docker", "build", "--platform", "linux/amd64"])
        self.assertIn(self.ref(), build)

    def test_scope_must_be_unlocked(self):
        with self.assertRaises(Refused):
            self.apply(unlocked=("container:edge1/demo-web",))
        self.assertEqual(self.f.calls, [])

    def test_build_failure_changes_nothing_and_releases_lock(self):
        self.f.fail.add("build")
        with self.assertRaises(Refused):
            self.apply()
        self.assertEqual(self.f.live, OLD)
        self.assertNotIn("set-image", self.kinds())
        self.assertEqual(self.kinds()[-1], "unlock")

    def test_import_failure_changes_nothing(self):
        self.f.fail.add("import")
        with self.assertRaises(Refused):
            self.apply()
        self.assertEqual(self.f.live, OLD)
        self.assertEqual(self.kinds()[-1], "unlock")

    def test_pull_policy_always_refused_before_build(self):
        self.f.policy = "Always"
        with self.assertRaises(Refused) as cm:
            self.apply()
        self.assertIn("Always", str(cm.exception))
        self.assertNotIn("local:build", self.kinds())

    def test_already_live_refused(self):
        self.f.live = self.ref()
        with self.assertRaises(Refused) as cm:
            self.apply()
        self.assertIn("already", str(cm.exception))
        self.assertNotIn("local:build", self.kinds())

    def test_verify_failure_restores_previous_image_and_releases_lock(self):
        self.f.verify_results = [False, True]
        with self.assertRaises(Refused) as cm:
            self.apply()
        self.assertIn("restore health PASS", str(cm.exception))
        self.assertEqual(self.f.live, OLD)
        self.assertEqual(self.kinds()[-1], "unlock")
        self.assertTrue(any(e["event"] == "deploy_failed_restore_attempted" for e in self.events()))

    def test_rollout_failure_restores_previous_image(self):
        self.f.fail.add("rollout")
        self.f.verify_results = [True]
        with self.assertRaises(Refused) as cm:
            self.apply()
        self.assertIn("rollout FAILED", str(cm.exception))
        self.assertEqual(self.f.live, OLD)

    def test_remote_output_is_masked_in_the_journal(self):
        """secretmask (a91a5e4) covers the k3s steps too: a secret in
        set-image / rollout output never reaches the journal raw."""
        canary = "hunter2-k3s-Zq9xLw4vT"
        real = self.f.ssh

        def leaky(host, cmd, timeout=120):
            rc, out, err = real(host, cmd, timeout)
            if " set image " in cmd or "rollout status" in cmd:
                return rc, out, "token=%s\nDATABASE_URL=postgres://u:%s@db/x" % (canary, canary)
            return rc, out, err
        self.f.ssh = leaky
        self.assertEqual(self.apply(), 0)
        raw = (journal.JOURNAL_DIR / "executor.jsonl").read_text()
        self.assertTrue(any(e.get("step") == "set-image-rollout-status" for e in self.events()))
        self.assertNotIn(canary, raw)

    def test_unreadable_state_refusal_is_masked(self):
        """parse_state quotes remote stdout in its refusal; it must be masked
        (the refusal is printed and, via preflight, journaled)."""
        canary = "hunter2-state-Zq9xLw4vT"
        for bad in ("token=%s" % canary, "a\tWeird token=%s\t1\t1" % canary,
                    "img\tAlways\tx token=%s\t1" % canary):
            with self.assertRaises(Refused) as cm:
                k3sapply.parse_state(bad)
            self.assertNotIn(canary, str(cm.exception), bad)

    def test_preflight_evidence_is_masked_for_every_check(self):
        canary = "hunter2-evidence-Zq9xLw4vT"
        def leaks():
            raise Refused("probe said DATABASE_URL=postgres://u:%s@db/x" % canary)
        out = preflight._guarded("leaky", leaks)
        self.assertEqual(out["status"], "fail")
        self.assertNotIn(canary, out["evidence"])

    def test_failed_restore_retains_lock(self):
        self.f.verify_results = [False]
        self.f.fail.add("restore")
        with self.assertRaises(Refused) as cm:
            self.apply()
        self.assertIn("lock retained", str(cm.exception))
        self.assertNotIn("unlock", self.kinds())

    def test_unhealthy_restore_retains_lock(self):
        self.f.verify_results = [False, False]
        with self.assertRaises(Refused):
            self.apply()
        self.assertNotIn("unlock", self.kinds())

    def test_live_image_not_the_new_one_is_never_success(self):
        """set image 'succeeded' but the cluster still runs the old image:
        the deploy must fail, and the confirm re-read decides the lock."""
        self.f.fail.add("ignore_set")
        with self.assertRaises(Refused):
            self.apply()
        self.assertFalse(any(e["event"] == "mutation_complete" for e in self.events()))
        self.assertEqual(self.f.live, OLD)  # provably the recorded image: release is safe

    def test_restore_that_does_not_land_retains_lock(self):
        """Set-back rc 0 + healthy verify, but the live image is NOT the
        recorded one: the lock must be retained."""
        self.f.verify_results = [False, True]
        real = self.f.ssh

        def ssh(host, cmd, timeout=120):
            if " set image " in cmd and cmd.rsplit("=", 1)[1].strip("'") == OLD:
                self.f.calls.append(("ssh", cmd))
                return 0, "", ""  # claims success, changes nothing
            return real(host, cmd, timeout)
        self.f.ssh = ssh
        with self.assertRaises(Refused) as cm:
            self.apply()
        self.assertIn("lock retained", str(cm.exception))
        self.assertNotIn("unlock", self.kinds())

    def test_sources_changing_during_build_refused_before_import(self):
        real = self.f.local

        def local(argv, timeout=300):
            if argv[1] == "build":
                (self.repo / "app" / "main.py").write_text("print('edited mid-build')\n")
            return real(argv, timeout)
        self.f.local = local
        with self.assertRaises(Refused) as cm:
            self.apply()
        self.assertIn("changed while building", str(cm.exception))
        self.assertNotIn("import", self.kinds())
        self.assertEqual(self.f.live, OLD)

    def test_rollback_sets_back_the_last_deploys_previous_image(self):
        self.assertEqual(self.apply(), 0)
        new = self.f.live
        self.f.calls[:] = []
        self.assertEqual(self.apply(verb="rollback"), 0)
        self.assertEqual(self.f.live, OLD)
        self.assertFalse(any("rollout undo" in c[1] for c in self.f.calls if c[0] == "ssh"))
        self.assertNotIn("local:build", self.kinds())
        self.assertNotEqual(new, OLD)

    def test_rollback_after_failed_deploy_does_not_bring_the_bad_image_back(self):
        """The reviewer's scenario: deploy fails, set-back succeeds. The last
        COMPLETED deploy is still the earlier one, so rollback has no target
        that is live — it refuses instead of reviving the failed image."""
        self.f.verify_results = [False, True]
        with self.assertRaises(Refused):
            self.apply()
        self.assertEqual(self.f.live, OLD)
        with self.assertRaises(Refused) as cm:
            self.apply(verb="rollback")
        self.assertIn("no completed door deploy", str(cm.exception))
        self.assertEqual(self.f.live, OLD)

    def test_rollback_refuses_when_live_image_changed_since_last_deploy(self):
        self.assertEqual(self.apply(), 0)
        self.f.live = "registry.example.com/demo/web:hand-pushed"
        with self.assertRaises(Refused) as cm:
            self.apply(verb="rollback")
        self.assertIn("not the last door-deployed image", str(cm.exception))

    def test_released_sequence_data(self):
        steps = [s["step"] for s in executor.released_sequence(self.contract, HOST)]
        self.assertEqual(steps[0], "lock")
        self.assertEqual(steps[-1], "unlock")
        self.assertLess(steps.index("record_previous_image"), steps.index("set_image"))
        self.assertLess(steps.index("set_image"), steps.index("verify"))


class PreflightK3sTest(Base):
    nodes = 1

    def run_pf(self, live=OLD, policy="IfNotPresent"):
        def ssh(host, cmd, timeout=90):
            if "get deployment" in cmd:
                return 0, "%s\t%s\t1\t1" % (live, policy), ""
            if "get nodes" in cmd:
                return 0, "".join("node/n%d\n" % i for i in range(self.nodes)), ""
            if "docker ps" in cmd or "docker volume ls" in cmd:
                return 0, "", ""
            if cmd.startswith("df -Pk"):
                self.df_cmd = cmd
                return 0, ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                           "/dev/a 1 1 41000000 1% /\n/dev/a 1 1 41000000 1% /\n"
                           "MemAvailable: 2048000 kB\n"), ""
            raise AssertionError(cmd)
        return preflight.run(self.contract, HOST, Guard(_policy(), True), "", [],
                             ssh=ssh, local=mock.Mock(side_effect=AssertionError("no local")),
                             checks=lambda c, h: (True, [{"check": "http", "ok": True, "detail": ""}]),
                             blackout_runner=lambda argv, timeout=10: (0, "[]", ""),
                             fingerprint_report=lambda ctx: None,
                             remote_runner=mock.Mock(side_effect=AssertionError("no md5")))

    def status(self, r, name):
        return next(c for c in r["checks"] if c["name"] == name)["status"]

    def test_k3s_preflight_goes(self):
        r = self.run_pf()
        self.assertEqual(r["verdict"], "GO", [c for c in r["checks"] if c["status"] != "pass"])
        self.assertEqual(self.status(r, "drift"), "skip")
        self.assertIn(self.ref(), next(c for c in r["checks"] if c["name"] == "sync_plan")["evidence"])
        self.assertIn("/var/lib/rancher", self.df_cmd)
        self.assertTrue(r["plan_hash"].startswith("sha256:"))

    def test_multi_node_cluster_is_no_go(self):
        self.nodes = 3
        r = self.run_pf()
        self.assertEqual(self.status(r, "sync_plan"), "fail")
        self.assertIn("single-node", next(c for c in r["checks"] if c["name"] == "sync_plan")["evidence"])

    def test_dirty_tree_is_no_go(self):
        (self.repo / "scratch.txt").write_text("x")
        self.assertEqual(self.run_pf()["verdict"], "NO-GO")

    def test_pull_always_is_no_go(self):
        self.assertEqual(self.run_pf(policy="Always")["verdict"], "NO-GO")

    def test_already_live_warns(self):
        self.assertEqual(self.status(self.run_pf(live=self.ref()), "sync_plan"), "warn")

    def test_migrations_are_no_go_in_k3s_mode(self):
        self.contract["migrations"] = {"irreversible": False}
        self.assertEqual(self.status(self.run_pf(), "backup"), "fail")

    def test_missing_dockerfile_fails(self):
        (self.repo / "Dockerfile").unlink()
        self.assertEqual(self.status(self.run_pf(), "sync_plan"), "fail")

    def test_plan_hash_changes_with_sources(self):
        a = preflight.plan_hash(self.contract, HOST, SVC)
        (self.repo / "app" / "main.py").write_text("print('v9')\n")
        self.commit("v9")
        self.assertNotEqual(a, preflight.plan_hash(self.contract, HOST, SVC))


class BlackoutExportTest(unittest.TestCase):
    def test_reads_export_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "active.json"
            p.write_text(json.dumps([{"hostname": "edge1", "ticket": "CHG-1"}]))
            with mock.patch.object(blackout.integrations, "blackout_file", lambda p=str(p): p):
                self.assertEqual(blackout.assess(["edge1", "web2"]),
                                 ({"edge1": True, "web2": False}, "ok"))

    def test_missing_file_is_unknown_never_inside(self):
        with mock.patch.object(blackout.integrations, "blackout_file", lambda p="/nonexistent/vpscfg/active.json": p):
            self.assertEqual(blackout.assess(["edge1"]), ({"edge1": None}, "unavailable"))

    def test_oversized_or_garbage_file_is_not_ok(self):
        with tempfile.TemporaryDirectory() as d:
            big = Path(d) / "big.json"
            big.write_bytes(b"[" + b" " * (blackout.EXPORT_MAX_BYTES + 10) + b"]")
            bad = Path(d) / "bad.json"
            bad.write_text("not json")
            for path in (big, bad):
                with mock.patch.object(blackout.integrations, "blackout_file", lambda p=str(path): p):
                    windows, status = blackout.assess(["edge1"])
                    self.assertNotEqual(status, "ok")
                    self.assertIsNone(windows["edge1"])

    def test_stale_export_file_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "active.json"
            p.write_text(json.dumps([{"hostname": "edge1"}]))
            old = os.stat(p).st_mtime - blackout.EXPORT_MAX_AGE_SECONDS - 60
            os.utime(p, (old, old))
            with mock.patch.object(blackout.integrations, "blackout_file", lambda p=str(p): p):
                windows, status = blackout.assess(["edge1"])
            self.assertNotEqual(status, "ok")
            self.assertIsNone(windows["edge1"])

    def test_expired_or_inactive_entries_do_not_count(self):
        entries = [{"hostname": "a", "end_time": "2020-01-01T00:00:00Z"},
                   {"hostname": "b", "status": "ended"},
                   {"hostname": "c", "active": False},
                   {"hostname": "d", "ends_at": "not a time"},
                   {"hostname": "e", "end_time": "2999-01-01T00:00:00Z", "status": "active"},
                   {"hostname": "f"}]
        runner = lambda argv, timeout=10: (0, json.dumps(entries), "")
        windows, status = blackout.assess(list("abcdef"), runner=runner)
        self.assertEqual(status, "ok")
        self.assertEqual(windows, {"a": False, "b": False, "c": False, "d": False,
                                   "e": True, "f": True})

    def test_never_calls_nonexistent_json_flag(self):
        seen = []
        blackout.active_hosts(runner=lambda argv, timeout=10: seen.append(argv) or (0, "[]", ""))
        self.assertNotIn("--json", seen[0])


if __name__ == "__main__":
    unittest.main()
