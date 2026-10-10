"""Wrapper tests — subprocess against a tmpdir COPY of the doors, so the real
journal and policy are never touched and no network is ever reachable (the
verbs exercised are status/refused paths only).

The governor is the example estate's (contrib/example-estate), with `deploy`
allowed so the deploy paths reach the posture check. tests/estate/ reruns
these against the estate's own governor."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "contrib" / "example-estate"


class WrapperTest(unittest.TestCase):
    # Example estate postures: db1 lockdown, edge1 test, web1 frozen.
    LOCKDOWN_HOST = "db1"
    TEST_HOST = "edge1"
    FROZEN_HOST = "web1"
    POLICIES = EXAMPLE / "policies"

    def install_governor(self, dest):
        gov = json.loads((EXAMPLE / "vpscfg-control.json").read_text())
        gov["allowed_verbs"].append("deploy")
        dest.write_text(json.dumps(gov, indent=2))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        shutil.copy(REPO / "vpscfg-control.py", self.root / "vpscfg-control.py")
        self.install_governor(self.root / "vpscfg-control.json")
        shutil.copytree(REPO / "vpscfg", self.root / "vpscfg",
                        ignore=shutil.ignore_patterns("__pycache__"))

    def tearDown(self):
        self.tmp.cleanup()

    def _clean_env(self, **extra):
        import os
        env = {k: v for k, v in os.environ.items() if not k.startswith("VPSCFG_")}
        # A copied wrapper must not read the developer's telemetry API key or
        # SSH configuration. The fixture owns its entire home directory.
        env['HOME'] = str(self.root)
        env.pop('VPSCFG_TELEMETRY_KEY', None)
        env.update(extra)
        return env

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(self.root / "vpscfg-control.py"), *args],
            capture_output=True, text=True, timeout=30, cwd=str(self.root),
            env=self._clean_env(),
        )

    def _journal(self):
        p = self.root / "journal" / "control.jsonl"
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text().splitlines()]

    def test_status_passes_and_reports_stage2(self):
        r = self._run("status")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("mode: test", r.stdout)
        self.assertIn("verified via wrapper token: True", r.stdout)

    def test_deploy_with_run_refused_on_lockdown_host(self):
        """The master switch is on, but a lockdown or frozen host stays shut —
        the door must still refuse it outright."""
        r = self._run(self.LOCKDOWN_HOST, "deploy", "somesvc", "--run")
        self.assertEqual(r.returncode, 2)
        self.assertIn("REFUSED", r.stderr)
        self.assertIn("posture", r.stderr)
        events = [e["event"] for e in self._journal()]
        self.assertIn("refused", events)

    def test_deploy_without_run_passes_governor_as_read(self):
        """Flag-sensitivity: plan/rehearsal is a read. The governor lets it
        through; it then fails in the PACKAGE for want of a contract — proving
        the refusal came from the inner layer, not the door."""
        r = self._run(self.TEST_HOST, "deploy", "no-such-service")
        self.assertEqual(r.returncode, 2)
        self.assertIn("no contract named", r.stderr)

    def test_deny_always_string_in_argv_refused(self):
        # Even a "read" invocation carrying a destructive payload is refused.
        r = self._run(self.FROZEN_HOST, "show", "docker volume prune")
        self.assertEqual(r.returncode, 2)
        self.assertIn("deny_always", r.stderr)

    def test_corrupt_policy_fails_closed(self):
        (self.root / "vpscfg-control.json").write_text("{ not json")
        r = self._run("status")
        self.assertEqual(r.returncode, 2)
        self.assertIn("REFUSED", r.stderr)

    def test_missing_policy_fails_closed(self):
        (self.root / "vpscfg-control.json").unlink()
        r = self._run("status")
        self.assertEqual(r.returncode, 2)
        self.assertIn("control file missing", r.stderr)

    def test_tampered_deny_floor_fails_closed(self):
        policy = json.loads((self.root / "vpscfg-control.json").read_text())
        policy["deny_always"] = ["something harmless"]
        (self.root / "vpscfg-control.json").write_text(json.dumps(policy))
        r = self._run("status")
        self.assertEqual(r.returncode, 2)
        self.assertIn("tampering", r.stderr)

    def test_every_invocation_is_journaled(self):
        self._run("status")
        self._run(self.LOCKDOWN_HOST, "deploy", "x", "--run")
        events = [e["event"] for e in self._journal()]
        self.assertIn("allowed_read", events)
        self.assertIn("refused", events)

    def test_direct_package_invocation_is_read_only(self):
        """Bypassing the wrapper entirely: mutations refuse, reads still work."""
        r = subprocess.run(
            [sys.executable, "-m", "vpscfg", "status"],
            capture_output=True, text=True, timeout=30, cwd=str(self.root),
            env=self._clean_env(),
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verified via wrapper token: False", r.stdout)

    def test_wrapper_impersonation_via_env_is_refused(self):
        """The hole the first test run found: a foreign VPSCFG_CONTROL_PATH +
        matching token must be refused, not honored as verified."""
        import hashlib
        evil = self.root / "evil-policy.json"
        policy = json.loads((self.root / "vpscfg-control.json").read_text())
        policy["mutation_enabled"] = True
        policy["mode"] = "released"
        evil.write_text(json.dumps(policy))
        token = hashlib.sha256(evil.read_bytes()).hexdigest()
        r = subprocess.run(
            [sys.executable, "-m", "vpscfg", "status"],
            capture_output=True, text=True, timeout=30, cwd=str(self.root),
            env=self._clean_env(
                VPSCFG_CONTROL_PATH=str(evil), VPSCFG_CONTROL_TOKEN=token
            ),
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("spoofing", r.stderr)


if __name__ == "__main__":
    unittest.main()


class WrapperLaunchFromAnyDirectory(unittest.TestCase):
    """The doors used to exec `python -m vpscfg`, which searches the working
    directory first: from anywhere but the repo the package was missing, and a
    directory carrying its own `vpscfg/` would have run that instead."""

    # Reuse the fixture only; inheriting WrapperTest would rerun its tests.
    install_governor = WrapperTest.install_governor
    POLICIES = WrapperTest.POLICIES
    setUp = WrapperTest.setUp
    tearDown = WrapperTest.tearDown
    _clean_env = WrapperTest._clean_env

    def _hostile_cwd(self):
        cwd = Path(self.tmp.name) / "elsewhere"
        pkg = cwd / "vpscfg"
        pkg.mkdir(parents=True)
        marker = cwd / "HIJACKED"
        body = f"open({str(marker)!r}, 'w').write('x')\n"
        (pkg / "__init__.py").write_text(body)
        (pkg / "__main__.py").write_text(body)
        (pkg / "vpsexec.py").write_text(body)
        return cwd, marker

    def test_control_door_runs_from_another_directory(self):
        cwd, marker = self._hostile_cwd()
        r = subprocess.run(
            [sys.executable, str(self.root / "vpscfg-control.py"), "status"],
            capture_output=True, text=True, timeout=30, cwd=str(cwd),
            env=self._clean_env(),
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verified via wrapper token: True", r.stdout)
        self.assertFalse(marker.exists(), "a vpscfg/ in the working directory ran instead of the door")

    def test_vpsexec_door_runs_from_another_directory(self):
        shutil.copy(REPO / "vpsexec", self.root / "vpsexec")
        shutil.copytree(self.POLICIES, self.root / "policies",
                        ignore=shutil.ignore_patterns("__pycache__"))
        cwd, marker = self._hostile_cwd()
        r = subprocess.run(
            [sys.executable, str(self.root / "vpsexec"), "log", "-n", "1"],
            capture_output=True, text=True, timeout=30, cwd=str(cwd),
            env=self._clean_env(),
        )
        self.assertNotIn("No module named", r.stderr)
        self.assertNotIn("ModuleNotFoundError", r.stderr)
        self.assertFalse(marker.exists(), "a vpscfg/ in the working directory ran instead of the door")

