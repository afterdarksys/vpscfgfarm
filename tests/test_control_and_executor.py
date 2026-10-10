"""Control + executor tests: the two doors, and the missing firing pin.

The most important test in this repo is FiringPinTest.test_all_gates_green_still_refuses:
a maximally-permissive policy, a verified token, an unlocked scope, a clean
command — and the executor still refuses. If that test ever fails, someone has
installed the firing pin; the test failing IS the review tripwire.
"""
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import executor, journal  # noqa: E402
from vpscfg.control import Guard, _validate  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402


def _permissive_policy():
    """Everything a policy could ever legitimately open, fully open."""
    return {
        "version": 1,
        "mode": "test",
        "mutation_enabled": True,
        "allowed_verbs": ["show", "status", "deploy"],
        "scopes": {"unlocked": ["service:edge1/testsvc"], "tested": []},
        "hosts": {"edge1": {"posture": "test"}},
        "deny_always": list(DENY_ALWAYS_FLOOR),
    }


def _guard_for(policy, verified):
    """Build a Guard via the tests-only explicit-path channel — never via env,
    so no cross-test (or cross-process) contamination is possible."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(policy, f)
        path = f.name
    token = hashlib.sha256(Path(path).read_bytes()).hexdigest() if verified else None
    return Guard.load(path=path, token=token)


class FloorSyncTest(unittest.TestCase):
    def test_wrapper_and_package_floors_are_identical(self):
        """The two doors must agree on what can never open. Loaded from the
        wrapper FILE, not an import, so drift in either copy fails here."""
        spec = importlib.util.spec_from_file_location(
            "wrapper", REPO / "vpscfg-control.py"
        )
        wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wrapper)
        self.assertEqual(sorted(wrapper.DENY_ALWAYS_FLOOR), sorted(DENY_ALWAYS_FLOOR))


class PolicyValidationTest(unittest.TestCase):
    def test_dropping_a_floor_entry_is_rejected_as_tampering(self):
        p = _permissive_policy()
        p["deny_always"].remove("volume prune")
        with self.assertRaises(Refused):
            _validate(p)

    def test_bad_mode_rejected(self):
        p = _permissive_policy()
        p["mode"] = "yolo"
        with self.assertRaises(Refused):
            _validate(p)

    def test_empty_deny_rejected(self):
        p = _permissive_policy()
        p["deny_always"] = []
        with self.assertRaises(Refused):
            _validate(p)


class BypassTest(unittest.TestCase):
    """Invoking the package without the wrapper degrades to read-only, never
    to unguarded — even against a fully permissive policy."""

    def test_unverified_token_locks_mutations(self):
        guard = _guard_for(_permissive_policy(), verified=False)
        with self.assertRaises(Refused):
            guard.assert_mutation_allowed("deploy", "edge1", "service:edge1/testsvc")

    def test_unverified_token_still_allows_reads(self):
        guard = _guard_for(_permissive_policy(), verified=False)
        guard.assert_read_only_or_verified("show")  # must not raise

    def test_verified_but_lockdown_refuses(self):
        p = _permissive_policy()
        p["mode"] = "lockdown"
        guard = _guard_for(p, verified=True)
        with self.assertRaises(Refused):
            guard.assert_mutation_allowed("deploy", "edge1", "service:edge1/testsvc")

    def test_verified_but_master_switch_off_refuses(self):
        p = _permissive_policy()
        p["mutation_enabled"] = False
        guard = _guard_for(p, verified=True)
        with self.assertRaises(Refused):
            guard.assert_mutation_allowed("deploy", "edge1", "service:edge1/testsvc")

    def test_verified_but_scope_not_graduated_refuses(self):
        guard = _guard_for(_permissive_policy(), verified=True)
        with self.assertRaises(Refused):
            guard.assert_mutation_allowed("deploy", "edge1", "service:edge1/OTHER")

    def test_verified_but_frozen_host_refuses(self):
        p = _permissive_policy()
        p["hosts"]["edge1"]["posture"] = "frozen"
        guard = _guard_for(p, verified=True)
        with self.assertRaises(Refused):
            guard.assert_mutation_allowed("deploy", "edge1", "service:edge1/testsvc")


class FiringPinTest(unittest.TestCase):
    CONTRACT = {
        "service": "testsvc", "host": "edge1", "deploy_dir": "/opt/testsvc",
        "sync": {"include": ["x"], "never": [".env.production"]},
        "verify": [{"http": {"url": "http://x/health", "expect": 200}}],
        "freeze": False,
    }

    def setUp(self):
        self._orig = journal.JOURNAL_DIR
        self._tmp = tempfile.TemporaryDirectory()
        journal.JOURNAL_DIR = Path(self._tmp.name)
        self._telemetry = mock.patch('vpscfg.telemetry.push_event')
        self._telemetry.start()

    def tearDown(self):
        journal.JOURNAL_DIR = self._orig
        self._telemetry.stop()
        self._tmp.cleanup()

    def test_all_gates_green_fires_the_sequence(self):
        """THE test, inverted at Stage 2: the pin is installed, so
        all-gates-green now EXECUTES lock -> backup -> sync -> build ->
        verify -> unlock, every step journaled — via injected transports,
        so no test ever touches a real host."""
        guard = _guard_for(_permissive_policy(), verified=True)
        calls = []

        def fake_ssh(host, cmd, timeout=120):
            calls.append(("ssh", cmd))
            return 0, "", ""

        def fake_local(argv, timeout=300):
            calls.append(("local", argv[0]))
            return 0, "", ""

        def fake_checks(contract, host):
            calls.append(("verify", host))
            return True, []

        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / "x").write_text("data")
            contract = dict(self.CONTRACT, repo=repo,
                            pre=[{"backup": "tar czf /root/{service}-pre-{ts}.tar.gz {deploy_dir}"}],
                            build="docker restart testsvc")
            rc = executor.apply(guard, contract, "deploy", "edge1",
                                "service:edge1/testsvc",
                                ["docker restart testsvc"],
                                reason="pin test",
                                ssh=fake_ssh, run_local=fake_local,
                                checks=fake_checks,
                                latest_backup=mock.Mock(side_effect=[None, "/root/testsvc-pre-current.tar.gz"]))
        self.assertEqual(rc, 0)
        self.assertIn("mkdir", calls[0][1])            # lock
        backup_index = next(i for i, call in enumerate(calls) if "tar czf" in str(call))
        self.assertGreater(backup_index, 2)             # live outage probes run under lock
        self.assertNotIn("{service}", calls[backup_index][1])
        self.assertTrue(any("docker restart" in str(call) for call in calls))
        self.assertEqual(sum(call[0] == "local" for call in calls), 2)  # sync and drift confirmation
        self.assertIn("rmdir", calls[-1][1])           # unlock, always last
        entries = [json.loads(line) for line in
                   (Path(self._tmp.name) / "executor.jsonl").read_text().splitlines()]
        self.assertEqual(entries[0]["event"], "mutation_attempt")
        self.assertTrue(any(e['event'] == 'mutation_complete' for e in entries))
        self.assertEqual(entries[-1]['step'], 'unlock')

    def test_verify_failure_restores_and_retains_lock_for_reconciliation(self):
        guard = _guard_for(_permissive_policy(), verified=True)
        ssh_cmds = []

        def fake_ssh(host, cmd, timeout=120):
            ssh_cmds.append(cmd)
            return 0, "", ""

        outcomes = iter([(False, []), (True, [])])  # deploy fails, rollback verifies

        def fake_checks(contract, host):
            return next(outcomes)

        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / "x").write_text("data")
            contract = dict(self.CONTRACT, repo=repo, build="docker restart testsvc",
                            pre=[{"backup": "tar czf /root/{service}-pre-{ts}.tar.gz {deploy_dir}"}])
            with self.assertRaises(Refused) as ctx:
                executor.apply(guard, contract, "deploy", "edge1",
                               "service:edge1/testsvc",
                               ["docker restart testsvc"],
                               reason="rollback path test",
                               ssh=fake_ssh,
                               run_local=lambda argv, timeout=300: (0, "", ""),
                               checks=fake_checks,
                               latest_backup=mock.Mock(side_effect=[None, "/root/testsvc-pre-x.tar.gz"]))
        self.assertNotIsInstance(ctx.exception, executor.NotReleased)
        self.assertIn("rollback remains required", str(ctx.exception))
        import shlex
        created = next(shlex.split(c)[2] for c in ssh_cmds if c.startswith("tar czf"))
        self.assertIn("tar xzf %s -C /" % created, ssh_cmds)
        self.assertFalse(any("rmdir" in c for c in ssh_cmds))  # added files require reconciliation

    def test_deny_pattern_refuses_before_the_pin(self):
        guard = _guard_for(_permissive_policy(), verified=True)
        with self.assertRaises(Refused) as ctx:
            executor.apply(guard, dict(self.CONTRACT), "deploy", "edge1",
                           "service:edge1/testsvc",
                           ["docker volume prune -f"], reason="t")
        self.assertNotIsInstance(ctx.exception, executor.NotReleased)

    def test_frozen_contract_refuses_before_the_pin(self):
        guard = _guard_for(_permissive_policy(), verified=True)
        frozen = dict(self.CONTRACT, freeze=True)
        with self.assertRaises(Refused) as ctx:
            executor.apply(guard, frozen, "deploy", "edge1",
                           "service:edge1/testsvc", ["echo hi"], reason="t")
        self.assertNotIsInstance(ctx.exception, executor.NotReleased)


if __name__ == "__main__":
    unittest.main()
