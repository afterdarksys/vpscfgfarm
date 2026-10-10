"""Protocol approval, crash recovery, source pinning and actual executor gates."""

import copy
from datetime import datetime, timedelta, timezone
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from vpscfg import executor, repair, syncplan
from vpscfg.gates import Refused, DENY_ALWAYS_FLOOR
from vpscfg.control import Guard


class RepairProtocolTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "vpscfg").mkdir()
        (self.root / "vpscfg/executor.py").write_text("# test executor\n")
        (self.root / "vpscfg-control.py").write_text("# test wrapper\n")
        (self.root / "vpscfg-control.json").write_text("{}")
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "app").write_text("release-one")
        for args in (("init", "-q"), ("add", "app"), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")):
            subprocess.run(["git", "-C", str(self.source), *args], check=True, capture_output=True)
        self.contract = {"service": "web", "host": "host", "repo": str(self.source), "deploy_dir": "/opt/web",
                         "sync": {"include": ["app"], "never": [".env"]}, "build": "docker restart web",
                         "verify": [{"container": {"name": "web", "state": "healthy"}}],
                         "pre": [{"backup": "tar czf /root/{service}-pre-{ts}.tar.gz {deploy_dir}"}],
                         "blast_radius": {"volumes": ["web-data"], "max_other_containers": 0}}
        self.guard = Guard({"allowed_verbs": ["deploy"], "mutation_enabled": True, "mode": "released",
                            "hosts": {"host": {"posture": "released"}},
                            "scopes": {"unlocked": ["service:host/web"]}, "deny_always": DENY_ALWAYS_FLOOR}, True)
        self.state = self.root / "state.db"
        self.request = {"schema_version": 1, "kind": "repair-request", "operation_id": "gf-fixture",
                        "recipe": repair.RECIPE, "host": "host", "service": "web", "plan_checksum": "sha256:" + "a" * 64,
                        "generated_at": repair.now(), "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                        "binding": repair.describe(self.contract, self.root), "ownership_digest": "sha256:" + "b" * 64,
                        "affected_services": ["web"], "rollback_proof": {"kind": "restore-drill", "host": "host", "service": "web",
                        "verified": True, "tested_at": repair.now(), "reference": "drill-001", "verifier": "operator"}}
        self.journal = mock.patch("vpscfg.repair.journal.append", return_value={"event": "fixture", "prev": "genesis"})
        self.journal.start()
        self.addCleanup(self.journal.stop)

    def approve(self):
        return repair.approve(self.request, self.contract, self.guard, repair.digest(self.request),
                              self.state, self.root, observe=lambda c: "live-one")["approval"]

    def execute(self, approval, apply=None, observe=None):
        return repair.execute(self.request, self.contract, self.guard, approval, self.state, self.root,
                              observe=observe or (lambda c: "live-one"), apply=apply or self.success,
                              recheck=lambda: self.guard)

    def success(self, *args, **kwargs):
        kwargs["preflight"]()
        for name in ("outage-preflight", "backup", "sync", "verify", "drift-confirm", "unlock"):
            kwargs["event_sink"]({"step": name, "ok": True})
        return 0

    def test_exact_approval_and_idempotent_execution_receipt(self):
        approval = self.approve()
        apply = mock.Mock(side_effect=self.success)
        result = self.execute(approval, apply)
        self.assertEqual(result["state"], "applied")
        self.assertEqual(self.execute(approval, apply)["state"], "applied")
        self.assertEqual(apply.call_count, 1)
        self.assertEqual(result["request_digest"], repair.digest(self.request))
        self.assertEqual(repair.status("gf-fixture", self.state)["steps"], result["steps"])

    def test_approval_digest_must_match_and_approval_cannot_move_to_another_request(self):
        with self.assertRaisesRegex(Refused, "exact"):
            repair.approve(self.request, self.contract, self.guard, "wrong", self.state, self.root)
        approval = self.approve()
        self.request["operation_id"] = "gf-other"
        with self.assertRaisesRegex(Refused, "approval"):
            self.execute(approval)

    def test_live_change_is_refused_before_mutation(self):
        approval = self.approve()
        calls = []
        def apply(*args, **kwargs):
            kwargs["preflight"]()
            calls.append("mutation")
        result = self.execute(approval, apply, observe=lambda c: "live-two")
        self.assertEqual(result["state"], "refused")
        self.assertEqual(calls, [])

    def test_source_policy_executor_change_invalidates_approval(self):
        approval = self.approve()
        for path in (self.source / "app", self.root / "vpscfg-control.json", self.root / "vpscfg/executor.py"):
            original = path.read_text()
            path.write_text(original + "\n")
            with self.subTest(path=path), self.assertRaises(Refused):
                self.execute(approval)
            path.write_text(original)

    def test_interruption_stays_unknown_and_never_reexecutes(self):
        approval = self.approve()
        with self.assertRaises(KeyboardInterrupt):
            self.execute(approval, apply=mock.Mock(side_effect=KeyboardInterrupt))
        self.assertEqual(repair.status("gf-fixture", self.state)["state"], "execution-unknown")
        apply = mock.Mock()
        self.assertEqual(self.execute(approval, apply)["state"], "execution-unknown")
        apply.assert_not_called()

    def test_governor_is_rechecked_after_approval(self):
        approval = self.approve()
        self.guard.policy["mutation_enabled"] = False
        with self.assertRaises(Refused):
            self.execute(approval)

    def test_outage_checks_daemon_failure_and_new_container_limit(self):
        with self.assertRaises(Refused):
            executor.observe_outage(self.contract, "host", lambda *a: (1, "", "daemon unavailable"))
        def remote(host, command):
            return (0, "web\timage\nother\timage", "") if "docker ps" in command else (0, "web-data", "")
        with self.assertRaisesRegex(Refused, "PREVENT"):
            executor.observe_outage(self.contract, "host", remote)

    def test_outage_volume_twin_blocks_apply(self):
        def remote(host, command):
            return (0, "web\timage", "") if "docker ps" in command else (0, "web_data", "")
        with self.assertRaisesRegex(Refused, "PREVENT"):
            executor.observe_outage(self.contract, "host", remote)

    def test_missing_service_does_not_subtract_an_unrelated_container(self):
        def remote(host, command):
            return (0, "other\timage", "") if "docker ps" in command else (0, "", "")
        with self.assertRaisesRegex(Refused, "PREVENT"):
            executor.observe_outage(self.contract, "host", remote)

    def test_rename_cannot_overwrite_protected_sync_never_path(self):
        contract = copy.deepcopy(self.contract)
        contract["sync"]["include"] = [{"src": "app", "dest": ".env"}]
        with self.assertRaisesRegex(Refused, "protected"):
            syncplan.rsync_argvs(contract, dry_run=False)

    def test_rename_cannot_target_ancestor_of_protected_file(self):
        contract = copy.deepcopy(self.contract)
        contract["sync"]["include"] = [{"src": "app/.env", "dest": "config"}]
        contract["sync"]["never"] = ["config/.env"]
        with self.assertRaisesRegex(Refused, "protected"):
            syncplan.rsync_argvs(contract, dry_run=False)

    @unittest.skipUnless(shutil.which("rsync"), "rsync unavailable")
    def test_same_size_same_mtime_content_is_corrected(self):
        destination = self.root / "deployed"
        destination.mkdir()
        source = self.source / "app"
        source.write_text("GOOD")
        remote = destination / "app"
        remote.write_text("EVIL")
        os.utime(remote, ns=(source.stat().st_atime_ns, source.stat().st_mtime_ns))
        for dry_run in (True, False, True):
            argv = syncplan.rsync_argvs(self.contract, dry_run=dry_run)[0]
            argv[-1] = str(destination) + "/"
            result = subprocess.run(argv, capture_output=True, text=True, check=True)
            if not dry_run:
                self.assertEqual(remote.read_text(), "GOOD")
        self.assertEqual(result.stdout.strip(), "")

    def test_restore_health_does_not_claim_complete_rollback(self):
        approval = self.approve()
        def failed(*args, **kwargs):
            kwargs["event_sink"]({"step": "sync", "phase": "started"})
            kwargs["event_sink"]({"step": "restore-health", "ok": True})
            raise Refused("archive overlay may leave added files")
        self.assertEqual(self.execute(approval, failed)["state"], "rollback-required")

    def test_actual_executor_drift_failure_and_backup_freshness(self):
        events = []
        with mock.patch("vpscfg.executor.journal.append"):
            with self.assertRaisesRegex(Refused, "drift-confirm"):
                executor.apply(self.guard, self.contract, "deploy", "host", "service:host/web", ["docker restart web"],
                    reason="fixture", ssh=lambda *a: (0, "", ""),
                    run_local=lambda argv: (0, ">f.. app" if "--dry-run" in argv else "", ""),
                    checks=lambda *a: (True, []), latest_backup=mock.Mock(side_effect=[None, "/root/web-pre-fixture.tar.gz"]),
                    event_sink=events.append, require_backup=True)
            self.assertTrue(any(e["step"] == "drift-confirm" and not e["ok"] for e in events))
            self.assertEqual(events[-1]["step"], "lock-retained")
            with self.assertRaisesRegex(Refused, "backup-new-path"):
                executor.apply(self.guard, self.contract, "deploy", "host", "service:host/web", [], reason="fixture",
                    ssh=lambda h, c: (1 if c.startswith("test ! -e") else 0, "", ""))


if __name__ == "__main__":
    unittest.main()
