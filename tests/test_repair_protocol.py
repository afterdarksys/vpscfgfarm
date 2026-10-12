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

    def host_request(self, recipe, change, operation_id="gf-host"):
        request = dict(self.request)
        request.update(operation_id=operation_id, recipe=recipe, transitions=[], change=change,
                       binding=repair.describe(self.contract, self.root))
        return request

    def upgrade_change(self, **overrides):
        change = {"family": "debian", "reboot": False, "packages": [
            {"name": "zzhostpkg", "installed": "1.0", "candidate": "1.1", "archive": "stable"}]}
        change.update(overrides)
        return change

    def assert_refused_without(self, request, text, needle):
        with self.assertRaises(Refused) as caught:
            repair.check_request(request, self.contract, self.root)
        self.assertIn(text, str(caught.exception))
        self.assertNotIn(needle, str(caught.exception))

    def test_describe_advertises_host_recipes_and_keeps_the_deploy_recipe_field(self):
        described = repair.describe(self.contract, self.root)
        self.assertEqual(described["recipe"], repair.RECIPE)
        self.assertEqual(described["supported_recipes"], list(repair.SUPPORTED_RECIPES))

    def test_dirty_checkout_still_blocks_describe(self):
        (self.source / "app").write_text("dirty")
        with self.assertRaisesRegex(Refused, "clean"):
            repair.describe(self.contract, self.root)

    def test_service_deploy_accepts_transitions_and_refuses_a_change_object(self):
        self.request["transitions"] = []
        self.assertEqual(repair.check_request(self.request, self.contract, self.root)["recipe"], repair.RECIPE)
        self.request["change"] = self.upgrade_change()
        self.assert_refused_without(self.request, "change object", "zzhostpkg")

    def test_unknown_recipe_is_refused_without_echoing_it(self):
        self.request["recipe"] = "apt-get/v1"
        self.assert_refused_without(self.request, "invalid operation or recipe", "apt-get")

    def test_host_change_rejects_shell_metacharacters_without_echoing_them(self):
        for name in ("openssl;id", "$(id)", "`id`", "-rf", "../openssl", "a..b", ".openssl"):
            with self.subTest(name=name):
                request = self.host_request(repair.DISTRO_SECURITY_UPGRADE, self.upgrade_change(packages=[
                    {"name": name, "installed": "1", "candidate": "2", "archive": ""}]))
                self.assert_refused_without(request, "invalid package name", name)

    def test_upgrade_change_shape_fails_closed(self):
        extra = self.upgrade_change(command="apt-get install zzhostpkg")
        self.assert_refused_without(self.host_request(repair.DISTRO_SECURITY_UPGRADE, extra),
                                    "invalid upgrade change", "apt-get")
        alpine = self.upgrade_change(family="alpine")
        self.assert_refused_without(self.host_request(repair.DISTRO_SECURITY_UPGRADE, alpine),
                                    "invalid package family", "alpine")
        for flag in (True, 1, "false", None):
            with self.subTest(flag=flag):
                request = self.host_request(repair.DISTRO_SECURITY_UPGRADE, self.upgrade_change(reboot=flag))
                with self.assertRaisesRegex(Refused, "upgrade reboot flag must be false"):
                    repair.check_request(request, self.contract, self.root)
        empty = self.upgrade_change(packages=[])
        with self.assertRaisesRegex(Refused, "invalid package list"):
            repair.check_request(self.host_request(repair.DISTRO_SECURITY_UPGRADE, empty), self.contract, self.root)
        too_many = self.upgrade_change(packages=[
            {"name": "p%d" % i, "installed": "1", "candidate": "2", "archive": ""} for i in range(65)])
        with self.assertRaisesRegex(Refused, "invalid package list"):
            repair.check_request(self.host_request(repair.DISTRO_SECURITY_UPGRADE, too_many), self.contract, self.root)
        duplicate = self.upgrade_change(packages=[
            {"name": "zzhostpkg", "installed": "1", "candidate": "2", "archive": ""},
            {"name": "zzhostpkg", "installed": "1", "candidate": "2", "archive": ""}])
        self.assert_refused_without(self.host_request(repair.DISTRO_SECURITY_UPGRADE, duplicate),
                                    "duplicate package name", "zzhostpkg")

    def test_reboot_change_shape_and_real_package_versions(self):
        kernel = "5.14.0-362.el9_3.x86_64"
        reboot = {"family": "rpm", "packages": [], "reboot": True, "running_kernel": kernel}
        self.assertEqual(repair.check_request(
            self.host_request(repair.REBOOT, reboot), self.contract, self.root)["change"]["running_kernel"], kernel)
        debian = self.upgrade_change(packages=[{
            "name": "openssl", "installed": "3.0.11-1", "candidate": "1:2.36-9+deb12u7",
            "archive": "3.0.11-1~deb12u2"}])
        self.assertEqual(repair.check_request(
            self.host_request(repair.DISTRO_SECURITY_UPGRADE, debian), self.contract, self.root)["recipe"],
            repair.DISTRO_SECURITY_UPGRADE)
        named = dict(reboot, packages=[{"name": "zzhostpkg"}])
        self.assert_refused_without(self.host_request(repair.REBOOT, named),
                                    "reboot change must not name packages", "zzhostpkg")
        for flag in (False, 1, "true"):
            with self.subTest(flag=flag):
                request = self.host_request(repair.REBOOT, dict(reboot, reboot=flag))
                with self.assertRaisesRegex(Refused, "reboot flag must be true"):
                    repair.check_request(request, self.contract, self.root)
        missing = {key: reboot[key] for key in reboot if key != "running_kernel"}
        with self.assertRaisesRegex(Refused, "invalid reboot change"):
            repair.check_request(self.host_request(repair.REBOOT, missing), self.contract, self.root)
        bad_kernel = dict(reboot, running_kernel="5.14;reboot")
        self.assert_refused_without(self.host_request(repair.REBOOT, bad_kernel),
                                    "invalid running kernel", "reboot")

    def test_upgrade_accepts_the_archive_badfarm_reads_from_apt_and_dnf(self):
        for archive in ("Debian-Security:12/stable-security", "Ubuntu:22.04/jammy-security",
                        "bookworm-security", "RHSA-2024:1234", ""):
            with self.subTest(archive=archive):
                request = self.host_request(repair.DISTRO_SECURITY_UPGRADE, self.upgrade_change(packages=[
                    {"name": "openssl", "installed": "3.0.11-1~deb12u2", "candidate": "3.0.15-1~deb12u1",
                     "archive": archive}]))
                self.assertEqual(repair.check_request(request, self.contract, self.root)["recipe"],
                                 repair.DISTRO_SECURITY_UPGRADE)

    def test_upgrade_archive_refuses_traversal_and_metacharacters_without_echoing_them(self):
        for archive in ("/etc/apt", "a/../b", "a//b", "a/", "-x", "stable;id", "$(id)/x", "a b", "x" * 129):
            with self.subTest(archive=archive):
                request = self.host_request(repair.DISTRO_SECURITY_UPGRADE, self.upgrade_change(packages=[
                    {"name": "openssl", "installed": "1", "candidate": "2", "archive": archive}]))
                self.assert_refused_without(request, "invalid package archive", archive)

    def test_host_recipe_refuses_transitions_and_a_hand_edited_binding(self):
        request = self.host_request(repair.DISTRO_SECURITY_UPGRADE, self.upgrade_change())
        request["transitions"] = [{"from_asset_id": "asset-1"}]
        with self.assertRaisesRegex(Refused, "asset transitions"):
            repair.check_request(request, self.contract, self.root)
        request = self.host_request(repair.DISTRO_SECURITY_UPGRADE, self.upgrade_change())
        request["binding"] = dict(request["binding"], supported_recipes=["service-deploy/v1"])
        with self.assertRaisesRegex(Refused, "changed"):
            repair.check_request(request, self.contract, self.root)

    def test_host_approve_uses_a_local_preflight_and_stage_zero_writes_nothing(self):
        request = self.host_request(repair.DISTRO_SECURITY_UPGRADE, self.upgrade_change())
        def boom(_contract):
            raise AssertionError("live snapshot")
        granted = repair.approve(request, self.contract, self.guard, repair.digest(request),
                                 self.state, self.root, observe=boom)
        self.assertEqual(len(granted["approval"]), 64)
        import sqlite3
        with sqlite3.connect(self.state) as db:
            payload = json.loads(db.execute("SELECT payload FROM approvals").fetchone()[0])
        self.assertEqual(payload["preflight"], repair.digest(
            {"recipe": request["recipe"], "change": request["change"], "contact": "none"}))
        self.assertNotIn("zzhostpkg", json.dumps(payload))
        approved = [call.args[1] for call in repair.journal.append.call_args_list if call.args[1].get("event") == "approved"]
        self.assertEqual(set(approved[0]), {"event", "operation_id", "request_digest"})
        self.assertNotIn("zzhostpkg", json.dumps(approved[0]))
        off = self.root / "absent.db"
        self.guard.policy["mutation_enabled"] = False
        with self.assertRaises(Refused):
            repair.approve(request, self.contract, self.guard, repair.digest(request), off, self.root, observe=boom)
        self.assertFalse(off.exists())

    def test_host_execute_consumes_the_approval_and_sends_no_command(self):
        request = self.host_request(repair.REBOOT, {
            "family": "debian", "packages": [], "reboot": True, "running_kernel": "6.1.0-18-amd64"})
        approval = repair.approve(request, self.contract, self.guard, repair.digest(request),
                                  self.state, self.root, observe=lambda _c: (_ for _ in ()).throw(AssertionError("observe")))
        apply = mock.Mock(side_effect=AssertionError("apply"))
        with mock.patch("vpscfg.repair.live_snapshot", side_effect=AssertionError("snapshot")), \
                mock.patch("vpscfg.repair.isolated_source", side_effect=AssertionError("source")), \
                mock.patch("vpscfg.executor._default_ssh", side_effect=AssertionError("ssh")):
            receipt = repair.execute(request, self.contract, self.guard, approval["approval"], self.state, self.root,
                                     observe=lambda _c: (_ for _ in ()).throw(AssertionError("observe")),
                                     apply=apply, recheck=lambda: self.guard)
            again = repair.execute(request, self.contract, self.guard, approval["approval"], self.state, self.root,
                                   observe=lambda _c: (_ for _ in ()).throw(AssertionError("observe")),
                                   apply=apply, recheck=lambda: self.guard)
        apply.assert_not_called()
        self.assertEqual(receipt["state"], "refused")
        self.assertEqual(again["state"], "refused")
        self.assertEqual(receipt["error"], repair.HOST_NOT_GRADUATED)
        self.assertEqual(receipt["steps"], [{"step": "host-recipe", "ok": False}])
        self.assertNotIn("6.1.0-18-amd64", json.dumps(receipt))
        import sqlite3
        with sqlite3.connect(self.state) as db:
            self.assertEqual(db.execute("SELECT used FROM approvals").fetchone()[0], 1)
            stored = db.execute("SELECT payload FROM operations").fetchone()[0]
        self.assertNotIn("6.1.0-18-amd64", stored)
        refused = [call.args[1] for call in repair.journal.append.call_args_list if call.args[1].get("event") == "refused"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(set(refused[0]), {"event", "operation_id", "recipe", "request_digest"})
        self.assertNotIn("6.1.0-18-amd64", json.dumps(refused[0]))

    def test_host_execute_rechecks_the_governor_before_consuming_the_approval(self):
        request = self.host_request(repair.DISTRO_SECURITY_UPGRADE, self.upgrade_change(), operation_id="gf-host-gate")
        approval = repair.approve(request, self.contract, self.guard, repair.digest(request),
                                  self.state, self.root, observe=lambda _c: "unused")
        policy = copy.deepcopy(self.guard.policy)
        policy["mutation_enabled"] = False
        with self.assertRaises(Refused):
            repair.execute(request, self.contract, self.guard, approval["approval"], self.state, self.root,
                           apply=mock.Mock(side_effect=AssertionError("apply")),
                           recheck=lambda: Guard(policy, True))
        import sqlite3
        with sqlite3.connect(self.state) as db:
            self.assertEqual(db.execute("SELECT used FROM approvals").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
