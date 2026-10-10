"""Fleet-watch gaps: coverage, duration, OS nag, twins, image pins, postgres shape.

Judgment is local. These tests inject probe text. They do not SSH.
"""
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import contracts, coverage, healthdur, hostos, imagepin, pgtopology, probe  # noqa: E402
from vpscfg import authority  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402
from vpscfg.probesplit import sections  # noqa: E402

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)


def _base_contract(**extra):
    doc = {
        "service": "svc",
        "host": "edge1",
        "deploy_dir": "/opt/svc",
        "sync": {"include": ["compose.yml"], "never": [".env.production"]},
        "verify": [{"container": {"name": "svc", "state": "running"}}],
    }
    doc.update(extra)
    return doc


def _decl(host, names, namespace=None, deployments=None):
    return {
        "host": host,
        "service": next(iter(names)),
        "names": set(names),
        "namespace": namespace,
        "deployments": list(deployments or []),
    }


class ProbeShapeTest(unittest.TestCase):
    def test_new_probes_are_fixed_shell(self):
        for name in ("workloads", "health"):
            cmd = probe.COMMANDS[name]
            self.assertNotIn("%s", cmd)
            self.assertNotIn("{0}", cmd)
            self.assertFalse(cmd.rstrip().endswith("true"))
            checked = subprocess.run(["bash", "-n", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_sections_drop_preamble(self):
        parts = sections("noise\n@@@containers\na\n@@@pods\nNO_K3S\n")
        self.assertEqual(parts["containers"], "a")
        self.assertEqual(parts["pods"], "NO_K3S")
        self.assertNotIn("noise", parts)


class CoverageTest(unittest.TestCase):
    def test_stopped_is_ignored_and_empty_host_is_not_bare(self):
        containers = coverage.parse_containers("gone\timg\tExited (0) 1 day ago\n")
        report = coverage.judge("dns1", {"dns1"}, containers, [], [])
        self.assertTrue(report["ok"])
        self.assertFalse(report["bare"])
        self.assertEqual(report["running"], 0)

    def test_uncovered_running_workload(self):
        containers = coverage.parse_containers("orphan\timg\tUp 2 hours\n")
        decls = [_decl("web2", {"blobstore"})]
        report = coverage.judge("web2", {"web2"}, containers, [], decls)
        self.assertFalse(report["ok"])
        self.assertFalse(report["bare"])
        self.assertEqual(report["uncovered"][0]["name"], "orphan")

    def test_bare_when_nothing_declares_the_host(self):
        containers = coverage.parse_containers("/web\timg\tRestarting (1) 2 seconds ago\n")
        report = coverage.judge("web3", {"web3"}, containers, [], [_decl("edge1", {"web"})])
        self.assertTrue(report["bare"])
        self.assertFalse(report["ok"])

    def test_skeleton_name_covers_and_frozen_namespace_is_skipped(self):
        containers = coverage.parse_containers("traefik\timg\tUp 1 second\n")
        pods, err = coverage.parse_pods(
            "kube-system coredns-6d4b75cb6d-abcde Running <none> 0 registry.k8s.io/coredns:1.11\n"
            "blobstore blobstore-api-7f8b9c6d4-xk2lp Running <none> 3 img:1\n")
        self.assertIsNone(err)
        self.assertEqual(coverage.pod_owner("blobstore-api-7f8b9c6d4-xk2lp"), "blobstore-api")
        self.assertEqual(coverage.pod_owner("shop-redis"), "shop-redis")
        decls = [
            _decl("web2", {"traefik", "blobstore-api"}, namespace="blobstore",
                  deployments=["blobstore-api"]),
        ]
        report = coverage.judge("web2", {"web2"}, containers, pods, decls)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["running"], 2)

    def test_namespace_must_match_when_declared(self):
        pods, err = coverage.parse_pods(
            "other blobstore-api-7f8b9c6d4-xk2lp Running <none> 0 img:1\n")
        self.assertIsNone(err)
        decls = [_decl("web2", {"blobstore-api"}, namespace="blobstore",
                       deployments=["blobstore-api"])]
        report = coverage.judge("web2", {"web2"}, [], pods, decls)
        self.assertFalse(report["ok"])

    def test_pod_probe_error_is_unverified(self):
        pods, err = coverage.parse_pods("error: the server is down\n")
        self.assertIsNotNone(err)
        report = coverage.judge("web2", {"web2"}, [], pods, [], pod_error=err)
        self.assertFalse(report["ok"])
        self.assertIn("UNVERIFIED", report["uncovered"][0]["detail"])

    def test_empty_pod_body_is_unverified_and_no_k3s_is_empty(self):
        _rows, err = coverage.parse_pods("")
        self.assertEqual(err, "pod probe produced nothing")
        rows, err = coverage.parse_pods("NO_K3S")
        self.assertEqual(rows, [])
        self.assertIsNone(err)
        self.assertEqual(coverage.parse_containers("NO_DOCKER"), [])

    def test_broken_skeleton_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skeletons").mkdir()
            (root / "skeletons" / "bad.yaml").write_text("just a string\n")
            with self.assertRaises(Refused):
                coverage.load_index(root)


class HealthTest(unittest.TestCase):
    def _docker(self, line):
        return healthdur.parse_docker(line)

    def test_contract_cannot_loosen_the_ceiling(self):
        healthdur.validate_watch({"watch": {"unhealthy_max": "10m"}})
        healthdur.validate_watch({"watch": {"unhealthy_max": "9m"}})
        with self.assertRaises(Refused):
            healthdur.validate_watch({"watch": {"unhealthy_max": "1h"}})
        with self.assertRaises(Refused):
            healthdur.validate_watch({"watch": {"unhealthy_max": "601s"}})
        with self.assertRaises(Refused):
            contracts._validate(_base_contract(watch={"unhealthy_max": "1h"}), "fixture")
        contracts._validate(_base_contract(), "fixture")
        contracts._validate(_base_contract(watch={"unhealthy_max": "60s"}), "fixture")

    def test_young_single_restart_is_quiet_and_fresh_restarting_is_quiet(self):
        young = "2026-10-09T11:59:58Z"
        quiet = healthdur.judge(
            self._docker("web\trunning\t-\t%s\t1\t0" % young), [], NOW)
        self.assertTrue(quiet["ok"])
        restarting = healthdur.judge(
            self._docker("web\trestarting\t-\t%s\t1\t0" % young), [], NOW)
        self.assertTrue(restarting["ok"])

    def test_crashloop_with_high_restarts_alarms_while_young(self):
        pods, err = healthdur.parse_pods(
            "blobstore blobstore-api-7f8b9c6d4-xk2lp Running CrashLoopBackOff "
            "4123 2026-10-09T11:59:58Z\n")
        self.assertIsNone(err)
        report = healthdur.judge([], pods, NOW)
        self.assertFalse(report["ok"])
        self.assertIn("4123", report["findings"][0]["detail"])

    def test_old_unhealthy_and_long_streak_alarm_and_a_tighter_watch_fires_sooner(self):
        old = (NOW - timedelta(seconds=700)).strftime("%Y-%m-%dT%H:%M:%SZ")
        report = healthdur.judge(
            self._docker("web\trunning\tunhealthy\t%s\t0\t0" % old), [], NOW)
        self.assertFalse(report["ok"])
        young = "2026-10-09T11:59:58Z"
        streak = healthdur.judge(
            self._docker("web\trunning\tunhealthy\t%s\t0\t21" % young), [], NOW)
        self.assertFalse(streak["ok"])
        watches = [{"names": {"api"}, "unhealthy_max": 60}]
        early = healthdur.judge(
            self._docker("api\trunning\tunhealthy\t%s\t0\t0" % young), [], NOW, watches=watches)
        # 2s is under a 60s ceiling and the restart floor.
        self.assertTrue(early["ok"])
        mid = (NOW - timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        tightened = healthdur.judge(
            self._docker("api\trunning\tunhealthy\t%s\t0\t0" % mid), [], NOW, watches=watches)
        self.assertFalse(tightened["ok"])
        fleet = healthdur.judge(
            self._docker("api\trunning\tunhealthy\t%s\t0\t0" % mid), [], NOW)
        self.assertTrue(fleet["ok"])

    def test_healthy_restart_floor_still_alarms(self):
        young = "2026-10-09T11:59:58Z"
        report = healthdur.judge(
            self._docker("web\trunning\t-\t%s\t5\t0" % young), [], NOW)
        self.assertFalse(report["ok"])


class HostOsTest(unittest.TestCase):
    def test_missing_host_is_unpinned_and_eol_fails(self):
        declared = {
            "edge1": {"os": "Debian 10", "eol": True},
            "ci1": {"os": "Debian 12", "eol": False},
        }
        findings = hostos.nag(["ci1", "edge1", "ghost"], declared=declared)
        by_host = {}
        for item in findings:
            by_host.setdefault(item["host"], []).append(item)
        self.assertFalse(by_host["ghost"][0]["ok"])
        self.assertEqual(by_host["ghost"][0]["state"], "UNPINNED")
        self.assertEqual(by_host["edge1"][0]["state"], "EOL")
        self.assertTrue(by_host["ci1"][0]["ok"])

    def test_live_line_mismatch_fails_without_echoing_it(self):
        declared = {"ci1": {"os": "Debian 12", "eol": False}}
        findings = hostos.nag(["ci1"], declared=declared,
                              live={"ci1": "Debian GNU/Linux 10 (buster)"})
        bad = [item for item in findings if not item["ok"]]
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0]["state"], "MISMATCH")
        self.assertNotIn("buster", bad[0]["detail"])
        quiet = hostos.nag(["ci1"], declared=declared,
                           live={"ci1": "Debian GNU/Linux 12 (bookworm)"})
        self.assertTrue(all(item["ok"] for item in quiet))

    def test_unknown_key_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "host-os.yaml"
            path.write_text("hosts:\n  edge1: {os: Debian 10, eol: true, cve: true}\n")
            with self.assertRaises(Refused):
                hostos.load(path)


class FleetWatchTest(unittest.TestCase):
    def test_a_refused_host_os_pin_still_runs_the_chain_check(self):
        from unittest import mock
        from vpscfg import cli
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "svc.yaml").write_text("service: svc\n")
            with mock.patch.object(cli, "CONTRACT_DIR", Path(tmp)), \
                    mock.patch.object(cli.contracts, "load", return_value={"host": "edge1"}), \
                    mock.patch.object(cli.verify, "run_checks", return_value=(True, [])), \
                    mock.patch.object(cli.verify, "render", return_value=""), \
                    mock.patch.object(cli, "_governed_docker_hosts", return_value={"edge1": {"edge1"}}), \
                    mock.patch.object(hostos, "nag", side_effect=Refused("host OS pin missing")), \
                    mock.patch("vpscfg.journal.streams", return_value=["watch"]), \
                    mock.patch("vpscfg.journal.chain_verify", return_value={"problems": []}) as chain, \
                    mock.patch("vpscfg.journal.append") as append:
                rc = cli._fleet_watch()
        self.assertEqual(rc, 1)
        chain.assert_called_once_with("watch")
        record = append.call_args[0][1]
        self.assertEqual(record["event"], "fleet_watch")
        self.assertIsNone(record["eol"])
        self.assertEqual(record["failures"], 1)


class TwinsTest(unittest.TestCase):
    def test_unknown_authority_key_refused_and_absent_is_fine(self):
        authority.validate({})
        authority.validate({"authority": {"name": "keyvault", "runtime": "k3s"}})
        with self.assertRaises(Refused):
            authority.validate({"authority": {"name": "keyvault", "runtime": "k3s", "stop": True}})
        with self.assertRaises(Refused):
            contracts._validate(_base_contract(
                authority={"name": "keyvault", "runtime": "both"}), "fixture")

    def test_declared_and_live_twins(self):
        one = {"service": "kv-api", "host": "web1",
               "authority": {"name": "keyvault", "runtime": "compose"}}
        two = {"service": "kv-prod", "host": "web2",
               "authority": {"name": "keyvault", "runtime": "k3s"}}
        report = authority.judge([one, two], {})
        self.assertFalse(report["ok"])
        self.assertEqual(report["findings"][0]["kind"], "declared")
        live = authority.judge([], {"web1": ["web"], "web2": ["web", "other"]})
        self.assertFalse(live["ok"])
        self.assertEqual(live["findings"][0]["name"], "web")
        quiet = authority.judge([one], {"web1": ["web"], "web2": ["api"]})
        self.assertTrue(quiet["ok"])


class ImagePinTest(unittest.TestCase):
    def test_absent_policy_fails_on_floating_and_watch_does_not(self):
        bare = {"service": "blobstore"}
        policies = imagepin.policies_from([bare], lambda _c: {"api"})
        floating = imagepin.judge([{"name": "api", "image": "repo/api:latest"}], policies)
        self.assertFalse(floating["ok"])
        self.assertEqual(floating["findings"][0]["state"], "UNPINNED")
        untagged = imagepin.judge([{"name": "api", "image": "repo/api"}], policies)
        self.assertFalse(untagged["ok"])
        watched = {"service": "blobstore", "image_policy": {"updates": "watch"}}
        policies = imagepin.policies_from([watched], lambda _c: {"api"})
        noted = imagepin.judge([{"name": "api", "image": "repo/api:latest"}], policies)
        self.assertTrue(noted["ok"])
        self.assertEqual(noted["findings"][0]["state"], "watch")
        pinned_tag = imagepin.judge([{"name": "api", "image": "repo/api:1.2.3"}], policies)
        self.assertTrue(pinned_tag["ok"])
        self.assertEqual(pinned_tag["findings"], [])

    def test_digest_mismatch_fails_closed_without_printing_the_digest(self):
        contract = {"service": "api", "image_policy": {
            "updates": "pinned",
            "pins": [{"name": "api", "digest": DIGEST_A}],
        }}
        policies = imagepin.policies_from([contract], lambda _c: {"api"})
        bad = imagepin.judge([{"name": "api", "image": "repo/api@" + DIGEST_B}], policies)
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["findings"][0]["detail"], "live digest does not match the pin")
        self.assertNotIn(DIGEST_A, bad["findings"][0]["detail"])
        self.assertNotIn(DIGEST_B, bad["findings"][0]["detail"])
        good = imagepin.judge([{"name": "api", "image": "repo/api@" + DIGEST_A}], policies)
        self.assertTrue(good["ok"])
        self.assertEqual(good["findings"], [])
        missing = imagepin.judge([{"name": "api", "image": "repo/api:1.2.3"}], policies)
        self.assertFalse(missing["ok"])

    def test_unknown_image_policy_refused_and_uncovered_names_ignored(self):
        with self.assertRaises(Refused):
            imagepin.validate({"image_policy": {"updates": "latest"}})
        policies = imagepin.policies_from(
            [{"service": "api"}], lambda _c: {"api"})
        report = imagepin.judge([{"name": "stranger", "image": "repo/x:latest"}], policies)
        self.assertTrue(report["ok"])

    def test_digest_and_floating_helpers(self):
        self.assertFalse(imagepin.floating("repo/app@" + DIGEST_A))
        self.assertFalse(imagepin.floating("repo/app:1"))
        self.assertTrue(imagepin.floating("repo/app:latest"))
        self.assertTrue(imagepin.floating("repo/app"))
        self.assertFalse(imagepin.floating(""))


class PostgresShapeTest(unittest.TestCase):
    def test_fewer_than_two_is_unpinned(self):
        report = pgtopology.judge([{"service": "only", "postgres": {"role": "primary"}}])
        self.assertFalse(report["ok"])
        self.assertEqual(report["state"], "UNPINNED")
        empty = pgtopology.judge([{"service": "web"}])
        self.assertFalse(empty["ok"])

    def test_complete_shape_passes_and_a_replica_without_verify_does_not(self):
        primary = {"service": "pg-a", "host": "web1", "postgres": {"role": "primary", "container": "pg"}}
        replica = {"service": "pg-b", "host": "edge1",
                   "postgres": {"role": "replica", "replicates": "pg-a", "container": "pg"},
                   "verify": [{"pg_replication": {"container": "pg"}}]}
        report = pgtopology.judge([primary, replica])
        self.assertTrue(report["ok"], report)
        replica["verify"] = [{"container": {"name": "pg"}}]
        bare = pgtopology.judge([primary, replica])
        self.assertFalse(bare["ok"])
        self.assertIn("pg_replication", bare["detail"])

    def test_wrong_shape_refuses_or_stays_unpinned(self):
        with self.assertRaises(Refused):
            pgtopology.validate({"postgres": {"role": "primary", "replicates": "other"}})
        with self.assertRaises(Refused):
            pgtopology.validate({"postgres": {"role": "replica"}})
        pgtopology.validate({})
        drifted = pgtopology.judge([
            {"service": "pg-a", "postgres": {"role": "primary"}},
            {"service": "pg-b", "postgres": {"role": "replica", "replicates": "nope"},
             "verify": [{"pg_replication": {}}]},
        ])
        self.assertFalse(drifted["ok"])


if __name__ == "__main__":
    unittest.main()
