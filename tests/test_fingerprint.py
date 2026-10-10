"""Unjournaled-change detector tests. The negative paths matter most: a
refused journal entry must NOT cover a change, an unparseable timestamp must
NOT grant coverage, and a Watchtower-shaped change with an empty journal must
alarm."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import fingerprint  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402


def _probe(stdout, rc=0):
    def prober(host, what):
        assert what == "fingerprint"
        return {"host": host, "probe": what, "rc": rc, "stdout": stdout, "stderr": ""}
    return prober


def _pod_probe(stdout, rc=0, stderr=""):
    def prober(host, what):
        assert what == "fingerprint_pods"
        return {"host": host, "probe": what, "rc": rc, "stdout": stdout,
                "stderr": stderr}
    return prober


POD_SNAP_A = ("kube-system   coredns-abc   uid-1111   2026-08-01T00:00:00Z   "
              "rancher/mirrored-coredns:1.10\n"
              "default       shop-xyz     uid-2222   2026-08-01T00:00:00Z   "
              "n8nio/n8n:1.55\n")


SNAP_A = ("/api\tsha256:aaaa1111\trunning\t2026-08-01T00:00:00Z\n"
          "/web\tsha256:bbbb2222\trunning\t2026-08-01T00:00:00Z\n")


class SnapshotTest(unittest.TestCase):
    def test_parses_inspect_lines(self):
        snap = fingerprint.snapshot("edge1", prober=_probe(SNAP_A))
        self.assertEqual(set(snap), {"api", "web"})
        self.assertEqual(snap["api"]["image"], "sha256:aaaa1111")

    def test_no_docker_is_empty_observation(self):
        snap = fingerprint.snapshot("dns1", prober=_probe("NO_DOCKER\n"))
        self.assertEqual(snap, {})

    def test_failed_probe_refuses(self):
        with self.assertRaises(Refused):
            fingerprint.snapshot("edge1", prober=_probe("", rc=255))

    def test_invalid_host_refused_before_any_path_touch(self):
        with self.assertRaises(Refused):
            fingerprint._baseline_path("../../etc/passwd")


class DiffTest(unittest.TestCase):
    def _base(self):
        return {"api": {"image": "sha256:aaaa1111", "status": "running",
                        "created": "2026-08-01T00:00:00Z"}}

    def test_no_change(self):
        self.assertEqual(fingerprint.diff(self._base(), self._base()), [])

    def test_image_change_is_watchtower_shaped(self):
        cur = self._base()
        cur["api"] = dict(cur["api"], image="sha256:ffff9999")
        changes = fingerprint.diff(self._base(), cur)
        self.assertEqual(changes[0][1], "image_changed")

    def test_recreate_same_image_detected(self):
        cur = self._base()
        cur["api"] = dict(cur["api"], created="2026-08-27T12:00:00Z")
        self.assertEqual(fingerprint.diff(self._base(), cur)[0][1], "recreated")

    def test_added_and_removed(self):
        cur = {"new": {"image": "sha256:cccc", "status": "running", "created": "x"}}
        kinds = {c[1] for c in fingerprint.diff(self._base(), cur)}
        self.assertEqual(kinds, {"added", "removed"})


class CoverageTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.jdir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, stream, records):
        with open(self.jdir / ("%s.jsonl" % stream), "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    def test_mutation_complete_covers(self):
        self._write("executor", [{"ts": "2026-08-27T12:00:00-0400",
                                  "event": "mutation_complete", "host": "edge1"}])
        hits = fingerprint.mutations_since("edge1", 0, journal_dir=self.jdir)
        self.assertEqual(len(hits), 1)

    def test_refused_never_covers(self):
        self._write("vpsexec", [{"ts": "2026-08-27T12:00:00-0400",
                                 "event": "refused", "hosts": ["edge1"]}])
        self.assertEqual(fingerprint.mutations_since("edge1", 0, journal_dir=self.jdir), [])

    def test_read_never_covers(self):
        self._write("vpsexec", [{"ts": "2026-08-27T12:00:00-0400",
                                 "event": "read", "hosts": ["edge1"]}])
        self.assertEqual(fingerprint.mutations_since("edge1", 0, journal_dir=self.jdir), [])

    def test_entry_before_baseline_does_not_cover(self):
        self._write("executor", [{"ts": "2026-08-01T00:00:00-0400",
                                  "event": "mutation_complete", "host": "edge1"}])
        far_future = 4102444800  # 2100
        self.assertEqual(fingerprint.mutations_since("edge1", far_future,
                                                     journal_dir=self.jdir), [])

    def test_unparseable_ts_fails_closed(self):
        self._write("executor", [{"ts": "not a timestamp",
                                  "event": "mutation_complete", "host": "edge1"}])
        self.assertEqual(fingerprint.mutations_since("edge1", 0, journal_dir=self.jdir), [])

    def test_other_hosts_entry_does_not_cover(self):
        self._write("executor", [{"ts": "2026-08-27T12:00:00-0400",
                                  "event": "mutation_complete", "host": "web2"}])
        self.assertEqual(fingerprint.mutations_since("edge1", 0, journal_dir=self.jdir), [])

    def test_alias_names_collapse(self):
        self._write("vpsexec", [{"ts": "2026-08-27T12:00:00-0400",
                                 "event": "mutation_complete",
                                 "hosts": ["relay2.example.net"]}])
        hits = fingerprint.mutations_since("relay2", 0,
                                           aliases={"relay2.example.net"},
                                           journal_dir=self.jdir)
        self.assertEqual(len(hits), 1)


class PodSnapshotTest(unittest.TestCase):
    def test_parses_pod_lines_keyed_by_ns_name(self):
        snap = fingerprint.snapshot_pods("edge1", prober=_pod_probe(POD_SNAP_A))
        self.assertEqual(set(snap), {"kube-system/coredns-abc",
                                     "default/shop-xyz"})
        self.assertEqual(snap["default/shop-xyz"]["images"], "n8nio/n8n:1.55")
        self.assertEqual(snap["default/shop-xyz"]["uid"], "uid-2222")

    def test_no_k3s_is_empty_observation(self):
        snap = fingerprint.snapshot_pods("relay1", prober=_pod_probe("NO_K3S\n"))
        self.assertEqual(snap, {})

    def test_k3s_host_with_dead_api_refuses_not_empty(self):
        # k3s exists but kubectl failed: rc!=0, no stdout. Reading this as
        # "no pods" would let a bypasser silence the alarm by breaking kubectl.
        with self.assertRaises(Refused):
            fingerprint.snapshot_pods(
                "edge1", prober=_pod_probe("", rc=1,
                                         stderr="connection refused"))

    def test_malformed_line_skipped(self):
        snap = fingerprint.snapshot_pods(
            "edge1", prober=_pod_probe("garbage line\n" + POD_SNAP_A))
        self.assertEqual(len(snap), 2)


class PodDiffTest(unittest.TestCase):
    def _base(self):
        return {"default/shop-xyz": {"uid": "uid-2222",
                                      "created": "2026-08-01T00:00:00Z",
                                      "images": "n8nio/n8n:1.55"}}

    def test_no_change(self):
        self.assertEqual(fingerprint.diff_pods(self._base(), self._base()), [])

    def test_image_change_detected(self):
        cur = self._base()
        cur["default/shop-xyz"] = dict(cur["default/shop-xyz"],
                                        images="n8nio/n8n:1.60")
        changes = fingerprint.diff_pods(self._base(), cur)
        self.assertEqual(changes[0][1], "image_changed")

    def test_same_image_new_uid_is_recreated(self):
        cur = self._base()
        cur["default/shop-xyz"] = dict(cur["default/shop-xyz"],
                                        uid="uid-9999")
        self.assertEqual(fingerprint.diff_pods(self._base(), cur)[0][1],
                         "recreated")

    def test_added_and_removed(self):
        cur = {"default/new-pod": {"uid": "uid-3333", "created": "x",
                                   "images": "img:1"}}
        kinds = {c[1] for c in fingerprint.diff_pods(self._base(), cur)}
        self.assertEqual(kinds, {"added", "removed"})


class ReportTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_base = fingerprint.BASELINE_DIR
        fingerprint.BASELINE_DIR = Path(self._tmp.name) / "fp"
        self._orig_jdir = fingerprint.journal.JOURNAL_DIR
        fingerprint.journal.JOURNAL_DIR = Path(self._tmp.name) / "j"

    def tearDown(self):
        fingerprint.BASELINE_DIR = self._orig_base
        fingerprint.journal.JOURNAL_DIR = self._orig_jdir
        self._tmp.cleanup()

    def _baseline(self, host="edge1", pods=None):
        snap = {"api": {"image": "sha256:aaaa1111", "status": "running",
                        "created": "2026-08-01T00:00:00Z"}}
        with mock.patch("vpscfg.telemetry.push_event"):
            fingerprint.save_baseline(host, snap, now="2026-08-20T00:00:00-0400",
                                      pods=pods)
        return snap

    BASE_PODS = {"default/shop-xyz": {"uid": "uid-2222",
                                       "created": "2026-08-01T00:00:00Z",
                                       "images": "n8nio/n8n:1.55"}}
    SAME_CONTAINERS = {"api": {"image": "sha256:aaaa1111", "status": "running",
                               "created": "2026-08-01T00:00:00Z"}}

    def test_change_with_empty_journal_is_unjournaled(self):
        self._baseline()
        cur = {"api": {"image": "sha256:ffff9999", "status": "running",
                       "created": "2026-08-01T00:00:00Z"}}
        rep = fingerprint.report("edge1", cur)
        self.assertEqual(len(rep["uncovered"]), 1)
        self.assertIn("UNJOURNALED", fingerprint.render(rep))

    def test_change_with_covering_mutation_is_accounted(self):
        self._baseline()
        jdir = fingerprint.journal.JOURNAL_DIR
        jdir.mkdir(parents=True, exist_ok=True)
        with open(jdir / "executor.jsonl", "w") as f:
            f.write(json.dumps({"ts": "2026-08-27T12:00:00-0400",
                                "event": "mutation_complete", "host": "edge1"}) + "\n")
        cur = {"api": {"image": "sha256:ffff9999", "status": "running",
                       "created": "2026-08-01T00:00:00Z"}}
        rep = fingerprint.report("edge1", cur)
        self.assertEqual(rep["uncovered"], [])

    def test_pod_change_with_empty_journal_is_unjournaled(self):
        self._baseline(pods=self.BASE_PODS)
        cur_pods = {"default/shop-xyz": {"uid": "uid-2222",
                                          "created": "2026-08-01T00:00:00Z",
                                          "images": "n8nio/n8n:1.99"}}
        rep = fingerprint.report("edge1", dict(self.SAME_CONTAINERS),
                                 current_pods=cur_pods)
        self.assertEqual(len(rep["uncovered"]), 1)
        self.assertEqual(rep["pod_changes"][0][1], "image_changed")
        self.assertIn("UNJOURNALED", fingerprint.render(rep))
        self.assertIn("default/shop-xyz", fingerprint.render(rep))

    def test_pod_change_with_covering_mutation_is_accounted(self):
        self._baseline(pods=self.BASE_PODS)
        jdir = fingerprint.journal.JOURNAL_DIR
        jdir.mkdir(parents=True, exist_ok=True)
        with open(jdir / "executor.jsonl", "w") as f:
            f.write(json.dumps({"ts": "2026-08-27T12:00:00-0400",
                                "event": "mutation_complete", "host": "edge1"}) + "\n")
        cur_pods = {"default/shop-xyz": {"uid": "uid-9999",
                                          "created": "2026-08-27T00:00:00Z",
                                          "images": "n8nio/n8n:1.55"}}
        rep = fingerprint.report("edge1", dict(self.SAME_CONTAINERS),
                                 current_pods=cur_pods)
        self.assertEqual(rep["uncovered"], [])
        self.assertEqual(rep["pod_changes"][0][1], "recreated")

    def test_old_baseline_with_live_pods_flags_unbaselined(self):
        # Baseline saved before pod fingerprinting existed (no "pods" key):
        # a k3s host with live pods is unverifiable, and that must count as
        # a change (non-zero sweep), not read as clean.
        self._baseline(pods=None)
        rep = fingerprint.report("edge1", dict(self.SAME_CONTAINERS),
                                 current_pods={"default/x": {
                                     "uid": "u", "created": "c", "images": "i"}})
        self.assertEqual(rep["pod_changes"][0][1], "unbaselined")
        self.assertEqual(len(rep["uncovered"]), 1)

    def test_old_baseline_with_no_pods_host_stays_clean(self):
        # NO_K3S host ({} observed) against a pre-pods baseline: nothing to
        # verify, no false alarm.
        self._baseline(pods=None)
        rep = fingerprint.report("edge1", dict(self.SAME_CONTAINERS),
                                 current_pods={})
        self.assertEqual(rep["pod_changes"], [])
        self.assertEqual(rep["uncovered"], [])

    def test_pods_not_probed_keeps_legacy_behavior(self):
        self._baseline(pods=self.BASE_PODS)
        rep = fingerprint.report("edge1", dict(self.SAME_CONTAINERS))
        self.assertEqual(rep["pod_changes"], [])
        self.assertEqual(rep["uncovered"], [])

    def test_no_baseline_refuses(self):
        with self.assertRaises(Refused):
            fingerprint.report("edge1", {})

    def test_corrupt_baseline_ts_fails_closed(self):
        self._baseline()
        path = fingerprint._baseline_path("edge1")
        doc = json.loads(path.read_text())
        doc["ts"] = "garbage"
        path.write_text(json.dumps(doc))
        # journal HAS a covering entry, but the window is unknowable -> alarm
        jdir = fingerprint.journal.JOURNAL_DIR
        jdir.mkdir(parents=True, exist_ok=True)
        with open(jdir / "executor.jsonl", "w") as f:
            f.write(json.dumps({"ts": "2026-08-27T12:00:00-0400",
                                "event": "mutation_complete", "host": "edge1"}) + "\n")
        cur = {"api": {"image": "sha256:ffff9999", "status": "running",
                       "created": "2026-08-01T00:00:00Z"}}
        rep = fingerprint.report("edge1", cur)
        self.assertEqual(len(rep["uncovered"]), 1)


if __name__ == "__main__":
    unittest.main()
