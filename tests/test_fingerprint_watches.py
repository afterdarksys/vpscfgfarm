"""Fingerprint watches: replica hashes, never-paths, DNS pins, key census.

Judgment is local. Runners are injected. These tests do not SSH and do not
write the real journal.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import authkeys, dnspins, neverprint, replicaof, verify  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
HASH_A = "a" * 64
HASH_B = "b" * 64
LEAK = "LEAKED-FILE-BODY-do-not-echo"
KEY_LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexampleonly"


def _line_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _replica(**extra):
    spec = {
        "source_host": "web2",
        "source_path": "/etc/ssl/source.pem",
        "dest_path": "/etc/ssl/dest.pem",
        "compare": "sha256",
    }
    spec.update(extra)
    return spec


def _pair(answers):
    """Runner whose answers are (rc, text) keyed by host. Records the command."""
    calls = []

    def runner(host, remote):
        calls.append((host, remote))
        rc, text = answers[host]
        return rc, text

    runner.calls = calls
    return runner


class ReplicaOfTest(unittest.TestCase):
    def test_exact_keys_and_bad_shapes_refuse(self):
        replicaof.validate(_replica())
        verify.validate_checks({"verify": [{"replica_of": _replica()}]})
        for spec in (
            _replica(compare="cat"),
            _replica(extra=True),
            {k: v for k, v in _replica().items() if k != "compare"},
            _replica(source_host="bad host"),
            _replica(source_path="/etc/ssl/../source.pem"),
            _replica(dest_path="/tmp/foo;id"),
            _replica(source_path="relative.pem"),
        ):
            with self.assertRaises(Refused):
                replicaof.validate(spec)

    def test_remote_commands_are_hash_or_enddate_and_never_cat(self):
        sha = replicaof.remote_command("/etc/ssl/source.pem", "sha256")
        exp = replicaof.remote_command("/etc/ssl/source.pem", "expiry")
        self.assertEqual(sha, "sha256sum -- /etc/ssl/source.pem")
        self.assertEqual(exp, "openssl x509 -in /etc/ssl/source.pem -noout -enddate")
        for cmd in (sha, exp):
            self.assertNotIn("cat", cmd)
            self.assertNotIn(LEAK, cmd)
        with self.assertRaises(Refused):
            replicaof.remote_command("/etc/ssl/../source.pem", "sha256")

    def test_sha256_match_and_drift_detail_has_hashes_not_the_body(self):
        spec = _replica()
        same = _pair({"web2": (0, HASH_A + "  /etc/ssl/source.pem\n"),
                      "edge1": (0, HASH_A + "  /etc/ssl/dest.pem\n")})
        ok = replicaof.check(spec, "edge1", runner=same, now=NOW)
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["detail"], "sha256 matches")

        drift = _pair({"web2": (0, HASH_A + "  " + LEAK + "\n"),
                       "edge1": (0, HASH_B + "\n")})
        bad = replicaof.check(spec, "edge1", runner=drift, now=NOW)
        self.assertFalse(bad["ok"])
        self.assertIn(HASH_A, bad["detail"])
        self.assertIn(HASH_B, bad["detail"])
        self.assertNotIn(LEAK, bad["detail"])

    def test_unparseable_and_failed_read_do_not_echo_stdout(self):
        spec = _replica()
        junk = _pair({"web2": (0, LEAK + "\n"), "edge1": (0, HASH_A + "\n")})
        bad = replicaof.check(spec, "edge1", runner=junk, now=NOW)
        self.assertEqual(bad["detail"], "unparseable hash")
        self.assertNotIn(LEAK, bad["detail"])

        failed = _pair({"web2": (1, LEAK), "edge1": (0, HASH_A + "\n")})
        down = replicaof.check(spec, "edge1", runner=failed, now=NOW)
        self.assertEqual(down["detail"], "read failed rc=1/0")
        self.assertNotIn(LEAK, down["detail"])

    def test_expiry_match_whitespace_and_already_expired(self):
        spec = _replica(compare="expiry")
        future = "notAfter=Oct  9 12:00:00 2027 GMT\n"
        matched = _pair({"web2": (0, future), "edge1": (0, "notAfter=Oct   9  12:00:00  2027 GMT\n")})
        ok = replicaof.check(spec, "edge1", runner=matched, now=NOW)
        self.assertTrue(ok["ok"])
        self.assertIn("end dates match", ok["detail"])

        past = "notAfter=Jan  1 00:00:00 2020 GMT\n"
        expired = _pair({"web2": (0, past), "edge1": (0, past)})
        bad = replicaof.check(spec, "edge1", runner=expired, now=NOW)
        self.assertFalse(bad["ok"])
        self.assertIn("already expired", bad["detail"])
        self.assertIn("2020-01-01T00:00:00+00:00", bad["detail"])
        self.assertNotIn("differ", bad["detail"])

    def test_differing_end_dates_include_both(self):
        spec = _replica(compare="expiry")
        runner = _pair({
            "web2": (0, "notAfter=Oct  9 12:00:00 2027 GMT\n"),
            "edge1": (0, "notAfter=Nov  9 12:00:00 2027 GMT\n"),
        })
        bad = replicaof.check(spec, "edge1", runner=runner, now=NOW)
        self.assertFalse(bad["ok"])
        self.assertIn("2027-10-09T12:00:00+00:00", bad["detail"])
        self.assertIn("2027-11-09T12:00:00+00:00", bad["detail"])

    def test_naive_clock_refuses(self):
        with self.assertRaises(Refused):
            replicaof.check(_replica(), "edge1", runner=_pair({}), now=datetime(2026, 10, 9))

    def test_run_checks_uses_replica_runner_not_the_container_runner(self):
        container_calls = []
        replica_calls = []

        def container_runner(host, name):
            container_calls.append((host, name))
            return 0, "running"

        def replica_runner(host, remote):
            replica_calls.append((host, remote))
            return 0, HASH_A + "\n"

        contract = {"verify": [
            {"container": {"name": "svc", "state": "running"}},
            {"replica_of": _replica()},
        ]}
        ok, results = verify.run_checks(
            contract, "edge1", runner=container_runner, replica_runner=replica_runner)
        self.assertTrue(ok)
        self.assertEqual(container_calls, [("edge1", "svc")])
        self.assertEqual([host for host, _remote in replica_calls], ["web2", "edge1"])
        self.assertTrue(all(remote.startswith("sha256sum -- ") for _host, remote in replica_calls))
        self.assertTrue(all("sha256sum" not in name for _host, name in container_calls))


class NeverPrintTest(unittest.TestCase):
    def test_relative_without_deploy_dir_and_dotdot_refuse(self):
        with self.assertRaises(Refused):
            neverprint.never_paths({"sync": {"never": [".env.production"]}})
        with self.assertRaises(Refused):
            neverprint.never_paths({"deploy_dir": "/opt/svc", "sync": {"never": ["../etc/passwd"]}})
        with self.assertRaises(Refused):
            neverprint.never_paths({"deploy_dir": "/opt/svc", "sync": {"never": ["foo..bar"]}})
        with self.assertRaises(Refused):
            neverprint.never_paths({"deploy_dir": "/opt/svc", "sync": {"never": ["foo;rm"]}})

    def test_remote_command_is_hash_and_mode_not_cat(self):
        cmd = neverprint.remote_command("/opt/acme-api/.env.production")
        self.assertIn("sha256sum -- /opt/acme-api/.env.production", cmd)
        self.assertIn("stat -c '%a %s' -- /opt/acme-api/.env.production", cmd)
        self.assertNotIn("%%", cmd)
        self.assertNotIn("cat ", cmd)
        self.assertNotIn("cat\t", cmd)
        checked = subprocess.run(["bash", "-n", "-c", cmd], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_parser_drops_a_body_and_missing_is_a_problem(self):
        def runner(host, remote):
            return 0, LEAK + "\n"

        files = neverprint.fingerprint({
            "host": "edge1", "service": "svc", "deploy_dir": "/opt/svc",
            "sync": {"never": [".env.production"]},
        }, runner=runner)
        self.assertEqual(files, [{"path": "/opt/svc/.env.production", "exists": False}])
        self.assertNotIn(LEAK, repr(files))
        problems = neverprint.judge(files, {})
        self.assertEqual(problems[0]["kind"], "MISSING")

    def test_first_sight_is_quiet_and_hash_or_mode_change_is_drift(self):
        current = {"path": "/opt/svc/.env.production", "exists": True,
                   "sha256": HASH_A, "mode": "600", "size": 4}
        self.assertEqual(neverprint.judge([current], {}), [])
        hashed = neverprint.judge([current], {"/opt/svc/.env.production": {"sha256": HASH_B, "mode": "600"}})
        self.assertEqual(hashed[0]["kind"], "HASH")
        moded = neverprint.judge([current], {"/opt/svc/.env.production": {"sha256": HASH_A, "mode": "640"}})
        self.assertEqual(moded[0]["kind"], "MODE")
        self.assertIn("640", moded[0]["detail"])
        self.assertIn("600", moded[0]["detail"])
        both = neverprint.judge([current], {"/opt/svc/.env.production": {"sha256": HASH_B, "mode": "640"}})
        self.assertEqual(both[0]["kind"], "CHANGED")

    def test_report_records_fingerprints_on_the_never_stream(self):
        def runner(host, remote):
            return 0, "%s  /opt/svc/.env.production\n600 4\n" % HASH_A

        contract = {
            "host": "edge1", "service": "svc", "deploy_dir": "/opt/svc",
            "sync": {"never": [".env.production"]},
        }
        recorded = []
        with tempfile.TemporaryDirectory() as tmp:
            files, problems = neverprint.report(
                contract, runner=runner, journal_dir=tmp, record=recorded.append)
        self.assertEqual(problems, [])
        self.assertTrue(files[0]["exists"])
        payload = recorded[0]
        self.assertEqual(payload["event"], "neverprint")
        self.assertNotIn(LEAK, json.dumps(payload))
        self.assertNotIn("body", payload["files"][0])
        with mock.patch("vpscfg.journal.append") as append:
            neverprint.report(contract, runner=runner, journal_dir=tmp, record=None)
        append.assert_called_once()
        self.assertEqual(append.call_args[0][0], "never")
        self.assertNotEqual(append.call_args[0][0], "secrets")

    def test_last_reads_a_regular_journal_and_refuses_a_symlinked_one(self):
        line = json.dumps({"event": "neverprint", "service": "svc", "files": [
            {"path": "/opt/svc/.env.production", "exists": True, "sha256": HASH_A, "mode": "600"}]})
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(neverprint.last("svc", journal_dir=tmp), {})
            real = Path(tmp) / "elsewhere.jsonl"
            real.write_text(line + "\n")
            (Path(tmp) / "never.jsonl").symlink_to(real)
            with self.assertRaises(Refused):
                neverprint.last("svc", journal_dir=tmp)
            (Path(tmp) / "never.jsonl").unlink()
            (Path(tmp) / "never.jsonl").write_text(line + "\n")
            self.assertEqual(neverprint.last("svc", journal_dir=tmp)["/opt/svc/.env.production"]["sha256"], HASH_A)


class DnsPinsTest(unittest.TestCase):
    def test_missing_sha256_is_unpinned_and_malformed_refuses(self):
        blank = [{"name": "example.com", "host": "dns1",
                  "path": "/etc/bind/db.example", "sha256": ""}]
        gate = dnspins.readiness(blank)
        self.assertIn("UNPINNED", gate["detail"])
        calls = []
        result = dnspins.run(blank, runner=lambda *args: calls.append(args))
        self.assertFalse(result["probed"])
        self.assertEqual(calls, [])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.yaml"
            path.write_text(
                "zones:\n"
                "  - {name: example.com, host: dns1, path: /etc/bind/db.example, sha256: ZZ}\n")
            with self.assertRaises(Refused):
                dnspins.load(path)
            path.write_text("zones: []\nextra: true\n")
            with self.assertRaises(Refused):
                dnspins.load(path)
            path.write_text(
                "zones:\n"
                "  - {name: example.com, host: dns1, path: /etc/bind/../db.example, sha256: %s}\n" % HASH_A)
            with self.assertRaises(Refused):
                dnspins.load(path)
            path.write_text(
                "zones:\n"
                "  - {name: example.com, host: dns1, path: '/etc/bind/db;id', sha256: %s}\n" % HASH_A)
            with self.assertRaises(Refused):
                dnspins.load(path)

    def test_pinned_zone_compares_hash_and_hides_zone_text(self):
        zone = {"name": "example.com", "host": "dns1",
                "path": "/etc/bind/db.example", "sha256": HASH_A}
        cmd = dnspins.remote_command(zone)
        self.assertIn("sha256sum -- /etc/bind/db.example", cmd)
        self.assertIn("named-checkzone example.com /etc/bind/db.example", cmd)
        self.assertNotIn("cat", cmd)
        checked = subprocess.run(["bash", "-n", "-c", cmd], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

        def run_with(rc, text):
            calls = []

            def runner(host, remote):
                calls.append((host, remote))
                return rc, text

            result = dnspins.run([zone], runner=runner)
            return result, calls

        good, calls = run_with(0, HASH_A + "  /etc/bind/db.example\n")
        self.assertTrue(good["ok"])
        self.assertTrue(good["probed"])
        self.assertEqual(calls[0][0], "dns1")

        drift, _calls = run_with(0, HASH_B + "\n" + LEAK + "\n")
        self.assertFalse(drift["findings"][0]["ok"])
        self.assertIn(HASH_A, drift["findings"][0]["detail"])
        self.assertIn(HASH_B, drift["findings"][0]["detail"])
        self.assertNotIn(LEAK, drift["findings"][0]["detail"])

        broken, _calls = run_with(2, HASH_A + "\n" + LEAK + "\n")
        self.assertEqual(broken["findings"][0]["detail"], "named-checkzone failed rc=2")
        self.assertNotIn(LEAK, broken["findings"][0]["detail"])

        junk, _calls = run_with(0, LEAK + "\n")
        self.assertEqual(junk["findings"][0]["detail"], "unparseable zone hash")
        self.assertNotIn(LEAK, junk["findings"][0]["detail"])


class AuthKeysTest(unittest.TestCase):
    def test_pin_must_cover_governed_hosts_and_empty_lines_stay_unpinned(self):
        one = {"dns1": {"files": [{
            "path": "/root/.ssh/authorized_keys", "lines": [HASH_A], "pinned_empty": False}]}}
        gate = authkeys.readiness(one, ["dns1", "dns2"])
        self.assertIn("governed", gate["detail"])
        calls = []
        result = authkeys.run(one, ["dns1", "dns2"], runner=lambda *args: calls.append(args))
        self.assertFalse(result["probed"])
        self.assertEqual(calls, [])

        extra = dict(one)
        extra["ghost"] = one["dns1"]
        self.assertFalse(authkeys.readiness(extra, ["dns1"])["ok"])

        empty = {"dns1": {"files": [{
            "path": "/etc/sudoers", "lines": [], "pinned_empty": False}]}}
        detail = authkeys.readiness(empty, ["dns1"])["detail"]
        self.assertIn("pinned_empty", detail)
        self.assertIn("UNPINNED", detail)

    def test_remote_script_hashes_without_a_newline_and_parses(self):
        cmd = authkeys.remote_command("/root/.ssh/authorized_keys")
        self.assertIn("printf '%s'", cmd)
        self.assertNotIn("printf '%s\\n'", cmd)
        self.assertNotIn("%%", cmd)
        self.assertIn("stat -c '%a'", cmd)
        self.assertNotIn("cat", cmd)
        checked = subprocess.run(["bash", "-n", "-c", cmd], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        digest = _line_hash(KEY_LINE)
        self.assertNotEqual(digest, _line_hash(KEY_LINE + "\n"))
        self.assertEqual(len(digest), 64)

    def test_mode_and_set_compare(self):
        digest = _line_hash(KEY_LINE)
        item = {"path": "/root/.ssh/authorized_keys", "lines": [digest], "pinned_empty": False}

        def judge(mode, hashes, rc=0, lines=None):
            body = [mode] + ["%s  -" % item_hash for item_hash in hashes]
            return authkeys.judge_output("dns1", item if lines is None else dict(item, lines=lines), rc, "\n".join(body) + "\n")

        for mode in ("600", "644", "755", "0644"):
            found = judge(mode, [digest])
            self.assertTrue(found["ok"], mode)
        for mode in ("664", "666", "606"):
            found = judge(mode, [digest])
            self.assertEqual(found["state"], "MODE", mode)
            self.assertIn("writable", found["detail"])

        extra_live = judge("600", [digest, HASH_B])
        self.assertIn("2 live, 1 pinned", extra_live["detail"])
        missing_live = judge("600", [digest], lines=[digest, HASH_B])
        self.assertIn("1 live, 2 pinned", missing_live["detail"])

        empty = {"path": "/etc/sudoers", "lines": [], "pinned_empty": True}
        quiet = authkeys.judge_output("dns1", empty, 0, "600\n")
        self.assertTrue(quiet["ok"])
        noisy = authkeys.judge_output("dns1", empty, 0, "600\n%s  -\n" % digest)
        self.assertEqual(noisy["state"], "MISMATCH")

        gone = authkeys.judge_output("dns1", item, 0, "MISSING\n")
        self.assertEqual(gone["detail"], "file is missing")

    def test_leaked_key_material_is_not_echoed(self):
        item = {"path": "/root/.ssh/authorized_keys", "lines": [HASH_A], "pinned_empty": False}
        leaked = authkeys.judge_output("dns1", item, 0, KEY_LINE + "\n")
        self.assertEqual(leaked["detail"], "unparseable key census")
        self.assertNotIn("ssh-ed25519", leaked["detail"])
        self.assertNotIn("AAAA", leaked["detail"])
        begun = authkeys.judge_output("dns1", item, 0, "-----BEGIN " "OPENSSH PRIVATE KEY-----\n")
        self.assertEqual(begun["detail"], "unparseable key census")
        self.assertNotIn("PRIVATE", begun["detail"])
        self.assertNotIn("BEGIN", begun["detail"])

    def test_run_only_reads_declared_paths(self):
        digest = _line_hash(KEY_LINE)
        allow = {"dns1": {"files": [{
            "path": "/root/.ssh/authorized_keys", "lines": [digest], "pinned_empty": False}]}}
        calls = []

        def runner(host, remote):
            calls.append((host, remote))
            return 0, "600\n%s  -\n" % digest

        result = authkeys.run(allow, ["dns1"], runner=runner)
        self.assertTrue(result["ok"])
        self.assertTrue(result["probed"])
        self.assertEqual(len(calls), 1)
        self.assertIn("/root/.ssh/authorized_keys", calls[0][1])
        self.assertNotIn("sudoers", calls[0][1])

    def test_load_refuses_key_material_and_unknown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.yaml"
            path.write_text(
                "allowlist:\n"
                "  dns1:\n"
                "    files:\n"
                "      - path: /root/.ssh/authorized_keys\n"
                "        lines: ['%s']\n" % KEY_LINE)
            with self.assertRaises(Refused):
                authkeys.load(path)
            path.write_text("allowlist: {}\nextra: 1\n")
            with self.assertRaises(Refused):
                authkeys.load(path)


if __name__ == "__main__":
    unittest.main()
