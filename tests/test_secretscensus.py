"""Secrets census + escrow tests. Per SECURITY-RULES, the negative paths are
the asset: refuses without age, refuses bad recipients, path validation
rejects traversal, plaintext never lands on local disk, failures delete
partial output."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import secretscensus  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

CONTRACT = {
    "service": "svc", "host": "edge1", "deploy_dir": "/opt/svc",
    "sync": {"include": [], "never": [".env.production", ".git"]},
    "verify": [],
}


class CredentialPathTest(unittest.TestCase):
    def test_explicit_credentials_win(self):
        c = dict(CONTRACT, credentials=["/etc/svc/server.key", "conf/.env.local"])
        self.assertEqual(secretscensus.credential_paths(c),
                         ["/etc/svc/server.key", "/opt/svc/conf/.env.local"])

    def test_fallback_is_env_entries_from_sync_never(self):
        self.assertEqual(secretscensus.credential_paths(CONTRACT),
                         ["/opt/svc/.env.production"])

    def test_traversal_is_refused(self):
        c = dict(CONTRACT, credentials=["../../etc/shadow"])
        with self.assertRaises(Refused):
            secretscensus.credential_paths(c)

    def test_shell_metacharacters_are_refused(self):
        for evil in ["/opt/x;rm -rf /", "/opt/$(whoami)", "/opt/a b", "/opt/x`y`"]:
            c = dict(CONTRACT, credentials=[evil])
            with self.assertRaises(Refused):
                secretscensus.credential_paths(c)


class CensusTest(unittest.TestCase):
    def test_existing_file_is_fingerprinted(self):
        def runner(host, remote):
            self.assertIn("sha256sum", remote)
            # PATH_RE already guarantees no shell metacharacters, so
            # shlex.quote may legitimately leave the path bare.
            self.assertIn("/opt/svc/.env.production", remote)
            return 0, "abc123  /opt/svc/.env.production\n512 1700000000\n"
        files = secretscensus.census(CONTRACT, runner=runner)
        self.assertEqual(files, [{"path": "/opt/svc/.env.production",
                                  "exists": True, "sha256": "abc123",
                                  "size": 512, "mtime": 1700000000}])

    def test_missing_file_is_a_fact_not_an_error(self):
        files = secretscensus.census(CONTRACT, runner=lambda h, r: (0, ""))
        self.assertEqual(files, [{"path": "/opt/svc/.env.production",
                                  "exists": False}])

    def test_census_never_ships_contents(self):
        # The remote command must only ever hash and stat — no cat, no cp.
        def runner(host, remote):
            for banned in ("cat ", "cp ", "scp", "base64"):
                self.assertNotIn(banned, remote)
            return 0, ""
        secretscensus.census(CONTRACT, runner=runner)


class CensusDriftTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.jdir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _journal(self, records):
        with open(self.jdir / "secrets.jsonl", "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    def test_changed_hash_is_flagged(self):
        self._journal([{"event": "census", "service": "svc", "files": [
            {"path": "/opt/svc/.env.production", "exists": True,
             "sha256": "OLDHASH", "size": 1, "mtime": 1}]}])
        with mock.patch.object(secretscensus.journal, "append"):
            _, drift = secretscensus.census_report(
                CONTRACT,
                runner=lambda h, r: (0, "NEWHASH  x\n512 1700000000\n"),
                journal_dir=self.jdir)
        self.assertEqual(len(drift), 1)
        self.assertIn("rotation", drift[0][1])

    def test_vanished_file_is_flagged(self):
        self._journal([{"event": "census", "service": "svc", "files": [
            {"path": "/opt/svc/.env.production", "exists": True,
             "sha256": "H", "size": 1, "mtime": 1}]}])
        with mock.patch.object(secretscensus.journal, "append"):
            _, drift = secretscensus.census_report(
                CONTRACT, runner=lambda h, r: (0, ""), journal_dir=self.jdir)
        self.assertTrue(any("MISSING" in why for _, why in drift))


class EscrowRefusalTest(unittest.TestCase):
    """Escrow must refuse loudly long before any byte moves."""

    def test_refuses_without_reason(self):
        with self.assertRaises(Refused):
            secretscensus.escrow(CONTRACT, reason=None)

    def test_refuses_without_age_binary(self):
        with mock.patch.object(secretscensus.shutil, "which", return_value=None):
            with self.assertRaises(Refused) as cm:
                secretscensus.escrow(CONTRACT, reason="drill")
        self.assertIn("age", str(cm.exception))

    def test_refuses_without_recipients_file(self):
        with mock.patch.object(secretscensus.shutil, "which", return_value="/bin/age"), \
             mock.patch.object(secretscensus, "RECIPIENTS",
                               Path(tempfile.mkdtemp()) / "nope.txt"):
            with self.assertRaises(Refused):
                secretscensus.escrow(CONTRACT, reason="drill")

    def _recipients(self, text):
        d = Path(tempfile.mkdtemp())
        p = d / "escrow-recipients.txt"
        p.write_text(text)
        return p

    def test_refuses_empty_recipients(self):
        p = self._recipients("# only comments\n")
        with mock.patch.object(secretscensus.shutil, "which", return_value="/bin/age"), \
             mock.patch.object(secretscensus, "RECIPIENTS", p):
            with self.assertRaises(Refused) as cm:
                secretscensus.escrow(CONTRACT, reason="drill")
        self.assertIn("decrypt", str(cm.exception))

    def test_refuses_garbage_recipient_line(self):
        p = self._recipients("this is not a public key\n")
        with mock.patch.object(secretscensus.shutil, "which", return_value="/bin/age"), \
             mock.patch.object(secretscensus, "RECIPIENTS", p):
            with self.assertRaises(Refused):
                secretscensus.escrow(CONTRACT, reason="drill")

    def test_valid_recipient_lines_accepted(self):
        p = self._recipients(
            "# comment\n"
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKx7 op@ops\n"
            "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n")
        with mock.patch.object(secretscensus, "RECIPIENTS", p):
            self.assertEqual(len(secretscensus._load_recipients()), 2)


class EscrowPipelineTest(unittest.TestCase):
    """Run the real pipeline with a FAKE age (copies stdin) — proves plumbing
    without needing the binary, and proves failure deletes the output."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self._orig_escrow = secretscensus.ESCROW_DIR
        secretscensus.ESCROW_DIR = tmp / "escrow"
        self._orig_recip = secretscensus.RECIPIENTS
        recip = tmp / "recipients.txt"
        recip.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKx7 t@t\n")
        secretscensus.RECIPIENTS = recip
        # fake age: reads -R/-o args, copies stdin to the -o path
        self.fake_age = tmp / "age"
        self.fake_age.write_text(
            "#!/bin/sh\nout=''\nwhile [ $# -gt 0 ]; do\n"
            "  if [ \"$1\" = '-o' ]; then out=\"$2\"; shift; fi\n  shift\ndone\n"
            "cat > \"$out\"\n")
        self.fake_age.chmod(0o755)

    def tearDown(self):
        secretscensus.ESCROW_DIR = self._orig_escrow
        secretscensus.RECIPIENTS = self._orig_recip
        self._tmp.cleanup()

    def _with_fake_age(self):
        import os
        return mock.patch.dict(os.environ,
                               {"PATH": "%s:%s" % (self.fake_age.parent,
                                                   os.environ.get("PATH", ""))})

    def test_pipeline_produces_output_and_journals_fingerprint_only(self):
        with self._with_fake_age(), \
             mock.patch.object(secretscensus.journal, "append") as ap:
            res = secretscensus.escrow(
                CONTRACT, reason="restore drill",
                runner_argv=["printf", "pretend-tarball-bytes"])
        out = Path(res["output"])
        self.assertTrue(out.exists())
        self.assertEqual(out.read_text(), "pretend-tarball-bytes")
        entry = ap.call_args[0][1]
        self.assertEqual(entry["event"], "escrow")
        self.assertEqual(entry["ciphertext_sha256"], res["ciphertext_sha256"])
        self.assertNotIn("pretend", json.dumps(entry))  # no contents in journal

    def test_failed_producer_deletes_partial_output(self):
        with self._with_fake_age():
            with self.assertRaises(Refused):
                secretscensus.escrow(CONTRACT, reason="drill",
                                     runner_argv=["false"])
        self.assertEqual(list(secretscensus.ESCROW_DIR.glob("*")), [])

    def test_oversized_bundle_is_refused_and_deleted(self):
        with self._with_fake_age(), \
             mock.patch.object(secretscensus, "MAX_ESCROW_BYTES", 4):
            with self.assertRaises(Refused) as cm:
                secretscensus.escrow(CONTRACT, reason="drill",
                                     runner_argv=["printf", "way more than four"])
        self.assertIn("caught a tree", str(cm.exception))
        self.assertEqual(list(secretscensus.ESCROW_DIR.glob("*")), [])


if __name__ == "__main__":
    unittest.main()
