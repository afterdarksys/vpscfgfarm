"""backup-verify tests — truncated, corrupt, empty, oversized, and missing
backups must all FAIL or refuse; only a complete walkable archive passes."""
import gzip
import io
import sys
import tarfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import backupverify  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

GOOD_PATH = "/root/svc-pre-20260827-120000.tar.gz"


def _tarball(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _opener(blob):
    return lambda host, path: io.BytesIO(blob)


class BackupVerifyTest(unittest.TestCase):
    def _run(self, blob, cap=backupverify.MAX_BACKUP_BYTES, path=GOOD_PATH):
        with mock.patch.object(backupverify.probe, "latest_backup",
                               return_value=path), \
             mock.patch.object(backupverify.journal, "append"):
            return backupverify.verify_backup("edge1", "svc",
                                              opener=_opener(blob), cap=cap)

    def test_complete_archive_passes(self):
        blob = _tarball({"opt/svc/server.js": b"x" * 1000,
                         "opt/svc/.env.production": b"k=v"})
        res = self._run(blob)
        self.assertTrue(res["ok"])
        self.assertEqual(res["members"], 2)

    def test_truncated_archive_fails(self):
        blob = _tarball({"opt/svc/server.js": b"x" * 100000})
        res = self._run(blob[:len(blob) // 2])
        self.assertFalse(res["ok"])
        self.assertIn("NOT fully readable", res["detail"])

    def test_corrupt_bytes_fail(self):
        blob = bytearray(_tarball({"a": b"data"}))
        blob[len(blob) // 2] ^= 0xFF  # flip a bit mid-stream
        res = self._run(bytes(blob))
        self.assertFalse(res["ok"])

    def test_not_a_gzip_fails(self):
        res = self._run(b"this was never a tarball")
        self.assertFalse(res["ok"])

    def test_empty_archive_fails(self):
        res = self._run(_tarball({}))
        self.assertFalse(res["ok"])
        self.assertIn("EMPTY", res["detail"])

    def test_oversized_stream_refuses(self):
        import os
        # incompressible payload, so the on-the-wire stream really is big
        blob = _tarball({"big": os.urandom(50000)})
        self.assertGreater(len(blob), 1000)
        with self.assertRaises(Refused):
            self._run(blob, cap=1000)

    def test_missing_backup_refuses_loudly(self):
        with mock.patch.object(backupverify.probe, "latest_backup",
                               return_value=None):
            with self.assertRaises(Refused) as cm:
                backupverify.verify_backup("edge1", "svc", opener=_opener(b""))
        self.assertIn("nothing to restore FROM", str(cm.exception))

    def test_suspicious_backup_path_refuses(self):
        for bad in ("/tmp/evil.tar.gz", "/root/svc-pre-x.tar.gz; rm -rf /",
                    "/root/../etc/x-pre-1.tar.gz"):
            with mock.patch.object(backupverify.probe, "latest_backup",
                                   return_value=bad):
                with self.assertRaises(Refused):
                    backupverify.verify_backup("edge1", "svc", opener=_opener(b""))

    def test_gzip_bomb_of_zeros_hits_the_cap_not_the_disk(self):
        # 64KB of gzip expands to ~1GB of tar bytes; the cap counts COMPRESSED
        # stream bytes read, so craft the cap below the compressed size.
        big = gzip.compress(b"\0" * (10 * 1024 * 1024))
        with self.assertRaises(Refused):
            self._run(big, cap=1024)


if __name__ == "__main__":
    unittest.main()
