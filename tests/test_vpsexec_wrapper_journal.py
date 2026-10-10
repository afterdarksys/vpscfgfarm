"""The vpsexec OUTER door (the `vpsexec` script) must journal through the
package's hash-chained writer, into the same stream as the inner door.

Regression: the wrapper once appended its own unchained lines to
journal/vpsexec.jsonl. The inner door's lines are chained, so every wrapper
line after one of them read as "spliced in after the fact" to
`vpscfg journal verify` as a broken link, and fleet watch reported one
failure on every ten-minute sweep because of it.
"""
import importlib.machinery
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vpscfg import journal, telemetry  # noqa: E402


def _load_door(filename):
    # The doors have no importable names, so name the loader explicitly.
    loader = importlib.machinery.SourceFileLoader(
        filename.replace("-", "_").replace(".py", "") + "_under_test",
        str(ROOT / filename))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _load_wrapper():
    return _load_door("vpsexec")


class ControlDoorJournalChain(unittest.TestCase):
    """The vpscfg-control.py door writes the `control` stream. It never shared
    a stream with a chained writer, so nothing broke — but it had no tamper
    evidence at all. It now chains too."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._real_dir = journal.JOURNAL_DIR
        self._real_push = telemetry.push_event
        journal.JOURNAL_DIR = Path(self.tmp.name)
        telemetry.push_event = lambda *a, **k: False
        self.door = _load_door("vpscfg-control.py")

    def tearDown(self):
        journal.JOURNAL_DIR = self._real_dir
        telemetry.push_event = self._real_push
        self.tmp.cleanup()

    def test_control_door_records_are_chained(self):
        self.door.journal({"event": "allowed_read", "judgment": {"verb": "status"}})
        self.door.journal({"event": "refused", "reason": "unit test"})
        path = journal.JOURNAL_DIR / "control.jsonl"
        recs = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
        self.assertEqual([r["event"] for r in recs], ["allowed_read", "refused"])
        self.assertEqual(recs[0]["prev"], journal.GENESIS)
        self.assertEqual(recs[0]["argv"], sys.argv[1:])
        result = journal.chain_verify("control")
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["chained"], 2)


class WrapperJournalChain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._real_dir = journal.JOURNAL_DIR
        self._real_push = telemetry.push_event
        journal.JOURNAL_DIR = Path(self.tmp.name)
        telemetry.push_event = lambda *a, **k: False
        self.wrapper = _load_wrapper()

    def tearDown(self):
        journal.JOURNAL_DIR = self._real_dir
        telemetry.push_event = self._real_push
        self.tmp.cleanup()

    def _lines(self):
        path = journal.JOURNAL_DIR / "vpsexec.jsonl"
        return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]

    def test_wrapper_lines_are_chained_with_the_inner_door(self):
        # wrapper (allowed_read) -> inner door (read) -> wrapper (refused):
        # exactly the interleaving that used to break the chain.
        self.wrapper.journal({"event": "allowed_read", "judgment": {"verb": "exec"}})
        journal.append("vpsexec", {"event": "read", "host": "edge1"})
        self.wrapper.journal({"event": "refused", "reason": "unit test"})

        recs = self._lines()
        self.assertEqual([r["event"] for r in recs],
                         ["allowed_read", "read", "refused"])
        self.assertTrue(all("prev" in r for r in recs),
                        "every line, from either door, carries a chain link")
        self.assertEqual(recs[0]["prev"], journal.GENESIS)
        self.assertEqual(recs[0]["door"], "vpsexec-wrapper")
        self.assertEqual(recs[2]["door"], "vpsexec-wrapper")

        result = journal.chain_verify("vpsexec")
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["chained"], 3)

    def test_wrapper_records_carry_operator_and_timestamp(self):
        self.wrapper.journal({"event": "allowed_read"})
        rec = self._lines()[0]
        self.assertIn("ts", rec)
        self.assertIn("operator", rec)
        self.assertEqual(rec["argv"], sys.argv[1:])

    def test_wrapper_cannot_forge_the_chain_link(self):
        # A caller-supplied prev must be overwritten by the system-owned link.
        self.wrapper.journal({"event": "allowed_read", "prev": "forged"})
        self.assertEqual(self._lines()[0]["prev"], journal.GENESIS)


if __name__ == "__main__":
    unittest.main()
