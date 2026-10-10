"""Journal hash-chain tests — weighted to tampering, per SECURITY-RULES:
the chain exists to catch edits, so the tests edit things."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import journal  # noqa: E402


def _append(stream, entry):
    """journal.append with the telemetry mirror stubbed out (no network)."""
    with mock.patch("vpscfg.telemetry.push_event"):
        return journal.append(stream, entry)


class ChainedAppendTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = journal.JOURNAL_DIR
        journal.JOURNAL_DIR = Path(self._tmp.name)

    def tearDown(self):
        journal.JOURNAL_DIR = self._orig
        self._tmp.cleanup()

    def _lines(self, stream):
        return (journal.JOURNAL_DIR / (stream + ".jsonl")).read_text().splitlines()

    def test_first_entry_is_genesis(self):
        rec = _append("t", {"event": "one"})
        self.assertEqual(rec["prev"], journal.GENESIS)

    def test_second_entry_links_to_first_raw_line(self):
        _append("t", {"event": "one"})
        first_raw = self._lines("t")[0]
        rec = _append("t", {"event": "two"})
        self.assertEqual(rec["prev"], journal._line_hash(first_raw))

    def test_entry_cannot_forge_its_own_prev(self):
        # An entry carrying `prev` must have it overwritten by the system.
        rec = _append("t", {"event": "one", "prev": "attacker-chosen"})
        self.assertEqual(rec["prev"], journal.GENESIS)

    def test_clean_chain_verifies(self):
        for i in range(5):
            _append("t", {"event": "e%d" % i})
        res = journal.chain_verify("t")
        self.assertTrue(res["ok"])
        self.assertEqual(res["entries"], 5)
        self.assertEqual(res["chained"], 5)

    def test_edited_middle_line_is_detected(self):
        for i in range(4):
            _append("t", {"event": "e%d" % i})
        path = journal.JOURNAL_DIR / "t.jsonl"
        lines = path.read_text().splitlines()
        doctored = json.loads(lines[1])
        doctored["event"] = "history, revised"
        lines[1] = json.dumps(doctored)
        path.write_text("\n".join(lines) + "\n")
        res = journal.chain_verify("t")
        self.assertFalse(res["ok"])
        # the line AFTER the edit no longer links to it
        self.assertIn(3, [ln for ln, _ in res["problems"]])

    def test_deleted_middle_line_is_detected(self):
        for i in range(4):
            _append("t", {"event": "e%d" % i})
        path = journal.JOURNAL_DIR / "t.jsonl"
        lines = path.read_text().splitlines()
        del lines[1]
        path.write_text("\n".join(lines) + "\n")
        self.assertFalse(journal.chain_verify("t")["ok"])

    def test_inserted_line_is_detected(self):
        for i in range(3):
            _append("t", {"event": "e%d" % i})
        path = journal.JOURNAL_DIR / "t.jsonl"
        lines = path.read_text().splitlines()
        lines.insert(1, json.dumps({"event": "sneaky", "prev": "whatever"}))
        path.write_text("\n".join(lines) + "\n")
        self.assertFalse(journal.chain_verify("t")["ok"])

    def test_hand_edited_garbage_line_is_detected(self):
        _append("t", {"event": "one"})
        path = journal.JOURNAL_DIR / "t.jsonl"
        with open(path, "a") as f:
            f.write("this is not json\n")
        _append("t", {"event": "after-garbage"})  # chains over the garbage line
        res = journal.chain_verify("t")
        self.assertFalse(res["ok"])
        self.assertTrue(any("JSON" in why for _, why in res["problems"]))

    def test_legacy_prefix_is_tolerated(self):
        # Streams written before chaining existed have no `prev` — a prefix of
        # them must verify clean once chained entries begin.
        path = journal.JOURNAL_DIR / "t.jsonl"
        path.write_text(json.dumps({"ts": "old", "event": "legacy"}) + "\n")
        _append("t", {"event": "chained-now"})
        res = journal.chain_verify("t")
        self.assertTrue(res["ok"])
        self.assertEqual(res["entries"], 2)
        self.assertEqual(res["chained"], 1)

    def test_unchained_after_chained_is_flagged(self):
        _append("t", {"event": "chained"})
        path = journal.JOURNAL_DIR / "t.jsonl"
        with open(path, "a") as f:
            f.write(json.dumps({"ts": "x", "event": "spliced, no prev"}) + "\n")
        res = journal.chain_verify("t")
        self.assertFalse(res["ok"])
        self.assertTrue(any("spliced" in why for _, why in res["problems"]))

    def test_missing_stream_is_ok_and_empty(self):
        res = journal.chain_verify("never-written")
        self.assertTrue(res["ok"])
        self.assertEqual(res["entries"], 0)


if __name__ == "__main__":
    unittest.main()
