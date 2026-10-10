"""fleet keys tests — the relay trap (one machine, two names, different keys)
is the shape these exist to catch."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import fleetkeys  # noqa: E402


def _dialer(answers):
    def dial(alias):
        ok = answers.get(alias, False)
        return {"alias": alias, "ok": ok, "detail": "" if ok else "Permission denied (publickey)"}
    return dial


MACHINES = {
    "relay2.example.net": {"aliases": ["relay2", "relay2.example.net"], "user": "root"},
    "edge1.example.internal": {"aliases": ["edge1"], "user": "root"},
}


class SurveyTest(unittest.TestCase):
    def test_all_keys_working_no_problems(self):
        res = fleetkeys.survey(
            dialer=_dialer({"relay2": True, "relay2.example.net": True, "edge1": True}),
            machines=MACHINES)
        self.assertTrue(all(m["reachable"] for m in res))
        self.assertFalse(any(m["disagree"] for m in res))

    def test_the_relay_trap_aliases_disagree(self):
        # The trap: the FQDN stanza works, the short name is broken.
        res = fleetkeys.survey(
            dialer=_dialer({"relay2": False, "relay2.example.net": True, "edge1": True}),
            machines=MACHINES)
        relay = next(m for m in res if m["target"] == "relay2.example.net")
        self.assertTrue(relay["reachable"])
        self.assertTrue(relay["disagree"])
        text, problems = fleetkeys.render(res, [])
        self.assertIn("name order", text)
        self.assertEqual(problems, 1)

    def test_fully_dead_machine_is_flagged(self):
        res = fleetkeys.survey(
            dialer=_dialer({"relay2": False, "relay2.example.net": False, "edge1": True}),
            machines=MACHINES)
        relay = next(m for m in res if m["target"] == "relay2.example.net")
        self.assertFalse(relay["reachable"])
        self.assertFalse(relay["disagree"])  # disagreement needs at least one OK
        text, problems = fleetkeys.render(res, [])
        self.assertIn("NO working alias", text)
        self.assertEqual(problems, 1)


class GovernorGapTest(unittest.TestCase):
    GOVERNED = {
        "edge1": {"posture": "test"},
        "relay2.example.net": {"posture": "frozen"},
        "relay2": {"posture": "frozen", "alias_of": "relay2.example.net"},
        "mx.example.org": {"posture": "frozen"},
    }

    def _results(self, answers):
        return fleetkeys.survey(dialer=_dialer(answers), machines=MACHINES)

    def test_unreachable_governed_host_is_a_gap(self):
        res = self._results({"relay2": True, "relay2.example.net": True, "edge1": True})
        gaps = fleetkeys.governor_gaps(res, self.GOVERNED)
        self.assertEqual(gaps, ["mx.example.org"])

    def test_alias_answering_counts_for_canonical(self):
        # Only the FQDN answers; canonical relay2.example.net must NOT be a gap,
        # and the alias entry must not be reported separately either.
        res = self._results({"relay2": False, "relay2.example.net": True, "edge1": True})
        gaps = fleetkeys.governor_gaps(res, self.GOVERNED)
        self.assertNotIn("relay2.example.net", gaps)
        self.assertNotIn("relay2", gaps)

    def test_gap_counts_as_problem_in_render(self):
        res = self._results({"relay2": True, "relay2.example.net": True, "edge1": True})
        gaps = fleetkeys.governor_gaps(res, self.GOVERNED)
        text, problems = fleetkeys.render(res, gaps)
        self.assertIn("door to nowhere", text)
        self.assertEqual(problems, 1)


class RunTest(unittest.TestCase):
    def test_run_journals_the_survey(self):
        with mock.patch.object(fleetkeys.sshconfig, "machines", return_value=MACHINES), \
             mock.patch.object(fleetkeys.journal, "append") as ap:
            text, problems = fleetkeys.run(
                dialer=_dialer({"relay2": True, "relay2.example.net": True, "edge1": True}))
        self.assertEqual(problems, 0)
        entry = ap.call_args[0][1]
        self.assertEqual(entry["event"], "key_survey")
        self.assertEqual(entry["machines"], 2)
        # No key material, no paths — only names and counts, per rule 6.
        self.assertNotIn("id_", str(entry))


if __name__ == "__main__":
    unittest.main()
