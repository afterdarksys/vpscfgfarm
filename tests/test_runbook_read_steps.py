"""Read steps in runbooks and plays: explicit, never inert, never elevated.

  * `vpsexec grant new` reports a read step as "read: runs without a grant"
    instead of skipping it in silence, and never puts it in a grant.
  * `vpsrun` runs a play's read step in place, after the phrase, as a plain
    read: never planned (plan mode would run it early), never sent with
    --run / --approve / a contract, and halted if the door does not report it
    as tier read.
"""
import contextlib
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
import test_vpsexec_grant as tg  # noqa: E402
import test_vpsrun as tr  # noqa: E402
from vpscfg import vpsexec, vpsexecgrant  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

vpsrun = tr.vpsrun

READ_STEP = """  - hosts: [web1]
    cmd: "systemctl is-active nginx"
    where: host
    why: "step five: is nginx up"
"""


# ===========================================================================
# grants
# ===========================================================================

class GrantReportsReadStepsTest(tg._GrantHarness):

    def setUp(self):
        super().setUp()
        self.write_runbook(extra=READ_STEP, steps=5)

    def grant_plan(self, *flags):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexec.dispatch(["grant", "new", "rb", "--ttl", "1h"] + list(flags),
                                  guard=tv._guard(), policy=self.policy)
        return rc, out.getvalue()

    def test_plan_names_the_read_step_instead_of_skipping_it(self):
        rc, out = self.grant_plan()
        self.assertEqual(rc, 0)
        self.assertIn("5  read: runs without a grant — step five: is nginx up", out)
        self.assertIn("systemctl is-active nginx", out)
        # The other left-out steps are named too, each with why.
        self.assertIn("4  not break_glass", out)
        self.assertIn("3  rollback: excluded", out)

    def test_read_step_never_becomes_a_grant_step(self):
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexec.dispatch(["grant", "new", "rb", "--ttl", "1h", "--steps", "1,5",
                              "--run"], guard=tv._guard(), policy=self.policy,
                             stream=tg._TTY(), prompt=lambda m: "GRANT:rb:1h")
        path = sorted(self.grant_dir.glob("*.json"))[-1]
        steps = [s["index"] for s in self.load(path)["steps"]]
        self.assertEqual(steps, [1])

    def test_only_read_steps_selected_refuses(self):
        with self.assertRaises(Refused) as cm:
            self.grant_plan("--steps", "5")
        self.assertIn("no eligible break-glass steps", str(cm.exception))

    def test_non_break_glass_mutation_named_explicitly_still_refuses(self):
        with self.assertRaises(Refused) as cm:
            self.grant_plan("--steps", "1,4")
        self.assertIn("not break_glass: true", str(cm.exception))

    def test_a_classifier_that_refuses_means_not_a_read(self):
        def refusing(cmd):
            raise Refused("cannot classify")
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.select(self.policy, "rb", "1h", steps="5", classify=refusing)
        self.assertIn("not break_glass: true", str(cm.exception))

    def test_read_step_run_with_a_contract_is_just_a_read(self):
        """The contract is not consulted for a read: no grant_used, nothing
        journaled as a mutation, no lock."""
        path = self.mint()
        rc = self.use("web1", "systemctl is-active nginx", path)
        self.assertEqual(rc, 0)
        events = [e["event"] for e in self.events()]
        self.assertIn("read", events)
        self.assertNotIn("grant_used", events)
        self.assertNotIn("mutation_attempt", events)

    def test_read_step_never_gains_mutation_authority(self):
        """If policy later makes the read step's command a mutation, neither the
        runbook (not break_glass) nor the grant (does not list it) reaches the
        frozen host with it."""
        path = self.mint()
        self.policy["risky_extra"] = ["systemctl is-active"]
        with self.assertRaises(Refused):
            self.use("web1", "systemctl is-active nginx", path)
        self.assertEqual(self.ran(), [])
        self.assertNotIn("grant_used", [e["event"] for e in self.events()])


# ===========================================================================
# vpsrun
# ===========================================================================

READ_PLAY = """version: 1
reason: "OPS-9 restart and check"
steps:
  - hosts: edge1
    cmd: "k3s kubectl scale deployment a -n a --replicas=0"
    why: "stop a"
  - hosts: edge1
    cmd: "systemctl is-active nginx"
    why: "check nginx"
  - hosts: edge1
    cmd: "k3s kubectl scale deployment b -n b --replicas=0"
    why: "stop b"
"""


class ReadDoor(tr.FakeDoor):
    """FakeDoor, plus: a read (no --run) prints a read plan and its output,
    the way the real door does. `tier` lets a test model policy making the
    "read" something else, in which case the door only prints a plan."""

    READS = ("systemctl is-active nginx", "df -h")

    def __init__(self, tier="read", read_rc=0, **kw):
        super().__init__(**kw)
        self.tier, self.read_rc = tier, read_rc
        self.order = []

    def __call__(self, argv):
        if argv[1] in self.READS:
            self.calls.append(argv)
            self.order.append(("read", argv[1]))
            if self.tier != "read":
                return 0, ("PLAN — 1 host: edge1\n  tier    : %s\n\nPlan only. "
                           "Nothing has run.\n" % self.tier)
            return self.read_rc, ("PLAN — 1 host: edge1\n  tier    : read\n"
                                  "───── edge1 ─────\nactive\n")
        self.order.append(("run" if "--run" in argv else "plan", argv[1]))
        return super().__call__(argv)


class VpsrunReadStepTest(unittest.TestCase):
    # test_vpsrun's fixtures, without re-running its tests here.
    setUp, tearDown = tr.VpsrunTest.setUp, tr.VpsrunTest.tearDown
    _play, _go = tr.VpsrunTest._play, tr.VpsrunTest._go

    def go(self, door, text=READ_PLAY, **kw):
        return self._go(door, play=self._play(text), **kw)

    def test_read_runs_in_place_after_the_phrase_as_a_plain_read(self):
        door = ReadDoor()
        rc, out = self.go(door)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.order, [
            ("plan", "k3s kubectl scale deployment a -n a --replicas=0"),
            ("plan", "k3s kubectl scale deployment b -n b --replicas=0"),
            ("run", "k3s kubectl scale deployment a -n a --replicas=0"),
            ("read", "systemctl is-active nginx"),
            ("run", "k3s kubectl scale deployment b -n b --replicas=0")])
        read_call = [c for c in door.calls if c[1] == "systemctl is-active nginx"][0]
        for flag in read_call:
            self.assertFalse(flag.startswith(("--run", "--approve", "--approval-contract",
                                              "--break-glass")), read_call)
        self.assertIn("READ — runs here, after approval", out)
        self.assertIn("PLAY COMPLETE", out)

    def test_wrong_phrase_never_reaches_the_read(self):
        door = ReadDoor()
        with self.assertRaises(vpsrun.Refused):
            self.go(door, typed="nope")
        self.assertNotIn(("read", "systemctl is-active nginx"), door.order)

    def test_door_that_does_not_call_it_a_read_halts_the_play(self):
        door = ReadDoor(tier="risky (systemctl is-active)")
        rc, out = self.go(door)
        self.assertEqual(rc, 2)
        self.assertIn("did not run it as a read", out)
        self.assertIn("1 later step(s) NOT run", out)
        self.assertEqual([o for o in door.order if o[0] == "run"],
                         [("run", "k3s kubectl scale deployment a -n a --replicas=0")])

    def test_a_later_tier_line_cannot_vouch_for_the_plan(self):
        """Only the door's own (first) tier line counts, not text after it."""
        door = ReadDoor(tier="mutating (not on the read-only allowlist)\n  tier    : read")
        rc, out = self.go(door)
        self.assertEqual(rc, 2)
        self.assertIn("did not run it as a read", out)

    def test_failing_read_halts_the_play(self):
        door = ReadDoor(read_rc=3)
        rc, out = self.go(door)
        self.assertEqual(rc, 3)
        self.assertIn("PLAY HALTED at step 2", out)

    def test_read_step_gets_no_contract_even_when_one_is_given(self):
        door = ReadDoor()
        play = self._play(READ_PLAY)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = vpsrun.run_play(play, door, lambda m: m.split("Type ", 1)[1].split(" ")[0],
                                 tr.TTY(), contract="/nonexistent/grant.json",
                                 load_grant=lambda p: {"steps": [], "hosts": []})
        self.assertEqual(rc, 0)
        self.assertFalse([c for c in door.calls
                          if any(a.startswith("--approval-contract") for a in c)])

    def test_read_step_may_not_carry_authority_flags(self):
        for flag in ("--break-glass", "--verify=uptime", "--override=overrides/x.yaml",
                     "--canary", "--require-blackout"):
            text = READ_PLAY.replace('    why: "check nginx"',
                                     '    flags: ["%s"]\n    why: "check nginx"' % flag)
            door = ReadDoor()
            with self.assertRaises(vpsrun.Refused, msg=flag) as cm:
                self.go(door, text=text)
            self.assertIn("is a read; a read step may carry only", str(cm.exception))
            self.assertEqual(door.calls, [], flag)

    def test_read_step_may_carry_placement(self):
        text = READ_PLAY.replace('    why: "check nginx"',
                                 '    flags: ["--in=nginx", "--timeout=30"]\n    why: "check nginx"')
        door = ReadDoor()
        rc, _ = self.go(door, text=text)
        self.assertEqual(rc, 0)
        read_call = [c for c in door.calls if c[1] == "systemctl is-active nginx"][0]
        self.assertIn("--in=nginx", read_call)

    def test_the_phrase_binds_the_read_as_shown(self):
        a = vpsrun.load_play(self._write(READ_PLAY))
        b = vpsrun.load_play(self._write(READ_PLAY.replace("is-active nginx", "is-active caddy")))
        ta = vpsrun.plan_all(a, ReadDoor(), vpsrun.read_steps(a))
        tb = vpsrun.plan_all(b, ReadDoor(), vpsrun.read_steps(b))
        self.assertNotEqual(vpsrun.phrase(a, [d for _, d in ta]),
                            vpsrun.phrase(b, [d for _, d in tb]))

    def test_a_play_of_only_reads_runs(self):
        text = """version: 1
reason: "look"
steps:
  - hosts: edge1
    cmd: "df -h"
    why: "disk"
"""
        door = ReadDoor()
        rc, out = self.go(door, text=text)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.order, [("read", "df -h")])

    def _write(self, text):
        p = Path(self.tmp.name) / ("p%d.yaml" % len(list(Path(self.tmp.name).iterdir())))
        p.write_text(text)
        return p


if __name__ == "__main__":
    unittest.main()
