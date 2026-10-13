"""vpsrun: a human approves a queued play once; every step still goes through
the real vpsexec door with its own plan-hash (docs/NO-PASTE.md F2)."""
import contextlib
import importlib.machinery
import importlib.util
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import journal  # noqa: E402

_loader = importlib.machinery.SourceFileLoader("vpsrun", str(REPO / "vpsrun"))
_spec = importlib.util.spec_from_loader("vpsrun", _loader)
vpsrun = importlib.util.module_from_spec(_spec)
_loader.exec_module(vpsrun)

H1, H2 = "a" * 64, "b" * 64
STEP_B_CMD = '    cmd: "k3s kubectl scale deployment b -n b --replicas=0"'

PLAY = """version: 1
reason: "OPS-9 stop the lease leak"
steps:
  - hosts: edge1
    cmd: "k3s kubectl scale deployment a -n a --replicas=0"
    flags: ["--override=overrides/x.yaml"]
    why: "stop a"
  - hosts: edge1
    cmd: "k3s kubectl scale deployment b -n b --replicas=0"
    why: "stop b"
"""


class TTY:
    def isatty(self):
        return True


class NoTTY:
    def isatty(self):
        return False


class FakeDoor:
    """Stands in for the vpsexec subprocess. Plan mode prints a hash."""

    def __init__(self, digests=(H1, H2), run_rcs=(0, 0), drift_at=None):
        self.digests, self.run_rcs, self.drift_at = list(digests), list(run_rcs), drift_at
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if "--reason" not in argv:  # the real door refuses a plan with no reason
            return 2, 'REFUSED: every vpsexec mutation requires --reason "why"'
        idx = [c[1] for c in self.calls if "--run" not in c]
        if "--run" not in argv:
            n = len(idx) - 1
            return 0, "WILL RUN: %s\n  --run --reason \"why\" --approve=%s   if unattended\n" % (
                argv[1], self.digests[n])
        n = len([c for c in self.calls if "--run" in c]) - 1
        supplied = [a for a in argv if a.startswith("--approve=")][0].split("=", 1)[1]
        if self.drift_at == n + 1 or supplied != self.digests[n]:
            return 2, "REFUSED: --approve does not match this plan."
        return self.run_rcs[n], "  [ok] approved via plan-hash\n  done"


class VpsrunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._jdir = journal.JOURNAL_DIR
        journal.JOURNAL_DIR = Path(self.tmp.name)
        self.path = Path(self.tmp.name) / "p.yaml"
        self.path.write_text(PLAY)

    def tearDown(self):
        journal.JOURNAL_DIR = self._jdir
        self.tmp.cleanup()

    def _play(self, text=None):
        if text is not None:
            self.path.write_text(text)
        return vpsrun.load_play(self.path)

    def _go(self, door, typed=None, stream=None, play=None):
        play = play or self._play()
        if typed is None:  # type exactly what the prompt asks for
            typed = lambda m: m.split("Type ", 1)[1].split(" ", 1)[0]  # noqa: E731
        elif isinstance(typed, str):
            typed = (lambda t: lambda m: t)(typed)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = vpsrun.run_play(play, door, typed, stream or TTY())
        return rc, out.getvalue()

    def test_runs_every_step_with_its_own_plan_hash(self):
        door = FakeDoor()
        rc, out = self._go(door)
        self.assertEqual(rc, 0)
        runs = [c for c in door.calls if "--run" in c]
        self.assertEqual([c[-1] for c in runs], ["--approve=" + H1, "--approve=" + H2])
        self.assertIn("--override=overrides/x.yaml", runs[0])
        # The run id rides in the reason, so the door's journal says which run
        # made each attempt (the guard-aware retry reads it back).
        self.assertRegex(runs[0][runs[0].index("--reason") + 1],
                         r"^OPS-9 stop the lease leak — step 1: stop a \[run r_[0-9a-f]{16}\]$")
        plans = [c for c in door.calls if "--run" not in c]
        self.assertEqual([p[p.index("--reason") + 1] for p in plans],
                         [r[r.index("--reason") + 1] for r in runs])
        self.assertIn("PLAY COMPLETE", out)
        events = [r["event"] for r in __import__("vpscfg.vpsexeclog").vpsexeclog.read()]
        self.assertEqual(events, ["play_approved"])

    def test_no_tty_refuses_before_touching_the_door(self):
        door = FakeDoor()
        with self.assertRaises(vpsrun.Refused):
            self._go(door, stream=NoTTY())
        self.assertEqual(door.calls, [])

    def test_wrong_phrase_runs_nothing(self):
        door = FakeDoor()
        with self.assertRaises(vpsrun.Refused):
            self._go(door, typed="PLAY:3")
        self.assertFalse(any("--run" in c for c in door.calls))

    def test_break_glass_is_in_the_phrase(self):
        play = self._play(PLAY.replace('flags: ["--override=overrides/x.yaml"]',
                                       'flags: ["--break-glass"]'))
        self.assertEqual(vpsrun.phrase(play), "PLAY:2:BREAK-GLASS:1")

    def test_phrase_binds_the_plans_shown(self):
        play = self._play()
        self.assertNotEqual(vpsrun.phrase(play, [H1, H2]), vpsrun.phrase(play, [H2, H1]))
        door = FakeDoor()
        with self.assertRaises(vpsrun.Refused):  # the bare count is no longer enough
            self._go(door, typed="PLAY:2")
        self.assertFalse(any("--run" in c for c in door.calls))

    def test_control_characters_refuse_at_load(self):
        for field, bad in (("reason", "ok\\e[2J\\e[H fine"), ("why", "stop a\\r"),
                           ("cmd", "touch /tmp/a\\x1b[2K")):
            text = {"reason": PLAY.replace("OPS-9 stop the lease leak", bad),
                    "why": PLAY.replace('why: "stop a"', 'why: "%s"' % bad),
                    "cmd": PLAY.replace("k3s kubectl scale deployment a -n a --replicas=0", bad)}[field]
            with self.assertRaises(vpsrun.Refused, msg=field):
                self._play(text)

    def test_door_output_is_escaped_before_the_approver_sees_it(self):
        self.assertEqual(vpsrun.printable("a\x1b[2Jb\nc"), "a\\x1b[2Jb\nc")

    def test_first_failure_halts_the_play(self):
        door = FakeDoor(run_rcs=(1, 0))
        rc, out = self._go(door)
        self.assertEqual(rc, 1)
        self.assertEqual(len([c for c in door.calls if "--run" in c]), 1)
        self.assertIn("1 later step(s) NOT run", out)

    def test_plan_that_changed_after_approval_halts(self):
        rc, out = self._go(FakeDoor(drift_at=2))
        self.assertEqual(rc, 2)
        self.assertIn("PLAY HALTED at step 2", out)

    def test_step_without_a_plan_hash_refuses_the_play(self):
        def door(argv):
            return 2, "REFUSED: posture frozen"
        with self.assertRaises(vpsrun.Refused):
            self._go(door)

    def test_smuggled_approval_flags_refuse_at_load(self):
        for flag in ("--run", "--approve=" + H1, "--reason=x", "--yes", "--approve"):
            with self.assertRaises(vpsrun.Refused, msg=flag):
                self._play(PLAY.replace('"--override=overrides/x.yaml"', '"%s"' % flag))

    def test_read_step_is_never_sent_to_the_door_before_approval(self):
        """Plan mode RUNS a read, so a read step is not planned: with a wrong
        phrase it never reaches the door at all (tests/test_runbook_read_steps.py
        covers how it runs after approval)."""
        door = FakeDoor()
        play = self._play(PLAY.replace("k3s kubectl scale deployment b -n b --replicas=0",
                                       "df -h"))
        with self.assertRaises(vpsrun.Refused):
            self._go(door, typed="nope", play=play)
        self.assertEqual([c[1] for c in door.calls],
                         ["k3s kubectl scale deployment a -n a --replicas=0"])

    def test_floor_step_refuses_before_planning(self):
        door = FakeDoor()
        play = self._play(PLAY.replace("k3s kubectl scale deployment b -n b --replicas=0",
                                       "docker volume prune -f"))
        with self.assertRaises(vpsrun.Refused):
            self._go(door, play=play)
        self.assertEqual(door.calls, [])

    def test_push_step_goes_through_the_door_as_a_push(self):
        text = PLAY.replace(STEP_B_CMD, "    push: deploy/x.sh\n    sha256: \"%s\"" % ("c" * 64))
        door = FakeDoor()
        rc, _ = self._go(door, play=self._play(text))
        self.assertEqual(rc, 0)
        run2 = [c for c in door.calls if "--run" in c][1]
        self.assertEqual(run2[:5], ["edge1", "push", "deploy/x.sh", "--sha256", "c" * 64])

    def test_push_step_shape_is_strict(self):
        sha = "c" * 64
        for bad in ("    push: x\n    sha256: \"short\"",
                    "    push: x\n    cmd: \"ls\"\n    sha256: \"%s\"" % sha,
                    "    cmd: \"ls /\"\n    sha256: \"%s\"" % sha):
            with self.assertRaises(vpsrun.Refused, msg=bad):
                self._play(PLAY.replace(STEP_B_CMD, bad))

    def test_precheck_failure_refuses_before_anything_is_planned(self):
        play = self._play("precheck: [k3s]\n" + PLAY)
        door, calls = FakeDoor(), []
        def check(argv):
            calls.append(argv)
            return 1, "edge1 REBOOT-SAFE: NO"
        with self.assertRaises(vpsrun.Refused) as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                vpsrun.run_play(play, door, lambda m: "x", TTY(), check=check)
        self.assertIn("precheck 'k3s' failed", str(cm.exception))
        self.assertEqual(calls, [["fleet", "k3s", "edge1"]])
        self.assertEqual(door.calls, [])

    def test_passing_precheck_lets_the_play_run(self):
        play = self._play("precheck: [k3s, firewall]\n" + PLAY)
        calls = []
        def check(argv):
            calls.append(argv[:2])
            return 0, "ok"
        door = FakeDoor()
        with contextlib.redirect_stdout(io.StringIO()):
            rc = vpsrun.run_play(play, door, lambda m: m.split("Type ", 1)[1].split(" ", 1)[0],
                                 TTY(), check=check)
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [["fleet", "k3s"], ["fleet", "firewall"]])

    def test_unknown_precheck_refuses_at_load(self):
        with self.assertRaises(vpsrun.Refused):
            self._play("precheck: [rm-rf]\n" + PLAY)

    def test_malformed_plays_refuse(self):
        for bad in ("version: 2\nreason: r\nsteps: [{hosts: a, cmd: b, why: c}]\n",
                    "version: 1\nsteps: [{hosts: a, cmd: b, why: c}]\n",
                    "version: 1\nreason: r\nsteps: []\n",
                    "version: 1\nreason: r\nsteps: [{hosts: a, cmd: b}]\n",
                    "version: 1\nreason: r\ngrant: all\nsteps: [{hosts: a, cmd: b, why: c}]\n"):
            with self.assertRaises(vpsrun.Refused, msg=bad):
                self._play(bad)


if __name__ == "__main__":
    unittest.main()


class CommittedPlaysTest(unittest.TestCase):
    """Disabling netfilter-persistent on a k3s host without
    checking its iptables backend took the host's sites down at the next
    reboot. Any committed play that changes boot-time firewall behaviour or
    reboots/stops a host must gate on `vpscfg fleet k3s`."""

    BOOT_SENSITIVE = re.compile(r"netfilter-persistent|\breboot\b|shutdown|"
                                r"systemctl (stop|disable|mask) (k3s|docker)")

    def test_the_pattern_matches_what_it_claims(self):
        for hit in ("systemctl disable netfilter-persistent", "reboot", "shutdown -r now",
                    "systemctl stop k3s", "systemctl disable docker"):
            self.assertTrue(self.BOOT_SENSITIVE.search(hit), hit)
        for miss in ("systemctl start k3s", "docker restart shop-caddy", "rebooted-at"):
            self.assertFalse(self.BOOT_SENSITIVE.search(miss), miss)


# ===========================================================================
# break-glass steps: --approve alone no longer approves them, so a play takes
# an approval contract covering each one, checked BEFORE anything runs.
# ===========================================================================

BG_PLAY = """version: 1
reason: "wave5"
steps:
  - hosts: web1
    cmd: "systemctl restart nginx"
    flags: ["--break-glass"]
    why: "restart nginx"
  - hosts: edge1
    cmd: "touch /tmp/marker"
    why: "plain step"
  - hosts: web1
    cmd: "systemctl restart caddy"
    flags: ["--break-glass"]
    why: "restart caddy"
"""
H3 = "c" * 64
GRANT = {"hosts": ["web1"],
         "steps": [{"cmd": "systemctl restart nginx", "where": "host"},
                   {"cmd": "systemctl restart caddy", "where": "host"}]}


class BreakGlassDoor(FakeDoor):
    """Plan text shaped like render_plan(): the PLAN/command lines, and the
    BREAK-GLASS line only when a host is elevated."""

    def __call__(self, argv):
        rc, out = super().__call__(argv)
        if "--run" in argv or rc != 0:
            return rc, out
        bg = argv[0] == "web1"
        head = "PLAN — 1 host: %s\n  command : %s\n" % (argv[0], argv[1])
        if bg:
            head += "  BREAK-GLASS: 1 of 1 host(s) elevated past posture — web1(frozen)\n"
        return rc, head + out


class VpsrunContractTest(unittest.TestCase):
    # VpsrunTest's fixtures, without re-running its tests here.
    setUp, tearDown = VpsrunTest.setUp, VpsrunTest.tearDown
    _play, _go = VpsrunTest._play, VpsrunTest._go

    def _bg(self, contract=None, grant=GRANT, run_rcs=(0, 0, 0)):
        door = BreakGlassDoor(digests=(H1, H2, H3), run_rcs=run_rcs)
        loaded = []

        def load_grant(path):
            loaded.append(path)
            return grant
        play = self._play(BG_PLAY)
        typed = lambda m: m.split("Type ", 1)[1].split(" ", 1)[0]  # noqa: E731
        with contextlib.redirect_stdout(io.StringIO()):
            rc = vpsrun.run_play(play, door, typed, TTY(), contract=contract,
                                 load_grant=load_grant)
        return rc, door, loaded

    def test_valid_contract_runs_every_step_and_only_bg_steps_get_it(self):
        rc, door, loaded = self._bg(contract="/abs/grant.json")
        self.assertEqual(rc, 0)
        self.assertEqual(loaded, ["/abs/grant.json"])
        runs = [c for c in door.calls if "--run" in c]
        self.assertEqual(len(runs), 3)
        self.assertEqual(runs[0][-2:], ["--approve=" + H1,
                                        "--approval-contract=/abs/grant.json"])
        self.assertEqual(runs[1][-1], "--approve=" + H2)
        self.assertFalse([a for a in runs[1] if a.startswith("--approval-contract")])
        self.assertEqual(runs[2][-2:], ["--approve=" + H3,
                                        "--approval-contract=/abs/grant.json"])

    def test_play_phrase_is_still_required(self):
        door = BreakGlassDoor(digests=(H1, H2, H3))
        with self.assertRaises(vpsrun.Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsrun.run_play(self._play(BG_PLAY), door, lambda m: "nope", TTY(),
                                contract="/abs/g.json", load_grant=lambda p: GRANT)
        self.assertEqual([c for c in door.calls if "--run" in c], [])

    def test_no_contract_refuses_up_front(self):
        with self.assertRaises(vpsrun.Refused) as cm:
            self._bg(contract=None)
        self.assertIn("step(s) 1, 3 are break-glass", str(cm.exception))
        self.assertIn("vpsexec grant new", str(cm.exception))

    def test_no_contract_runs_nothing(self):
        door = BreakGlassDoor(digests=(H1, H2, H3))
        with self.assertRaises(vpsrun.Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsrun.run_play(self._play(BG_PLAY), door, lambda m: "x", TTY())
        self.assertEqual([c for c in door.calls if "--run" in c], [])

    def test_grant_missing_a_step_refuses_up_front(self):
        partial = {"hosts": ["web1"], "steps": [GRANT["steps"][0]]}
        door = BreakGlassDoor(digests=(H1, H2, H3))
        with self.assertRaises(vpsrun.Refused) as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                vpsrun.run_play(self._play(BG_PLAY), door, lambda m: "x", TTY(),
                                contract="/abs/g.json", load_grant=lambda p: partial)
        self.assertIn("does not cover break-glass step(s) 3", str(cm.exception))
        self.assertEqual([c for c in door.calls if "--run" in c], [])

    def test_grant_missing_a_host_refuses_up_front(self):
        other = dict(GRANT, hosts=["web2"])
        with self.assertRaises(vpsrun.Refused) as cm:
            self._bg(contract="/abs/g.json", grant=other)
        self.assertIn("step(s) 1, 3", str(cm.exception))

    def test_invalid_contract_refuses_up_front(self):
        """The real preflight: a file that is not a grant refuses before any run."""
        bad = Path(self.tmp.name) / "g.json"
        bad.write_text("{}")
        door = BreakGlassDoor(digests=(H1, H2, H3))
        with self.assertRaises(vpsrun.Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsrun.run_play(self._play(BG_PLAY), door, lambda m: "x", TTY(),
                                contract=str(bad))
        self.assertEqual([c for c in door.calls if "--run" in c], [])

    def test_empty_contract_flag_refuses(self):
        for argv in (["p.yaml", "--approval-contract="],
                     ["p.yaml", "--approval-contract", "  "],
                     ["p.yaml", "--approval-contract"]):
            with self.assertRaises(vpsrun.Refused, msg=argv):
                vpsrun.parse_argv(argv)

    def test_contract_path_is_expanded_and_absolute(self):
        _, contract = vpsrun.parse_argv(["p.yaml", "--approval-contract=~/g.json"])
        self.assertEqual(contract, str(Path("~/g.json").expanduser()))
        _, contract = vpsrun.parse_argv(["p.yaml", "--approval-contract", "rel.json"])
        self.assertTrue(Path(contract).is_absolute())

    def test_play_without_break_glass_needs_no_contract(self):
        rc, _ = self._go(FakeDoor())
        self.assertEqual(rc, 0)
