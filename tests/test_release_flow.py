"""vpsrun releases, resume, the guard-aware retry, optional steps, holds,
on_fail offers and the notifier (W3/W5 of the release-valves plan).

Fakes and temp dirs only: SimDoor stands in for the vpsexec subprocess and
models the one door behaviour these features lean on, the identical-plan
guard (gate 7b), from the same journal records the real door writes."""
import contextlib
import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import (integrations, journal, notify, telemetry, vpsexec,  # noqa: E402
                    vpsexecgrant, vpsexeclog)
import test_vpsexec as tv  # noqa: E402
import test_vpsrun as tr  # noqa: E402

vpsrun = tr.vpsrun

PLAY_A = """version: 1
reason: "OPS-1 stage a"
steps:
  - hosts: edge1
    cmd: "mkdir /srv/a"
    why: "make a"
  - hosts: edge1
    cmd: "docker tag app:1 app:live"
    why: "tag a"
"""
PLAY_B = """version: 1
reason: "OPS-1 stage b"
steps:
  - hosts: edge1
    cmd: "mkdir /srv/b"
    why: "make b"
"""
RELEASE = """version: 1
reason: "weekend release"
plays:
  - stage-a
  - play: stage-b
    hold_before: "is the login dashboard green?"
"""
ROLLBACK_POLICY = """version: 1
expires: "2999-01-01"
reason: "rollbacks"
runbooks:
  - hosts: [edge1]
    cmd: "docker tag app:0 app:live"
    why: "forward step"
  - hosts: [edge1]
    cmd: "docker tag app:0 app:live"
    why: "put the old image back"
    rollback: true
    break_glass: true
"""
GRANT_ID = "ru_" + "c" * 32
GRANT_LINE = ("  grants  : 1 valid for this plan (auto-pick order):\n"
              "            %s reusable until 2099-01-01T00:00:00Z code "
              "ABCD-EFGH-IJKL uses-left 50\n" % GRANT_ID)


def typed(msg):
    """Type exactly what a prompt asks for (the play phrase or a hold)."""
    return msg.split("Type ", 1)[1].split(" ", 1)[0]


class SimDoor:
    """Plans print a plan-hash per command; runs journal mutation_attempt /
    mutation_complete as the real door does and refuse an identical plan
    inside the window exactly like gate 7b. `slept` stands for the clock."""

    def __init__(self, rcs=None, outputs=None, bg=(), grants=False, window=300):
        self.rcs = dict((k, list(v)) for k, v in (rcs or {}).items())
        self.outputs, self.bg, self.grants = outputs or {}, set(bg), grants
        self.window, self.slept, self.calls = window, 0, []

    @staticmethod
    def digest(cmd):
        return hashlib.sha256(cmd.encode()).hexdigest()

    def sleep(self, seconds):
        self.slept += seconds

    def runs(self):
        return [c[1] for c in self.calls if "--run" in c]

    def __call__(self, argv):
        self.calls.append(argv)
        cmd, reason = argv[1], argv[argv.index("--reason") + 1]
        d = self.digest(cmd)
        text = "PLAN — 1 host: %s\n  command : %s\n  tier    : mutating\n" % (argv[0], cmd)
        if cmd in self.bg:
            text += "  BREAK-GLASS: 1 of 1 host(s) elevated past posture — edge1(frozen)\n"
            if self.grants:
                text += GRANT_LINE
        text += "plan-hash: %s\n" % d
        if "--run" not in argv:
            return 0, text + '  --run --reason "why" --approve=%s   if unattended\n' % d
        assert argv[argv.index("--run") + 1] == "--approve=" + d
        prior = vpsexeclog.recent_plan(d, within_seconds=self.window)
        if prior and self.slept < self.window:
            return 2, text + ("REFUSED: this IDENTICAL plan ran 3s ago (reason: %r).\n"
                              "  Refusing an unattended repeat inside %ds — a script "
                              "re-firing the same mutation is more likely a bug than "
                              "intent." % (prior.get("reason"), self.window))
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": d,
                                   "reason": reason, "command": cmd, "hosts": [argv[0]]})
        queue = self.rcs.get(cmd)
        rc = queue.pop(0) if queue else 0
        journal.append("vpsexec", {"event": "mutation_complete", "command": cmd,
                                   "hosts": [argv[0]], "failed": [argv[0]] if rc else [],
                                   "not_run": []})
        return rc, text + "───── %s ─────\n%s\nSUMMARY — 1 host(s)\n" % (
            argv[0], self.outputs.get(cmd, "done"))


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self._saved = (journal.JOURNAL_DIR, telemetry.push_event,
                       vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH)
        journal.JOURNAL_DIR = root / "journal"
        telemetry.push_event = lambda *a, **k: False
        vpsexecgrant.GRANT_DIR = root / "grants"
        vpsexecgrant.KEY_PATH = root / "grant.key"
        self.plays, self.releases, self.policies = (root / "plays", root / "releases",
                                                    root / "policies")
        for d in (self.plays, self.releases, self.policies):
            d.mkdir()
        (self.plays / "stage-a.yaml").write_text(PLAY_A)
        (self.plays / "stage-b.yaml").write_text(PLAY_B)
        (self.releases / "weekend.yaml").write_text(RELEASE)
        (self.policies / "rollbacks.yaml").write_text(ROLLBACK_POLICY)
        self.notes = []

    def tearDown(self):
        (journal.JOURNAL_DIR, telemetry.push_event,
         vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH) = self._saved
        self.tmp.cleanup()

    def release(self, text=None, name="weekend"):
        if text is not None:
            (self.releases / ("%s.yaml" % name)).write_text(text)
        return vpsrun.load_release(name, release_dir=self.releases,
                                   play_dir=self.plays, policy_dir=self.policies)

    def go(self, door, release=None, prompt=typed, stream=None, **kw):
        kw.setdefault("notify", lambda ev, f: self.notes.append((ev, f)))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = vpsrun.run_release(release or self.release(), door, prompt,
                                    stream or tr.TTY(), sleep=door.sleep, **kw)
        return rc, out.getvalue()

    def go_play(self, door, name="stage-a", prompt=typed, **kw):
        kw.setdefault("notify", lambda ev, f: self.notes.append((ev, f)))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = vpsrun.run_play(vpsrun.load_play(self.plays / ("%s.yaml" % name)),
                                 door, prompt, tr.TTY(), sleep=door.sleep, **kw)
        return rc, out.getvalue()

    def run_events(self):
        return vpsexeclog.read(vpsrun.RUN_STREAM)


# ---------------------------------------------------------------------------
# release manifests
# ---------------------------------------------------------------------------

class ReleaseManifestTest(_Base):
    def test_loads_plays_in_order_with_holds(self):
        rel = self.release()
        self.assertEqual([Path(p["path"]).stem for p in rel["plays"]], ["stage-a", "stage-b"])
        self.assertEqual(list(rel["holds"].values()), ["is the login dashboard green?"])
        self.assertEqual(rel["grant_ttl"], "12h")

    def test_refuses_malformed_manifests(self):
        bad = {
            "unknown key": RELEASE + "deploy_now: true\n",
            "no reason": RELEASE.replace('reason: "weekend release"\n', ""),
            "duplicate play": RELEASE + "  - stage-a\n",
            "path in a play name": RELEASE.replace("  - stage-a", "  - ../stage-a"),
            "unknown entry key": RELEASE.replace("  - stage-a", "  - {play: stage-a, run: x}"),
            "empty hold": RELEASE.replace('"is the login dashboard green?"', '""'),
            "bad ttl": RELEASE + "grant_ttl: 99d\n",
            "missing play": RELEASE.replace("stage-b", "stage-z"),
        }
        for label, text in bad.items():
            with self.subTest(label), self.assertRaises(vpsrun.Refused):
                self.release(text)

    def test_release_name_cannot_be_a_path(self):
        for name in ("../x", "/etc/passwd", "a/b", ""):
            with self.subTest(name=name), self.assertRaises(vpsrun.Refused):
                vpsrun.load_release(name, release_dir=self.releases,
                                    play_dir=self.plays, policy_dir=self.policies)


# ---------------------------------------------------------------------------
# one command, one phrase, every play in order
# ---------------------------------------------------------------------------

class ReleaseRunTest(_Base):
    def test_one_phrase_runs_every_play_in_order(self):
        door, asked = SimDoor(), []

        def prompt(msg):
            asked.append(msg)
            return typed(msg)
        rc, out = self.go(door, prompt=prompt)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), ["mkdir /srv/a", "docker tag app:1 app:live",
                                       "mkdir /srv/b"])
        approvals = [m for m in asked if not m.startswith("Type GO:")]
        self.assertEqual(len(approvals), 1)
        self.assertRegex(approvals[0], r"Type RELEASE:weekend:3:[0-9a-f]{6} to run all 3")
        self.assertIn("RELEASE COMPLETE", out)
        self.assertEqual(self.notes[-1][0], "finish")
        events = [e["event"] for e in self.run_events()]
        self.assertEqual(events[0], "run_started")
        self.assertEqual(events[-1], "run_complete")

    def test_one_approval_covers_exactly_the_plans_shown(self):
        rel = self.release()
        with contextlib.redirect_stdout(io.StringIO()):
            units = vpsrun.prepare(rel["plays"], SimDoor(), vpsrun.new_run_id())
        shown = [u["digest"] for u in units]
        want = vpsrun.run_phrase("RELEASE:weekend", [u["step"] for u in units], shown)
        other = vpsrun.run_phrase("RELEASE:weekend", [u["step"] for u in units],
                                  shown[:-1] + ["f" * 64])
        self.assertNotEqual(want, other)
        door = SimDoor()
        rc, out = self.go(door)
        ran = [a for c in door.calls if "--run" in c for a in c if a.startswith("--approve=")]
        self.assertEqual(ran, ["--approve=" + d for d in shown])
        for d in shown:
            self.assertIn("plan-hash: %s" % d, out)  # every plan run was shown

    def test_wrong_phrase_runs_nothing_and_leaves_no_run(self):
        door = SimDoor()
        with self.assertRaises(vpsrun.Refused):
            self.go(door, prompt=lambda m: "RELEASE:weekend:3")
        self.assertEqual(door.runs(), [])
        self.assertEqual(self.run_events(), [])

    def test_halts_on_first_failure_and_says_how_to_resume(self):
        door = SimDoor(rcs={"docker tag app:1 app:live": [1]})
        rc, out = self.go(door)
        self.assertEqual(rc, 1)
        self.assertEqual(door.runs(), ["mkdir /srv/a", "docker tag app:1 app:live"])
        self.assertIn("RELEASE HALTED at play stage-a step 2 (rc=1). 1 later step(s) NOT run.",
                      out)
        self.assertIn("vpsrun release weekend --resume", out)
        self.assertEqual(self.notes[-1][0], "halt")
        self.assertEqual(self.notes[-1][1]["resume"], "vpsrun release weekend --resume")

    def test_hold_stops_before_the_play_and_resume_asks_again(self):
        door = SimDoor()

        def no_go(msg):
            return "no" if msg.startswith("Type GO:") else typed(msg)
        rc, out = self.go(door, prompt=no_go)
        self.assertEqual(rc, 3)
        self.assertIn("HOLD before play stage-b — is the login dashboard green?", out)
        self.assertNotIn("mkdir /srv/b", door.runs())
        asked = []

        def go(msg):
            asked.append(msg)
            return typed(msg)
        rc, out = self.go(door, prompt=go, resume=True)
        self.assertEqual(rc, 0, out)
        self.assertTrue(any(m.startswith("Type GO:stage-b") for m in asked))
        self.assertEqual(door.runs(), ["mkdir /srv/a", "docker tag app:1 app:live",
                                       "mkdir /srv/b"])  # stage-a not run twice

    def test_release_is_tty_only(self):
        door = SimDoor()
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go(door, stream=tr.NoTTY())
        self.assertIn("real terminal", str(cm.exception))
        self.assertEqual(door.calls, [])
        with self.assertRaises(vpsrun.Refused):
            self.go(door, stream=tr.NoTTY(), resume=True)
        self.assertEqual(door.calls, [])

    def test_play_with_a_floor_command_refuses_before_anything_is_planned(self):
        (self.plays / "stage-b.yaml").write_text(PLAY_B.replace("mkdir /srv/b",
                                                                "docker volume prune -f"))
        door = SimDoor()
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go(door)
        self.assertIn("refused by the classifier", str(cm.exception))
        self.assertEqual(door.runs(), [])

    def test_cli_parses_release_and_resume(self):
        self.assertEqual(vpsrun.parse_cli(["release", "weekend", "--resume"]),
                         ("release", "weekend", None, True))
        self.assertEqual(vpsrun.parse_cli(["plays/x.yaml"]),
                         ("play", "plays/x.yaml", None, False))
        self.assertEqual(vpsrun.parse_cli(["release", "weekend", "--grant", "auto"]),
                         ("release", "weekend", vpsrun.AUTO, False))


# ---------------------------------------------------------------------------
# resume from the journal
# ---------------------------------------------------------------------------

class ResumeTest(_Base):
    def test_resume_skips_succeeded_steps_and_reruns_the_failed_one(self):
        door = SimDoor(rcs={"docker tag app:1 app:live": [1, 0]}, window=0)
        self.assertEqual(self.go(door)[0], 1)
        asked = []

        def prompt(msg):
            asked.append(msg)
            return typed(msg)
        rc, out = self.go(door, resume=True, prompt=prompt)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), ["mkdir /srv/a", "docker tag app:1 app:live",
                                       "docker tag app:1 app:live", "mkdir /srv/b"])
        self.assertIn("ALREADY DONE in run", out)
        self.assertRegex(asked[0], r"^Type RELEASE:weekend:2:[0-9a-f]{6} ")  # only what runs

    def test_resume_continues_the_same_run_id(self):
        door = SimDoor(rcs={"mkdir /srv/b": [1]}, window=0)
        self.go(door)
        self.go(door, resume=True)
        ids = set(e["run_id"] for e in self.run_events())
        self.assertEqual(len(ids), 1)
        run_id = ids.pop()
        reasons = [c[c.index("--reason") + 1] for c in door.calls if "--run" in c]
        self.assertTrue(all(r.endswith("[run %s]" % run_id) for r in reasons), reasons)

    def test_resume_never_skips_a_failed_step(self):
        door = SimDoor(rcs={"mkdir /srv/a": [1]}, window=0)
        self.go(door)
        rc, out = self.go(door, resume=True)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs().count("mkdir /srv/a"), 2)

    def test_resume_refuses_when_a_done_step_now_plans_differently(self):
        door = SimDoor(rcs={"mkdir /srv/b": [1]}, window=0)
        self.go(door)
        (self.plays / "stage-a.yaml").write_text(PLAY_A.replace("mkdir /srv/a", "mkdir -p /srv/a"))
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go(door, resume=True)
        self.assertIn("will neither re-run a done step nor skip a changed one", str(cm.exception))
        self.assertEqual(door.runs(), ["mkdir /srv/a", "docker tag app:1 app:live",
                                       "mkdir /srv/b"])

    def test_resume_of_a_completed_or_missing_run_refuses(self):
        door = SimDoor()
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go(door, resume=True)
        self.assertIn("no earlier run", str(cm.exception))
        self.go(door)
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go(door, resume=True)
        self.assertIn("completed", str(cm.exception))

    def test_play_resume(self):
        door = SimDoor(rcs={"docker tag app:1 app:live": [1, 0]}, window=0)
        rc, out = self.go_play(door)
        self.assertEqual(rc, 1)
        self.assertIn("vpsrun %s --resume" % (self.plays / "stage-a.yaml"), out)
        rc, out = self.go_play(door, resume=True)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), ["mkdir /srv/a", "docker tag app:1 app:live",
                                       "docker tag app:1 app:live"])

    def test_unrecorded_outcome_is_settled_from_the_door_journal(self):
        """vpsrun died after the door ran the step: the door's journal says ok."""
        door = SimDoor(rcs={"docker tag app:1 app:live": [1]}, window=0)
        self.go(door)
        run_id = self.run_events()[0]["run_id"]
        rel = self.release()
        play = rel["plays"][1]
        u = {"play": play, "n": 1, "step": play["steps"][0]}
        vpsrun._rjournal({"event": "step_started", "run_id": run_id,
                          "play": vpsrun._key(play), "step": 1,
                          "digest": SimDoor.digest("mkdir /srv/b")})
        door([u["step"]["hosts"], "mkdir /srv/b", "--reason",
              vpsrun.step_reason(play, 1, u["step"], run_id), "--run",
              "--approve=" + SimDoor.digest("mkdir /srv/b")])
        door.calls.clear()
        rc, out = self.go(door, resume=True)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), ["docker tag app:1 app:live"])  # /srv/b not again

    def test_attempt_with_no_recorded_outcome_refuses_resume(self):
        door = SimDoor(rcs={"docker tag app:1 app:live": [1]}, window=0)
        self.go(door)
        run_id = self.run_events()[0]["run_id"]
        play = self.release()["plays"][1]
        vpsrun._rjournal({"event": "step_started", "run_id": run_id,
                          "play": vpsrun._key(play), "step": 1,
                          "digest": SimDoor.digest("mkdir /srv/b")})
        journal.append("vpsexec", {"event": "mutation_attempt",
                                   "plan_hash": SimDoor.digest("mkdir /srv/b"),
                                   "reason": vpsrun.step_reason(play, 1, play["steps"][0], run_id),
                                   "command": "mkdir /srv/b", "hosts": ["edge1"]})
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go(door, resume=True)
        self.assertIn("refuses to guess", str(cm.exception))

    def test_a_step_whose_start_cannot_be_journaled_does_not_run(self):
        door = SimDoor()
        real = journal.append

        def failing(stream, entry):
            if stream == vpsrun.RUN_STREAM and entry.get("event") == "step_started":
                raise OSError("disk full")
            return real(stream, entry)
        journal.append = failing
        try:
            with self.assertRaises(OSError):
                self.go(door)
        finally:
            journal.append = real
        self.assertEqual(door.runs(), [])


# ---------------------------------------------------------------------------
# guard-aware retry
# ---------------------------------------------------------------------------

class GuardRetryTest(_Base):
    def test_own_failed_step_waits_out_the_window_and_retries(self):
        door = SimDoor(rcs={"docker tag app:1 app:live": [1, 0]})
        self.assertEqual(self.go(door)[0], 1)
        rc, out = self.go(door, resume=True)
        self.assertEqual(rc, 0, out)
        self.assertGreaterEqual(door.slept, 300)
        self.assertIn("repeat guard: retrying in", out)
        self.assertIn("this run's own failed step", out)
        self.assertEqual(door.runs().count("docker tag app:1 app:live"), 3)  # fail, refused, ok

    def test_another_runs_identical_plan_still_refuses(self):
        cmd = "mkdir /srv/a"
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": SimDoor.digest(cmd),
                                   "reason": "someone else [run r_%s]" % ("9" * 16),
                                   "command": cmd, "hosts": ["edge1"]})
        door = SimDoor()
        rc, out = self.go(door)
        self.assertEqual(rc, 2)
        self.assertEqual(door.slept, 0)
        self.assertIn("NOT retrying — another run's identical plan", out)
        self.assertIn("RELEASE HALTED at play stage-a step 1", out)

    def test_a_previous_run_of_the_same_release_is_another_run(self):
        door = SimDoor(rcs={"mkdir /srv/a": [1]})
        self.go(door)
        rc, out = self.go(door)  # a NEW run, not --resume
        self.assertEqual(rc, 2)
        self.assertEqual(door.slept, 0)
        self.assertIn("NOT retrying", out)

    def test_own_succeeded_identical_plan_is_not_retried(self):
        """Only a FAILED own attempt qualifies: a play repeating an identical
        plan that already succeeded in this run still meets the guard."""
        (self.plays / "stage-b.yaml").write_text(PLAY_B.replace("mkdir /srv/b", "mkdir /srv/a")
                                                 .replace("make b", "make a again"))
        door = SimDoor()
        rc, out = self.go(door)
        self.assertEqual(rc, 2)
        self.assertEqual(door.slept, 0)

    def test_no_retry_when_the_guard_is_not_the_only_refusal(self):
        self.assertFalse(vpsrun._guard_only(2, "REFUSED: x\nRefusing an unattended repeat\n"
                                               "REFUSED: lock held"))
        self.assertFalse(vpsrun._guard_only(0, "Refusing an unattended repeat"))
        self.assertTrue(vpsrun._guard_only(2, "REFUSED: this IDENTICAL plan ran 3s ago.\n"
                                              "  Refusing an unattended repeat inside 300s"))


# ---------------------------------------------------------------------------
# optional steps
# ---------------------------------------------------------------------------

COND_PLAY = """version: 1
reason: "OPS-2 ownership"
steps:
  - hosts: edge1
    cmd: "psql -c 'select owner_check()' NOT OWNED"
    id: w9
    why: "W 9: who owns the tables"
  - hosts: edge1
    cmd: "psql -c 'alter table t owner to app'"
    when: "w9 reports NOT OWNED"
    why: "W 10: take ownership"
"""


class OptionalStepTest(_Base):
    def setUp(self):
        super().setUp()
        (self.plays / "cond.yaml").write_text(COND_PLAY)

    def test_runs_when_the_earlier_step_reports_the_text(self):
        door = SimDoor(outputs={"psql -c 'select owner_check()' NOT OWNED": "t: NOT OWNED"})
        rc, out = self.go_play(door, name="cond")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(door.runs()), 2)
        self.assertIn("OPTIONAL — runs only if step 1 (w9) reports /NOT OWNED/", out)

    def test_skipped_and_journaled_otherwise_even_though_the_command_says_it(self):
        door = SimDoor(outputs={"psql -c 'select owner_check()' NOT OWNED": "t: owned"})
        rc, out = self.go_play(door, name="cond")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(door.runs()), 1)
        self.assertIn("SKIPPED: step 1 (w9) did not report /NOT OWNED/", out)
        skipped = [e for e in self.run_events() if e.get("status") == "skipped"]
        self.assertEqual([e["step"] for e in skipped], [2])

    def test_resume_keeps_the_recorded_verdict(self):
        cmd = "psql -c 'alter table t owner to app'"
        door = SimDoor(outputs={"psql -c 'select owner_check()' NOT OWNED": "NOT OWNED"},
                       rcs={cmd: [1, 0]}, window=0)
        self.assertEqual(self.go_play(door, name="cond")[0], 1)
        rc, out = self.go_play(door, name="cond", resume=True)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs().count(cmd), 2)
        self.assertEqual(door.runs().count("psql -c 'select owner_check()' NOT OWNED"), 1)

    def test_condition_must_name_an_earlier_step(self):
        for bad in ('    when: "w9 reports NOT OWNED"\n', '    when: "zz reports x"\n',
                    '    when: "w9 says x"\n', '    when: "w9 reports ("\n'):
            text = COND_PLAY.replace('    when: "w9 reports NOT OWNED"\n', bad)
            if bad.startswith('    when: "w9 reports NOT'):
                text = text.replace("    id: w9\n", "")
            (self.plays / "bad.yaml").write_text(text)
            with self.subTest(bad=bad), self.assertRaises(vpsrun.Refused):
                vpsrun.load_play(self.plays / "bad.yaml")

    def test_remote_output_excludes_the_plan(self):
        out = ("PLAN — 1 host: edge1\n  command : echo NOT OWNED\nplan-hash: x\n"
               "───── edge1 ─────\nowned\nSUMMARY — 1 host(s)\n  [ok  ] edge1 rc=0\n")
        self.assertEqual(vpsrun.remote_output(out), "owned")
        self.assertEqual(vpsrun.remote_output("PLAN only, echo NOT OWNED"), "")


# ---------------------------------------------------------------------------
# grants: one for the whole release, or the door mints one
# ---------------------------------------------------------------------------

BG_RELEASE = RELEASE.replace('reason: "weekend release"',
                             'reason: "weekend release"\npolicies: [login-stage-a.yaml]')


class ReleaseGrantTest(_Base):
    def load_grant(self, path):
        return {"kind": "reusable", "session_id": GRANT_ID}

    def test_one_grant_covers_break_glass_steps_across_plays(self):
        door = SimDoor(bg={"mkdir /srv/a", "mkdir /srv/b"}, grants=True)
        rc, out = self.go(door, load_grant=self.load_grant)
        self.assertEqual(rc, 0, out)
        contracts = [[a for a in c if a.startswith("--approval-contract=")]
                     for c in door.calls if "--run" in c]
        want = ["--approval-contract=%s" % (vpsexecgrant.GRANT_DIR / ("%s.json" % GRANT_ID))]
        self.assertEqual(contracts, [want, [], want])
        self.assertIn("grant  : auto-picked reusable ru_cccccccc", out)
        approved = [e for e in vpsexeclog.read() if e["event"] == "release_approved"][0]
        self.assertEqual(approved["grant"]["session_id"], GRANT_ID)

    def test_no_grant_mints_one_through_the_door_then_runs(self):
        door, minted = SimDoor(bg={"mkdir /srv/a"}), []

        def mint(argv):
            minted.append(argv)
            door.grants = True
            return 0
        rc, out = self.go(door, release=self.release(BG_RELEASE), mint=mint,
                          load_grant=self.load_grant)
        self.assertEqual(rc, 0, out)
        # H4b: narrowed to the break-glass steps' hosts, one use per step,
        # bound to this release.
        self.assertEqual(minted, [["grant", "new", "login-stage-a.yaml", "--kind",
                                   "reusable", "--ttl", "12h", "--hosts", "edge1",
                                   "--max-uses", "1", "--for-release", "weekend",
                                   "--run"]])

    def test_failed_mint_runs_nothing(self):
        door = SimDoor(bg={"mkdir /srv/a"})
        with self.assertRaises(vpsrun.Refused):
            self.go(door, release=self.release(BG_RELEASE), mint=lambda argv: 1)
        self.assertEqual(door.runs(), [])

    def test_without_policies_it_prints_the_mint_command(self):
        door = SimDoor(bg={"mkdir /srv/a"})
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go(door, mint=lambda argv: self.fail("must not mint"))
        self.assertIn("vpsexec grant new '<policy,...>' --kind reusable --ttl 12h --run",
                      str(cm.exception))
        self.assertEqual(door.runs(), [])


# ---------------------------------------------------------------------------
# W5: on_fail offers and the notifier
# ---------------------------------------------------------------------------

class OnFailTest(_Base):
    TEXT = RELEASE + "on_fail:\n  - runbook: rollbacks.yaml\n    step: 2\n"

    def test_halt_prints_the_rollback_and_never_runs_it(self):
        door = SimDoor(rcs={"mkdir /srv/a": [1]})
        rc, out = self.go(door, release=self.release(self.TEXT))
        self.assertEqual(rc, 1)
        self.assertIn("Rollback — offered, NOT run", out)
        self.assertIn("vpsexec edge1 'docker tag app:0 app:live' --break-glass --run "
                      "--reason 'rollback after release weekend halted'", out)
        self.assertNotIn("docker tag app:0 app:live", door.runs())
        self.assertEqual(len(self.notes[-1][1]["rollback"]), 1)

    def test_on_fail_naming_an_action_policy_by_bare_name_offers_the_action(self):
        # An action policy lives in policies/actions/; on_fail names it by its
        # bare file name and the offer is the typed action, printed, never run.
        sub = self.policies / "actions"
        sub.mkdir()
        (sub / "tag-back.yaml").write_text(
            'version: 1\nexpires: "2999-01-01"\nreason: "tag back"\nrunbooks:\n'
            '  - hosts: [edge1]\n    action: tag_image\n'
            '    with: {image: "app", from_tag: "0", to_tag: "live"}\n'
            '    why: "put the old image back"\n    rollback: true\n')
        text = RELEASE + "on_fail:\n  - runbook: tag-back.yaml\n    step: 1\n"
        door = SimDoor(rcs={"mkdir /srv/a": [1]})
        rc, out = self.go(door, release=self.release(text))
        self.assertEqual(rc, 1)
        self.assertIn("Rollback — offered, NOT run", out)
        self.assertIn("vpsexec edge1 --action tag_image --with "
                      "'{\"from_tag\": \"0\", \"image\": \"app\", \"to_tag\": \"live\"}' "
                      "--run --reason 'rollback after release weekend halted'", out)
        self.assertFalse([c for c in door.calls if "--action" in c], "printed, never run")
        self.assertEqual(self.notes[-1][1]["rollback"][0].split(" --with")[0],
                         "vpsexec edge1 --action tag_image")

    def test_on_fail_must_name_a_rollback_entry(self):
        for bad in ("    step: 1\n", "    step: 9\n", "    step: 0\n"):
            with self.subTest(bad=bad), self.assertRaises(vpsrun.Refused):
                self.release(self.TEXT.replace("    step: 2\n", bad))
        with self.assertRaises(vpsrun.Refused):
            self.release(self.TEXT.replace("rollbacks.yaml", "../rollbacks.yaml"))


class NotifyTest(_Base):
    def governor(self, integ):
        path = Path(self.tmp.name) / "gov.json"
        path.write_text(json.dumps({"integrations": integ} if integ is not None else {}))
        return str(path)

    def test_off_by_default_and_runs_nothing(self):
        ran = []
        self.assertFalse(notify.send("halt", {}, governor=self.governor(None),
                                     runner=lambda a, p: ran.append(a)))
        self.assertEqual(ran, [])

    def test_configured_command_gets_the_event_and_json_on_stdin(self):
        ran = []
        gov = self.governor({"notify": {"command": ["/usr/local/bin/push-note", "-q"]}})
        ok = notify.send("halt", {"run_id": "r_1", "rc": 1}, governor=gov,
                         runner=lambda a, p: ran.append((a, json.loads(p))) or 0)
        self.assertTrue(ok)
        self.assertEqual(ran[0][0], ["/usr/local/bin/push-note", "-q", "halt"])
        self.assertEqual(ran[0][1], {"event": "halt", "rc": 1, "run_id": "r_1"})

    def test_a_broken_notifier_never_raises(self):
        gov = self.governor({"notify": {"command": ["push-note"]}})

        def boom(argv, payload):
            raise OSError("no such file")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(notify.send("finish", {}, governor=gov, runner=boom))
            self.assertFalse(notify.send("finish", {}, governor=gov, runner=lambda a, p: 3))

    def test_command_must_be_plain_argv(self):
        for bad in ("push-note --x", ["sh", "-c", "curl x; rm -rf /"], [], ["-x"],
                    ["relative/push"], ["a$(b)"]):
            with self.subTest(bad=bad), self.assertRaises(integrations.Refused):
                integrations.notify_command(self.governor({"notify": {"command": bad}}))

    def test_unknown_event_is_a_bug(self):
        with self.assertRaises(ValueError):
            notify.send("deployed", {})

    def test_lock_retained_is_notified(self):
        class LockDoor(SimDoor):
            def __call__(self, argv):
                rc, out = super().__call__(argv)
                if "--run" in argv:
                    return 1, out + "  [BLOCKED: lock retained; reconcile operation op1]\n"
                return rc, out
        rc, _ = self.go(LockDoor())
        self.assertEqual(rc, 1)
        self.assertEqual([n[0] for n in self.notes], ["lock_retained", "halt"])


# ---------------------------------------------------------------------------
# play steps inherit the runbook's timeout (the door already does this)
# ---------------------------------------------------------------------------

class PlayStepTimeoutTest(tv._Harness):
    CMD = "systemctl restart nginx"

    def _door(self, argv, calls, out):
        def ssh(host, cmd, timeout=None, connect_timeout=None):
            calls.append((cmd, timeout))
            return 0, "ok", ""
        runbook = dict(tv._runbook(["edge1"], self.CMD), timeout=1234)
        with contextlib.redirect_stdout(out):
            return vpsexec.dispatch(
                argv, guard=tv._guard(), policy=tv._yaml_policy(runbooks=[runbook]),
                prober=self.prober(), ssh=ssh, stream=tr.NoTTY(),
                blackout_runner=self.blackout_runner(unavailable=True))

    def _play_step(self, flags=()):
        play = {"reason": "OPS-3", "steps": []}
        step = {"hosts": "edge1", "cmd": self.CMD, "why": "restart", "flags": list(flags)}
        return vpsrun.step_argv(play, 1, step, "r_" + "0" * 16)

    def _run(self, flags=()):
        argv, calls, out = self._play_step(flags), [], io.StringIO()
        self.assertEqual(self._door(argv, calls, out), 0)
        digest = re.search(r"--approve=([0-9a-f]{64})", out.getvalue()).group(1)
        self.assertEqual(self._door(argv + ["--run", "--approve=" + digest], calls, out), 0)
        return [t for c, t in calls if "vpscfg.lock" not in c and self.CMD in c], out.getvalue()

    def test_step_without_timeout_inherits_the_runbook_timeout(self):
        timeouts, out = self._run()
        self.assertIn("timeout : 1234s per host (runbook)", out)
        self.assertEqual(timeouts, [1234])

    def test_an_explicit_step_timeout_still_wins(self):
        timeouts, out = self._run(["--timeout=30"])
        self.assertIn("timeout : 30s per host (--timeout)", out)
        self.assertEqual(timeouts, [30])


if __name__ == "__main__":
    unittest.main()
