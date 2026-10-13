"""Interactions between the release-valves workstreams, tested where two of
them meet (integration of W0-W6 onto one branch):

  IncidentGrantTest      W4 incident vs W0 grant kinds: an --incident command
                         takes no contract flag and never auto-picks a grant;
                         an incident file is never offered or accepted as one.
  UncertainResumeTest    W3 resume vs W2 detached steps: a step the door left
                         UNCERTAIN (lost contact, lock retained) is neither
                         skipped as done nor re-run blind.
  DoorLockRetainedTest   the real door journals which host kept its lock.
  ReconcileResumeTest    W2 `vpsexec reconcile` then W3 `vpsrun release
                         --resume`: the real reconcile releases the lock and the
                         resume re-runs the step and completes.
  LintPlayConditionTest  W1 lint understands W3's `id:` / `when:` play keys.
  LintReleaseTest        W1 lint understands W3's releases/*.yaml.

Hermetic: temp dirs, fake doors, a local bash standing in for the host. No
~/.vpscfg, no estate, no fleet host.
"""
import contextlib
import io
import json
import os
import shutil
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_detach_reconcile as dr  # noqa: E402  (modules, not names: no re-collection)
import test_release_flow as rf  # noqa: E402
import test_runbookcheck as rc_  # noqa: E402
import test_vpsexec as tv  # noqa: E402
import test_vpsexec_grant as tg  # noqa: E402
import test_vpsexec_incident as ti  # noqa: E402
from vpscfg import (detach, journal, lock, runbookcheck, vpsexec,  # noqa: E402
                    vpsexecgrant, vpsexeclog)
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

vpsrun = rf.vpsrun
NGINX = "systemctl restart nginx"
OP = "e" * 64


# ===========================================================================
# W4 incident vs W0 grants
# ===========================================================================

class IncidentGrantTest(ti._IncidentHarness):

    def test_incident_refuses_every_spelling_of_a_grant(self):
        iid = self.open()
        for extra in (("--grant", "auto"), ("--grant=auto",), ("--approval-contract=auto",),
                      ("--grant", "/nonexistent.json")):
            with self.subTest(extra=extra):
                self.refused("web1", iid, extra=extra, needle="typed GO")

    def test_incident_never_auto_picks_a_covering_grant(self):
        self.mint()  # a valid short grant that covers NGINX on web1
        iid = self.open()
        asked = []

        def prompt(msg):
            asked.append(msg)
            return "GO:web1"
        rc, out = self.run_cmd("web1", iid, cmd=NGINX, prompt=prompt)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("auto-picked", out)
        self.assertNotIn("grants  :", out)  # candidates were not even listed
        names = [e.get("event") for e in self.events()]
        self.assertNotIn("grant_autopicked", names)
        self.assertNotIn("grant_used", names)
        self.assertEqual([e["incident"] for e in self.of("incident_command")], [iid])
        self.assertEqual(len(asked), 1)
        self.assertEqual(self.ran(), [("web1", NGINX)])

    def _incident_as_grant_file(self):
        iid = self.open()
        fake = self.grant_dir / ("ru_" + "d" * 32 + ".json")
        shutil.copy(self.grant_dir / iid, fake)
        os.chmod(fake, 0o600)
        return fake

    def test_an_incident_file_is_never_auto_picked(self):
        self._incident_as_grant_file()
        out = io.StringIO()
        with self.assertRaises(Refused) as cm, contextlib.redirect_stdout(out):
            vpsexec.dispatch(
                ["web1", NGINX, "--break-glass", "--run", "--reason", "OPS-1",
                 "--approval-contract=auto"],
                guard=tv._guard(), prober=self.prober(), policy=self.policy,
                ssh=self.fake_ssh(), stream=tg._TTY(), prompt=tg._no_prompt,
                blackout_runner=self.blackout_runner(unavailable=True))
        self.assertIn("no valid grant", str(cm.exception))
        self.assertIn("grants  : none valid for this plan", out.getvalue())
        self.assertEqual(self.ran(), [])

    def test_an_incident_file_is_refused_as_an_explicit_contract(self):
        fake = self._incident_as_grant_file()
        with self.assertRaises(Refused):
            vpsexecgrant.check(fake, self.policy)
        with self.assertRaises(Refused):
            self.run_cmd("web1", None, cmd=NGINX,
                         extra=("--approval-contract=%s" % fake,))
        self.assertEqual(self.ran(), [])


# ===========================================================================
# W3 resume vs W2 uncertain (detached) steps
# ===========================================================================

class UncertainDoor(rf.SimDoor):
    """The first --run of each command in `uncertain` loses contact the way the
    W2 door reports it: an `uncertain` step record and/or `lock_retained` on
    mutation_complete, rc 1 and the BLOCKED line naming the reconcile."""

    def __init__(self, uncertain=(), host="edge1", op=OP, step_record=True,
                 retained=True, **kw):
        rf.SimDoor.__init__(self, **kw)
        self.uncertain, self.host, self.op = set(uncertain), host, op
        self.step_record, self.retained = step_record, retained

    def __call__(self, argv):
        cmd = argv[1]
        if "--run" not in argv or cmd not in self.uncertain:
            return rf.SimDoor.__call__(self, argv)
        self.uncertain.discard(cmd)
        self.calls.append(argv)
        reason = argv[argv.index("--reason") + 1]
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": self.digest(cmd),
                                   "reason": reason, "command": cmd, "hosts": [argv[0]]})
        if self.step_record:
            journal.append("vpsexec", {"event": "step", "host": argv[0], "remote": cmd,
                                       "rc": None, "uncertain": True,
                                       "operation_id": self.op})
        done = {"event": "mutation_complete", "command": cmd, "hosts": [argv[0]],
                "failed": [argv[0]], "not_run": []}
        if self.retained:
            done["lock_retained"] = {argv[0]: self.op}
        journal.append("vpsexec", done)
        return 1, ("PLAN — 1 host: %s\n  command : %s\nplan-hash: %s\n"
                   "  [FAIL] %s rc=1  transport: SSH connection lost [BLOCKED: lock "
                   "retained; reconcile operation %s — next: vpsexec reconcile %s]\n"
                   % (argv[0], cmd, self.digest(cmd), argv[0], self.op, argv[0]))


def reconciled(op, verdict="COMPLETED", rc=0, host="edge1"):
    journal.append("vpsexec", {"event": "reconciled", "host": host, "operation_id": op,
                               "verdict": verdict, "rc": rc})


class UncertainResumeTest(rf._Base):
    TAG = "docker tag app:1 app:live"

    def test_halt_names_the_reconcile_command(self):
        rc, out = self.go(UncertainDoor(uncertain=[self.TAG], window=0))
        self.assertEqual(rc, 1)
        self.assertIn("RELEASE HALTED", out)
        self.assertIn("  vpsexec reconcile edge1\n", out)

    def _refuses(self, door):
        self.go(door)
        before = list(door.runs())
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go(door, resume=True)
        self.assertIn("UNCERTAIN", str(cm.exception))
        self.assertIn("vpsexec reconcile edge1", str(cm.exception))
        self.assertEqual(door.runs(), before, "resume ran something")
        return door

    def test_uncertain_step_record_refuses_resume(self):
        self._refuses(UncertainDoor(uncertain=[self.TAG], retained=False, window=0))

    def test_lock_retained_alone_refuses_resume(self):
        self._refuses(UncertainDoor(uncertain=[self.TAG], step_record=False, window=0))

    def test_reconcile_of_another_operation_does_not_count(self):
        door = UncertainDoor(uncertain=[self.TAG], window=0)
        self.go(door)
        reconciled("f" * 64)
        with self.assertRaises(vpsrun.Refused):
            self.go(door, resume=True)

    def _resume_answering(self, door, answer):
        asked = []

        def prompt(msg):
            asked.append(msg)
            if "COMPLETED rc=0 on every host" in msg:
                return answer
            return rf.typed(msg)
        return self.go(door, resume=True, prompt=prompt), asked

    def test_reconciled_completed_is_not_rerun_by_default_skip_done(self):
        door = UncertainDoor(uncertain=[self.TAG], window=0)
        self.go(door)
        reconciled(OP)  # verdict COMPLETED rc=0
        (rc, out), asked = self._resume_answering(door, "SKIP-DONE:stage-a:2")
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), ["mkdir /srv/a", self.TAG, "mkdir /srv/b"])
        self.assertIn("SKIP-DONE:stage-a:2", asked[0])
        self.assertIn("RERUN:stage-a:2", asked[0])
        done = [r for r in self.run_events() if r.get("settled_from") == "reconcile"]
        self.assertEqual((done[0]["status"], done[0]["step"]), ("ok", 2))

    def test_reconciled_completed_rerun_choice_runs_it_again(self):
        door = UncertainDoor(uncertain=[self.TAG], window=0)
        self.go(door)
        reconciled(OP)
        (rc, out), _ = self._resume_answering(door, "RERUN:stage-a:2")
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), ["mkdir /srv/a", self.TAG, self.TAG, "mkdir /srv/b"])
        self.assertIn("not counted as done", out)

    def test_reconciled_completed_any_other_answer_refuses(self):
        door = UncertainDoor(uncertain=[self.TAG], window=0)
        self.go(door)
        reconciled(OP)
        for answer in ("", "yes", "SKIP-DONE:stage-a:1", "RERUN:stage-b:2"):
            with self.subTest(answer=answer), self.assertRaises(vpsrun.Refused):
                self._resume_answering(door, answer)
        self.assertEqual(door.runs(), ["mkdir /srv/a", self.TAG])

    def test_other_verdicts_rerun_without_asking(self):
        for verdict, rc_, vrc in (("UNKNOWN", None, None), ("COMPLETED", 1, None),
                                  ("COMPLETED", 0, 3)):
            with self.subTest(verdict=verdict, rc=rc_, verify=vrc):
                self.tearDown()
                self.setUp()
                door = UncertainDoor(uncertain=[self.TAG], window=0)
                self.go(door)
                journal.append("vpsexec", {"event": "reconciled", "host": "edge1",
                                           "operation_id": OP, "verdict": verdict,
                                           "rc": rc_, "verify_rc": vrc})
                (rc, out), asked = self._resume_answering(door, "SKIP-DONE:stage-a:2")
                self.assertEqual(rc, 0, out)
                self.assertFalse([a for a in asked if "COMPLETED rc=0 on every host" in a])
                self.assertEqual(door.runs().count(self.TAG), 2)

    def test_killed_vpsrun_with_an_uncertain_door_attempt_refuses(self):
        """vpsrun died; the door's journal shows the step's attempt was
        uncertain: settling it from the door must not make it `failed` and
        re-run it blind."""
        door = rf.SimDoor(rcs={self.TAG: [1]}, window=0)
        self.go(door)
        run_id = self.run_events()[0]["run_id"]
        play = self.release()["plays"][1]
        vpsrun._rjournal({"event": "step_started", "run_id": run_id,
                          "play": vpsrun._key(play), "step": 1,
                          "digest": rf.SimDoor.digest("mkdir /srv/b")})
        udoor = UncertainDoor(uncertain=["mkdir /srv/b"], window=0)
        udoor([play["steps"][0]["hosts"], "mkdir /srv/b", "--reason",
               vpsrun.step_reason(play, 1, play["steps"][0], run_id), "--run",
               "--approve=" + rf.SimDoor.digest("mkdir /srv/b")])
        door.calls.clear()
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go(door, resume=True)
        self.assertIn("UNCERTAIN", str(cm.exception))
        self.assertEqual(door.runs(), [])

    def test_a_plain_failure_still_reruns(self):
        door = rf.SimDoor(rcs={self.TAG: [1, 0]}, window=0)
        self.go(door)
        rc, out = self.go(door, resume=True)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("UNCERTAIN", out)


# ===========================================================================
# the real door journals lock_retained
# ===========================================================================

class DoorLockRetainedTest(dr._Base):

    def execute(self, cmd, ssh):
        plan = vpsexec.build_plan([dr.HOST], cmd, {}, "mutating", None)
        guard = Guard({"deny_always": list(DENY_ALWAYS_FLOOR), "hosts": {dr.HOST: {}},
                       "allow_unmanaged_steps": [dr.HOST]}, True)  # no systemd here
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return vpsexec.execute(plan, guard, "test", "interactive", ssh=ssh, timeout=30)

    def test_lost_contact_names_the_retained_operation(self):
        now = [0.0]
        detach._clock = lambda: now[0]
        detach._sleep = lambda s: now.__setitem__(0, now[0] + s)
        self.assertEqual(self.execute("echo started", dr.Dropping(drops=10 ** 6)), 1)
        step = self.events("step")[-1]
        self.assertTrue(step["uncertain"])
        done = self.events("mutation_complete")[-1]
        self.assertEqual(done["lock_retained"], {dr.HOST: step["operation_id"]})

    def test_a_known_outcome_records_no_retained_lock(self):
        self.assertEqual(self.execute("exit 3", dr._local), 1)
        self.assertNotIn("lock_retained", self.events("mutation_complete")[-1])


# ===========================================================================
# W2 reconcile, then W3 release --resume, end to end
# ===========================================================================

class ReconcileResumeTest(dr._Base):
    CMD = "docker compose up -d app"

    def setUp(self):
        super().setUp()
        root = Path(self.tmp.name)
        self.saved_grant = (vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH)
        vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH = root / "grants", root / "grant.key"
        vpsexecgrant._is_controlling_tty = lambda stream: stream.isatty()
        for d in ("plays", "releases", "policies"):
            (root / d).mkdir()
        (root / "plays" / "recreate.yaml").write_text(
            'version: 1\nreason: "OPS-2 recreate"\nsteps:\n'
            '  - hosts: %s\n    cmd: "%s"\n    why: "recreate"\n'
            '  - hosts: %s\n    cmd: "mkdir /srv/after"\n    why: "after"\n'
            % (dr.HOST, self.CMD, dr.HOST))
        (root / "releases" / "night.yaml").write_text(
            'version: 1\nreason: "night release"\nplays:\n  - recreate\n')
        self.root = root

    def tearDown(self):
        vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH = self.saved_grant
        super().tearDown()

    def release(self):
        return vpsrun.load_release("night", release_dir=self.root / "releases",
                                   play_dir=self.root / "plays",
                                   policy_dir=self.root / "policies")

    def run_release(self, door, resume=False):  # dr._Base already has self.go
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = vpsrun.run_release(self.release(), door, rf.typed, dr.TTY(),
                                    sleep=door.sleep, resume=resume,
                                    notify=lambda ev, f: None)
        return rc, out.getvalue()

    def test_reconcile_releases_the_lock_and_resume_completes(self):
        # The door took the lock and launched the step detached; the session
        # dropped. The step finished on the host; the lock stayed.
        token = lock.acquire(dr.HOST, "alice", "night release", runner=dr._local)
        _, out, _ = dr._local(dr.HOST, detach.launch_cmd(token, 1, "echo app up", token,
                                                         unmanaged_ok=True))
        self.assertIn(detach.LAUNCHED, out)
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        door = UncertainDoor(uncertain=[self.CMD], host=dr.HOST, op=token, window=0)

        rc, out = self.run_release(door)
        self.assertEqual(rc, 1)
        self.assertIn("  vpsexec reconcile %s\n" % dr.HOST, out)
        with self.assertRaises(vpsrun.Refused):
            self.run_release(door, resume=True)

        guard = Guard(dr._governor(), True)
        policy = {"groups": {}, "runbooks": [], "deny_extra": [], "risky_extra": [],
                  "files": []}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vpsexec.reconcile([dr.HOST], guard, policy, ssh=dr._local,
                                               stream=dr.TTY(), prompt=rf.typed), 0)
        self.assertFalse(Path(lock.LOCK_DIR).exists())
        self.assertEqual(self.events("reconciled")[-1]["operation_id"], token)

        rc, out = self.run_release(door, resume=True)  # types SKIP-DONE:recreate:1
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), [self.CMD, "mkdir /srv/after"])
        self.assertIn("reconciled (verdict COMPLETED rc=0)", out)
        runs = vpsexeclog.read(vpsrun.RUN_STREAM)
        self.assertEqual(len(set(r["run_id"] for r in runs)), 1)
        self.assertEqual(runs[-1]["event"], "run_complete")


# ===========================================================================
# W1 lint vs W3 plays and releases
# ===========================================================================

def _cond_play(when="w1 reports old schema", ids=("w1",)):
    steps = rc_.LintTest._play_steps(None, include_optional=True)
    steps[1]["id"] = ids[0]
    if len(ids) > 1:
        steps[0]["id"] = ids[1]
    if when is not None:
        steps[2]["when"] = when
    return steps


class LintPlayConditionTest(rc_._Estate):

    def policy(self):
        return rc_.LintTest._optional_policy(None)

    def test_a_conditional_optional_step_passes(self):
        self.write_play(_cond_play())
        rep = self.lint(self.policy())
        self.assertEqual(self.status(rep, "play shop.yaml"), "pass", runbookcheck.render(rep))
        self.assertEqual(self.status(rep, "optional steps"), "pass")

    def test_an_unconditional_optional_step_warns(self):
        self.write_play(_cond_play(when=None))
        rep = self.lint(self.policy())
        self.assertEqual(self.status(rep, "play shop.yaml"), "warn")
        self.assertIn("unconditionally", self.evidence(rep, "play shop.yaml"))

    def test_when_must_name_an_earlier_id(self):
        for when, needle in (("w9 reports x", "EARLIER"), ("w1 says x", "must read"),
                             ("w1 reports (", "does not compile")):
            with self.subTest(when=when):
                self.write_play(_cond_play(when=when))
                rep = self.lint(self.policy())
                self.assertEqual(self.status(rep, "play shop.yaml"), "fail")
                self.assertIn(needle, self.evidence(rep, "play shop.yaml"))
                self.assertEqual(rep["verdict"], "NO-GO")

    def test_a_duplicate_or_malformed_id_fails(self):
        for ids, needle in ((("w1", "w1"), "already used"), (("bad id!",), "must be 1-32")):
            with self.subTest(ids=ids):
                self.write_play(_cond_play(when=None, ids=ids))
                rep = self.lint(self.policy())
                self.assertEqual(self.status(rep, "play shop.yaml"), "fail")
                self.assertIn(needle, self.evidence(rep, "play shop.yaml"))

    def test_lint_agrees_with_vpsrun_on_a_valid_play(self):
        self.write_play(_cond_play())
        play = vpsrun.load_play(self.root / "plays" / "shop.yaml")  # vpsrun accepts it
        self.assertEqual(play["steps"][2]["when"]["id"], "w1")


ROLLBACK_STEPS = [
    {"cmd": "vpscfg-push %s shop.tar.gz" % rc_.SHA, "why": "stage", "timeout": 120},
    {"cmd": "docker compose --project-directory /srv/shop up -d --no-build app",
     "why": "recreate", "timeout": 240},
    {"cmd": "docker compose --project-directory /srv/shop restart app",
     "why": "put the old one back", "timeout": 240, "rollback": True},
]


class LintReleaseTest(rc_._Estate):

    def setUp(self):
        super().setUp()
        (self.root / "releases").mkdir()
        self.write_play(rc_.LintTest._play_steps(None))

    def write_release(self, text, name="night.yaml"):
        (self.root / "releases" / name).write_text(text)

    def policy(self, break_glass=False):
        text = rc_._policy_text(steps=ROLLBACK_STEPS, assumes=rc_.ASSUMES_OK)
        if break_glass:
            text = text.replace('    why: "recreate"\n',
                                '    why: "recreate"\n    break_glass: true\n')
            text = text.replace("break_glass: false}", "break_glass: mixed}")
        return text

    def test_no_release_is_skipped_and_stays_go(self):
        rep = self.lint(self.policy())
        self.assertEqual(self.status(rep, "releases"), "skip")
        self.assertEqual(rep["verdict"], "GO", runbookcheck.render(rep))

    def test_release_naming_a_missing_play_fails(self):
        self.write_release('version: 1\nreason: "r"\nplays:\n  - shop\n  - nosuch\n')
        rep = self.lint(self.policy())
        self.assertEqual(self.status(rep, "release night.yaml"), "fail")
        self.assertIn("nosuch.yaml is not a file", self.evidence(rep, "release night.yaml"))

    def test_on_fail_must_be_a_rollback_step_of_this_policy(self):
        for step, status in ((3, "pass"), (2, "fail"), (9, "fail")):
            with self.subTest(step=step):
                self.write_release('version: 1\nreason: "r"\nplays: [shop]\n'
                                   'policies: [shop-release.yaml]\n'
                                   'on_fail:\n  - runbook: shop-release.yaml\n'
                                   '    step: %d\n' % step)
                rep = self.lint(self.policy())
                self.assertEqual(self.status(rep, "release night.yaml"), status,
                                 runbookcheck.render(rep))

    def test_release_running_break_glass_steps_must_list_the_policy(self):
        self.write_release('version: 1\nreason: "r"\nplays: [shop]\n')
        rep = self.lint(self.policy(break_glass=True))
        self.assertEqual(self.status(rep, "policy"), "pass", runbookcheck.render(rep))
        self.assertEqual(self.status(rep, "release night.yaml"), "warn")
        self.assertIn("policies:", self.evidence(rep, "release night.yaml"))
        self.write_release('version: 1\nreason: "r"\nplays: [shop]\n'
                           'policies: [shop-release.yaml]\n')
        rep = self.lint(self.policy(break_glass=True))
        self.assertEqual(self.status(rep, "release night.yaml"), "pass")

    def test_unrelated_release_is_ignored(self):
        (self.root / "plays" / "other.yaml").write_text(json.dumps(
            {"version": 1, "reason": "x", "steps": [
                {"hosts": "web3", "cmd": "systemctl restart caddy", "why": "x"}]}))
        self.write_release('version: 1\nreason: "r"\nplays: [other]\n')
        self.assertEqual(self.status(self.lint(self.policy()), "releases"), "skip")

    def test_cli_releases_flag(self):
        other = Path(self.tmp.name) / "elsewhere"
        other.mkdir()
        (other / "night.yaml").write_text('version: 1\nreason: "r"\nplays: [shop, gone]\n')
        path = self.write_policy(self.policy())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = runbookcheck.cli(["lint", str(path), "--releases", str(other), "--json"],
                                    self.guard, tv._yaml_policy(), today=rc_.TODAY,
                                    now=rc_.NOW)
        rep = json.loads(out.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(self.status(rep, "release night.yaml"), "fail")


if __name__ == "__main__":
    unittest.main()
