"""Regression tests for the security review of feat/release-valves.

One test class (or more) per finding, named by its id (H1-H4, M1-M8, L1-L8).
The review's probe (test_probe_resume.py) is ported as ProbeResumeTest: the
same two scenarios, now asserting the fixed behaviour instead of printing.

Hermetic: temp dirs, fake doors, a local bash standing in for a host.
"""
import contextlib
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_detach_reconcile as dr  # noqa: E402  (modules, not names: no re-collection)
import test_grant_kinds as tk  # noqa: E402
import test_hostindex as ti_host  # noqa: E402
import test_release_flow as rf  # noqa: E402
import test_vpsexec as tv  # noqa: E402
import test_vpsexec_grant as tg  # noqa: E402
import test_vpsexec_incident as ti  # noqa: E402
from vpscfg import (detach, gitcmd, hostindex, indexstore, integrations, journal,  # noqa: E402
                    lock, notify, telemetry, vpsexec, vpsexecgrant, vpsexecincident,
                    vpsexeclog)
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

vpsrun = rf.vpsrun
OP = "a" * 64


# ===========================================================================
# H1 / H2: settling a step that reached the door (ported probe)
# ===========================================================================

class ProbeResumeTest(rf._Base):
    TAG = "docker tag app:1 app:live"

    def _killed_mid_step(self, step_record_op=None):
        # run 1: stage-a step 2 fails normally, so the run is unfinished
        door = rf.SimDoor(rcs={self.TAG: [1]}, window=0)
        self.go(door)
        run_id = self.run_events()[0]["run_id"]
        play = self.release()["plays"][1]
        step = play["steps"][0]
        dig = rf.SimDoor.digest(step["cmd"])
        vpsrun._rjournal({"event": "step_started", "run_id": run_id,
                          "play": vpsrun._key(play), "step": 1, "digest": dig})
        # the door child got SIGHUP mid-step: attempt journaled, nothing after
        reason = vpsrun.step_reason(play, 1, step, run_id)
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": dig,
                                   "reason": reason, "command": step["cmd"],
                                   "hosts": [step["hosts"]]})
        if step_record_op:  # the door lost contact on this host's step
            journal.append("vpsexec", {"event": "step", "host": step["hosts"],
                                       "remote": step["cmd"], "rc": None, "uncertain": True,
                                       "operation_id": step_record_op})
        door.calls.clear()
        return door, step, reason

    def _resume(self, door, answer=None):
        def prompt(msg):
            if "COMPLETED rc=0 on every host" in msg:
                return answer or ""
            return rf.typed(msg)
        return self.go(door, resume=True, prompt=prompt)

    # --- H2 -------------------------------------------------------------------
    def test_unsettled_kill_refuses_and_names_reconcile(self):
        door, step, _ = self._killed_mid_step()
        with self.assertRaises(vpsrun.Refused) as cm:
            self._resume(door)
        self.assertIn("vpsexec reconcile %s" % step["hosts"], str(cm.exception))
        self.assertIn("refuses to guess", str(cm.exception))
        self.assertEqual(door.runs(), [])

    def test_an_unrelated_reconcile_does_not_unblock_a_killed_run(self):
        """The probe's scenario: a `reconciled` record that names neither this
        attempt's operation nor this step's reason settles nothing."""
        door, step, _ = self._killed_mid_step()
        journal.append("vpsexec", {"event": "reconciled", "host": step["hosts"],
                                   "operation_id": OP, "verdict": "COMPLETED", "rc": 0})
        for _ in range(2):
            with self.assertRaises(vpsrun.Refused):
                self._resume(door, "SKIP-DONE:stage-b:1")
        self.assertEqual(door.runs(), [])

    def test_reconcile_by_lock_owner_reason_settles_a_killed_run(self):
        door, step, reason = self._killed_mid_step()
        journal.append("vpsexec", {"event": "reconciled", "host": step["hosts"],
                                   "operation_id": OP, "verdict": "COMPLETED", "rc": 0,
                                   "owner": {"operator": "alice", "reason": reason,
                                             "operation_id": OP}})
        rc, out = self._resume(door, "SKIP-DONE:stage-b:1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), [self.TAG])  # stage-b step 1 counted done (H3)

    def test_reconcile_by_step_record_op_settles_a_killed_run(self):
        door, step, _ = self._killed_mid_step(step_record_op=OP)
        journal.append("vpsexec", {"event": "reconciled", "host": step["hosts"],
                                   "operation_id": OP, "verdict": "UNKNOWN", "rc": None})
        rc, out = self._resume(door)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), [self.TAG, "mkdir /srv/b"])  # UNKNOWN: re-run

    def test_free_lock_settles_a_killed_run_and_reruns(self):
        door, step, _ = self._killed_mid_step()
        journal.append("vpsexec", {"event": "reconcile_free", "host": step["hosts"]})
        rc, out = self._resume(door)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), [self.TAG, "mkdir /srv/b"])

    # --- H1 -------------------------------------------------------------------
    def test_changed_digest_after_kill_refuses(self):
        door, step, _ = self._killed_mid_step()
        orig = rf.SimDoor.digest
        rf.SimDoor.digest = staticmethod(
            lambda cmd: orig(cmd + " ") if cmd == step["cmd"] else orig(cmd))
        try:
            with self.assertRaises(vpsrun.Refused) as cm:
                self._resume(door)
        finally:
            rf.SimDoor.digest = staticmethod(orig)
        self.assertIn("changed after it reached the door", str(cm.exception))
        self.assertEqual(door.runs(), [])

    def test_changed_digest_with_a_recorded_outcome_also_refuses(self):
        """vpsrun died after the door completed the step: settled by the
        digest the start recorded, and a changed plan still refuses."""
        door, step, reason = self._killed_mid_step()
        journal.append("vpsexec", {"event": "mutation_complete", "command": step["cmd"],
                                   "hosts": [step["hosts"]], "failed": [], "not_run": []})
        orig = rf.SimDoor.digest
        rf.SimDoor.digest = staticmethod(
            lambda cmd: orig(cmd + " ") if cmd == step["cmd"] else orig(cmd))
        try:
            with self.assertRaises(vpsrun.Refused) as cm:
                self._resume(door)
        finally:
            rf.SimDoor.digest = staticmethod(orig)
        self.assertIn("changed after it reached the door", str(cm.exception))

    def test_unchanged_digest_with_recorded_ok_is_skipped(self):
        door, step, _ = self._killed_mid_step()
        journal.append("vpsexec", {"event": "mutation_complete", "command": step["cmd"],
                                   "hosts": [step["hosts"]], "failed": [], "not_run": []})
        rc, out = self._resume(door)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), [self.TAG])

    def test_start_that_never_reached_the_door_runs_under_its_new_plan(self):
        door = rf.SimDoor(rcs={self.TAG: [1]}, window=0)
        self.go(door)
        run_id = self.run_events()[0]["run_id"]
        play = self.release()["plays"][1]
        vpsrun._rjournal({"event": "step_started", "run_id": run_id,
                          "play": vpsrun._key(play), "step": 1, "digest": "0" * 64})
        door.calls.clear()
        rc, out = self._resume(door)
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), [self.TAG, "mkdir /srv/b"])


OPA, OPB = "a" * 64, "b" * 64


class MultiHostResumeTest(rf._Base):
    """Verifier H2/H3: stage-b step 1 reached the door on edge1 AND edge2, and
    the door died before its mutation_complete."""
    TAG = "docker tag app:1 app:live"

    def _killed_two_hosts(self, b_finished=True, b_rc=0):
        door = rf.SimDoor(rcs={self.TAG: [1]}, window=0)
        self.go(door)
        run_id = self.run_events()[0]["run_id"]
        play = self.release()["plays"][1]
        step = play["steps"][0]
        dig = rf.SimDoor.digest(step["cmd"])
        vpsrun._rjournal({"event": "step_started", "run_id": run_id,
                          "play": vpsrun._key(play), "step": 1, "digest": dig})
        reason = vpsrun.step_reason(play, 1, step, run_id)
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": dig,
                                   "reason": reason, "command": step["cmd"],
                                   "hosts": ["edge1", "edge2"]})
        if b_finished:  # the door finished edge2: step, verify, lock released
            journal.append("vpsexec", {"event": "step", "host": "edge2",
                                       "remote": step["cmd"], "rc": b_rc,
                                       "operation_id": OPB})
            journal.append("vpsexec", {"event": "host_done", "host": "edge2",
                                       "operation_id": OPB, "rc": b_rc, "verify_rc": None,
                                       "reason": reason, "plan_hash": dig})
        door.calls.clear()
        return door, reason

    def killed(self, hosts):
        door = rf.SimDoor(rcs={self.TAG: [1]}, window=0)
        self.go(door)
        run_id = self.run_events()[0]["run_id"]
        play = self.release()["plays"][1]
        step = play["steps"][0]
        dig = rf.SimDoor.digest(step["cmd"])
        vpsrun._rjournal({"event": "step_started", "run_id": run_id,
                          "play": vpsrun._key(play), "step": 1, "digest": dig})
        reason = vpsrun.step_reason(play, 1, step, run_id)
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": dig,
                                   "reason": reason, "command": step["cmd"], "hosts": hosts})
        self._attempt = (reason, dig)
        door.calls.clear()
        return door, reason

    OPS = {"edge1": "a" * 64, "edge2": "b" * 64, "edge3": "c" * 64, "edge4": "d" * 64}

    def step_rec(self, h, rc=0):
        journal.append("vpsexec", {"event": "step", "host": h, "remote": "x", "rc": rc,
                                   "operation_id": self.OPS[h]})

    def host_done(self, h, rc=0, verify_rc=None, op=None):
        """The door's host_done, as it writes it: the attempt's reason and
        plan hash with it."""
        reason, dig = self._attempt
        journal.append("vpsexec", {"event": "host_done", "host": h, "rc": rc,
                                   "verify_rc": verify_rc,
                                   "operation_id": op or self.OPS[h],
                                   "reason": reason, "plan_hash": dig})

    # --- verifier round 4 ---------------------------------------------------
    def test_op_unknown_later_unrelated_host_done(self):
        # The door died on edge1 before any step record (op unknown). Later an
        # unrelated operation on edge1 finishes: its host_done is not this
        # attempt's and must never settle it.
        door, _ = self.killed(["edge1"])
        journal.append("vpsexec", {"event": "reconcile_free", "host": "edge1"})
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": "e" * 64,
                                   "reason": "someone else's unrelated fix",
                                   "command": "other", "hosts": ["edge1"]})
        journal.append("vpsexec", {"event": "host_done", "host": "edge1",
                                   "operation_id": "f" * 64, "rc": 0, "verify_rc": None,
                                   "reason": "someone else's unrelated fix",
                                   "plan_hash": "e" * 64})
        (rc, out), asked = self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(asked and [a for a in asked if "SKIP-DONE" in a], [])
        self.assertIn(self.TAG, door.runs())  # it ran again, never counted done
        self.assertNotIn("finished before the door died", out)

    def test_host_done_without_this_attempts_reason_never_settles(self):
        # Same op id and host, but not this attempt's reason/plan hash (an
        # older-format or foreign record): it settles nothing.
        door, _ = self.killed(["edge1"])
        self.step_rec("edge1")
        journal.append("vpsexec", {"event": "host_done", "host": "edge1", "rc": 0,
                                   "verify_rc": None, "operation_id": self.OPS["edge1"]})
        with self.assertRaises(vpsrun.Refused) as cm:
            self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertIn("vpsexec reconcile edge1", str(cm.exception))

    def test_host_done_after_the_next_attempt_on_the_host_never_counts(self):
        # Op unknown; a later attempt on edge1 (same reason and plan, e.g. a
        # retried door) finishes. Its host_done is past this attempt's window.
        door, reason = self.killed(["edge1"])
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": self._attempt[1],
                                   "reason": reason, "command": "other", "hosts": ["edge1"]})
        self.host_done("edge1")
        recs = vpsexeclog.read()
        idx = [i for i, r in enumerate(recs) if r.get("event") == "mutation_attempt"]
        play = self.release()["plays"][1]
        u = {"play": play, "n": 1, "step": play["steps"][0]}
        run_id = self.run_events()[0]["run_id"]
        entries, _ = vpsrun._uncertain_ops(u, run_id, recs, self._attempt[1])
        first = [e for e in entries if e["attempt"] == idx[-2]]
        later = [e for e in entries if e["attempt"] == idx[-1]]
        self.assertEqual(len(first), 1)
        self.assertIsNone(first[0].get("settled"))  # not the later attempt's host_done
        self.assertEqual(later[0]["settled"]["event"], "finished")  # that one is its own

    def test_reconciled_outranks_host_done(self):
        door, reason = self.killed(["edge1"])
        self.step_rec("edge1")
        self.host_done("edge1")
        self.reconciled("edge1", self.OPS["edge1"], reason, verdict="UNKNOWN", rc=None)
        (rc, out), asked = self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertEqual(rc, 0, out)
        self.assertEqual([a for a in asked if "SKIP-DONE" in a], [])  # never offered
        self.assertIn(self.TAG, door.runs())  # it runs again
        self.assertIn("reconciled (verdict UNKNOWN)", out)

    def test_crash_after_release_before_host_done(self):
        door, _ = self.killed(["edge1", "edge2"])
        self.step_rec("edge1")
        self.step_rec("edge2")
        self.host_done("edge2")
        # edge1: the door released the lock, then died before its host_done.
        journal.append("vpsexec", {"event": "reconcile_free", "host": "edge1"})
        with self.assertRaises(vpsrun.Refused):
            self.resume(door, "SKIP-DONE:stage-b:1")  # never SKIP
        (rc, out), asked = self.resume(door, "RERUN:stage-b:1")
        self.assertEqual(rc, 0, out)
        self.assertTrue(any("COMPLETED on edge2 but not on edge1" in a for a in asked), asked)
        self.assertIn("RELEASED, OUTCOME UNKNOWN", out)
        self.assertIn(self.TAG, door.runs())

    def test_crash_after_release_alone_runs_again(self):
        door, _ = self.killed(["edge1"])
        self.step_rec("edge1")
        journal.append("vpsexec", {"event": "reconcile_free", "host": "edge1"})
        (rc, out), asked = self.resume(door)
        self.assertEqual(rc, 0, out)
        self.assertEqual([a for a in asked if "SKIP-DONE" in a or "RERUN" in a], [])
        self.assertIn(self.TAG, door.runs())

    # --- verifier round 2: a per-step record is not "finished" -------------
    def test_died_between_container_steps_is_not_finished(self):
        door, _ = self.killed(["edge1"])
        self.step_rec("edge1")  # container 1 done; container 2 running; lock held
        with self.assertRaises(vpsrun.Refused) as cm:
            self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertIn("vpsexec reconcile edge1", str(cm.exception))
        self.assertEqual(door.runs(), [])

    def test_died_during_verify_is_not_finished(self):
        door, _ = self.killed(["edge1"])
        self.step_rec("edge1")
        journal.append("vpsexec", {"event": "verify", "host": "edge1", "rc": 0,
                                   "remote": "v"})  # verify ran; lock never released
        with self.assertRaises(vpsrun.Refused) as cm:
            self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertIn("vpsexec reconcile edge1", str(cm.exception))

    def test_finished_with_a_failed_verify_is_not_done(self):
        door, _ = self.killed(["edge1", "edge2"])
        self.step_rec("edge1")
        self.host_done("edge1", rc=1, verify_rc=1)
        self.step_rec("edge2")
        self.host_done("edge2")
        (rc, out), asked = self.resume(door, "RERUN:stage-b:1")
        self.assertEqual(rc, 0, out)
        self.assertIn("COMPLETED on edge2 but not on edge1", asked[0])

    def test_four_hosts_finished_completed_unknown_free(self):
        door, reason = self.killed(["edge1", "edge2", "edge3", "edge4"])
        self.step_rec("edge1")
        self.host_done("edge1")
        self.reconciled("edge2", self.OPS["edge2"], reason)
        self.reconciled("edge3", self.OPS["edge3"], reason, verdict="UNKNOWN", rc=None)
        journal.append("vpsexec", {"event": "reconcile_free", "host": "edge4"})
        with self.assertRaises(vpsrun.Refused):
            self.resume(door, "SKIP-DONE:stage-b:1")
        (rc, out), asked = self.resume(door, "RERUN:stage-b:1")
        self.assertEqual(rc, 0, out)
        self.assertIn("COMPLETED on edge1, edge2 but not on edge3, edge4", asked[0])

    def test_three_hosts_one_unreconciled_names_only_it(self):
        door, reason = self.killed(["edge1", "edge2", "edge3"])
        self.step_rec("edge1")
        self.host_done("edge1")
        self.reconciled("edge2", self.OPS["edge2"], reason)
        with self.assertRaises(vpsrun.Refused) as cm:
            self.resume(door)
        self.assertIn("vpsexec reconcile edge3", str(cm.exception))
        self.assertNotIn("reconcile edge1", str(cm.exception))
        self.assertNotIn("reconcile edge2", str(cm.exception))

    def test_all_done_prompt_names_its_evidence_per_host(self):
        door, reason = self.killed(["edge1", "edge2", "edge3"])
        for h in ("edge1", "edge2"):
            self.step_rec(h)
            self.host_done(h)
        self.reconciled("edge3", self.OPS["edge3"], reason)
        (rc, out), asked = self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertEqual(rc, 0, out)
        prompt = asked[0]
        self.assertNotIn("Reconcile says", prompt)
        self.assertIn("edge1: finished by the door", prompt)
        self.assertIn("edge3: reconciled COMPLETED", prompt)
        done = [r for r in self.run_events() if r.get("settled_from")]
        self.assertEqual(done[-1]["settled_from"], "door+reconcile")

    def test_only_door_evidence_never_claims_a_reconcile(self):
        door, _ = self.killed(["edge1"])
        self.step_rec("edge1")
        self.host_done("edge1")
        (rc, out), asked = self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("econcile", asked[0])
        done = [r for r in self.run_events() if r.get("settled_from")]
        self.assertEqual(done[-1]["settled_from"], "door")

    def reconciled(self, host, op, reason, verdict="COMPLETED", rc=0):
        journal.append("vpsexec", {"event": "reconciled", "host": host,
                                   "operation_id": op, "verdict": verdict, "rc": rc,
                                   "owner": {"reason": reason, "operation_id": op}})

    def resume(self, door, answer=""):
        asked = []

        def prompt(msg):
            asked.append(msg)
            if msg.startswith("stage-b step 1 COMPLETED") or "Type RERUN:" in msg:
                return answer
            return rf.typed(msg)
        return self.go(door, resume=True, prompt=prompt), asked

    def test_a_host_that_finished_before_the_door_died_settles_itself(self):
        door, reason = self._killed_two_hosts()
        self.reconciled("edge1", OPA, reason)
        journal.append("vpsexec", {"event": "reconcile_free", "host": "edge2"})
        (rc, out), asked = self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(door.runs(), [self.TAG])  # step 1 of stage-b counted done
        self.assertIn("finished before the door died", out)

    def test_finished_host_needs_no_reconcile_but_the_other_does(self):
        door, reason = self._killed_two_hosts()
        with self.assertRaises(vpsrun.Refused) as cm:
            self.resume(door)
        self.assertIn("vpsexec reconcile edge1", str(cm.exception))
        self.assertNotIn("reconcile edge2", str(cm.exception))

    def test_mixed_completed_and_unknown_needs_an_explicit_rerun(self):
        door, reason = self._killed_two_hosts(b_finished=False)
        self.reconciled("edge1", OPA, reason)
        self.reconciled("edge2", OPB, reason, verdict="UNKNOWN", rc=None)
        for answer in ("", "SKIP-DONE:stage-b:1", "RERUN:stage-a:2"):
            with self.subTest(answer=answer):
                with self.assertRaises(vpsrun.Refused) as cm:
                    self.resume(door, answer)
                self.assertIn("nothing ran", str(cm.exception))
        self.assertEqual(door.runs(), [])
        (rc, out), asked = self.resume(door, "RERUN:stage-b:1")
        self.assertEqual(rc, 0, out)
        self.assertIn("COMPLETED on edge1 but not on edge2", asked[0])
        self.assertIn("including edge1", asked[0])
        self.assertEqual(door.runs()[:2], [self.TAG, "mkdir /srv/b"])

    def test_mixed_completed_and_free_needs_an_explicit_rerun(self):
        door, reason = self._killed_two_hosts(b_finished=False)
        self.reconciled("edge1", OPA, reason)
        journal.append("vpsexec", {"event": "reconcile_free", "host": "edge2"})
        with self.assertRaises(vpsrun.Refused):
            self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertEqual(door.runs(), [])

    def test_finished_with_a_failure_and_unknown_elsewhere_reruns(self):
        door, reason = self._killed_two_hosts(b_rc=3)
        self.reconciled("edge1", OPA, reason, verdict="UNKNOWN", rc=None)
        (rc, out), asked = self.resume(door)
        self.assertEqual(rc, 0, out)
        self.assertFalse([a for a in asked if "COMPLETED" in a])
        self.assertEqual(door.runs()[:2], [self.TAG, "mkdir /srv/b"])

    def test_completed_door_attempt_with_one_retained_host_is_mixed(self):
        """lock_retained on edge1, edge2 succeeded per the door: re-running
        would repeat it on edge2, so it needs an explicit RERUN."""
        door = rf.SimDoor(rcs={self.TAG: [1]}, window=0)
        self.go(door)
        run_id = self.run_events()[0]["run_id"]
        play = self.release()["plays"][1]
        step = play["steps"][0]
        dig = rf.SimDoor.digest(step["cmd"])
        reason = vpsrun.step_reason(play, 1, step, run_id)
        vpsrun._rjournal({"event": "step_started", "run_id": run_id,
                          "play": vpsrun._key(play), "step": 1, "digest": dig})
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": dig,
                                   "reason": reason, "command": step["cmd"],
                                   "hosts": ["edge1", "edge2"]})
        journal.append("vpsexec", {"event": "mutation_complete", "command": step["cmd"],
                                   "hosts": ["edge1", "edge2"], "failed": ["edge1"],
                                   "not_run": [], "lock_retained": {"edge1": OPA}})
        self.reconciled("edge1", OPA, reason, verdict="UNKNOWN", rc=None)
        door.calls.clear()
        with self.assertRaises(vpsrun.Refused):
            self.resume(door, "SKIP-DONE:stage-b:1")
        self.assertEqual(door.runs(), [])

    def test_multi_host_changed_digest_refuses(self):
        door, _ = self._killed_two_hosts()
        orig = rf.SimDoor.digest
        rf.SimDoor.digest = staticmethod(
            lambda cmd: orig(cmd + " ") if cmd == "mkdir /srv/b" else orig(cmd))
        try:
            with self.assertRaises(vpsrun.Refused) as cm:
                self.resume(door)
        finally:
            rf.SimDoor.digest = staticmethod(orig)
        self.assertIn("changed after it reached the door", str(cm.exception))
        self.assertEqual(door.runs(), [])


# ===========================================================================
# H4a: a reusable grant is bound to its scope files' git history
# ===========================================================================

class GitBindingTest(tk._KindsHarness):
    NGINX = tk.NGINX

    def edit(self, text="# an edit\n"):
        with open(self.policy_dir / "rb.yaml", "a") as f:
            f.write(text)
        self.reload_policy()

    def test_mint_records_the_committed_blob_and_head(self):
        # Round 5: the commit is the fetched policy-remote commit (pushed HEAD).
        g = self.load(self.mint_reusable())
        self.assertEqual(g["scope"]["git"], {
            "commit": self.git("--git-dir", str(self.origin), "rev-parse", "refs/heads/main"),
            "blobs": {"rb.yaml": self.git("rev-parse", "HEAD:rb.yaml")},
            "toplevel": os.path.realpath(self.git("rev-parse", "--show-toplevel")),
            "remote": {"name": "origin", "ref": "main", "url": str(self.origin)}})
        self.assertEqual(g["scope"]["git"]["commit"], self.git("rev-parse", "HEAD"))

    def test_an_uncommitted_edit_refuses_at_use(self):
        path = self.mint_reusable()
        self.edit()
        self.refuses(path, "uncommitted")

    def test_a_committed_edit_is_a_descendant_and_works(self):
        path = self.mint_reusable()
        self.edit()
        self.commit("reviewed edit")
        self.assertEqual(self.use("web1", self.NGINX, path), 0)

    def test_an_untracked_scope_file_refuses_at_mint(self):
        shutil.copy(self.policy_dir / "rb.yaml", self.policy_dir / "rb2.yaml")
        self.reload_policy()
        with self.assertRaises(Refused) as cm:
            self.mint_reusable(name="rb2")
        self.assertIn("pushed to origin/main", str(cm.exception))

    def test_an_uncommitted_edit_refuses_at_mint(self):
        self.edit()
        with self.assertRaises(Refused) as cm:
            self.mint_reusable()
        self.assertIn("uncommitted", str(cm.exception))

    def test_rewritten_history_refuses(self):
        path = self.mint_reusable()
        self.git("checkout", "-q", "--orphan", "rewritten")
        self.edit("# the same file, from a history that never held the minted one\n")
        self.commit("orphan", push=False)
        self.refuses(path, "unpushed")       # a local rewrite is not pushed
        self.push(force=True)                # and a rewritten remote refuses too
        self.refuses(path, "force-pushed or rewritten")

    def test_no_repository_refuses(self):
        path = self.mint_reusable()
        shutil.rmtree(self.policy_dir / ".git")
        self.refuses(path, "not in a git repository")

    def test_no_git_binary_fails_closed(self):
        path = self.mint_reusable()
        with mock.patch.object(gitcmd, "GIT_CANDIDATES", ("/nonexistent/git",)):
            self.refuses(path, "git is not available")

    # --- verifier: the edit the index lies about -------------------------
    NEWCMD = "systemctl restart postgres"

    def _new_break_glass_command(self):
        """An agent's uncommitted edit: step two now runs a different command."""
        p = self.policy_dir / "rb.yaml"
        p.write_text(p.read_text().replace('cmd: "systemctl restart caddy"',
                                           'cmd: "%s"' % self.NEWCMD))
        self.reload_policy()

    def _refuses_new_command(self, path):
        with self.assertRaises(Refused) as cm:
            self.use("web1", self.NEWCMD, path)
        self.assertIn("uncommitted", str(cm.exception))
        self.assertEqual(self.ran(), [], "the never-committed command ran")

    def test_assume_unchanged_cannot_hide_an_uncommitted_edit(self):
        path = self.mint_reusable()
        self._new_break_glass_command()
        self.git("update-index", "--assume-unchanged", "rb.yaml")
        self._refuses_new_command(path)

    def test_skip_worktree_cannot_hide_an_uncommitted_edit(self):
        path = self.mint_reusable()
        self._new_break_glass_command()
        self.git("update-index", "--skip-worktree", "rb.yaml")
        self._refuses_new_command(path)

    def test_a_fake_git_on_path_is_never_run(self):
        path = self.mint_reusable()
        self._new_break_glass_command()
        fake = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, fake)
        marker = fake / "fake-git-ran"
        (fake / "git").write_text("#!/bin/sh\ntouch %s\nexit 0\n" % marker)
        (fake / "git").chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": "%s:%s" % (fake, os.environ["PATH"]),
                                          "GIT_DIR": str(fake), "GIT_INDEX_FILE": "/x"}):
            self._refuses_new_command(path)
        self.assertFalse(marker.exists(), "git was taken from PATH")

    def test_repository_fsmonitor_hook_is_never_executed(self):
        path = self.mint_reusable()
        marker = Path(self.home.name) / "fsmon-ran"
        hook = Path(self.home.name) / "fsmon.sh"
        hook.write_text("#!/bin/sh\ntouch %s\nexit 1\n" % marker)
        hook.chmod(0o755)
        self.git("config", "core.fsmonitor", str(hook))
        self.assertEqual(self.use("web1", self.NGINX, path), 0)
        self.assertFalse(marker.exists(), "a repository's core.fsmonitor ran")

    def test_a_committed_edit_is_accepted_committing_is_not_review(self):
        """By design (documented in the Threats text): a same-user commit
        makes the edit valid — the binding proves history, not review."""
        path = self.mint_reusable()
        self._new_break_glass_command()
        self.commit("agent edit")
        self.assertEqual(self.use("web1", self.NEWCMD, path), 0)
        # Round 5: the binding is to PUSHED policy; the docs say pushing is
        # not review unless the branch is protected.
        self.assertIn("pushing is not review", vpsexecgrant.__doc__.lower()
                      + open(vpsexecgrant.__file__).read().lower())

    def test_the_policy_bytes_must_be_what_the_loader_read(self):
        path = self.mint_reusable()
        p = self.policy_dir / "rb.yaml"
        p.write_text(p.read_text() + "# after load\n")  # NOT reloaded
        self.commit("after load")
        self.refuses(path, "changed since the policy was loaded")

    def test_pinned_git_ignores_a_group_writable_binary(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        bad = tmp / "git"
        bad.write_text("#!/bin/sh\nexit 0\n")
        bad.chmod(0o775)
        with self.assertRaises(Refused):
            gitcmd.binary((str(bad),))

    def test_a_grant_minted_before_the_binding_refuses(self):
        path = self.mint_reusable()
        g = self.load(path)
        del g["scope"]["git"]
        self.reseal(path, g)
        self.refuses(path, "scope")


# ===========================================================================
# H4c / M6: plain vpsexec auto-picks only with --grant auto, never a
# release-bound grant; --no-grant; the refusal names the flag used
# ===========================================================================

class AutoPickOptInTest(tk._KindsHarness):

    def test_no_flag_lists_but_never_uses_a_grant(self):
        self.mint()
        typed = []

        def prompt(msg):
            typed.append(msg)
            return msg.split("Type ", 1)[1].split(" ", 1)[0]
        rc, out = self.run_auto(prompt=prompt)
        self.assertEqual(rc, 0)
        self.assertIn("grants  : 1 valid", out)  # vpsrun still reads the listing
        self.assertIn("auto-picks only with --grant auto", out)
        self.assertIn("BREAK-GLASS", typed[0])
        self.assertFalse([e for e in self.events()
                          if e["event"] in ("grant_autopicked", "grant_used")])

    def test_no_grant_never_lists_or_uses_one(self):
        self.mint()
        rc, out = self.run_auto(flag="--no-grant",
                                prompt=lambda m: m.split("Type ", 1)[1].split(" ", 1)[0])
        self.assertEqual(rc, 0)
        self.assertNotIn("grants  :", out)
        for flag in ("--grant=auto", "--approval-contract=/x.json"):
            with self.subTest(flag=flag), self.assertRaises(Refused) as cm:
                self.run_auto(flag="--no-grant", extra=[flag])
            self.assertIn("contradict", str(cm.exception))

    def test_refusal_names_the_flag_actually_used(self):
        bogus = str(self.policy_dir / "missing.json")
        for flag, needle in (("--grant=%s", "Drop --grant to"),
                             ("--approval-contract=%s", "Drop --approval-contract to")):
            with self.subTest(flag=flag), self.assertRaises(Refused) as cm:
                self.use("web1", tk.NGINX, bogus, flag=flag)
            self.assertIn(needle, str(cm.exception))

    def _release_bound(self):
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecgrant.cli(["new", "rb", "--kind", "reusable", "--ttl", "12h",
                              "--for-release", "weekend", "--run"], self.policy,
                             stream=tg._TTY(), prompt=lambda m: "REUSABLE-GRANT:rb:12h")
        return sorted(self.grant_dir.glob("ru_*.json"))[-1]

    def test_grant_auto_never_spends_a_release_bound_grant(self):
        path = self._release_bound()
        self.assertEqual(self.load(path)["release"], "weekend")
        with self.assertRaises(Refused) as cm:
            self.run_auto(flag="--grant=auto")
        self.assertIn("spent only by their release", str(cm.exception))
        self.assertEqual(self.ran(), [])
        # naming it is deliberate, not silent: allowed
        self.assertEqual(self.use("web1", tk.NGINX, path), 0)

    def test_plan_listing_marks_the_release(self):
        g = self.load(self._release_bound())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexec.dispatch(["web1", tk.NGINX, "--break-glass", "--reason", "x"],
                             guard=tv._guard(), prober=self.prober(), policy=self.policy,
                             ssh=self.fake_ssh(), stream=tg._TTY(), prompt=tg._no_prompt,
                             blackout_runner=self.blackout_runner(unavailable=True))
        info = rf.vpsrun.door_grants(out.getvalue())[g["session_id"]]
        self.assertEqual(info["release"], "weekend")


BOUND_LINE = rf.GRANT_LINE.replace("uses-left 50\n", "uses-left 50 release %s\n")


class ReleaseBoundPickTest(rf._Base):

    def plans(self, release):
        text = ("PLAN — 1 host: edge1\n  command : mkdir /srv/a\n"
                "  BREAK-GLASS: 1 of 1 host(s) elevated past posture — edge1(frozen)\n"
                + BOUND_LINE % release + "plan-hash: %s\n" % ("d" * 64))
        return [(text, "d" * 64)]

    def test_a_play_never_picks_a_release_bound_grant(self):
        self.assertIsNone(rf.vpsrun.auto_pick({"path": "p"}, self.plans("weekend"), [1]))

    def test_only_the_named_release_picks_it(self):
        self.assertIsNone(rf.vpsrun.auto_pick({"path": "p"}, self.plans("weekend"), [1],
                                              release="other"))
        self.assertIsNotNone(rf.vpsrun.auto_pick({"path": "p"}, self.plans("weekend"), [1],
                                                 release="weekend"))


# ===========================================================================
# H4b: a release-minted grant is narrowed and revoked when the run completes
# ===========================================================================

class BoundDoor(rf.SimDoor):
    def __init__(self, release, **kw):
        rf.SimDoor.__init__(self, **kw)
        self.release = release

    def __call__(self, argv):
        rc, out = rf.SimDoor.__call__(self, argv)
        return rc, out.replace(rf.GRANT_LINE, BOUND_LINE % self.release)


class ReleaseGrantLifetimeTest(rf._Base):
    def load_grant(self, path):
        return {"kind": "reusable", "session_id": rf.GRANT_ID}

    def test_completed_release_revokes_its_grant(self):
        door = BoundDoor("weekend", bg={"mkdir /srv/a"}, grants=True)
        rc, out = self.go(door, load_grant=self.load_grant)
        self.assertEqual(rc, 0, out)
        self.assertIn(rf.GRANT_ID, vpsexecgrant.revoked_ids())
        self.assertIn("revoked — release weekend completed", out)

    def test_halted_release_keeps_its_grant_for_resume(self):
        door = BoundDoor("weekend", bg={"mkdir /srv/a"}, grants=True,
                         rcs={"docker tag app:1 app:live": [1]})
        rc, _ = self.go(door, load_grant=self.load_grant)
        self.assertEqual(rc, 1)
        self.assertNotIn(rf.GRANT_ID, vpsexecgrant.revoked_ids())

    def test_unbound_grant_is_not_revoked(self):
        door = rf.SimDoor(bg={"mkdir /srv/a"}, grants=True)
        rc, out = self.go(door, load_grant=self.load_grant)
        self.assertEqual(rc, 0, out)
        self.assertNotIn(rf.GRANT_ID, vpsexecgrant.revoked_ids())


# ===========================================================================
# M7: a play boundary re-plans; changed plans need a new phrase
# ===========================================================================

class DriftDoor(rf.SimDoor):
    """stage-b's plan changes once stage-a's first step has run (as when an
    earlier play changes the containers a later one resolves)."""

    def digest(self, cmd):
        drift = "+drift" if cmd == "mkdir /srv/b" and "mkdir /srv/a" in self.runs() else ""
        return hashlib.sha256((cmd + drift).encode()).hexdigest()


class ReplanBoundaryTest(rf._Base):

    def test_changed_plan_needs_a_phrase_over_the_new_hashes(self):
        asked = []

        def prompt(msg):
            asked.append(msg)
            return rf.typed(msg)
        door = DriftDoor()
        rc, out = self.go(door, prompt=prompt)
        self.assertEqual(rc, 0, out)
        self.assertIn("RE-PLANNED play stage-b", out)
        replan = [a for a in asked if "REPLAN:stage-b" in a]
        new = door.digest("mkdir /srv/b")
        self.assertIn(rf.vpsrun.run_phrase("REPLAN:stage-b", [{"flags": []}], [new]),
                      replan[0])
        self.assertEqual(door.runs()[-1], "mkdir /srv/b")
        ev = [e for e in self.run_events() if e["event"] == "play_replanned"]
        self.assertEqual(ev[0]["steps"][0]["digest"], new)

    def test_refusing_the_new_plans_stops_before_the_play(self):
        def prompt(msg):
            return "no" if "REPLAN:" in msg else rf.typed(msg)
        door = DriftDoor()
        rc, out = self.go(door, prompt=prompt)
        self.assertEqual(rc, 3)
        self.assertNotIn("mkdir /srv/b", door.runs())
        self.assertIn("new plans not approved", out)

    def test_unchanged_plans_ask_nothing_more(self):
        asked = []

        def prompt(msg):
            asked.append(msg)
            return rf.typed(msg)
        rc, out = self.go(rf.SimDoor(), prompt=prompt)
        self.assertEqual(rc, 0, out)
        self.assertFalse([a for a in asked if "REPLAN:" in a])


# ===========================================================================
# M1 / M2 / M3 / L1 / L2: locks, op dirs, reconcile (local bash as the host)
# ===========================================================================

class _Reconcile(dr._Base):
    def setUp(self):
        super().setUp()
        vpsexecgrant._is_controlling_tty = lambda stream: stream.isatty()
        self.prompts = []

    def reconcile(self, *flags, answer=None):
        def prompt(msg):
            self.prompts.append(msg)
            return answer if answer is not None else msg.split("Type ", 1)[1].split(" ", 1)[0]
        guard = Guard(dr._governor(), True)
        policy = {"groups": {}, "runbooks": [], "deny_extra": [], "risky_extra": [],
                  "files": []}
        with contextlib.redirect_stdout(io.StringIO()) as out:
            try:
                rc = vpsexec.reconcile([dr.HOST] + list(flags), guard, policy,
                                       ssh=dr._local, stream=dr.TTY(), prompt=prompt)
            except Refused as r:
                return r, out.getvalue()
        return rc, out.getvalue()

    def owner(self):
        return json.loads(Path(lock.LOCK_DIR, "owner").read_text())

    def set_owner(self, meta):
        Path(lock.LOCK_DIR, "owner").write_text(json.dumps(meta) + "\n")

    def launched(self, cmd, timeout=None):
        token = lock.acquire(dr.HOST, "alice", "night release", runner=dr._local)
        _, out, _ = dr._local(dr.HOST, detach.launch_cmd(token, 1, cmd, token, timeout,
                                                         unmanaged_ok=True))
        self.assertIn(detach.LAUNCHED, out)
        return token

    def dead_pid(self):
        p = subprocess.Popen(["true"])
        p.wait()
        return p.pid


class LockControllerTest(_Reconcile):  # M1

    def live(self):
        """The lock below is held by THIS (live) process, as a running
        `vpscfg deploy` or vpsexec door would hold it."""
        self.restore_controller()

    def test_lock_owner_names_the_controller(self):
        self.live()
        lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        ctl = self.owner()["controller"]
        self.assertEqual((ctl["host"], ctl["pid"]), (socket.gethostname(), os.getpid()))
        self.assertIsInstance(ctl["started"], int)

    def test_a_non_positive_start_time_on_a_live_pid_counts_as_alive(self):
        """Round 5: `started` 0 or negative on a live pid of this machine is
        malformed — never compared (0 vs a real start time would look like a
        recycled pid, i.e. dead) — so the lock stays held."""
        self.live()
        here = socket.gethostname()
        for started in (0, -1, -10 ** 9):
            with self.subTest(started=started):
                ctl = {"host": here, "pid": os.getpid(), "started": started}
                self.assertIsNotNone(vpsexec._live_controller({"controller": ctl}))
        lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        meta = self.owner()
        meta["controller"]["started"] = 0
        self.set_owner(meta)
        res, _ = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertIn("still alive on THIS machine", str(res))
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())
        # A positive, matching start time is still checked normally.
        good = {"host": here, "pid": os.getpid(), "started": lock.process_start(os.getpid())}
        self.assertIsNotNone(vpsexec._live_controller({"controller": good}))

    def test_an_unreadable_start_time_is_recorded_as_unknown_never_now(self):
        """Verifier: when ps failed, controller() recorded started=time.time()
        — a guess that could later look like a recycled pid (a dead
        controller). It records None, and None counts as alive."""
        self.live()
        with mock.patch.object(lock, "process_start", lambda pid: None):
            ctl = lock.controller()
        self.assertIsNone(ctl["started"])
        self.assertEqual(ctl["pid"], os.getpid())
        self.assertIsNotNone(vpsexec._live_controller({"controller": ctl}))
        with mock.patch.object(lock, "process_start", lambda pid: None):
            lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        self.assertIsNone(self.owner()["controller"]["started"])
        res, _ = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertIn("still alive on THIS machine", str(res))
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())

    def test_live_controller_refuses_with_a_journaled_attempt(self):
        self.live()
        token = self.launched("true")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        journal.append("vpsexec", {"event": "mutation_attempt", "reason": "night release",
                                   "command": "true", "hosts": [dr.HOST]})
        res, _ = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertIn("still alive on THIS machine", str(res))
        self.assertEqual(self.prompts, [])
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())

    def test_live_deploy_controller_refuses_without_any_vpsexec_attempt(self):
        """`vpscfg deploy` journals no vpsexec mutation_attempt: a live
        controller still refuses, even for an old unproven lock (verifier)."""
        self.live()
        lock.acquire(dr.HOST, "alice", "vpscfg deploy web k3s", runner=dr._local)
        old = time.time() - vpsexec.unproven_lock_min_age() - 60
        os.utime(lock.LOCK_DIR, (old, old))
        res, _ = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertIn("still alive on THIS machine", str(res))
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())

    def test_malformed_controller_pid_fails_closed(self):
        self.live()
        for pid in (0, -1, "x", None, True, 1.5):
            with self.subTest(pid=pid):
                meta = {"reason": "r", "controller": {"host": socket.gethostname(),
                                                      "pid": pid, "started": 1}}
                self.assertIsNotNone(vpsexec._live_controller(meta))
        self.assertFalse(vpsexec._pid_alive(0))
        self.assertFalse(vpsexec._pid_alive(-1))
        self.assertIsNotNone(vpsexec._live_controller({"controller": "garbage"}))

    def test_another_machines_or_a_dead_controller_does_not_block(self):
        token = self.launched("true")  # controller: a dead pid (harness)
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        rc, out = self.reconcile()
        self.assertEqual(rc, 0, out)
        self.assertIsNone(vpsexec._live_controller(
            {"controller": {"host": "elsewhere.invalid", "pid": os.getpid(), "started": 1}}))

    def test_unproven_lock_must_be_older_than_twice_the_longest_step(self):
        from vpscfg import executor, k3sapply, vpsexecpolicy
        need = vpsexec.unproven_lock_min_age()
        self.assertEqual(need, 2 * max(executor.MAX_STEP_SECONDS,
                                       vpsexecpolicy.RUNBOOK_TIMEOUT_MAX,
                                       k3sapply.MAX_TIMEOUT + 60))
        self.assertGreater(need, executor.MAX_STEP_SECONDS)
        lock.acquire(dr.HOST, "alice", "vpscfg deploy", runner=dr._local)
        res, out = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertIn("NO op dir", str(res))
        self.assertIn("at least %ds" % need, str(res))
        self.assertEqual(self.prompts, [])
        young = time.time() - executor.MAX_STEP_SECONDS - 60  # past one step: not enough
        os.utime(lock.LOCK_DIR, (young, young))
        res, _ = self.reconcile()
        self.assertIsInstance(res, Refused)
        old = time.time() - need - 60
        os.utime(lock.LOCK_DIR, (old, old))
        rc, out = self.reconcile()
        self.assertEqual(rc, 0, out)
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_free_lock_is_journaled_for_resume(self):
        rc, _ = self.reconcile()
        self.assertEqual(rc, 0)
        self.assertEqual(self.events("reconcile_free")[-1]["host"], dr.HOST)


class StopTest(_Reconcile):  # M2

    def test_systemd_units_are_bounded_by_the_step_timeout(self):
        cmd = detach.launch_cmd("f" * 64, 1, "true", "f" * 64, timeout=120)
        self.assertIn("--property=RuntimeMaxSec=%d" % (120 + detach.RUNTIME_GRACE), cmd)
        self.assertNotIn("RuntimeMaxSec", detach.launch_cmd("f" * 64, 1, "true", "f" * 64))

    def unique_sleep(self):
        """A sleep whose argv is unique to this test, to look for afterwards."""
        n = "%d.%06d" % (40, int(time.time() * 1e6) % 1000000)
        self.addCleanup(subprocess.run, ["pkill", "-f", "sleep %s" % n],
                        capture_output=True)
        return n

    def alive(self, n):
        return subprocess.run(["pgrep", "-f", "sleep %s" % n], capture_output=True,
                              text=True).stdout.split()

    def test_stop_ends_the_step_and_its_foreground_child(self):
        """Verifier M2: TERM to the step's shell alone left its foreground
        `sleep` running, and reconcile then said COMPLETED and released."""
        n = self.unique_sleep()
        token = self.launched("sleep %s; echo after" % n)
        self.wait_for(Path(detach.op_dir(token), "1.cpid"))
        time.sleep(0.3)
        self.assertTrue(self.alive(n))
        rc, out = self.reconcile("--stop")
        self.assertEqual(rc, 0, out)
        self.assertIn("STOP:%s:%s" % (dr.HOST, token[:8]), self.prompts[0])
        self.assertTrue(self.events("reconcile_stop_attempt"))
        self.assertTrue(self.events("reconcile_stopped"))
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists(), "--stop releases nothing")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.5)
        self.assertEqual(self.alive(n), [], "the step's child survived --stop")
        self.assertNotEqual(Path(detach.op_dir(token), "1.rc").read_text().strip(), "0")
        self.assertNotIn("after", Path(detach.op_dir(token), "1.out").read_text())
        self.prompts.clear()
        rc, out = self.reconcile()
        self.assertEqual(rc, 0, out)
        self.assertIn("VERDICT: COMPLETED", out)

    def test_a_leaderless_group_is_still_running_and_stop_refuses(self):
        """The step exited, but a child it left behind still runs in its group:
        reconcile never calls that COMPLETED; with the leader gone the group's
        identity cannot be proven, so --stop signals nothing and asks a human."""
        n = self.unique_sleep()
        token = self.launched("sleep %s >/dev/null 2>&1 & echo left" % n)
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.3)
        self.assertTrue(self.alive(n))
        res, out = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertIn("STILL RUNNING", str(res))
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists())
        # On Linux the leader's recorded start time lets the members prove
        # they are the step's (test_step_leaves_background_child_then_stop);
        # without it nothing can. Drop it, so this is the unprovable group on
        # every platform. (Before the leader recorded its own start time, a
        # fast-exiting step always lost it — which is what this test saw.)
        Path(detach.op_dir(token), "1.cstart").write_text("\n")
        self.prompts.clear()
        res, _ = self.reconcile("--stop")
        self.assertIsInstance(res, Refused)
        self.assertIn("LEADERLESS", str(res))
        self.assertIn("ps -o pid,pgid,lstart,args -g", str(res))
        self.assertTrue(self.alive(n), "--stop signalled an unproven group")
        self.assertTrue(self.events("reconcile_stop_refused"))
        subprocess.run(["pkill", "-f", "sleep %s" % n])  # the human acts by hand
        time.sleep(0.5)
        self.prompts.clear()
        rc, out = self.reconcile()
        self.assertEqual(rc, 0, out)

    def test_step_leaves_background_child_then_stop(self):
        """Verifier: the step exits leaving `sleep &` in its group. On Linux
        the members prove they are the step's (/proc: session = pgid, started
        after the leader) and --stop ends them; elsewhere nothing can prove
        it and --stop refuses, signalling nothing."""
        n = self.unique_sleep()
        token = self.launched("sleep %s & exit 0" % n)
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.3)
        res, _ = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertIn("STILL RUNNING", str(res))
        self.prompts.clear()
        res, out = self.reconcile("--stop")
        if os.access("/proc/self/stat", os.R_OK):
            self.assertEqual(res, 0, out)
            time.sleep(0.5)
            self.assertEqual(self.alive(n), [])
        else:
            self.assertIsInstance(res, Refused)
            self.assertIn("LEADERLESS", str(res))
            self.assertTrue(self.alive(n), "--stop signalled an unproven group off Linux")

    def leaderless(self):
        """A real leaderless group: its leader (a session leader, as the
        step's setsid makes it) exits, its `sleep` lives on. Returns (pgid,
        the sleep's pid, its unique argv)."""
        n = self.unique_sleep()
        p = subprocess.Popen(["/bin/sh", "-c", "sleep %s >/dev/null 2>&1 & exit 0" % n],
                             start_new_session=True)
        p.wait()
        end = time.time() + 5
        while not self.alive(n) and time.time() < end:
            time.sleep(0.05)
        return p.pid, int(self.alive(n)[0]), n

    OP = "e" * 64
    TAG = b"VPSCFG_OP=" + b"e" * 64 + b".1"   # what the runner gives step 1 of OP

    def fake_proc(self, members, linux=True):
        """A /proc with only `self/stat` (Linux) and, per member, a stat file
        in the kernel's own layout and an environ (NUL-separated). A member is
        (pid, pgrp, session, starttime[, environ bytes[, comm]]); by default
        its environ carries this op's step tag."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        if linux:
            (root / "self").mkdir()
            (root / "self" / "stat").write_text("1 (sh) S 0 1 1 0\n")
        for m in members:
            pid, pgrp, sess, start = m[:4]
            env = m[4] if len(m) > 4 else b"PATH=/bin\0" + self.TAG + b"\0HOME=/\0"
            comm = m[5] if len(m) > 5 else "sleep x"
            (root / str(pid)).mkdir()
            rest = ["S", "1", str(pgrp), str(sess)] + ["0"] * 15 + [str(start)] + ["0"] * 10
            (root / str(pid) / "stat").write_text("%d (%s) %s\n" % (pid, comm, " ".join(rest)))
            if env is not None:
                (root / str(pid) / "environ").write_bytes(env)
        return str(root)

    def stop_in(self, op, g, cstart, proc, shell="/bin/sh"):
        d = Path(detach.op_dir(op))
        d.mkdir(parents=True, exist_ok=True)
        (d / "1.sh").write_text("true")
        (d / "1.cpid").write_text("%d\n" % g)
        (d / "1.cstart").write_text("%s\n" % cstart)
        r = subprocess.run([shell, "-c", detach.stop_cmd(op, proc=proc)],
                           capture_output=True, text=True, timeout=60)
        return r.stdout

    def test_a_verified_leaderless_group_is_stopped(self):
        for sh in [s for s in ("/bin/dash", "/bin/sh", "/bin/bash") if os.path.exists(s)]:
            with self.subTest(shell=sh):
                g, pid, n = self.leaderless()
                proc = self.fake_proc([(pid, g, g, 500),
                                       (pid + 100000, g, g, 400, self.TAG + b"\0", "evil) 1 2 3")])
                out = self.stop_in(self.OP, g, 400, proc, sh)
                self.assertIn(detach.STOPPED, out)
                self.assertNotIn(detach.STOP_REFUSED, out)
                end = time.time() + 5
                while self.alive(n) and time.time() < end:
                    time.sleep(0.05)
                self.assertEqual(self.alive(n), [], "a verified leaderless group survived")

    def test_an_unverified_leaderless_group_is_never_signalled(self):
        cases = {
            "member started before the leader": lambda g, pid: ([(pid, g, g, 300)], True, "400"),
            "member in another session": lambda g, pid: ([(pid, g, g + 1, 500)], True, "400"),
            "not Linux (no /proc/self/stat)": lambda g, pid: ([(pid, g, g, 500)], False, "400"),
            "cstart is not a tick count": lambda g, pid: ([(pid, g, g, 500)], True,
                                                          "Mon Oct 12 10:00:00 2026"),
            "no member visible": lambda g, pid: ([], True, "400"),
            "one bad member among good": lambda g, pid: ([(pid, g, g, 500),
                                                          (pid + 100000, g, g, 1)], True, "400"),
            # Round 5 (verifier test_pgverify_r4): a REUSED group whose leader
            # is gone too — an unrelated setsid'd process, later start time,
            # session == pgid — passed every check but the tag.
            "REUSED leaderless group (no step tag)": lambda g, pid: (
                [(pid, g, g, 99999, b"PATH=/bin\0HOME=/\0", "unrelated")], True, "400"),
            "another op's tag": lambda g, pid: (
                [(pid, g, g, 500, b"VPSCFG_OP=" + b"f" * 64 + b".1\0")], True, "400"),
            "another step's tag": lambda g, pid: (
                [(pid, g, g, 500, b"VPSCFG_OP=" + b"e" * 64 + b".2\0")], True, "400"),
            "tag forged inside another value": lambda g, pid: (
                [(pid, g, g, 500, b"X=a\n" + self.TAG + b"\0")], True, "400"),
            "tag as a prefix only": lambda g, pid: (
                [(pid, g, g, 500, self.TAG + b"0\0")], True, "400"),
            "environ unreadable": lambda g, pid: ([(pid, g, g, 500, None)], True, "400"),
            "one untagged member among tagged": lambda g, pid: (
                [(pid, g, g, 500), (pid + 100000, g, g, 600, b"PATH=/bin\0")], True, "400"),
            "comm with a newline, other session": lambda g, pid: (
                [(pid, g, g + 1, 500, self.TAG + b"\0", "a\nb"), (pid + 100000, g, g, 600)],
                True, "400"),
            "comm forging fields, other session": lambda g, pid: (
                [(pid, g, g + 1, 500, self.TAG + b"\0", "x) S 1 %d %d 0" % (g, g))], True, "400"),
        }
        for why, make in cases.items():
            with self.subTest(why=why):
                g, pid, n = self.leaderless()
                members, linux, cstart = make(g, pid)
                out = self.stop_in("e" * 64, g, cstart, self.fake_proc(members, linux))
                self.assertIn("%s leaderless 1 %d" % (detach.STOP_REFUSED, g), out)
                self.assertNotIn(detach.STOPPED, out)
                time.sleep(0.2)
                self.assertTrue(self.alive(n), "an unproven group was signalled")
                subprocess.run(["pkill", "-f", "sleep %s" % n], capture_output=True)

    def test_systemd_unit_kills_the_whole_step(self):
        cmd = detach.launch_cmd("f" * 64, 1, "true", "f" * 64, timeout=120)
        self.assertIn("KillMode=mixed", cmd)
        self.assertNotIn("KillMode=process", cmd)
        self.assertIn("--kill-who=all", detach.stop_cmd("f" * 64))

    def test_wrong_stop_phrase_stops_nothing(self):
        token = self.launched("while test ! -e %s; do sleep 0.1; done" % self.go)
        self.wait_for(Path(detach.op_dir(token), "1.cpid"))
        time.sleep(0.2)
        res, _ = self.reconcile("--stop", answer="STOP:%s:00000000" % dr.HOST)
        self.assertIsInstance(res, Refused)
        self.assertFalse(self.events("reconcile_stopped"))
        self.assertFalse(Path(detach.op_dir(token), "1.rc").exists())
        self.go.touch()
        self.wait_for(Path(detach.op_dir(token), "1.rc"))

    def test_stop_with_nothing_running_says_so(self):
        token = self.launched("true")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        rc, out = self.reconcile("--stop")
        self.assertEqual(rc, 0)
        self.assertIn("nothing to stop", out)
        self.assertEqual(self.prompts, [])

    def test_package_refuses_any_other_flag(self):
        res, _ = self.reconcile("--yes")
        self.assertIsInstance(res, Refused)

    def test_outer_door_accepts_only_stop(self):
        t = dr.OuterDoorReconcileTest("test_frozen_host_is_judged_a_mutation_without_break_glass")
        t.setUp()
        j = t.door.judge(dr._governor(), ["reconcile", dr.HOST, "--stop"])
        self.assertEqual((j["introspect"], j["read_only"]), ("reconcile", False))
        for argv in (["reconcile", dr.HOST, "--yes"], ["reconcile", dr.HOST, "--stop", "x"],
                     ["reconcile", "--stop", dr.HOST]):
            with self.assertRaises(Refused):
                t.door.judge(dr._governor(), argv)


class OpDirTest(_Reconcile):  # M3

    def test_successful_step_removes_its_op_dir_with_the_lock(self):
        result = self.run_host("echo hi", dr._local)
        self.assertEqual(result["rc"], 0)
        self.assertFalse(Path(lock.LOCK_DIR).exists())
        self.assertEqual(list(Path(detach.OPS_DIR).iterdir()), [])

    def test_reconcile_removes_the_op_dir_after_journaling_evidence(self):
        token = self.launched("echo evidence")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        time.sleep(0.2)
        rc, _ = self.reconcile()
        self.assertEqual(rc, 0)
        self.assertFalse(Path(detach.op_dir(token)).exists())
        self.assertIn("evidence", self.events("reconcile_attempt")[-1]["steps"][0]["stdout_tail"])

    def test_logs_are_capped_and_the_step_is_not_killed(self):
        old = detach.LOG_CAP
        detach.LOG_CAP = 1000
        self.addCleanup(setattr, detach, "LOG_CAP", old)
        token = self.launched("head -c 50000 /dev/zero | tr '\\0' x; echo done >&2; exit 4")
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        self.assertEqual(Path(detach.op_dir(token), "1.rc").read_text().strip(), "4")
        self.assertEqual(os.path.getsize(Path(detach.op_dir(token), "1.out")), 1000)
        self.assertIn("done", Path(detach.op_dir(token), "1.err").read_text())

    def test_only_an_op_dir_is_ever_removed(self):
        for bad in ("/", "/run", "/opt/app", detach.OPS_DIR, detach.OPS_DIR + "/../x",
                    detach.OPS_DIR + "/" + "a" * 16 + "\n",          # trailing newline
                    detach.OPS_DIR + "//" + "a" * 16, detach.OPS_DIR + "/" + "A" * 16,
                    detach.OPS_DIR + "/" + "a" * 16 + "/../../etc"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                lock._drop_op_dir(bad)

    def test_op_id_must_match_whole_string(self):
        for bad in ("a" * 16 + "\n", "a" * 15, "a" * 129, "g" * 16, "\n" + "a" * 16):
            with self.subTest(bad=bad):
                self.assertIsNone(detach.OP_RE.match(bad))
                with self.assertRaises(ValueError):
                    detach.op_dir(bad)


class RunnerTest(unittest.TestCase):
    """The detached runner itself, under every POSIX shell this machine has
    (dash, sh, bash), started as systemd/setsid/nohup would start it."""

    SHELLS = [s for s in ("/bin/dash", "/bin/sh", "/bin/bash") if os.path.exists(s)]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # Registered FIRST so it runs LAST: after every runner's group was
        # killed by the cleanups each test registers (a tearDown would remove
        # the dir while runners still write into it).
        self.addCleanup(self.tmp.cleanup)
        self.runners = set()

    def run_step(self, shell, script, term_after=None, term_now=False, cap=None,
                 path_prefix=None, storm=0):
        d = tempfile.mkdtemp(dir=self.tmp.name)
        os.chmod(d, 0o700)
        Path(d, "1.sh").write_text(script)
        old = detach.LOG_CAP
        if cap:
            detach.LOG_CAP = cap
        try:
            Path(d, "1.run").write_text(detach._runner(d, 1))
        finally:
            detach.LOG_CAP = old
        t0 = time.time()
        env = None
        if path_prefix:
            env = dict(os.environ, PATH="%s:%s" % (path_prefix, os.environ.get("PATH", "")))
        p = subprocess.Popen([shell, d + "/1.run"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True, env=env)
        self.runners.add(str(p.pid))
        self.addCleanup(subprocess.run, ["pkill", "-g", str(p.pid)], capture_output=True)
        if term_now:
            p.send_signal(15)
        elif term_after is not None:
            end = time.time() + 10
            while not os.path.exists(d + "/1.cpid") and time.time() < end:
                time.sleep(0.02)
            time.sleep(term_after)
            for _ in range(max(1, storm)):
                try:
                    p.send_signal(15)
                except ProcessLookupError:
                    break
                if storm:
                    time.sleep(0.005)
        p.wait(timeout=60)
        rc_path = Path(d, "1.rc")
        rc = rc_path.read_text().strip() if rc_path.exists() else None
        raw = Path(d, "1.out").read_bytes() if Path(d, "1.out").exists() else b""
        self.last_raw = raw
        return rc, raw.decode("latin-1"), time.time() - t0, d

    def test_plain_exit_code(self):
        for sh in self.SHELLS:
            with self.subTest(shell=sh):
                rc, out, _, _ = self.run_step(sh, "echo hi; exit 3")
                self.assertEqual((rc, out), ("3", "hi\n"))

    def shim(self, always_german=True):
        """A `dd` that prints its statistics the way GNU dd does under a German
        locale (verifier's ddshim) — always, or unless LC_ALL=C. It records the
        LC_ALL/LANG it was run with."""
        d = tempfile.mkdtemp(dir=self.tmp.name)
        seen = Path(d, "env-seen")
        cond = "" if always_german else (
            'if [ "$LC_ALL" = C ]; then exec %s "$@"; fi\n' % shutil.which("dd"))
        Path(d, "dd").write_text(
            "#!/bin/sh\nprintf '%%s %%s\\n' \"$LC_ALL\" \"$LANG\" >> %s\n%s"
            "%s \"$@\" 2>%s/.err; rc=$?\n"
            "n=$(sed -n 's/^\\([0-9][0-9]*\\) bytes.*/\\1/p' %s/.err)\n"
            "echo \"${n:-0} Bytes (${n:-0} B) kopiert, 0,0001 s, 1 kB/s\" >&2; exit $rc\n"
            % (seen, cond, shutil.which("dd"), d, d))
        Path(d, "dd").chmod(0o755)
        return d, seen

    def test_a_localised_dd_never_truncates_or_kills_the_step(self):
        """Verifier ddshim: the reader parsed dd's English statistics; under a
        German locale it saw 0 bytes, stopped reading, and lost the output."""
        d, _ = self.shim(always_german=True)
        for sh in self.SHELLS:
            with self.subTest(shell=sh):
                rc, out, _, _ = self.run_step(
                    sh, "head -c 5000 /dev/zero | tr '\\0' y; echo; exit 0",
                    cap=3000, path_prefix=d)
                self.assertEqual(rc, "0")
                self.assertEqual(out, "y" * 3000)

    def test_the_reader_runs_dd_under_the_c_locale(self):
        d, seen = self.shim(always_german=False)
        rc, out, _, _ = self.run_step(self.SHELLS[0], "echo ok", path_prefix=d)
        self.assertEqual((rc, out), ("0", "ok\n"))
        self.assertEqual(set(Path(seen).read_text().split("\n")) - {""}, {"C C"})

    def test_binary_output_is_kept_byte_exact_around_the_cap(self):
        """Verifier runner_r2: binary blobs of cap-1, cap, cap+1 and 3*cap+7."""
        cap = 1000
        for n in (cap - 1, cap, cap + 1, 3 * cap + 7):
            with self.subTest(n=n):
                blob = (b"\0\xff\n" + hashlib.sha256(str(n).encode()).digest() * (n // 32 + 1))[:n]
                fn = Path(self.tmp.name, "blob%d" % n)
                fn.write_bytes(blob)
                rc, _, _, _ = self.run_step(self.SHELLS[0], "cat %s; exit 0" % fn, cap=cap)
                self.assertEqual(rc, "0")
                self.assertEqual(self.last_raw, blob[:cap])

    def test_a_term_storm_still_ends_with_an_exit_code(self):
        for sh in self.SHELLS:
            with self.subTest(shell=sh):
                rc, _, took, _ = self.run_step(sh, "sleep 30; exit 7", term_after=0.3,
                                               storm=50)
                self.assertIsNotNone(rc)
                self.assertNotIn(rc, ("0", "7"))
                self.assertLess(took, 20)

    def test_every_process_of_the_step_carries_its_tag(self):
        """`reconcile --stop` proves a leaderless group is the step's by this
        tag: the step and its children get VPSCFG_OP=<op>.<i>, and nothing
        outside the step does (the runner and its readers do not)."""
        for sh in self.SHELLS:
            with self.subTest(shell=sh):
                out = Path(tempfile.mkdtemp(dir=self.tmp.name), "env-child")
                rc, own, _, d = self.run_step(
                    sh, "env | grep '^VPSCFG_OP='; sh -c 'env' > %s" % out)
                want = "%s=%s.1" % (detach.STEP_TAG, os.path.basename(d.rstrip("/")))
                self.assertEqual(rc, "0")
                self.assertEqual(own.strip(), want)
                self.assertIn(want, out.read_text().splitlines())
        text = detach._runner(detach.op_dir("a" * 16), 3)
        self.assertNotIn("export VPSCFG_OP", text)  # never in the runner's own env
        self.assertIn("VPSCFG_OP=%s.3 setsid" % ("a" * 16), text)

    def test_the_leaders_start_time_is_recorded(self):
        rc, _, _, d = self.run_step(self.SHELLS[0], "sleep 1")
        self.assertTrue(Path(d, "1.cstart").read_text().strip())

    def test_a_step_that_exits_at_once_still_records_its_start_time(self):
        """The runner used to read the leader's start time after the leader
        had already exited and been reaped: cstart was empty, and the child
        the step left could never be proven the step's (ubuntu CI, StopTest)."""
        for sh in self.SHELLS:
            with self.subTest(shell=sh):
                n = "44.%06d" % (int(time.time() * 1e6) % 1000000)
                self.addCleanup(subprocess.run, ["pkill", "-f", "sleep %s" % n],
                                capture_output=True)
                _, _, _, d = self.run_step(sh, "sleep %s >/dev/null 2>&1 & exit 0" % n)
                self.assertTrue(Path(d, "1.cstart").read_text().strip())

    def test_no_command_substitution_inside_arithmetic(self):
        """bash 5.2 running the TERM trap while it parses `$(($(cmd) ...))`
        exits 1 with no rc (test_a_term_storm_still_ends_with_an_exit_code,
        ~3% of runs on a loaded Linux host)."""
        self.assertNotIn("$(($(", detach._runner("/run/vpscfg-ops/" + "a" * 16, 1))

    def start_runner(self, shell, d):
        """Start <d>/1.run in a new session, as systemd/setsid would. Its
        pid is recorded: every log reader it forks stays in that process group
        (even after the runner dies, even while blocked opening its FIFO), which
        is how readers() tells this test's readers from anyone else's."""
        p = subprocess.Popen([shell, d + "/1.run"], start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.runners.add(str(p.pid))
        self.addCleanup(subprocess.run, ["pkill", "-g", str(p.pid)], capture_output=True)
        return p

    def readers(self):
        """Log readers of THIS test's runners only (process group = one of
        their pids). Readers of other tests or processes never count."""
        out = subprocess.run(["ps", "-eo", "pid=,pgid=,args="], capture_output=True,
                             text=True).stdout
        return set(l.split()[0] for l in out.splitlines()
                   if "vpscfg-log-reader" in l and l.split()[1] in self.runners)

    def test_no_log_reader_is_ever_left_behind(self):
        """Verifier: a dd reader sat blocked on a FIFO with no writer for 18+
        minutes after a TERM landed between the readers' start and the step's
        launch. The runner now holds a write end of each FIFO until the step
        started, and closes it on every path."""
        for delay in (0, 0.001, 0.003, 0.006, 0.01, 0.02, 0.04):
            for _ in range(3):
                d = tempfile.mkdtemp(dir=self.tmp.name)
                Path(d, "1.sh").write_text("sleep 2")
                Path(d, "1.run").write_text(detach._runner(d, 1))
                p = self.start_runner("/bin/sh", d)
                end = time.time() + 5
                while not Path(d, "1.pid").exists() and time.time() < end:
                    time.sleep(0.0005)
                time.sleep(delay)
                p.send_signal(15)
                p.wait(timeout=20)
        time.sleep(1.5)
        self.assertEqual(self.readers(), set(), "a log reader was left behind")

    def test_readers_counts_only_this_tests_readers(self):
        """Another process's log reader (here: one this test did not start
        through a recorded runner) is never counted as this test's leak."""
        foreign = subprocess.Popen(["sh", "-c", "sleep 30; :", "vpscfg-log-reader"],
                                   start_new_session=True)
        self.addCleanup(foreign.kill)
        time.sleep(0.2)
        self.assertEqual(self.readers(), set())
        self.runners.add(str(foreign.pid))
        self.assertEqual(self.readers(), {str(foreign.pid)})

    def test_an_early_term_always_writes_rc_143(self):
        """Verifier runner_earlyterm: a TERM landing while the runner was
        blocked opening a FIFO for writing (`exec 7>fifo`) interrupted the
        open; the failed redirection of the special builtin killed the shell
        and the exit code was lost (NORC). The FIFOs are now opened read-write
        (never blocks) through `command exec`."""
        for sh in self.SHELLS:
            for delay in (0, 0.001, 0.003, 0.006, 0.01, 0.02):
                for _ in range(4 if delay != 0.01 else 20):
                    with self.subTest(shell=sh, delay=delay):
                        d = tempfile.mkdtemp(dir=self.tmp.name)
                        Path(d, "1.sh").write_text("touch %s/RAN; sleep 2" % d)
                        Path(d, "1.run").write_text(detach._runner(d, 1))
                        p = self.start_runner(sh, d)
                        end = time.time() + 5
                        while not Path(d, "1.pid").exists() and time.time() < end:
                            time.sleep(0.0005)
                        time.sleep(delay)
                        p.send_signal(15)
                        p.wait(timeout=20)
                        rc = Path(d, "1.rc")
                        self.assertTrue(rc.exists(), "NORC: the exit code was lost")
                        self.assertEqual(rc.read_text().strip(), "143")

    def test_a_sigkilled_runner_leaves_no_log_reader(self):
        """Verifier runner_sigkill: a runner SIGKILLed while its readers were
        blocked opening their FIFOs left them blocked forever (no writer would
        ever come). The runner now holds its write ends before the readers
        start, so the kernel closes them with the runner."""
        for sh in self.SHELLS:
            for delay in (0, 0.002, 0.005, 0.01, 0.02, 0.05, 0.3):
                for _ in range(2):
                    d = tempfile.mkdtemp(dir=self.tmp.name)
                    Path(d, "1.sh").write_text("echo out; sleep 1")
                    Path(d, "1.run").write_text(detach._runner(d, 1))
                    p = self.start_runner(sh, d)
                    end = time.time() + 5
                    while not Path(d, "1.pid").exists() and time.time() < end:
                        time.sleep(0.0005)
                    time.sleep(delay)
                    p.send_signal(9)
                    p.wait(timeout=20)
        end = time.time() + 10  # the steps (sleep 1) end; their readers then reach EOF
        while self.readers() and time.time() < end:
            time.sleep(0.2)
        left = self.readers()
        for pid in left:
            subprocess.run(["kill", "-9", pid], capture_output=True)
        self.assertEqual(left, set(), "a log reader outlived its SIGKILLed runner")

    def test_the_fifo_write_ends_open_before_the_readers_and_never_block(self):
        text = detach._runner("/run/vpscfg-ops/" + "a" * 16, 1)
        opened = text.index("command exec 7<>")
        self.assertLess(opened, text.index("vpscfg-log-reader"))
        self.assertNotIn("exec 7>/", text)  # a write-only FIFO open blocks

    def test_no_reader_ever_opens_its_fifo_itself(self):
        """Round 5 (RunnerTest errors=1, 2 of 7 runs): an early TERM made the
        runner close its write ends before a just-forked reader had opened
        its FIFO; the reader's read-only open then blocked forever and the
        runner's `wait` with it (p.wait timed out after 20 s). The runner now
        opens the read ends itself, while its write ends exist, and hands
        them to the readers already open."""
        text = detach._runner("/run/vpscfg-ops/" + "a" * 16, 1)
        exec_line = next(l for l in text.splitlines() if l.startswith("command exec 7<>"))
        self.assertIn("5</run/vpscfg-ops/", exec_line)
        self.assertIn("6</run/vpscfg-ops/", exec_line)
        self.assertLess(exec_line.index("7<>"), exec_line.index("5<"))
        readers = [l for l in text.splitlines() if "vpscfg-log-reader" in l]
        self.assertEqual(len(readers), 2)
        for line in readers:
            self.assertNotIn("< /run", line)
            self.assertRegex(line, r"<&[56] ")
        self.assertIn("\nexec 5<&- 6<&-\n", text)

    def test_output_is_capped_exactly_and_the_step_is_not_killed(self):
        for sh in self.SHELLS:
            with self.subTest(shell=sh):
                rc, out, _, _ = self.run_step(
                    sh, "head -c 50000 /dev/zero | tr '\\0' x; exit 0", cap=1000)
                self.assertEqual((rc, len(out)), ("0", 1000))

    def test_a_background_child_holding_stdout_loses_no_output(self):
        """macOS head -c buffered output until EOF: with a child still holding
        the FIFO the log stayed empty. The rc also arrives within LOG_GRACE."""
        for sh in self.SHELLS:
            with self.subTest(shell=sh):
                rc, out, took, _ = self.run_step(sh, "sleep 30 & echo bg-line")
                self.assertEqual(rc, "0")
                self.assertIn("bg-line", out)
                self.assertLess(took, detach.LOG_GRACE + 4)

    def test_term_during_a_foreground_child_ends_the_whole_group(self):
        for sh in self.SHELLS:
            with self.subTest(shell=sh):
                n = "41.%06d" % (int(time.time() * 1e6) % 1000000)
                rc, out, took, _ = self.run_step(sh, "sleep %s; echo after" % n,
                                                 term_after=0.3)
                time.sleep(0.3)
                left = subprocess.run(["pgrep", "-f", "sleep %s" % n],
                                      capture_output=True, text=True).stdout.split()
                self.assertEqual(left, [], "the step's child survived the TERM")
                self.assertNotEqual(rc, "0")
                self.assertIsNotNone(rc)
                self.assertNotIn("after", out)

    def test_the_term_trap_only_records_the_signal(self):
        """Round 5 (RunnerTest run 10 of 30: rc None under a TERM storm):
        macOS /bin/bash 3.2 died of SIGSEGV (exit -11, no exit code) when its
        TERM trap ran `kill` while TERMs kept arriving — reproduced 2 in 750
        under load. The trap now only sets a flag; the runner's flow forwards
        the TERM to the step's group after launch and on every poll."""
        text = detach._runner("/run/vpscfg-ops/" + "a" * 16, 1)
        self.assertIn("\ntrap 't=1' TERM\n", text)
        poll = next(l for l in text.splitlines() if l.startswith("while s=$(ps -o stat="))
        self.assertIn('kill -s TERM -- -"$c"', poll)

    def test_the_term_trap_comes_before_anything_starts(self):
        text = detach._runner("/run/vpscfg-ops/" + "a" * 16, 1)
        trap = text.index("trap ")
        for later in ("mkdir ", "mkfifo ", "vpscfg-log-reader", "setsid ", "perl "):
            self.assertLess(trap, text.index(later), later)

    def test_term_before_the_step_starts_is_never_lost(self):
        """The trap is installed first: a TERM at any moment still yields an
        exit code and no surviving step."""
        for sh in self.SHELLS:
            for _ in range(3):
                with self.subTest(shell=sh):
                    n = "42.%06d" % (int(time.time() * 1e6) % 1000000)
                    rc, _, _, d = self.run_step(sh, "sleep %s" % n, term_now=True)
                    time.sleep(0.2)
                    left = subprocess.run(["pgrep", "-f", "sleep %s" % n],
                                          capture_output=True, text=True).stdout.split()
                    self.assertEqual(left, [])
                    if rc is not None:  # TERM may land before the runner's own trap
                        self.assertNotEqual(rc, "0")

    def test_no_process_group_isolation_means_never_started(self):
        sh = self.SHELLS[0]
        empty = tempfile.mkdtemp(dir=self.tmp.name)
        for tool in ("mkdir", "mkfifo", "cat", "rm", "mv", "dd", "sed", "sleep", "ps", "tr",
                     "bash", "sh"):
            for base in ("/bin", "/usr/bin"):
                if os.path.exists(os.path.join(base, tool)):
                    os.symlink(os.path.join(base, tool), os.path.join(empty, tool))
                    break
        d = tempfile.mkdtemp(dir=self.tmp.name)
        marker = Path(self.tmp.name, "ran")
        Path(d, "1.sh").write_text("touch %s\n" % marker)
        Path(d, "1.run").write_text(detach._runner(d, 1))
        subprocess.run([sh, d + "/1.run"], env={"PATH": empty}, timeout=60,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(Path(d, "1.rc").read_text().strip(), str(detach.RC_NO_ISOLATION))
        self.assertFalse(marker.exists(), "a step without group isolation ran")


class LaunchFenceTest(_Reconcile):  # L1

    def test_a_launch_that_never_landed_is_fenced_before_not_run(self):
        late = []

        def ssh(host, cmd, timeout=None, connect_timeout=None):
            if detach.LAUNCHED in cmd:
                late.append(cmd)  # in flight: it lands only after we gave up
                raise OSError("SSH connection lost")
            return dr._local(host, cmd, timeout)
        token = lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        with self.assertRaises(Refused) as cm:
            detach.run(dr.HOST, token, 1, "touch %s" % self.go, token, ssh, 10)
        self.assertIn("fenced", str(cm.exception))
        self.assertTrue(Path(detach.op_dir(token), "1.started").is_dir())
        # The late launch lands now: its runner finds the guard taken.
        dr._local(dr.HOST, late[0])
        time.sleep(0.5)
        self.assertFalse(self.go.exists(), "a fenced step ran")

    def test_a_guard_already_taken_is_not_called_not_run(self):
        token = lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        Path(detach.op_dir(token), "1.started").mkdir(parents=True)

        def ssh(host, cmd, timeout=None, connect_timeout=None):
            if detach.LAUNCHED in cmd:
                raise OSError("SSH connection lost")
            return dr._local(host, cmd, timeout)
        with self.assertRaises(detach.DetachUnknown):
            detach.run(dr.HOST, token, 1, "true", token, ssh, 10)


class OperatorIdentityTest(_Reconcile):  # L2

    def test_identity_comes_from_the_password_database(self):
        real = pwd.getpwuid(os.getuid()).pw_name
        with mock.patch.dict(os.environ, {"USER": "mallory", "LOGNAME": "mallory"}):
            self.assertEqual(vpsexecgrant.operator(), real)
            self.assertEqual(journal.operator(), real)
            self.run_host("true", dr._local)
            journal.append("vpsexec", {"event": "probe"})
        probe = self.events("probe")[-1]
        self.assertEqual(probe["operator"], real, "journal records $USER")
        self.assertTrue(all(e["operator"] == real for e in self.events()))
        token = self.launched("true")
        self.assertEqual(self.owner()["operator"], "alice")  # explicit operator arg
        self.wait_for(Path(detach.op_dir(token), "1.rc"))
        with mock.patch.dict(os.environ, {"USER": "mallory"}):
            vpsexec.lock.release(dr.HOST, runner=dr._local, token=token)
            rc, _ = self.reconcile()
        self.assertEqual(self.events("reconcile_free")[-1]["reconciled_by"], real)


# ===========================================================================
# M4 / M5: the host index is never committed, and every read is journaled
# ===========================================================================

class IndexCacheIgnoredTest(unittest.TestCase):  # M4

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "estate"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True,
                       capture_output=True)
        self.doc = {"host": "web1", "sections": {}}

    def tearDown(self):
        self.tmp.cleanup()

    def test_not_ignored_in_a_repo_refuses_and_writes_nothing(self):
        with self.assertRaises(Refused) as cm:
            indexstore.save(self.doc, self.repo / "index")
        self.assertIn("NOT ignored", str(cm.exception))
        self.assertIn("/index/", str(cm.exception))
        self.assertFalse((self.repo / "index" / "web1.json").exists())

    def test_ignored_in_a_repo_is_written(self):
        (self.repo / ".gitignore").write_text("/index/\n")
        path = indexstore.save(self.doc, self.repo / "index")
        self.assertTrue(path.exists())

    def test_outside_any_repo_is_written(self):
        plain = Path(self.tmp.name) / "plain" / "index"
        self.assertTrue(indexstore.save(self.doc, plain).exists())

    def test_no_git_inside_a_repo_fails_closed(self):
        (self.repo / ".gitignore").write_text("/index/\n")
        with mock.patch.object(gitcmd, "GIT_CANDIDATES", ("/nonexistent/git",)):
            with self.assertRaises(Refused) as cm:
                indexstore.save(self.doc, self.repo / "index")
        self.assertIn("cannot ask git", str(cm.exception))

    def test_a_fake_git_on_path_cannot_say_ignored(self):
        fake = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, fake)
        marker = fake / "fake-git-ran"
        (fake / "git").write_text("#!/bin/sh\ntouch %s\nexit 0\n" % marker)
        (fake / "git").chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": "%s:%s" % (fake, os.environ["PATH"])}):
            with self.assertRaises(Refused):
                indexstore.save(self.doc, self.repo / "index")
        self.assertFalse(marker.exists())

    def test_global_excludes_do_not_count_and_fsmonitor_never_runs(self):
        home = Path(self.tmp.name) / "home"
        (home / ".config" / "git").mkdir(parents=True)
        (home / ".config" / "git" / "ignore").write_text("index/\n")
        (home / ".gitconfig").write_text("[core]\n\texcludesFile = %s\n"
                                         % (home / ".config" / "git" / "ignore"))
        marker = Path(self.tmp.name) / "fsmon-ran"
        hook = Path(self.tmp.name) / "fsmon.sh"
        hook.write_text("#!/bin/sh\ntouch %s\nexit 1\n" % marker)
        hook.chmod(0o755)
        subprocess.run(["git", "-C", str(self.repo), "config", "core.fsmonitor", str(hook)],
                       check=True, capture_output=True)
        with mock.patch.dict(os.environ, {"HOME": str(home),
                                          "XDG_CONFIG_HOME": str(home / ".config")}):
            with self.assertRaises(Refused):  # only the repository's own ignores count
                indexstore.save(self.doc, self.repo / "index")
        self.assertFalse(marker.exists())


class IndexReadJournalTest(unittest.TestCase):  # M5

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (journal.JOURNAL_DIR, telemetry.push_event)
        journal.JOURNAL_DIR = Path(self.tmp.name) / "journal"
        telemetry.push_event = lambda *a, **k: False

    def tearDown(self):
        journal.JOURNAL_DIR, telemetry.push_event = self.saved
        self.tmp.cleanup()

    def events(self):
        p = Path(journal.JOURNAL_DIR) / "vpsexec.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def test_host_and_every_db_instance_are_journaled_before_sending(self):
        fake = ti_host.FakeHost()
        sent_at_first_journal = []
        real = journal.append

        def spy(stream, entry):
            if entry.get("event") == "index_read":
                sent_at_first_journal.append((entry.get("instance"), len(fake.sent)))
            return real(stream, entry)
        with mock.patch.object(journal, "append", spy):
            hostindex.collect("web1", ssh=fake, now=ti_host.NOW, traefik=ti_host.TRAEFIK)
        reads = [e for e in self.events() if e["event"] == "index_read"]
        self.assertEqual(reads[0]["host"], "web1")
        self.assertIsNone(sent_at_first_journal[0][0])
        self.assertEqual(sent_at_first_journal[0][1], 0, "journaled before any send")
        instances = [e["instance"] for e in reads[1:]]
        self.assertIn("container:app-postgres", instances)
        self.assertIn("container:cache", instances)
        self.assertIn("container:mq", instances)

    def test_no_journal_no_read(self):
        fake = ti_host.FakeHost()

        def broken(stream, entry):
            raise OSError("disk full")
        with mock.patch.object(journal, "append", broken):
            with self.assertRaises(OSError):
                hostindex.collect("web1", ssh=fake, now=ti_host.NOW)
        self.assertEqual(fake.sent, [])

    def test_instance_journal_failure_sends_nothing_to_it(self):
        fake = ti_host.FakeHost()
        real = journal.append

        def flaky(stream, entry):
            if entry.get("instance") == "container:app-postgres":
                raise OSError("disk full")
            return real(stream, entry)
        with mock.patch.object(journal, "append", flaky):
            doc = hostindex.collect("web1", ssh=fake, now=ti_host.NOW,
                                    traefik=ti_host.TRAEFIK)
        self.assertFalse([c for c, _ in fake.sent if "psql" in c])
        pg = doc["sections"]["postgres"]["instances"][0]
        self.assertIn("error", pg)


# ===========================================================================
# M8 / L5 / L6: incident phrases and posture text
# ===========================================================================

class IncidentPhraseTest(ti._IncidentHarness):

    def test_go_names_the_host(self):
        iid = self.open()
        asked = []

        def prompt(msg):
            asked.append(msg)
            return "GO:web1"
        rc, _ = self.run_cmd("web1", iid, prompt=prompt)
        self.assertEqual(rc, 0)
        self.assertIn("Type GO:web1 ", asked[0])
        before = len(self.ran())
        with self.assertRaises(Refused) as cm:  # a bare GO no longer approves
            self.run_cmd("web1", iid, prompt=lambda m: "GO")
        self.assertIn("did not match", str(cm.exception))
        self.assertEqual(len(self.ran()), before)

    def test_several_hosts_go_names_the_plan(self):
        iid = self.open("web1,dns1")
        asked = []

        def prompt(msg):
            asked.append(msg)
            return ti._go(msg)
        rc, out = self.run_cmd("web1,dns1", iid, prompt=prompt)
        self.assertEqual(rc, 0)
        digest = [l.split()[-1] for l in out.splitlines() if l.startswith("plan-hash:")][0]
        self.assertIn("Type GO:%s " % digest[:6], asked[0])

    def test_close_phrase_uses_the_short_id(self):
        iid = self.open()
        asked = []

        def prompt(msg):
            asked.append(msg)
            return "CLOSE:%s" % iid[:11]
        self.close(iid, prompt=prompt)
        self.assertIn("CLOSE:%s " % iid[:11], asked[0])
        self.assertEqual(vpsexecincident.short_id(iid), iid[:11])

    def test_posture_refusal_under_an_incident_says_add_break_glass(self):
        iid = self.open()
        msg = self.refused("web1", iid, break_glass=False, needle="refuse mutations")
        self.assertIn("names incident %s" % iid, msg)
        self.assertIn("add --break-glass", msg)

    def test_posture_refusal_without_an_incident_points_at_one(self):
        msg = self.refused("web1", None, break_glass=False, cmd="systemctl reload nginx",
                           needle="refuse mutations")
        self.assertIn("vpsexec incident open", msg)


# ===========================================================================
# L3 / L8: the notifier, refusals and Ctrl-C, live progress; L7 hints;
# L4 templates run the door by path
# ===========================================================================

class NotifyHardeningTest(rf._Base):

    def governor(self, command):
        path = Path(self.tmp.name) / "gov.json"
        path.write_text(json.dumps({"integrations": {"notify": {"command": command}}}))
        return str(path)

    def test_the_notifier_must_be_an_absolute_path(self):
        for bad in (["push-note"], ["bin/push-note"], ["./push-note"]):
            with self.subTest(bad=bad), self.assertRaises(integrations.Refused):
                integrations.notify_command(self.governor(bad))
        self.assertEqual(integrations.notify_command(self.governor(["/usr/bin/true"])),
                         ["/usr/bin/true"])

    def test_the_notifier_runs_with_a_minimal_environment(self):
        script = Path(self.tmp.name) / "dump-env"
        out = Path(self.tmp.name) / "env.out"
        script.write_text("#!/bin/sh\nenv > %s\n" % out)
        script.chmod(0o700)
        with mock.patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "nope",
                                          "PATH": "/evil:" + os.environ.get("PATH", "")}):
            self.assertTrue(notify.send("halt", {}, governor=self.governor([str(script)])))
        env = dict(l.split("=", 1) for l in out.read_text().splitlines() if "=" in l)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertEqual(env.get("PATH"), notify.MINIMAL_ENV["PATH"])

    def test_refusals_and_ctrl_c_are_notified_without_output(self):
        sent = []
        vpsrun._notify_outside_run("refused", "release", "weekend",
                                   why="step 3 did not produce a plan (rc=2):\nPLAN — secret "
                                       "DB_PASSWORD=hunter2",
                                   send=lambda e, f: sent.append((e, f)))
        vpsrun._notify_outside_run("aborted", "play", "plays/x.yaml",
                                   send=lambda e, f: sent.append((e, f)))
        self.assertEqual([e for e, _ in sent], ["refused", "aborted"])
        self.assertEqual(sent[0][1]["why"], "step 3 did not produce a plan (rc=2):")
        self.assertNotIn("hunter2", json.dumps(sent))
        self.assertIn("refused", notify.EVENTS)
        self.assertIn("aborted", notify.EVENTS)

    def test_main_notifies_a_refusal(self):
        sent = []
        with mock.patch.object(vpsrun, "_notify_outside_run",
                               lambda e, m, t, why=None: sent.append((e, m, t))):
            with contextlib.redirect_stderr(io.StringIO()):
                rc = vpsrun.main(["release", "no-such-release"])
        self.assertEqual(rc, 2)
        self.assertEqual(sent, [("refused", "release", "no-such-release")])

    def test_a_long_step_prints_live_progress(self):
        class Slow:
            returncode = 0

            def __init__(self, *a, **k):
                self.calls = 0

            def communicate(self, timeout=None):
                self.calls += 1
                if self.calls < 3:
                    raise subprocess.TimeoutExpired("vpsexec", timeout)
                return "done\n", ""
        ticks = iter([0, 15, 30, 45])
        err = io.StringIO()
        rc, out = vpsrun._subprocess_run(["edge1", "docker compose up -d"], popen=Slow,
                                         clock=lambda: next(ticks), err=err)
        self.assertEqual((rc, out), (0, "done\n"))
        self.assertEqual(err.getvalue().count("still running"), 2)
        self.assertIn("still running (15s)", err.getvalue())

    def test_guard_refusal_hints_resume_or_wait(self):
        door = rf.SimDoor(rcs={"mkdir /srv/a": [1]}, window=300)
        self.go(door)
        door.calls.clear()
        # a NEW run meets the first run's identical plan inside the window:
        # no retry (another run's attempt), and a hint instead
        rc, out = self.go(door)
        self.assertNotEqual(rc, 0)
        self.assertIn("NOT retrying", out)
        self.assertRegex(out, r"wait until \d\d:\d\d .*--resume")


class DoorGuardHintTest(tk._KindsHarness):  # L7, at the door

    def test_unattended_repeat_names_a_time_and_resume(self):
        digest = self.digest_of("web1", tk.NGINX)
        argv = ["web1", tk.NGINX, "--break-glass", "--run", "--reason", "x",
                "--approve=%s" % digest]
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": digest,
                                   "reason": "earlier", "command": "x", "hosts": ["web1"]})
        with self.assertRaises(Refused) as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(argv, guard=tv._guard(), prober=self.prober(),
                                 policy=self.policy, ssh=self.fake_ssh(), stream=tg._TTY(),
                                 prompt=tg._no_prompt,
                                 blackout_runner=self.blackout_runner(unavailable=True))
        self.assertIn("Refusing an unattended repeat", str(cm.exception))
        self.assertRegex(str(cm.exception), r"wait until \d\d:\d\d")
        self.assertIn("--resume", str(cm.exception))


# ===========================================================================
# Round 3 (verifier r2)
# ===========================================================================

class ScopeFileLocationTest(tk._KindsHarness):  # item 2: H4a, symlinks/mode/repo
    NEWCMD = "systemctl restart postgres"

    def env(self):
        return {"PATH": os.environ["PATH"], "HOME": self.home.name, "GIT_AUTHOR_NAME": "a",
                "GIT_AUTHOR_EMAIL": "a@x", "GIT_COMMITTER_NAME": "a",
                "GIT_COMMITTER_EMAIL": "a@x", "GIT_CONFIG_NOSYSTEM": "1"}

    def test_symlink_into_a_private_clone_with_a_committed_edit_refuses(self):
        """Verifier test_symlink_into_private_clone_with_edit_committed_there:
        rc=0 and the never-reviewed command ran."""
        path = self.mint_reusable()
        clone = Path(tempfile.mkdtemp()) / "c"
        self.addCleanup(shutil.rmtree, clone.parent)
        subprocess.run(["git", "clone", "-q", str(self.policy_dir), str(clone)], check=True,
                       env=self.env(), capture_output=True)
        p = clone / "rb.yaml"
        p.write_text(p.read_text().replace('cmd: "systemctl restart caddy"',
                                           'cmd: "%s"' % self.NEWCMD))
        subprocess.run(["git", "-C", str(clone), "commit", "-qam", "private"], check=True,
                       env=self.env(), capture_output=True)
        (self.policy_dir / "rb.yaml").unlink()
        os.symlink(clone / "rb.yaml", self.policy_dir / "rb.yaml")
        self.reload_policy()
        with self.assertRaises(Refused) as cm:
            self.use("web1", self.NEWCMD, path)
        self.assertIn("symlink", str(cm.exception))
        self.assertEqual(self.ran(), [])

    def test_estate_root_reached_through_symlink(self):
        """Verifier: a policy directory reached through a symlink ABOVE the
        worktree top (a legitimate estate alias) refused. Only links between
        the top and the file refuse; the file must still resolve inside."""
        path = self.mint_reusable()
        alias = Path(tempfile.mkdtemp()) / "estate-link"
        self.addCleanup(shutil.rmtree, alias.parent)
        os.symlink(self.policy_dir, alias)
        real = self.policy_dir
        self.policy_dir = alias
        self.addCleanup(setattr, self, "policy_dir", real)
        self.reload_policy()
        self.assertEqual(self.use("web1", tk.NGINX, path), 0)
        self.assertTrue(self.ran())

    def test_a_symlink_to_the_same_content_elsewhere_refuses_too(self):
        path = self.mint_reusable()
        other = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, other)
        shutil.copy(self.policy_dir / "rb.yaml", other / "rb.yaml")
        (self.policy_dir / "rb.yaml").unlink()
        os.symlink(other / "rb.yaml", self.policy_dir / "rb.yaml")
        self.reload_policy()
        self.refuses(path, "symlink")

    def test_a_scope_file_not_mode_100644_refuses(self):
        path = self.mint_reusable()
        (self.policy_dir / "rb.yaml").chmod(0o755)
        self.git("update-index", "--chmod=+x", "rb.yaml")
        self.commit("make it executable")
        self.reload_policy()
        self.refuses(path, "mode 100644")

    def test_the_repository_must_be_the_one_minted_in(self):
        path = self.mint_reusable()
        g = self.load(path)
        g["scope"]["git"]["toplevel"] = "/somewhere/else"
        self.reseal(path, g)
        self.refuses(path, "not the one this grant was minted in")

    def test_renaming_the_scope_file_refuses(self):
        path = self.mint_reusable()
        self.git("mv", "rb.yaml", "rb-renamed.yaml")
        self.commit("rename")
        self.reload_policy()
        with self.assertRaises(Refused):
            self.use("web1", tk.NGINX, path)
        self.assertEqual(self.ran(), [])

    def test_git_environment_at_call_time_changes_nothing(self):
        """Verifier test_git_env_at_call_time: GIT_DIR / GIT_INDEX_FILE /
        GIT_CONFIG_PARAMETERS in the caller's environment."""
        path = self.mint_reusable()
        p = self.policy_dir / "rb.yaml"
        p.write_text(p.read_text().replace('cmd: "systemctl restart caddy"',
                                           'cmd: "%s"' % self.NEWCMD))
        self.reload_policy()
        fake = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, fake)
        with mock.patch.dict(os.environ, {"GIT_DIR": str(fake),
                                          "GIT_INDEX_FILE": str(fake / "i"),
                                          "GIT_CONFIG_PARAMETERS": "'core.fsmonitor'='/bin/true'",
                                          "GIT_CEILING_DIRECTORIES": "/"}):
            with self.assertRaises(Refused) as cm:
                self.use("web1", self.NEWCMD, path)
        self.assertIn("uncommitted", str(cm.exception))
        self.assertEqual(self.ran(), [])


class PinnedGitOwnershipTest(unittest.TestCase):  # item 7

    def test_a_user_owned_git_is_never_pinned(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        mine = tmp / "git"
        mine.write_text("#!/bin/sh\nexit 0\n")
        mine.chmod(0o755)  # not group/world-writable, but owned by this user
        with self.assertRaises(Refused):
            gitcmd.binary((str(mine),))

    def test_the_pinned_binary_and_every_parent_are_root_owned(self):
        path = os.path.realpath(gitcmd.binary())
        node = path
        while True:
            st = os.stat(node)
            self.assertEqual(st.st_uid, 0, node)
            self.assertFalse(st.st_mode & 0o022, node)
            if os.path.dirname(node) == node:
                break
            node = os.path.dirname(node)

    def test_symlink_in_user_dir_to_root_git(self):
        """Verifier: a symlink in a user-writable directory pointing at
        /usr/bin/git passed the (resolved) ownership check, and binary()
        returned — and run() executed — the symlink, which its owner could
        repoint between the check and the exec. The resolved path is returned."""
        real = os.path.realpath(gitcmd.binary())
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        link = tmp / "git"
        os.symlink(real, link)
        self.assertEqual(gitcmd.binary((str(link),)), real)
        seen = []
        real_run = subprocess.run

        def spy(argv, *a, **k):
            seen.append(argv[0])
            return real_run(argv, *a, **k)
        with mock.patch.object(gitcmd, "GIT_CANDIDATES", (str(link),)), \
                mock.patch.object(gitcmd.subprocess, "run", spy):
            gitcmd.run(str(tmp), "--version")
        self.assertEqual(seen, [real])

    def test_a_root_owned_binary_in_a_user_writable_directory_is_refused(self):
        chain = []

        def fake_stat(p, *a, **k):
            chain.append(p)
            real = os.stat.__wrapped__(p) if hasattr(os.stat, "__wrapped__") else _REAL_STAT(p)
            if p.endswith("/bin"):
                return os.stat_result((real.st_mode | 0o002,) + tuple(real)[1:])
            return real
        with mock.patch.object(gitcmd.os, "stat", fake_stat):
            with self.assertRaises(Refused):
                gitcmd.binary(("/usr/bin/git",))


_REAL_STAT = os.stat


class HostDoneRecordTest(dr._Base):  # item 1, the door side

    def test_host_done_is_written_only_after_the_lock_is_released(self):
        result = self.run_host("echo hi", dr._local)
        self.assertEqual(result["rc"], 0)
        events = self.events()
        names = [e["event"] for e in events]
        self.assertIn("host_done", names)
        done = [e for e in events if e["event"] == "host_done"][-1]
        self.assertEqual((done["host"], done["rc"]), (dr.HOST, 0))
        # Round 4: the attempt's run-scoped reason and plan hash travel with it.
        self.assertIn("reason", done)
        self.assertRegex(done.get("plan_hash") or "", r"^[0-9a-f]{64}\Z")
        self.assertGreater(names.index("host_done"),
                           max(i for i, n in enumerate(names) if n == "step"))
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_no_host_done_when_the_lock_is_retained(self):
        now = [0.0]
        detach._clock = lambda: now[0]
        detach._sleep = lambda s: now.__setitem__(0, now[0] + s)
        self.run_host("echo started", dr.Dropping(drops=10 ** 6))
        self.assertFalse(self.events("host_done"))


class LiveGroupAfterExitTest(dr._Base):  # item 3

    def test_an_exit_code_with_a_live_group_keeps_the_lock(self):
        n = "43.%06d" % (int(time.time() * 1e6) % 1000000)
        self.addCleanup(subprocess.run, ["pkill", "-f", "sleep %s" % n], capture_output=True)
        result = self.run_host("sleep %s >/dev/null 2>&1 & echo left" % n, dr._local)
        self.assertNotEqual(result["rc"], 0)
        self.assertIn("STILL RUNNING", result["error"] + " ".join(
            e.get("detail", "") for e in self.events("step")) or result["error"])
        self.assertIn("--stop", result["error"])
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists(), "the lock was released")
        self.assertTrue(Path(detach.OPS_DIR).exists() and list(Path(detach.OPS_DIR).iterdir()),
                        "the op dir was removed")
        self.assertTrue(self.events("step")[-1]["uncertain"])
        self.assertFalse(self.events("host_done"))
        self.assertEqual(self.events("mutation_complete"), [])  # run_host: no execute()


class UnmanagedHostTest(dr._Base):  # item 5

    def test_a_host_without_systemd_refuses_detached_steps(self):
        result = self.run_host("touch %s" % self.go, dr._local, unmanaged=False)
        self.assertNotEqual(result["rc"], 0)
        self.assertIn("no systemd", result["error"])
        self.assertIn("allow_unmanaged_steps", result["error"])
        time.sleep(0.3)
        self.assertFalse(self.go.exists(), "the step ran")
        self.assertFalse(Path(lock.LOCK_DIR).exists(), "a step that never started keeps no lock")
        ops = Path(detach.OPS_DIR)
        self.assertFalse(ops.exists() and list(ops.iterdir()), "files were written")

    def test_the_governor_can_opt_a_host_in(self):
        result = self.run_host("touch %s" % self.go, dr._local, unmanaged=True)
        self.assertEqual(result["rc"], 0)
        self.assertTrue(self.go.exists())

    def test_opt_in_takes_the_canonical_host_and_validates(self):
        from vpscfg.control import _validate
        base = {"version": 1, "mode": "test", "mutation_enabled": True,
                "deny_always": list(DENY_ALWAYS_FLOOR), "scopes": {"unlocked": []},
                "hosts": {"web1": {"posture": "test"},
                          "web": {"posture": "test", "alias_of": "web1"}}}
        for bad in ("web1", ["nosuch"], ["web"], [1]):
            with self.subTest(bad=bad), self.assertRaises(Refused):
                _validate(dict(base, allow_unmanaged_steps=bad))
        _validate(dict(base, allow_unmanaged_steps=["web1"]))
        guard = Guard(dict(base, allow_unmanaged_steps=["web1"]), True)
        self.assertTrue(vpsexec._allows_unmanaged(guard, "web1"))
        self.assertTrue(vpsexec._allows_unmanaged(guard, "web"))   # alias of an opted-in host
        self.assertFalse(vpsexec._allows_unmanaged(Guard(base, True), "web1"))

    def systemd_host(self, systemd_run):
        """A fake systemd host: /run/systemd/system exists, systemd-run is
        `systemd_run`, and a setsid shim that would launch anything."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "run-systemd-system").mkdir()
        b = root / "bin"
        b.mkdir()
        (b / "systemd-run").write_text(systemd_run)
        (b / "setsid").write_text("#!/bin/sh\nexec \"$@\"\n")
        for f in ("systemd-run", "setsid"):
            (b / f).chmod(0o755)

        def ssh(host, cmd, timeout=None, connect_timeout=None):
            cmd = cmd.replace("/run/systemd/system", str(root / "run-systemd-system"))
            r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                               timeout=timeout or 60,
                               env=dict(os.environ, PATH="%s:%s" % (b, os.environ["PATH"])))
            return r.returncode, r.stdout, r.stderr
        ssh.detached = True  # as the real ssh: mutation steps launch detached
        return ssh

    def test_systemd_run_failure_falls_back_to_unmanaged(self):
        """Verifier: on a systemd host NOT opted in, a failing systemd-run
        fell through to `setsid nohup` and the step ran unmanaged. Now it is
        fenced and refused; nothing runs, and the lock is released."""
        ssh = self.systemd_host("#!/bin/sh\necho 'Failed to start transient service unit: "
                                "Connection timed out' >&2\nexit 1\n")
        token = lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        with self.assertRaises(Refused) as cm:
            detach.run(dr.HOST, token, 1, "touch %s" % self.go, token, ssh, 10)
        self.assertIn("systemd-run failed", str(cm.exception))
        self.assertIn("NOT started", str(cm.exception))
        time.sleep(1.0)
        self.assertFalse(self.go.exists(), "the step ran unmanaged")
        self.assertTrue(Path(detach.op_dir(token), "1.started").is_dir(), "not fenced")
        # The whole door: refused, never run, lock released.
        lock.release(dr.HOST, runner=dr._local, token=token)
        result = self.run_host("touch %s" % self.go, ssh, unmanaged=False)
        self.assertNotEqual(result["rc"], 0, result)
        self.assertIn("systemd-run failed", result["error"])
        time.sleep(0.5)
        self.assertFalse(self.go.exists())
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_a_failed_systemd_run_whose_unit_started_anyway_is_followed(self):
        # systemd-run reports failure but the unit DID start the runner: the
        # guard is taken, so the launch is reported launched, never "not run".
        ssh = self.systemd_host(
            "#!/bin/sh\nfor a; do r=$a; done\n/bin/sh \"$r\" >/dev/null 2>&1 </dev/null &\n"
            "sleep 0.5; exit 1\n")
        token = lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        rc, _, _ = detach.run(dr.HOST, token, 1, "touch %s" % self.go, token, ssh, 30)
        self.assertEqual(rc, 0)
        self.assertTrue(self.go.exists())

    def test_a_stale_guard_with_no_runner_is_fenced_by_other_not_launched(self):
        """Verifier test_adv_fence_r4 "fails, stale .started from a fence":
        systemd-run failed, the single-run guard already existed (an earlier
        fence) and no runner ever wrote a pid — yet the launch said LAUNCHED.
        Now: FENCED_BY_OTHER, this launch ran nothing, outcome UNKNOWN and
        the lock stays."""
        ssh = self.systemd_host("#!/bin/sh\nexit 1\n")
        token = lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        Path(detach.op_dir(token), "1.started").mkdir(parents=True)
        _, out, _ = ssh(dr.HOST, detach.launch_cmd(token, 1, "touch %s" % self.go, token))
        self.assertIn(detach.FENCED_BY_OTHER, out)
        self.assertNotIn(detach.LAUNCHED, out)
        for f in ("1.sh", "1.run"):  # so the door's own launch gets that far again
            Path(detach.op_dir(token), f).unlink()
        with self.assertRaises(detach.DetachUnknown) as cm:
            detach.run(dr.HOST, token, 1, "touch %s" % self.go, token, ssh, 10)
        self.assertIn("already taken by another launch or fence", str(cm.exception))
        self.assertNotIsInstance(cm.exception, Refused)
        self.assertFalse(self.go.exists())
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists(), "the lock was released")

    def test_a_stale_guard_keeps_the_door_lock_and_journals_uncertain(self):
        ssh = self.systemd_host("#!/bin/sh\nexit 1\n")
        real_acquire = lock.acquire

        def acquire_with_stale_guard(*a, **k):
            token = real_acquire(*a, **k)
            Path(detach.op_dir(token), "1.started").mkdir(parents=True)
            return token
        with mock.patch.object(lock, "acquire", acquire_with_stale_guard):
            result = self.run_host("touch %s" % self.go, ssh, unmanaged=False)
        self.assertNotEqual(result["rc"], 0)
        self.assertFalse(self.go.exists())
        self.assertTrue(Path(lock.LOCK_DIR, "token").exists(), "the lock was released")
        self.assertTrue(self.events("step")[-1].get("uncertain"))
        self.assertFalse(self.events("host_done"))

    def test_only_an_opted_in_host_has_a_setsid_fallback(self):
        strict = detach.launch_cmd("f" * 64, 1, "true", "f" * 64)
        self.assertNotIn("setsid /bin/sh", strict)
        self.assertNotIn("nohup", strict)
        self.assertIn(detach.SYSTEMD_FAILED, strict)
        opted = detach.launch_cmd("f" * 64, 1, "true", "f" * 64, unmanaged_ok=True)
        self.assertIn("setsid /bin/sh", opted)

    def test_the_gate_runs_before_anything_is_written(self):
        cmd = detach.launch_cmd("f" * 64, 1, "true", "f" * 64)
        self.assertLess(cmd.index(detach.UNMANAGED), cmd.index("mkdir"))
        self.assertNotIn(detach.UNMANAGED,
                         detach.launch_cmd("f" * 64, 1, "true", "f" * 64, unmanaged_ok=True))


class PgidReuseTest(_Reconcile):  # item 6

    def reused_op(self):
        """A held lock whose step's recorded leader pid now belongs to an
        unrelated process group leader that started at another time."""
        token = lock.acquire(dr.HOST, "alice", "night release", runner=dr._local)
        d = Path(detach.op_dir(token))
        d.mkdir(parents=True)
        os.chmod(d, 0o700)
        (d / "1.sh").write_text("true\n")
        (d / "1.started").mkdir()
        (d / "1.rc").write_text("0\n")
        other = subprocess.Popen(["sleep", "30"], start_new_session=True)
        self.addCleanup(other.kill)
        (d / "1.cpid").write_text("%d\n" % other.pid)
        (d / "1.cstart").write_text("Thu Jan  1 00:00:00 1970\n")
        return token, other

    def test_a_reused_leader_pid_is_unknown_and_never_signalled(self):
        token, other = self.reused_op()
        st = detach.poll(dr.HOST, token, 1, dr._local)
        self.assertEqual(st["pg"], "reused")
        self.assertFalse(st["running"])
        res, out = self.reconcile("--stop")
        self.assertIn("nothing to stop", out)  # not running: nothing is signalled
        self.assertIsNone(other.poll(), "an unrelated process was signalled")
        res, out = self.reconcile(answer="no")
        self.assertIn("VERDICT: UNKNOWN", out)
        self.assertIsNone(other.poll())

    def test_stop_refuses_a_reused_group_while_the_op_runs(self):
        token, other = self.reused_op()
        (Path(detach.op_dir(token)) / "1.rc").unlink()
        # The runner (by argv) is gone; only the recycled leader pid exists.
        out = dr._local(dr.HOST, detach.stop_cmd(token))[1]
        self.assertIn(detach.STOP_REFUSED + " reused 1 %d" % other.pid, out)
        self.assertIsNone(other.poll())

    def test_a_live_leader_with_its_own_start_time_is_alive(self):
        token = self.launched("sleep 5")
        self.wait_for(Path(detach.op_dir(token), "1.cstart"))
        time.sleep(0.2)
        st = detach.poll(dr.HOST, token, 1, dr._local)
        self.assertEqual(st["pg"], "alive")
        self.assertTrue(st["running"])
        self.prompts.clear()
        rc, out = self.reconcile("--stop")
        self.assertEqual(rc, 0, out)


class RecycledControllerTest(_Reconcile):  # item 8

    def test_a_recycled_controller_pid_is_a_dead_controller(self):
        """Verifier test_M1_recycled_pid: pid 1 is alive but is not the door."""
        lock.acquire(dr.HOST, "alice", "night release", runner=dr._local)
        meta = self.owner()
        meta["controller"]["pid"] = 1
        meta["controller"]["started"] = int(time.time())
        self.set_owner(meta)
        self.assertIsNone(vpsexec._live_controller(meta))
        old = time.time() - vpsexec.unproven_lock_min_age() - 60
        os.utime(lock.LOCK_DIR, (old, old))
        rc, out = self.reconcile()
        self.assertEqual(rc, 0, out)

    def test_the_real_controller_is_recognised_by_its_start_time(self):
        self.restore_controller()
        lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        meta = self.owner()
        self.assertLessEqual(abs(meta["controller"]["started"]
                                 - lock.process_start(os.getpid())), lock.START_TOLERANCE)
        self.assertIsNotNone(vpsexec._live_controller(meta))
        meta["controller"]["started"] -= 3600  # same pid number, another process
        self.assertIsNone(vpsexec._live_controller(meta))

    def test_the_refusal_says_how_to_find_the_process(self):
        self.restore_controller()
        lock.acquire(dr.HOST, "alice", "x", runner=dr._local)
        res, _ = self.reconcile()
        self.assertIsInstance(res, Refused)
        self.assertNotIn("Ctrl-C in its terminal", str(res))
        self.assertIn("ps -o pid,lstart,args -p %d" % os.getpid(), str(res))

    def test_etime_parsing(self):
        for text, secs in (("05:07", 307), ("1:02:03", 3723), ("2-01:00:00", 176400),
                           (" 00:01", 1), ("bogus", None), ("", None)):
            self.assertEqual(lock._etime_seconds(text), secs, text)


class NoEnvironmentIdentityTest(unittest.TestCase):  # L2, everywhere

    def test_no_source_takes_the_operator_from_the_environment(self):
        root = Path(__file__).resolve().parent.parent
        files = sorted(list((root / "vpscfg").glob("*.py"))
                       + [root / n for n in ("vpsexec", "vpsrun", "vpscfg-control.py")])
        bad = []
        for path in files:
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if re.search(r"environ(\.get)?\(?\[?[\"'](USER|LOGNAME)[\"']|getpass\.getuser",
                             line):
                    bad.append("%s:%d: %s" % (path.name, n, line.strip()))
        self.assertEqual(bad, [])

    def test_executor_lock_owner_uses_the_password_database(self):
        src = (Path(__file__).resolve().parent.parent / "vpscfg" / "executor.py").read_text()
        self.assertIn("operator = journal.operator()", src)


class TemplatesRunDoorsByPathTest(unittest.TestCase):  # L4

    def test_no_template_runs_a_door_through_python(self):
        root = Path(__file__).resolve().parent.parent / "contrib"
        doors = ("vpscfg-control.py", "vpsexec", "vpsrun")
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            text = path.read_text(errors="replace")
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                for door in doors:
                    with self.subTest(path=str(path), door=door):
                        self.assertNotRegex(line, r"python3?\S*\s+\S*%s" % re.escape(door))
            if path.suffix == ".plist":
                self.assertNotIn("<string>/usr/bin/python3</string>", text)


if __name__ == "__main__":
    unittest.main()
