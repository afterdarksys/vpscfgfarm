"""vpsrun: typed-action steps in a play (docs/ACTIONS.md, vpscfgfarm phase 2
plan P3) — `action:` + `with:` instead of `cmd:`, the reserved-word refusal,
plan-display collapsing, and resume settling an idempotent action's host as
`[done]` from its own check, with no SKIP-DONE/RERUN phrase.

Fakes and temp dirs only, exactly like tests/test_vpsrun.py: no real host, no
real policy, no subprocess. The FakeDoor here only needs to produce plan text
shaped like vpsexec's (docs/ACTIONS.md "What the plan... carries"), not expand
a real action."""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import actions, journal  # noqa: E402
import test_vpsrun as tr  # noqa: E402

vpsrun = tr.vpsrun

ACTION_PLAY = """version: 1
reason: "shop health gate"
steps:
  - hosts: edge1
    action: wait_healthy
    with: {container: shop-web, tries: 20, interval: 3}
    why: "H1: wait until shop-web reports healthy"
"""


class _FakeAction(object):
    """Stands in for a registered Action: only .tier matters to vpsrun."""

    def __init__(self, tier):
        self.tier = tier


class _RegistryPatch(object):
    """Patches vpscfg.actions.get for the duration of a test, so a test can
    make `read_steps()` see a MUTATION-tier action without a real P1
    action module (none is registered in this worktree yet — P0 ships only
    the reference read action, wait_healthy)."""

    def __init__(self, tiers):
        self.tiers = tiers

    def __enter__(self):
        self._orig = actions.get

        def fake_get(name, where="action"):
            base = name.split("@", 1)[0]
            if base in self.tiers:
                return _FakeAction(self.tiers[base])
            return self._orig(name, where)
        actions.get = fake_get
        return self

    def __exit__(self, *exc):
        actions.get = self._orig


class LoadPlayActionStepTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._jdir = journal.JOURNAL_DIR
        journal.JOURNAL_DIR = Path(self.tmp.name)
        self.path = Path(self.tmp.name) / "p.yaml"

    def tearDown(self):
        journal.JOURNAL_DIR = self._jdir
        self.tmp.cleanup()

    def _play(self, text):
        self.path.write_text(text)
        return vpsrun.load_play(self.path)

    def test_action_step_loads(self):
        play = self._play(ACTION_PLAY)
        step = play["steps"][0]
        self.assertEqual(step["action"], "wait_healthy")
        self.assertEqual(step["with"], {"container": "shop-web", "tries": 20,
                                        "interval": 3})
        self.assertNotIn("cmd", step)

    def test_with_defaults_to_empty_mapping(self):
        play = self._play(ACTION_PLAY.replace(
            "    with: {container: shop-web, tries: 20, interval: 3}\n", ""))
        self.assertEqual(play["steps"][0]["with"], {})

    def test_cmd_and_action_together_refuses(self):
        text = ACTION_PLAY.replace(
            '    why: "H1: wait until shop-web reports healthy"',
            '    cmd: "echo hi"\n    why: "H1: wait until shop-web reports healthy"')
        with self.assertRaises(vpsrun.Refused):
            self._play(text)

    def test_bad_action_name_refuses(self):
        for bad in ("Ensure_Owner", "123start", "has space", "a" * 40):
            with self.assertRaises(vpsrun.Refused, msg=bad):
                self._play(ACTION_PLAY.replace("wait_healthy", bad))

    def test_with_must_be_a_mapping(self):
        text = ACTION_PLAY.replace(
            "with: {container: shop-web, tries: 20, interval: 3}", "with: [1, 2]")
        with self.assertRaises(vpsrun.Refused):
            self._play(text)

    def test_with_over_size_refuses(self):
        big = "with: {container: %s}" % ("x" * 9000)
        text = ACTION_PLAY.replace(
            "with: {container: shop-web, tries: 20, interval: 3}", big)
        with self.assertRaises(vpsrun.Refused):
            self._play(text)

    def test_action_step_refuses_placement_flags(self):
        for flag in ("--in=shop-web", "--in-match=shop", "--verify=true"):
            text = ACTION_PLAY.replace(
                '    why: "H1: wait until shop-web reports healthy"',
                '    flags: ["%s"]\n    why: "H1: wait until shop-web reports healthy"'
                % flag)
            with self.assertRaises(vpsrun.Refused, msg=flag):
                self._play(text)

    def test_action_step_accepts_timeout_and_break_glass(self):
        text = ACTION_PLAY.replace(
            '    why: "H1: wait until shop-web reports healthy"',
            '    flags: ["--timeout=90", "--break-glass"]\n'
            '    why: "H1: wait until shop-web reports healthy"')
        play = self._play(text)
        self.assertEqual(play["steps"][0]["flags"], ["--timeout=90", "--break-glass"])

    def test_push_and_action_together_refuses(self):
        text = ACTION_PLAY.replace(
            '    action: wait_healthy',
            '    push: deploy/x.sh\n    sha256: "%s"\n    action: wait_healthy' % ("c" * 64))
        with self.assertRaises(vpsrun.Refused):
            self._play(text)


# ===========================================================================
# the reserved spelling: a hand-typed `vpscfg-action ...` in cmd: is refused
# (the only way to reach an action is action: + with:, docs/ACTIONS.md)
# ===========================================================================

RESERVED_PLAY = """version: 1
reason: "r"
steps:
  - hosts: edge1
    cmd: "vpscfg-action ensure_owner@1 '{\\"container\\":\\"shop-db\\"}'"
    why: "hand-typed, must refuse"
"""


class ReservedWordTest(unittest.TestCase):
    setUp, tearDown = LoadPlayActionStepTest.setUp, LoadPlayActionStepTest.tearDown
    _play = LoadPlayActionStepTest._play

    def test_reserved_word_in_cmd_refuses(self):
        with self.assertRaises(vpsrun.Refused) as cm:
            self._play(RESERVED_PLAY)
        self.assertIn("reserved", str(cm.exception))

    def test_reserved_word_as_a_path_prefix_also_refuses(self):
        text = RESERVED_PLAY.replace("vpscfg-action", "/usr/local/bin/vpscfg-action")
        with self.assertRaises(vpsrun.Refused):
            self._play(text)

    def test_ordinary_cmd_steps_are_unaffected(self):
        play = self._play(RESERVED_PLAY.replace(
            'cmd: "vpscfg-action ensure_owner@1 \'{\\"container\\":\\"shop-db\\"}\'"',
            'cmd: "systemctl restart nginx"'))
        self.assertEqual(play["steps"][0]["cmd"], "systemctl restart nginx")


# ===========================================================================
# step_argv: the door builds the body — vpsrun only hands it typed literals
# ===========================================================================

class StepArgvTest(unittest.TestCase):
    def test_action_argv_shape(self):
        play = {"reason": "r"}
        step = {"hosts": "edge1", "action": "wait_healthy",
                "with": {"tries": 20, "container": "shop-web"}, "why": "H1", "flags": []}
        argv = vpsrun.step_argv(play, 1, step, "r_deadbeefdeadbeef")
        self.assertEqual(argv[:4], ["edge1", "--action", "wait_healthy", "--with"])
        # canonical JSON: sorted keys, no spaces — two spellings hash the same.
        self.assertEqual(argv[4], '{"container":"shop-web","tries":20}')
        self.assertEqual(argv[-2], "--reason")

    def test_action_argv_carries_flags_before_reason(self):
        play = {"reason": "r"}
        step = {"hosts": "edge1", "action": "wait_healthy", "with": {},
                "why": "H1", "flags": ["--timeout=90"]}
        argv = vpsrun.step_argv(play, 1, step)
        self.assertIn("--timeout=90", argv)
        self.assertLess(argv.index("--timeout=90"), argv.index("--reason"))


# ===========================================================================
# read_steps: an action's tier is fixed in code, never guessed from cmd text
# ===========================================================================

class ReadStepsActionTierTest(unittest.TestCase):
    setUp, tearDown = LoadPlayActionStepTest.setUp, LoadPlayActionStepTest.tearDown
    _play = LoadPlayActionStepTest._play

    def test_a_read_action_is_treated_as_a_read(self):
        play = self._play(ACTION_PLAY)
        self.assertEqual(vpsrun.read_steps(play), {1})

    def test_a_mutation_action_is_not_a_read(self):
        with _RegistryPatch({"wait_healthy": "mutation"}):
            play = self._play(ACTION_PLAY)
            self.assertEqual(vpsrun.read_steps(play), set())

    def test_a_read_action_step_may_not_carry_a_mutation_flag(self):
        text = ACTION_PLAY.replace(
            '    why: "H1: wait until shop-web reports healthy"',
            '    flags: ["--break-glass"]\n    why: "H1: wait until shop-web reports healthy"')
        play = self._play(text)
        with self.assertRaises(vpsrun.Refused):
            vpsrun.read_steps(play)


# ===========================================================================
# plan display: an action's body is collapsed after 15 lines; --full expands.
# The hash binds the whole body either way — collapsing is display only.
# ===========================================================================

def _plan_with_body(n_lines):
    body = "\n".join("      line %d" % i for i in range(n_lines))
    return ("PLAN — 1 host: edge1\n  command : vpscfg-action wait_healthy@1 '{}'\n"
            "  action  : wait_healthy@1 (read)\nWILL RUN:\n  edge1\n    body:\n%s\n"
            "    check:\n      true\n" % body)


class CollapseBodyTest(unittest.TestCase):
    def test_short_body_is_unchanged(self):
        text = _plan_with_body(5)
        self.assertEqual(vpsrun._collapse_bodies(text, full=False).rstrip(), text.rstrip())

    def test_long_body_is_collapsed_by_default(self):
        text = _plan_with_body(40)
        out = vpsrun._collapse_bodies(text, full=False)
        self.assertIn("      line 14", out)
        self.assertNotIn("      line 15", out)
        self.assertIn("more line(s)", out)
        self.assertIn("--full", out)
        # the line AFTER the body (check:) still prints, untouched.
        self.assertIn("    check:\n      true", out)

    def test_full_flag_shows_every_line(self):
        text = _plan_with_body(40)
        out = vpsrun._collapse_bodies(text, full=True)
        self.assertEqual(out, text)
        self.assertIn("      line 39", out)

    def test_collapsing_never_changes_the_digest(self):
        """The plan-hash is computed by the door from the full plan text
        BEFORE vpsrun ever collapses anything for display; collapsing must
        never touch the --approve=<hash> line itself."""
        text = _plan_with_body(40) + "plan-hash: " + "a" * 64 + "\n"
        out = vpsrun._collapse_bodies(text, full=False)
        self.assertIn("plan-hash: " + "a" * 64, out)


# ===========================================================================
# resume: an idempotent action's [done] host settles with no SKIP-DONE/RERUN
# phrase (docs/ACTIONS.md: "a done step costs no SKIP-DONE phrase: it reports
# [done]"); the check never releases a lock, so a RETAINED lock still needs
# `vpsexec reconcile` exactly as for a plain cmd (unchanged).
# ===========================================================================

class ResumeActionSettlementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._jdir = journal.JOURNAL_DIR
        journal.JOURNAL_DIR = Path(self.tmp.name)
        self.play = {"path": "p.yaml", "sha256": "x" * 64, "reason": "r",
                    "steps": [{"hosts": "edge1", "action": "ensure_owner",
                              "with": {"container": "shop-db"},
                              "why": "take ownership", "flags": []}],
                    "precheck": []}
        self.run_id = "r_" + "0" * 16
        self.digest = "d" * 64

    def tearDown(self):
        journal.JOURNAL_DIR = self._jdir
        self.tmp.cleanup()

    def _unit(self):
        step = self.play["steps"][0]
        return {"play": self.play, "n": 1, "step": step, "text": "plan", "read": False,
                "digest": self.digest, "done": None, "reports": {}}

    def _reason(self):
        return vpsrun.step_reason(self.play, 1, self.play["steps"][0], self.run_id)

    def _seed_started(self):
        vpsrun._rjournal({"event": "step_started", "run_id": self.run_id,
                          "play": vpsrun._key(self.play), "step": 1,
                          "digest": self.digest})

    def _seed_attempt(self, hosts=("edge1",)):
        journal.append("vpsexec", {"event": "mutation_attempt", "plan_hash": self.digest,
                                   "reason": self._reason(), "command": "whatever",
                                   "hosts": list(hosts)})

    def test_door_died_after_the_check_reported_done_settles_with_no_phrase(self):
        self._seed_started()
        self._seed_attempt()
        journal.append("vpsexec", {"event": "host_done", "host": "edge1",
                                   "reason": self._reason(), "plan_hash": self.digest,
                                   "rc": 0, "verify_rc": None, "already_done": True})

        def no_ask(msg):
            raise AssertionError("no phrase should be asked: %r" % msg)
        units = [self._unit()]
        with contextlib.redirect_stdout(io.StringIO()):
            vpsrun.resume_plan(units, self.run_id, ask=no_ask)
        self.assertEqual(units[0]["done"], "ok")
        recs = vpsrun._run_records(self.run_id)
        done = [r for r in recs if r["event"] == "step_done"][0]
        self.assertEqual(done["status"], "ok")
        self.assertEqual(done["settled_from"], "check")

    def test_door_died_before_finishing_the_host_still_needs_reconcile(self):
        """No host_done at all (the check never ran, or NEEDED and the body
        was still running): resume refuses and names `vpsexec reconcile`,
        unchanged from a plain cmd step."""
        self._seed_started()
        self._seed_attempt()
        units = [self._unit()]
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(vpsrun.Refused) as cm:
                vpsrun.resume_plan(units, self.run_id, ask=lambda m: "nope")
        self.assertIn("vpsexec reconcile edge1", str(cm.exception))

    def test_a_retained_lock_still_needs_reconcile_even_if_done_elsewhere(self):
        """S7: a check never releases a lock. A mutation_complete that
        retained edge1's lock is not settled by any host_done, even an
        already_done one recorded for a DIFFERENT, unrelated attempt."""
        self._seed_started()
        self._seed_attempt()
        journal.append("vpsexec", {"event": "host_done", "host": "web2",
                                   "reason": "unrelated attempt", "plan_hash": "e" * 64,
                                   "rc": 0, "verify_rc": None, "already_done": True})
        # edge1's outcome is uncertain (not_run), its lock still retained: a
        # real door writes exactly this when it could not finish the check.
        journal.append("vpsexec", {"event": "mutation_complete", "command": "whatever",
                                   "hosts": ["edge1"], "failed": [], "not_run": ["edge1"],
                                   "lock_retained": {"edge1": "op_123"}})
        units = [self._unit()]
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(vpsrun.Refused) as cm:
                vpsrun.resume_plan(units, self.run_id, ask=lambda m: "nope")
        self.assertIn("vpsexec reconcile edge1", str(cm.exception))

    def test_completed_but_not_already_done_still_asks_skip_done(self):
        """A plain (non-idempotent, or idempotent-but-NEEDED-then-ran) step
        that genuinely completed still goes through the human SKIP-DONE/RERUN
        decision — only an already_done check bypasses it."""
        self._seed_started()
        self._seed_attempt()
        journal.append("vpsexec", {"event": "host_done", "host": "edge1",
                                   "reason": self._reason(), "plan_hash": self.digest,
                                   "rc": 0, "verify_rc": None, "already_done": False})
        asked = []

        def ask(msg):
            asked.append(msg)
            return "SKIP-DONE:p:1"
        units = [self._unit()]
        with contextlib.redirect_stdout(io.StringIO()):
            vpsrun.resume_plan(units, self.run_id, ask=ask)
        self.assertTrue(asked)
        self.assertEqual(units[0]["done"], "ok")


class RerunCautionTest(unittest.TestCase):
    """L4: the RERUN prompt says what a migrate rerun repeats."""

    def test_sql_dir_rerun_warns_that_every_file_is_applied_again(self):
        text = vpsrun._rerun_caution({"action": "migrate", "with": {
            "container": "pg-main", "runner": "sql_dir", "db": "shop",
            "workdir": "/migrations"}})
        self.assertIn("every .sql file", text)
        self.assertIn("already succeeded", text)

    def test_other_runners_get_the_milder_caution(self):
        text = vpsrun._rerun_caution({"action": "migrate@1", "with": {
            "container": "shop-api", "runner": "prisma_deploy"}})
        self.assertIn("skips migrations it already applied", text)

    def test_no_caution_for_other_steps(self):
        self.assertIsNone(vpsrun._rerun_caution({"cmd": "systemctl restart shop-web"}))
        self.assertIsNone(vpsrun._rerun_caution({"action": "tag_image", "with": {}}))


if __name__ == "__main__":
    unittest.main()
