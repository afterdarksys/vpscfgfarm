"""`vpsrun release new` (vpscfgfarm phase 2 plan, P3) — scaffolding plays/ and
releases/ from a committed runbook policy, and the "lint on save" gate that
`vpsrun release NAME` runs before planning anything.

Fakes and temp dirs only, exactly like tests/test_vpsrun.py and
tests/test_release_flow.py: no real host, no real door subprocess. lint_fn
and preflight_fn are always injected fakes here — releasenew.new() itself
never contacts a host (it always runs `--index-only`), but a test must not
depend on the real `vpsexec` binary or a governor existing."""
import contextlib
import datetime
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import journal, releasenew, runbookcheck  # noqa: E402
from vpscfg.gates import Refused as GatesRefused  # noqa: E402
import test_vpsexec as tv  # noqa: E402
import test_vpsrun as tr  # noqa: E402

vpsrun = tr.vpsrun

# A worked example: the weekend's `shop` policy, trimmed to what a hermetic
# test needs — a STOP step (a read that can fail, as `runbook lint`'s STOP
# and probe rules require), two forward steps and one rollback. It is
# complete enough that the REAL lint says GO on what `release new` makes.
SHOP_POLICY = """version: 1
expires: "2999-01-01"
reason: "shop 1.5.0 release"
shape: {steps: 4, hosts: [edge1, web1], break_glass: mixed}
runbooks:
  - hosts: [web1]
    cmd: "systemctl is-active --quiet shop-db-proxy"
    why: "STOP: halt unless the shop-db proxy is active"
    timeout: 30
  - hosts: [edge1]
    cmd: "docker exec shop-db shop-migrate up"
    why: "W2: run the pending migration"
    timeout: 120
  - hosts: [web1]
    cmd: "systemctl restart shop-web"
    why: "W3: restart shop-web on the new schema"
    timeout: 60
  - hosts: [web1]
    cmd: "systemctl start shop-web-old"
    why: "put the old unit back (rollback only)"
    rollback: true
    break_glass: true
    timeout: 60
assumes:
  - host: edge1
    container: shop-db
"""
# The same, with step 3 optional: release new gives it a `when:` stub on the
# STOP step, which lint fails until a human writes the real condition.
OPTIONAL_POLICY = SHOP_POLICY.replace(
    'why: "W3: restart shop-web on the new schema"',
    'why: "W3: optional - restart shop-web only if the schema changed"')


LINT_TODAY = "2026-10-12"
LINT_NOW = datetime.datetime(2026, 10, 12, 12, 0, 0)


def _real_lint(case, policy=None):
    """The REAL `runbook lint` (runbookcheck.lint + render), as `vpsexec
    runbook lint` runs it, against the test estate's plays and releases."""
    def fn(policy_path):
        rep = runbookcheck.lint(policy_path, tv._guard(), policy or tv._yaml_policy(),
                                plays_dir=case.plays, releases_dir=case.releases,
                                today=LINT_TODAY, now=LINT_NOW)
        return rep["exit_code"], runbookcheck.render(rep)
    return fn


def _real_preflight(case):
    """The REAL `runbook preflight --index-only`, with a transport that fails
    the test if it is ever dialled."""
    def never(*a, **k):
        raise AssertionError("--index-only dialled a host: %r" % (a,))

    def fn(policy_path):
        rep = runbookcheck.preflight(policy_path, tv._guard(), tv._yaml_policy(), ssh=never,
                                     today=LINT_TODAY, index_only=True,
                                     index_dir=case.root / "index",
                                     now=LINT_NOW.replace(tzinfo=datetime.timezone.utc))
        return rep["exit_code"], runbookcheck.render(rep)
    return fn


class _ReadAwareDoor(tr.FakeDoor):
    """tr.FakeDoor, plus the STOP step: a read runs in place (no plan, no
    --run), and the door reports it as a read."""

    READS = ("systemctl is-active --quiet shop-db-proxy",)

    def __call__(self, argv):
        if len(argv) > 1 and argv[1] in self.READS and "--run" not in argv:
            self.reads = getattr(self, "reads", []) + [argv]
            return 0, "  tier    : read\n  [ok] web1\n"
        return tr.FakeDoor.__call__(self, argv)


def _go_fake(rc=0, label="policy"):
    def fn(policy_path):
        return rc, "RUNBOOK CHECK %s\n  [%-6s] %-20s ok\nVERDICT: %s (exit %d)" % (
            policy_path, "pass" if rc == 0 else ("warn" if rc == 1 else "fail"),
            label, releasenew.VERDICT_NAME[rc], rc)
    return fn


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.policies = self.root / "policies"
        self.plays = self.root / "plays"
        self.releases = self.root / "releases"
        for d in (self.policies, self.plays, self.releases):
            d.mkdir()
        (self.policies / "shop-1.5.0.yaml").write_text(SHOP_POLICY)
        self._jdir = journal.JOURNAL_DIR
        journal.JOURNAL_DIR = self.root / "journal"

    def tearDown(self):
        journal.JOURNAL_DIR = self._jdir
        self.tmp.cleanup()

    def _new(self, name="shop-1.5", from_arg="policies/shop-1.5.0.yaml", **kw):
        kw.setdefault("lint_fn", _go_fake(0, "lint"))
        kw.setdefault("preflight_fn", _go_fake(0, "preflight"))
        return releasenew.new(name, from_arg, estate_root=self.root,
                              plays_dir=self.plays, releases_dir=self.releases, **kw)


# ===========================================================================
# the worked example: GO, one play per policy, a release that plans with
# exactly one phrase through a fake door
# ===========================================================================

class WorkedExampleTest(_Base):
    def test_scaffolds_one_play_and_a_release_that_lint_go(self):
        result = self._new()
        self.assertEqual(result["verdict"], "GO")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(len(result["plays"]), 1)
        play_path = Path(result["plays"][0])
        self.assertEqual(play_path.name, "shop-1.5-shop-1.5.0.yaml")
        self.assertTrue(play_path.is_file())
        self.assertEqual(Path(result["release"]).name, "shop-1.5.yaml")

    def test_the_forward_steps_are_in_the_play_and_rollback_is_not(self):
        self._new()
        play = vpsrun.load_play(self.plays / "shop-1.5-shop-1.5.0.yaml")
        cmds = [s.get("cmd") for s in play["steps"]]
        self.assertEqual(cmds, ["systemctl is-active --quiet shop-db-proxy",
                                "docker exec shop-db shop-migrate up",
                                "systemctl restart shop-web"])
        self.assertNotIn("systemctl start shop-web-old", cmds)

    def test_timeout_is_carried_as_a_flag(self):
        self._new()
        play = vpsrun.load_play(self.plays / "shop-1.5-shop-1.5.0.yaml")
        self.assertIn("--timeout=120", play["steps"][1]["flags"])

    def test_rollback_step_is_only_under_on_fail(self):
        self._new()
        release = vpsrun.load_release("shop-1.5", release_dir=self.releases,
                                      play_dir=self.plays, policy_dir=self.policies)
        self.assertEqual(len(release["on_fail"]), 1)
        offer = release["on_fail"][0]
        self.assertEqual(offer["runbook"], "shop-1.5.0.yaml")
        self.assertEqual(offer["step"], 4)
        self.assertIn("systemctl start shop-web-old", offer["command"])

    def test_the_optional_step_stub_points_at_the_stop_step(self):
        (self.policies / "shop-1.5.0.yaml").write_text(OPTIONAL_POLICY)
        self._new()
        play = vpsrun.load_play(self.plays / "shop-1.5-shop-1.5.0.yaml")
        # step 1 (STOP) got an id; the OPTIONAL step 3 got a `when:` stub a
        # human must read and replace or delete; required step 2 got none.
        self.assertEqual(play["steps"][0].get("id"), "s1")
        self.assertNotIn("when", play["steps"][1])
        self.assertEqual(play["steps"][2]["when"]["id"], "s1")

    def test_required_steps_never_get_a_when_stub(self):
        # V5: a stub on a required step silently skipped the migration and
        # the restart (the placeholder regex never matches).
        self._new()
        play = vpsrun.load_play(self.plays / "shop-1.5-shop-1.5.0.yaml")
        self.assertEqual([s.get("when") for s in play["steps"]], [None, None, None])
        self.assertNotIn(releasenew.STUB_REGEX,
                         (self.plays / "shop-1.5-shop-1.5.0.yaml").read_text())

    def test_a_verb_stop_in_why_is_not_a_stop_step(self):
        # V6: "stop" as a verb ("stop the old worker") is not the STOP label
        # lint's probe rule enforces; only the lint's own words count.
        text = SHOP_POLICY.replace('why: "W3: restart shop-web on the new schema"',
                                   'why: "W3: stop and restart shop-web"')
        (self.policies / "shop-1.5.0.yaml").write_text(text)
        self._new()
        play = vpsrun.load_play(self.plays / "shop-1.5-shop-1.5.0.yaml")
        self.assertNotIn("id", play["steps"][2])

    def test_release_plans_with_exactly_one_phrase(self):
        self._new()
        release = vpsrun.load_release("shop-1.5", release_dir=self.releases,
                                      play_dir=self.plays, policy_dir=self.policies)
        door = _ReadAwareDoor(digests=(tr.H1, tr.H2))
        prompts = []

        def typed(m):
            prompts.append(m)
            return m.split("Type ", 1)[1].split(" ", 1)[0]
        with contextlib.redirect_stdout(io.StringIO()):
            rc = vpsrun.run_release(release, door, typed, tr.TTY(), gate_release=False)
        self.assertEqual(rc, 0)
        # ONE phrase for all 3 planned steps — a release never asks per step.
        self.assertEqual(len(prompts), 1)
        self.assertTrue(prompts[0].startswith("Type RELEASE:shop-1.5:3:"))

    def test_grant_ttl_and_policies_are_set(self):
        self._new()
        release = vpsrun.load_release("shop-1.5", release_dir=self.releases,
                                      play_dir=self.plays, policy_dir=self.policies)
        self.assertEqual(release["grant_ttl"], "12h")
        self.assertEqual(release["policies"], ["shop-1.5.0.yaml"])


# ===========================================================================
# never writes under policies/, never contacts a host, never --run
# ===========================================================================

class NeverTouchesPoliciesOrAHostTest(_Base):
    def test_policies_directory_is_unchanged(self):
        before = sorted(p.name for p in self.policies.iterdir())
        before_bytes = (self.policies / "shop-1.5.0.yaml").read_bytes()
        self._new()
        after = sorted(p.name for p in self.policies.iterdir())
        self.assertEqual(before, after)
        self.assertEqual(before_bytes, (self.policies / "shop-1.5.0.yaml").read_bytes())

    def test_lint_and_preflight_are_never_given_run(self):
        calls = []

        def spy(expect_run_absent):
            def fn(policy_path):
                calls.append(str(policy_path))
                return 0, "ok"
            return fn
        self._new(lint_fn=spy(True), preflight_fn=spy(True))
        self.assertTrue(calls)
        self.assertFalse(any("--run" in c for c in calls))

    def test_default_preflight_never_omits_index_only(self):
        """The production default (never exercised against a real door here)
        always asks for --index-only — the one thing that keeps release new
        from dialling a host (S11)."""
        seen = {}

        def fake_runner(argv):
            seen["argv"] = argv
            return 0, "ok"
        orig = releasenew._default_vpsexec_runner
        releasenew._default_vpsexec_runner = fake_runner
        try:
            releasenew.default_preflight_index_only("policies/x.yaml")
        finally:
            releasenew._default_vpsexec_runner = orig
        self.assertIn("--index-only", seen["argv"])
        self.assertNotIn("--run", seen["argv"])


# ===========================================================================
# overwrite refusal: only --replace, and only over a file this tool wrote
# ===========================================================================

class OverwriteTest(_Base):
    def test_a_second_run_without_replace_refuses(self):
        self._new()
        with self.assertRaises(GatesRefused):
            self._new()

    def test_replace_regenerates_its_own_file(self):
        self._new()
        result = self._new(replace=True)
        self.assertEqual(result["verdict"], "GO")

    def test_replace_refuses_a_hand_edited_body(self):
        """L2/V5: the header pins the sha256 of the body below it, so a hand
        edit under an intact header is never discarded by --replace."""
        self._new()
        play_path = self.plays / "shop-1.5-shop-1.5.0.yaml"
        header = play_path.read_text().splitlines()[0]
        play_path.write_text(header + "\n# a human appended a note below the header\n")
        with self.assertRaises(GatesRefused) as cm:
            self._new(replace=True)
        self.assertIn("edited by hand", str(cm.exception))
        self.assertIn("appended a note", play_path.read_text())

    def test_replace_refuses_an_old_header_without_a_body_hash(self):
        self._new()
        play_path = self.plays / "shop-1.5-shop-1.5.0.yaml"
        text = play_path.read_text()
        first, rest = text.split("\n", 1)
        old = first.replace(" v2 ", " v1 ").split(" body sha256:")[0] + \
            " — do not hand-edit; re-run with --replace after reviewing the diff"
        play_path.write_text(old + "\n" + rest)
        with self.assertRaises(GatesRefused) as cm:
            self._new(replace=True)
        self.assertIn("no body", str(cm.exception))

    def test_a_symlink_at_an_output_path_is_refused(self):
        victim = self.root / "victim.txt"
        victim.write_text("keep\n")
        (self.plays / "shop-1.5-shop-1.5.0.yaml").symlink_to(victim)
        for replace in (False, True):
            with self.assertRaises(GatesRefused) as cm:
                self._new(replace=replace)
            self.assertIn("symlink", str(cm.exception))
        self.assertEqual(victim.read_text(), "keep\n")
        self.assertFalse((self.releases / "shop-1.5.yaml").exists())

    def test_write_refuses_a_symlink_planted_after_the_check(self):
        victim = self.root / "victim.txt"
        victim.write_text("keep\n")
        target = self.plays / "late.yaml"
        target.symlink_to(victim)
        with self.assertRaises(GatesRefused):
            releasenew._write(target, "x\n")
        self.assertEqual(victim.read_text(), "keep\n")

    def test_replace_refuses_a_file_without_the_header_at_all(self):
        """Strip the header a human would have to delete to disguise a hand
        file as generated: without it, --replace refuses."""
        self._new()
        play_path = self.plays / "shop-1.5-shop-1.5.0.yaml"
        body = "\n".join(play_path.read_text().splitlines()[1:])
        play_path.write_text(body)
        with self.assertRaises(GatesRefused) as cm:
            self._new(replace=True)
        self.assertIn("not written by", str(cm.exception))

    def test_replace_refuses_a_file_never_generated_by_this_tool(self):
        (self.plays / "shop-1.5-shop-1.5.0.yaml").write_text("version: 1\nreason: r\n"
                                                             "steps: [{hosts: a, cmd: b, "
                                                             "why: c}]\n")
        with self.assertRaises(GatesRefused):
            self._new(replace=True)

    def test_a_failed_overwrite_check_leaves_no_partial_write(self):
        """The release file would be new, but the play already exists and is
        hand-edited: nothing gets written, not even the release."""
        self._new()
        play_path = self.plays / "shop-1.5-shop-1.5.0.yaml"
        play_path.write_text(play_path.read_text() + "\n# hand-edited\n")
        (self.releases / "shop-1.5.yaml").unlink()
        with self.assertRaises(GatesRefused):
            self._new()
        self.assertFalse((self.releases / "shop-1.5.yaml").exists())


# ===========================================================================
# outside-estate refusal
# ===========================================================================

class OutsideEstateTest(_Base):
    def test_a_path_outside_policies_refuses(self):
        outside = self.root / "shop-1.5.0.yaml"
        outside.write_text(SHOP_POLICY)
        with self.assertRaises(GatesRefused) as cm:
            self._new(from_arg=str(outside))
        self.assertIn("outside policies/", str(cm.exception))

    def test_dot_dot_escape_refuses(self):
        with self.assertRaises(GatesRefused):
            self._new(from_arg="../shop-1.5.0.yaml")

    def test_a_missing_policy_refuses(self):
        with self.assertRaises(GatesRefused):
            self._new(from_arg="does-not-exist.yaml")

    def test_policies_actions_subdir_resolves(self):
        sub = self.policies / "actions"
        sub.mkdir()
        (sub / "ensure.yaml").write_text(SHOP_POLICY)
        path, ref = releasenew.resolve_policy_path("policies/actions/ensure.yaml", self.root)
        self.assertEqual(ref, "actions/ensure.yaml")
        self.assertTrue(path.is_file())


# ===========================================================================
# "lint on save" (D10): `vpsrun release NAME` gates on lint + --index-only
# preflight before planning anything. A stale play (policy edited, play not
# regenerated) is NO-GO, refused before any phrase.
# ===========================================================================

class LintOnSaveGateTest(_Base):
    def _release(self):
        self._new()
        return vpsrun.load_release("shop-1.5", release_dir=self.releases,
                                   play_dir=self.plays, policy_dir=self.policies)

    def _staleness_sensitive_lint(self):
        """Models what a real lint would catch: the play's steps no longer
        match the policy it was generated from. Fails NO-GO on a mismatch,
        exactly like runbookcheck's own play/runbook comparison would."""
        play_path = self.plays / "shop-1.5-shop-1.5.0.yaml"

        def fn(policy_path):
            policy_text = Path(policy_path).read_text()
            play_text = play_path.read_text()
            # The play still names the command it was generated from; stale
            # when the (edited) policy no longer has that command at all.
            stale = "shop-migrate up" in play_text and "shop-migrate up" not in policy_text
            if stale:
                return 2, ("RUNBOOK LINT %s\n  [fail  ] play                   "
                           "shop-1.5-shop-1.5.0.yaml no longer matches this policy's "
                           "runbooks (stale)\nVERDICT: NO-GO (exit 2)" % policy_path)
            return 0, "RUNBOOK LINT %s\n  [pass  ] play                   ok\n" \
                      "VERDICT: GO (exit 0)" % policy_path
        return fn

    def test_go_plans_normally(self):
        release = self._release()
        door = _ReadAwareDoor(digests=(tr.H1, tr.H2))
        typed = lambda m: m.split("Type ", 1)[1].split(" ", 1)[0]  # noqa: E731
        with contextlib.redirect_stdout(io.StringIO()):
            rc = vpsrun.run_release(release, door, typed, tr.TTY(), gate_release=True,
                                    lint_fn=self._staleness_sensitive_lint(),
                                    preflight_fn=_go_fake(0), policy_dir=self.policies)
        self.assertEqual(rc, 0)

    def test_stale_play_is_no_go_before_any_phrase(self):
        release = self._release()
        # Edit the policy's migration step (e.g. a new runner) WITHOUT
        # regenerating the play: the play on disk is now stale.
        (self.policies / "shop-1.5.0.yaml").write_text(
            SHOP_POLICY.replace("shop-migrate up", "shop-migrate2 up"))
        door = _ReadAwareDoor(digests=(tr.H1, tr.H2))

        def no_prompt(msg):
            raise AssertionError("no phrase should ever be asked: %r" % msg)
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(vpsrun.Refused) as cm:
                vpsrun.run_release(release, door, no_prompt, tr.TTY(), gate_release=True,
                                   lint_fn=self._staleness_sensitive_lint(),
                                   preflight_fn=_go_fake(0), policy_dir=self.policies)
        self.assertIn("NO-GO", str(cm.exception))
        self.assertEqual(door.calls, [])

    def test_go_with_warnings_prints_and_continues(self):
        release = self._release()
        door = _ReadAwareDoor(digests=(tr.H1, tr.H2))
        typed = lambda m: m.split("Type ", 1)[1].split(" ", 1)[0]  # noqa: E731
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = vpsrun.run_release(release, door, typed, tr.TTY(), gate_release=True,
                                    lint_fn=_go_fake(1, "assumes"), preflight_fn=_go_fake(0),
                                    policy_dir=self.policies)
        self.assertEqual(rc, 0)
        self.assertIn("GO-WITH-WARNINGS", out.getvalue())

    def test_stale_play_is_no_go_with_the_real_lint_before_any_phrase(self):
        # V3: the REAL runbookcheck.lint, not a model of it.
        release = self._release()
        (self.policies / "shop-1.5.0.yaml").write_text(
            SHOP_POLICY.replace("shop-migrate up", "shop-migrate2 up"))
        door = _ReadAwareDoor(digests=(tr.H1, tr.H2))

        def no_prompt(msg):
            raise AssertionError("no phrase should ever be asked: %r" % msg)
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(vpsrun.Refused) as cm:
                vpsrun.run_release(release, door, no_prompt, tr.TTY(), gate_release=True,
                                   lint_fn=_real_lint(self), preflight_fn=_real_preflight(self),
                                   policy_dir=self.policies)
        self.assertIn("NO-GO", str(cm.exception))
        self.assertIn("matches no runbook step", str(cm.exception))
        self.assertEqual(door.calls, [])

    def test_release_check_is_read_only_and_never_plans(self):
        self._release()
        with contextlib.redirect_stdout(io.StringIO()):
            rc = vpsrun.release_check("shop-1.5", lint_fn=_go_fake(0),
                                      preflight_fn=_go_fake(0), release_dir=self.releases,
                                      play_dir=self.plays, policy_dir=self.policies)
        self.assertEqual(rc, 0)


# ===========================================================================
# the REAL lint and preflight on what `release new` writes (V3-V6, L2)
# ===========================================================================

DUMP_POLICY = """version: 1
expires: "2999-01-01"
reason: "shop 1.5 dump"
shape: {steps: 1, hosts: [edge1], break_glass: false}
runbooks:
  - hosts: [edge1]
    action: pg_dump
    with: {container: shop-db, db: shop, dest_dir: /var/backups/db1, label: rel-1.5}
    why: "B1: dump shop before the release"
"""


class RealLintTest(_Base):
    def real(self, **kw):
        return self._new(lint_fn=_real_lint(self), preflight_fn=_real_preflight(self), **kw)

    def action_policy(self, text=DUMP_POLICY, name="dump.yaml"):
        sub = self.policies / "actions"
        sub.mkdir(exist_ok=True)
        path = sub / name
        path.write_text(text)
        _, _, runbooks, _ = runbookcheck.load_file(path, list(tv.DENY), LINT_TODAY,
                                                   set(tv._policy()["hosts"]))
        from vpscfg import actions
        path.write_text(text + 'expands: "%s"\n' % actions.expands_digest(runbooks))
        return path

    def test_release_new_output_lints_go_with_the_real_lint(self):
        # V6: no injected fake — the real lint and --index-only preflight.
        result = self.real()
        self.assertEqual(result["verdict"], "GO", result["report"])
        self.assertIn("play shop-1.5-shop-1.5.0.yaml", result["report"])

    def test_a_when_stub_is_no_go_until_a_human_resolves_it(self):
        # V5: a stub never silently skips; the real lint refuses it.
        (self.policies / "shop-1.5.0.yaml").write_text(OPTIONAL_POLICY)
        result = self.real()
        self.assertEqual(result["verdict"], "NO-GO", result["report"])
        self.assertIn("placeholder when:", result["report"])

    def test_a_policy_edit_leaves_the_play_stale_and_no_go(self):
        # V3: the unmatched play step is a failure, not ignored.
        self.real()
        (self.policies / "shop-1.5.0.yaml").write_text(
            SHOP_POLICY.replace("shop-migrate up", "shop-migrate2 up"))
        rc, text = _real_lint(self)(self.policies / "shop-1.5.0.yaml")
        self.assertEqual(rc, 2, text)
        self.assertIn("matches no runbook step", text)
        self.assertIn("shop-migrate up", text)

    def test_a_plain_read_play_step_with_no_runbook_is_fine(self):
        self.real()
        self.write_extra_play([{"hosts": "web1", "cmd": "systemctl is-active --quiet "
                                "shop-db-proxy", "why": "STOP: proxy up", "flags":
                                ["--timeout=30"]},
                               {"hosts": "web1", "cmd": "docker ps", "why": "look"}])
        rc, text = _real_lint(self)(self.policies / "shop-1.5.0.yaml")
        self.assertNotIn("matches no runbook step", text)

    def test_a_step_of_another_committed_policy_is_fine(self):
        self.real()
        other = [{"hosts": ["web1"], "cmd": "systemctl restart caddy", "source": "web.yaml"}]
        self.write_extra_play([{"hosts": "web1", "cmd": "systemctl is-active --quiet "
                                "shop-db-proxy", "why": "STOP: proxy up", "flags":
                                ["--timeout=30"]},
                               {"hosts": "web1", "cmd": "systemctl restart caddy",
                                "why": "web.yaml's step"}])
        rc, text = _real_lint(self, policy=dict(tv._yaml_policy(), runbooks=other))(
            self.policies / "shop-1.5.0.yaml")
        self.assertNotIn("matches no runbook step", text)
        rc, text = _real_lint(self)(self.policies / "shop-1.5.0.yaml")
        self.assertIn("matches no runbook step", text, "without it, the step is unknown")

    def write_extra_play(self, steps):
        (self.plays / "extra.yaml").write_text(json.dumps(
            {"version": 1, "reason": "extra", "steps": steps}))

    def test_an_action_play_is_seen_by_lint_with_its_timeout(self):
        # V4: lint matches action steps by their canonical string.
        self.action_policy()
        result = self.real(name="dump-1.5", from_arg="policies/actions/dump.yaml")
        self.assertIn("play dump-1.5-dump.yaml", result["report"])
        self.assertNotIn("no play under", result["report"])
        self.assertIn("hashes and timeouts carried", result["report"])
        play = vpsrun.load_play(self.plays / "dump-1.5-dump.yaml")
        self.assertIn("--timeout=1800", play["steps"][0]["flags"], "the template timeout")

    def test_an_action_play_with_a_changed_with_is_no_go(self):
        path = self.action_policy()
        self.real(name="dump-1.5", from_arg="policies/actions/dump.yaml")
        self.action_policy(DUMP_POLICY.replace("rel-1.5", "rel-1.6"))
        rc, text = _real_lint(self)(path)
        self.assertEqual(rc, 2, text)
        self.assertIn("matches no runbook step", text)

    def test_an_action_policy_release_names_it_by_its_bare_file_name(self):
        # L2: vpsrun's NAME_RE refuses "actions/dump.yaml"; the bare name is
        # resolved under policies/actions/ by vpsrun itself.
        self.action_policy()
        self.real(name="dump-1.5", from_arg="policies/actions/dump.yaml")
        release = vpsrun.load_release("dump-1.5", release_dir=self.releases,
                                      play_dir=self.plays, policy_dir=self.policies)
        self.assertEqual(release["policies"], ["dump.yaml"])
        paths = vpsrun._release_policy_paths(release, policy_dir=self.policies)
        self.assertEqual(paths, [self.policies / "actions" / "dump.yaml"])

    def test_every_generated_scalar_is_quoted(self):
        # L2: names and values are JSON-quoted YAML scalars, never bare words
        # YAML could read as another type (a ttl, an id, a play name).
        self._new()
        text = (self.releases / "shop-1.5.yaml").read_text()
        self.assertIn('grant_ttl: "12h"', text)
        self.assertIn('  - "shop-1.5-shop-1.5.0"', text)
        self.assertIn('  - runbook: "shop-1.5.0.yaml"', text)
        self.assertIn('id: "s1"', (self.plays / "shop-1.5-shop-1.5.0.yaml").read_text())

    def test_a_pg_dump_without_min_free_gb_is_sized_from_a_fresh_index(self):
        self.action_policy()
        idx = self.root / "index"
        idx.mkdir()
        doc = {"host": "edge1", "index_version": 1,
               "collected_at": LINT_NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "sections": {"postgres": {"instances": [{"container": "shop-db",
                                                        "databases": [{"name": "shop",
                                                                       "size_bytes": 5 << 30}]}]}}}
        (idx / "edge1.json").write_text(json.dumps(doc))
        os.chmod(idx / "edge1.json", 0o600)
        result = self._new(name="dump-1.5", from_arg="policies/actions/dump.yaml",
                           index_dir=idx, now=LINT_NOW.replace(tzinfo=datetime.timezone.utc))
        self.assertEqual(len(result["advice"]), 1, result["advice"])
        self.assertIn("min_free_gb: 6", result["advice"][0])  # ceil(5 GiB x 1.2)
        self.assertIn("ADVICE", result["report"])
        # never written into the play: the play's with: must equal the policy's
        self.assertNotIn("min_free_gb", (self.plays / "dump-1.5-dump.yaml").read_text())

    def test_no_index_means_the_dump_cannot_be_sized(self):
        self.action_policy()
        result = self._new(name="dump-1.5", from_arg="policies/actions/dump.yaml",
                           index_dir=self.root / "no-index")
        self.assertIn("cannot size", result["advice"][0])


# ===========================================================================
# S12: every file this builder touched carries no estate data (fictional
# names only — web1/edge1/db1, shop, alice, example.com/.internal, RFC 5737)
# ===========================================================================

class PublicHygieneTest(unittest.TestCase):
    FILES = [REPO / "vpsrun", REPO / "vpscfg" / "releasenew.py",
             REPO / "plays" / "README.md", REPO / "tests" / "test_release_new.py",
             REPO / "tests" / "test_vpsrun_actions.py"]

    def test_exporter_scan_finds_nothing(self):
        spec = importlib.util.spec_from_file_location(
            "export_public", REPO / "tools" / "export-public.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for path in self.FILES:
            hits = mod.scan_text(str(path.relative_to(REPO)), path.read_text(), [])
            self.assertEqual(hits, [], path)


if __name__ == "__main__":
    unittest.main()
