"""V7a: the phase-2 success criterion end to end, with the REAL pieces:

    an action policy (policies/actions/) -> `release new` (real lint, real
    --index-only preflight) -> `vpsrun release` through the REAL door
    (vpsexec.dispatch) on the hermetic host (local bash, temp op/lock dirs)
    with ONE phrase -> a second run reports `[done]` and runs no body.

The action is ensure_secret on a temp `.env` (fictional values): its check is
the pinned token-only script, its body really rotates the key. Nothing dials
a host, nothing reads ~/.vpscfg; the journal is redirected by the harness.
"""
import contextlib
import io
import os
import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_release_new as trn  # noqa: E402
import test_token_check as ttc  # noqa: E402
import test_vpsexec as tv  # noqa: E402
import test_vpsrun as tr  # noqa: E402
from vpscfg import releasenew, runbookcheck, vpsexec  # noqa: E402

vpsrun = tr.vpsrun
HOST = ttc.HOST
SS, JWT = "SESSION_SECRET", "JWT_SECRET"
SEED = "c0ffee" * 9  # 54 hex chars, fictional


class ReleaseEndToEndTest(ttc._Door):
    def setUp(self):
        super().setUp()
        self.estate = self.pdir.parent
        self.plays = self.estate / "plays"
        self.releases = self.estate / "releases"
        self.env = self.work / ".env"
        self.env.write_text("APP=shop\n%s=%s\n%s=%s\n" % (SS, SEED, JWT, SEED))
        os.chmod(self.env, 0o600)
        text = textwrap.dedent("""\
            version: 1
            expires: "2026-12-31"
            reason: rotate the shop session secret (release e2e)
            shape: {steps: 1, hosts: [%s], break_glass: false}
            runbooks:
              - hosts: [%s]
                action: ensure_secret
                with: {file: %s, key: SESSION_SECRET, distinct_from: [JWT_SECRET]}
                why: "S1: SESSION_SECRET must differ from JWT_SECRET"
            """ % (HOST, HOST, self.env))
        self.policy_path = self.armed(text, name="secret.yaml")

    def door(self, outputs):
        def run(argv):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                try:
                    rc = vpsexec.dispatch(
                        argv, guard=tv._guard(self.gov()), policy=self.load(),
                        prober=self.prober(), ssh=self.ssh, stream=tv.ApprovalTest._TTY(),
                        prompt=lambda m: self.fail("the door asked its own phrase: %r" % m),
                        today=ttc.TODAY,
                        blackout_runner=self.blackout_runner(unavailable=True))
                except vpsexec.Refused as r:
                    print("REFUSED: %s" % r)
                    rc = 2
            outputs.append(out.getvalue())
            return rc, out.getvalue()
        return run

    def lint(self, policy_path):
        rep = runbookcheck.lint(policy_path, tv._guard(self.gov()), self.load(),
                                plays_dir=self.plays, releases_dir=self.releases,
                                today=ttc.TODAY, now=trn.LINT_NOW)
        return rep["exit_code"], runbookcheck.render(rep)

    def preflight(self, policy_path):
        def never(*a, **k):
            raise AssertionError("--index-only dialled a host")
        rep = runbookcheck.preflight(policy_path, tv._guard(self.gov()), self.load(),
                                     ssh=never, today=ttc.TODAY, index_only=True,
                                     index_dir=self.estate / "index")
        return rep["exit_code"], runbookcheck.render(rep)

    def release(self, outputs):
        release = vpsrun.load_release("rotate", release_dir=self.releases,
                                      play_dir=self.plays, policy_dir=self.pdir)
        prompts = []

        def typed(m):
            prompts.append(m)
            return m.split("Type ", 1)[1].split(" ", 1)[0]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsrun.run_release(release, self.door(outputs), typed, tr.TTY(),
                                    gate_release=True, lint_fn=self.lint,
                                    preflight_fn=self.preflight, policy_dir=self.pdir)
        return rc, out.getvalue(), prompts

    def test_policy_to_release_new_to_one_phrase_then_done(self):
        result = releasenew.new("rotate", "policies/actions/secret.yaml",
                                estate_root=self.estate, plays_dir=self.plays,
                                releases_dir=self.releases, lint_fn=self.lint,
                                preflight_fn=self.preflight)
        self.assertLessEqual(result["exit_code"], 1, result["report"])
        self.assertIn("play rotate-secret.yaml", result["report"])

        outputs = []
        rc, out, prompts = self.release(outputs)
        self.assertEqual(rc, 0, out + "\n".join(outputs))
        self.assertEqual(len(prompts), 1, "one phrase for the whole release")
        self.assertTrue(prompts[0].startswith("Type RELEASE:rotate:1:"), prompts[0])
        self.assertTrue(any("rotated SESSION_SECRET (48 chars)" in o for o in outputs),
                        "\n".join(outputs))
        new = dict(l.split("=", 1) for l in self.env.read_text().splitlines())[SS]
        self.assertRegex(new, r"^[0-9a-f]{48}$")

        # The second release comes later than the door's unattended-repeat
        # window (a re-fired identical mutation inside it is refused before
        # anything, check included): model the time passing.
        saved, vpsexec.REPEAT_WINDOW_SECONDS = vpsexec.REPEAT_WINDOW_SECONDS, 0
        self.addCleanup(setattr, vpsexec, "REPEAT_WINDOW_SECONDS", saved)
        outputs2 = []
        rc, out, prompts = self.release(outputs2)
        self.assertEqual(rc, 0, out + "\n".join(outputs2))
        self.assertTrue(any("[done] %s" % HOST in o for o in outputs2), "\n".join(outputs2))
        steps = [e for e in self.events() if e.get("event") == "step"]
        self.assertEqual(len(steps), 1, "the second release ran no body")
        self.assertEqual(dict(l.split("=", 1) for l in self.env.read_text().splitlines())[SS],
                         new, "the second release changed nothing")
        # nothing secret anywhere the door or vpsrun wrote or printed
        self.hunt([out] + outputs + outputs2, SEED, new, keep={self.env})


if __name__ == "__main__":
    unittest.main()
