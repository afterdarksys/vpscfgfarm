"""V7c: grants over action policies (plan "Grants", adversarial item 7).

  - a short grant covers a break-glass action step by its canonical string;
  - a reusable grant survives a reviewed, PUSHED `with:` edit (it re-reads
    the pushed file and re-expands), where the short grant dies;
  - a version bump of the action changes the canonical string, so the short
    grant stops covering the step (and `expands:` disarms the file) until it
    is re-reviewed.

Hermetic like test_grant_kinds: the grants dir, key and a real policy git
repo with a local bare origin live in a temp home; ssh is faked; nothing
reaches a host or ~/.vpscfg. Fictional names only (web1, shop).
"""
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_grant_kinds as tgk  # noqa: E402
import test_vpsexec as tv  # noqa: E402
import test_vpsexec_grant as tg  # noqa: E402
from vpscfg import actions, runbookcheck, vpsexec, vpsexecpolicy  # noqa: E402
from vpscfg.actions import base  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

WITH = {"image_ref": "shop/web:1.5", "new_tag": "shop/web:rollback"}
ACTION_POLICY = """version: 1
reason: "action grant tests"
expires: "2999-01-01"
shape: {steps: 1, hosts: [web1], break_glass: true}
runbooks:
  - hosts: [web1]
    action: tag_image
    with: %s
    break_glass: true
    why: "T1: tag the rollback image"
"""


class _ActionGrantHarness(tgk._KindsHarness):

    def setUp(self):
        super().setUp()
        self.with_ = dict(WITH)
        self.write_action_policy()

    def write_action_policy(self, with_=None):
        self.with_ = dict(with_ or self.with_)
        d = self.policy_dir / vpsexecpolicy.ACTIONS_SUBDIR
        d.mkdir(exist_ok=True)
        path = d / "act.yaml"
        text = ACTION_POLICY % json.dumps(self.with_, sort_keys=True)
        path.write_text(text)
        _, _, runbooks, _ = runbookcheck.load_file(path, tv.DENY, None,
                                                   set(tv._policy()["hosts"]))
        path.write_text(text + 'expands: "%s"\n' % actions.expands_digest(runbooks))
        self.commit("action policy")
        self.reload_policy()

    def action_ssh(self):
        def _ssh(host, cmd, timeout=None, connect_timeout=None, data=None):
            with self._lock:
                self.ssh_calls.append((host, cmd))
            if "vpscfg.lock" in cmd:
                return 0, "", ""
            if "VPSCFG-DONE" in cmd:
                return 0, "VPSCFG-NEEDED\n", ""
            return 0, "ok", ""
        return _ssh

    def act(self, contract, with_=None):
        argv = ["web1", "--action", "tag_image", "--with",
                json.dumps(with_ or self.with_), "--break-glass", "--run", "--reason",
                "OPS-1", "--approval-contract=%s" % contract]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexec.dispatch(
                argv, guard=tv._guard(), prober=self.prober(), policy=self.policy,
                ssh=self.action_ssh(), stream=tg._TTY(), prompt=tg._no_prompt,
                blackout_runner=self.blackout_runner(unavailable=True))
        return rc, out.getvalue()

    def tagged(self):
        return [c for _, c in self.ssh_calls if c.startswith("docker image tag ")]

    def mint_action(self, kind="short"):
        if kind == "short":
            return self.mint(name="act")
        return self.mint_reusable(name="act")


class ActionGrantTest(_ActionGrantHarness):

    def test_a_short_grant_covers_the_break_glass_action_step(self):
        path = self.mint_action()
        rc, out = self.act(path)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.tagged()), 1)
        used = [e for e in self.events() if e["event"] == "grant_used"]
        self.assertTrue(used)

    def test_a_short_grant_does_not_cover_another_with(self):
        path = self.mint_action()
        other = dict(self.with_, new_tag="shop/web:other")
        with self.assertRaises(Refused):
            self.act(path, with_=other)
        self.assertEqual(self.tagged(), [])

    def test_a_reusable_grant_survives_a_pushed_with_edit_that_kills_a_short_one(self):
        short = self.mint_action("short")
        reusable = self.mint_action("reusable")
        edited = dict(self.with_, new_tag="shop/web:rollback-2")
        self.write_action_policy(edited)  # reviewed, committed AND pushed
        with self.assertRaises(Refused) as cm:
            self.act(short)
        self.assertIn("changed since this grant was minted", str(cm.exception))
        self.assertEqual(self.tagged(), [])
        rc, out = self.act(reusable)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.tagged()), 1)
        self.assertIn("shop/web:rollback-2", self.tagged()[0])

    def test_an_unpushed_with_edit_is_not_covered_by_the_reusable_grant(self):
        reusable = self.mint_action("reusable")
        d = self.policy_dir / vpsexecpolicy.ACTIONS_SUBDIR
        text = (d / "act.yaml").read_text().replace("shop/web:rollback",
                                                    "shop/web:sneaky")
        (d / "act.yaml").write_text(text)
        self.commit("local only", push=False)
        self.reload_policy()
        with self.assertRaises(Refused):
            self.act(reusable, with_=dict(self.with_, new_tag="shop/web:sneaky"))
        self.assertEqual(self.tagged(), [])

    def test_a_version_bump_stops_a_short_grant_covering_the_step(self):
        # Adversarial item 7: a template version bump changes the canonical
        # string (tag_image@1 -> @2), so the grant minted for @1 covers
        # nothing, and the file's expands: no longer matches (DISARMED).
        path = self.mint_action()
        action = base.REGISTRY["tag_image"]
        saved = type(action).version
        type(action).version = saved + 1
        self.addCleanup(setattr, type(action), "version", saved)
        self.reload_policy()
        self.assertTrue(self.policy.get("misshapen"), "expands: disarmed the file")
        with self.assertRaises(Refused):
            self.act(path)
        self.assertEqual(self.tagged(), [])


if __name__ == "__main__":
    unittest.main()
