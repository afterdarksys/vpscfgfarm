"""An approval contract on a listed step whose hosts need no elevation.

Before: refused ("this plan elevates no host"), so a break_glass step whose
hosts were all test/released broke a grant-driven walk. Now the contract
stands in for that step's ordinary typed phrase; the plan stays a normal,
non-break-glass mutation, every gate still runs, and the use is journaled.

The negative tests are the point: the contract is never accepted for a step,
host or command it does not list, and no other gate is skipped.
"""
import contextlib
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
import test_vpsexec_grant as tg  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402
from vpscfg import vpsexec  # noqa: E402


def _released(**extra):
    """web1 and web2 no longer need elevation."""
    gov = tv._policy()
    gov["hosts"]["web1"] = {"posture": "test"}
    gov["hosts"]["web2"] = {"posture": "released"}
    gov.update(extra)
    return gov


class GrantWithoutElevationTest(tg._GrantHarness):

    def test_listed_step_runs_as_a_normal_mutation(self):
        path = self.mint()
        g = self.load(path)
        rc = self.use("web1", "systemctl restart nginx", path, gov=_released())
        self.assertEqual(rc, 0)
        self.assertEqual([h for h, _ in self.ran()], ["web1"])
        events = self.events()
        used = [e for e in events if e["event"] == "grant_used"]
        self.assertEqual(len(used), 1)
        self.assertEqual((used[0]["session_id"], used[0]["step"], used[0]["elevated"]),
                         (g["session_id"], 1, False))
        attempt = [e for e in events if e["event"] == "mutation_attempt"][0]
        self.assertIs(attempt["break_glass"], False)
        self.assertEqual(attempt["approval"], "approval-contract:%s" % g["session_id"])
        self.assertFalse([e for e in events if e["event"] == "break_glass"],
                         "nothing was elevated, so nothing is journaled as break-glass")

    def test_elevated_use_is_journaled_as_elevated(self):
        path = self.mint()
        self.assertEqual(self.use("web1", "systemctl restart nginx", path), 0)
        used = [e for e in self.events() if e["event"] == "grant_used"][0]
        self.assertIs(used["elevated"], True)

    def test_plan_hash_is_the_ordinary_non_break_glass_one(self):
        path = self.mint()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexec.dispatch(["web1", "systemctl restart nginx", "--reason", "x"],
                             guard=tv._guard(_released()), prober=self.prober(),
                             policy=self.policy, ssh=self.fake_ssh(), stream=tg._TTY(),
                             prompt=tg._no_prompt,
                             blackout_runner=self.blackout_runner(unavailable=True))
        digest = [l.split()[-1] for l in out.getvalue().splitlines()
                  if l.startswith("plan-hash:")][0]
        self.use("web1", "systemctl restart nginx", path, gov=_released())
        attempt = [e for e in self.events() if e["event"] == "mutation_attempt"][0]
        self.assertEqual(attempt["plan_hash"], digest)

    # --- never for something the contract does not list --------------------

    def test_unlisted_step_refuses(self):
        """Step 4 (reload) is authorised by the runbook but not break_glass, so
        no grant lists it: the contract must not approve it."""
        path = self.mint()
        with self.assertRaises(Refused) as cm:
            self.use("web1", "systemctl reload nginx", path, gov=_released())
        self.assertIn("does not authorise this plan", str(cm.exception))
        self.assertIn("Drop --approval-contract", str(cm.exception))
        self.assertEqual(self.ran(), [])
        self.assertTrue([e for e in self.events() if e["event"] == "grant_refused"])
        self.assertFalse([e for e in self.events() if e["event"] == "grant_used"])

    def test_excluded_rollback_step_refuses(self):
        path = self.mint()
        with self.assertRaises(Refused):
            self.use("web1", "systemctl stop nginx", path, gov=_released())
        self.assertEqual(self.ran(), [])

    def test_step_not_selected_at_mint_refuses(self):
        path = self.mint("--steps", "2")
        with self.assertRaises(Refused):
            self.use("web1", "systemctl restart nginx", path, gov=_released())
        self.assertEqual(self.ran(), [])

    def test_host_outside_the_contract_refuses(self):
        path = self.mint("--hosts", "web1")
        with self.assertRaises(Refused) as cm:
            self.use("web2", "systemctl restart caddy", path, gov=_released())
        self.assertIn("does not cover host", str(cm.exception))
        self.assertEqual(self.ran(), [])

    def test_contract_for_another_runbook_refuses(self):
        path = self.mint()
        (self.policy_dir / "other.yaml").write_text(
            tg.RUNBOOK.replace("systemctl restart nginx", "systemctl restart redis")
            % "2999-01-01")
        self.write_runbook()  # reload both files
        self.assertIn("systemctl restart redis", [r["cmd"] for r in self.policy["runbooks"]])
        with self.assertRaises(Refused):
            self.use("web1", "systemctl restart redis", path, gov=_released())
        self.assertEqual(self.ran(), [])

    def test_invalid_contract_refuses_and_never_prompts(self):
        path = self.mint()
        g = self.load(path)
        g["hosts"].append("edge1")  # edited without the key: MAC fails
        Path(path).write_text(__import__("json").dumps(g))
        with self.assertRaises(Refused) as cm:
            self.use("web1", "systemctl restart nginx", path, gov=_released())
        self.assertIn("MAC", str(cm.exception))
        self.assertEqual(self.ran(), [])

    # --- never skips any other gate ------------------------------------------

    def test_no_tty_refuses(self):
        path = self.mint()
        with self.assertRaises(Refused):
            self.use("web1", "systemctl restart nginx", path, gov=_released(),
                     stream=tg._NoTTY())
        self.assertEqual(self.ran(), [])

    def test_master_switch_and_lockdown_mode_still_refuse(self):
        path = self.mint()
        for gov in (_released(mutation_enabled=False), _released(mode="lockdown")):
            with self.assertRaises(Refused):
                self.use("web1", "systemctl restart nginx", path, gov=gov)
        self.assertEqual(self.ran(), [])

    def test_reason_is_still_required(self):
        path = self.mint()
        with self.assertRaises(Refused) as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(
                    ["web1", "systemctl restart nginx", "--run",
                     "--approval-contract=%s" % path],
                    guard=tv._guard(_released()), prober=self.prober(),
                    policy=self.policy, ssh=self.fake_ssh(), stream=tg._TTY(),
                    prompt=tg._no_prompt,
                    blackout_runner=self.blackout_runner(unavailable=True))
        self.assertIn("--reason", str(cm.exception))
        self.assertEqual(self.ran(), [])

    def test_risky_command_on_a_host_no_runbook_names_still_refuses(self):
        """edge1 is test and the contract lists the command, but no runbook
        entry names edge1: the risky gate refuses before the contract is read."""
        path = self.mint()
        with self.assertRaises(Refused) as cm:
            self.use("edge1", "systemctl restart nginx", path, gov=_released())
        self.assertIn("not authorised", str(cm.exception))
        self.assertEqual(self.ran(), [])

    def test_approve_and_contract_together_still_refuse_without_elevation(self):
        path = self.mint()
        with self.assertRaises(Refused) as cm:
            self.use("web1", "systemctl restart nginx", path, gov=_released(),
                     extra=["--approve=" + "0" * 64])
        self.assertIn("two approvals", str(cm.exception))
        self.assertEqual(self.ran(), [])


if __name__ == "__main__":
    unittest.main()
