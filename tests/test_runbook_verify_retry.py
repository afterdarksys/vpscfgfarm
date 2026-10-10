"""`verify_retry: {tries, interval}` — let a service settle before its verify fails.

Strict at load (exact sub-keys, bounded ints, total wait capped), still a
read at run time, every attempt journaled, and the sleep injected so nothing
here really waits.
"""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
from vpscfg import probe, vpsexec, vpsexeclog, vpsexecpolicy  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

GOV = {"edge1", "web1", "web2", "web3", "dns1", "dns2"}

FILE = """version: 1
reason: "retry tests"
expires: "2999-01-01"
shape: {steps: 1, hosts: [edge1], break_glass: false}
runbooks:
  - hosts: [edge1]
    cmd: "systemctl restart nginx"
    verify: "systemctl is-active nginx"
    why: "restart"
%s"""


def _load(extra):
    d = tempfile.mkdtemp()
    Path(d, "rb.yaml").write_text(FILE % extra)
    return vpsexecpolicy.load(d, deny_patterns=tv.DENY, today="2026-10-09",
                              governor_hosts=GOV, host_re=probe.HOST_RE)


@unittest.skipUnless(vpsexecpolicy._HAVE_YAML, "PyYAML unavailable")
class VerifyRetryLoadTest(unittest.TestCase):

    def test_valid_retry_loads(self):
        rb = _load("    verify_retry: {tries: 5, interval: 2}\n")["runbooks"][0]
        self.assertEqual(rb["verify_retry"], {"tries": 5, "interval": 2})

    def test_absent_means_none(self):
        self.assertIsNone(_load("")["runbooks"][0]["verify_retry"])

    def test_the_cap_is_inclusive(self):
        rb = _load("    verify_retry: {tries: 10, interval: 60}\n")["runbooks"][0]
        self.assertEqual(rb["verify_retry"], {"tries": 10, "interval": 60})

    def test_bad_shapes_refuse(self):
        bad = {
            "not a mapping": "    verify_retry: 5\n",
            "list": "    verify_retry: [5, 2]\n",
            "unknown sub-key": "    verify_retry: {tries: 5, interval: 2, backoff: 2}\n",
            "missing interval": "    verify_retry: {tries: 5}\n",
            "missing tries": "    verify_retry: {interval: 5}\n",
            "zero tries": "    verify_retry: {tries: 0, interval: 2}\n",
            "too many tries": "    verify_retry: {tries: 31, interval: 1}\n",
            "zero interval": "    verify_retry: {tries: 3, interval: 0}\n",
            "interval too long": "    verify_retry: {tries: 2, interval: 61}\n",
            "bool tries": "    verify_retry: {tries: true, interval: 2}\n",
            "string tries": "    verify_retry: {tries: '3', interval: 2}\n",
            "float interval": "    verify_retry: {tries: 3, interval: 1.5}\n",
            "negative": "    verify_retry: {tries: -3, interval: 2}\n",
            "total over 600": "    verify_retry: {tries: 30, interval: 21}\n",
            "misspelled key": "    verify_retries: {tries: 3, interval: 2}\n",
        }
        for name, extra in bad.items():
            with self.assertRaises(Refused, msg=name):
                _load(extra)

    def test_retry_without_verify_refuses(self):
        d = tempfile.mkdtemp()
        Path(d, "rb.yaml").write_text(
            (FILE % "    verify_retry: {tries: 3, interval: 2}\n")
            .replace('    verify: "systemctl is-active nginx"\n', ""))
        with self.assertRaises(Refused) as cm:
            vpsexecpolicy.load(d, deny_patterns=tv.DENY, governor_hosts=GOV)
        self.assertIn("without a verify", str(cm.exception))

    def test_override_file_may_not_carry_it(self):
        body = tv.OverrideFileTest.GOOD + \
            '    verify: "systemctl is-active x"\n    verify_retry: {tries: 3, interval: 2}\n'
        with self.assertRaises(Refused) as cm:
            vpsexec.load_override(tv._write(body), tv.DENY, today="2026-08-27")
        self.assertIn("verify_retry", str(cm.exception))


def _rb(verify="systemctl is-active nginx", retry=None):
    rb = tv._runbook(["edge1", "web3"], "systemctl restart nginx")
    rb["verify"] = verify
    rb["verify_retry"] = retry
    return [rb]


class VerifyRetryRunTest(tv._FleetHarness):

    def setUp(self):
        super().setUp()
        self.slept = []
        patcher = mock.patch.object(vpsexec, "_verify_sleep", self.slept.append)
        patcher.start()
        self.addCleanup(patcher.stop)

    def ssh_failing(self, failures):
        """The verify fails `failures` times per host, then passes."""
        seen = {}

        def ssh(host, cmd, timeout=None, connect_timeout=None):
            self.ssh_calls.append((host, cmd))
            if "vpscfg.lock" in cmd:
                return 0, "", ""
            if "is-active" in cmd:
                seen[host] = seen.get(host, 0) + 1
                return (3, "", "activating") if seen[host] <= failures else (0, "active", "")
            return 0, "ok", ""
        return ssh

    def go(self, retry, failures, extra=(), verify="systemctl is-active nginx"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = self.run_fleet(["edge1", "systemctl restart nginx", "--run", "--reason", "x"]
                                + list(extra), runbooks=_rb(verify, retry),
                                prompt=lambda m: "edge1", ssh=self.ssh_failing(failures))
        return rc, out.getvalue()

    def verifies(self):
        return [e for e in self.events() if e["event"] == "verify"]

    def test_passes_on_the_first_success(self):
        rc, _ = self.go({"tries": 5, "interval": 7}, failures=2)
        self.assertEqual(rc, 0)
        self.assertEqual(self.cmds("edge1").count("systemctl is-active nginx"), 3)
        self.assertEqual(self.slept, [7, 7])
        self.assertEqual([(e["attempt"], e["tries"], e["rc"]) for e in self.verifies()],
                         [(1, 5, 3), (2, 5, 3), (3, 5, 0)])

    def test_fails_after_the_last_try_without_a_trailing_sleep(self):
        rc, out = self.go({"tries": 3, "interval": 4}, failures=99)
        self.assertEqual(rc, 1)
        self.assertEqual(self.cmds("edge1").count("systemctl is-active nginx"), 3)
        self.assertEqual(self.slept, [4, 4])
        self.assertIn("verify FAILED", out)
        done = [e for e in self.events() if e["event"] == "mutation_complete"][0]
        self.assertEqual(done["failed"], ["edge1"])

    def test_first_try_success_never_sleeps(self):
        rc, _ = self.go({"tries": 3, "interval": 4}, failures=0)
        self.assertEqual(rc, 0)
        self.assertEqual(self.slept, [])
        self.assertEqual(len(self.verifies()), 1)

    def test_default_is_a_single_try(self):
        rc, _ = self.go(None, failures=1)
        self.assertEqual(rc, 1)
        self.assertEqual(self.cmds("edge1").count("systemctl is-active nginx"), 1)
        self.assertEqual(self.slept, [])
        self.assertNotIn("attempt", self.verifies()[0])

    def test_explicit_verify_flag_runs_once(self):
        """--verify replaces the runbook's verify, and with it the retry."""
        rc, _ = self.go({"tries": 5, "interval": 2}, failures=1,
                        extra=["--verify", "systemctl is-active nginx"])
        self.assertEqual(rc, 1)
        self.assertEqual(self.slept, [])

    def test_retried_verify_must_still_be_a_read(self):
        with self.assertRaises(Refused) as cm:
            self.go({"tries": 5, "interval": 2}, failures=0, verify="touch /tmp/ready")
        self.assertIn("must be unable to change anything", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_plan_shows_it_and_it_is_in_the_plan_hash(self):
        _, out = self.go({"tries": 5, "interval": 2}, failures=0)
        self.assertIn("verify  : systemctl is-active nginx (up to 5 tries, 2s apart)", out)
        with_retry = vpsexec.build_plan(["edge1"], "systemctl restart nginx", {}, "risky",
                                        None, verify={"edge1": "v"},
                                        verify_retry={"edge1": (5, 2)})
        without = vpsexec.build_plan(["edge1"], "systemctl restart nginx", {}, "risky",
                                     None, verify={"edge1": "v"})
        self.assertNotEqual(vpsexec.plan_hash(with_retry), vpsexec.plan_hash(without))

    def test_plans_without_a_retry_keep_their_old_hash(self):
        plan = vpsexec.build_plan(["edge1"], "systemctl restart nginx", {}, "risky",
                                  None, verify={"edge1": "v"})
        old = dict(plan, per_host=dict(
            (h, dict((k, v) for k, v in rec.items() if k != "verify_retry"))
            for h, rec in plan["per_host"].items()))
        self.assertEqual(vpsexec.plan_hash(plan), vpsexec.plan_hash(old))

    def test_last_shows_each_attempt(self):
        self.go({"tries": 3, "interval": 1}, failures=1)
        text = vpsexeclog.render_runs(vpsexeclog.runs(vpsexeclog.read()))
        self.assertIn("[verify 1/3] edge1 rc=3", text)
        self.assertIn("[verify 2/3] edge1 rc=0", text)

    def test_runbooks_listing_shows_it(self):
        text = vpsexec._render_runbooks(tv._yaml_policy(runbooks=_rb(retry={"tries": 4,
                                                                           "interval": 3})))
        self.assertIn("(up to 4 tries, 3s apart)", text)


if __name__ == "__main__":
    unittest.main()


class VerifyRetryBudgetTest(tv._FleetHarness):
    """L2: the WHOLE retry is bounded (attempts included), on a monotonic clock."""

    def setUp(self):
        super().setUp()
        self.now = [1000.0]
        self.slept, self.timeouts = [], []

        def sleep(seconds):
            self.slept.append(seconds)
            self.now[0] += seconds
        for name, fake in (("_verify_sleep", sleep), ("_verify_clock", lambda: self.now[0])):
            p = mock.patch.object(vpsexec, name, fake)
            p.start()
            self.addCleanup(p.stop)

    def slow_failing_ssh(self, attempt_cost):
        def ssh(host, cmd, timeout=None, connect_timeout=None):
            self.ssh_calls.append((host, cmd))
            if "vpscfg.lock" in cmd:
                return 0, "", ""
            if "is-active" in cmd:
                self.timeouts.append(timeout)
                self.now[0] += min(attempt_cost, timeout)
                return 3, "", "activating"
            return 0, "ok", ""
        return ssh

    def go(self, retry, attempt_cost, extra=()):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = self.run_fleet(["edge1", "systemctl restart nginx", "--run", "--reason", "x",
                                 "--timeout", "300"] + list(extra),
                                runbooks=_rb(retry=retry), prompt=lambda m: "edge1",
                                ssh=self.slow_failing_ssh(attempt_cost))
        return rc, out.getvalue()

    def test_each_retried_attempt_is_capped(self):
        self.go({"tries": 3, "interval": 1}, attempt_cost=1)
        self.assertEqual(self.timeouts, [vpsexec.VERIFY_ATTEMPT_TIMEOUT_MAX] * 3)

    def test_slow_attempts_cannot_push_past_the_total_budget(self):
        """30 tries x 20 s sleeps is within the 600 s sleep cap, but with every
        attempt taking its full 60 s the deadline, not the try count, stops it."""
        start = self.now[0]
        rc, out = self.go({"tries": 30, "interval": 20}, attempt_cost=999)
        self.assertEqual(rc, 1)
        self.assertLessEqual(self.now[0] - start, vpsexecpolicy.VERIFY_RETRY_TOTAL_MAX)
        self.assertLess(len(self.timeouts), 30)
        self.assertIn("retry budget of 600s spent", out)
        self.assertTrue(all(1 <= t <= vpsexec.VERIFY_ATTEMPT_TIMEOUT_MAX
                            for t in self.timeouts))

    def test_single_try_keeps_the_per_host_timeout(self):
        self.go(None, attempt_cost=1)
        self.assertEqual(self.timeouts, [300])
