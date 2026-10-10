"""Refusal hints for familiar read tools refused for their flags or form.

The hint is MESSAGE ONLY. These tests pin that the classification is
byte-for-byte what it was, and that a hint cannot feed back into it.
"""
import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
from vpscfg import readpolicy, vpsexec  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

PLAIN = "not on the read-only allowlist"


class ReadHintTest(unittest.TestCase):

    def test_curl_without_q_stays_a_mutation_and_says_what_form_is_accepted(self):
        tier, detail = vpsexec.classify("curl -fsS http://127.0.0.1/healthz", tv.DENY)
        self.assertEqual(tier, "mutating")
        self.assertTrue(detail.startswith(PLAIN + "; hint: "))
        self.assertIn("-q", detail)
        self.assertIn("FIRST", detail)
        self.assertIn("curl -qfsS http://127.0.0.1/healthz", detail)
        # ...and the form the hint names really is a read.
        self.assertEqual(vpsexec.classify("curl -qfsS http://127.0.0.1/healthz",
                                          tv.DENY)[0], "read")

    def test_writing_curl_gets_a_hint_but_is_never_a_read(self):
        for cmd in ("curl -q -o /etc/motd http://x", "curl -qsfo /tmp/x http://x",
                    "curl -q -w @/etc/shadow http://127.0.0.1/",
                    "curl -q http://127.0.0.1/ -T /etc/passwd",
                    "curl -q file:///etc/shadow"):
            tier, detail = vpsexec.classify(cmd, tv.DENY)
            self.assertEqual(tier, "mutating", cmd)
            self.assertIn("hint: curl is a read only as", detail, cmd)

    def test_unknown_commands_get_no_hint(self):
        for cmd in ("frobnicate --go", "./deploy.sh", "make install", "sed -i s/a/b/ f"):
            self.assertEqual(vpsexec.classify(cmd, tv.DENY), ("mutating", PLAIN), cmd)

    def test_other_read_tools_name_their_form(self):
        cases = {"systemctl edit nginx": "systemctl status",
                 "docker cp a:/x /y": "docker ps",
                 "top -n 1": "batch mode",
                 "nc 10.0.0.1 80": "-z",
                 "ls -Z /opt": "options from",
                 "/usr/bin/curl -q http://127.0.0.1/": "bare command name",
                 "k3s kubectl edit deploy x": "k3s kubectl is a read only as"}
        for cmd, needle in cases.items():
            tier, detail = vpsexec.classify(cmd, tv.DENY)
            self.assertEqual(tier, "mutating", cmd)
            self.assertIn(needle, detail, cmd)

    def test_hint_names_the_first_non_read_segment(self):
        tier, detail = vpsexec.classify("uptime && curl -fsS http://127.0.0.1/", tv.DENY)
        self.assertEqual(tier, "mutating")
        self.assertIn("curl is a read only as", detail)

    def test_risky_and_redirect_details_are_unchanged(self):
        self.assertEqual(vpsexec.classify("systemctl restart nginx", tv.DENY),
                         ("risky", "systemctl restart"))
        self.assertEqual(vpsexec.classify("curl -q http://127.0.0.1/ > /tmp/x", tv.DENY),
                         ("mutating", "redirection"))

    def test_the_hint_cannot_change_any_tier(self):
        """is_read never consults the hint table, and classify computes the hint
        only after the tier is decided: a hint function that lies or explodes
        changes no tier (an exploding one is never even reached for a read)."""
        corpus = ["curl -qfsS http://127.0.0.1/healthz", "curl -fsS http://127.0.0.1/",
                  "df -h", "ls -Z", "docker ps", "docker cp a b", "uptime",
                  "systemctl status nginx", "systemctl edit nginx", "frobnicate"]
        before = [vpsexec.classify(c, tv.DENY)[0] for c in corpus]
        with mock.patch.object(readpolicy, "read_form_hint", return_value="it is a read"):
            lying = [vpsexec.classify(c, tv.DENY)[0] for c in corpus]
        self.assertEqual(before, lying)
        with mock.patch.object(readpolicy, "read_form_hint",
                               side_effect=AssertionError("consulted")):
            for c, tier in zip(corpus, before):
                if tier == "read":
                    self.assertEqual(vpsexec.classify(c, tv.DENY)[0], "read", c)
        for c in corpus:
            self.assertEqual(readpolicy.is_read(c.split()),
                             vpsexec.classify(c, tv.DENY)[0] == "read", c)


class ReadHintInRefusalTest(tv._Harness):

    def test_posture_refusal_carries_the_hint(self):
        with self.assertRaises(Refused) as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(["web1", "curl -fsS http://127.0.0.1/healthz",
                                  "--reason", "health"],
                                 guard=tv._guard(), policy=tv._yaml_policy(),
                                 ssh=self.fake_ssh(), prober=self.prober(),
                                 blackout_runner=self.blackout_runner(unavailable=True))
        msg = str(cm.exception)
        self.assertIn("refuse mutations by posture", msg)
        self.assertIn("This command is a mutation, not a read", msg)
        self.assertIn("curl -qfsS http://127.0.0.1/healthz", msg)
        self.assertEqual(self.cmds(), [])

    def test_verify_refusal_carries_the_hint(self):
        with self.assertRaises(Refused) as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(["edge1", "touch /tmp/x", "--reason", "x",
                                  "--verify", "curl -fsS http://127.0.0.1/"],
                                 guard=tv._guard(), policy=tv._yaml_policy(),
                                 ssh=self.fake_ssh(), prober=self.prober(),
                                 blackout_runner=self.blackout_runner(unavailable=True))
        self.assertIn("curl is a read only as", str(cm.exception))


if __name__ == "__main__":
    unittest.main()


class LowFindingHintTest(unittest.TestCase):

    def test_sysctl_hint_names_the_read_form_and_the_writing_ones(self):
        self.assertEqual(vpsexec.classify("sysctl -w net.ipv4.ip_forward=1", tv.DENY)[0],
                         "risky")  # `sysctl -w` is in the risky tier outright
        tier, detail = vpsexec.classify("sysctl -p /etc/sysctl.d/x.conf", tv.DENY)
        self.assertEqual(tier, "mutating")
        for needle in ("sysctl [-n]", "-w", "-p", "key=value"):
            self.assertIn(needle, detail)
        # The form it names really is a read; the ones it warns about are not.
        self.assertEqual(vpsexec.classify("sysctl -n net.ipv4.ip_forward", tv.DENY)[0], "read")
        self.assertEqual(vpsexec.classify("sysctl -a", tv.DENY)[0], "read")
        for cmd in ("sysctl -p", "sysctl --system", "sysctl net.ipv4.ip_forward=1"):
            self.assertEqual(vpsexec.classify(cmd, tv.DENY)[0], "mutating", cmd)

    def test_container_name_rule_matches_its_comment(self):
        """CONTAINER_RE is probe.HOST_RE: alnum first, then alnum . - and no _."""
        self.assertTrue(vpsexec.CONTAINER_RE.match("shop-web.1"))
        for bad in ("shop_web", "-web", ".web", "a b"):
            self.assertFalse(vpsexec.CONTAINER_RE.fullmatch(bad), bad)
