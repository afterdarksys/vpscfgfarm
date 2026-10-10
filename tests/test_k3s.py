"""`vpscfg fleet k3s`: k3s + iptables backend health and reboot safety.

Fixtures are the states the audit must tell apart: edge1 mid-outage (crash
loop on iptables-nft 1.8.2), edge1 after recovery (legacy host, stale nft
rules, k3s stopped but enabled), web2 (healthy legacy k3s), web1/web3 (nft, no
k3s).
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import k3s, probe  # noqa: E402


def out(**over):
    sec = {"present": "yes", "uptime": "42643.80 1.0",
           "alternatives": "/usr/sbin/xtables-legacy-multi\n/usr/sbin/xtables-legacy-multi",
           "version": "iptables v1.8.2 (legacy)", "legacy_rules": "1848", "nft_rules": "0",
           "unit": "NRestarts=0\nActiveState=active\nSubState=running\nUnitFileState=enabled",
           "panics": "0", "last_panic": "", "docker": "active\nenabled",
           "netfilter": "disabled\nabsent", "config": "",
           "nodes": "web2.example.internal   Ready   control-plane   188d   v1.34.5+k3s1",
           "pods_bad": ""}
    sec.update(over)
    return "\n".join("@@@%s\n%s" % (k, v) for k, v in sec.items())


def kinds(text):
    return sorted((f["severity"], f["kind"]) for f in k3s.audit(text)[0])


EDGE1_OUTAGE = dict(version="iptables v1.8.2 (nf_tables)", legacy_rules="0", nft_rules="1929",
                  alternatives="/usr/sbin/xtables-nft-multi\n/usr/sbin/xtables-nft-multi",
                  unit="NRestarts=320\nActiveState=activating\nSubState=auto-restart\nUnitFileState=enabled",
                  panics="320", last_panic="panic: ... Chain 'KUBE-ROUTER-INPUT' does not exist",
                  docker="failed\nenabled")


class AuditTest(unittest.TestCase):
    def test_healthy_legacy_k3s_host_is_clean_and_reboot_safe(self):
        findings, f = k3s.audit(out())
        self.assertEqual(findings, [])
        self.assertTrue(k3s.reboot_safe(findings))
        self.assertEqual((f["backend"], f["iptables_version"]), ("legacy", "1.8.2"))

    def test_edge1_outage_state(self):
        got = kinds(out(**EDGE1_OUTAGE))
        for want in (("CRITICAL", "k3s-crashloop"), ("HIGH", "k3s-nft-boot-race"),
                     ("HIGH", "docker-down")):
            self.assertIn(want, got)
        self.assertFalse(k3s.reboot_safe(k3s.audit(out(**EDGE1_OUTAGE))[0]))

    def test_edge1_after_recovery_mixed_backends_and_stopped_but_enabled(self):
        text = out(legacy_rules="702", nft_rules="1929",
                   unit="NRestarts=1000\nActiveState=inactive\nSubState=dead\nUnitFileState=enabled")
        self.assertEqual(kinds(text), [("HIGH", "k3s-stopped-but-enabled"), ("HIGH", "mixed-backends")])
        self.assertFalse(k3s.reboot_safe(k3s.audit(text)[0]))

    def test_nft_host_without_k3s_is_not_a_boot_race(self):
        text = out(present="NO_K3S", version="iptables v1.8.2 (nf_tables)", legacy_rules="0",
                   nft_rules="560", unit="", nodes="", pods_bad="")
        findings = k3s.audit(text)[0]
        self.assertEqual(findings, [])
        self.assertTrue(k3s.reboot_safe(findings))

    def test_newer_nft_with_k3s_is_not_flagged_as_the_1_8_2_race(self):
        self.assertNotIn(("HIGH", "k3s-nft-boot-race"),
                         kinds(out(version="iptables v1.8.9 (nf_tables)", legacy_rules="0", nft_rules="50")))

    def test_bundled_iptables_against_a_legacy_host(self):
        self.assertIn(("HIGH", "k3s-bundled-vs-host"), kinds(out(config="prefer-bundled-bin: true")))

    def test_api_down_while_active(self):
        text = out(nodes="The connection to the server 127.0.0.1:6443 was refused")
        self.assertIn(("CRITICAL", "k3s-api-or-node-down"), kinds(text))
        self.assertIn(("CRITICAL", "k3s-api-or-node-down"),
                      kinds(out(nodes="web2   NotReady   control-plane   188d   v1.34.5")))

    def test_crashlooping_pods_are_reported(self):
        pods = ("shop      payout-worker-7b46   0/1   CrashLoopBackOff   15479   111d\n"
                "blobstore   blobstore-api-8465   0/1   CrashLoopBackOff   16174   111d")
        findings = k3s.audit(out(pods_bad=pods))[0]
        self.assertEqual([x["kind"] for x in findings], ["pods-crashlooping"])
        self.assertIn("shop/payout-worker-7b46", findings[0]["detail"])
        self.assertTrue(k3s.reboot_safe(findings))   # a bad pod does not make a reboot unsafe

    def test_docker_absent_or_disabled_is_not_down(self):
        self.assertNotIn(("HIGH", "docker-down"), kinds(out(docker="inactive\nabsent")))
        self.assertNotIn(("HIGH", "docker-down"), kinds(out(docker="inactive\ndisabled")))
        self.assertIn(("HIGH", "docker-down"), kinds(out(docker="inactive\nenabled")))

    def test_render_states_the_verdict(self):
        findings, f = k3s.audit(out(**EDGE1_OUTAGE))
        self.assertIn("REBOOT-SAFE: NO", k3s.render("edge1", findings, f))


class ProbeTest(unittest.TestCase):
    def test_probe_is_read_only(self):
        """The k3s probe may list, count and show; it must never change state."""
        cmd = probe.COMMANDS["k3s"]
        # iptables flags (-A/-I/-F...) are pinned below by listing every iptables
        # invocation; checking them as bare substrings would trip on kubectl -A.
        for bad in ("-restore", "systemctl start", "systemctl stop", "systemctl restart",
                    "systemctl enable", "systemctl disable", "update-alternatives --set",
                    "kubectl delete", "kubectl apply", "kubectl patch", "kubectl scale",
                    "kubectl drain", "kubectl cordon", " > ", ">/etc", ">/var", " rm "):
            stripped = cmd.replace("2>/dev/null", "").replace(">/dev/null", "").replace("2>&1", "")
            self.assertNotIn(bad, stripped, bad)
        # the only iptables invocations are a version string and two -save dumps,
        # piped straight into a count (rules are never printed)
        calls = re.findall(r"(?<![/\w-])iptables[\w-]*[^;|&]*", cmd)
        self.assertEqual(sorted(c.split()[0] for c in calls),
                         ["iptables", "iptables-legacy-save", "iptables-nft-save"])
        self.assertIn("iptables-legacy-save 2>/dev/null | grep -c '^-A'", cmd)
        self.assertIn("iptables-nft-save 2>/dev/null | grep -c '^-A'", cmd)


if __name__ == "__main__":
    unittest.main()
