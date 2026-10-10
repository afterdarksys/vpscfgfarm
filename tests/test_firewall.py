"""`vpscfg fleet firewall` — a firewall manager's audit judged locally from
one probe.

Fixtures mirror what the probe prints on a Debian 10 docker/k3s host. The
publisher_of cases are the firewall manager's own regression set.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import firewall, probe  # noqa: E402

MANAGER = {"desired_state": "estate/firewall.json", "script": "/usr/local/sbin/lockdown.sh",
           "unit": "lockdown.service", "installer": "lockdown-install"}
ESTATE = {"servers": ["192.0.2.5"], "admin": ["198.51.100.185"],
          "private": ["10.0.0.0/8"], "ports": [6379, 5432], "path": "t", "sha256": "x",
          "manager": MANAGER}

RAW_OK = """-P PREROUTING ACCEPT
-A PREROUTING -s 198.51.100.185/32 -p tcp -m tcp --dport 5432 -j ACCEPT
-A PREROUTING -s 192.0.2.5/32 -p tcp -m tcp --dport 5432 -j ACCEPT
-A PREROUTING -s 10.0.0.0/8 -p tcp -m tcp --dport 5432 -j ACCEPT
-A PREROUTING -p tcp -m tcp --dport 5432 -j DROP
-A PREROUTING -s 198.51.100.185/32 -p tcp -m tcp --dport 6379 -j ACCEPT
-A PREROUTING -s 192.0.2.5/32 -p tcp -m tcp --dport 6379 -j ACCEPT
-A PREROUTING -s 10.0.0.0/8 -p tcp -m tcp --dport 6379 -j ACCEPT
-A PREROUTING -p tcp -m tcp --dport 6379 -j DROP"""

RAW_L = """Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination
      25     1500 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:5432
      14      840 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:6379"""

PS = ("vault-main\t0.0.0.0:8200-8201->8200-8201/tcp, :::8200-8201->8200-8201/tcp\n"
      "shop-web\t0.0.0.0:3009->80/tcp\n"
      "exposed-only\t9000/tcp\n"
      "udp-thing\t0.0.0.0:5300->53/udp\n"
      "multi\t0.0.0.0:7000->7000/tcp, 0.0.0.0:7100-7102->7100-7102/tcp\n"
      "postgres\t0.0.0.0:5432->5432/tcp\n")
PS_ALL = PS + "ghost\t0.0.0.0:9999->9999/tcp\n"


def probe_out(**over):
    sec = {"nat": "-P PREROUTING ACCEPT", "raw_s": RAW_OK, "raw_l": RAW_L, "du_s": "",
           "forward_l": "Chain FORWARD", "input_s": "", "raw6_s": "", "docker_ps": PS, "docker_ps_all": PS_ALL,
           "docker_ips": "/postgres\t172.17.0.7 \n", "pods": "NO_K3S", "endpoints": "",
           "listen": "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n",
           "units": "lockdown.service enabled active\nnetfilter-persistent absent ",
           "script": "abc  /usr/local/sbin/lockdown.sh", "rules_v4": ""}
    sec.update(over)
    return "\n".join("@@@%s\n%s" % (k, v) for k, v in sec.items())


def kinds(out):
    return sorted((f["severity"], f["kind"]) for f in firewall.audit(out, ESTATE)[0])


class ParsingTest(unittest.TestCase):
    def test_section_names_may_contain_digits(self):
        self.assertEqual(firewall.sections("@@@rules_v4\nx\n@@@script\ny")["rules_v4"], "x")

    def test_ports_in_handles_single_multiport_and_ranges(self):
        self.assertEqual(firewall.ports_in("--dport 6379"), [6379])
        self.assertEqual(firewall.ports_in("-m multiport --dports 5432,5433,6379"), [5432, 5433, 6379])
        self.assertEqual(firewall.ports_in("--dports 8000:8002"), [8000, 8001, 8002])
        self.assertEqual(firewall.ports_in("-j ACCEPT"), [])

    def test_publisher_of_matches_the_regression_cases(self):
        cases = [(8200, PS, "vault-main"), (8201, PS, "vault-main"),
                 (3009, PS, "shop-web"), (7000, PS, "multi"), (7101, PS, "multi"),
                 (7102, PS, "multi"), (5300, PS, "udp-thing"), (8199, PS, ""), (8202, PS, ""),
                 (9000, PS, ""), (80, PS, ""), (9999, PS, ""), (9999, PS_ALL, "ghost")]
        for port, lines, want in cases:
            self.assertEqual(firewall.publisher_of(port, lines), want, port)

    def test_listening_ignores_loopback_only(self):
        ss = ("LISTEN 0 128 127.0.0.1:6379 0.0.0.0:*\nLISTEN 0 128 [::1]:6379 [::]:*\n"
              "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\nLISTEN 0 128 *:8080 *:*\n")
        self.assertFalse(firewall.listening(6379, ss))
        self.assertTrue(firewall.listening(5432, ss))
        self.assertTrue(firewall.listening(8080, ss))
        self.assertFalse(firewall.listening(543, ss))

    def test_drop_counters(self):
        self.assertEqual(firewall.drop_counters(RAW_L), {5432: 25, 6379: 14})


class AuditTest(unittest.TestCase):
    def test_compliant_host_has_no_findings(self):
        self.assertEqual(kinds(probe_out()), [])

    def test_missing_drop_on_public_listener_is_critical_idle_is_medium(self):
        raw = "\n".join(l for l in RAW_OK.splitlines() if "6379 -j DROP" not in l
                        and "5432 -j DROP" not in l)
        self.assertEqual(kinds(probe_out(raw_s=raw)),
                         [("CRITICAL", "missing-drop"), ("MEDIUM", "missing-drop-no-listener")])

    def test_missing_allow_is_reported(self):
        raw = RAW_OK.replace("-A PREROUTING -s 192.0.2.5/32 -p tcp -m tcp --dport 6379 -j ACCEPT\n", "")
        self.assertIn(("MEDIUM", "missing-allow"), kinds(probe_out(raw_s=raw)))

    def test_accept_below_drop_never_matches(self):
        raw = RAW_OK + "\n-A PREROUTING -s 10.9.9.9/32 -p tcp -m tcp --dport 6379 -j ACCEPT"
        self.assertIn(("HIGH", "allow-below-drop"), kinds(probe_out(raw_s=raw)))

    def test_multiport_lockdown_counts(self):
        raw = ("-A PREROUTING -s 10.0.0.0/8 -p tcp -m multiport --dports 5432,6379 -j ACCEPT\n"
               "-A PREROUTING -s 192.0.2.5/32 -p tcp -m multiport --dports 5432,6379 -j ACCEPT\n"
               "-A PREROUTING -s 198.51.100.185/32 -p tcp -m multiport --dports 5432,6379 -j ACCEPT\n"
               "-A PREROUTING -p tcp -m multiport --dports 5432,6379 -j DROP")
        self.assertEqual(kinds(probe_out(raw_s=raw)), [])

    def test_stale_and_orphan_docker_dnat(self):
        nat = ("-A DOCKER ! -i docker0 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.17.0.3:5432\n"
               "-A DOCKER ! -i docker0 -p tcp -m tcp --dport 9999 -j DNAT --to-destination 172.17.0.9:9999")
        self.assertEqual(kinds(probe_out(nat=nat)),
                         [("HIGH", "stale-dnat"), ("INFO", "orphan-dnat")])
        ok = nat.replace("172.17.0.3", "172.17.0.7").splitlines()[0]
        self.assertEqual(kinds(probe_out(nat=ok)), [])

    def test_stale_cni_hostport_and_kube_endpoint(self):
        nat = ("-A CNI-DN-abc -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.42.0.24:443\n"
               "-A KUBE-SEP-XYZ -p tcp -m tcp -j DNAT --to-destination 10.42.0.46:8443")
        out = probe_out(nat=nat, pods="10.42.0.27\n10.42.0.30", endpoints="10.42.0.27")
        self.assertEqual(kinds(out), [("HIGH", "stale-hostport"), ("HIGH", "stale-kube-endpoint")])

    def test_landmine_armed_when_snapshot_holds_docker_nat(self):
        out = probe_out(units="lockdown.service enabled active\nnetfilter-persistent enabled active",
                        rules_v4="-A DOCKER -p tcp --dport 5432 -j DNAT --to-destination 172.17.0.3:5432")
        self.assertIn(("HIGH", "landmine-armed"), kinds(out))
        clean = probe_out(units="lockdown.service enabled active\nnetfilter-persistent enabled active")
        self.assertIn(("MEDIUM", "snapshot-persistence"), kinds(clean))

    def test_snapshot_unique_rules_are_listed_before_anyone_disables_the_loader(self):
        # INPUT policy DROP: the SSH allow is load-bearing, so losing it matters.
        saved = ("*filter\n:INPUT DROP [0:0]\n"
                 "-A INPUT -s 203.0.113.9/32 -p tcp -m tcp --dport 22 -j ACCEPT\n"
                 "-A DOCKER-USER -p tcp -m tcp --dport 6379 -j DROP\n"
                 "-A DOCKER -p tcp --dport 5432 -j DNAT --to-destination 172.17.0.3:5432\nCOMMIT")
        out = probe_out(units="lockdown.service enabled active\nnetfilter-persistent enabled active",
                        rules_v4=saved)
        findings, facts = firewall.audit(out, ESTATE)
        self.assertEqual(facts["snapshot_unique"],
                         ["-A INPUT -s 203.0.113.9/32 -p tcp -m tcp --dport 22 -j ACCEPT"])
        self.assertIn("snapshot-unique-rules", [f["kind"] for f in findings])
        self.assertIn("landmine-armed", [f["kind"] for f in findings])

    def test_input_drop_protects_host_process_but_not_a_docker_port(self):
        estate = dict(ESTATE, ports=[8080, 5432])
        raw = "\n".join(l for l in RAW_OK.splitlines() if "5432" in l)
        inp = "-A INPUT -p tcp -m tcp --dport 8080 -j DROP\n-A INPUT -p tcp -m tcp --dport 5432 -j DROP"
        v6 = "-A PREROUTING -p tcp -m tcp --dport 8080 -j DROP"
        out = probe_out(raw_s=raw, input_s=inp, raw6_s=v6, listen="LISTEN 0 128 *:8080 *:*\n")
        got = sorted((f["severity"], f["kind"]) for f in firewall.audit(out, estate)[0])
        self.assertEqual(got, [("INFO", "input-drop-only")])
        # the same INPUT drop does nothing for a docker-published port
        ps = PS + "proxy\t0.0.0.0:8080->80/tcp\n"
        out = probe_out(raw_s=raw, input_s=inp, docker_ps=ps, listen="LISTEN 0 128 *:8080 *:*\n")
        got = [f["kind"] for f in firewall.audit(out, estate)[0]]
        self.assertIn("missing-drop", got)

    def test_review_h1_docker_user_rules_in_the_snapshot_are_unique(self):
        """The reviewer's repro: a DOCKER-USER DROP for a port that is NOT in
        the lockdown exists nowhere but the snapshot (Docker never re-creates
        DOCKER-USER), so disabling the loader would open it."""
        saved = ("-A DOCKER-USER -s 10.0.0.0/8 -p tcp -m conntrack --ctorigdstport 5434 -j RETURN\n"
                 "-A DOCKER-USER -p tcp -m tcp --dport 5434 -j DROP\n"
                 "-A DOCKER-USER -p tcp -m tcp --dport 6379 -j DROP\n"
                 "-A DOCKER -d 172.17.0.3/32 -p tcp -j ACCEPT")
        out = probe_out(units="lockdown.service enabled active\nnetfilter-persistent enabled active",
                        rules_v4=saved)
        unique = firewall.audit(out, ESTATE)[1]["snapshot_unique"]
        self.assertEqual(len(unique), 2)           # both 5434 lines; 6379 is covered by raw
        self.assertTrue(all("5434" in u for u in unique))

    def test_review_h3_v6_listener_without_v6_drop(self):
        out = probe_out(listen="LISTEN 0 128 [::]:6379 [::]:*\nLISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n")
        self.assertIn(("HIGH", "v6-unprotected"), kinds(out))
        v6 = "-A PREROUTING -p tcp -m tcp --dport 6379 -j DROP"
        self.assertNotIn(("HIGH", "v6-unprotected"), kinds(probe_out(
            listen="LISTEN 0 128 [::]:6379 [::]:*\n", raw6_s=v6)))
        self.assertNotIn(("HIGH", "v6-unprotected"), kinds(probe_out(   # loopback only
            listen="LISTEN 0 128 [::1]:6379 [::]:*\n")))

    def test_review_m1_blanket_accept_above_drop_shadows_it(self):
        raw = "-A PREROUTING -j ACCEPT\n" + RAW_OK
        self.assertIn(("CRITICAL", "drop-shadowed"), kinds(probe_out(raw_s=raw)))

    def test_review_m1_qualified_drop_is_not_a_lockdown(self):
        for q in ("-p udp -m udp --dport 6379 -j DROP", "-i eth9 -p tcp -m tcp --dport 6379 -j DROP",
                  "-d 10.9.9.9/32 -p tcp -m tcp --dport 6379 -j DROP"):
            raw = RAW_OK.replace("-p tcp -m tcp --dport 6379 -j DROP", q)
            out = probe_out(raw_s=raw, listen="LISTEN 0 128 0.0.0.0:6379 0.0.0.0:*\n")
            self.assertIn(("CRITICAL", "missing-drop"), kinds(out), q)

    def test_review_m1_docker_user_drop_does_not_protect_a_host_process(self):
        raw = "\n".join(l for l in RAW_OK.splitlines() if "6379" not in l)
        du = "-A DOCKER-USER -p tcp -m tcp --dport 6379 -j DROP"
        out = probe_out(raw_s=raw, du_s=du, forward_l="-A FORWARD -j DOCKER-USER",
                        listen="LISTEN 0 128 0.0.0.0:6379 0.0.0.0:*\n")
        self.assertIn(("CRITICAL", "missing-drop"), kinds(out))

    def test_input_rules_covered_by_policy_accept_and_raw_lockdown(self):
        """A k3s host: saved INPUT ACCEPTs under an ACCEPT policy are
        no-ops, and an INPUT DROP for a locked port is covered by raw."""
        saved = (":INPUT ACCEPT [0:0]\n"
                 "-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n"
                 "-A INPUT -p tcp -m tcp --dport 6379 -j DROP\n"
                 "-A INPUT -p tcp -m tcp --dport 1234 -j DROP")
        out = probe_out(units="lockdown.service enabled active\nnetfilter-persistent enabled active",
                        rules_v4=saved)
        self.assertEqual(firewall.audit(out, ESTATE)[1]["snapshot_unique"],
                         ["-A INPUT -p tcp -m tcp --dport 1234 -j DROP"])
        dropping = saved.replace(":INPUT ACCEPT", ":INPUT DROP")
        out = probe_out(units="lockdown.service enabled active\nnetfilter-persistent enabled active",
                        rules_v4=dropping)
        self.assertIn("-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT",
                      firewall.audit(out, ESTATE)[1]["snapshot_unique"])

    def test_lockdown_not_persisted(self):
        out = probe_out(units="lockdown.service absent \nnetfilter-persistent absent ")
        self.assertIn(("HIGH", "not-persistent"), kinds(out))

    def test_host_without_iptables(self):
        out = "@@@nat\nNO_IPTABLES\n"
        self.assertEqual(kinds(out), [("INFO", "no-iptables")])

    def test_script_drift_across_hosts(self):
        drift = firewall.fleet_findings({"a": {"script_sha256": "1"}, "b": {"script_sha256": "2"}}, ESTATE)
        self.assertEqual([(f["severity"], f["kind"]) for f in drift], [("INFO", "script-drift")])
        self.assertEqual(firewall.fleet_findings({"a": {"script_sha256": "1"},
                                                  "b": {"script_sha256": "1"}}, ESTATE), [])


class PerHostTest(unittest.TestCase):
    def test_host_ports_by_any_alias_and_intent_markers(self):
        estate = dict(ESTATE, host_ports={"web1": [6379, 9091]}, public={"web1": [2525]},
                      undecided={"edge1": [8080]})
        web1 = firewall.for_host(estate, ["web1", "web1.example.internal"])
        self.assertEqual((web1["ports"], web1["public_ports"]), ([6379, 9091], [2525]))
        other = firewall.for_host(estate, ["web3"])
        self.assertEqual(other["ports"], ESTATE["ports"])
        edge1 = firewall.for_host(estate, ["edge1"])
        out = probe_out(listen="LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n")
        self.assertIn(("INFO", "undecided-exposure"),
                      sorted((f["severity"], f["kind"]) for f in firewall.audit(out, edge1)[0]))

    def test_estate_rejects_non_mapping_host_ports(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"servers": [], "admin": [], "private": [], "ports": [],
                       "host_ports": [6379]}, f)
        with self.assertRaises(ValueError):
            firewall.load_estate(f.name)


class EstateAndProbeTest(unittest.TestCase):
    def test_missing_or_malformed_estate_refuses(self):
        with self.assertRaises(ValueError):
            firewall.load_estate("/nonexistent/estate.json")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"servers": "not-a-list", "admin": [], "private": [], "ports": []}, f)
        with self.assertRaises(ValueError):
            firewall.load_estate(f.name)

    def test_probe_is_listings_only(self):
        """The one remote string. Every iptables call in it is a listing, token
        by token, and nothing else in it can change netfilter or unit state."""
        import re
        cmd = probe.firewall_command(MANAGER)
        # every `iptables` word except inside a path like /etc/iptables/rules.v4
        calls = re.findall(r"(?<![/\w-])iptables\b(?![/.-])[^;|&]*", cmd)
        self.assertEqual(calls[0].split()[0:2], ["iptables", ">/dev/null"])  # command -v
        calls = calls[1:]
        self.assertEqual(len(calls), 6)
        allowed = {"iptables", "-t", "nat", "raw", "-S", "-L", "-n", "-v", "-x",
                   "PREROUTING", "DOCKER-USER", "FORWARD", "INPUT", "2>/dev/null"}
        for call in calls:
            self.assertLessEqual(set(call.split()), allowed, call)
            self.assertTrue(" -S" in call or " -L" in call, call)
        for bad in ("iptables-restore", "iptables-save", "nft ", "ufw ", "systemctl start",
                    "systemctl stop", "systemctl restart", "systemctl disable",
                    "systemctl enable", "kubectl delete", "kubectl apply", "docker rm",
                    "docker stop", " rm ", "tee ", "> /", ">/etc", ">/var"):
            self.assertNotIn(bad, cmd, bad)
        for listing in ("iptables -t nat -S", "iptables -t raw -S PREROUTING",
                        "iptables -t raw -L PREROUTING -n -v -x", "iptables -S DOCKER-USER",
                        "iptables -L FORWARD -n -v -x"):
            self.assertIn(listing, cmd)


if __name__ == "__main__":
    unittest.main()
