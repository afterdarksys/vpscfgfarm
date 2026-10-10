"""Port audit tests — collisions and dead listeners are failures; undeclared
listeners are the coverage to-do, not noise that fails every host forever."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import ports  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402


def _contract(service, host="web1", declared=None, run_ports=None):
    c = {"service": service, "host": host, "deploy_dir": "/opt/" + service,
         "sync": {"include": [], "never": []}, "verify": []}
    if declared is not None:
        c["ports"] = declared
    if run_ports is not None:
        c["run"] = {"ports": run_ports}
    return c


SS_OUTPUT = """\
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*
tcp   LISTEN 0      128    0.0.0.0:25          0.0.0.0:*
tcp   LISTEN 0      511    *:443               *:*
tcp6  LISTEN 0      128    [::]:80             [::]:*
udp   UNCONN 0      0      0.0.0.0:53          0.0.0.0:*
"""


class DeclaredPortsTest(unittest.TestCase):
    def test_int_string_and_mapping_forms(self):
        c = _contract("s", declared=[8080, "9090", "25:2525", "53/udp"])
        self.assertEqual(ports.declared_ports(c),
                         {("tcp", 8080), ("tcp", 9090), ("tcp", 25), ("udp", 53)})

    def test_run_ports_docker_mappings_count(self):
        c = _contract("s", run_ports=["25:2525", "587:2587"])
        self.assertEqual(ports.declared_ports(c), {("tcp", 25), ("tcp", 587)})

    def test_garbage_entry_refused(self):
        for bad in ["http", "0", "70000", "25/sctp"]:
            with self.assertRaises(Refused):
                ports.declared_ports(_contract("s", declared=[bad]))


class ParseListeningTest(unittest.TestCase):
    def test_parses_ss_shapes(self):
        got = ports.parse_listening(SS_OUTPUT)
        self.assertEqual(got, {("tcp", 22), ("tcp", 25), ("tcp", 443),
                               ("tcp", 80), ("udp", 53)})

    def test_empty_output_is_empty(self):
        self.assertEqual(ports.parse_listening(""), set())


class AuditTest(unittest.TestCase):
    def test_collision_is_a_failure(self):
        cs = {"a": _contract("a", declared=[443]),
              "b": _contract("b", declared=[443])}
        rep = ports.audit({("tcp", 443)}, cs)
        self.assertIn(("tcp", 443), rep["collisions"])
        _, failures = ports.render("web1", rep)
        self.assertEqual(failures, 1)

    def test_declared_but_dead_is_a_failure(self):
        cs = {"a": _contract("a", declared=[9999])}
        rep = ports.audit({("tcp", 443)}, cs)
        self.assertIn(("tcp", 9999), rep["down"])
        text, failures = ports.render("web1", rep)
        self.assertIn("DOWN", text)
        self.assertEqual(failures, 1)

    def test_undeclared_listener_reported_but_not_fatal(self):
        rep = ports.audit({("tcp", 443), ("tcp", 22)}, {})
        self.assertEqual(rep["undeclared"], [("tcp", 443)])  # 22 baselined
        _, failures = ports.render("web1", rep)
        self.assertEqual(failures, 0)

    def test_ssh_is_baselined_out(self):
        rep = ports.audit({("tcp", 22)}, {})
        self.assertEqual(rep["undeclared"], [])

    def test_healthy_declared_port_is_ok(self):
        cs = {"a": _contract("a", declared=[443])}
        rep = ports.audit({("tcp", 443)}, cs)
        text, failures = ports.render("web1", rep)
        self.assertEqual(failures, 0)
        self.assertIn("ok", text)


class LintCollisionTest(unittest.TestCase):
    def test_same_host_same_port_is_error(self):
        loaded = {"a": _contract("a", declared=[443]),
                  "b": _contract("b", declared=[443])}
        errs = ports.lint_collisions(loaded)
        self.assertEqual(len(errs), 1)
        self.assertIn("a AND b", errs[0])

    def test_same_port_different_hosts_is_fine(self):
        loaded = {"a": _contract("a", host="web1", declared=[443]),
                  "b": _contract("b", host="edge1", declared=[443])}
        self.assertEqual(ports.lint_collisions(loaded), [])

    def test_two_host_ports_onto_one_container_port_is_no_collision(self):
        # an SMTP relay's run.ports shape: 587 and 465 both land on one port
        loaded = {"smtp-relay": _contract(
            "smtp-relay", host="web1.example.internal",
            run_ports=["25:2525", "587:2587", "465:2587"])}
        self.assertEqual(ports.lint_collisions(loaded), [])


if __name__ == "__main__":
    unittest.main()


class EphemeralPortTest(unittest.TestCase):
    """Regression: a media relay binds ~200 ephemeral UDP ports; listing them
    individually buried the ~20 real low ports the undeclared list exists for."""

    def test_ephemeral_ports_are_counted_not_listed(self):
        listening = {("tcp", 443), ("tcp", 8080)}
        listening |= {("udp", p) for p in range(50000, 50200)}  # media relay
        rep = ports.audit(listening, {})
        # the two real low ports are enumerated
        self.assertEqual(rep["undeclared"], [("tcp", 443), ("tcp", 8080)])
        # the 200 ephemeral are collected separately, not in undeclared
        self.assertEqual(len(rep["ephemeral"]), 200)
        text, failures = ports.render("edge1", rep)
        self.assertEqual(failures, 0)
        self.assertIn("tcp/443", text)
        self.assertIn("200 listener(s) in the ephemeral range", text)
        # the 200 individual udp lines must NOT appear
        self.assertNotIn("udp/50100", text)

    def test_boundary_32768_is_ephemeral_32767_is_not(self):
        rep = ports.audit({("tcp", 32767), ("tcp", 32768)}, {})
        self.assertEqual(rep["undeclared"], [("tcp", 32767)])
        self.assertEqual(rep["ephemeral"], [("tcp", 32768)])

    def test_declared_high_port_is_unaffected_by_ephemeral_filter(self):
        # A contract that legitimately declares a high port must still be
        # checked normally — the filter only touches the UNDECLARED advisory.
        c = {"a": _contract("a", declared=[50051])}
        rep = ports.audit({("tcp", 50051)}, c)
        self.assertEqual(rep["ephemeral"], [])          # it's declared, not loose
        self.assertIn(("tcp", 50051), rep["declared"])
        _, failures = ports.render("web1", rep)
        self.assertEqual(failures, 0)


SS_OUTPUT_WITH_PROC = """\
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:(("sshd",pid=800,fd=3))
tcp   LISTEN 0      511    *:443              *:*              users:(("nginx",pid=1234,fd=6),("nginx",pid=1235,fd=6))
tcp   LISTEN 0      128    0.0.0.0:9000       0.0.0.0:*        users:(("docker-proxy",pid=42,fd=4))
udp   UNCONN 0      0      0.0.0.0:53         0.0.0.0:*        users:(("systemd-resolve",pid=99,fd=12))
"""


class ProcessOwnerTest(unittest.TestCase):
    def test_parses_owner_per_port(self):
        got = ports.parse_process_owners(SS_OUTPUT_WITH_PROC)
        self.assertEqual(got, {("tcp", 22): "sshd",
                               ("tcp", 443): "nginx",
                               ("tcp", 9000): "docker-proxy",
                               ("udp", 53): "systemd-resolve"})

    def test_output_without_proc_column_yields_no_owners(self):
        # netstat fallback / non-root: parse_listening still works, owners empty
        self.assertEqual(ports.parse_process_owners(SS_OUTPUT), {})
        self.assertEqual(ports.parse_listening(SS_OUTPUT_WITH_PROC),
                         {("tcp", 22), ("tcp", 443), ("tcp", 9000), ("udp", 53)})

    def test_owner_annotates_ok_line(self):
        cs = {"web": _contract("web", declared=[443])}
        rep = ports.audit({("tcp", 443)}, cs, {("tcp", 443): "nginx"})
        text, failures = ports.render("web1", rep)
        self.assertEqual(failures, 0)
        self.assertIn("[nginx]", text)

    def test_owner_annotates_undeclared_line(self):
        rep = ports.audit({("tcp", 9000)}, {}, {("tcp", 9000): "docker-proxy"})
        self.assertEqual(rep["undeclared"], [("tcp", 9000)])
        text, failures = ports.render("web1", rep)
        self.assertEqual(failures, 0)
        self.assertIn("tcp/9000", text)
        self.assertIn("[docker-proxy]", text)

    def test_audit_owners_default_empty_is_backward_compatible(self):
        rep = ports.audit({("tcp", 443)}, {})
        self.assertEqual(rep["owners"], {})
        text, _ = ports.render("web1", rep)
        self.assertNotIn("[", text)
