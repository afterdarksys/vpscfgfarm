"""logs verb tests. The load-bearing ones: a --file read of a secret path
refuses through the SAME deny stack the doors use, and no operator input
reaches a remote shell unquoted."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import logsearch  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

# The secrets deny list, as the real verb would merge it (floor + secrets).
SECRETS = [".env.production", "id_rsa", "id_ed25519", ".pgpass", "private_key"]
DENY = list(DENY_ALWAYS_FLOOR) + SECRETS


class BuildCommandTest(unittest.TestCase):
    def test_unit_logs_with_time_and_search(self):
        c = logsearch.build_command(
            {"target": "nginx", "searches": ["ERROR"], "since": "2h"})
        self.assertIn("journalctl -u nginx", c)
        self.assertIn("date -d '2 hours ago'", c)
        self.assertIn("grep -F -e ERROR", c)
        self.assertIn("tail -n 400", c)

    def test_container_logs(self):
        c = logsearch.build_command(
            {"in_container": "smtp-relay", "searches": ["554"], "since": "1d"})
        self.assertIn("docker logs", c)
        self.assertIn("smtp-relay", c)
        self.assertIn("date -d '1 days ago'", c)

    def test_file_read(self):
        c = logsearch.build_command(
            {"target": "x", "file": "/opt/app/config.yaml", "searches": ["timeout"]})
        self.assertTrue(c.startswith("cat -- /opt/app/config.yaml"))
        self.assertIn("head -n 400", c)

    def test_file_read_inside_container(self):
        c = logsearch.build_command(
            {"in_container": "api", "file": "/etc/app.conf", "searches": ["x"]})
        self.assertIn("docker exec api cat -- /etc/app.conf", c)

    def test_current_tails_without_since(self):
        c = logsearch.build_command({"target": "sshd", "since": "current", "max": 50})
        self.assertIn("-n 50", c)
        self.assertNotIn("--since", c)

    def test_regex_uses_E_fixed_uses_F(self):
        r = logsearch.build_command({"target": "x", "searches": ["a.*b"], "regex": True})
        self.assertIn("grep -E -e", r)
        f = logsearch.build_command({"target": "x", "searches": ["a.*b"]})
        self.assertIn("grep -F -e", f)

    def test_multiple_searches_chain_AND(self):
        c = logsearch.build_command(
            {"target": "x", "searches": ["ERROR", "timeout"]})
        self.assertEqual(c.count("grep -F -e"), 2)

    def test_max_capped_at_ceiling(self):
        c = logsearch.build_command({"target": "x", "max": 999999})
        self.assertIn("tail -n %d" % logsearch.MAX_CAP, c)


class ValidationTest(unittest.TestCase):
    def test_needs_a_source(self):
        with self.assertRaises(Refused):
            logsearch.build_command({"searches": ["x"]})

    def test_bad_unit_refused(self):
        with self.assertRaises(Refused):
            logsearch.build_command({"target": "a b; rm -rf /"})

    def test_bad_container_refused(self):
        with self.assertRaises(Refused):
            logsearch.build_command({"in_container": "a/b`c`"})

    def test_traversal_file_refused(self):
        with self.assertRaises(Refused):
            logsearch.build_command({"target": "x", "file": "/opt/../etc/shadow"})

    def test_relative_file_refused(self):
        with self.assertRaises(Refused):
            logsearch.build_command({"target": "x", "file": "app/.env"})

    def test_bad_since_refused(self):
        with self.assertRaises(Refused):
            logsearch.build_command({"target": "x", "since": "yesterday"})

    def test_timestamp_since_accepted(self):
        c = logsearch.build_command(
            {"target": "x", "since": "2026-09-10 05:00:00"})
        self.assertIn("--since", c)

    def test_empty_search_refused(self):
        with self.assertRaises(Refused):
            logsearch.build_command({"target": "x", "searches": [""]})


class SecretGateTest(unittest.TestCase):
    """The whole reason --file is gated: a new door must not read secrets."""

    def _run(self, spec):
        # runner must never be reached if the gate fires
        def boom(h, c):
            raise AssertionError("command ran despite deny: %s" % c)
        return logsearch.run("edge1", spec, DENY, runner=boom)

    def test_secret_env_file_refused(self):
        with self.assertRaises(Refused):
            self._run({"target": "x", "file": "/opt/app/.env.production",
                       "searches": ["KEY"]})

    def test_ssh_key_refused(self):
        with self.assertRaises(Refused):
            self._run({"target": "x", "file": "/root/.ssh/id_rsa"})

    def test_pgpass_refused(self):
        with self.assertRaises(Refused):
            self._run({"in_container": "pg", "file": "/var/lib/pgsql/.pgpass"})

    def test_ordinary_config_file_allowed(self):
        captured = {}
        def runner(h, c):
            captured["cmd"] = c
            return 0, "timeout: 30\n", ""
        r = logsearch.run("edge1", {"target": "x", "file": "/opt/app/config.yaml",
                                  "searches": ["timeout"]}, DENY, runner=runner)
        self.assertTrue(r["matched"])
        self.assertIn("config.yaml", captured["cmd"])

    def test_floor_pattern_in_search_still_refused(self):
        # a contrived path that trips the floor must refuse too
        with self.assertRaises(Refused):
            self._run({"target": "x", "file": "/opt/volume prune/log"})


class RunTest(unittest.TestCase):
    def test_no_matches_is_clean_empty_not_error(self):
        r = logsearch.run("edge1", {"target": "nginx", "searches": ["ZZZ"]},
                          DENY, runner=lambda h, c: (1, "", ""))
        self.assertFalse(r["matched"])
        self.assertIn("no matches", logsearch.render("edge1",
                      {"target": "nginx", "searches": ["ZZZ"]}, r))

    def test_bad_host_refused(self):
        with self.assertRaises(Refused):
            logsearch.run("bad host!", {"target": "x"}, DENY,
                          runner=lambda h, c: (0, "", ""))

    def test_shell_metacharacters_in_search_are_quoted_not_injected(self):
        captured = {}
        def runner(h, c):
            captured["cmd"] = c
            return 0, "", ""
        # metacharacters, but no floor phrase: must run, safely quoted
        logsearch.run("edge1", {"target": "x", "searches": ["$(whoami); ls"]},
                      DENY, runner=runner)
        self.assertIn("grep -F -e", captured["cmd"])
        # single-quoted arg — the $() and ; are inert grep text, not shell
        self.assertIn("'$(whoami); ls'", captured["cmd"])

    def test_search_containing_a_floor_phrase_fails_closed(self):
        # deny_scan is substring-based by design; a search for a floor phrase
        # is refused rather than risk it being anything but inert grep text.
        def boom(h, c):
            raise AssertionError("ran despite floor phrase")
        with self.assertRaises(Refused):
            logsearch.run("edge1", {"target": "x", "searches": ["volume prune"]},
                          DENY, runner=boom)


if __name__ == "__main__":
    unittest.main()
