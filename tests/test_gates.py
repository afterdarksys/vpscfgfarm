"""Gate tests — weighted to negative paths per SECURITY-RULES: a safety asset
with only happy-path tests is a draft, period."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg.gates import (  # noqa: E402
    DENY_ALWAYS_FLOOR, Refused, assert_not_frozen, deny_scan,
    edit_distance, volume_name_check,
)


class DenyScanTest(unittest.TestCase):
    def test_blocks_exact(self):
        with self.assertRaises(Refused):
            deny_scan("docker volume prune -f", DENY_ALWAYS_FLOOR)

    def test_blocks_mid_string_inside_ssh_payload(self):
        # The near-miss shape: destructive verb inside a quoted remote command.
        with self.assertRaises(Refused):
            deny_scan("ssh root@web1 'docker volume prune -f'", DENY_ALWAYS_FLOOR)

    def test_blocks_case_insensitive(self):
        with self.assertRaises(Refused):
            deny_scan("psql -c 'drop table users'", DENY_ALWAYS_FLOOR)

    def test_blocks_whitespace_tricks(self):
        with self.assertRaises(Refused):
            deny_scan("docker  volume   prune", DENY_ALWAYS_FLOOR)

    def test_blocks_compose_down_with_volumes(self):
        for cmd in ("docker compose down -v", "docker compose down --volumes"):
            with self.assertRaises(Refused):
                deny_scan(cmd, DENY_ALWAYS_FLOOR)

    def test_allows_plain_compose_down_restart_flow(self):
        # Routine operations must pass or the tool gets bypassed out of annoyance.
        deny_scan("docker compose up -d --build --force-recreate", DENY_ALWAYS_FLOOR)
        deny_scan("docker compose restart acme-api", DENY_ALWAYS_FLOOR)
        deny_scan("docker ps --format '{{.Names}}'", DENY_ALWAYS_FLOOR)

    def test_allows_reads(self):
        deny_scan("kubectl get pods -A", DENY_ALWAYS_FLOOR)
        deny_scan("ls -la /opt", DENY_ALWAYS_FLOOR)


class EditDistanceTest(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(edit_distance("abc", "abc"), 0)

    def test_the_exact_production_pair(self):
        self.assertEqual(
            edit_distance("acmedns_postgres-data", "acmedns_postgres_data"), 1
        )

    def test_distance_two(self):
        self.assertEqual(edit_distance("abc", "axy"), 2)

    def test_empty(self):
        self.assertEqual(edit_distance("", "abc"), 3)


class VolumeNameCheckTest(unittest.TestCase):
    LIVE = ["acmedns_postgres_data", "idp_idp_postgres", "chatbot_qdrant_storage"]

    def test_refuses_the_one_character_twin(self):
        # THE rule. If this test is ever deleted, ask why.
        with self.assertRaises(Refused):
            volume_name_check("acmedns_postgres-data", self.LIVE)

    def test_allows_exact_live_reference(self):
        volume_name_check("acmedns_postgres_data", self.LIVE)

    def test_allows_clearly_distinct_names(self):
        volume_name_check("totally_unrelated_volume", self.LIVE)


class FreezeTest(unittest.TestCase):
    def test_frozen_contract_refuses(self):
        with self.assertRaises(Refused):
            assert_not_frozen({"service": "x", "freeze": True})

    def test_unfrozen_passes(self):
        assert_not_frozen({"service": "x", "freeze": False})
        assert_not_frozen({"service": "x"})  # absent == not frozen


if __name__ == "__main__":
    unittest.main()
