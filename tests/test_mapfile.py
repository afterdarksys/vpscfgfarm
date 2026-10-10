"""`.vpscfgfarm.map` tests. The file is UNTRUSTED input from arbitrary repos,
so the weight is on refusals: grant-shaped keys, typo'd constraints, wrong-repo
routing, and every enforcement failing closed."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import mapfile, vpsexec  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

import test_vpsexec as tv  # noqa: E402  (harness + governor fixtures)


def _map(tmp, body):
    p = Path(tmp) / mapfile.MAP_NAME
    p.write_text(body)
    return p


MINIMAL = "version: 1\n"


class SchemaTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _load(self, body):
        return mapfile.load(_map(self.tmp, body))

    def test_minimal_map_loads(self):
        doc = self._load(MINIMAL)
        self.assertIsNone(doc["service"])
        self.assertEqual(doc["constraints"]["deny_extra"], [])

    def test_full_map_loads(self):
        doc = self._load(
            "version: 1\n"
            "service: smtp-relay\n"
            "deploy: {entry: ./deploy.sh, host: web1.example.internal}\n"
            "constraints:\n"
            "  deny_extra: ['docker build']\n"
            "  risky_extra: ['systemctl restart']\n"
            "  max_tier: read\n"
            "  hosts_allow: [edge1]\n"
            "  forbid_flags: ['--force', '-f']\n"
            "  require_blackout: true\n"
            "  forbid_break_glass: true\n")
        self.assertEqual(doc["service"], "smtp-relay")
        self.assertEqual(doc["constraints"]["max_tier"], "read")

    def test_unknown_top_key_refuses(self):
        with self.assertRaises(Refused):
            self._load("version: 1\nsurprise: yes\n")

    def test_typoed_constraint_refuses_not_ignores(self):
        # deny_extr instead of deny_extra: silently ignoring it would mean the
        # operator BELIEVES a constraint applies that does not.
        with self.assertRaises(Refused) as cm:
            self._load("version: 1\nconstraints: {deny_extr: [x]}\n")
        self.assertIn("unknown", str(cm.exception))

    def test_grant_shaped_keys_refuse_anywhere(self):
        with self.assertRaises(Refused):
            self._load("version: 1\nbreak_glass: true\n")
        with self.assertRaises(Refused):
            self._load("version: 1\nconstraints:\n  deny_extra:\n"
                       "    - {posture: released}\n")
        with self.assertRaises(Refused):
            self._load("version: 1\ndeploy: {mode: released}\n")

    def test_max_tier_risky_is_no_cap_and_refused(self):
        with self.assertRaises(Refused):
            self._load("version: 1\nconstraints: {max_tier: risky}\n")

    def test_forbid_flags_must_be_flags(self):
        with self.assertRaises(Refused):
            self._load("version: 1\nconstraints: {forbid_flags: [force]}\n")

    def test_bad_yaml_refuses(self):
        with self.assertRaises(Refused):
            self._load("version: 1\nconstraints: [unbalanced\n")

    def test_non_mapping_refuses(self):
        with self.assertRaises(Refused):
            self._load("- just\n- a\n- list\n")

    def test_wrong_version_refuses(self):
        with self.assertRaises(Refused):
            self._load("version: 2\n")

    def test_oversized_file_refuses(self):
        with self.assertRaises(Refused):
            self._load("# pad\n" + "#" * (mapfile.MAX_MAP_BYTES + 10) + "\nversion: 1\n")

    def test_broken_map_never_degrades_to_no_map(self):
        _map(self.tmp, "version: 1\nsurprise: true\n")
        with self.assertRaises(Refused):
            mapfile.resolve(self.tmp)


class DiscoveryTest(unittest.TestCase):
    def test_nearest_wins_no_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            outer, inner = Path(tmp), Path(tmp) / "a" / "b"
            inner.mkdir(parents=True)
            _map(outer, "version: 1\nconstraints: {max_tier: mutating}\n")
            _map(inner, "version: 1\nconstraints: {max_tier: read}\n")
            doc = mapfile.resolve(inner)
            self.assertEqual(doc["constraints"]["max_tier"], "read")

    def test_found_in_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "x" / "y" / "z"
            deep.mkdir(parents=True)
            _map(tmp, MINIMAL)
            self.assertIsNotNone(mapfile.resolve(deep))

    def test_absent_is_none_not_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(mapfile.find(tmp))


class BindingTest(unittest.TestCase):
    def _doc(self, tmp, service="svc", host=None):
        body = "version: 1\nservice: %s\n" % service
        if host:
            body += "deploy: {host: %s}\n" % host
        return mapfile.load(_map(tmp, body))

    def test_map_inside_contract_repo_binds(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = self._doc(tmp)
            contract = {"service": "svc", "host": "edge1", "repo": tmp}
            got = mapfile.bind(doc, contract_loader=lambda n: contract)
            self.assertEqual(got["host"], "edge1")

    def test_map_in_subdir_of_repo_binds(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub = Path(tmp) / "deploy"
            sub.mkdir()
            doc = mapfile.load(_map(sub, "version: 1\nservice: svc\n"))
            contract = {"service": "svc", "host": "edge1", "repo": tmp}
            mapfile.bind(doc, contract_loader=lambda n: contract)

    def test_map_in_unrelated_dir_refuses(self):
        # The malicious shape: a map pasted into repo B routing at service A.
        with tempfile.TemporaryDirectory() as tmp:
            doc = self._doc(tmp)
            contract = {"service": "svc", "host": "edge1",
                        "repo": "/somewhere/else/entirely"}
            with self.assertRaises(Refused) as cm:
                mapfile.bind(doc, contract_loader=lambda n: contract)
            self.assertIn("do not agree", str(cm.exception))

    def test_deploy_host_mismatch_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = self._doc(tmp, host="web1")
            contract = {"service": "svc", "host": "edge1", "repo": tmp}
            with self.assertRaises(Refused):
                mapfile.bind(doc, contract_loader=lambda n: contract)

    def test_contract_without_repo_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = self._doc(tmp)
            with self.assertRaises(Refused):
                mapfile.bind(doc, contract_loader=lambda n: {"service": "svc",
                                                             "host": "edge1"})

    def test_serviceless_map_cannot_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = mapfile.load(_map(tmp, MINIMAL))
            with self.assertRaises(Refused):
                mapfile.bind(doc, contract_loader=lambda n: {})


def _docfor(**cons):
    base = {"deny_extra": [], "risky_extra": [], "hosts_allow": [],
            "forbid_flags": [], "require_blackout": False,
            "forbid_break_glass": False, "max_tier": None}
    base.update(cons)
    return {"path": "/x/.vpscfgfarm.map", "dir": "/x", "service": None,
            "deploy": {}, "constraints": base}


class EnforcementTest(unittest.TestCase):
    def test_tier_cap_read_blocks_mutating_and_risky(self):
        doc = _docfor(max_tier="read")
        mapfile.enforce_tier_cap(doc, "read")
        for tier in ("mutating", "risky"):
            with self.assertRaises(Refused):
                mapfile.enforce_tier_cap(doc, tier)

    def test_tier_cap_mutating_blocks_only_risky(self):
        doc = _docfor(max_tier="mutating")
        mapfile.enforce_tier_cap(doc, "read")
        mapfile.enforce_tier_cap(doc, "mutating")
        with self.assertRaises(Refused):
            mapfile.enforce_tier_cap(doc, "risky")

    def test_no_cap_is_no_cap(self):
        mapfile.enforce_tier_cap(_docfor(), "risky")

    def test_hosts_allow_refuses_whole_run_on_one_outsider(self):
        doc = _docfor(hosts_allow=["edge1"])
        mapfile.enforce_hosts_allow(doc, ["edge1"])
        with self.assertRaises(Refused):
            mapfile.enforce_hosts_allow(doc, ["edge1", "web1"])

    def test_hosts_allow_collapses_governor_aliases(self):
        doc = _docfor(hosts_allow=["relay2"])
        aliases = {"relay2": "relay2.example.net"}
        mapfile.enforce_hosts_allow(doc, ["relay2.example.net"],
                                    aliases_of=aliases)

    def test_forbid_flags_catches_plain_and_bundled(self):
        doc = _docfor(forbid_flags=["-f"])
        with self.assertRaises(Refused):
            mapfile.enforce_forbid_flags(doc, "compose up -f x",
                                         flag_expander=vpsexec._expand_short_flags)
        with self.assertRaises(Refused):
            mapfile.enforce_forbid_flags(doc, "curl -sfo out",
                                         flag_expander=vpsexec._expand_short_flags)
        mapfile.enforce_forbid_flags(doc, "ls -la",
                                     flag_expander=vpsexec._expand_short_flags)

    def test_unparseable_command_fails_closed(self):
        doc = _docfor(forbid_flags=["-f"])
        with self.assertRaises(Refused):
            mapfile.enforce_forbid_flags(doc, "echo 'unbalanced")


class DispatchIntegrationTest(tv._Harness):
    """The leash on the real gate stack — full dispatch, fake fleet."""

    def _go(self, argv, mapdoc, gov=None):
        guard = tv._guard(gov or tv._policy(verbs=["exec"]))
        return vpsexec.dispatch(
            argv, guard=guard, policy=tv._yaml_policy(),
            ssh=self.fake_ssh(), mapdoc=mapdoc,
            blackout_runner=self.blackout_runner())

    def test_read_capped_dir_refuses_a_mutation(self):
        with self.assertRaises(Refused) as cm:
            self._go(["edge1", "docker restart api", "--run", "--reason", "x"],
                     _docfor(max_tier="read"))
        self.assertIn(".vpscfgfarm.map", str(cm.exception))

    def test_read_capped_dir_still_reads(self):
        rc = self._go(["edge1", "uptime"], _docfor(max_tier="read"))
        self.assertEqual(rc, 0)

    def test_map_deny_extra_is_absolute_here_too(self):
        with self.assertRaises(Refused):
            self._go(["edge1", "docker build -t x ."],
                     _docfor(deny_extra=["docker build"]))

    def test_hosts_allow_narrows_the_fleet(self):
        with self.assertRaises(Refused):
            self._go(["edge1,web3", "uptime"], _docfor(hosts_allow=["edge1"]))

    def test_forbid_break_glass_blocks_elevation_flag(self):
        with self.assertRaises(Refused) as cm:
            self._go(["edge1", "docker restart api", "--run", "--reason", "x",
                      "--break-glass"], _docfor(forbid_break_glass=True))
        self.assertIn("break-glass", str(cm.exception).lower())

    def test_no_map_changes_nothing(self):
        rc = self._go(["edge1", "uptime"], None)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
