"""The estate generators in tools/ read and write the ESTATE root, take every
estate fact from the estate (a spec file, the governor), and name no estate of
their own. Each test runs the real script in a temp tool checkout, whose
estate root is that checkout (no estate.path)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

UNIT = """[Unit]
Description=example oneshot
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lockdown.sh
"""

INSTALLER = """#!/bin/bash
[ "$1" = "--emit" ] && { echo "# lockdown for $2"; exit 0; }
exit 2
read -r -d '' UNIT <<'UNIT_EOF' || true
%sUNIT_EOF
""" % UNIT


class _Checkout(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(os.path.realpath(self.tmp.name)) / "tool"
        self.root.mkdir()
        shutil.copytree(str(REPO / "vpscfg"), str(self.root / "vpscfg"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(str(REPO / "tools"), str(self.root / "tools"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        for d in ("policies", "plays", "estate", "inventory", "contracts/skeletons"):
            (self.root / d).mkdir(parents=True)
        self.governor({})

    def governor(self, integrations):
        doc = {"version": 1, "mode": "test", "mutation_enabled": False,
               "deny_always": ["x"], "scopes": {"unlocked": []}, "hosts": {}}
        if integrations:
            doc["integrations"] = integrations
        (self.root / "vpscfg-control.json").write_text(json.dumps(doc))

    def run_tool(self, name, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("VPSCFG_")}
        env["HOME"] = str(self.root)  # no ssh config, no API key
        env.pop("VPSCFG_TELEMETRY_KEY", None)
        return subprocess.run([sys.executable, str(self.root / "tools" / name), *args],
                              capture_output=True, text=True, timeout=60,
                              cwd=str(self.root), env=env)


class FirewallRollout(_Checkout):
    def spec(self, **over):
        spec = {"installer": "estate/install.sh",
                "emit": ["bash", "{installer}", "--emit", "{host}"],
                "unit_markers": ["read -r -d '' UNIT <<'UNIT_EOF' || true\n", "UNIT_EOF\n"],
                "script_name": "lockdown.sh", "script_path": "/usr/local/sbin/lockdown.sh",
                "unit_name": "lockdown.service",
                "unit_path": "/etc/systemd/system/lockdown.service",
                "deploy_dir": "deploy/firewall",
                "runbook": "policies/firewall-lockdown-rollout.yaml",
                "play": "plays/firewall-lockdown-rollout.yaml",
                "hosts": ["dns1", "web1"],
                "backup_hosts": ["web1"], "backup_suffix": "20260101",
                "unit_hosts": ["dns1"], "expires": "2026-01-15",
                "reason": "roll out the example lockdown",
                "play_reason": "example lockdown rollout",
                "notes": ["# Example rollout.", "# Order: dns1, web1."]}
        spec.update(over)
        (self.root / "estate" / "firewall-rollout.json").write_text(json.dumps(spec))
        (self.root / "estate" / "install.sh").write_text(INSTALLER)

    def test_generates_under_the_estate_root_from_the_spec(self):
        self.spec()
        r = self.run_tool("gen_firewall_rollout.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.root / "deploy/firewall/web1/lockdown.sh").read_text(),
                         "# lockdown for web1\n")
        self.assertEqual((self.root / "deploy/firewall/lockdown.service").read_text(), UNIT)
        policy = (self.root / "policies/firewall-lockdown-rollout.yaml").read_text()
        self.assertTrue(policy.startswith("# Example rollout.\n# Order: dns1, web1.\n\nversion: 1\n"))
        self.assertIn('expires: "2026-01-15"\n', policy)
        self.assertIn('reason: "roll out the example lockdown"\n', policy)
        self.assertIn("lockdown.sh.bak-20260101", policy)
        steps = policy.count("  - hosts: [")
        self.assertIn("shape: {steps: %d, hosts: [dns1, web1], break_glass: true}\n" % steps, policy)
        self.assertEqual(policy.count("break_glass: true\n    why:"), steps)
        play = (self.root / "plays/firewall-lockdown-rollout.yaml").read_text()
        self.assertTrue(play.startswith('version: 1\nreason: "example lockdown rollout"\nsteps:\n'))
        self.assertEqual(play.count("  - hosts: "), steps)

    def test_the_shape_matches_what_the_policy_loader_counts(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML unavailable")
        self.spec()
        r = self.run_tool("gen_firewall_rollout.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = yaml.safe_load((self.root / "policies/firewall-lockdown-rollout.yaml").read_text())
        hosts = sorted({h for rb in doc["runbooks"] for h in rb["hosts"]})
        self.assertEqual(doc["shape"], {"steps": len(doc["runbooks"]), "hosts": hosts,
                                        "break_glass": True})

    def test_an_estate_header_replaces_the_default(self):
        (self.root / "estate" / "header.txt").write_text(
            "# estate header\n%(notes)sversion: 1\nexpires: \"%(expires)s\"\n"
            "shape: %(shape)s\nreason: \"%(reason)s\"\n\nrunbooks:\n")
        self.spec(header="estate/header.txt")
        r = self.run_tool("gen_firewall_rollout.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        policy = (self.root / "policies/firewall-lockdown-rollout.yaml").read_text()
        self.assertTrue(policy.startswith("# estate header\n# Example rollout.\n"), policy[:80])

    def test_bad_specs_refuse_and_write_nothing(self):
        for over in ({"hosts": ["web1; rm -rf /"]}, {"hosts": ["web1\n"]},
                     {"backup_hosts": ["db9"]},
                     {"backup_suffix": "x y"}, {"backup_suffix": "20260101\n"},
                     {"reason": 'a "quoted" reason'}, {"reason": "a \\ reason"},
                     {"reason": "a\rreason"}, {"expires": "2026-01-15\\"},
                     {"play_reason": "x\r"},
                     {"notes": ["not a comment"]}, {"hosts": "web1"},
                     {"script_path": "relative/lockdown.sh"}, {"script_name": "a/b.sh"},
                     {"deploy_dir": "../outside"}, {"runbook": "/etc/x.yaml"},
                     {"unit_markers": ["only one"]}, {"emit": "bash install.sh"},
                     {"unit_path": "/etc/x/../y.service"}):
            self.spec(**over)
            r = self.run_tool("gen_firewall_rollout.py")
            self.assertNotEqual(r.returncode, 0, over)
            self.assertFalse((self.root / "policies/firewall-lockdown-rollout.yaml").exists(), over)

    def test_reads_no_home_directory(self):
        # The estate's own tests also check these files name none of its hosts.
        for name in ("gen_firewall_rollout.py", "firewall_rollout_header.txt"):
            text = (REPO / "tools" / name).read_text()
            for word in ("Path.home", "expanduser", "/Users/", "/home/"):
                self.assertNotIn(word, text, name)


class Skeletons(_Checkout):
    def test_reads_inventory_and_writes_skeletons_in_the_estate(self):
        (self.root / "inventory" / "web1-deep.txt").write_text(
            "== containers ==\nshop-web\texample/shop:1.4.0\n== other ==\nx\ty\n")
        r = self.run_tool("gen_skeletons.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        skel = (self.root / "contracts/skeletons/web1--shop-web.yaml").read_text()
        self.assertIn("service: shop-web\nhost: web1\n", skel)
        self.assertIn("image: example/shop:1.4.0", skel)
        self.assertIn("hosts covered by deep probes: web1", r.stdout)


class TraefikVerify(_Checkout):
    def test_skipped_when_the_governor_names_no_file_provider(self):
        r = self.run_tool("traefik_verify.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("traefik mapping skipped", r.stdout)

    def test_a_malformed_entry_refuses(self):
        self.governor({"traefik": {"host": "web1", "file": "relative.yml"}})
        r = self.run_tool("traefik_verify.py")
        self.assertEqual(r.returncode, 2)
        self.assertIn("REFUSED", r.stderr)


if __name__ == "__main__":
    unittest.main()
