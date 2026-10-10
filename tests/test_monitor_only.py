"""monitor_only contracts: verify-only, watched by the sweep, never applied.

A monitor_only contract is how a service that ships elsewhere (k3s via CI, or a
path the executor cannot yet drive) still gets convergence monitoring: its
verify block runs on the sweep, so a down deployment surfaces instead of going
silent. It has no apply path, so it needs no deploy_dir/sync and the deploy
verb must refuse it.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import contracts  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402


class MonitorOnlyValidation(unittest.TestCase):
    def test_minimal_monitor_only_validates(self):
        c = {"service": "x", "host": "web2", "monitor_only": True,
             "verify": [{"http": {"url": "https://x/health", "expect": 200}}]}
        contracts._validate(c, "test")  # must not raise despite no deploy_dir/sync

    def test_monitor_only_still_needs_verify(self):
        c = {"service": "x", "host": "web2", "monitor_only": True}
        with self.assertRaises(Refused):
            contracts._validate(c, "test")

    def test_normal_contract_still_needs_deploy_dir_and_sync(self):
        c = {"service": "x", "host": "web1", "verify": [{"http": {"url": "https://x"}}]}
        with self.assertRaises(Refused):
            contracts._validate(c, "test")  # missing deploy_dir + sync


if __name__ == "__main__":
    unittest.main()
