"""contrib/example-estate ships a generic credential-path deny list, so a
copy of the example estate denies reading credentials from its first run.

Threats: a fresh estate built from the example printing `.env.production`,
private keys or password hashes through a read, which needs no approval and
works on frozen hosts.
"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import gates  # noqa: E402

try:
    from test_contrib import _governor, _load
except ImportError:  # run as a module of the tests package
    from tests.test_contrib import _governor, _load


class ExampleSecretsTest(unittest.TestCase):
    def setUp(self):
        self.policy = _load()
        self.deny = list(_governor()["deny_always"]) + list(self.policy["deny_extra"])

    def test_credential_reads_are_refused(self):
        for cmd in ("cat /srv/shop/.env.production", "head -1 ~/.ssh/id_ed25519",
                    "cat /etc//shadow", "cat /var/lib/rancher/k3s/server/token",
                    "cat /root/.pgpass", "docker inspect x | grep -A3 config.v2.json",
                    "cat /etc/traefik/acme.json"):
            with self.assertRaises(gates.Refused, msg=cmd):
                gates.deny_scan(cmd, self.deny)

    def test_ordinary_reads_still_pass(self):
        for cmd in ("docker logs secrets-api --tail 50", "systemctl is-active shop-web",
                    "cat /srv/shop/compose.yaml", "df -h"):
            gates.deny_scan(cmd, self.deny)

    def test_the_list_is_absolute_and_grants_nothing(self):
        self.assertGreater(len(self.policy["deny_extra"]), 40)
        self.assertIn("secrets.yaml", [Path(f["path"]).name for f in self.policy["files"]])


if __name__ == "__main__":
    unittest.main()
