"""`container: <name>` on a `where: container` runbook entry.

An entry naming a container authorises exactly `--in <that container>`: never
another container, a glob, or --in-all. Entries without the key keep matching
any container, as before.
"""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
import test_vpsexec_grant as tg  # noqa: E402
from vpscfg import probe, vpsexec, vpsexecpolicy  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

GOV = {"edge1", "web1", "web2", "web3", "dns1", "dns2"}
CMD = "pkill -HUP nginx"  # risky: it needs a runbook naming it

FILE = """version: 1
reason: "container tests"
expires: "2999-01-01"
shape: {steps: 1, hosts: [edge1], break_glass: false}
runbooks:
  - hosts: [edge1]
    cmd: "%s"
%s    why: "reload nginx in one container"
"""


def _load(lines):
    d = tempfile.mkdtemp()
    Path(d, "rb.yaml").write_text(FILE % (CMD, lines))
    return vpsexecpolicy.load(d, deny_patterns=tv.DENY, today="2026-10-09",
                              governor_hosts=GOV, host_re=probe.HOST_RE)


@unittest.skipUnless(vpsexecpolicy._HAVE_YAML, "PyYAML unavailable")
class ContainerLoadTest(unittest.TestCase):

    def test_valid_container_loads(self):
        rb = _load("    where: container\n    container: shop-api\n")["runbooks"][0]
        self.assertEqual((rb["where"], rb["container"]), ("container", "shop-api"))

    def test_absent_means_none(self):
        self.assertIsNone(_load("    where: container\n")["runbooks"][0]["container"])

    def test_container_without_where_container_refuses(self):
        for lines in ("    container: shop-api\n",
                      "    where: host\n    container: shop-api\n"):
            with self.assertRaises(Refused) as cm:
                _load(lines)
            self.assertIn("needs where: container", str(cm.exception))

    def test_names_the_cli_would_refuse_are_refused(self):
        for name in ('""', "-rm", "'a b'", "'a;b'", "a_b", "'../x'", "5", "[a]",
                     '"web\\n"', "'*'", "'shop-*'"):
            with self.assertRaises(Refused, msg=name):
                _load("    where: container\n    container: %s\n" % name)

    def test_override_file_may_not_carry_it(self):
        body = tv.OverrideFileTest.GOOD.replace("where: host", "where: container") + \
            "    container: shop-api\n"
        with self.assertRaises(Refused) as cm:
            vpsexec.load_override(tv._write(body), tv.DENY, today="2026-08-27")
        self.assertIn("container", str(cm.exception))

    def test_runbooks_listing_shows_it(self):
        text = vpsexec._render_runbooks(
            _load("    where: container\n    container: shop-api\n"))
        self.assertIn("where   : container  (container: shop-api)", text)


def _entry(container=None, hosts=("edge1",), break_glass=False):
    rb = tv._runbook(list(hosts), CMD, break_glass=break_glass, where="container")
    rb["container"] = container
    return rb


class ContainerMatchTest(tv._Harness):

    def go(self, flags, runbooks, host="edge1", gov=None, extra=()):
        """Plan only (no --run): rc 0 means every gate up to the plan passed."""
        with contextlib.redirect_stdout(io.StringIO()):
            return vpsexec.dispatch(
                [host, CMD, "--reason", "x"] + list(flags) + list(extra),
                guard=tv._guard(gov), policy=tv._yaml_policy(runbooks=runbooks),
                prober=self.prober(), ssh=self.fake_ssh(),
                blackout_runner=self.blackout_runner(unavailable=True))

    def test_exact_container_is_authorised(self):
        self.assertEqual(self.go(["--in", "shop-api"], [_entry("shop-api")]), 0)

    def test_other_container_is_not_authorised(self):
        """The negative that matters: naming shop-api never authorises
        blog-web, which is live on the same host."""
        with self.assertRaises(Refused) as cm:
            self.go(["--in", "blog-web"], [_entry("shop-api")])
        self.assertIn("not authorised", str(cm.exception))
        self.assertEqual(self.cmds(), [])

    def test_glob_all_and_extra_names_are_not_authorised(self):
        for flags in (["--in-match", "shop-*"], ["--in-match", "shop-a*"],
                      ["--in-all"], ["--in", "shop-api", "--in", "blog-web"]):
            with self.assertRaises(Refused, msg=flags):
                self.go(flags, [_entry("shop-api")])
        self.assertEqual(self.cmds(), [])

    def test_host_placement_is_not_authorised(self):
        with self.assertRaises(Refused):
            self.go([], [_entry("shop-api")])

    def test_entry_without_container_still_matches_any(self):
        for flags in (["--in", "blog-web"], ["--in-match", "shop-*"], ["--in-all"]):
            self.assertEqual(self.go(flags, [_entry(None)]), 0, flags)

    def test_break_glass_needs_the_named_container_too(self):
        rb = [_entry("shop-api", hosts=("web1",), break_glass=True)]
        self.assertEqual(self.go(["--in", "shop-api", "--break-glass"], rb, host="web1"), 0)
        with self.assertRaises(Refused) as cm:
            self.go(["--in", "blog-web", "--break-glass"], rb, host="web1")
        self.assertIn("not authorised", str(cm.exception))

    def test_targets_are_rechecked_after_resolution(self):
        """Defence in depth: even if matching were wrong, a plan whose resolved
        targets differ from the entry's container refuses before any plan."""
        entry = _entry("shop-api")
        with mock.patch.object(vpsexec, "lookup",
                               lambda entries, hosts, *a, **k: dict((h, entry) for h in hosts)):
            with self.assertRaises(Refused) as cm:
                self.go(["--in", "blog-web"], [entry])
        self.assertIn("names container 'shop-api'", str(cm.exception))
        self.assertEqual(self.cmds(), [])

    def test_permits_unit(self):
        entries = [_entry("shop-api")]
        self.assertIsNotNone(vpsexec.permits(entries, "edge1", CMD, "container",
                                             containers=["shop-api"]))
        for containers in (None, [], ["blog-web"], ["shop-api", "blog-web"]):
            self.assertIsNone(vpsexec.permits(entries, "edge1", CMD, "container",
                                              containers=containers), containers)


GRANT_RUNBOOK = """version: 1
reason: "container grant tests"
expires: "2999-01-01"
shape: {steps: 2, hosts: [web1], break_glass: true}
runbooks:
  - hosts: [web1]
    cmd: "pkill -HUP nginx"
    where: container
    container: shop-api
    break_glass: true
    why: "step one: api only"
  - hosts: [web1]
    cmd: "pkill -HUP nginx"
    where: container
    break_glass: true
    why: "step two: any container (not granted below)"
"""


class ContainerGrantTest(tg._GrantHarness):

    def setUp(self):
        super().setUp()
        (self.policy_dir / "rb.yaml").write_text(GRANT_RUNBOOK)
        self.policy = vpsexecpolicy.load(
            policy_dir=self.policy_dir, deny_patterns=tv.DENY,
            governor_hosts=set(tv._policy()["hosts"]), host_re=probe.HOST_RE)

    def test_grant_step_naming_a_container_covers_only_it(self):
        path = self.mint("--steps", "1")
        self.assertEqual(self.use("web1", CMD, path, extra=["--in", "shop-api"]), 0)
        # blog-web is authorised by step 2 of the runbook, but the grant lists
        # only step 1, which names shop-api: the contract must refuse.
        self.ssh_calls = []
        with self.assertRaises(Refused) as cm:
            self.use("web1", CMD, path, extra=["--in", "blog-web"])
        self.assertIn("does not authorise this plan", str(cm.exception))
        self.assertEqual([c for _, c in self.ssh_calls if "pkill" in c], [])


if __name__ == "__main__":
    unittest.main()


WALK_RUNBOOK = """version: 1
expires: "2999-01-01"
reason: "walker container test"
shape: {steps: 1, hosts: [web1], break_glass: false}
runbooks:
  - hosts: [web1]
    cmd: "pkill -HUP nginx"
    where: container
    container: shop-web
    why: "C1: reload nginx in the shop container"
"""


class WalkerContainerTest(unittest.TestCase):
    """contrib/runbook-walker builds --in from the `container:` key."""

    def setUp(self):
        import test_contrib
        self.tc = test_contrib

    def _walk(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "c.yaml").write_text(body)
            stub, log = self.tc._stub_vpsexec(tmp)
            r = self.tc._walk("--policies", tmp, "--runbook", "c", "--vpsexec", str(stub),
                              "--artifacts", tmp, "--state-dir", str(Path(tmp) / "s"),
                              "--reason", "x")
            calls = log.read_text().splitlines() if log.exists() else []
        return r, calls

    def test_named_container_becomes_in(self):
        r, calls = self._walk(WALK_RUNBOOK)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        argv = __import__("json").loads(calls[0])
        self.assertEqual(argv[:2], ["web1", "pkill -HUP nginx"])
        self.assertEqual(argv[argv.index("--in") + 1], "shop-web")

    def test_unnamed_container_still_refuses_before_any_step(self):
        r, calls = self._walk(WALK_RUNBOOK.replace("    container: shop-web\n", ""))
        self.assertEqual(r.returncode, 2)
        self.assertIn("no container: key", r.stderr)
        self.assertEqual(calls, [])
