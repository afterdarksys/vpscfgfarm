"""Approval contracts (`vpsexec grant`) and the keystroke flush.

Hermetic: the harness is test_vpsexec's (ssh, docker ps, ~/.ssh/config, the
journal and telemetry are injected or redirected), and the grant directory and
key live in a temporary HOME-like directory. Nothing here reaches a fleet host.

Most tests prove a REFUSAL, and that a refused contract never falls back to
the typed phrase: the prompt in those tests fails the test if it is called.
"""
import contextlib
import datetime
import hashlib
import io
import json
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402  (module, not names: no re-collection)
from vpscfg import probe, vpsexec, vpsexecgrant, vpsexecpolicy  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

RUNBOOK = """version: 1
reason: "grant tests"
expires: "%s"
shape: {steps: 4, hosts: [web1, web2], break_glass: mixed}
runbooks:
  - hosts: [web1]
    cmd: "systemctl restart nginx"
    where: host
    break_glass: true
    why: "step one: restart nginx"
  - hosts: [web1, web2]
    cmd: "systemctl restart caddy"
    where: host
    break_glass: true
    why: "step two: restart caddy"
  - hosts: [web1]
    cmd: "systemctl stop nginx"
    where: host
    break_glass: true
    why: "undo step one (rollback only, if step one fails)"
  - hosts: [web1]
    cmd: "systemctl reload nginx"
    where: host
    break_glass: false
    why: "not break-glass"
"""


class _TTY:
    def isatty(self):
        return True


class _NoTTY:
    def isatty(self):
        return False


def _no_prompt(msg):
    raise AssertionError("prompted after a contract was given: %r" % msg)


class _GrantHarness(tv._Harness):

    def setUp(self):
        super().setUp()
        self.home = tempfile.TemporaryDirectory()
        base = Path(self.home.name) / ".vpscfg"
        self.grant_dir = base / "grants"
        self.key_path = base / "grant.key"
        self._real = (vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH,
                      vpsexecgrant._is_controlling_tty)
        vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH = self.grant_dir, self.key_path
        # The fake streams here stand in for a controlling terminal; the real
        # controlling-tty check is exercised in real ptys (ControllingTtyTest).
        vpsexecgrant._is_controlling_tty = lambda stream: stream.isatty()
        self.policy_dir = Path(self.home.name) / "policies"
        self.policy_dir.mkdir()
        self.write_runbook()

    def tearDown(self):
        (vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH,
         vpsexecgrant._is_controlling_tty) = self._real
        self.home.cleanup()
        super().tearDown()

    def write_runbook(self, expires="2999-01-01", extra="", steps=4):
        # `steps`: a reviewed edit that adds a step updates the shape with it.
        text = (RUNBOOK % expires).replace("shape: {steps: 4,", "shape: {steps: %d," % steps)
        (self.policy_dir / "rb.yaml").write_text(text + extra)
        self.policy = vpsexecpolicy.load(
            policy_dir=self.policy_dir, deny_patterns=tv.DENY,
            governor_hosts=set(tv._policy()["hosts"]), host_re=probe.HOST_RE)

    def mint(self, *flags, ttl="1h", now=None, name="rb"):
        """Mint through the CLI, as the operator would. Returns the path."""
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecgrant.cli(["new", name, "--ttl", ttl, "--run"] + list(flags),
                             self.policy, stream=_TTY(), now=now,
                             prompt=lambda m: "GRANT:%s:%s" % (name, ttl))
        paths = sorted(self.grant_dir.glob("*.json"), key=os.path.getmtime)
        return paths[-1]

    def mint_at(self, now, ttl="1h", **kw):
        fields = vpsexecgrant.select(self.policy, "rb", ttl, now=now, **kw)
        with contextlib.redirect_stdout(io.StringIO()):
            path, _ = vpsexecgrant.mint(fields)
        return path

    def use(self, hosts, cmd, contract, stream=None, extra=(), gov=None,
            mapdoc=None, ssh=None, flag="--approval-contract=%s"):
        argv = [hosts, cmd, "--break-glass", "--run", "--reason", "OPS-1"]
        if contract is not None:
            argv.append(flag % contract)
        with contextlib.redirect_stdout(io.StringIO()):
            return vpsexec.dispatch(
                argv + list(extra),
                guard=tv._guard(gov), prober=self.prober(), policy=self.policy,
                ssh=ssh or self.fake_ssh(), stream=stream or _TTY(), prompt=_no_prompt,
                blackout_runner=self.blackout_runner(unavailable=True), mapdoc=mapdoc)

    def digest_of(self, hosts, cmd):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexec.dispatch([hosts, cmd, "--break-glass", "--reason", "x"],
                             guard=tv._guard(), prober=self.prober(),
                             policy=self.policy, ssh=self.fake_ssh(), stream=_TTY(),
                             prompt=_no_prompt,
                             blackout_runner=self.blackout_runner(unavailable=True))
        return [l.split()[-1] for l in out.getvalue().splitlines()
                if l.startswith("plan-hash:")][0]

    def ran(self):
        return [(h, c) for h, c in self.ssh_calls if "systemctl" in c]

    def refuses(self, path, needle, hosts="web1", cmd="systemctl restart nginx",
                stream=None):
        with self.assertRaises(Refused) as cm:
            self.use(hosts, cmd, path, stream=stream)
        self.assertIn(needle, str(cm.exception))
        self.assertIn("Drop --approval-contract", str(cm.exception))
        self.assertEqual(self.ran(), [], "a refused contract reached a host")
        refused = [e for e in self.events() if e["event"] == "grant_refused"]
        self.assertTrue(refused, "refusal was not journaled")
        return str(cm.exception)

    def load(self, path):
        return json.loads(Path(path).read_text())

    def reseal(self, path, grant):
        """Rewrite a grant WITH a valid MAC — models someone holding the key,
        so the checks behind the MAC are tested on their own."""
        grant["mac"] = vpsexecgrant._mac(vpsexecgrant.load_key(), grant)
        Path(path).write_text(json.dumps(grant))
        os.chmod(path, 0o600)


# ===========================================================================
# minting
# ===========================================================================

class GrantMintTest(_GrantHarness):

    def test_plan_only_writes_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexecgrant.cli(["new", "rb", "--ttl", "1h"], self.policy,
                                  stream=_TTY(), prompt=_no_prompt)
        self.assertEqual(rc, 0)
        self.assertIn("systemctl restart nginx", out.getvalue())
        self.assertIn("Nothing was written", out.getvalue())
        self.assertFalse(self.grant_dir.exists())
        self.assertFalse(self.key_path.exists())

    def test_mint_writes_private_files_and_journals(self):
        path = self.mint()
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.grant_dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.key_path).st_mode & 0o777, 0o600)
        self.assertEqual(len(self.key_path.read_bytes()), 32)
        g = self.load(path)
        self.assertEqual(set(g), vpsexecgrant.TOP_KEYS)
        self.assertRegex(g["session_id"], r"^[0-9a-f]{32}$")
        self.assertRegex(g["approval_code"], r"^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$")
        # Rollback (3) and non-break-glass (4) are left out by default.
        self.assertEqual([s["index"] for s in g["steps"]], [1, 2])
        self.assertEqual(g["hosts"], ["web1", "web2"])
        minted = [e for e in self.events() if e["event"] == "grant_minted"]
        self.assertEqual(minted[0]["session_id"], g["session_id"])
        self.assertNotIn(g["mac"], json.dumps(self.events()))

    def test_mint_without_a_tty_refuses(self):
        with self.assertRaises(Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexecgrant.cli(["new", "rb", "--ttl", "1h", "--run"], self.policy,
                                 stream=_NoTTY(), prompt=lambda m: "GRANT:rb:1h")
        self.assertEqual(list(self.grant_dir.glob("*.json")) if self.grant_dir.exists()
                         else [], [])

    def test_mint_with_the_wrong_phrase_refuses(self):
        with self.assertRaises(Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexecgrant.cli(["new", "rb", "--ttl", "1h", "--run"], self.policy,
                                 stream=_TTY(), prompt=lambda m: "GRANT:rb:3h")
        self.assertFalse(self.grant_dir.exists())

    def test_only_the_allowed_ttls(self):
        for bad in ("2h", "48h", "1d", "0", "", "15M"):
            with self.assertRaises(Refused, msg=bad):
                vpsexecgrant.select(self.policy, "rb", bad)
        for good in ("15m", "30m", "1h", "3h", "6h", "12h", "24h"):
            vpsexecgrant.select(self.policy, "rb", good)

    def test_rollback_step_needs_include_rollback(self):
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.select(self.policy, "rb", "1h", steps="3")
        self.assertIn("--include-rollback", str(cm.exception))
        fields = vpsexecgrant.select(self.policy, "rb", "1h", steps="1-3",
                                     include_rollback=True)
        self.assertEqual([s["index"] for s in fields["steps"]], [1, 2, 3])
        self.assertTrue(fields["options"]["include_rollback"])

    def test_rollback_field_needs_include_rollback_too(self):
        """`rollback: true` is the structured marker; its why need not say so."""
        self.write_runbook(extra='  - hosts: [web1]\n    cmd: "systemctl start nginx"\n'
                                 '    where: host\n    break_glass: true\n'
                                 '    why: "R: remove it again"\n    rollback: true\n',
                          steps=5)
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.select(self.policy, "rb", "1h", steps="5")
        self.assertIn("--include-rollback", str(cm.exception))
        fields = vpsexecgrant.select(self.policy, "rb", "1h", steps="5",
                                     include_rollback=True)
        self.assertEqual([s["index"] for s in fields["steps"]], [5])

    def test_contract_minted_while_live_is_refused_after_the_file_lapses(self):
        """Same bytes (so the sha256 binding still matches); only the day moved."""
        contract = self.mint()
        self.policy = vpsexecpolicy.load(
            policy_dir=self.policy_dir, deny_patterns=tv.DENY, today="3000-01-01",
            governor_hosts=set(tv._policy()["hosts"]), host_re=probe.HOST_RE)
        self.assertEqual(self.policy["runbooks"], [])
        with self.assertRaises(Refused) as cm:
            self.use("web1", "systemctl restart nginx", contract)
        self.assertIn("not authorised", str(cm.exception))
        self.assertEqual(self.ran(), [], "a lapsed runbook's contract reached a host")

    def test_lapsed_runbook_file_cannot_be_granted(self):
        self.write_runbook(expires="2020-01-01")
        with self.assertRaises(Refused):
            vpsexecgrant.select(self.policy, "rb", "1h", steps="1")

    def test_non_break_glass_step_cannot_be_granted(self):
        with self.assertRaises(Refused):
            vpsexecgrant.select(self.policy, "rb", "1h", steps="4")

    def test_step_out_of_range_refuses(self):
        with self.assertRaises(Refused):
            vpsexecgrant.select(self.policy, "rb", "1h", steps="1-9")

    def test_hosts_outside_the_runbook_refuse(self):
        with self.assertRaises(Refused):
            vpsexecgrant.select(self.policy, "rb", "1h", hosts="web3")

    def test_unknown_runbook_refuses(self):
        with self.assertRaises(Refused):
            vpsexecgrant.select(self.policy, "nope", "1h")

    def test_grant_may_not_outlive_its_runbook_policy(self):
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        self.write_runbook(expires=today)
        late = datetime.datetime.now(datetime.timezone.utc).replace(
            hour=23, minute=0, second=0, microsecond=0)
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.select(self.policy, "rb", "24h", now=late)
        self.assertIn("expires", str(cm.exception))


# ===========================================================================
# use
# ===========================================================================

class GrantUseTest(_GrantHarness):

    def test_valid_contract_replaces_the_phrase(self):
        path = self.mint()
        g = self.load(path)
        rc = self.use("web1", "systemctl restart nginx", path)
        self.assertEqual(rc, 0)
        self.assertEqual([h for h, _ in self.ran()], ["web1"])
        used = [e for e in self.events() if e["event"] == "grant_used"]
        self.assertEqual(len(used), 1)
        self.assertEqual((used[0]["session_id"], used[0]["approval_code"],
                          used[0]["step"]), (g["session_id"], g["approval_code"], 1))
        attempt = [e for e in self.events() if e["event"] == "mutation_attempt"][0]
        self.assertEqual(attempt["approval"], "approval-contract:%s" % g["session_id"])
        self.assertTrue([e for e in self.events() if e["event"] == "break_glass"])
        journal_text = json.dumps(self.events())
        self.assertNotIn(g["mac"], journal_text)
        self.assertNotIn(self.key_path.read_bytes().hex(), journal_text)

    def test_one_grant_covers_every_listed_step(self):
        path = self.mint()
        self.assertEqual(self.use("web1", "systemctl restart nginx", path), 0)
        self.assertEqual(self.use("web1,web2", "systemctl restart caddy", path), 0)

    def test_every_other_gate_still_runs(self):
        path = self.mint()
        # --reason is still required.
        with self.assertRaises(Refused) as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(
                    ["web1", "systemctl restart nginx", "--break-glass", "--run",
                     "--approval-contract=%s" % path],
                    guard=tv._guard(), prober=self.prober(), policy=self.policy,
                    ssh=self.fake_ssh(), stream=_TTY(), prompt=_no_prompt,
                    blackout_runner=self.blackout_runner(unavailable=True))
        self.assertIn("--reason", str(cm.exception))
        # The master switch still applies.
        with self.assertRaises(Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(
                    ["web1", "systemctl restart nginx", "--break-glass", "--run",
                     "--reason", "x", "--approval-contract=%s" % path],
                    guard=tv._guard(tv._policy(mutation=False)), prober=self.prober(),
                    policy=self.policy, ssh=self.fake_ssh(), stream=_TTY(),
                    prompt=_no_prompt,
                    blackout_runner=self.blackout_runner(unavailable=True))
        self.assertEqual(self.ran(), [])

    def test_empty_contract_flag_refuses_instead_of_prompting(self):
        for value in ("", "   "):
            with self.assertRaises(Refused) as cm:
                self.use("web1", "systemctl restart nginx", value)
            self.assertIn("--approval-contract needs a file path", str(cm.exception))
        with self.assertRaises(Refused):
            self.use("web1", "systemctl restart nginx", "",
                     flag="--approval-contract%s", extra=["--approval-contract", ""])
        self.assertEqual(self.ran(), [])

    def test_tilde_path_is_expanded(self):
        path = self.mint()
        real = os.environ.get("HOME")
        os.environ["HOME"] = str(Path(path).parent)
        try:
            self.assertEqual(self.use("web1", "systemctl restart nginx",
                                      "~/%s" % Path(path).name), 0)
        finally:
            if real is None:
                del os.environ["HOME"]
            else:
                os.environ["HOME"] = real

    def test_no_tty_refuses(self):
        self.refuses(self.mint(), "controlling TTY", stream=_NoTTY())

    def test_command_not_in_grant_refuses(self):
        path = self.mint("--steps", "1")
        self.refuses(path, "does not authorise", cmd="systemctl restart caddy")

    def test_rollback_step_not_granted_by_default(self):
        self.refuses(self.mint(), "does not authorise", cmd="systemctl stop nginx")

    def test_host_outside_grant_refuses(self):
        path = self.mint("--steps", "2", "--hosts", "web1")
        self.refuses(path, "does not cover host", hosts="web1,web2",
                     cmd="systemctl restart caddy")

    def test_tampered_field_refuses(self):
        path = self.mint("--steps", "1")
        g = self.load(path)
        g["hosts"] = ["web1", "web2", "web3"]
        Path(path).write_text(json.dumps(g))
        self.refuses(path, "MAC")

    def test_hand_added_step_refuses(self):
        path = self.mint("--steps", "1")
        g = self.load(path)
        g["steps"].append(dict(g["steps"][0], index=3, cmd="systemctl stop nginx"))
        Path(path).write_text(json.dumps(g))
        self.refuses(path, "MAC", cmd="systemctl stop nginx")

    def test_wrong_key_refuses(self):
        path = self.mint()
        os.chmod(self.key_path, 0o600)
        self.key_path.write_bytes(os.urandom(32))
        self.refuses(path, "MAC")

    def test_missing_key_refuses(self):
        path = self.mint()
        self.key_path.unlink()
        self.refuses(path, "grant key")

    def test_missing_field_refuses(self):
        path = self.mint()
        g = self.load(path)
        del g["operator"]
        self.reseal(path, g)
        self.refuses(path, "missing")

    def test_extra_field_refuses(self):
        path = self.mint()
        g = self.load(path)
        g["allow_all"] = True
        self.reseal(path, g)
        self.refuses(path, "unknown")

    def test_extra_nested_field_refuses(self):
        path = self.mint()
        g = self.load(path)
        g["steps"][0]["hosts"] = ["web3"]
        self.reseal(path, g)
        self.refuses(path, "step 1 key set")

    def test_duplicate_json_key_refuses(self):
        path = self.mint()
        text = Path(path).read_text()
        Path(path).write_text(text.replace('"ttl": "1h"', '"ttl": "1h", "ttl": "24h"'))
        self.refuses(path, "not valid JSON")

    def test_expired_refuses(self):
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
        self.refuses(self.mint_at(past), "expired")

    def test_future_issued_at_refuses(self):
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)
        self.refuses(self.mint_at(future), "in the future")

    def test_bad_ttl_refuses(self):
        path = self.mint()
        g = self.load(path)
        g["ttl"] = "2h"
        self.reseal(path, g)
        self.refuses(path, "ttl")

    def test_ttl_expiry_mismatch_refuses(self):
        path = self.mint(ttl="1h")
        g = self.load(path)
        g["ttl"] = "30m"
        self.reseal(path, g)
        self.refuses(path, "does not equal its ttl")

    def test_extended_expiry_refuses(self):
        path = self.mint(ttl="1h")
        g = self.load(path)
        issued = vpsexecgrant._parse_time(g["issued_at"], "issued_at")
        g["expires_at"] = vpsexecgrant._fmt(issued + datetime.timedelta(hours=24))
        self.reseal(path, g)
        self.refuses(path, "does not equal its ttl")

    def test_runbook_edited_after_mint_refuses(self):
        path = self.mint()
        self.write_runbook(extra="# a reviewed edit\n")
        self.refuses(path, "changed since this grant was minted")

    def test_step_index_moved_in_runbook_refuses(self):
        """The grant names step 1; a reseal pointing it at step 2's slot with
        step 1's command must not match a different runbook entry."""
        path = self.mint("--steps", "1")
        g = self.load(path)
        g["steps"][0]["index"] = 2
        self.reseal(path, g)
        self.refuses(path, "does not authorise")

    def test_revoked_refuses_permanently(self):
        path = self.mint()
        sid = self.load(path)["session_id"]
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecgrant.cli(["revoke", sid[:8]], self.policy, stream=_TTY(),
                             prompt=lambda m: "REVOKE:%s" % sid[:8])
        self.assertTrue([e for e in self.events() if e["event"] == "grant_revoked"
                         and e["session_id"] == sid])
        self.refuses(path, "revoked")
        self.assertEqual(os.stat(self.grant_dir / "revocations.jsonl").st_mode & 0o777,
                         0o600)

    def test_revoke_needs_tty_and_phrase(self):
        path = self.mint()
        sid = self.load(path)["session_id"]
        for stream, typed in ((_NoTTY(), "REVOKE:%s" % sid[:8]), (_TTY(), "REVOKE:x")):
            with self.assertRaises(Refused):
                with contextlib.redirect_stdout(io.StringIO()):
                    vpsexecgrant.cli(["revoke", sid], self.policy, stream=stream,
                                     prompt=lambda m, t=typed: t)
        self.assertEqual(self.use("web1", "systemctl restart nginx", path), 0)

    def test_untrusted_revocations_file_fails_closed(self):
        path = self.mint()
        rev = self.grant_dir / "revocations.jsonl"
        rev.write_text("not json\n")
        os.chmod(rev, 0o600)
        self.refuses(path, "revocations file")

    def test_oversized_file_refuses(self):
        path = self.mint()
        g = self.load(path)
        Path(path).write_text(json.dumps(g) + " " * (vpsexecgrant.MAX_BYTES + 1))
        self.refuses(path, "bytes")

    def test_group_readable_grant_refuses(self):
        path = self.mint()
        os.chmod(path, 0o644)
        self.refuses(path, "mode 644")

    def test_group_readable_grant_dir_refuses(self):
        path = self.mint()
        os.chmod(self.grant_dir, 0o755)
        self.refuses(path, "group/world accessible")

    def test_group_readable_key_refuses(self):
        path = self.mint()
        os.chmod(self.key_path, 0o644)
        self.refuses(path, "not 600")

    def test_symlinked_grant_refuses(self):
        path = self.mint()
        link = self.grant_dir / "link.json"
        link.symlink_to(path)
        self.refuses(link, "unreadable")

    def test_invalid_json_refuses(self):
        path = self.mint()
        Path(path).write_text("{not json")
        self.refuses(path, "not valid JSON")

    def test_invalid_contract_never_falls_back_to_the_prompt(self):
        """_no_prompt fails the test if called; refuses() asserts nothing ran."""
        path = self.mint()
        Path(path).write_text("{}")
        os.chmod(path, 0o600)
        self.refuses(path, "key set")

    def test_plan_without_elevation_still_needs_a_listed_step(self):
        """No elevation no longer refuses by itself (test_grant_noelevation.py
        covers that path); an unlisted command still does."""
        path = self.mint()
        g = self.load(path)
        plan = {"break_glass": False, "command": "systemctl restart nginx",
                "placement": "host", "hosts": ["web1"]}
        self.assertEqual(vpsexecgrant.authorize(g, plan, self.policy)["index"], 1)
        plan["command"] = "systemctl reload nginx"
        with self.assertRaises(Refused):
            vpsexecgrant.authorize(g, plan, self.policy)


class GrantIntrospectionTest(_GrantHarness):

    def _cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexecgrant.cli(list(argv), self.policy, stream=_TTY())
        return rc, out.getvalue()

    def test_show_valid_and_invalid(self):
        path = self.mint()
        rc, out = self._cli("show", str(path))
        self.assertEqual(rc, 0)
        self.assertIn("VALID", out)
        self.assertNotIn(self.load(path)["mac"], out)
        os.chmod(path, 0o644)
        rc, out = self._cli("show", str(path))
        self.assertEqual(rc, 1)
        self.assertIn("INVALID", out)

    def test_list_shows_active_expired_and_revoked(self):
        active = self.mint()
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
        expired = self.mint_at(past)
        revoked = self.mint()
        sid = self.load(revoked)["session_id"]
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecgrant.cli(["revoke", sid], self.policy, stream=_TTY(),
                             prompt=lambda m: "REVOKE:%s" % sid[:8])
        rc, out = self._cli("list")
        self.assertEqual(rc, 0)
        rows = dict((line.split()[1], line.split()[0])
                    for line in out.splitlines() if line.strip())
        self.assertEqual(rows[self.load(active)["session_id"][:8]], "ACTIVE")
        self.assertEqual(rows[Path(expired).stem[:8]], "EXPIRED")
        self.assertEqual(rows[sid[:8]], "REVOKED")

    def test_grant_is_a_reserved_verb(self):
        self.assertIn("grant", vpsexec.RESERVED_VERBS)

    def test_outer_door_judges_grant_as_local_not_a_host(self):
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader("vpsexec_door", str(REPO / "vpsexec"))
        spec = importlib.util.spec_from_loader("vpsexec_door", loader)
        door = importlib.util.module_from_spec(spec)
        loader.exec_module(door)
        gov = tv._policy()
        judged = door.judge(gov, ["grant", "new", "rb", "--ttl", "1h", "--run"])
        self.assertEqual((judged["hosts"], judged["read_only"], judged["introspect"]),
                         ([], True, "grant"))
        # The floor sweep still runs over a grant's argv.
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                door.judge(gov, ["grant", "new", "volume prune", "--ttl", "1h"])


# ===========================================================================
# review fixes (M1 is ControllingTtyTest below; L1/L5 are in GrantUseTest)
# ===========================================================================

@contextlib.contextmanager
def _deadline(seconds=5):
    """A FIFO that blocks would hang the suite; fail the test instead."""
    def _boom(*_):
        raise AssertionError("blocked — a FIFO was opened for reading")
    old = signal.signal(signal.SIGALRM, _boom)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


class ReviewFixTest(_GrantHarness):

    def test_lone_surrogate_is_invalid_not_a_crash(self):
        good = self.mint()
        g = self.load(good)
        bad = self.grant_dir / ("f" * 32 + ".json")
        g["operator"] = "\ud800"
        bad.write_text(json.dumps(g))  # ensure_ascii: written as \ud800
        os.chmod(bad, 0o600)
        self.refuses(bad, "")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexecgrant.cli(["list"], self.policy, stream=_TTY())
        rows = [l.split()[:2] for l in out.getvalue().splitlines() if l.strip()]
        self.assertIn(["INVALID", "f" * 8], rows)
        self.assertIn(["ACTIVE", g["session_id"][:8]], rows)
        # Even sealed by the key holder, a surrogate canonicalises without error.
        self.assertTrue(vpsexecgrant.canonical(g))

    def test_grant_paths_ignore_HOME(self):
        """`HOME=/tmp/h` with a copied key must not find an empty revocations
        file: the base directory comes from the password database."""
        import pwd
        fake = tempfile.mkdtemp()
        out = subprocess.run(
            [sys.executable, "-c", "import sys; sys.path.insert(0, %r); "
             "from vpscfg import vpsexecgrant as g; print(g.GRANT_DIR); print(g.KEY_PATH)"
             % str(REPO)],
            env=dict(os.environ, HOME=fake), capture_output=True, text=True, check=True)
        home = pwd.getpwuid(os.getuid()).pw_dir
        self.assertEqual(out.stdout.split(),
                         [home + "/.vpscfg/grants", home + "/.vpscfg/grant.key"])

    def test_revoked_grant_stays_revoked_under_another_HOME(self):
        path = self.mint()
        sid = self.load(path)["session_id"]
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecgrant.cli(["revoke", sid], self.policy, stream=_TTY(),
                             prompt=lambda m: "REVOKE:%s" % sid[:8])
        fake = Path(tempfile.mkdtemp())
        (fake / ".vpscfg").mkdir(mode=0o700)
        (fake / ".vpscfg" / "grant.key").write_bytes(self.key_path.read_bytes())
        with mock.patch.dict(os.environ, {"HOME": str(fake)}):
            self.refuses(path, "revoked")

    def test_fifo_contract_refuses_without_hanging(self):
        self.mint()
        fifo = self.grant_dir / "fifo.json"
        os.mkfifo(fifo, 0o600)
        with _deadline():
            self.refuses(fifo, "not a regular file")

    def test_fifo_revocations_refuses_without_hanging(self):
        path = self.mint()
        os.mkfifo(self.grant_dir / "revocations.jsonl", 0o600)
        with _deadline():
            self.refuses(path, "not a regular file")

    def test_symlinked_revocations_refuses(self):
        path = self.mint()
        target = self.grant_dir / "elsewhere"
        target.write_text("")
        os.chmod(target, 0o600)
        (self.grant_dir / "revocations.jsonl").symlink_to(target)
        self.refuses(path, "revocations file")

    def test_group_readable_revocations_refuses(self):
        path = self.mint()
        rev = self.grant_dir / "revocations.jsonl"
        rev.write_text("")
        os.chmod(rev, 0o644)
        self.refuses(path, "revocations file")

    def test_revocations_owned_by_someone_else_refuses(self):
        rev = self.grant_dir / "revocations.jsonl"
        self.mint()
        rev.write_text("")
        os.chmod(rev, 0o600)
        with mock.patch("os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(Refused):
                vpsexecgrant.revoked_ids(self.grant_dir)

    def test_ambiguous_revoke_prefix_refuses(self):
        for tail in ("0" * 24, "1" * 24):
            p = self.grant_dir / ("abcdef01" + tail + ".json")
            self.grant_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            p.write_text("{}")
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.cli(["revoke", "abcdef01"], self.policy, stream=_TTY(),
                             prompt=lambda m: "REVOKE:abcdef01")
        self.assertIn("matches 2", str(cm.exception))
        self.assertFalse((self.grant_dir / "revocations.jsonl").exists())

    def test_lockdown_mode_still_refuses(self):
        path = self.mint()
        with self.assertRaises(Refused):
            self.use("web1", "systemctl restart nginx", path,
                     gov=tv._policy(mode="lockdown"))
        self.assertEqual(self.ran(), [])
        self.assertFalse([e for e in self.events() if e["event"] == "grant_used"])

    def test_map_forbidding_break_glass_still_refuses(self):
        path = self.mint()
        mapdoc = {"path": "/x/.vpscfgfarm.map",
                  "constraints": {"deny_extra": [], "risky_extra": [],
                                  "forbid_break_glass": True,
                                  "require_blackout": False}}
        with self.assertRaises(Refused) as cm:
            self.use("web1", "systemctl restart nginx", path, mapdoc=mapdoc)
        self.assertIn("forbids --break-glass", str(cm.exception))
        self.assertEqual(self.ran(), [])

    def test_deny_extra_still_refuses(self):
        path = self.mint()
        (self.policy_dir / "deny.yaml").write_text(
            'version: 1\nreason: "t"\ndeny_extra: ["restart nginx"]\n')
        self.write_runbook()  # rb.yaml bytes unchanged, so the grant is still valid
        with self.assertRaises(Refused) as cm:
            self.use("web1", "systemctl restart nginx", path)
        self.assertIn("restart nginx", str(cm.exception))
        self.assertEqual(self.ran(), [])
        self.assertFalse([e for e in self.events() if e["event"] == "grant_used"])


class GrantAliasTest(_GrantHarness):
    ALIASES = tv._Harness.ALIASES + ("web1.example.internal",)

    def test_alias_host_name_is_covered_by_canonical_name(self):
        path = self.mint("--steps", "1")
        rc = self.use("web1", "systemctl restart nginx", path,
                      gov=tv._policy_aliased())
        self.assertEqual(rc, 0)
        self.assertEqual([h for h, _ in self.ran()], ["web1.example.internal"])


class GrantPushTest(_GrantHarness):

    def test_push_canonical_form_uses_the_contract(self):
        data = b"\x7fELF fake\n" * 20
        sha = hashlib.sha256(data).hexdigest()
        local = Path(self.home.name) / "diskwatch"
        local.write_bytes(data)
        (self.policy_dir / "push.yaml").write_text(
            'version: 1\nreason: "t"\nexpires: "2999-01-01"\n'
            'shape: {steps: 1, hosts: [web1], break_glass: true}\nrunbooks:\n'
            '  - hosts: [web1]\n    cmd: "vpscfg-push %s diskwatch"\n    where: host\n'
            '    break_glass: true\n    why: "stage diskwatch"\n' % sha)
        self.write_runbook()
        path = self.mint(name="push")
        uploads = []

        def ssh(host, cmd, timeout=None, connect_timeout=None, data=None):
            self.ssh_calls.append((host, cmd))
            if data is not None:
                uploads.append(data)
            if cmd.startswith("test -f"):
                return 1, "", ""
            if cmd.startswith("sha256sum"):
                return 0, "%s  /var/tmp/x\n" % hashlib.sha256(uploads[-1]).hexdigest(), ""
            return 0, "", ""
        with contextlib.redirect_stdout(io.StringIO()):
            rc = vpsexec.dispatch(
                ["web1", "push", str(local), "--sha256", sha, "--break-glass",
                 "--run", "--reason", "x", "--approval-contract=%s" % path],
                guard=tv._guard(), prober=self.prober(), policy=self.policy,
                ssh=ssh, stream=_TTY(), prompt=_no_prompt,
                blackout_runner=self.blackout_runner(unavailable=True))
        self.assertEqual(rc, 0)
        self.assertEqual(uploads, [data])
        used = [e for e in self.events() if e["event"] == "grant_used"]
        self.assertEqual(used[0]["command"], "vpscfg-push %s diskwatch" % sha)


class GrantPreflightTest(_GrantHarness):
    """vpsrun's up-front check: everything but the runbook sha256."""

    def test_valid_grant_preflights(self):
        path = self.mint()
        self.assertEqual(vpsexecgrant.preflight(path)["session_id"],
                         self.load(path)["session_id"])

    def test_tampered_or_revoked_grant_fails_preflight(self):
        path = self.mint()
        g = self.load(path)
        sid = g["session_id"]
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecgrant.cli(["revoke", sid], self.policy, stream=_TTY(),
                             prompt=lambda m: "REVOKE:%s" % sid[:8])
        with self.assertRaises(Refused):
            vpsexecgrant.preflight(path)
        g["hosts"].append("web3")
        Path(path).write_text(json.dumps(g))
        with self.assertRaises(Refused):
            vpsexecgrant.preflight(path)

    def test_check_without_policy_refuses(self):
        # Only preflight() may skip the runbook binding; check() never does.
        path = self.mint()
        with self.assertRaises(Refused):
            vpsexecgrant.check(path, None)


# ===========================================================================
# --approve no longer approves break-glass on its own
# ===========================================================================

class BreakGlassApproveTest(_GrantHarness):

    def test_approve_alone_refuses_break_glass(self):
        digest = self.digest_of("web1", "systemctl restart nginx")
        with self.assertRaises(Refused) as cm:
            self.use("web1", "systemctl restart nginx", None, stream=_NoTTY(),
                     extra=["--approve=%s" % digest])
        self.assertIn("--approve alone no longer approves break-glass", str(cm.exception))
        self.assertEqual(self.ran(), [])
        self.assertTrue([e for e in self.events() if e["event"] == "refused"
                         and "no longer approves" in e["reason"]])

    def test_approve_unit_refuses_break_glass_plan(self):
        plan = {"break_glass": True, "hosts": ["web1"], "all_flag": False}
        with self.assertRaises(Refused):
            vpsexec.approve(plan, "d" * 64, "d" * 64, stream=_NoTTY())

    def test_matching_approve_plus_valid_contract_passes(self):
        path = self.mint()
        sid = self.load(path)["session_id"]
        digest = self.digest_of("web1", "systemctl restart nginx")
        rc = self.use("web1", "systemctl restart nginx", path,
                      extra=["--approve=%s" % digest])
        self.assertEqual(rc, 0)
        attempt = [e for e in self.events() if e["event"] == "mutation_attempt"][0]
        self.assertEqual(attempt["approval"], "plan-hash+approval-contract:%s" % sid)

    def test_wrong_hash_plus_valid_contract_refuses(self):
        path = self.mint()
        with self.assertRaises(Refused) as cm:
            self.use("web1", "systemctl restart nginx", path,
                     extra=["--approve=%s" % ("0" * 64)])
        self.assertIn("does not match this plan", str(cm.exception))
        self.assertEqual(self.ran(), [])
        self.assertFalse([e for e in self.events() if e["event"] == "grant_used"])

    def test_approve_plus_invalid_contract_refuses(self):
        path = self.mint()
        os.chmod(path, 0o644)
        digest = self.digest_of("web1", "systemctl restart nginx")
        with self.assertRaises(Refused):
            self.use("web1", "systemctl restart nginx", path,
                     extra=["--approve=%s" % digest])
        self.assertEqual(self.ran(), [])

    def test_approve_plus_contract_still_needs_the_controlling_tty(self):
        path = self.mint()
        digest = self.digest_of("web1", "systemctl restart nginx")
        with self.assertRaises(Refused):
            self.use("web1", "systemctl restart nginx", path, stream=_NoTTY(),
                     extra=["--approve=%s" % digest])
        self.assertEqual(self.ran(), [])

    def _plain(self, extra, stream):
        with contextlib.redirect_stdout(io.StringIO()):
            return vpsexec.dispatch(
                ["edge1", "touch /tmp/x", "--run", "--reason", "x"] + extra,
                guard=tv._guard(), prober=self.prober(), policy=self.policy,
                ssh=self.fake_ssh(), stream=stream, prompt=_no_prompt,
                blackout_runner=self.blackout_runner(unavailable=True))

    def test_non_break_glass_approve_unchanged(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexec.dispatch(["edge1", "touch /tmp/x", "--reason", "x"],
                             guard=tv._guard(), prober=self.prober(),
                             policy=self.policy, ssh=self.fake_ssh(),
                             stream=_NoTTY(), prompt=_no_prompt,
                             blackout_runner=self.blackout_runner(unavailable=True))
        digest = [l.split()[-1] for l in out.getvalue().splitlines()
                  if l.startswith("plan-hash:")][0]
        self.assertEqual(self._plain(["--approve=%s" % digest], _NoTTY()), 0)
        self.assertIn(("edge1", "touch /tmp/x"),
                      [(h, c) for h, c in self.ssh_calls if "touch" in c])

    def test_non_break_glass_contract_plus_approve_refuses(self):
        path = self.mint()
        with self.assertRaises(Refused) as cm:
            self._plain(["--approve=%s" % ("0" * 64),
                         "--approval-contract=%s" % path], _TTY())
        self.assertIn("only replaces the break-glass phrase", str(cm.exception))


# ===========================================================================
# M1: the real controlling-terminal check, in real ptys
# ===========================================================================

_TTY_CHILD = r"""
import os, sys
sys.path.insert(0, %r)
from vpscfg import vpsexecgrant
from vpscfg.gates import Refused
if sys.argv[1:] == ["bg"]:  # a background process group on our own terminal
    pid = os.fork()  # the pty.fork child leads its session and cannot change pgrp
    if pid:
        os.waitpid(pid, 0)
        os._exit(0)
    os.setpgid(0, 0)
elif len(sys.argv) > 1:  # replace stdin with ANOTHER terminal: `< /dev/ttysNNN`
    fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOCTTY)
    os.dup2(fd, 0)
try:
    vpsexecgrant._require_tty(sys.stdin, "test")
    print("RESULT:OK")
except Refused:
    print("RESULT:REFUSED")
sys.stdout.flush()
""" % str(REPO)


def _read_all(fd, deadline=20):
    out, end = b"", time.time() + deadline
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    return out.decode("utf-8", "replace")


class ControllingTtyTest(unittest.TestCase):

    def _forked(self, *args):
        pid, fd = pty.fork()  # the child's controlling terminal is the slave
        if pid == 0:
            try:
                os.execv(sys.executable, [sys.executable, "-c", _TTY_CHILD] + list(args))
            finally:
                os._exit(127)
        out = _read_all(fd)
        os.waitpid(pid, 0)
        os.close(fd)
        return out

    def test_controlling_terminal_passes(self):
        self.assertIn("RESULT:OK", self._forked())

    def test_someone_elses_terminal_as_stdin_refuses(self):
        """`< /dev/ttysNNN`: a tty, owned by the operator, but not this
        process's controlling terminal."""
        master, slave = pty.openpty()
        try:
            self.assertIn("RESULT:REFUSED", self._forked(os.ttyname(slave)))
        finally:
            os.close(master)
            os.close(slave)

    def test_background_process_group_refuses(self):
        self.assertIn("RESULT:REFUSED", self._forked("bg"))

    def test_new_session_with_a_pty_as_stdin_refuses(self):
        master, slave = pty.openpty()
        try:
            out = subprocess.run([sys.executable, "-c", _TTY_CHILD], stdin=slave,
                                 capture_output=True, text=True, timeout=20,
                                 start_new_session=True)
        finally:
            os.close(master)
            os.close(slave)
        self.assertIn("RESULT:REFUSED", out.stdout)

    def test_pipe_refuses(self):
        out = subprocess.run([sys.executable, "-c", _TTY_CHILD], input="",
                             capture_output=True, text=True, timeout=20)
        self.assertIn("RESULT:REFUSED", out.stdout)


# ===========================================================================
# keystroke flush
# ===========================================================================

_CHILD = r"""
import os, sys, time
sys.path.insert(0, %r)
from vpscfg import vpsexec
from vpscfg.gates import Refused
if sys.argv[1] == "noflush":
    vpsexec.vpsexecgrant.flush_input = lambda stream: None
time.sleep(0.5)  # the parent's stray keystrokes land in the tty queue first
plan = {"break_glass": False, "all_flag": False, "hosts": ["a", "b"]}
try:
    print("RESULT:" + vpsexec.approve(plan, "0" * 64, None, stream=sys.stdin))
except Refused:
    print("RESULT:REFUSED")
sys.stdout.flush()
""" % str(REPO)


class KeystrokeFlushTest(unittest.TestCase):

    def _session(self, mode):
        pid, fd = pty.fork()
        if pid == 0:  # child: a real program on a real terminal
            try:
                os.execv(sys.executable, [sys.executable, "-c", _CHILD, mode])
            finally:
                os._exit(127)
        os.write(fd, b"stray\n")  # typed ahead, before any prompt exists
        out, answered, deadline = b"", False, time.time() + 20
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            if not answered and b"to approve" in out:
                os.write(fd, b"FLEET:2\n")
                answered = True
        os.waitpid(pid, 0)
        os.close(fd)
        return out.decode("utf-8", "replace")

    def test_typed_ahead_input_is_not_consumed_as_the_answer(self):
        self.assertIn("RESULT:interactive", self._session("flush"))

    def test_control_without_flush_the_stray_line_would_answer(self):
        """Proves the test above is load-bearing."""
        self.assertIn("RESULT:REFUSED", self._session("noflush"))

    def test_canary_continue_flushes_too(self):
        seen = []
        real = vpsexecgrant.flush_input
        vpsexecgrant.flush_input = seen.append
        try:
            stream = _TTY()
            vpsexec._confirm_continue(["b"], stream, lambda m: "CONTINUE")
        finally:
            vpsexecgrant.flush_input = real
        self.assertEqual(seen, [stream])

    def test_flush_is_harmless_on_non_terminals(self):
        vpsexecgrant.flush_input(_TTY())        # no fileno
        vpsexecgrant.flush_input(io.StringIO())  # not a tty


if __name__ == "__main__":
    unittest.main()
