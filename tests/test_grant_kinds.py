"""Grant kinds (short / reusable) and auto-pick.

Hermetic like test_vpsexec_grant: the grants dir and key live in a temporary
directory, the journal is redirected, ssh is faked. Nothing reaches a host and
nothing touches ~/.vpscfg.

Most tests prove a REFUSAL, and that nothing ran: the prompt fails the test
if it is called unless a test says otherwise.
"""
import contextlib
import datetime
import io
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
import test_vpsexec_grant as tg  # noqa: E402
import test_vpsrun as tr  # noqa: E402
from vpscfg import probe, vpsexec, vpsexecgrant, vpsexecpolicy  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

vpsrun = tr.vpsrun
NGINX = "systemctl restart nginx"
CADDY = "systemctl restart caddy"
AUTO = "--grant=auto"  # the only way plain vpsexec auto-picks (H4c)


class _KindsHarness(tg._GrantHarness):

    def mint_reusable(self, *flags, ttl="12h", name="rb", now=None):
        files = name.split(",")
        phrase = "REUSABLE-GRANT:%s:%s" % ("+".join(files), ttl)
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecgrant.cli(["new", name, "--kind", "reusable", "--ttl", ttl, "--run"]
                             + list(flags), self.policy, stream=tg._TTY(), now=now,
                             prompt=lambda m: phrase)
        return sorted(self.grant_dir.glob("ru_*.json"), key=os.path.getmtime)[-1]

    def reusable_at(self, now, ttl="12h", **kw):
        fields = vpsexecgrant.select_reusable(self.policy, "rb", ttl, now=now, **kw)
        with contextlib.redirect_stdout(io.StringIO()):
            path, _ = vpsexecgrant.mint(fields)
        return path

    def run_auto(self, hosts="web1", cmd=NGINX, flag=None, stream=None, prompt=None,
                 extra=()):
        """dispatch with NO contract flag (or `flag`), capturing stdout."""
        argv = [hosts, cmd, "--break-glass", "--run", "--reason", "OPS-1"]
        if flag:
            argv.append(flag)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexec.dispatch(
                argv + list(extra), guard=tv._guard(), prober=self.prober(),
                policy=self.policy, ssh=self.fake_ssh(), stream=stream or tg._TTY(),
                prompt=prompt or tg._no_prompt,
                blackout_runner=self.blackout_runner(unavailable=True))
        return rc, out.getvalue()

    def reload_policy(self, today=None):
        self.policy = vpsexecpolicy.load(
            policy_dir=self.policy_dir, deny_patterns=tv.DENY, today=today,
            governor_hosts=set(tv._policy()["hosts"]), host_re=probe.HOST_RE)


# ===========================================================================
# minting a reusable grant
# ===========================================================================

class ReusableMintTest(_KindsHarness):

    def test_plan_only_lists_what_it_would_authorise_and_writes_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexecgrant.cli(["new", "rb", "--kind", "reusable", "--ttl", "12h"],
                                  self.policy, stream=tg._TTY(), prompt=tg._no_prompt)
        text = out.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("kind    : reusable", text)
        self.assertIn("scope   : rb.yaml", text)
        self.assertIn(NGINX, text)
        self.assertIn(CADDY, text)
        self.assertIn("rollback: excluded", text)
        self.assertIn("not break_glass", text)
        self.assertIn("uses    : 0 of 50", text)
        self.assertIn("Nothing was written", text)
        self.assertFalse(self.grant_dir.exists())
        self.assertFalse(self.key_path.exists())

    def test_mint_writes_a_private_ru_grant_and_journals_its_kind(self):
        path = self.mint_reusable("--max-uses", "5")
        g = self.load(path)
        self.assertEqual(set(g), vpsexecgrant.REUSABLE_KEYS)
        self.assertEqual((g["version"], g["kind"], g["max_uses"]), (2, "reusable", 5))
        self.assertRegex(g["session_id"], r"^ru_[0-9a-f]{32}$")
        self.assertEqual(g["scope"]["files"], ["rb.yaml"])
        self.assertEqual(g["scope"]["git"]["commit"], self.git("rev-parse", "HEAD"))
        self.assertEqual(g["scope"]["git"]["blobs"],
                         {"rb.yaml": self.git("rev-parse", "HEAD:rb.yaml")})
        self.assertIsNone(g["release"])
        self.assertEqual(g["hosts"], ["web1", "web2"])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.grant_dir).st_mode & 0o777, 0o700)
        minted = [e for e in self.events() if e["event"] == "grant_minted"]
        self.assertEqual((minted[0]["kind"], minted[0]["max_uses"]), ("reusable", 5))
        self.assertNotIn(g["mac"], json.dumps(self.events()))

    def test_mint_needs_a_tty(self):
        with self.assertRaises(Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexecgrant.cli(["new", "rb", "--kind", "reusable", "--ttl", "12h",
                                  "--run"], self.policy, stream=tg._NoTTY(),
                                 prompt=lambda m: "REUSABLE-GRANT:rb:12h")
        self.assertFalse(self.grant_dir.exists())

    def test_mint_needs_its_own_distinct_phrase(self):
        for typed in ("GRANT:rb:12h", "REUSABLE-GRANT:rb:3h", "reusable-grant:rb:12h"):
            with self.assertRaises(Refused, msg=typed):
                with contextlib.redirect_stdout(io.StringIO()):
                    vpsexecgrant.cli(["new", "rb", "--kind", "reusable", "--ttl", "12h",
                                      "--run"], self.policy, stream=tg._TTY(),
                                     prompt=lambda m, t=typed: t)
        self.assertFalse(self.grant_dir.exists())

    def test_mint_flushes_pending_input_before_the_prompt(self):
        flushed = []
        real = vpsexecgrant.flush_input
        vpsexecgrant.flush_input = lambda stream: flushed.append(stream)
        try:
            self.mint_reusable()
        finally:
            vpsexecgrant.flush_input = real
        self.assertEqual(len(flushed), 1)

    def test_reusable_ttls(self):
        for bad in ("15m", "30m", "2h", "48h", "8d", ""):
            with self.assertRaises(Refused, msg=bad):
                vpsexecgrant.select_reusable(self.policy, "rb", bad)
        for good in ("1h", "3h", "6h", "12h", "24h", "72h", "7d"):
            vpsexecgrant.select_reusable(self.policy, "rb", good)
        # The short kind keeps its own, narrower set.
        for bad in ("72h", "7d"):
            with self.assertRaises(Refused):
                vpsexecgrant.select(self.policy, "rb", bad)

    def test_ttl_capped_by_the_policy_expiry(self):
        tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
        self.write_runbook(expires=tomorrow)
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.select_reusable(self.policy, "rb", "7d")
        self.assertIn("expires", str(cm.exception))

    def test_kind_specific_flags_refuse_on_the_other_kind(self):
        with self.assertRaises(Refused):
            vpsexecgrant.cli(["new", "rb", "--kind", "reusable", "--ttl", "12h",
                              "--steps", "1"], self.policy, stream=tg._TTY())
        with self.assertRaises(Refused):
            vpsexecgrant.cli(["new", "rb", "--ttl", "1h", "--max-uses", "3"],
                             self.policy, stream=tg._TTY())
        with self.assertRaises(Refused):
            vpsexecgrant.cli(["new", "rb", "--kind", "agent", "--ttl", "1h"],
                             self.policy, stream=tg._TTY())
        for bad in ("0", "-1", "501", "x", "1.5"):
            with self.assertRaises(Refused, msg=bad):
                vpsexecgrant.select_reusable(self.policy, "rb", "12h", max_uses=bad)

    def test_scope_hosts_must_be_reached_by_a_break_glass_step(self):
        with self.assertRaises(Refused):
            vpsexecgrant.select_reusable(self.policy, "rb", "12h", hosts="edge1")
        with self.assertRaises(Refused):
            vpsexecgrant.select_reusable(self.policy, "rb", "12h", hosts="@web")

    def test_there_is_no_verb_that_extends_widens_or_resets(self):
        path = self.mint_reusable("--max-uses", "1")
        for verb in ("reset", "extend", "widen", "renew", "edit"):
            with self.assertRaises(Refused, msg=verb):
                vpsexecgrant.cli([verb, str(path)], self.policy, stream=tg._TTY(),
                                 prompt=lambda m: "yes")


# ===========================================================================
# using a reusable grant
# ===========================================================================

class ReusableUseTest(_KindsHarness):

    def test_valid_reusable_grant_replaces_the_phrase_and_counts_the_use(self):
        path = self.mint_reusable("--max-uses", "3")
        g = self.load(path)
        self.assertEqual(self.use("web1", NGINX, path), 0)
        self.assertEqual([h for h, _ in self.ran()], ["web1"])
        used = [e for e in self.events() if e["event"] == "grant_used"]
        self.assertEqual((used[0]["kind"], used[0]["session_id"], used[0]["use"],
                          used[0]["max_uses"], used[0]["runbook"], used[0]["step"]),
                         ("reusable", g["session_id"], 1, 3, "rb.yaml", 1))
        ledger = self.grant_dir / (g["session_id"] + ".uses")
        self.assertEqual(os.stat(ledger).st_mode & 0o777, 0o600)
        self.assertEqual(vpsexecgrant.uses(g, grant_dir=self.grant_dir), 1)

    def test_survives_an_edit_to_the_runbook_that_kills_a_short_grant(self):
        short = self.mint()
        reusable = self.mint_reusable()
        self.write_runbook(extra="# a reviewed edit\n")
        self.refuses(short, "changed since this grant was minted")
        self.assertEqual(self.use("web1", NGINX, reusable), 0)

    def test_covers_only_break_glass_steps(self):
        # The door refuses a non-break-glass command on a frozen host before
        # any grant is consulted; at the grant layer it is not covered either,
        # elevation or not.
        g = vpsexecgrant.check(self.mint_reusable(), self.policy)
        plan = {"break_glass": False, "command": "systemctl reload nginx",
                "placement": "host", "hosts": ["web1"]}
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.authorize(g, plan, self.policy)
        self.assertIn("does not authorise", str(cm.exception))
        plan["command"] = NGINX
        self.assertEqual(vpsexecgrant.authorize(g, plan, self.policy)["index"], 1)

    def test_rollback_needs_include_rollback_at_mint(self):
        self.refuses(self.mint_reusable(), "does not authorise", cmd="systemctl stop nginx")
        with_rb = self.mint_reusable("--include-rollback")
        self.assertEqual(self.use("web1", "systemctl stop nginx", with_rb), 0)

    def test_break_glass_step_of_a_file_outside_the_scope_refuses(self):
        (self.policy_dir / "other.yaml").write_text(
            'version: 1\nreason: "t"\nexpires: "2999-01-01"\n'
            'shape: {steps: 1, hosts: [web1], break_glass: true}\nrunbooks:\n'
            '  - hosts: [web1]\n    cmd: "systemctl restart sshd"\n    where: host\n'
            '    break_glass: true\n    why: "another reviewed runbook"\n')
        self.write_runbook()
        path = self.mint_reusable()  # scope: rb.yaml only
        self.refuses(path, "does not authorise", cmd="systemctl restart sshd")
        both = self.mint_reusable(name="rb,other")
        self.assertEqual(self.load(both)["scope"]["files"], ["rb.yaml", "other.yaml"])
        self.assertEqual(self.use("web1", "systemctl restart sshd", both), 0)

    def test_plan_host_outside_the_scope_host_set_refuses(self):
        path = self.mint_reusable("--hosts", "web1")
        self.refuses(path, "does not cover host", hosts="web1,web2", cmd=CADDY)

    def test_refuses_once_max_uses_is_reached(self):
        path = self.mint_reusable("--max-uses", "2")
        self.assertEqual(self.use("web1", NGINX, path), 0)
        self.assertEqual(self.use("web1", NGINX, path), 0)
        before = len(self.ran())
        with self.assertRaises(Refused) as cm:
            self.use("web1", NGINX, path)
        self.assertIn("used 2 of 2", str(cm.exception))
        self.assertEqual(len(self.ran()), before, "a spent grant reached a host")
        self.assertTrue([e for e in self.events() if e["event"] == "grant_refused"])

    def test_deleting_the_ledger_does_not_reset_the_count(self):
        path = self.mint_reusable("--max-uses", "2")
        sid = self.load(path)["session_id"]
        self.use("web1", NGINX, path)
        self.use("web1", NGINX, path)
        (self.grant_dir / (sid + ".uses")).unlink()
        with self.assertRaises(Refused) as cm:
            self.use("web1", NGINX, path)
        self.assertIn("used 2 of 2", str(cm.exception))

    def test_a_ledger_alone_still_counts_without_the_journal(self):
        """Another checkout's journal: the ledger in the grants dir counts."""
        path = self.mint_reusable("--max-uses", "1")
        self.use("web1", NGINX, path)
        (Path(self.tmp.name) / "vpsexec.jsonl").unlink()
        with self.assertRaises(Refused) as cm:
            self.use("web1", NGINX, path)
        self.assertIn("used 1 of 1", str(cm.exception))

    def test_broken_journal_chain_fails_closed(self):
        path = self.mint_reusable()
        self.use("web1", NGINX, path)
        jpath = Path(self.tmp.name) / "vpsexec.jsonl"
        lines = jpath.read_text().splitlines()
        lines[0] = lines[0].replace('"grant_minted"', '"grant_mintedX"')
        jpath.write_text("\n".join(lines) + "\n")
        with self.assertRaises(Refused) as cm:
            self.use("web1", NGINX, path)
        self.assertIn("hash chain", str(cm.exception))

    def test_untrusted_ledger_fails_closed(self):
        path = self.mint_reusable()
        sid = self.load(path)["session_id"]
        ledger = self.grant_dir / (sid + ".uses")
        ledger.write_text("")
        os.chmod(ledger, 0o644)
        self.refuses(path, "use ledger")
        os.chmod(ledger, 0o600)
        ledger.write_text("garbage\n")
        self.refuses(path, "use ledger")
        ledger.unlink()
        ledger.write_text(json.dumps({"session_id": "ru_" + "0" * 32}) + "\n")
        os.chmod(ledger, 0o600)
        self.refuses(path, "use ledger")

    def test_use_needs_the_controlling_tty_and_counts_nothing_without_it(self):
        path = self.mint_reusable()
        self.refuses(path, "controlling TTY", stream=tg._NoTTY())
        sid = self.load(path)["session_id"]
        self.assertFalse((self.grant_dir / (sid + ".uses")).exists())

    def _dead_policy(self, path):
        """The grant itself refuses, and the door as a whole runs nothing."""
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.check(path, self.policy)
        self.assertIn("no loaded runbook policy", str(cm.exception))
        with self.assertRaises(Refused):
            self.use("web1", NGINX, path)
        self.assertEqual(self.ran(), [])
        self.assertFalse([e for e in self.events() if e["event"] == "grant_used"])

    def test_refuses_after_its_policy_expired(self):
        path = self.mint_reusable()
        self.reload_policy(today="3000-01-01")
        self._dead_policy(path)

    def test_refuses_after_its_policy_lost_its_shape(self):
        path = self.mint_reusable()
        self.write_runbook(steps=7)  # shape now disagrees with the file
        self.assertTrue([f for f in self.policy["files"] if f.get("misshapen")])
        self._dead_policy(path)

    def test_tampered_mac_refuses(self):
        path = self.mint_reusable("--max-uses", "2")
        g = self.load(path)
        g["max_uses"] = 500
        Path(path).write_text(json.dumps(g))
        self.refuses(path, "MAC")
        g = self.load(path)
        g["max_uses"], g["scope"]["files"] = 2, ["rb.yaml", "other.yaml"]
        Path(path).write_text(json.dumps(g))
        self.refuses(path, "MAC")

    def test_expired_refuses(self):
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
        self.refuses(self.reusable_at(past, ttl="1h"), "expired")

    def test_revoked_refuses(self):
        path = self.mint_reusable()
        sid = self.load(path)["session_id"]
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecgrant.cli(["revoke", vpsexecgrant.short_id(sid)], self.policy,
                             stream=tg._TTY(),
                             prompt=lambda m: "REVOKE:%s" % vpsexecgrant.short_id(sid))
        self.assertTrue(vpsexecgrant.short_id(sid).startswith("ru_"))
        self.refuses(path, "revoked")

    def test_reusable_ttl_outside_its_set_refuses_even_when_sealed(self):
        path = self.mint_reusable(ttl="1h")
        g = self.load(path)
        g["ttl"] = "15m"
        self.reseal(path, g)
        self.refuses(path, "ttl")


# ===========================================================================
# kind <-> id prefix, and version 1
# ===========================================================================

class KindPrefixTest(_KindsHarness):

    def test_reusable_kind_with_a_short_prefix_refuses(self):
        path = self.mint_reusable()
        g = self.load(path)
        g["session_id"] = "st_" + g["session_id"][3:]
        self.reseal(path, g)
        self.refuses(path, "does not match its kind")

    def test_short_kind_with_a_reusable_prefix_refuses(self):
        path = self.mint()
        g = self.load(path)
        g["session_id"] = "ru_" + g["session_id"][3:]
        self.reseal(path, g)
        self.refuses(path, "does not match its kind")

    def test_short_relabelled_reusable_refuses(self):
        path = self.mint()
        g = self.load(path)
        g["kind"] = "reusable"
        self.reseal(path, g)
        self.refuses(path, "key set")

    def test_unknown_kind_refuses(self):
        path = self.mint()
        g = self.load(path)
        g["kind"] = "agent"
        self.reseal(path, g)
        self.refuses(path, "kind")

    def test_v2_with_a_bare_hex_id_refuses(self):
        path = self.mint()
        g = self.load(path)
        g["session_id"] = g["session_id"][3:]
        self.reseal(path, g)
        self.refuses(path, "session_id is malformed")

    def test_v1_claiming_a_kind_refuses(self):
        path = self.mint()
        g = self.load(path)
        g["version"] = 1
        g["session_id"] = g["session_id"][3:]
        self.reseal(path, g)
        self.refuses(path, "unknown")

    def _as_v1(self):
        """A grant exactly as the previous release minted it."""
        path = self.mint()
        g = self.load(path)
        del g["kind"]
        g["version"] = 1
        g["session_id"] = g["session_id"][3:]
        os.unlink(path)
        v1 = self.grant_dir / (g["session_id"] + ".json")
        self.reseal(v1, g)
        return v1, g

    def test_old_v1_grant_still_works_as_short(self):
        v1, g = self._as_v1()
        self.assertEqual(self.use("web1", NGINX, v1), 0)
        used = [e for e in self.events() if e["event"] == "grant_used"][0]
        self.assertEqual((used["kind"], used["session_id"]), ("short", g["session_id"]))
        self.assertNotIn("use", used)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexecgrant.cli(["list"], self.policy, stream=tg._TTY())
        self.assertIn("ACTIVE   %s  short" % g["session_id"][:8], out.getvalue())

    def test_old_v1_grant_is_auto_picked_as_short(self):
        v1, g = self._as_v1()
        rc, out = self.run_auto(flag=AUTO)
        self.assertEqual(rc, 0)
        self.assertIn("auto-picked short %s" % g["session_id"][:8], out)

    def test_old_v1_grant_with_a_wrong_version_refuses(self):
        v1, g = self._as_v1()
        g["version"] = 3
        self.reseal(v1, g)
        self.refuses(v1, "version")

    def test_list_and_show_name_the_kind(self):
        self.mint()
        r = self.mint_reusable("--max-uses", "4")
        self.use("web1", NGINX, r)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexecgrant.cli(["list"], self.policy, stream=tg._TTY())
        rows = [l.split() for l in out.getvalue().splitlines() if l.strip()]
        kinds = sorted((row[1][:3], row[2]) for row in rows)
        self.assertEqual(kinds, [("ru_", "reusable"), ("st_", "short")])
        self.assertIn("1/4", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexecgrant.cli(["show", str(r)], self.policy, stream=tg._TTY())
        self.assertEqual(rc, 0)
        self.assertIn("kind    : reusable", out.getvalue())
        self.assertIn("uses    : 1 of 4", out.getvalue())

    def test_spent_reusable_lists_as_spent(self):
        r = self.mint_reusable("--max-uses", "1")
        self.use("web1", NGINX, r)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexecgrant.cli(["list"], self.policy, stream=tg._TTY())
        self.assertTrue(out.getvalue().strip().startswith("SPENT"))


# ===========================================================================
# auto-pick in vpsexec
# ===========================================================================

class AutoPickTest(_KindsHarness):

    def picked(self):
        return [e for e in self.events() if e["event"] == "grant_autopicked"]

    def test_grant_auto_picks_a_valid_grant_prints_and_journals_it(self):
        path = self.mint()
        g = self.load(path)
        rc, out = self.run_auto(flag=AUTO)
        self.assertEqual(rc, 0)
        self.assertIn("auto-picked short %s  code %s"
                      % (vpsexecgrant.short_id(g["session_id"]), g["approval_code"]), out)
        self.assertEqual(self.picked()[0]["session_id"], g["session_id"])
        self.assertEqual(self.picked()[0]["kind"], "short")
        used = [e for e in self.events() if e["event"] == "grant_used"]
        self.assertEqual(used[0]["session_id"], g["session_id"])
        self.assertEqual([h for h, _ in self.ran()], ["web1"])

    def test_grant_flag_auto_spelling(self):
        self.mint_reusable()
        for flag in ("--grant=auto", "--approval-contract=auto"):
            rc, out = self.run_auto(flag=flag)
            self.assertEqual(rc, 0)
            self.assertIn("auto-picked reusable", out)
        rc, out = self.run_auto(extra=["--grant", "auto"])
        self.assertEqual(rc, 0)

    def test_short_is_picked_before_reusable(self):
        self.mint_reusable()
        short = self.load(self.mint())
        self.run_auto(flag=AUTO)
        self.assertEqual(self.picked()[0]["session_id"], short["session_id"])

    def test_within_a_kind_the_soonest_expiring_is_picked(self):
        later = self.load(self.mint(ttl="3h"))
        sooner = self.load(self.mint(ttl="1h"))
        self.assertLess(sooner["expires_at"], later["expires_at"])
        self.run_auto(flag=AUTO)
        self.assertEqual(self.picked()[0]["session_id"], sooner["session_id"])

    def test_equal_rank_picks_the_lowest_id_and_says_so(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        a = self.load(self.mint(now=now))
        b = self.load(self.mint(now=now))
        rc, out = self.run_auto(flag=AUTO)
        lowest = min(a["session_id"], b["session_id"])
        self.assertEqual(self.picked()[0]["session_id"], lowest)
        self.assertEqual(self.picked()[0]["ties"], 1)
        self.assertIn("ranked equal", out)

    def test_never_picks_an_invalid_grant(self):
        """A tampered, an expired and a revoked short grant (all ranked before
        any reusable) are skipped; the valid reusable one is used."""
        tampered = self.mint(ttl="15m")
        g = self.load(tampered)
        g["hosts"] = ["web1", "web2", "web3"]
        Path(tampered).write_text(json.dumps(g))
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
        self.mint_at(past)
        revoked = self.load(self.mint(ttl="30m"))["session_id"]
        with contextlib.redirect_stdout(io.StringIO()):
            vpsexecgrant.cli(["revoke", revoked], self.policy, stream=tg._TTY(),
                             prompt=lambda m: "REVOKE:%s" % vpsexecgrant.short_id(revoked))
        good = self.load(self.mint_reusable())
        rc, out = self.run_auto(flag=AUTO)
        self.assertEqual(rc, 0)
        self.assertEqual(self.picked()[0]["session_id"], good["session_id"])
        self.assertEqual(self.picked()[0]["candidates"], 1)

    def test_never_picks_a_grant_that_does_not_cover_the_plan(self):
        self.mint("--steps", "2")  # caddy only
        # Nothing covers nginx: the typed phrase path runs, exactly as before.
        prompts = []

        def prompt(msg):
            prompts.append(msg)
            return "wrong"
        with self.assertRaises(Refused) as cm:
            self.run_auto(prompt=prompt)
        self.assertIn("approval text did not match", str(cm.exception))
        self.assertEqual(len(prompts), 1)
        self.assertIn("BREAK-GLASS", prompts[0])
        self.assertEqual(self.picked(), [])
        self.assertEqual(self.ran(), [])

    def test_no_grants_at_all_behaves_exactly_as_before(self):
        typed = []

        def prompt(msg):
            typed.append(msg)
            return msg.split("Type ", 1)[1].split(" ", 1)[0]
        rc, _ = self.run_auto(prompt=prompt)
        self.assertEqual(rc, 0)
        self.assertIn("BREAK-GLASS", typed[0])
        self.assertFalse([e for e in self.events()
                          if e["event"].startswith("grant_")])

    def test_explicit_auto_refuses_when_nothing_matches_and_never_prompts(self):
        self.mint("--steps", "2")
        with self.assertRaises(Refused) as cm:
            self.run_auto(flag="--approval-contract=auto")
        self.assertIn("no valid grant", str(cm.exception))
        self.assertEqual(self.ran(), [])

    def test_spent_reusable_is_not_offered(self):
        r = self.mint_reusable("--max-uses", "1")
        self.use("web1", NGINX, r)
        with self.assertRaises(Refused):
            self.run_auto(flag="--grant=auto")
        self.assertEqual(len(self.ran()), 1)

    def test_approve_without_tty_still_refuses_with_a_matching_grant(self):
        self.mint()
        digest = self.digest_of("web1", NGINX)
        with self.assertRaises(Refused) as cm:
            self.run_auto(stream=tg._NoTTY(), flag=AUTO, extra=["--approve=%s" % digest])
        self.assertIn("controlling TTY", str(cm.exception))
        self.assertEqual(self.ran(), [])

    def test_every_other_gate_still_runs_on_an_auto_pick(self):
        self.mint()
        with self.assertRaises(Refused):  # master switch off
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(
                    ["web1", NGINX, "--break-glass", "--run", "--reason", "x"],
                    guard=tv._guard(tv._policy(mutation=False)), prober=self.prober(),
                    policy=self.policy, ssh=self.fake_ssh(), stream=tg._TTY(),
                    prompt=tg._no_prompt,
                    blackout_runner=self.blackout_runner(unavailable=True))
        with self.assertRaises(Refused) as cm:  # --reason
            with contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(
                    ["web1", NGINX, "--break-glass", "--run"],
                    guard=tv._guard(), prober=self.prober(), policy=self.policy,
                    ssh=self.fake_ssh(), stream=tg._TTY(), prompt=tg._no_prompt,
                    blackout_runner=self.blackout_runner(unavailable=True))
        self.assertIn("--reason", str(cm.exception))
        self.assertEqual(self.ran(), [])
        self.assertEqual(self.picked(), [])

    def test_loose_grants_dir_refuses_rather_than_skipping(self):
        self.mint()
        os.chmod(self.grant_dir, 0o755)
        with self.assertRaises(Refused) as cm:
            self.run_auto()
        self.assertIn("group/world accessible", str(cm.exception))
        self.assertEqual(self.ran(), [])

    def test_plan_mode_lists_valid_grants_and_counts_nothing(self):
        r = self.load(self.mint_reusable("--max-uses", "9"))
        s = self.load(self.mint())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vpsexec.dispatch(["web1", NGINX, "--break-glass", "--reason", "x"],
                             guard=tv._guard(), prober=self.prober(),
                             policy=self.policy, ssh=self.fake_ssh(),
                             stream=tg._TTY(), prompt=tg._no_prompt,
                             blackout_runner=self.blackout_runner(unavailable=True))
        found = vpsrun.door_grants(out.getvalue())
        self.assertEqual(list(found), [s["session_id"], r["session_id"]])
        self.assertEqual(found[r["session_id"]]["left"], 9)
        self.assertEqual(found[s["session_id"]]["code"], s["approval_code"])
        self.assertFalse(list(self.grant_dir.glob("*.uses")))
        self.assertEqual(self.picked(), [])

    def test_explicit_contract_still_wins_over_auto(self):
        self.mint_reusable()
        short = self.mint()
        rc = self.use("web1", NGINX, short)
        self.assertEqual(rc, 0)
        self.assertEqual(self.picked(), [])


# ===========================================================================
# vpsrun: one grant per play, chosen before anything runs
# ===========================================================================

def _line(sid, kind, until="2026-10-12T20:00:00Z", code="ABCD-EFGH-JK23", left=None):
    return "            %s %s until %s code %s%s" % (
        sid, kind, until, code, "" if left is None else " uses-left %d" % left)


ST = "st_" + "1" * 32
ST2 = "st_" + "0" * 32
RU = "ru_" + "2" * 32


class ListingDoor(tr.BreakGlassDoor):
    """BreakGlassDoor whose plan for each break-glass step lists grants."""

    def __init__(self, listings, **kw):
        super().__init__(**kw)
        self.listings = listings  # cmd -> [lines]

    def __call__(self, argv):
        rc, out = super().__call__(argv)
        if "--run" in argv or rc != 0 or argv[0] != "web1":
            return rc, out
        lines = self.listings.get(argv[1], [])
        head = ("  grants  : %d valid for this plan (auto-pick order):" % len(lines)
                if lines else "  grants  : none valid for this plan")
        return rc, out + "\n".join([head] + lines) + "\n"


class VpsrunAutoPickTest(unittest.TestCase):
    setUp, tearDown = tr.VpsrunTest.setUp, tr.VpsrunTest.tearDown
    _play = tr.VpsrunTest._play

    def go(self, listings, contract=None, grant=None, typed=None):
        door = ListingDoor(listings, digests=(tr.H1, tr.H2, tr.H3), run_rcs=(0, 0, 0))
        loaded = []

        def load_grant(path):
            loaded.append(path)
            return grant or {"kind": "reusable" if Path(path).name.startswith("ru_")
                             else "short", "session_id": Path(path).stem,
                             "hosts": ["web1"], "steps": tr.GRANT["steps"]}
        typed = typed or (lambda m: m.split("Type ", 1)[1].split(" ", 1)[0])
        real = vpsexecgrant.GRANT_DIR
        vpsexecgrant.GRANT_DIR = Path("/grants-for-test")
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = vpsrun.run_play(self._play(tr.BG_PLAY), door, typed, tr.TTY(),
                                     contract=contract, load_grant=load_grant)
        finally:
            vpsexecgrant.GRANT_DIR = real
        return rc, door, loaded, out.getvalue()

    def runs(self, door):
        return [c for c in door.calls if "--run" in c]

    def test_one_reusable_grant_covers_the_play(self):
        listing = {NGINX: [_line(RU, "reusable", left=5)],
                   CADDY: [_line(RU, "reusable", left=5)]}
        rc, door, loaded, out = self.go(listing)
        self.assertEqual(rc, 0)
        want = "--approval-contract=/grants-for-test/%s.json" % RU
        runs = self.runs(door)
        self.assertEqual([want in r for r in runs], [True, False, True])
        self.assertEqual(loaded, ["/grants-for-test/%s.json" % RU])
        self.assertIn("auto-picked reusable ru_22222222", out)
        approved = [e for e in __import__("vpscfg.vpsexeclog").vpsexeclog.read()
                    if e["event"] == "play_approved"][0]
        self.assertEqual((approved["grant"]["session_id"], approved["grant"]["auto"],
                          approved["grant"]["kind"]), (RU, True, "reusable"))

    def test_short_before_reusable_then_soonest(self):
        lines = [_line(RU, "reusable", until="2026-10-12T19:00:00Z", left=9),
                 _line(ST, "short", until="2026-10-12T21:00:00Z"),
                 _line(ST2, "short", until="2026-10-12T20:00:00Z")]
        rc, door, _, out = self.go({NGINX: lines, CADDY: lines})
        self.assertEqual(rc, 0)
        self.assertIn("--approval-contract=/grants-for-test/%s.json" % ST2,
                      self.runs(door)[0])

    def test_equal_rank_is_deterministic_and_printed(self):
        lines = [_line(ST, "short"), _line(ST2, "short")]
        rc, door, _, out = self.go({NGINX: lines, CADDY: list(reversed(lines))})
        self.assertIn(ST2, self.runs(door)[0][-1])
        self.assertIn("ranked equal", out)

    def test_grant_not_covering_every_step_refuses_the_whole_play(self):
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go({NGINX: [_line(ST, "short")], CADDY: [_line(ST2, "short")]})
        self.assertIn("step(s) 1, 3 are break-glass", str(cm.exception))

    def test_nothing_runs_when_no_grant_covers_every_step(self):
        door = ListingDoor({NGINX: [_line(ST, "short")]}, digests=(tr.H1, tr.H2, tr.H3))
        with self.assertRaises(vpsrun.Refused):
            with contextlib.redirect_stdout(io.StringIO()):
                vpsrun.run_play(self._play(tr.BG_PLAY), door, lambda m: "x", tr.TTY())
        self.assertEqual(self.runs(door), [])

    def test_reusable_without_a_use_per_step_is_not_picked(self):
        lines = [_line(RU, "reusable", left=1)]
        with self.assertRaises(vpsrun.Refused):
            self.go({NGINX: lines, CADDY: lines})

    def test_explicit_reusable_contract_must_be_listed_for_every_step(self):
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go({NGINX: [_line(RU, "reusable", left=9)], CADDY: []},
                    contract="/grants-for-test/%s.json" % RU,
                    grant={"kind": "reusable", "session_id": RU})
        self.assertIn("does not cover break-glass step(s) 3", str(cm.exception))

    def test_explicit_reusable_contract_needs_enough_uses(self):
        lines = [_line(RU, "reusable", left=1)]
        with self.assertRaises(vpsrun.Refused) as cm:
            self.go({NGINX: lines, CADDY: lines},
                    contract="/grants-for-test/%s.json" % RU,
                    grant={"kind": "reusable", "session_id": RU})
        self.assertIn("1 use(s) left; this play needs 2", str(cm.exception))

    def test_a_forged_listing_cannot_inject_a_path(self):
        """Only well-formed ids under the door's header are read; the path is
        always GRANT_DIR/<id>.json, never text from the plan."""
        bad = ["            ../../etc/passwd short until 2026-10-12T20:00:00Z "
               "code ABCD-EFGH-JK23"]
        with self.assertRaises(vpsrun.Refused):
            self.go({NGINX: bad, CADDY: bad})

    def test_parse_argv_auto_spellings(self):
        for argv in (["p.yaml", "--approval-contract=auto"], ["p.yaml", "--grant", "auto"],
                     ["p.yaml", "--grant=auto"]):
            self.assertEqual(vpsrun.parse_argv(argv), ("p.yaml", vpsrun.AUTO))
        self.assertEqual(vpsrun.parse_argv(["p.yaml"]), ("p.yaml", None))
        _, c = vpsrun.parse_argv(["p.yaml", "--grant=~/g.json"])
        self.assertEqual(c, str(Path("~/g.json").expanduser()))


if __name__ == "__main__":
    unittest.main()
