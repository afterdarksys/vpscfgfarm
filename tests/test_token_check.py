"""Tripwires for the token-only check kind (actions.TokenCheck,
vpsexec._gate_token, ensure_secret@3, `runbook preflight --secrets-compare`).

A TokenCheck is the ONE exemption from the door's credential-file rule
(readpolicy._credential_file): a reviewed script, fixed in tool code and pinned
by sha256, that may read an environment file because it can only print
VPSCFG-DONE or VPSCFG-NEEDED. These tests exist to break loudly if:

  - a seeded secret value reaches any stdout/stderr, argv, stdin, plan,
    journal line, op-dir file, `vpsexec last`/`log` output or notify payload,
    even when the (fake) host prints the value, the value plus a token, or
    fails (TokenCheckSecrecyTest);
  - the exemption spreads: any other read of an env or credential file (a
    plain cmd, grep, a shell check, a SqlCheck, another action's name, a
    swapped script, a script from YAML, a crafted canonical) is no longer
    refused (TokenCheckExemptionTripwireTest);
  - output other than exactly one token stops failing closed
    (TokenCheckParseTripwireTest);
  - --secrets-compare reads without being asked, prints a value, or dials
    under --index-only (SecretsCompareTripwireTest).

Hermetic: the "host" is local bash through the detached transport (temp op and
lock dirs, the journal redirected), or a scripted fake. Fictional names only.
"""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import textwrap
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_actions_core as core  # noqa: E402
import test_vpsexec as tv  # noqa: E402
from vpscfg import actions, detach, lock, notify, runbookcheck, vpsexec  # noqa: E402
from vpscfg.actions import base, secret  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DENY = list(DENY_ALWAYS_FLOOR)
TODAY = "2026-10-12"
HOST = "edge1"
SS, JWT = "SESSION_SECRET", "JWT_SECRET"
# Fictional seeded values, deliberately NOT hex or high-entropy, so secretmask
# would not hide a leak from these assertions: only never-sending can pass.
SEED = "pinkflamingo" * 4
OTHER = "bluewhale" * 6


def kv(*pairs):
    return "".join("%s=%s\n" % pair for pair in pairs)


def ensure(path, **over):
    return actions.expand("ensure_secret", dict({"file": str(path), "key": SS,
                                                 "distinct_from": [JWT]}, **over), "web1")


def swap(exp, check=None, verify=None):
    """`exp` with its check and/or verify replaced (a forged expansion)."""
    fields = dict((f, getattr(exp, f)) for f in base.Expansion.FIELDS)
    if check is not None:
        fields["check"] = check
    if verify is not None:
        fields["verify"] = verify
    return base.Expansion(**fields)


def gate(exp, deny=DENY, risky=()):
    vpsexec._gate_action({"web1": exp}, deny, list(risky))


# ---------------------------------------------------------------------------
# SecretPath stays intact: the exemption is this class, this action, this file
# ---------------------------------------------------------------------------

class TokenCheckExemptionTripwireTest(unittest.TestCase):
    ENV = "/srv/shop/.env"

    def refused(self, fn, *words):
        with self.assertRaises(Refused) as cm:
            fn()
        for w in words:
            self.assertIn(w, str(cm.exception))
        return str(cm.exception)

    def test_the_real_check_passes_the_gate_on_an_env_file(self):
        exp = ensure(self.ENV)
        self.assertIsInstance(exp.check, actions.TokenCheck)
        self.assertIsInstance(exp.verify, actions.TokenCheck)
        gate(exp)
        self.assertEqual(exp.check.pinned().sha256, secret.CHECK_SHA256)
        self.assertEqual(exp.check.command(), "sh -s")

    def test_every_other_env_read_is_still_refused_on_every_tier(self):
        # classify() has no tier switch for this: a refusal is not a tier.
        for cmd in ("cat /srv/shop/.env",
                    "grep SESSION_SECRET /srv/shop/.env",
                    "grep -c -x 'SESSION_SECRET=.*' /srv/shop/.env | grep -qx 1",
                    "head -c 8 /srv/shop/.env.production",
                    "cut -d= -f2 /srv/shop/prod.env",
                    "sort < /srv/shop/.env",
                    "cat /etc/ssh/ssh_host_ed25519_key",
                    "cat /etc/ssl/private/shop.key"):
            with self.assertRaises(Refused, msg=cmd) as cm:
                vpsexec.classify(cmd, DENY)
            self.assertRegex(str(cm.exception), "environment file|private key|ssh host", cmd)

    def test_an_ordinary_shell_check_on_an_env_file_is_refused(self):
        exp = swap(ensure(self.ENV),
                   check="grep -c -x 'SESSION_SECRET=.*' /srv/shop/.env",
                   verify="grep -qx 'SESSION_SECRET=.*' /srv/shop/.env")
        self.refused(lambda: gate(exp), "environment file")

    def test_a_crafted_canonical_is_reserved(self):
        canonical = ensure(self.ENV).canonical
        self.assertTrue(actions.is_reserved(canonical))
        self.assertTrue(actions.is_reserved("cat /srv/shop/.env; " + canonical))

    def test_a_script_cannot_come_from_yaml(self):
        # `with:` takes only declared parameters; an action entry owns its
        # verify; a cmd's verify is shell text and meets the credential rule.
        self.refused(lambda: actions.expand(
            "ensure_secret", {"file": self.ENV, "key": SS, "script": "cat \"$f\""}, "web1"),
            "unknown parameter")
        with self.assertRaises(Refused):
            vpsexec.classify("sh -s < /srv/shop/.env", DENY)

    def test_another_action_name_cannot_borrow_the_script(self):
        real = ensure(self.ENV)
        fields = dict((f, getattr(real, f)) for f in base.Expansion.FIELDS)
        fields.update(name="install_pushed", version=1)
        self.refused(lambda: gate(base.Expansion(**fields)),
                     "only for its own action and version")
        fields.update(name="ensure_secret", version=1)
        self.refused(lambda: gate(base.Expansion(**fields)),
                     "only for its own action and version")

    def test_an_unregistered_key_is_refused(self):
        real = ensure(self.ENV)
        forged = actions.TokenCheck("evil_reader@1", real.check.reviewed, real.check.values)
        fields = dict((f, getattr(real, f)) for f in base.Expansion.FIELDS)
        fields.update(name="evil_reader", version=1, check=forged, verify=forged)
        self.refused(lambda: gate(base.Expansion(**fields)),
                     "not a registered reviewed script")

    def test_a_swapped_script_is_refused_at_gate_time_and_before_sending(self):
        real = ensure(self.ENV)
        for evil in (real.check.reviewed + 'cat "$f"\n',
                     real.check.reviewed.replace("exec 2>/dev/null", "cat \"$f\" >&2"),
                     'printf "VPSCFG-DONE\\n"\n'):
            forged = actions.TokenCheck(secret.CHECK_KEY, evil, real.check.values)
            msg = self.refused(lambda: gate(swap(real, check=forged)),
                               "not the reviewed one")
            self.assertIn(secret.CHECK_SHA256[:12], msg)
            self.refused(lambda: vpsexec._run_probe(
                HOST, forged, lambda *a, **k: self.fail("sent a swapped script"), 10, DENY),
                "not the reviewed one")

    def test_the_registry_pins_the_bytes(self):
        with self.assertRaises(ValueError):
            actions.register_token_script("x_test@1", "echo hi\n", "0" * 64,
                                          (("f", "file"),), "file")
        with self.assertRaises(ValueError):
            actions.register_token_script(secret.CHECK_KEY, secret.CHECK_SCRIPT,
                                          secret.CHECK_SHA256, secret.CHECK_BINDS, "file")
        self.assertNotIn("x_test@1", actions.TOKEN_SCRIPTS)
        self.assertEqual(base.sha256_text(secret.CHECK_SCRIPT), secret.CHECK_SHA256)

    def test_the_check_must_carry_its_own_actions_parameters(self):
        real = ensure(self.ENV)
        for over in ({"f": "/etc/shadow"}, {"k": JWT}, {"n": 32}, {"@": ()}):
            values = tuple((v, over.get(v, x)) for v, x in real.check.values)
            forged = actions.TokenCheck(secret.CHECK_KEY, secret.CHECK_SCRIPT, values)
            self.refused(lambda: gate(swap(real, check=forged)), "own parameters")

    def test_only_an_env_file_is_exempt_never_another_credential(self):
        for path in ("/etc/ssh/ssh_host_ed25519_key", "/etc/ssl/private/shop.key",
                     "/etc/opendkim/mail.private",
                     "/etc/rancher/k3s/registries.yaml",
                     "/proc/1/environ", "/proc/self/mem", "/dev/sda", "/sys/kernel/x"):
            with self.assertRaises(Refused, msg=path):
                gate(ensure(path))

    def test_a_sqlcheck_never_gets_the_exemption(self):
        # The exemption is by class: a SqlCheck goes through the sqlread gate
        # and has no file parameter at all (container and database are typed).
        real = ensure(self.ENV)
        with self.assertRaises(actions.ParamError):
            actions.SqlCheck("/srv/shop/.env", "shop", "SELECT 1")
        sql = actions.SqlCheck("shop-db", "shop", "SELECT 'VPSCFG-DONE'")
        self.assertFalse(isinstance(sql, actions.TokenCheck))
        self.assertFalse(hasattr(sql, "bind"))
        exp = swap(real, check=sql, verify=sql)
        gate(exp)  # the sqlread path, nothing token-only about it

        class Lookalike(object):
            """Duck-typed TokenCheck: refused by the Expansion itself."""
            key, reviewed, values = real.check.key, real.check.reviewed, real.check.values
            command, script, text = real.check.command, real.check.script, real.check.text
        with self.assertRaises(ValueError):
            swap(real, check=Lookalike())

    def test_the_floor_and_deny_lists_scan_the_whole_script(self):
        real = ensure(self.ENV)
        gate(real)
        for pattern in ("uniq -d", "exec 2>", "/srv/shop", "SESSION_SECRET"):
            with self.assertRaises(Refused, msg=pattern):
                gate(real, deny=DENY + [pattern])
        with self.assertRaises(Refused):
            gate(real, risky=["uniq -d"])
        with self.assertRaises(Refused):
            actions.deny_check(real, DENY + ["grep -c -x"], "--action")

    def test_plan_hash_and_expands_cover_the_script(self):
        real = ensure(self.ENV)
        self.assertIn(secret.CHECK_SHA256, real.check_text())
        self.assertIn(secret.CHECK_SCRIPT.rstrip("\n"), real.check_text())
        self.assertIn(secret.CHECK_SCRIPT.rstrip("\n"), real.verify_text())
        forged = actions.TokenCheck(secret.CHECK_KEY, secret.CHECK_SCRIPT + "true\n",
                                    real.check.values)
        other = swap(real, check=forged, verify=forged)
        self.assertNotEqual(real.check_sha256(), other.check_sha256())
        self.assertNotEqual(real.verify_text(), other.verify_text())
        items = lambda e: actions.digest_items(  # noqa: E731
            [{"hosts": ["web1"], "action": {"expansions": {"web1": e}}}])
        self.assertNotEqual(items(real), items(other))
        texts = real.texts()
        self.assertIn("sh -s", texts)
        self.assertIn(real.check.script(), texts)


# ---------------------------------------------------------------------------
# output parsing: exactly one token, or fail closed
# ---------------------------------------------------------------------------

class TokenCheckParseTripwireTest(unittest.TestCase):
    def test_only_an_exact_token_with_rc_zero_counts(self):
        probe = ensure("/srv/shop/.env").check
        good = {("VPSCFG-DONE\n", 0): "VPSCFG-DONE", ("VPSCFG-NEEDED", 0): "VPSCFG-NEEDED"}
        for (out, rc), want in good.items():
            self.assertEqual(vpsexec._probe_token(probe, rc, out), want)
        for out, rc in (("VPSCFG-DONE\n", 1), ("", 0), ("\n", 0), ("vpscfg-done\n", 0),
                        ("VPSCFG-DONE\n\n", 0), ("VPSCFG-DONE\nVPSCFG-DONE\n", 0),
                        (" VPSCFG-DONE\n", 0), ("VPSCFG-DONE \n", 0), (SEED + "\n", 0),
                        ("VPSCFG-DONE\n" + SEED, 0), (SEED + "VPSCFG-DONE\n", 0),
                        ("@@@check\nVPSCFG-DONE\n", 0), (b"VPSCFG-DONE\x00\n", 0)):
            self.assertIsNone(vpsexec._probe_token(probe, rc, out), repr((out, rc)))


# ---------------------------------------------------------------------------
# through the door: the leak hunt
# ---------------------------------------------------------------------------

class _Door(core._PolicyDir):
    def setUp(self):
        super().setUp()
        root = Path(self.tmp.name)
        self.saved = (detach.OPS_DIR, lock.LOCK_DIR, detach._sleep, lock.controller,
                      notify.send)
        detach.OPS_DIR = str(root / "ops")
        lock.LOCK_DIR = str(root / "lock")
        detach._sleep = lambda s: time.sleep(0.02)
        self.notified = []
        notify.send = lambda event, fields, **k: self.notified.append(
            json.dumps(dict(fields, event=event), default=str)) or False
        self.work = root / "work"
        self.work.mkdir()
        self.sent = []
        self.script = []   # scripted answers for `sh -s` probes, in order; None = real

        def _ssh(host, cmd, timeout=None, connect_timeout=None, data=None):
            self.sent.append((cmd, data))
            if cmd == "sh -s" and self.script:
                answer = self.script.pop(0)
                if isinstance(answer, BaseException):
                    raise answer
                if answer is not None:
                    return answer
            return core._local(host, cmd, timeout=timeout, data=data)
        _ssh.detached = True
        self.ssh = _ssh

    def tearDown(self):
        (detach.OPS_DIR, lock.LOCK_DIR, detach._sleep, lock.controller,
         notify.send) = self.saved
        time.sleep(0.2)
        super().tearDown()

    def policy(self, path):
        return textwrap.dedent("""\
            version: 1
            expires: "2026-12-31"
            reason: rotate the shop session secret (test)
            shape: {steps: 1, hosts: [%s], break_glass: false}
            assumes:
              - host: %s
                env_distinct: [[SESSION_SECRET, JWT_SECRET]]
                verified_by: 1
            runbooks:
              - hosts: [%s]
                action: ensure_secret
                with: {file: %s, key: SESSION_SECRET, distinct_from: [JWT_SECRET]}
                why: "S1: SESSION_SECRET must differ from JWT_SECRET"
            """ % (HOST, HOST, HOST, path))

    def gov(self):
        gov = tv._policy()
        gov["allow_unmanaged_steps"] = [HOST]
        return gov

    def go(self, path):
        policy = self.load()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = vpsexec.dispatch(
                    [HOST, "--action", "ensure_secret", "--with",
                     json.dumps({"file": str(path), "key": SS, "distinct_from": [JWT]}),
                     "--run", "--reason", "rotate the shop session secret"],
                    guard=tv._guard(self.gov()), policy=policy, prober=self.prober(),
                    ssh=self.ssh, stream=tv.ApprovalTest._TTY(), prompt=lambda m: HOST,
                    today=TODAY, blackout_runner=self.blackout_runner(unavailable=True))
            except Refused as r:
                rc = r
        return rc, out.getvalue() + err.getvalue()

    def views(self):
        """What `vpsexec last` and `vpsexec log` (plain and --export --raw) print."""
        texts = []
        for argv in (["last", "-n", "20"], ["log", "-n", "200"],
                     ["log", "--export", "--raw"]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                vpsexec.dispatch(argv, guard=tv._guard(self.gov()), policy=self.load())
            texts.append(out.getvalue())
        return texts

    def hunt(self, outputs, *values, keep=()):
        """Every captured stream, every argv and stdin sent, every file the
        door wrote (journal, op dirs, policies) except the secret file and its
        backups, `last`/`log`, and every notify payload."""
        streams = list(outputs) + self.views() + self.notified
        for cmd, data in self.sent:
            streams += [cmd, data.decode() if isinstance(data, bytes) else (data or "")]
        keep = set(keep)
        for path in Path(self.tmp.name).rglob("*"):
            if path.is_file() and not path.is_symlink() and path not in keep \
                    and ".vpscfg-bak." not in path.name:
                streams.append(path.read_bytes().decode("utf-8", "replace"))
        self.assertTrue(any("action_planned" in s for s in streams), "the journal was read")
        for text in streams:
            for value in values:
                self.assertNotIn(value, text)
        return streams


class TokenCheckSecrecyTest(_Door):
    def seed(self, name=".env"):
        secret_file = self.work / name
        secret_file.write_text(kv(("APP", "shop"), (SS, SEED), (JWT, SEED)))
        os.chmod(secret_file, 0o600)
        self.armed(self.policy(secret_file))
        return secret_file

    def test_env_file_needed_rotation_done_twice_and_nothing_leaks(self):
        f = self.seed()
        rc, out1 = self.go(f)
        self.assertEqual(rc, 0, out1)
        self.assertIn("rotated SESSION_SECRET (48 chars)", out1)
        self.assertIn("token-only check %s" % secret.CHECK_KEY, out1, "the plan shows the check")
        new = dict(l.split("=", 1) for l in f.read_text().splitlines())[SS]
        self.assertRegex(new, r"^[0-9a-f]{48}$")
        rc, out2 = self.go(f)
        self.assertEqual(rc, 0, out2)
        self.assertIn("[done] %s" % HOST, out2)
        checks = [e["token"] for e in self.events() if e.get("event") == "action_check"]
        self.assertEqual(checks, ["VPSCFG-NEEDED", "VPSCFG-DONE"])
        self.assertEqual(len([e for e in self.events() if e.get("event") == "step"]), 1)
        # Probes: fixed argv, parameters only on stdin.
        probes = [(c, d) for c, d in self.sent if c == "sh -s"]
        self.assertEqual(len(probes), 3, "check, verify, check")
        for _, data in probes:
            self.assertIn(b"f='%s'" % str(f).encode(), data)
        self.hunt([out1, out2], SEED, new, keep={f})

    def test_the_hunt_itself_bites(self):
        # Control: the hunt sees a value in a captured stream, and in any file
        # under the temp root it was not told to keep (here the secret file).
        f = self.seed()
        rc, out = self.go(f)
        with self.assertRaises(AssertionError):
            self.hunt([out, "leak:" + OTHER], OTHER, keep={f})
        new = dict(l.split("=", 1) for l in f.read_text().splitlines())[SS]
        with self.assertRaises(AssertionError):
            self.hunt([out], new)

    def assert_failed_closed(self, f, out, rc):
        self.assertNotEqual(rc, 0, out)
        self.assertEqual([e for e in self.events() if e.get("event") == "step"], [],
                         "the body did not run")
        self.assertIn(kv((SS, SEED)), f.read_text(), "nothing changed")
        self.assertIn("done-check on %s failing closed" % HOST, out)

    def test_host_prints_the_value_or_value_plus_token_or_fails(self):
        for answer in ((0, SEED + "\n", ""),
                       (0, "VPSCFG-NEEDED\n" + SEED + "\n", ""),
                       (0, SEED + "VPSCFG-DONE\n", ""),
                       (0, "VPSCFG-DONE\n", SEED),     # a token, with the value on stderr
                       (1, "VPSCFG-NEEDED\n", SEED),
                       (2, SEED, SEED),
                       (0, "", ""),
                       OSError("ssh: lost after printing " + SEED),
                       subprocess.TimeoutExpired("sh -s " + SEED, 60, output=SEED)):
            with self.subTest(answer=repr(answer)[:40]):
                f = self.seed()
                self.script = [answer]
                rc, out = self.go(f)
                if answer == (0, "VPSCFG-DONE\n", SEED):
                    # stdout is exactly a token: DONE skips the body; stderr is
                    # discarded, never shown.
                    self.assertEqual(rc, 0, out)
                    self.assertIn("[done] %s" % HOST, out)
                else:
                    self.assert_failed_closed(f, out, rc)
                    last = [e for e in self.events() if e.get("event") == "action_check"][-1]
                    self.assertIsNone(last["token"])
                    self.assertIn(last.get("error") or last.get("detail"),
                                  ("not-a-token", "transport"))
                self.hunt([out], SEED, keep={f})
                journal = Path(self.tmp.name) / "vpsexec.jsonl"
                if journal.exists():
                    journal.unlink()

    def test_verify_prints_the_value_or_fails(self):
        for answer in ((0, SEED + "\n", ""), (0, "VPSCFG-DONE\n" + SEED, ""),
                       (1, "", SEED), OSError("lost: " + SEED)):
            with self.subTest(answer=repr(answer)[:40]):
                for p in self.work.iterdir():
                    p.unlink()
                f = self.seed()
                self.script = [None, answer]   # the real check (NEEDED), then the verify
                rc, out = self.go(f)
                self.assertNotEqual(rc, 0, out)
                self.assertTrue(any(e.get("event") == "step" for e in self.events()),
                                "the body ran (the check said NEEDED)")
                new = dict(l.split("=", 1) for l in f.read_text().splitlines())[SS]
                self.hunt([out], SEED, new, keep={f})
                verifies = [e for e in self.events() if e.get("event") == "verify"]
                for v in verifies:
                    self.assertIn(v["stdout"], ("", "VPSCFG-DONE", "VPSCFG-NEEDED"))
                journal = Path(self.tmp.name) / "vpsexec.jsonl"
                if journal.exists():
                    journal.unlink()


# ---------------------------------------------------------------------------
# D4: runbook preflight --secrets-compare
# ---------------------------------------------------------------------------

class SecretsCompareTripwireTest(_Door):
    def setUp(self):
        super().setUp()
        self.idx = Path(self.tmp.name) / "no-index"
        self.idx.mkdir()

    def write_env(self, session, jwt):
        f = self.work / ".env"
        f.write_text(kv(("APP", "shop"), (SS, session), (JWT, jwt)))
        return f

    def preflight(self, path, **kw):
        rep = runbookcheck.preflight(path, tv._guard(self.gov()), ssh=self.ssh, today=TODAY,
                                     index_dir=self.idx, **kw)
        return rep, [c for c in rep["checks"] if c["name"].endswith("env_distinct")]

    def test_without_the_flag_env_distinct_stays_manual_and_nothing_is_read(self):
        f = self.write_env(SEED, SEED)
        pol = self.armed(self.policy(f))
        rep, (r,) = self.preflight(pol)
        self.assertEqual(r["status"], "manual")
        self.assertEqual([c for c, _ in self.sent if c == "sh -s"], [])

    def test_equal_values_fail_distinct_pass_and_no_value_appears(self):
        f = self.write_env(SEED, SEED)
        pol = self.armed(self.policy(f))
        rep, (r,) = self.preflight(pol, secrets_compare=True)
        self.assertEqual(r["status"], "fail", r)
        self.assertIn("NEEDED", r["evidence"])
        f.write_text(kv((SS, OTHER), (JWT, SEED)))
        rep2, (r2,) = self.preflight(pol, secrets_compare=True)
        self.assertEqual(r2["status"], "pass", r2)
        self.assertIn("no value read back", r2["evidence"])
        tokens = [e["token"] for e in self.events() if e.get("event") == "secrets_compare"]
        self.assertEqual(tokens, ["VPSCFG-NEEDED", "VPSCFG-DONE"])
        texts = [json.dumps(rep), json.dumps(rep2), runbookcheck.render(rep)]
        for cmd, data in self.sent:
            texts += [cmd, data.decode() if data else ""]
        texts.append((Path(self.tmp.name) / "vpsexec.jsonl").read_text())
        for t in texts:
            self.assertNotIn(SEED, t)
            self.assertNotIn(OTHER, t)

    def test_index_only_skips_and_never_dials(self):
        f = self.write_env(SEED, SEED)
        pol = self.armed(self.policy(f))
        rep, (r,) = self.preflight(pol, secrets_compare=True, index_only=True)
        self.assertEqual(r["status"], "skip")
        self.assertEqual(self.sent, [])

    def test_a_host_printing_the_value_is_an_error_with_output_withheld(self):
        f = self.write_env(SEED, SEED)
        pol = self.armed(self.policy(f))
        for answer in ((0, SEED + "\n", ""), (0, "VPSCFG-DONE\n" + SEED, ""),
                       (1, "", SEED), OSError("lost " + SEED)):
            self.script = [answer]
            rep, (r,) = self.preflight(pol, secrets_compare=True)
            self.assertEqual(r["status"], "error", r)
            for t in (json.dumps(rep), runbookcheck.render(rep),
                      (Path(self.tmp.name) / "vpsexec.jsonl").read_text()):
                self.assertNotIn(SEED, t)

    def test_no_covering_step_is_manual(self):
        f = self.write_env(SEED, SEED)
        text = self.policy(f).replace("[[SESSION_SECRET, JWT_SECRET]]",
                                      "[[SESSION_SECRET, COOKIE_SECRET]]")
        pol = self.armed(text)
        rep, (r,) = self.preflight(pol, secrets_compare=True)
        self.assertEqual(r["status"], "manual")
        self.assertIn("no ensure_secret step", r["evidence"])
        self.assertEqual([c for c, _ in self.sent if c == "sh -s"], [])

    def test_the_cli_flag(self):
        f = self.write_env(SEED, SEED)
        pol = self.armed(self.policy(f))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = runbookcheck.cli(["preflight", str(pol), "--secrets-compare", "--json"],
                                    tv._guard(self.gov()), None, ssh=self.ssh, today=TODAY)
        self.assertEqual(code, 2)
        rep = json.loads(out.getvalue())
        self.assertIn("fail", [c["status"] for c in rep["checks"]
                               if c["name"].endswith("env_distinct")])
        self.assertNotIn(SEED, out.getvalue())
        with self.assertRaises(Refused):
            runbookcheck.cli(["lint", str(pol), "--secrets-compare"],
                             tv._guard(self.gov()), None, today=TODAY)


class PublicHygieneTest(unittest.TestCase):
    def test_exporter_scan_finds_nothing_in_the_changed_files(self):
        spec = importlib.util.spec_from_file_location("export_public",
                                                      REPO / "tools" / "export-public.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for rel in ("vpscfg/actions/base.py", "vpscfg/actions/secret.py",
                    "vpscfg/actions/__init__.py", "vpscfg/vpsexec.py",
                    "vpscfg/runbookcheck.py",
                    "tests/golden/actions/ensure_secret@%d.json" % secret.EnsureSecret.version,
                    "tests/test_token_check.py", "tests/test_actions_secret.py",
                    "docs/ACTIONS.md", "docs/VPSEXEC.md"):
            path = REPO / rel
            self.assertEqual(mod.scan_text(rel, path.read_text(), []), [], rel)


if __name__ == "__main__":
    unittest.main()
