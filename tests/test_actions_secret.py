"""P1b: ensure_secret (vpscfg/actions/secret.py, docs/ACTIONS.md).

Hermetic: the "host" is local bash, either called directly on the expansion's
texts or through the door's detached transport (temp op and lock dirs, the
journal redirected). Nothing dials a host or reads ~/.vpscfg.

What is proven here:
  S1  no body, check or verify hits the floor; every value is a quoted word
  S5  parameters are typed literals (accept/refuse tables, injection corpus,
      YAML type confusion through the real policy loader)
  S6  the check is the pinned token-only check (v2), prints exactly one
      token, and fails closed (the full tripwire: tests/test_token_check.py)
  S8  the seeded and generated values appear in no captured stream, argv,
      journal line or op-dir file
  idempotency: SESSION_SECRET == JWT_SECRET -> NEEDED -> rotation -> DONE,
      and a second door run is [done] with no body
"""
import contextlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_actions_core as core  # noqa: E402
import test_vpsexec as tv  # noqa: E402
from vpscfg import actions, detach, lock, probe, vpsexec, vpsexecpolicy  # noqa: E402
from vpscfg.actions import base  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused, deny_scan  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "tests" / "golden" / "actions"
DENY = list(DENY_ALWAYS_FLOOR)
TODAY = "2026-10-12"
SEED = "f00dfacecafe0123456789abcdef0123456789abcdef0123456789"   # 54 chars, fictional
OP = "ab12cd34" + "0" * 56 + ".1"
BASE = {"file": "/srv/shop/.env", "key": "SESSION_SECRET", "distinct_from": ["JWT_SECRET"]}


def kv(*pairs):
    """KEY=value lines for a seeded file (spelled so the exporter's
    secret-assignment scan sees no literal)."""
    return "".join("%s=%s\n" % pair for pair in pairs)


SS, JWT = "SESSION_SECRET", "JWT_SECRET"


def expand(**over):
    return actions.expand("ensure_secret", dict(BASE, **over), "web1")


def bash(text, cwd=None, env=None):
    r = subprocess.run(["bash", "-c", text], capture_output=True, text=True, timeout=60,
                       cwd=cwd, env=env)
    return r.returncode, r.stdout, r.stderr


def run_env(op=OP):
    env = dict(os.environ)
    env.pop("VPSCFG_OP", None)
    if op is not None:
        env["VPSCFG_OP"] = op
    return env


# ---------------------------------------------------------------------------
# S5: parameters
# ---------------------------------------------------------------------------

class ParamTest(unittest.TestCase):
    def refuses(self, word, **over):
        with self.assertRaises(Refused, msg=repr(over)) as cm:
            expand(**over)
        self.assertIn(word, str(cm.exception))

    def test_accepts_and_defaults(self):
        exp = actions.expand("ensure_secret", {"file": "/srv/shop/.env", "key": "SESSION_SECRET"},
                             "web1")
        self.assertEqual(exp.params, {"file": "/srv/shop/.env", "key": "SESSION_SECRET",
                                      "length": 48, "distinct_from": [], "force": False})
        self.assertTrue(exp.idempotent)
        self.assertEqual(exp.tier, "mutation")
        self.assertIn('"distinct_from":[]', exp.canonical)
        for n in (32, 128):
            self.assertEqual(expand(length=n).params["length"], n)

    def test_refusals_name_the_field(self):
        self.refuses("with.length", length=31)
        self.refuses("with.length", length=129)
        self.refuses("with.length", length="48")
        self.refuses("with.length", length=48.0)
        self.refuses("with.length", length=True)
        self.refuses("with.distinct_from", distinct_from="JWT_SECRET")
        self.refuses("with.distinct_from", distinct_from=["JWT_SECRET", "JWT_SECRET"])
        self.refuses("with.distinct_from", distinct_from=["K%d" % i for i in range(9)])
        self.refuses("names the key itself", distinct_from=["SESSION_SECRET"])
        self.refuses("with.force", force="true")
        self.refuses("with.force", force=vpsexecpolicy.YamlWord("yes", True))
        self.refuses("with.file", file="srv/shop/.env")
        self.refuses("with.file", file="/srv/shop/")
        self.refuses("with.key", key="1KEY")
        self.refuses("unknown parameter", value="x")
        with self.assertRaises(Refused):
            actions.expand("ensure_secret", {"key": "SESSION_SECRET"}, "web1")

    def test_injection_corpus_is_refused_for_every_string_param(self):
        for value in core.ParamTypeTest.INJECTIONS + ["/srv/shop/.env;id", "KEY=x"]:
            for over in ({"file": value}, {"key": value}, {"distinct_from": [value]}):
                with self.assertRaises(Refused, msg=repr(over)):
                    expand(**over)

    def test_force_is_a_deliberate_rotation(self):
        exp = expand(force=True)
        self.assertFalse(exp.idempotent)
        self.assertIsNone(exp.check)
        self.assertEqual(exp.verify_text(), expand().verify_text())
        self.assertEqual(exp.body, expand().body)

    def test_threats_note(self):
        from vpscfg.actions import secret
        self.assertIn("Threats:", secret.__doc__)
        self.assertIn("Does NOT protect against", secret.__doc__)
        self.assertIn("backup", secret.__doc__)


class YamlTypeConfusionTest(core._PolicyDir):
    """The real loader: YAML spellings that must refuse the whole file."""

    def policy(self, with_):
        return textwrap.dedent("""\
            version: 1
            expires: "2026-12-31"
            reason: rotate the shop session secret (test)
            shape: {steps: 1, hosts: [edge1], break_glass: false}
            runbooks:
              - hosts: [edge1]
                action: ensure_secret
                with: %s
                why: "S1: rotate SESSION_SECRET"
            """ % with_)

    def test_type_confusion_refuses_the_load(self):
        good = "{file: /srv/shop/.env, key: SESSION_SECRET, distinct_from: [JWT_SECRET]}"
        for with_, word in (
                ('{file: /srv/shop/.env, key: SESSION_SECRET, length: "48"}', "with.length"),
                ("{file: /srv/shop/.env, key: SESSION_SECRET, force: yes}", "write true or false"),
                ("{file: /srv/shop/.env, key: SESSION_SECRET, force: on}", "with.force"),
                ("{file: /srv/shop/.env, key: SESSION_SECRET, distinct_from: JWT_SECRET}",
                 "with.distinct_from"),
                ("{file: /srv/shop/.env, key: 1234}", "with.key"),
                ("{file: /srv/shop/.env, key: null}", "with.key"),
                ("[/srv/shop/.env, SESSION_SECRET]", "mapping"),
                ("{file: /srv/shop/.env, file: /srv/shop/x.env, key: SESSION_SECRET}",
                 "duplicate")):
            self.write(self.policy(with_))
            with self.assertRaises(Refused, msg=with_) as cm:
                self.load()
            self.assertIn(word, str(cm.exception), with_)
        self.write(self.policy(good))
        self.load()  # loads (disarmed: no expands line), nothing refused


# ---------------------------------------------------------------------------
# golden, S1 floor sweep, S6 read classification, argv hygiene
# ---------------------------------------------------------------------------

class GoldenTest(unittest.TestCase):
    def test_golden_file_matches(self):
        action = base.REGISTRY["ensure_secret"]
        want = json.loads((GOLDEN / ("ensure_secret@%d.json" % action.version)).read_text())
        self.assertEqual(core._golden_doc(action), want)


CORPUS = [dict(BASE), dict(BASE, force=True), dict(BASE, length=128, distinct_from=[]),
          {"file": "/etc/shop/app.conf", "key": "API_TOKEN", "length": 32,
           "distinct_from": ["JWT_SECRET", "SESSION_SECRET", "COOKIE_KEY"]}]


def quoted_only(testcase, exp):
    values = []
    for v in exp.params.values():
        values += v if isinstance(v, list) else [v]
    texts = [exp.body] + [p if isinstance(p, str) else p.script()
                          for p in (exp.check, exp.verify) if p is not None]
    for value in (v for v in values if isinstance(v, str)):
        for text in texts:
            start = text.find(value)
            while start != -1:
                end = start + len(value)
                testcase.assertTrue(text[start - 1:start] == "'" and text[end:end + 1] == "'",
                                    "%r appears outside single quotes in %r" % (value, text))
                start = text.find(value, end)


class FloorSweepTest(unittest.TestCase):
    def test_no_text_hits_the_floor_and_values_are_quoted(self):
        for params in CORPUS:
            exp = actions.expand("ensure_secret", params, "web1")
            for text in [exp.canonical] + exp.texts():
                deny_scan(text, DENY)
            quoted_only(self, exp)

    def test_check_and_verify_pass_the_token_gate_for_a_plain_file(self):
        exp = actions.expand("ensure_secret", CORPUS[3], "web1")
        for probe in (exp.check, exp.verify):
            self.assertIsInstance(probe, actions.TokenCheck)
        vpsexec._gate_action({"web1": exp}, DENY, [])

    def test_an_env_file_check_is_a_token_only_check(self):
        # v1 refused this at plan time (a shell content read of an environment
        # file, readpolicy._credential_file). v2's check is the pinned
        # token-only script, the one exemption; the same read written as a
        # shell check is still refused (tests/test_token_check.py has the
        # full tripwire).
        exp = expand()
        self.assertIsInstance(exp.check, actions.TokenCheck)
        vpsexec._gate_action({"web1": exp}, DENY, [])
        with self.assertRaises(Refused) as cm:
            vpsexec.classify("grep -c -x 'SESSION_SECRET=.*' /srv/shop/.env", DENY)
        self.assertIn("environment file", str(cm.exception))

    def test_the_value_only_reaches_builtins(self):
        # argv hygiene: "$v" is only ever an argument of printf or a test, and
        # the only external command fed from it is `cut`, over a pipe.
        for line in expand().body.splitlines():
            if "$v" not in line:
                continue
            stripped = line.strip()
            self.assertTrue(stripped.startswith(("v=$(printf '%s' \"$v\" | cut ",
                                                 'case "$v" in',
                                                 "printf '%s%s=%s\\n' \"$pre\" \"$k\" \"$v\" >>")),
                            line)


# ---------------------------------------------------------------------------
# the texts on local bash: NEEDED -> rotation -> DONE, nothing leaks
# ---------------------------------------------------------------------------

class OnHostTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "srv"
        self.dir.mkdir()
        self.file = self.dir / ".env"
        self.file.write_text(kv(("APP", "shop"), (SS, SEED), (JWT, SEED), ("TAIL", "1")))
        os.chmod(self.file, 0o640)
        self.exp = actions.expand("ensure_secret", dict(BASE, file=str(self.file)), "web1")
        self.streams = []

    def sh(self, text, op=OP):
        if isinstance(text, actions.TokenCheck):
            # As the door sends it: the fixed argv, the script on stdin.
            r = subprocess.run(text.command().split(), input=text.script(), text=True,
                               capture_output=True, timeout=60, cwd=str(self.dir),
                               env=run_env(op))
            self.streams += [r.stdout, r.stderr]
            return r.returncode, r.stdout, r.stderr
        rc, out, err = bash(text, cwd=str(self.dir), env=run_env(op))
        self.streams += [out, err]
        return rc, out, err

    def values(self):
        lines = dict(l.split("=", 1) for l in self.file.read_text().splitlines())
        return lines

    def test_seeded_equal_secrets_rotate_then_check_done(self):
        self.assertEqual(self.sh(self.exp.check), (0, "VPSCFG-NEEDED\n", ""))
        rc, out, err = self.sh(self.exp.body)
        self.assertEqual((rc, out, err), (0, "rotated SESSION_SECRET (48 chars)\n", ""))
        self.assertEqual(self.sh(self.exp.check), (0, "VPSCFG-DONE\n", ""))
        self.assertEqual(self.sh(self.exp.verify), (0, "VPSCFG-DONE\n", ""))
        vals = self.values()
        new = vals["SESSION_SECRET"]
        self.assertRegex(new, r"^[0-9a-f]{48}$")
        self.assertEqual(vals["JWT_SECRET"], SEED)
        self.assertEqual((vals["APP"], vals["TAIL"]), ("shop", "1"))
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o640, "mode preserved")
        bak = Path(str(self.file) + ".vpscfg-bak.ab12cd34")
        self.assertEqual(stat.S_IMODE(bak.stat().st_mode), 0o600)
        self.assertIn(kv((SS, SEED)), bak.read_text())
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()),
                         sorted([".env", ".env.vpscfg-bak.ab12cd34"]), "no temp left")
        for text in self.streams + [self.exp.body, self.exp.check_text(),
                                    self.exp.verify_text(), self.exp.canonical]:
            self.assertNotIn(SEED, text)
            self.assertNotIn(new, text)

    def test_needed_when_missing_short_or_duplicated(self):
        for content in (kv((JWT, SEED)),                                 # missing
                        kv((SS, "a" * 47), (JWT, "x")),                  # short
                        kv((SS, "a" * 48), (SS, "b" * 48))):             # twice
            self.file.write_text(content)
            self.assertEqual(self.sh(self.exp.check), (0, "VPSCFG-NEEDED\n", ""), content)
        self.file.write_text(kv((SS, "a" * 48), (JWT, "b" * 48)))
        self.assertEqual(self.sh(self.exp.check), (0, "VPSCFG-DONE\n", ""))
        self.file.unlink()
        rc, out, err = self.sh(self.exp.check)
        self.assertEqual(out, "VPSCFG-NEEDED\n")

    def test_a_repeated_distinct_from_line_is_not_a_shared_value(self):
        # M4: two identical JWT_SECRET lines once read as a duplicate value
        # (uniq -d over raw lines), so the key rotated on every run.
        self.file.write_text(kv((SS, "a" * 48), (JWT, "b" * 48), (JWT, "b" * 48)))
        self.assertEqual(self.sh(self.exp.check), (0, "VPSCFG-DONE\n", ""))
        # ...and a real share across repeated lines is still NEEDED.
        self.file.write_text(kv((SS, "b" * 48), (JWT, "b" * 48), (JWT, "b" * 48)))
        self.assertEqual(self.sh(self.exp.check), (0, "VPSCFG-NEEDED\n", ""))
        self.file.write_text(kv((SS, "a" * 48), (JWT, "c" * 48), (JWT, "a" * 48)))
        self.assertEqual(self.sh(self.exp.check), (0, "VPSCFG-NEEDED\n", ""))

    def test_rotation_with_a_repeated_distinct_from_line_converges(self):
        self.file.write_text(kv((SS, SEED), (JWT, SEED), (JWT, SEED)))
        self.assertEqual(self.sh(self.exp.check)[1], "VPSCFG-NEEDED\n")
        self.assertEqual(self.sh(self.exp.body)[0], 0)
        self.assertEqual(self.sh(self.exp.check), (0, "VPSCFG-DONE\n", ""), "done after one run")

    def test_export_lines_count_as_the_key_in_check_and_body(self):
        exported = "export %s=%s\n" % (SS, "a" * 48)
        self.file.write_text(exported + kv((JWT, "b" * 48)))
        self.assertEqual(self.sh(self.exp.check)[1], "VPSCFG-DONE\n")
        # exported and plain spellings of one key are two definitions: NEEDED
        self.file.write_text(exported + kv((SS, "c" * 48), (JWT, "b" * 48)))
        self.assertEqual(self.sh(self.exp.check)[1], "VPSCFG-NEEDED\n")
        # an exported distinct_from key sharing the value: NEEDED
        self.file.write_text(kv((SS, "b" * 48)) + "export %s=%s\n" % (JWT, "b" * 48))
        self.assertEqual(self.sh(self.exp.check)[1], "VPSCFG-NEEDED\n")
        # the body replaces BOTH spellings, keeps the export, and converges
        self.file.write_text("export %s=%s\n" % (SS, SEED) + kv((SS, SEED), (JWT, SEED)))
        self.assertEqual(self.sh(self.exp.body)[0], 0)
        lines = self.file.read_text().splitlines()
        self.assertEqual(len([l for l in lines if SS + "=" in l]), 1, lines)
        self.assertTrue(lines[-1].startswith("export %s=" % SS), lines)
        self.assertEqual(self.sh(self.exp.check), (0, "VPSCFG-DONE\n", ""))
        for text in self.streams:
            self.assertNotIn(SEED, text)

    def test_missing_key_is_appended(self):
        self.file.write_text(kv((JWT, SEED)))
        self.assertEqual(self.sh(self.exp.body)[0], 0)
        self.assertEqual(self.sh(self.exp.check)[1], "VPSCFG-DONE\n")

    def test_body_refuses_and_changes_nothing(self):
        before = self.file.read_bytes()
        rc, out, err = self.sh(self.exp.body, op=None)
        self.assertEqual(rc, 3)
        self.assertIn("no operation id", err)
        rc, out, err = self.sh(self.exp.body, op="not-hex-at-all")
        self.assertEqual(rc, 3)
        Path(str(self.file) + ".vpscfg-bak.ab12cd34").write_text("earlier\n")
        rc, out, err = self.sh(self.exp.body)
        self.assertEqual(rc, 3)
        self.assertIn("already exists", err)
        self.assertEqual(self.file.read_bytes(), before)
        Path(str(self.file) + ".vpscfg-bak.ab12cd34").unlink()
        real = self.dir / "real.env"
        self.file.rename(real)
        self.file.symlink_to(real)
        rc, out, err = self.sh(self.exp.body)
        self.assertEqual(rc, 3)
        self.assertIn("not a regular file", err)
        self.assertTrue(self.file.is_symlink())
        self.assertEqual(real.read_bytes(), before)
        for text in self.streams:
            self.assertNotIn(SEED, text)


# ---------------------------------------------------------------------------
# through the door, on the detached transport: twice-run, leak hunt
# ---------------------------------------------------------------------------

HOST = "edge1"


class DoorTest(core._PolicyDir):
    def setUp(self):
        super().setUp()
        root = Path(self.tmp.name)
        self.saved = (detach.OPS_DIR, lock.LOCK_DIR, detach._sleep, lock.controller)
        detach.OPS_DIR = str(root / "ops")
        lock.LOCK_DIR = str(root / "lock")
        detach._sleep = lambda s: time.sleep(0.02)
        self.work = root / "work"
        self.work.mkdir()
        self.sent = []

        def _ssh(host, cmd, timeout=None, connect_timeout=None, data=None):
            rc, out, err = core._local(host, cmd, timeout=timeout, data=data)
            self.sent.append((cmd, data, out, err))
            return rc, out, err
        _ssh.detached = True
        self.ssh = _ssh

    def tearDown(self):
        detach.OPS_DIR, lock.LOCK_DIR, detach._sleep, lock.controller = self.saved
        time.sleep(0.2)
        super().tearDown()

    def policy(self, path):
        return textwrap.dedent("""\
            version: 1
            expires: "2026-12-31"
            reason: rotate the shop session secret (test)
            shape: {steps: 1, hosts: [%s], break_glass: false}
            runbooks:
              - hosts: [%s]
                action: ensure_secret
                with: {file: %s, key: SESSION_SECRET, distinct_from: [JWT_SECRET]}
                why: "S1: SESSION_SECRET must differ from JWT_SECRET"
            """ % (HOST, HOST, path))

    def go(self, path):
        gov = tv._policy()
        gov["allow_unmanaged_steps"] = [HOST]
        policy = self.load()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = vpsexec.dispatch(
                    [HOST, "--action", "ensure_secret", "--with",
                     json.dumps({"file": str(path), "key": "SESSION_SECRET",
                                 "distinct_from": ["JWT_SECRET"]}),
                     "--run", "--reason", "rotate the shop session secret"],
                    guard=tv._guard(gov), policy=policy, prober=self.prober(), ssh=self.ssh,
                    stream=tv.ApprovalTest._TTY(), prompt=lambda m: HOST, today=TODAY,
                    blackout_runner=self.blackout_runner(unavailable=True))
            except Refused as r:
                rc = r
        return rc, out.getvalue() + err.getvalue()

    def test_needed_rotation_done_and_nothing_leaks(self):
        self.twice("app.conf")

    def test_an_env_file_works_end_to_end(self):
        # v1 refused a `.env` at plan time; the token-only check reads it.
        self.twice(".env")

    def twice(self, name):
        secret = self.work / name
        secret.write_text(kv((SS, SEED), (JWT, SEED)))
        os.chmod(secret, 0o600)
        self.armed(self.policy(secret))
        rc, out1 = self.go(secret)
        self.assertEqual(rc, 0, out1)
        self.assertIn("rotated SESSION_SECRET (48 chars)", out1)
        checks = [e for e in self.events() if e.get("event") == "action_check"]
        self.assertEqual([c["token"] for c in checks], ["VPSCFG-NEEDED"])
        new = dict(l.split("=", 1) for l in secret.read_text().splitlines())["SESSION_SECRET"]
        self.assertRegex(new, r"^[0-9a-f]{48}$")

        rc, out2 = self.go(secret)
        self.assertEqual(rc, 0, out2)
        self.assertIn("[done] %s" % HOST, out2)
        self.assertEqual(len([e for e in self.events() if e.get("event") == "step"]), 1,
                         "the second run ran no body")
        last = [e for e in self.events() if e.get("event") == "host_done"][-1]
        self.assertIs(last["already_done"], True)
        self.assertFalse(Path(lock.LOCK_DIR).exists())

        # The leak hunt: every captured stream, every argv/stdin sent, every
        # file the door wrote (journal, op dirs, policies), except the secret
        # file and its backup.
        streams = [out1, out2]
        for cmd, data, o, e in self.sent:
            streams += [cmd, data.decode() if data else "", o, e]
        keep = {secret, *self.work.glob(name + ".vpscfg-bak.*")}
        self.assertEqual(len(keep), 2, "one backup")
        for path in Path(self.tmp.name).rglob("*"):
            if path.is_file() and not path.is_symlink() and path not in keep:
                streams.append(path.read_bytes().decode("utf-8", "replace"))
        self.assertTrue(any("action_planned" in s for s in streams), "the journal was read")
        for text in streams:
            self.assertNotIn(SEED, text)
            self.assertNotIn(new, text)
        # The checks went as `sh -s` with the script on stdin: no value, no
        # parameter on argv.
        probes = [c for c, d, _, _ in self.sent if d and c == "sh -s"]
        self.assertGreaterEqual(len(probes), 2)


class PublicHygieneTest(unittest.TestCase):
    def test_exporter_scan_finds_nothing(self):
        spec = importlib.util.spec_from_file_location("export_public",
                                                      REPO / "tools" / "export-public.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for path in (REPO / "vpscfg" / "actions" / "secret.py",
                     GOLDEN / ("ensure_secret@%d.json" % base.REGISTRY["ensure_secret"].version),
                     Path(__file__)):
            self.assertEqual(mod.scan_text(str(path.relative_to(REPO)), path.read_text(), []),
                             [], path)


if __name__ == "__main__":
    unittest.main()
