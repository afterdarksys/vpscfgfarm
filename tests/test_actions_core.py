"""P0: the typed-action contract (vpscfg/actions, docs/ACTIONS.md).

Hermetic: policies live in temp dirs, the "host" is a scripted fake or the
local-bash detached transport from test_detach_reconcile (temp op and lock
dirs), the journal is redirected. Nothing dials a host or reads ~/.vpscfg.

What is proven here, by invariant (plan S1-S13, the ones that apply at the core):
  S1  every byte an action sends is deny-scanned; no sample template hits the floor
  S2  a mutation action runs only where a runbook / non-break-glass override names it
  S3  the plan-hash binds sha256(body), sha256(check), verify and params
  S4  expansion is deterministic (same bytes under PYTHONHASHSEED 0, 1, random)
  S5  parameters are typed literals; every value appears only inside single quotes
  S6  a done-check is a read, prints exactly one token, and fails closed otherwise
  S7  a check runs only under THIS operation's lock and never releases another's
  S9  action_planned / action_check / host_done records are journaled
  S12 the new files carry no estate data (the exporter's own scan)
"""
import contextlib
import datetime
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
from vpscfg import (actions, detach, journal, lock, probe, runbookcheck,  # noqa: E402
                    vpsexec, vpsexecpolicy)
from vpscfg.actions import base, types  # noqa: E402
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused, deny_scan  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "tests" / "golden" / "actions"
TODAY = "2026-10-12"
DENY = list(DENY_ALWAYS_FLOOR)
WH = "vpscfg-action wait_healthy@1 '{\"container\":\"shop-web\",\"interval\":3,\"tries\":20}'"


# ---------------------------------------------------------------------------
# test-only actions, registered per test and removed afterwards
# ---------------------------------------------------------------------------

class TouchAction(base.Action):
    """A harmless idempotent mutation: create a marker file."""
    name = "p0_touch"
    version = 1
    tier = "mutation"
    params = {"path": base.Param(types.ABS_PATH),
              "force": base.Param(types.FLAG, required=False, default=False)}
    samples = ({"path": "/tmp/vpscfg-p0/marker"},)

    def build(self, p, host):
        if p["force"]:
            return {"body": "touch %s" % base.sq(p["path"]), "idempotent": False,
                    "timeout": 30}
        return {"body": "touch %s" % base.sq(p["path"]),
                "check": "ls -d %s >/dev/null 2>&1 && echo VPSCFG-DONE || echo VPSCFG-NEEDED"
                         % base.sq(p["path"]),
                "verify": "ls -d %s" % base.sq(p["path"]),
                "idempotent": True, "timeout": 30}


class SqlAction(base.Action):
    """An idempotent mutation whose check looks inside Postgres."""
    name = "p0_sql"
    version = 1
    tier = "mutation"
    params = {"container": base.Param(types.CONTAINER), "db": base.Param(types.PG_IDENT)}
    samples = ({"container": "shop-db", "db": "shop"},)
    SQL = ("SELECT CASE WHEN count(*) = 0 THEN 'VPSCFG-DONE' ELSE 'VPSCFG-NEEDED' END "
           "FROM pg_class WHERE relname = 'p0_marker'")

    def build(self, p, host):
        return {"body": "echo p0 %s" % base.sq(p["db"]),
                "check": base.SqlCheck(p["container"], p["db"], self.SQL),
                "idempotent": True}


class WriteCheckAction(SqlAction):
    name = "p0_writecheck"
    SQL = "UPDATE pg_class SET relname = 'x'"


class BadReadAction(base.Action):
    """A read action whose body is NOT a read: the door must refuse it."""
    name = "p0_badread"
    version = 1
    tier = "read"
    params = {"path": base.Param(types.ABS_PATH)}
    samples = ({"path": "/tmp/vpscfg-p0/x"},)

    def build(self, p, host):
        return {"body": "touch %s" % base.sq(p["path"])}


class _Registered(object):
    ACTIONS = ()

    def setUp(self):
        super().setUp()
        for cls in self.ACTIONS:
            base.register(cls)

    def tearDown(self):
        for cls in self.ACTIONS:
            base.REGISTRY.pop(cls.name, None)
        super().tearDown()


# ---------------------------------------------------------------------------
# S5: typed parameters
# ---------------------------------------------------------------------------

class ParamTypeTest(unittest.TestCase):
    INJECTIONS = ["shop; DROP SCHEMA shop", "x\" OWNER TO postgres; --", "a\nb", "a\x00b",
                  "a\rb", "a\tb", "$(id)", "`id`", "--help", "-rf", "ѕhop", "ｓhop",
                  "x" * 10000, "../etc", "a b", "a'b", "a|b", "a&b", "a>b", "{a}", "*",
                  "@file", "shop\n"]

    def refuses(self, ptype, value):
        with self.assertRaises(types.ParamError, msg="%s accepted %r" % (ptype, value)):
            ptype.check(value)

    def test_string_types_refuse_the_injection_corpus(self):
        for ptype in (types.CONTAINER, types.PG_IDENT, types.ENV_KEY, types.ABS_PATH,
                      types.LOCAL_URL, types.IMAGE_REF, types.SHA256, types.BASENAME,
                      types.enum("prisma_deploy", "sql_dir")):
            for value in self.INJECTIONS:
                self.refuses(ptype, value)

    def test_pg_ident_is_lowercase_only(self):
        self.assertEqual(types.PG_IDENT.check("shop_app"), "shop_app")
        for bad in ("Shop", "SHOP", "1shop", "shop-app", "sh$op", "a" * 64):
            self.refuses(types.PG_IDENT, bad)

    def test_paths(self):
        self.assertEqual(types.ABS_PATH.check("/srv/shop/.env"), "/srv/shop/.env")
        for bad in ("/srv/shop/", "/", "//srv", "/srv//shop", "/srv/../etc", "/srv/./x",
                    "srv/shop", "/srv/sh op"):
            self.refuses(types.ABS_PATH, bad)

    def test_local_url(self):
        self.assertEqual(types.LOCAL_URL.check("http://127.0.0.1:8080/healthz"),
                         "http://127.0.0.1:8080/healthz")
        for bad in ("http://127.0.0.1:0/", "http://127.0.0.1:70000/", "http://10.0.0.1:80/",
                    "https://127.0.0.1:443/", "http://127.0.0.1:80/~x",
                    "http://127.0.0.1:８０/"):
            self.refuses(types.LOCAL_URL, bad)

    def test_image_ref_and_sha(self):
        for good in ("shop/web:1.5", "registry.example.com:5000/shop/web:1.5",
                     "shop/web@sha256:" + "a" * 64):
            self.assertEqual(types.IMAGE_REF.check(good), good)
        self.refuses(types.IMAGE_REF, "Shop/Web")
        self.refuses(types.SHA256, "A" * 64)
        self.refuses(types.SHA256, "a" * 63)

    def test_basename(self):
        self.assertEqual(types.BASENAME.check("diskwatch"), "diskwatch")
        for bad in (".", "..", ".hidden", "-x", "a/b"):
            self.refuses(types.BASENAME, bad)

    def test_yaml_type_confusion(self):
        rng = types.int_range(32, 128)
        self.assertEqual(rng.check(48), 48)
        for bad in ("48", 48.0, True, None, [48], {"a": 48}, 31, 129):
            self.refuses(rng, bad)
        for bad in (420, True, None, ["0644"]):
            self.refuses(types.enum("0644", "0755"), bad)
        self.refuses(types.CONTAINER, 1)
        self.refuses(types.CONTAINER, ["shop-db"])
        self.assertIs(types.FLAG.check(True), True)
        for bad in ("true", 1, None, vpsexecpolicy.YamlWord("yes", True)):
            self.refuses(types.FLAG, bad)
        self.refuses(types.CONTAINER, vpsexecpolicy.YamlWord("on", True))

    def test_list_of(self):
        lst = types.list_of(types.ENV_KEY, 3)
        self.assertEqual(lst.check(["A", "B"]), ["A", "B"])
        for bad in ([], ["A", "A"], ["A", "B", "C", "D"], "A", ["A", "$B"]):
            self.refuses(lst, bad)


# ---------------------------------------------------------------------------
# the Expansion contract, the registry, validation
# ---------------------------------------------------------------------------

class ContractTest(_Registered, unittest.TestCase):
    ACTIONS = (TouchAction,)

    def test_canonical_spelling(self):
        exp = actions.expand("wait_healthy", {"container": "shop-web", "tries": 20},
                             "web1")
        self.assertEqual(exp.canonical, WH)
        self.assertEqual(exp.tier, "read")
        self.assertIsNone(exp.check)
        self.assertEqual(exp.verify_retry, (20, 3))
        self.assertEqual(exp.assumes, ({"container": "shop-web", "host": "web1"},))
        with self.assertRaises(AttributeError):
            exp.body = "rm -rf /tmp"

    def test_defaults_are_written_into_the_canonical_json(self):
        a = actions.expand("p0_touch", {"path": "/tmp/x"}, "web1")
        b = actions.expand("p0_touch", {"path": "/tmp/x", "force": False}, "web1")
        self.assertEqual(a.canonical, b.canonical)
        self.assertIn('"force":false', a.canonical)

    def test_unknown_missing_and_mistyped_params_refuse(self):
        for params, word in (({"path": "/tmp/x", "colour": "red"}, "unknown"),
                             ({}, "missing"), ({"path": 5}, "with.path"),
                             ([], "mapping"), ({"path": "/tmp/x", "force": "yes"}, "with.force")):
            with self.assertRaises(Refused) as cm:
                actions.expand("p0_touch", params, "web1")
            self.assertIn(word, str(cm.exception))

    def test_unknown_action_and_wrong_version_refuse(self):
        for name in ("nope", "wait_healthy@2", "wait_healthy@0", "Wait_healthy", 7):
            with self.assertRaises(Refused):
                actions.get(name)
        self.assertEqual(actions.get("wait_healthy@1").name, "wait_healthy")

    def test_build_level_refusals(self):
        for params in ({}, {"container": "a", "url": "http://127.0.0.1:80/"},
                       {"container": "a", "tries": 30, "interval": 60}):
            with self.assertRaises(Refused):
                actions.expand("wait_healthy", params, "web1")

    def _exp(self, **kw):
        fields = dict(name="x", version=1, params={}, host="web1", canonical="c", body="true",
                      check=None, verify=None, verify_retry=None, assumes=(), timeout=None,
                      idempotent=False, tier="mutation")
        fields.update(kw)
        return base.Expansion(**fields)

    def test_expansion_validation(self):
        self._exp()  # a non-idempotent mutation with no check is fine
        for kw in ({"idempotent": True},                       # claims it, no check
                   {"check": "true"},                          # check, not idempotent
                   {"tier": "read", "check": "true"},          # a read has no check
                   {"tier": "read", "verify": "true"},
                   {"verify_retry": (2, 2)},                   # retry without verify
                   {"verify": "true", "verify_retry": (31, 1)},
                   {"verify": "true", "verify_retry": (20, 60)},
                   {"timeout": 0}, {"timeout": True}, {"body": ""},
                   {"body": "x" * 70000}, {"tier": "write"}):
            with self.assertRaises(ValueError, msg=repr(kw)):
                self._exp(**kw)

    def test_register_validates(self):
        class Dup(TouchAction):
            pass
        with self.assertRaises(ValueError):
            base.register(Dup)  # same name
        class NoSamples(TouchAction):
            name = "p0_nosamples"
            samples = ()
        with self.assertRaises(ValueError):
            base.register(NoSamples)
        class BadName(TouchAction):
            name = "Bad-Name"
        with self.assertRaises(ValueError):
            base.register(BadName)

    def test_a_line_equal_to_a_heredoc_delimiter_refuses(self):
        # INFO-1: a script or SQL line equal to its heredoc delimiter would end
        # the heredoc early and run the rest as shell.
        for delim in base.HEREDOC_DELIMS:
            with self.assertRaises(ValueError, msg=delim):
                self._exp(body="cat <<'%s'\nok\n%s\nrm -rf /tmp/x\n%s" % (delim, delim, delim))
            with self.assertRaises(ValueError, msg=delim):
                self._exp(verify="true\n%s" % delim)
        # one opener, one terminator: fine
        self._exp(body="cat <<'VPSCFG_SQL'\nSELECT 1;\nVPSCFG_SQL")
        # a SqlCheck whose statement carries the delimiter line refuses
        sql = base.SqlCheck("shop-db", "shop", "SELECT 'VPSCFG-DONE'\nSQL\nAS x")
        with self.assertRaises((ValueError, Refused)):
            self._exp(check=sql, verify=sql, idempotent=True)

    def test_a_token_script_with_a_delimiter_line_refuses_at_registration(self):
        script = "printf '%s\\n' VPSCFG-NEEDED\nVPSCFG\nrm -rf /tmp/x\n"
        with self.assertRaises(ValueError) as cm:
            base.register_token_script("p0_delim@1", script, base.sha256_text(script),
                                       (("f", "file"),), "file")
        self.assertIn("heredoc delimiter", str(cm.exception))
        self.assertNotIn("p0_delim@1", base.TOKEN_SCRIPTS)

    def test_a_template_with_a_delimiter_line_refuses_at_registration(self):
        class Delim(TouchAction):
            name = "p0_delim"

            def build(self, p, host):
                return {"body": "cat <<'SQL'\nSQL\nSQL", "idempotent": False}
        with self.assertRaises(ValueError) as cm:
            base.register(Delim)
        self.assertIn("heredoc delimiter", str(cm.exception))
        self.assertNotIn("p0_delim", base.REGISTRY)

    def test_reserved_detection(self):
        for text in (WH, "true; vpscfg-action x@1 '{}'", "/usr/bin/vpscfg-action",
                     "  vpscfg-action   wait_healthy@1 '{}'"):
            self.assertTrue(actions.is_reserved(text), text)
        for text in ("docker ps", "echo vpscfg-actions", "ls /srv/vpscfg-action-logs"):
            self.assertFalse(actions.is_reserved(text), text)

    def test_with_json(self):
        self.assertEqual(actions.parse_with_json('{"a": 1}'), {"a": 1})
        for bad in ('{"a": 1, "a": 2}', "[1]", "nope", '{"a": NaN}', "x" * 9000):
            with self.assertRaises(Refused):
                actions.parse_with_json(bad)


# ---------------------------------------------------------------------------
# S4 determinism, golden files (version bumps), S1/S5 floor and quoting sweep
# ---------------------------------------------------------------------------

def _golden_doc(action):
    out = []
    for sample in action.samples:
        exp = actions.expand(action.name, sample, "web1")
        out.append({"params": exp.params, "canonical": exp.canonical, "body": exp.body,
                    "check": exp.check_text(), "verify": exp.verify_text(),
                    "verify_retry": list(exp.verify_retry) if exp.verify_retry else None,
                    "assumes": list(exp.assumes), "timeout": exp.timeout,
                    "idempotent": exp.idempotent, "tier": exp.tier})
    return {"action": action.name, "version": action.version, "expansions": out}


class GoldenTest(unittest.TestCase):
    """Every registered action has tests/golden/actions/<name>@<version>.json,
    and its samples expand to exactly those bytes. Change a template without
    bumping `version` and this fails; bump it and a new golden file is needed
    (and every policy using it disarms through `expands:`)."""

    def test_every_action_matches_its_golden_file(self):
        self.assertTrue(base.REGISTRY)
        for name, action in sorted(base.REGISTRY.items()):
            path = GOLDEN / ("%s@%d.json" % (name, action.version))
            got = _golden_doc(action)
            self.assertTrue(path.is_file(), "missing golden file %s — write it from:\n%s"
                            % (path, json.dumps(got, indent=2, sort_keys=True)))
            want = json.loads(path.read_text())
            self.assertEqual(got, want, "%s@%d expands differently from its golden file: "
                             "a template changed — bump %s.version and add a new golden "
                             "file (policies using it disarm via expands:)"
                             % (name, action.version, name))

    def test_no_orphan_golden_files(self):
        # A golden file for a version the door no longer registers is stale:
        # it pins bytes nothing can expand.
        registered = set("%s@%d.json" % (n, a.version) for n, a in base.REGISTRY.items())
        orphans = sorted(p.name for p in GOLDEN.glob("*.json") if p.name not in registered)
        self.assertEqual(orphans, [])

    def test_a_one_byte_template_change_is_caught(self):
        action = base.REGISTRY["wait_healthy"]
        want = json.loads((GOLDEN / ("wait_healthy@%d.json" % action.version)).read_text())
        real = type(action).build

        def drifted(self, p, host):
            out = real(self, p, host)
            return dict(out, body=out["body"] + " ")
        type(action).build = drifted
        try:
            self.assertNotEqual(_golden_doc(action), want)
        finally:
            type(action).build = real


class ExpandsDigestCoversTimeoutAndAssumesTest(_Registered, unittest.TestCase):
    """L7: the template's timeout and assumed facts are in the digest, so a
    change to either disarms a reviewed policy like a body change does."""
    ACTIONS = (TouchAction,)

    def digest(self, **over):
        real = TouchAction.build

        def drifted(self, p, host):
            return dict(real(self, p, host), **over)
        TouchAction.build = drifted
        try:
            exp = actions.expand("p0_touch", {"path": "/tmp/x"}, "web1")
        finally:
            TouchAction.build = real
        return actions.expands_digest([{"hosts": ["web1"],
                                        "action": {"expansions": {"web1": exp}}}])

    def test_a_timeout_change_changes_the_digest(self):
        self.assertNotEqual(self.digest(), self.digest(timeout=31))

    def test_an_assumes_change_changes_the_digest(self):
        self.assertNotEqual(self.digest(), self.digest(assumes=({"container": "shop-web"},)))
        self.assertNotEqual(self.digest(assumes=({"container": "shop-web"},)),
                            self.digest(assumes=({"container": "shop-api"},)))

    def test_same_template_same_digest(self):
        self.assertEqual(self.digest(), self.digest())


class DeterminismTest(unittest.TestCase):
    SCRIPT = textwrap.dedent("""
        import hashlib, json, sys
        sys.path.insert(0, sys.argv[1])
        from vpscfg import actions
        from vpscfg.actions import base
        items = []
        for name, a in sorted(base.REGISTRY.items()):
            for s in a.samples:
                e = actions.expand(name, dict(reversed(list(s.items()))), "web1")
                items.append([e.canonical, e.body_sha256(), e.check_sha256(), e.verify_text()])
        print(hashlib.sha256(json.dumps(items).encode()).hexdigest())
    """)

    def test_same_bytes_under_any_hash_seed(self):
        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "expand_all.py"
            script.write_text(self.SCRIPT)
            outs = set()
            for seed in ("0", "1", "random"):
                env = dict(os.environ, PYTHONHASHSEED=seed)
                r = subprocess.run([sys.executable, str(script), str(REPO)], env=env,
                                   capture_output=True, text=True, timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                outs.add(r.stdout.strip())
            self.assertEqual(len(outs), 1, outs)


class FloorSweepTest(_Registered, unittest.TestCase):
    ACTIONS = (TouchAction, SqlAction)

    def test_no_template_hits_the_floor_and_every_value_is_quoted(self):
        for name, action in sorted(base.REGISTRY.items()):
            for sample in action.samples:
                exp = actions.expand(name, sample, "web1")
                for text in [exp.canonical] + exp.texts():
                    deny_scan(text, DENY)  # raises on a floor hit
                values = []
                for v in exp.params.values():
                    values += v if isinstance(v, list) else [v]
                # Template-built shell texts. A SqlCheck's command is the host
                # index's own builder (shlex.quote, typed values) and its SQL
                # is checked by the sqlread gate; both are covered elsewhere.
                shell = [exp.body] + [p for p in (exp.check, exp.verify)
                                      if isinstance(p, str)]
                for value in (v for v in values if isinstance(v, str)):
                    for text in shell:
                        start = text.find(value)
                        while start != -1:
                            end = start + len(value)
                            self.assertTrue(
                                text[start - 1:start] == "'" and text[end:end + 1] == "'",
                                "%s: %r appears outside single quotes in %r"
                                % (name, value, text))
                            start = text.find(value, end)


# ---------------------------------------------------------------------------
# the policy loader: action:, with:, expands:
# ---------------------------------------------------------------------------

GOV_HOSTS = {"edge1", "web1", "web2", "web3", "dns1", "dns2"}


def _action_policy(host="edge1", with_="{container: shop-web, tries: 20}",
                   action="wait_healthy", expands=None, extra_step="", break_glass=False,
                   shape_steps=1, top_extra=""):
    lines = ["version: 1", 'expires: "2026-12-31"', "reason: shop health (test)",
             "shape: {steps: %d, hosts: [%s], break_glass: %s}"
             % (shape_steps, host, "true" if break_glass else "false"),
             "runbooks:",
             "  - hosts: [%s]" % host,
             "    action: %s" % action,
             "    with: %s" % with_,
             "    break_glass: %s" % ("true" if break_glass else "false"),
             "    timeout: 60",
             '    why: "H1: wait for shop-web"']
    if extra_step:
        lines.append(extra_step.rstrip("\n"))
    lines.append("assumes:\n  - host: %s\n    container: shop-web" % host)
    if expands:
        lines.append('expands: "%s"' % expands)
    return "\n".join(lines) + "\n" + top_extra


class _PolicyDir(tv._Harness):
    def setUp(self):
        super().setUp()
        self.pdir = Path(self.tmp.name) / "policies"
        self.adir = self.pdir / vpsexecpolicy.ACTIONS_SUBDIR
        self.adir.mkdir(parents=True)

    def write(self, text, name="health.yaml", top=False):
        """Action policies live in policies/actions/ (top=True: policies/)."""
        path = (self.pdir if top else self.adir) / name
        path.write_text(text)
        return path

    def load(self):
        return vpsexecpolicy.load(self.pdir, deny_patterns=DENY, today=TODAY,
                                  governor_hosts=GOV_HOSTS, host_re=probe.HOST_RE)

    def digest(self, path):
        _, _, runbooks, _ = runbookcheck.load_file(path, DENY, TODAY, GOV_HOSTS)
        return actions.expands_digest(runbooks)

    def armed(self, text, name="health.yaml"):
        """Write `text`, then add the expands line lint would print."""
        path = self.write(text, name)
        path.write_text(text + 'expands: "%s"\n' % self.digest(path))
        return path


class PolicyLoadTest(_Registered, _PolicyDir):
    ACTIONS = (TouchAction,)

    def test_action_step_loads_by_its_canonical_string(self):
        self.armed(_action_policy())
        pol = self.load()
        self.assertEqual(pol["misshapen"], [])
        (entry,) = pol["runbooks"]
        self.assertEqual(entry["cmd"], WH)
        self.assertEqual(entry["where"], "host")
        self.assertEqual(entry["action"]["name"], "wait_healthy")
        self.assertEqual(entry["timeout"], 60)

    def test_expands_missing_disarms_with_a_warning(self):
        self.write(_action_policy())
        pol = self.load()
        self.assertEqual(pol["runbooks"], [])
        self.assertIn("expands: not declared", pol["misshapen"][0]["reason"])
        notes = vpsexecpolicy.expiry_notes(pol, today=TODAY)
        self.assertTrue(any("DISARMED" in n and "expands" in n for n in notes), notes)

    def test_expands_wrong_disarms(self):
        self.write(_action_policy(expands="sha256:" + "0" * 64))
        pol = self.load()
        self.assertEqual(pol["runbooks"], [])
        self.assertIn("expands: declared", pol["misshapen"][0]["reason"])
        self.assertTrue(pol["files"][0]["misshapen"])

    def test_a_changed_with_disarms_until_expands_is_updated(self):
        path = self.armed(_action_policy())
        old = path.read_text()
        path.write_text(old.replace("tries: 20", "tries: 21"))
        self.assertEqual(self.load()["runbooks"], [])

    def test_expands_on_a_file_without_actions_disarms(self):
        text = textwrap.dedent("""\
            version: 1
            expires: "2026-12-31"
            reason: plain
            shape: {steps: 1, hosts: [edge1], break_glass: false}
            runbooks:
              - hosts: [edge1]
                cmd: "systemctl restart shop"
                why: "restart"
            expands: "sha256:%s"
            """ % ("1" * 64))
        self.write(text)
        self.assertIn("no step is an action", self.load()["misshapen"][0]["reason"])

    def test_malformed_or_duplicate_expands_refuses_the_load(self):
        self.write(_action_policy(expands="md5:abc"))
        with self.assertRaises(Refused):
            self.load()
        good = "sha256:" + "a" * 64
        self.write(_action_policy(expands=good) + 'expands: "%s"\n' % good)
        with self.assertRaises(Refused) as cm:
            self.load()
        self.assertIn("duplicate", str(cm.exception))

    def refuses(self, text, word):
        self.write(text)
        with self.assertRaises(Refused) as cm:
            self.load()
        self.assertIn(word, str(cm.exception))
        return str(cm.exception)

    def test_refusals_name_the_field(self):
        self.refuses(_action_policy(with_="{container: shop-web, colour: red}"),
                     "unknown parameter")
        self.refuses(_action_policy(with_="{}"), "exactly one of container or url")
        self.refuses(_action_policy(with_='{container: shop-web, tries: "20"}'),
                     "with.tries")
        self.refuses(_action_policy(with_="[shop-web]"), "mapping")
        self.refuses(_action_policy(action="nope"), "unknown action")
        self.refuses(_action_policy(action="wait_healthy@1"), "action: names the action only")
        self.refuses(_action_policy(with_="{container: Shop Web}"), "with.container")
        self.refuses(_action_policy(action="p0_touch", with_="{path: /tmp/x, force: yes}"),
                     "write true or false")
        self.refuses(_action_policy(action="p0_touch", with_="{path: /tmp/x, force: on}"),
                     "with.force")

    def test_cmd_and_action_together_refuse(self):
        text = _action_policy().replace("    action: wait_healthy",
                                        "    action: wait_healthy\n    cmd: \"true\"")
        self.refuses(text, "both cmd: and action:")

    def test_action_owns_placement_verify_and_retry(self):
        for line in ("    where: container", "    container: shop-web", "    verify: \"true\"",
                     "    verify_retry: {tries: 2, interval: 2}"):
            text = _action_policy().replace('    timeout: 60', '    timeout: 60\n' + line)
            self.refuses(text, "beside action:")

    def test_with_without_action_refuses(self):
        text = _action_policy().replace("    action: wait_healthy\n",
                                        '    cmd: "true"\n')
        self.refuses(text, "with: but no action:")

    def test_cmd_spelling_the_canonical_string_is_reserved(self):
        text = textwrap.dedent("""\
            version: 1
            expires: "2026-12-31"
            reason: sneaky
            shape: {steps: 1, hosts: [edge1], break_glass: false}
            runbooks:
              - hosts: [edge1]
                cmd: %s
                why: "pretend"
            """ % json.dumps(WH))
        self.refuses(text, "reserved spelling")
        check = textwrap.dedent("""\
            version: 1
            reason: sneaky check
            checks:
              health:
                cmd: %s
                why: "pretend"
            """ % json.dumps(WH))
        self.refuses(check, "reserved spelling")

    def test_yaml11_booleans_elsewhere_keep_their_old_meaning(self):
        text = textwrap.dedent("""\
            version: 1
            expires: "2026-12-31"
            reason: old style
            shape: {steps: 1, hosts: [edge1], break_glass: true}
            runbooks:
              - hosts: [edge1]
                cmd: "systemctl restart shop"
                break_glass: yes
                why: "restart"
            """)
        self.write(text)
        (entry,) = self.load()["runbooks"]
        self.assertIs(entry["break_glass"], True)

    def test_a_template_that_hits_a_deny_pattern_refuses(self):
        self.write(_action_policy(action="p0_touch", with_="{path: /tmp/x}"))
        with self.assertRaises(Refused) as cm:
            vpsexecpolicy.load(self.pdir, deny_patterns=DENY + ["touch"], today=TODAY,
                               governor_hosts=GOV_HOSTS, host_re=probe.HOST_RE)
        self.assertIn("deny pattern", str(cm.exception))


PLAIN_POLICY = textwrap.dedent("""\
    version: 1
    expires: "2026-12-31"
    reason: plain restart
    groups:
      shopweb: [edge1]
    shape: {steps: 1, hosts: [edge1], break_glass: true}
    runbooks:
      - hosts: [edge1]
        cmd: "systemctl restart shop"
        break_glass: true
        why: "restart"
    """)


class OldDoorCompatTest(_PolicyDir):
    """An older door copy (main's loader, frozen in tests/data/old_door/) must
    keep loading policies/ — every runbook, break-glass included — after a
    typed-action policy is committed. Otherwise adding one is an outage
    lockout for every other checkout."""

    def old_loader(self):
        path = REPO / "tests" / "data" / "old_door" / "vpsexecpolicy_main.py"
        spec = importlib.util.spec_from_file_location("vpscfg._old_door_policy", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_old_door_still_loads_after_an_action_policy_is_added(self):
        self.write(PLAIN_POLICY, "restart.yaml", top=True)
        self.armed(_action_policy())
        old = self.old_loader().load(self.pdir, deny_patterns=DENY, today=TODAY,
                                     governor_hosts=GOV_HOSTS, host_re=probe.HOST_RE)
        self.assertEqual([r["cmd"] for r in old["runbooks"]], ["systemctl restart shop"])
        self.assertTrue(old["runbooks"][0]["break_glass"])
        self.assertEqual(old["groups"], {"shopweb": ["edge1"]})
        new = self.load()
        self.assertEqual(sorted(r["cmd"] for r in new["runbooks"]),
                         sorted(["systemctl restart shop", WH]))

    def test_the_old_door_would_lock_out_on_a_top_level_action_policy(self):
        # Why the placement rule exists: proven against the old loader itself.
        self.write(PLAIN_POLICY, "restart.yaml", top=True)
        self.write(_action_policy(expands="sha256:" + "a" * 64), top=True)
        with self.assertRaises(Refused):
            self.old_loader().load(self.pdir, deny_patterns=DENY, today=TODAY,
                                   governor_hosts=GOV_HOSTS, host_re=probe.HOST_RE)

    def test_new_loader_refuses_action_keys_at_the_top_level(self):
        self.write(_action_policy(), top=True)
        with self.assertRaises(Refused) as cm:
            self.load()
        self.assertIn("move it to policies/actions/", str(cm.exception))
        self.write(PLAIN_POLICY.replace("reason: plain restart",
                                        'reason: x\nexpands: "sha256:%s"' % ("a" * 64)),
                   "restart.yaml", top=True)
        (self.pdir / "health.yaml").unlink()
        with self.assertRaises(Refused):
            self.load()

    def test_groups_are_refused_in_the_actions_dir(self):
        self.write(PLAIN_POLICY, "restart.yaml")
        with self.assertRaises(Refused) as cm:
            self.load()
        self.assertIn("defines groups", str(cm.exception))

    def test_a_file_name_in_both_dirs_refuses(self):
        self.write(PLAIN_POLICY, "health.yaml", top=True)
        self.armed(_action_policy())
        with self.assertRaises(Refused) as cm:
            self.load()
        self.assertIn("appear both", str(cm.exception))


class LintTest(_PolicyDir):
    def test_action_policy_lints_go_and_expands_passes(self):
        path = self.armed(_action_policy())
        rep = runbookcheck.lint(path, tv._guard(), tv._yaml_policy(), today=TODAY,
                                now=datetime.datetime(2026, 10, 12, 12, 0, 0),
                                plays_dir=self.pdir / "none", releases_dir=self.pdir / "none")
        self.assertEqual(rep["verdict"], "GO", runbookcheck.render(rep))
        doc, _, runbooks, _ = runbookcheck.load_file(path, DENY, TODAY, GOV_HOSTS)
        self.assertEqual(actions.lint_expands(doc, runbooks)["status"], "pass")

    def test_lint_expands_prints_the_line_to_paste(self):
        path = self.write(_action_policy())
        doc, _, runbooks, _ = runbookcheck.load_file(path, DENY, TODAY, GOV_HOSTS)
        res = actions.lint_expands(doc, runbooks)
        self.assertEqual(res["status"], "fail")
        line = actions.expands_line(runbooks)
        self.assertIn(line, res["evidence"])
        self.assertRegex(line, r'^expands: "sha256:[0-9a-f]{64}"$')
        path.write_text(path.read_text() + line + "\n")
        self.assertEqual(self.load_go(path), [])

    def load_go(self, path):
        return vpsexecpolicy.load(self.pdir, deny_patterns=DENY, today=TODAY,
                                  governor_hosts=GOV_HOSTS, host_re=probe.HOST_RE)["misshapen"]

    def test_step_assumes_are_exposed_for_preflight(self):
        path = self.armed(_action_policy())
        _, _, runbooks, _ = runbookcheck.load_file(path, DENY, TODAY, GOV_HOSTS)
        self.assertEqual(actions.step_assumes(runbooks),
                         [(1, {"container": "shop-web", "host": "edge1"})])


# ---------------------------------------------------------------------------
# the door: a read action end to end, reserved spellings, refusals
# ---------------------------------------------------------------------------

class _Door(tv._Harness):
    def scripted_ssh(self, answers):
        """answers: [(substring, rc, out)] matched in order; a callable answer
        may raise. Records (host, cmd, data)."""
        self.sent = []

        def _ssh(host, cmd, timeout=None, connect_timeout=None, data=None):
            self.sent.append((host, cmd, data))
            if "vpscfg.lock" in cmd:
                return 0, "", ""
            for needle, rc, out in answers:
                if needle in cmd:
                    if callable(rc):
                        return rc()
                    return rc, out, ""
            return 0, "ok", ""
        return _ssh

    def door(self, argv, policy=None, ssh=None, prompt=True, gov=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            try:
                rc = vpsexec.dispatch(
                    argv, guard=tv._guard(gov), policy=policy or tv._yaml_policy(),
                    prober=self.prober(), ssh=ssh or self.scripted_ssh([]),
                    stream=tv.ApprovalTest._TTY() if prompt else tv.ApprovalTest._NoTTY(),
                    prompt=(lambda m: m.split("Type ", 1)[1].split(" ", 1)[0])
                    if prompt else None, today=TODAY,
                    blackout_runner=self.blackout_runner(unavailable=True))
            except Refused as r:
                return r, out.getvalue()
        return rc, out.getvalue()

    def ev(self, name):
        return [e for e in self.events() if e.get("event") == name]


WITH_WH = '{"container": "shop-web", "tries": 20}'


class ReadActionDoorTest(_Registered, _Door):
    ACTIONS = (BadReadAction,)

    def setUp(self):
        super().setUp()
        self._sleep = vpsexec._verify_sleep
        vpsexec._verify_sleep = lambda s: None

    def tearDown(self):
        vpsexec._verify_sleep = self._sleep
        super().tearDown()

    def test_wait_healthy_plans_shows_body_and_runs(self):
        ssh = self.scripted_ssh([("docker inspect", 0, "")])
        rc, out = self.door(["edge1", "--action", "wait_healthy", "--with", WITH_WH], ssh=ssh)
        self.assertEqual(rc, 0, out)
        self.assertIn("command : %s" % WH, out)
        self.assertIn("action  : wait_healthy@1 (read)", out)
        self.assertIn("docker inspect --format '{{.State.Health.Status}}' 'shop-web' "
                      "| grep -qx healthy", out)
        self.assertIn("retry   : the probe, up to 20 tries, 3s apart", out)
        (planned,) = self.ev("action_planned")
        self.assertEqual(planned["action"], "wait_healthy")
        self.assertEqual(planned["action_version"], 1)
        self.assertEqual(planned["params"], '{"container":"shop-web","interval":3,"tries":20}')
        exp = actions.expand("wait_healthy", json.loads(WITH_WH), "edge1")
        self.assertEqual(planned["body_sha256"], {"edge1": exp.body_sha256()})

    def test_read_action_retries_its_probe(self):
        answers = [(1, "", ""), (1, "", ""), (0, "", "")]
        ssh = self.scripted_ssh([("docker inspect", lambda: answers.pop(0), None)])
        rc, out = self.door(["edge1", "--action", "wait_healthy", "--with", WITH_WH], ssh=ssh)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len([s for s in self.sent if "docker inspect" in s[1]]), 3)

    def test_read_action_fails_after_its_tries(self):
        ssh = self.scripted_ssh([("docker inspect", 1, "")])
        rc, out = self.door(["edge1", "--action", "wait_healthy",
                            "--with", '{"container": "shop-web", "tries": 4}'], ssh=ssh)
        self.assertEqual(rc, 1)
        self.assertEqual(len([s for s in self.sent if "docker inspect" in s[1]]), 4)

    def test_a_read_action_whose_body_is_not_a_read_is_refused(self):
        r, _ = self.door(["edge1", "--action", "p0_badread", "--with", '{"path": "/tmp/x"}'])
        self.assertIsInstance(r, Refused)
        self.assertIn("not a read", str(r))
        self.assertEqual([s for s in self.sent if "touch" in s[1]], [])

    def test_hand_typed_canonical_is_reserved(self):
        for cmd in (WH, "true; " + WH, "vpscfg-action wait_healthy@2 '{}'"):
            r, _ = self.door(["edge1", cmd])
            self.assertIsInstance(r, Refused, cmd)
            self.assertIn("reserved spelling", str(r))
        self.assertEqual(self.sent, [])

    def test_cli_refusals(self):
        for argv, word in (
                (["edge1", "--action", "wait_healthy@2", "--with", WITH_WH], "version 1"),
                (["edge1", "--action", "nope", "--with", "{}"], "unknown action"),
                (["edge1", "--action", "wait_healthy", "--with", '{"container": 1}'],
                 "with.container"),
                (["edge1", "--action", "wait_healthy", "--with", "{bad"], "not valid JSON"),
                (["edge1", "--with", WITH_WH, "uptime"], "needs --action"),
                (["edge1", "uptime", "--action", "wait_healthy", "--with", WITH_WH],
                 "takes no command text"),
                (["edge1", "--action", "wait_healthy", "--with", WITH_WH, "--in", "shop-web"],
                 "does not apply"),
                (["edge1", "--action", "wait_healthy", "--with", WITH_WH, "--verify",
                  "uptime"], "does not apply"),
                (["edge1", "--action", "wait_healthy", "--with", WITH_WH, "--incident",
                  "ic_x"], "does not apply")):
            r, _ = self.door(argv)
            self.assertIsInstance(r, Refused, argv)
            self.assertIn(word, str(r), argv)
        self.assertEqual(self.sent, [])

    def test_risky_extra_on_the_canonical_string_tightens_a_read(self):
        r, _ = self.door(["edge1", "--action", "wait_healthy", "--with", WITH_WH, "--run",
                         "--reason", "x"], policy=tv._yaml_policy(risky_extra=["shop-web"]))
        self.assertIsInstance(r, Refused)
        self.assertIn("'risky' (shop-web)", str(r))
        self.assertEqual(self.sent, [])


# ---------------------------------------------------------------------------
# a mutation action: authorisation, check semantics, plan-hash
# ---------------------------------------------------------------------------

def _touch_entry(hosts=("edge1",), path="/tmp/vpscfg-p0/marker", break_glass=False):
    exps = dict((h, actions.expand("p0_touch", {"path": path}, h)) for h in hosts)
    first = exps[hosts[0]]
    return {"hosts": list(hosts), "cmd": first.canonical, "where": "host", "why": "test",
            "break_glass": break_glass, "source": "touch.yaml", "expires": "2999-01-01",
            "verify": first.verify_text(), "timeout": 30, "rollback": False,
            "verify_retry": None, "container": None,
            "action": {"name": "p0_touch", "version": 1, "params": first.params,
                       "tier": "mutation", "expansions": exps}}


TOUCH = ["--action", "p0_touch", "--with", '{"path": "/tmp/vpscfg-p0/marker"}']


class MutationActionDoorTest(_Registered, _Door):
    ACTIONS = (TouchAction, SqlAction, WriteCheckAction)

    def pol(self, **kw):
        return tv._yaml_policy(runbooks=[_touch_entry(**kw)])

    def test_unauthorised_mutation_action_refuses(self):
        r, _ = self.door(["edge1"] + TOUCH + ["--run", "--reason", "x"])
        self.assertIsInstance(r, Refused)
        self.assertIn("typed action p0_touch@1", str(r))
        self.assertEqual([s for s in self.sent if "touch" in s[1]], [])

    def test_frozen_host_needs_a_break_glass_runbook(self):
        r, _ = self.door(["web1"] + TOUCH + ["--run", "--reason", "x", "--break-glass"],
                        policy=self.pol(hosts=("web1",)))
        self.assertIsInstance(r, Refused)
        self.assertIn("break_glass runbook", str(r))

    def test_a_committed_break_glass_action_reaches_a_frozen_host(self):
        ssh = self.scripted_ssh([("echo VPSCFG-DONE", 0, "VPSCFG-NEEDED\n")])
        rc, out = self.door(["web1"] + TOUCH + ["--run", "--reason", "x", "--break-glass",
                                                "--no-grant"],
                            policy=self.pol(hosts=("web1",), break_glass=True), ssh=ssh)
        self.assertEqual(rc, 0, out)
        self.assertIn("BREAK-GLASS: 1 of 1 host(s) elevated", out)
        self.assertEqual(len(self.ev("break_glass")), 1)

    def test_needed_runs_body_then_verify(self):
        ssh = self.scripted_ssh([("echo VPSCFG-DONE", 0, "VPSCFG-NEEDED\n")])
        rc, out = self.door(["edge1"] + TOUCH + ["--run", "--reason", "x"], policy=self.pol(),
                           ssh=ssh)
        self.assertEqual(rc, 0, out)
        cmds = [c for _, c, _ in self.sent if "vpscfg.lock" not in c]
        self.assertEqual(cmds, ["ls -d '/tmp/vpscfg-p0/marker' >/dev/null 2>&1 && echo "
                                "VPSCFG-DONE || echo VPSCFG-NEEDED",
                                "touch '/tmp/vpscfg-p0/marker'",
                                "ls -d '/tmp/vpscfg-p0/marker'"])
        self.assertIn("check:", out)
        (done,) = self.ev("host_done")
        self.assertIs(done["already_done"], False)
        (step,) = self.ev("step")
        self.assertEqual(step["action"], "p0_touch")
        self.assertEqual(step["body_sha256"], actions.sha256_text("touch '/tmp/vpscfg-p0/marker'"))
        self.assertEqual(self.ev("action_check")[0]["token"], "VPSCFG-NEEDED")
        complete = self.ev("mutation_complete")[0]
        self.assertIn("action_body_sha256", complete)

    def test_done_skips_body_and_verify(self):
        ssh = self.scripted_ssh([("echo VPSCFG-DONE", 0, "VPSCFG-DONE\n")])
        rc, out = self.door(["edge1"] + TOUCH + ["--run", "--reason", "x"], policy=self.pol(),
                           ssh=ssh)
        self.assertEqual(rc, 0, out)
        self.assertIn("[done] edge1", out)
        cmds = [c for _, c, _ in self.sent if "vpscfg.lock" not in c]
        self.assertEqual(len(cmds), 1, cmds)  # the check only
        self.assertEqual(self.ev("step"), [])
        (done,) = self.ev("host_done")
        self.assertIs(done["already_done"], True)
        self.assertEqual(len(self.ev("action_already_done")), 1)
        self.assertNotIn("lock retained", out)
        self.assertNotIn("lock not released", out)

    def test_check_abuse_fails_closed(self):
        def lost():
            raise OSError("SSH connection lost")

        def slow():
            raise subprocess.TimeoutExpired("ssh", 60)
        for rc, out in ((0, "VPSCFG-DONE\nextra\n"), (0, "vpscfg-done\n"), (0, ""),
                        (1, "VPSCFG-DONE\n"), (0, " VPSCFG-DONE"), (0, "VPSCFG-DONE\n\n"),
                        (lost, None), (slow, None)):
            ssh = self.scripted_ssh([("echo VPSCFG-DONE", rc, out)])
            got, text = self.door(["edge1"] + TOUCH + ["--run", "--reason", "x"],
                                 policy=self.pol(), ssh=ssh)
            self.assertEqual(got, 1, (rc, out, text))
            self.assertIn("failing closed", text)
            self.assertEqual([c for _, c, _ in self.sent if c.startswith("touch")], [],
                             (rc, out))
            self.assertNotIn("BLOCKED: lock retained", text)

    def test_check_made_non_read_by_risky_extra_refuses_at_plan_time(self):
        pol = self.pol()
        pol["risky_extra"] = ["ls -d"]
        r, _ = self.door(["edge1"] + TOUCH, policy=pol)
        self.assertIsInstance(r, Refused)
        self.assertIn("done-check", str(r))

    def test_plan_hash_binds_the_body(self):
        ssh = self.scripted_ssh([])
        argv = ["edge1"] + TOUCH + ["--reason", "x"]
        rc, out1 = self.door(argv, policy=self.pol(), ssh=ssh)
        self.assertEqual(rc, 0, out1)
        real = TouchAction.build

        def drifted(self, p, host):
            return dict(real(self, p, host), body="touch %s; true" % base.sq(p["path"]))
        TouchAction.build = drifted
        try:
            rc, out2 = self.door(argv, policy=self.pol(), ssh=ssh)
        finally:
            TouchAction.build = real
        h1 = [l for l in out1.splitlines() if l.startswith("plan-hash:")]
        h2 = [l for l in out2.splitlines() if l.startswith("plan-hash:")]
        self.assertEqual(len(h1), 1)
        self.assertNotEqual(h1, h2)
        self.assertIn("touch '/tmp/vpscfg-p0/marker'; true", out2)
        self.assertEqual([s for s in self.sent if "touch" in s[1]], [], "plan only")

    def test_override_reaches_a_test_host_but_never_break_glass(self):
        ov = Path(self.tmp.name) / "ov.yml"
        ov.write_text(textwrap.dedent("""\
            version: 1
            expires: "2999-01-01"
            reason: test
            allow:
              - hosts: [edge1]
                action: p0_touch
                with: {path: /tmp/vpscfg-p0/marker}
                why: "test"
            """))
        ssh = self.scripted_ssh([("echo VPSCFG-DONE", 0, "VPSCFG-NEEDED")])
        rc, out = self.door(["edge1"] + TOUCH + ["--run", "--reason", "x", "--override",
                                                str(ov)], ssh=ssh)
        self.assertEqual(rc, 0, out)
        ov.write_text(ov.read_text().replace('why: "test"', 'why: "test"\n    break_glass: true'))
        r, _ = self.door(["edge1"] + TOUCH + ["--override", str(ov)])
        self.assertIsInstance(r, Refused)
        ov.write_text(textwrap.dedent("""\
            version: 1
            expires: "2999-01-01"
            reason: test
            allow:
              - hosts: [edge1]
                cmd: %s
                why: "sneaky"
            """ % json.dumps(actions.expand("p0_touch", {"path": "/tmp/x"}, "edge1").canonical)))
        r, _ = self.door(["edge1"] + TOUCH + ["--override", str(ov)])
        self.assertIsInstance(r, Refused)
        self.assertIn("reserved spelling", str(r))

    def test_sql_check_goes_through_the_sqlread_gate(self):
        exp = actions.expand("p0_sql", {"container": "shop-db", "db": "shop"}, "edge1")
        entry = dict(_touch_entry(), cmd=exp.canonical, verify=None)
        argv = ["edge1", "--action", "p0_sql", "--with",
                '{"container": "shop-db", "db": "shop"}', "--run", "--reason", "x"]
        ssh = self.scripted_ssh([("docker exec -i", 0, "@@@check\nVPSCFG-DONE\n")])
        rc, out = self.door(argv, policy=tv._yaml_policy(runbooks=[entry]), ssh=ssh)
        self.assertEqual(rc, 0, out)
        (host, cmd, data) = [s for s in self.sent if "docker exec" in s[1]][0]
        script = data.decode()
        self.assertIn("BEGIN READ ONLY", script)
        self.assertIn("statement_timeout", script)
        self.assertIn("default_transaction_read_only=on", cmd)
        self.assertNotIn("PGPASSWORD=", cmd.split("sh -c")[0])
        self.assertIn("[done] edge1", out)
        for bad in ("@@@check\nVPSCFG-DONE\nx\n", "VPSCFG-DONE\n", "@@@check\n"):
            ssh = self.scripted_ssh([("docker exec -i", 0, bad)])
            got, text = self.door(argv, policy=tv._yaml_policy(runbooks=[entry]), ssh=ssh)
            self.assertEqual(got, 1, bad)
            self.assertIn("failing closed", text)

    def test_a_writing_sql_check_is_refused_at_plan_time(self):
        r, _ = self.door(["edge1", "--action", "p0_writecheck", "--with",
                         '{"container": "shop-db", "db": "shop"}'])
        self.assertIsInstance(r, Refused)
        self.assertIn("sqlread", str(r))


# ---------------------------------------------------------------------------
# end to end on the detached transport: policy file -> door -> twice-run no-op
# ---------------------------------------------------------------------------

HOST = "edge1"


def _local(host, cmd, timeout=None, connect_timeout=None, data=None):
    r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                       timeout=timeout or 60, input=data.decode() if data else None)
    return r.returncode, r.stdout, r.stderr


_local.detached = True


class DetachedEndToEndTest(_Registered, _PolicyDir):
    ACTIONS = (TouchAction,)

    def setUp(self):
        super().setUp()
        root = Path(self.tmp.name)
        self.saved = (detach.OPS_DIR, lock.LOCK_DIR, detach._sleep, lock.controller)
        detach.OPS_DIR = str(root / "ops")
        lock.LOCK_DIR = str(root / "lock")
        detach._sleep = lambda s: time.sleep(0.02)
        self.marker = root / "work" / "marker"
        self.marker.parent.mkdir()

    def tearDown(self):
        detach.OPS_DIR, lock.LOCK_DIR, detach._sleep, lock.controller = self.saved
        time.sleep(0.2)
        super().tearDown()

    def guard(self):
        gov = tv._policy()
        gov["allow_unmanaged_steps"] = [HOST]
        return tv._guard(gov)

    def go(self):
        policy = self.load()
        self.assertEqual(policy["misshapen"], [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = vpsexec.dispatch(
                [HOST, "--action", "p0_touch", "--with", json.dumps({"path": str(self.marker)}),
                 "--run", "--reason", "p0 e2e"],
                guard=self.guard(), policy=policy, prober=self.prober(), ssh=_local,
                stream=tv.ApprovalTest._TTY(), prompt=lambda m: HOST, today=TODAY,
                blackout_runner=self.blackout_runner(unavailable=True))
        return rc, out.getvalue()

    def test_policy_to_detached_run_and_a_second_run_is_a_no_op(self):
        self.armed(_action_policy(action="p0_touch", with_="{path: %s}" % self.marker))
        rc, out = self.go()
        self.assertEqual(rc, 0, out)
        self.assertTrue(self.marker.exists())
        self.assertFalse(Path(lock.LOCK_DIR).exists(), "the lock is released")
        first = [e for e in self.events() if e.get("event") == "host_done"]
        self.assertIs(first[-1]["already_done"], False)
        steps = [e for e in self.events() if e.get("event") == "step"]
        self.assertEqual(len(steps), 1)
        self.assertRegex(steps[0]["operation_id"], r"^[0-9a-f]{64}$")

        rc, out = self.go()
        self.assertEqual(rc, 0, out)
        self.assertIn("[done] %s" % HOST, out)
        self.assertEqual(len([e for e in self.events() if e.get("event") == "step"]), 1,
                         "the second run ran no body")
        last = [e for e in self.events() if e.get("event") == "host_done"][-1]
        self.assertIs(last["already_done"], True)
        self.assertFalse(Path(lock.LOCK_DIR).exists())

    def test_a_check_never_runs_under_another_operations_lock(self):
        self.armed(_action_policy(action="p0_touch", with_="{path: %s}" % self.marker))
        lock.acquire(HOST, "alice", "someone else", runner=_local)
        rc, out = self.go()
        self.assertEqual(rc, 1)
        self.assertFalse([e for e in self.events() if e.get("event") == "action_check"])
        self.assertTrue(Path(lock.LOCK_DIR).exists(), "another op's lock is untouched")


# ---------------------------------------------------------------------------
# S12: the new files carry no estate data
# ---------------------------------------------------------------------------

class PublicHygieneTest(unittest.TestCase):
    FILES = sorted(list((REPO / "vpscfg" / "actions").glob("*.py"))
                   + list(GOLDEN.glob("*.json"))
                   + [REPO / "docs" / "ACTIONS.md", Path(__file__)])

    def test_exporter_scan_finds_nothing(self):
        spec = importlib.util.spec_from_file_location("export_public",
                                                      REPO / "tools" / "export-public.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for path in self.FILES:
            hits = mod.scan_text(str(path.relative_to(REPO)), path.read_text(), [])
            self.assertEqual(hits, [], path)

    def test_actions_doc_is_exported(self):
        allow = (REPO / "tools" / "public-allowlist.txt").read_text().splitlines()
        self.assertIn("docs/ACTIONS.md", allow)


if __name__ == "__main__":
    unittest.main()
