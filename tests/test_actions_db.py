"""P1a: the database actions ensure_owner, pg_dump and migrate (vpscfg/actions/db.py).

Hermetic. Policies live in temp dirs; the "host" is either a scripted fake or
local bash with stub `docker`, `psql`, `pg_dump`, `pg_restore`, `prisma` and
`alembic` binaries first on PATH, with the lock dir redirected to a temp dir.
The journal is redirected. Nothing dials a host or reads ~/.vpscfg.

Adversarial items from the phase-2 plan covered here:
  1 param injection (every string parameter of every action)
  2 YAML type confusion (through the policy loader)
  4 template floor sweep (a wider valid corpus than the golden samples)
  5 check abuse (fails closed; a non-read check refused at plan time)
  6 secret leak hunt (a seeded password, every captured byte grepped)
  7 expansion drift (a one-byte template change fails the golden file)
plus twice-run idempotency for ensure_owner and pg_dump on the fake host.
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
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_actions_core as core  # noqa: E402
import test_vpsexec as tv  # noqa: E402
from vpscfg import actions, hostindex, lock, probe, vpsexec, vpsexecpolicy  # noqa: E402
from vpscfg.actions import base, db  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused, deny_scan  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "tests" / "golden" / "actions"
DENY = list(DENY_ALWAYS_FLOOR)
TODAY = core.TODAY
MINE = ("ensure_owner", "pg_dump", "migrate")
SEED = "alice-Fake-Pw-7Q2x9"   # a fake password; must appear in no captured byte

OWNER = {"container": "pg-main", "db": "shop", "role": "app_owner", "schema": "sales"}
DUMP = {"container": "pg-main", "db": "shop", "dest_dir": "/var/backups/db1", "label": "rel-1.5"}
MIG = {"container": "shop-api", "runner": "prisma_deploy", "workdir": "/app"}


def refused(name, params, word=None):
    try:
        actions.expand(name, params, "edge1")
    except Refused as r:
        if word is not None and word not in str(r):
            raise AssertionError("%s %r refused, but without %r: %s" % (name, params, word, r))
        return str(r)
    raise AssertionError("%s accepted %r" % (name, params))


# ---------------------------------------------------------------------------
# the password is read in the container exactly as the host index reads it
# ---------------------------------------------------------------------------

class PasswordHandlingTest(unittest.TestCase):
    def test_in_container_text_is_the_host_index_text(self):
        self.assertEqual(db.PSQL_STDIN, hostindex._PG_IN_CONTAINER)
        self.assertTrue(hostindex._PG_IN_CONTAINER.startswith(db.PG_PASSWORD))

    def test_no_template_puts_a_password_or_dsn_on_argv(self):
        for name in MINE:
            for sample in base.REGISTRY[name].samples:
                exp = actions.expand(name, sample, "edge1")
                for text in [exp.canonical] + exp.texts():
                    for bad in ("PGPASSWORD=", "--password", "postgres://", "postgresql://",
                                "DATABASE_URL="):
                        # PGPASSWORD= only ever appears inside the in-container
                        # script, assigned from the container's own secret.
                        if bad == "PGPASSWORD=":
                            for line in text.split("PGPASSWORD=")[1:]:
                                self.assertTrue(line.startswith(('$(cat "$POSTGRES_PASSWORD_FILE")',
                                                                 '"${POSTGRES_PASSWORD:-')),
                                                (name, text))
                            continue
                        self.assertNotIn(bad, text, (name, text))


# ---------------------------------------------------------------------------
# param type tables: accept and refuse
# ---------------------------------------------------------------------------

class ParamTableTest(unittest.TestCase):
    ACCEPT = {
        "ensure_owner": [OWNER, dict(OWNER, role="shop_app", schema="public"),
                         dict(OWNER, container="db1.pg-14", db="_x", schema="s1")],
        "pg_dump": [DUMP, dict(DUMP, min_free_gb=1), dict(DUMP, min_free_gb=100000),
                    dict(DUMP, label="shop-1.5.0_pre"), dict(DUMP, dest_dir="/srv/b@k+1")],
        "migrate": [MIG, {"container": "shop-api", "runner": "alembic_upgrade_head"},
                    {"container": "shop-api", "runner": "node_pg_migrate_up",
                     "workdir": "/srv/shop"},
                    {"container": "pg-main", "runner": "sql_dir", "db": "shop",
                     "workdir": "/docker-entrypoint-initdb.d"}],
    }
    REFUSE = {
        "ensure_owner": [
            ({}, "missing"), (dict(OWNER, colour="red"), "unknown"),
            (dict(OWNER, role="pg_read_all_data"), "system role"),
            (dict(OWNER, schema="pg_catalog"), "system schema"),
            (dict(OWNER, schema="information_schema"), "system schema"),
            (dict(OWNER, role="Shop_App"), "with.role"), (dict(OWNER, db="shop-db"), "with.db"),
            (dict(OWNER, schema="a" * 64), "with.schema"), (dict(OWNER, container="-x"), None),
            (dict(OWNER, role=None), "with.role")],
        "pg_dump": [
            (dict(DUMP, dest_dir="/var/backups/db1/"), "with.dest_dir"),
            (dict(DUMP, dest_dir="var/backups"), "with.dest_dir"),
            (dict(DUMP, dest_dir="/"), "with.dest_dir"),
            (dict(DUMP, dest_dir="/var/../etc"), "with.dest_dir"),
            (dict(DUMP, label=".hidden"), "with.label"), (dict(DUMP, label="-x"), None),
            (dict(DUMP, label="a/b"), "with.label"), (dict(DUMP, min_free_gb=0), "with.min_free_gb"),
            (dict(DUMP, min_free_gb=100001), "with.min_free_gb"),
            (dict(DUMP, min_free_gb="5"), "with.min_free_gb"),
            (dict(DUMP, min_free_gb=5.0), "with.min_free_gb"),
            (dict(DUMP, min_free_gb=True), "with.min_free_gb"),
            ({k: v for k, v in DUMP.items() if k != "label"}, "with.label is missing")],
        "migrate": [
            (dict(MIG, runner="npx prisma migrate deploy"), "with.runner"),
            (dict(MIG, runner="PRISMA_DEPLOY"), "with.runner"),
            (dict(MIG, runner="prisma"), "with.runner"), (dict(MIG, runner=1), "with.runner"),
            (dict(MIG, runner=["prisma_deploy"]), "with.runner"),
            (dict(MIG, db="shop"), "sql_dir only"),
            ({"container": "pg-main", "runner": "sql_dir", "db": "shop"}, "needs workdir"),
            ({"container": "pg-main", "runner": "sql_dir", "workdir": "/m"}, "needs workdir"),
            (dict(MIG, workdir="/app/"), "with.workdir"), (dict(MIG, cmd="true"), "unknown")],
    }

    def test_accept_table(self):
        for name, rows in self.ACCEPT.items():
            for params in rows:
                exp = actions.expand(name, params, "edge1")
                self.assertEqual(exp.tier, "mutation")
                for k, v in params.items():
                    self.assertEqual(exp.params[k], v)

    def test_refuse_table(self):
        for name, rows in self.REFUSE.items():
            for params, word in rows:
                refused(name, params, word)

    def test_idempotency_and_checks_are_declared_per_action(self):
        owner = actions.expand("ensure_owner", OWNER, "edge1")
        self.assertTrue(owner.idempotent)
        self.assertIsInstance(owner.check, base.SqlCheck)
        self.assertIs(owner.verify, owner.check)
        dump = actions.expand("pg_dump", DUMP, "edge1")
        self.assertTrue(dump.idempotent)
        self.assertIn("sha256sum --check --status", dump.check)
        for sample in base.REGISTRY["migrate"].samples:
            mig = actions.expand("migrate", sample, "edge1")
            self.assertFalse(mig.idempotent)
            self.assertIsNone(mig.check)

    def test_assumes(self):
        self.assertEqual(actions.expand("ensure_owner", OWNER, "edge1").assumes,
                         ({"container": "pg-main", "host": "edge1"},))
        self.assertEqual(actions.expand("pg_dump", dict(DUMP, min_free_gb=5), "edge1").assumes,
                         ({"container": "pg-main", "host": "edge1"},
                          {"min_free_gb": {"/var/backups/db1": 5}, "host": "edge1"}))
        self.assertEqual(actions.expand("migrate", MIG, "edge1").assumes,
                         ({"container": "shop-api", "host": "edge1",
                           "env_names_any_of": [["DATABASE_URL"],
                                                ["DB_HOST", "DB_NAME", "DB_USER", "DB_PASS"]]},))
        self.assertEqual(actions.expand("migrate", self.ACCEPT["migrate"][3], "edge1").assumes,
                         ({"container": "pg-main", "host": "edge1"},))

    def test_runner_maps_to_one_fixed_command(self):
        want = {"prisma_deploy": "./node_modules/.bin/prisma migrate deploy",
                "alembic_upgrade_head": "alembic upgrade head",
                "node_pg_migrate_up": "./node_modules/.bin/node-pg-migrate up"}
        for runner, cmd in want.items():
            body = actions.expand("migrate", {"container": "shop-api", "runner": runner},
                                  "edge1").body
            self.assertEqual(body, "docker exec 'shop-api' %s" % cmd)
        self.assertEqual(set(db.MIGRATE_RUNNERS), set(want) | {"sql_dir"})

    def test_dump_name_is_deterministic_per_call(self):
        a = actions.expand("pg_dump", DUMP, "edge1")
        b = actions.expand("pg_dump", dict(reversed(list(DUMP.items()))), "web1")
        self.assertEqual(a.body, b.body)
        c = actions.expand("pg_dump", dict(DUMP, label="rel-1.6"), "edge1")
        self.assertNotEqual(db.dump_suffix(a.params), db.dump_suffix(c.params))
        # min_free_gb is not part of the name: same dump, more or less checking
        d = actions.expand("pg_dump", dict(DUMP, min_free_gb=9), "edge1")
        self.assertEqual(db.dump_suffix(a.params), db.dump_suffix(d.params))


# ---------------------------------------------------------------------------
# adversarial 1: the injection corpus, every string parameter of every action
# ---------------------------------------------------------------------------

class InjectionCorpusTest(unittest.TestCase):
    CORPUS = ["shop; DROP SCHEMA shop", "x\" OWNER TO postgres; --", "x' OWNER TO postgres; --",
              "a\nb", "a\x00b", "a\rb", "a\tb", "$(id)", "`id`", "--help", "-rf", "ѕhop",
              "ｓhop", "x" * 10000, "../etc", "shop/", "SHOP", "Shop", "a b", "a|b", "a&b",
              "a>b", "{a}", "*", "@file", "shop\n", "%I", "$1", "VPSCFG_SQL\nDROP"]
    BASES = {"ensure_owner": OWNER, "pg_dump": DUMP, "migrate": MIG,
             "migrate_sql": {"container": "pg-main", "runner": "sql_dir", "db": "shop",
                             "workdir": "/migrations"}}

    def test_every_parameter_refuses_every_injection(self):
        for key, good in self.BASES.items():
            name = "migrate" if key == "migrate_sql" else key
            action = base.REGISTRY[name]
            for pname in action.params:
                for value in self.CORPUS:
                    # ABS_PATH / BASENAME / CONTAINER legitimately take some
                    # uppercase or dotted values; those are not injections.
                    if value in ("SHOP", "Shop") and pname in ("container", "label"):
                        continue
                    with self.assertRaises(Refused, msg="%s.%s accepted %r" % (key, pname, value)):
                        actions.expand(name, dict(good, **{pname: value}), "edge1")

    def test_uppercase_identifiers_are_refused(self):
        for pname in ("db", "role", "schema"):
            refused("ensure_owner", dict(OWNER, **{pname: "Shop"}), "with.%s" % pname)
        refused("pg_dump", dict(DUMP, db="SHOP"), "with.db")


# ---------------------------------------------------------------------------
# adversarial 2: YAML type confusion, through the policy loader
# ---------------------------------------------------------------------------

def _policy(action, with_, host="edge1"):
    return "\n".join([
        "version: 1", 'expires: "2026-12-31"', "reason: db actions (test)",
        "shape: {steps: 1, hosts: [%s], break_glass: false}" % host,
        "runbooks:", "  - hosts: [%s]" % host, "    action: %s" % action,
        "    with: %s" % with_, "    timeout: 600", '    why: "D1: database step"']) + "\n"


class YamlTypeConfusionTest(core._PolicyDir):
    def refuses(self, text, word):
        self.write(text)
        with self.assertRaises(Refused) as cm:
            self.load()
        self.assertIn(word, str(cm.exception))

    def test_policy_loads_and_disarms_without_expands(self):
        path = self.write(_policy("ensure_owner",
                                  "{container: pg-main, db: shop, role: app_owner, schema: sales}"))
        self.assertIn("expands", self.load()["misshapen"][0]["reason"])
        path.write_text(path.read_text() + 'expands: "%s"\n' % self.digest(path))
        (entry,) = self.load()["runbooks"]
        self.assertEqual(entry["cmd"], actions.expand("ensure_owner", OWNER, "edge1").canonical)

    def test_type_confusion_refuses_the_load(self):
        dump = "{container: pg-main, db: shop, dest_dir: /var/backups/db1, label: rel-1.5%s}"
        for text, word in (
                (_policy("pg_dump", dump % ', min_free_gb: "5"'), "with.min_free_gb"),
                (_policy("pg_dump", dump % ", min_free_gb: 5.5"), "with.min_free_gb"),
                (_policy("pg_dump", dump % ", min_free_gb: yes"), "with.min_free_gb"),
                (_policy("pg_dump", dump % ", min_free_gb: [5]"), "with.min_free_gb"),
                (_policy("pg_dump", "[pg-main, shop]"), "mapping"),
                (_policy("pg_dump", "pg-main"), "mapping"),
                (_policy("ensure_owner", "{container: pg-main, db: 420, role: a, schema: b}"),
                 "with.db"),
                (_policy("ensure_owner", "{container: pg-main, db: null, role: a, schema: b}"),
                 "with.db"),
                (_policy("ensure_owner", "{container: pg-main, db: on, role: a, schema: b}"),
                 "with.db"),
                (_policy("ensure_owner", "{container: pg-main, db: {x: 1}, role: a, schema: b}"),
                 "with.db"),
                (_policy("migrate", "{container: shop-api, runner: yes}"), "with.runner"),
                (_policy("migrate", "{container: shop-api, runner: [prisma_deploy]}"),
                 "with.runner"),
                (_policy("migrate", "{container: shop-api, runner: prisma_deploy, "
                                    "runner: sql_dir}"), "duplicate"),
                (_policy("migrate@1", "{container: shop-api, runner: prisma_deploy}"),
                 "action: names the action only")):
            self.refuses(text, word)

    def test_anchor_alias_cannot_smuggle_a_duplicate_key(self):
        text = _policy("migrate", "{container: shop-api, runner: prisma_deploy}").replace(
            "    with: {container: shop-api, runner: prisma_deploy}",
            "    with: &w {container: shop-api, runner: prisma_deploy}\n    with: *w")
        self.refuses(text, "duplicate")

    def test_cmd_beside_action_refuses(self):
        text = _policy("migrate", "{container: shop-api, runner: prisma_deploy}").replace(
            "    action: migrate", '    action: migrate\n    cmd: "alembic upgrade head"')
        self.refuses(text, "both cmd: and action:")


# ---------------------------------------------------------------------------
# adversarial 4: floor sweep over a wider valid corpus; checks gate as reads
# ---------------------------------------------------------------------------

class FloorSweepTest(unittest.TestCase):
    # Values chosen so that no value is a substring of another value or of
    # the template text: the quoting property is then checkable by search.
    CORPUS = {
        "ensure_owner": [OWNER, {"container": "db1.pg", "db": "orders_v2", "role": "svc_rw",
                                 "schema": "billing"}],
        "pg_dump": [DUMP, dict(DUMP, min_free_gb=40),
                    {"container": "db1.pg", "db": "orders_v2", "dest_dir": "/srv/dumps",
                     "label": "weekly_7"}],
        "migrate": list(base.REGISTRY["migrate"].samples) + [
            {"container": "web-api.2", "runner": "alembic_upgrade_head", "workdir": "/srv/api"}],
    }

    def test_no_text_hits_the_floor_and_every_value_is_quoted(self):
        for name, rows in self.CORPUS.items():
            for params in rows:
                exp = actions.expand(name, params, "edge1")
                for text in [exp.canonical] + exp.texts():
                    deny_scan(text, DENY)
                shell = [exp.body] + [p for p in (exp.check, exp.verify) if isinstance(p, str)]
                for value in (v for v in exp.params.values() if isinstance(v, str)):
                    for text in shell:
                        start = text.find(value)
                        while start != -1:
                            end = start + len(value)
                            self.assertTrue(text[start - 1:start] == "'"
                                            and text[end:end + 1] == "'",
                                            "%s: %r outside single quotes in %r"
                                            % (name, value, text))
                            start = text.find(value, end)

    def test_every_check_and_verify_passes_the_doors_plan_time_gate(self):
        for name, rows in self.CORPUS.items():
            for params in rows:
                exp = actions.expand(name, params, "edge1")
                vpsexec._gate_action({"edge1": exp}, DENY, [])

    def test_the_sql_check_passes_the_sqlread_gate_and_writes_nothing(self):
        exp = actions.expand("ensure_owner", OWNER, "edge1")
        script = exp.check.script()
        self.assertIn("BEGIN READ ONLY", script)
        self.assertIn("default_transaction_read_only=on", exp.check.command())

    def test_the_body_is_one_transaction_and_quotes_identifiers_server_side(self):
        body = actions.expand("ensure_owner", OWNER, "edge1").body
        sql = body.split("<<'VPSCFG_SQL'\n", 1)[1]
        self.assertTrue(sql.startswith("BEGIN;\n"))
        self.assertTrue(sql.endswith("COMMIT;\nVPSCFG_SQL"))
        self.assertEqual(sql.count("VPSCFG_SQL"), 1)
        self.assertIn("format('ALTER SCHEMA %I OWNER TO %I'", sql)
        self.assertIn("lock_timeout", sql)
        for verb in ("DROP", "TRUNCATE", "DELETE", "GRANT", "REVOKE", "INSERT", "UPDATE"):
            self.assertNotIn(verb, sql.upper().replace("UPDATE_", ""))


# ---------------------------------------------------------------------------
# adversarial 7: the golden files pin every byte
# ---------------------------------------------------------------------------

class GoldenTest(unittest.TestCase):
    def test_golden_files_exist_and_match(self):
        for name in MINE:
            action = base.REGISTRY[name]
            path = GOLDEN / ("%s@%d.json" % (name, action.version))
            self.assertTrue(path.is_file(), path)
            self.assertEqual(core._golden_doc(action), json.loads(path.read_text()), name)

    def test_a_one_byte_change_in_any_template_is_caught(self):
        for name in MINE:
            action = base.REGISTRY[name]
            want = json.loads((GOLDEN / ("%s@%d.json" % (name, action.version))).read_text())
            real = type(action).build

            def drifted(self, p, host, real=real):
                out = real(self, p, host)
                return dict(out, body=out["body"].replace("docker", "docker ", 1))
            type(action).build = drifted
            try:
                self.assertNotEqual(core._golden_doc(action), want, name)
            finally:
                type(action).build = real


# ---------------------------------------------------------------------------
# the fake host: local bash with stub binaries first on PATH
# ---------------------------------------------------------------------------

STUB_DOCKER = r"""#!/bin/sh
# docker exec [-i] [-w DIR] [-e K=V]... CONTAINER CMD...: the "container" is
# this shell with the container's own secret in its environment.
test "$1" = exec || { echo "stub docker: only exec" >&2; exit 90; }
shift
while :; do
  case "$1" in
    -i) shift ;;
    -w) cd "$2" || exit 91; shift 2 ;;
    -e) export "$2"; shift 2 ;;
    *) break ;;
  esac
done
echo "$1" >> "$STUB_STATE/containers"
shift
POSTGRES_PASSWORD="$STUB_SEED"; export POSTGRES_PASSWORD
exec "$@"
"""

STUB_PSQL = r"""#!/bin/sh
# Reads its script on stdin. Owner state lives in $STUB_STATE/owned.
test "$PGPASSWORD" = "$STUB_SEED" && touch "$STUB_STATE/pw-seen"
script=$(cat)
case "$script" in
  *"BEGIN READ ONLY"*)
    test "$PGOPTIONS" = "-c default_transaction_read_only=on" || exit 92
    echo "@@@check"
    if test -e "$STUB_STATE/owned"; then echo VPSCFG-DONE; else echo VPSCFG-NEEDED; fi ;;
  *"ALTER SCHEMA"*)
    test -z "$PGOPTIONS" || exit 93
    touch "$STUB_STATE/owned"; echo "pending table 8"; echo "owned 8" ;;
  *) echo "stub psql: unexpected script" >&2; exit 94 ;;
esac
"""

STUB_PG_DUMP = r"""#!/bin/sh
test "$PGPASSWORD" = "$STUB_SEED" && touch "$STUB_STATE/pw-seen"
test "$1" = -Fc || exit 95
printf 'PGDMP fake custom-format dump of %s\n' "$PGDATABASE"
"""

STUB_PG_RESTORE = r"""#!/bin/sh
test "$1" = --list || exit 96
head -c 5 | grep -q PGDMP
"""

STUB_PRISMA = r"""#!/bin/sh
if test -e "$STUB_STATE/fail-migrate"; then
  echo "Error: P1001: Can't reach database server at postgres://shop:$STUB_SEED@db1:5432/shop" >&2
  exit 1
fi
echo "1 migration applied"
"""


def _entry(name, params, host="edge1"):
    """A loaded runbook entry naming the action on `host` (non-break-glass)."""
    exp = actions.expand(name, params, host)
    return {"hosts": [host], "cmd": exp.canonical, "where": "host", "why": "test",
            "break_glass": False, "source": "db.yaml", "expires": "2999-01-01",
            "verify": exp.verify_text(), "timeout": exp.timeout, "rollback": False,
            "verify_retry": None, "container": None,
            "action": {"name": name, "version": exp.version, "params": exp.params,
                       "tier": "mutation", "expansions": {host: exp}}}


class _FakeHost(core._Door):
    """The door against local bash: real shell semantics for every body,
    check and verify, stub binaries for docker and the database clients."""

    def setUp(self):
        super().setUp()
        root = Path(self.tmp.name)
        self.saved_lock = (lock.LOCK_DIR, lock.controller)
        lock.LOCK_DIR = str(root / "lock")
        self.state = root / "state"
        self.state.mkdir()
        self.bin = root / "stubbin"
        self.bin.mkdir()
        self.app = root / "app"
        (self.app / "node_modules" / ".bin").mkdir(parents=True)
        for path, text in ((self.bin / "docker", STUB_DOCKER), (self.bin / "psql", STUB_PSQL),
                           (self.bin / "pg_dump", STUB_PG_DUMP),
                           (self.bin / "pg_restore", STUB_PG_RESTORE),
                           (self.app / "node_modules" / ".bin" / "prisma", STUB_PRISMA)):
            path.write_text(text)
            path.chmod(0o755)
        self.dumps = root / "backups"
        self.dumps.mkdir()
        self.env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ.get("PATH", "")),
                        STUB_SEED=SEED, STUB_STATE=str(self.state))
        self.sent = []
        self.streams = []        # what the fake host printed (may hold the seed)
        self.door_outputs = []   # what the door printed (must never)

    def tearDown(self):
        lock.LOCK_DIR, lock.controller = self.saved_lock
        super().tearDown()

    def local(self):
        def _ssh(host, cmd, timeout=None, connect_timeout=None, data=None):
            self.sent.append((host, cmd, data))
            r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                               timeout=timeout or 60, env=self.env,
                               input=data.decode() if data else None)
            self.streams += [r.stdout, r.stderr]
            return r.returncode, r.stdout, r.stderr
        return _ssh

    def run_action(self, name, params, ssh=None):
        argv = ["edge1", "--action", name, "--with", json.dumps(params), "--run",
                "--reason", "p1a test"]
        pol = tv._yaml_policy(runbooks=[_entry(name, params)])
        rc, out = self.door(argv, policy=pol, ssh=ssh or self.local())
        self.door_outputs.append(out)
        return rc, out


# ---------------------------------------------------------------------------
# idempotency: twice-run on the fake host, the second run is a no-op
# ---------------------------------------------------------------------------

class TwiceRunTest(_FakeHost):
    def test_ensure_owner_twice_second_is_a_no_op(self):
        rc, out = self.run_action("ensure_owner", OWNER)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("[done] edge1", out)
        self.assertIn("pending table 8", out)
        alters = [c for _, c, d in self.sent if "<<'VPSCFG_SQL'" in c]
        self.assertEqual(len(alters), 1)
        self.assertTrue((self.state / "pw-seen").exists(), "psql got the in-container password")
        dones = [e for e in self.events() if e.get("event") == "host_done"]
        self.assertIs(dones[-1]["already_done"], False)

        rc, out = self.run_action("ensure_owner", OWNER)
        self.assertEqual(rc, 0, out)
        self.assertIn("[done] edge1", out)
        self.assertEqual(len([c for _, c, d in self.sent if "<<'VPSCFG_SQL'" in c]), 1,
                         "the second run sent no body")
        dones = [e for e in self.events() if e.get("event") == "host_done"]
        self.assertIs(dones[-1]["already_done"], True)
        self.assertFalse(Path(lock.LOCK_DIR).exists(), "the lock is released")

    def test_pg_dump_twice_second_is_a_no_op(self):
        params = dict(DUMP, dest_dir=str(self.dumps))
        rc, out = self.run_action("pg_dump", params)
        self.assertEqual(rc, 0, out)
        name = "shop-rel-1.5-%s.dump" % db.dump_suffix(actions.validate(
            base.REGISTRY["pg_dump"], params))
        dump, record = self.dumps / name, self.dumps / (name + ".sha256")
        self.assertTrue(dump.is_file(), sorted(os.listdir(self.dumps)))
        self.assertEqual(stat.S_IMODE(dump.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertTrue(dump.read_bytes().startswith(b"PGDMP"))
        self.assertEqual(sorted(os.listdir(self.dumps)), sorted([name, name + ".sha256"]),
                         "no temp file left behind")
        self.assertIn("sha256", out)
        self.assertTrue((self.state / "pw-seen").exists())
        first = dump.read_bytes()

        rc, out = self.run_action("pg_dump", params)
        self.assertEqual(rc, 0, out)
        self.assertIn("[done] edge1", out)
        self.assertEqual(len([c for _, c, _ in self.sent if ".vpscfg-dump." in c]), 1,
                         "the second run sent no body")
        self.assertEqual(dump.read_bytes(), first)

    def test_pg_dump_never_overwrites_a_dump_it_cannot_vouch_for(self):
        params = dict(DUMP, dest_dir=str(self.dumps))
        rc, _ = self.run_action("pg_dump", params)
        self.assertEqual(rc, 0)
        name = [n for n in os.listdir(self.dumps) if n.endswith(".dump")][0]
        (self.dumps / name).write_bytes(b"PGDMP tampered")
        rc, out = self.run_action("pg_dump", params)
        self.assertNotEqual(rc, 0, out)
        self.assertEqual((self.dumps / name).read_bytes(), b"PGDMP tampered")

    def test_pg_dump_refuses_a_missing_dest_dir_and_an_unreadable_dump(self):
        rc, out = self.run_action("pg_dump", dict(DUMP, dest_dir=str(self.dumps / "nope")))
        self.assertNotEqual(rc, 0, out)
        (self.bin / "pg_restore").write_text("#!/bin/sh\nexit 1\n")
        rc, out = self.run_action("pg_dump", dict(DUMP, dest_dir=str(self.dumps)))
        self.assertNotEqual(rc, 0, out)
        self.assertEqual(os.listdir(self.dumps), [], "a dump pg_restore cannot read is removed")

    def test_pg_dump_refuses_a_world_writable_or_sticky_dest_dir(self):
        # L3: there anyone could plant the temp or record name first.
        for mode in (0o777, 0o1755, 0o1777):
            d = self.dumps / ("shared-%o" % mode)
            d.mkdir()
            os.chmod(d, mode)
            rc, out = self.run_action("pg_dump", dict(DUMP, dest_dir=str(d)))
            self.assertNotEqual(rc, 0, out)
            self.assertIn("world-writable or sticky", out)
            self.assertEqual(os.listdir(d), [], "nothing written to %o" % mode)

    def test_pg_dump_uses_fresh_temp_names_not_a_planted_one(self):
        # A name planted where v1 wrote its fixed temp file (a symlink out of
        # dest_dir) is never followed: v2's temp names come from mktemp.
        params = dict(DUMP, dest_dir=str(self.dumps))
        name = "shop-rel-1.5-%s.dump" % db.dump_suffix(actions.validate(
            base.REGISTRY["pg_dump"], params))
        victim = Path(self.tmp.name) / "victim"
        victim.write_text("keep\n")
        (self.dumps / (name + ".vpscfg-tmp")).symlink_to(victim)
        rc, out = self.run_action("pg_dump", params)
        self.assertEqual(rc, 0, out)
        self.assertEqual(victim.read_text(), "keep\n")
        self.assertTrue((self.dumps / name).read_bytes().startswith(b"PGDMP"))
        self.assertFalse([n for n in os.listdir(self.dumps) if n.startswith(".vpscfg-dump.")],
                         "no temp file left behind")
        body = actions.expand("pg_dump", params, "edge1").body
        self.assertIn('mktemp "$d/.vpscfg-dump.XXXXXX"', body)
        self.assertNotIn("vpscfg-tmp", body)

    def test_migrate_runs_its_fixed_command_and_is_not_idempotent(self):
        params = {"container": "shop-api", "runner": "prisma_deploy", "workdir": str(self.app)}
        rc, out = self.run_action("migrate", params)
        self.assertEqual(rc, 0, out)
        self.assertIn("1 migration applied", out)
        self.assertIn("NOT idempotent", out)
        self.assertFalse([e for e in self.events() if e.get("event") == "action_check"])


# ---------------------------------------------------------------------------
# adversarial 5: check abuse fails closed; a non-read check refuses at plan time
# ---------------------------------------------------------------------------

class CheckAbuseTest(core._Door):
    def pol(self, name, params):
        return tv._yaml_policy(runbooks=[_entry(name, params)])

    def go(self, name, params, ssh, risky_extra=None):
        pol = self.pol(name, params)
        if risky_extra:
            pol["risky_extra"] = risky_extra
        return self.door(["edge1", "--action", name, "--with", json.dumps(params), "--run",
                          "--reason", "x"], policy=pol, ssh=ssh)

    def test_bad_check_output_fails_closed(self):
        def lost():
            raise OSError("SSH connection lost")

        def slow():
            raise subprocess.TimeoutExpired("ssh", 60)
        sql_bad = ("@@@check\nVPSCFG-DONE\nextra\n", "@@@check\nvpscfg-done\n", "",
                   "VPSCFG-DONE\n", "@@@check\n", "@@@check\nVPSCFG-DONE extra\n")
        shell_bad = ("VPSCFG-DONE\nextra\n", "vpscfg-done\n", "", " VPSCFG-DONE",
                     "VPSCFG-DONE\n\n", "VPSCFG-NEEDED VPSCFG-DONE")
        cases = [("ensure_owner", OWNER, "default_transaction_read_only", 0, o) for o in sql_bad]
        cases += [("pg_dump", DUMP, "sha256sum --check", 0, o) for o in shell_bad]
        cases += [("ensure_owner", OWNER, "default_transaction_read_only", 1,
                   "@@@check\nVPSCFG-DONE\n"),
                  ("pg_dump", DUMP, "sha256sum --check", 1, "VPSCFG-DONE\n"),
                  ("ensure_owner", OWNER, "default_transaction_read_only", lost, None),
                  ("pg_dump", DUMP, "sha256sum --check", slow, None)]
        for name, params, needle, rc, out in cases:
            ssh = self.scripted_ssh([(needle, rc, out)])
            got, text = self.go(name, params, ssh)
            self.assertEqual(got, 1, (name, rc, out, text))
            self.assertIn("failing closed", text)
            self.assertEqual([c for _, c, _ in self.sent
                              if "VPSCFG_SQL" in c or "vpscfg-tmp" in c], [],
                             (name, rc, out))

    def test_needed_runs_the_body_done_skips_it(self):
        ssh = self.scripted_ssh([("default_transaction_read_only", 0,
                                  "@@@check\nVPSCFG-NEEDED\n"), ("VPSCFG_SQL", 0, "owned 3\n")])
        got, text = self.go("ensure_owner", OWNER, ssh)
        # NEEDED -> body -> verify (the same SqlCheck, which still says NEEDED
        # in this script): the verify fails, so the step fails, honestly.
        self.assertEqual(len([c for _, c, _ in self.sent if "VPSCFG_SQL" in c]), 1)
        self.assertEqual(got, 1, text)
        ssh = self.scripted_ssh([("default_transaction_read_only", 0, "@@@check\nVPSCFG-DONE\n")])
        got, text = self.go("ensure_owner", OWNER, ssh)
        self.assertEqual(got, 0, text)
        self.assertEqual([c for _, c, _ in self.sent if "VPSCFG_SQL" in c], [])

    def test_a_check_made_non_read_by_risky_extra_refuses_at_plan_time(self):
        for name, params, pattern in (("pg_dump", DUMP, "sha256sum"),
                                      ("ensure_owner", OWNER, "pg_namespace")):
            r, _ = self.go(name, params, self.scripted_ssh([]), risky_extra=[pattern])
            self.assertIsInstance(r, Refused, name)
            self.assertEqual(self.sent, [])

    def test_a_canonical_typed_by_hand_is_reserved(self):
        for name, params in (("ensure_owner", OWNER), ("pg_dump", DUMP), ("migrate", MIG)):
            canon = actions.expand(name, params, "edge1").canonical
            r, _ = self.door(["edge1", canon])
            self.assertIsInstance(r, Refused)
            self.assertIn("reserved spelling", str(r))
            r, _ = self.door(["edge1", "--action", "%s@2" % name, "--with", json.dumps(params)])
            self.assertIsInstance(r, Refused)
        self.assertEqual(self.sent, [])

    def test_an_unauthorised_db_action_refuses(self):
        for name, params in (("ensure_owner", OWNER), ("pg_dump", DUMP), ("migrate", MIG)):
            r, _ = self.door(["edge1", "--action", name, "--with", json.dumps(params), "--run",
                              "--reason", "x"])
            self.assertIsInstance(r, Refused, name)
        self.assertEqual(self.sent, [])


# ---------------------------------------------------------------------------
# adversarial 6: the seeded password appears in no captured byte
# ---------------------------------------------------------------------------

class SecretLeakTest(_FakeHost):
    def test_seeded_password_appears_nowhere(self):
        self.assertEqual(self.run_action("ensure_owner", OWNER)[0], 0)
        self.assertEqual(self.run_action("ensure_owner", OWNER)[0], 0)
        self.assertEqual(self.run_action("pg_dump", dict(DUMP, dest_dir=str(self.dumps)))[0], 0)
        mig = {"container": "shop-api", "runner": "prisma_deploy", "workdir": str(self.app)}
        self.assertEqual(self.run_action("migrate", mig)[0], 0)
        (self.state / "fail-migrate").touch()
        rc, out = self.run_action("migrate", mig)
        self.assertNotEqual(rc, 0, out)
        self.assertTrue(any(SEED in s for s in self.streams),
                        "the fake host did emit the secret (the test must be able to fail)")
        for argv in (["last", "-n", "20"], ["log", "-n", "200"], ["log", "--export", "--raw"]):
            rc, text = self.door(argv)
            self.assertEqual(rc, 0, text)
            self.assertNotIn(SEED, text, argv)
        self.assertTrue((self.state / "pw-seen").exists())
        # every byte the door sent: argv and stdin
        for host, cmd, data in self.sent:
            self.assertNotIn(SEED, cmd)
            self.assertNotIn(SEED, (data or b"").decode())
        # every door output and every journal file
        self.assertEqual(len(self.door_outputs), 5)
        for text in self.door_outputs:
            self.assertNotIn(SEED, text)
        for path in Path(self.tmp.name).rglob("*"):
            if path.is_file() and path.suffix in (".jsonl", ".json", ".log"):
                self.assertNotIn(SEED, path.read_text(errors="replace"), path)
        journal_text = (Path(self.tmp.name) / "vpsexec.jsonl").read_text()
        self.assertIn("action_planned", journal_text)


# ---------------------------------------------------------------------------
# public hygiene: the new files carry no estate data
# ---------------------------------------------------------------------------

class PublicHygieneTest(unittest.TestCase):
    FILES = [REPO / "vpscfg" / "actions" / "db.py", Path(__file__)] + [
        GOLDEN / ("%s@%d.json" % (n, base.REGISTRY[n].version)) for n in MINE]

    def test_exporter_scan_finds_nothing(self):
        spec = importlib.util.spec_from_file_location("export_public",
                                                      REPO / "tools" / "export-public.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for path in self.FILES + [REPO / "docs" / "ACTIONS.md"]:
            hits = mod.scan_text(str(path.relative_to(REPO)), path.read_text(), [])
            self.assertEqual(hits, [], path)


if __name__ == "__main__":
    unittest.main()
