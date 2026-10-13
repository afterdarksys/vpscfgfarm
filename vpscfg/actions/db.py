"""Database actions (P1a): ensure_owner, pg_dump, migrate. docs/ACTIONS.md has
the contract; each action's section there says what it runs.

ensure_owner {container, db, role, schema}
    Gives `role` ownership of the schema and of every table, partitioned
    table, view, materialized view and sequence in it, inside the Postgres
    container, in ONE transaction. The done-check is a SqlCheck (the host
    index's read-only session): DONE when the schema and every such object
    are already owned by `role`. Idempotent; the verify is the check.

pg_dump {container, db, dest_dir, label, min_free_gb?}
    A custom-format dump streamed out of the container to
    <dest_dir>/<db>-<label>-<p8>.dump on the host, mode 0600, where p8 is the
    first 8 hex of sha256 over the canonical parameters, so the same call is
    always the same file. It is written to a mktemp name in dest_dir, checked
    with `pg_restore --list`, recorded in <file>.sha256, then renamed into
    place. An existing dump is never overwritten. v2: a world-writable or
    sticky dest_dir is refused, and both temp names come from mktemp. Done-check and verify:
    `sha256sum --check` of that record. Idempotent.

migrate {container, runner, workdir?, db?}
    `runner` is a closed enum; each maps to one fixed command:
        prisma_deploy         ./node_modules/.bin/prisma migrate deploy
        alembic_upgrade_head  alembic upgrade head
        node_pg_migrate_up    ./node_modules/.bin/node-pg-migrate up
        sql_dir               psql -1 -f on every <workdir>/*.sql, in C-locale
                              name order (the Postgres container; needs db)
    Not idempotent: each runner's own status command needs `docker exec`,
    which the door's classifier rates risky, so it cannot be a done-check. A
    migrate step resumes like a plain `cmd:` (SKIP-DONE / RERUN).

Threats:
  - Protects against: a database password or DSN in argv, the plan, the
    journal or the output. The password is read INSIDE the container (its
    password file or environment, the same text as hostindex._PG_IN_CONTAINER,
    pinned equal by a test) and goes only into psql's / pg_dump's own
    environment; the migrate runners read their own environment in the
    container; nothing secret is ever a template input. Injection through a
    parameter: every value is a typed literal (types.py), shell-quoted with
    sq(); SQL identifiers are lowercase PG_IDENT values used only as SQL
    string literals compared server-side or through format('%I'), inside a
    quoted heredoc (no shell expansion; no value can hold a newline, so none
    can end it). Taking ownership of system objects: a `pg_*` role and a
    `pg_*` or information_schema schema are refused. A partial ownership
    change: one transaction with a 10 s lock_timeout, and it raises (rolls
    back) unless nothing is left unowned. A torn or silently bad dump: temp
    file, non-empty, `pg_restore --list` must read it, sha256 recorded, then
    renamed; an existing dump is never overwritten. A done-check that writes
    or lies: ensure_owner's check is a SqlCheck (sqlread gate, read-only
    session); pg_dump's is a shell read (`sha256sum --check`); anything but
    exactly one token fails the host closed (the door, S6). A free-form
    migration command: the runner is a closed enum mapped in code.
  - Does NOT protect against: root (or anyone with `docker exec`) on the host
    reading the password from the container, or reading the dump (0600, but
    a dump holds every row); a migration that is itself destructive (the
    door runs the project's own migrations; review them); a wrong but valid
    name (`role: shop_ro` instead of `shop_app`): review of the committed
    policy is the control; a host that lies about a check (the host is
    trusted, as for every verify).
"""

import hashlib

from . import types
from .base import Action, Param, SqlCheck, canonical_json, register, sq
from .types import ParamError

# Runs INSIDE the Postgres container: the password comes from the container's
# own password file or environment and goes only into the client's
# environment. Byte-identical to the start of hostindex._PG_IN_CONTAINER
# (tests/test_actions_db.py pins it).
PG_PASSWORD = (
    'if [ -n "${POSTGRES_PASSWORD_FILE:-}" ] && [ -r "$POSTGRES_PASSWORD_FILE" ]; '
    'then PGPASSWORD=$(cat "$POSTGRES_PASSWORD_FILE"); '
    'else PGPASSWORD='  # split: the exporter's scan reads `NAME="${...}"` as a value
    '"${POSTGRES_PASSWORD:-${POSTGRESQL_PASSWORD:-}}"; fi; export PGPASSWORD; ')
PG_USER = '-U "${POSTGRES_USER:-${POSTGRESQL_USERNAME:-postgres}}"'
PSQL_STDIN = PG_PASSWORD + 'exec psql -X -q -tA -F "\t" -v ON_ERROR_STOP=1 ' + PG_USER + ' -f -'

# What ensure_owner owns: tables, partitioned tables, views, materialized
# views, sequences. Tables go first: ALTER TABLE carries the sequences it owns
# (serial / identity), which refuse a direct ALTER SEQUENCE.
OWNED_KINDS = "('r', 'p', 'v', 'm', 'S')"
SQL_HEREDOC = "VPSCFG_SQL"

MIGRATE_RUNNERS = ("prisma_deploy", "alembic_upgrade_head", "node_pg_migrate_up", "sql_dir")
RUNNER_CMDS = {
    "prisma_deploy": "./node_modules/.bin/prisma migrate deploy",
    "alembic_upgrade_head": "alembic upgrade head",
    "node_pg_migrate_up": "./node_modules/.bin/node-pg-migrate up",
}
# The weekend's case: an app reads DATABASE_URL, or the four DB_* names.
APP_DB_ENV = [["DATABASE_URL"], ["DB_HOST", "DB_NAME", "DB_USER", "DB_PASS"]]


def _system_names(p):
    if p["role"].startswith("pg_"):
        raise ParamError("role %r is a system role (pg_*)" % p["role"])
    if p["schema"].startswith("pg_") or p["schema"] == "information_schema":
        raise ParamError("schema %r is a system schema" % p["schema"])


def _not_owned(schema, role, kinds=OWNED_KINDS):
    """FROM/WHERE text for objects of `kinds` in `schema` not owned by `role`.
    Values are typed PG_IDENT (no quote can occur), used as SQL literals."""
    return ("FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = '%s' AND c.relkind IN %s "
            "AND pg_get_userbyid(c.relowner) <> '%s'" % (schema, kinds, role))


@register
class EnsureOwner(Action):
    name = "ensure_owner"
    version = 1
    tier = "mutation"
    why = "give a role ownership of a schema and every table, view and sequence in it"
    params = {
        "container": Param(types.CONTAINER, why="the Postgres container"),
        "db": Param(types.PG_IDENT),
        "role": Param(types.PG_IDENT),
        "schema": Param(types.PG_IDENT),
    }
    samples = ({"container": "pg-main", "db": "shop", "role": "app_owner", "schema": "sales"},)

    def check_sql(self, p):
        return ("SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = '%s' "
                "AND pg_get_userbyid(nspowner) = '%s') AND NOT EXISTS (SELECT 1 %s) "
                "THEN 'VPSCFG-DONE' ELSE 'VPSCFG-NEEDED' END"
                % (p["schema"], p["role"], _not_owned(p["schema"], p["role"])))

    def build(self, p, host):
        _system_names(p)
        schema, role = p["schema"], p["role"]
        lit = "'%s', '%s'" % (schema, role)
        sql = "\n".join([
            "BEGIN;",
            "SET LOCAL lock_timeout = '10s';",
            # Counts per kind, never names: what this run is about to change.
            "SELECT 'pending ' || k || ' ' || count(*) FROM (SELECT CASE c.relkind "
            "WHEN 'v' THEN 'view' WHEN 'm' THEN 'matview' WHEN 'S' THEN 'sequence' "
            "ELSE 'table' END AS k %s) s GROUP BY k ORDER BY k;" % _not_owned(schema, role),
            "SELECT 'pending schema 1' FROM pg_namespace WHERE nspname = '%s' "
            "AND pg_get_userbyid(nspowner) <> '%s';" % (schema, role),
            "DO $vpscfg$",
            "DECLARE r record;",
            "BEGIN",
            "  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN" % role,
            "    RAISE EXCEPTION 'vpscfg: the role does not exist';",
            "  END IF;",
            "  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = '%s') THEN" % schema,
            "    RAISE EXCEPTION 'vpscfg: the schema does not exist';",
            "  END IF;",
            "  IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = '%s') "
            "<> '%s' THEN" % (schema, role),
            "    EXECUTE format('ALTER SCHEMA %%I OWNER TO %%I', %s);" % lit,
            "  END IF;",
            "  FOR r IN SELECT c.relname, c.relkind %s ORDER BY c.relkind, c.relname LOOP"
            % _not_owned(schema, role, "('r', 'p', 'v', 'm')"),
            "    EXECUTE format('ALTER %%s %%I.%%I OWNER TO %%I', CASE r.relkind "
            "WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE 'TABLE' END, "
            "'%s', r.relname, '%s');" % (schema, role),
            "  END LOOP;",
            "  FOR r IN SELECT c.relname %s ORDER BY c.relname LOOP"
            % _not_owned(schema, role, "('S')"),
            "    EXECUTE format('ALTER SEQUENCE %%I.%%I OWNER TO %%I', '%s', r.relname, '%s');"
            % (schema, role),
            "  END LOOP;",
            "  IF EXISTS (SELECT 1 %s) THEN" % _not_owned(schema, role),
            "    RAISE EXCEPTION 'vpscfg: objects are still not owned; rolled back';",
            "  END IF;",
            "END",
            "$vpscfg$;",
            "SELECT 'owned ' || count(*) FROM pg_class c JOIN pg_namespace n "
            "ON n.oid = c.relnamespace WHERE n.nspname = '%s' AND c.relkind IN %s;"
            % (schema, OWNED_KINDS),
            "COMMIT;",
        ])
        body = "docker exec -i -e PGDATABASE=%s %s sh -c %s <<'%s'\n%s\n%s" % (
            sq(p["db"]), sq(p["container"]), sq(PSQL_STDIN), SQL_HEREDOC, sql, SQL_HEREDOC)
        check = SqlCheck(p["container"], p["db"], self.check_sql(p))
        return {"body": body, "check": check, "verify": check, "idempotent": True,
                "timeout": 300, "assumes": ({"container": p["container"]},)}


def dump_suffix(p):
    """The 8 hex that make a dump's file name unique to its call."""
    keys = ("container", "db", "dest_dir", "label")
    return hashlib.sha256(canonical_json(dict((k, p[k]) for k in keys))
                          .encode("ascii")).hexdigest()[:8]


@register
class PgDump(Action):
    name = "pg_dump"
    version = 2
    tier = "mutation"
    why = "a verified custom-format dump of one database, kept on the host"
    params = {
        "container": Param(types.CONTAINER, why="the Postgres container"),
        "db": Param(types.PG_IDENT),
        "dest_dir": Param(types.ABS_PATH, why="an existing directory on the host"),
        "label": Param(types.BASENAME, why="the release or reason, part of the file name"),
        "min_free_gb": Param(types.int_range(1, 100000), required=False,
                             why="assumed free space on dest_dir"),
    }
    samples = (
        {"container": "pg-main", "db": "shop", "dest_dir": "/var/backups/db1",
         "label": "rel-1.5"},
        {"container": "pg-main", "db": "shop", "dest_dir": "/var/backups/db1",
         "label": "rel-1.5", "min_free_gb": 5},
    )

    def build(self, p, host):
        # Every value stays a quoted word of its own; the name is joined by
        # the shell from those words.
        path = "%s/%s-%s-%s.dump" % (sq(p["dest_dir"]), sq(p["db"]), sq(p["label"]),
                                     dump_suffix(p))
        record = "%s.sha256" % path
        dump = PG_PASSWORD + "exec pg_dump -Fc --no-password " + PG_USER
        body = "\n".join([
            "umask 077",
            "d=%s" % sq(p["dest_dir"]),
            "f=%s" % path,
            'test -d "$d" || { echo "vpscfg: dest_dir does not exist" >&2; exit 2; }',
            # v2: a directory others can write to (world-writable, or sticky
            # like /tmp) lets them plant a name first; refuse it.
            'if test -n "$(find "$d" -maxdepth 0 \\( -perm -0002 -o -perm -1000 \\) -print)"; '
            'then echo "vpscfg: dest_dir is world-writable or sticky; refused" >&2; exit 2; fi',
            'if test -e "$f"; then echo "vpscfg: $f already exists; a dump is never '
            'overwritten" >&2; exit 3; fi',
            # v2: fresh, unpredictable temp names made by mktemp (O_EXCL),
            # never a fixed name another process could pre-create or link.
            't=$(mktemp "$d/.vpscfg-dump.XXXXXX") || exit 4',
            'r=$(mktemp "$d/.vpscfg-dump.XXXXXX") || { rm -f "$t"; exit 4; }',
            "trap 'rm -f \"$t\" \"$r\"' EXIT",
            'docker exec -e PGDATABASE=%s %s sh -c %s > "$t" || { '
            'echo "vpscfg: pg_dump failed" >&2; exit 4; }'
            % (sq(p["db"]), sq(p["container"]), sq(dump)),
            'test -s "$t" || { echo "vpscfg: the dump is empty" >&2; exit 5; }',
            'docker exec -i %s pg_restore --list < "$t" > /dev/null || { '
            'echo "vpscfg: pg_restore --list cannot read the dump" >&2; exit 6; }'
            % sq(p["container"]),
            'h=$(sha256sum < "$t" | cut -d " " -f 1)',
            'test -n "$h" || { echo "vpscfg: sha256sum failed" >&2; exit 7; }',
            "printf '%s  %s\\n' \"$h\" \"$f\" > \"$r\"",
            'chmod 0600 "$t" "$r"',
            # The record first: a crash between the two renames leaves a
            # record without a dump, which the check reports NEEDED and the
            # next run replaces; never a dump the check cannot vouch for.
            'mv "$r" "$f.sha256" && mv "$t" "$f" || exit 8',
            'echo "vpscfg: dumped $(wc -c < "$f" | tr -d " ") bytes to $f, sha256 $h"',
        ])
        check = ("sha256sum --check --status %s >/dev/null 2>&1 && echo VPSCFG-DONE "
                 "|| echo VPSCFG-NEEDED" % record)
        assumes = [{"container": p["container"]}]
        if "min_free_gb" in p:
            assumes.append({"min_free_gb": {p["dest_dir"]: p["min_free_gb"]}})
        return {"body": body, "check": check, "verify": "sha256sum --check --status %s" % record,
                "idempotent": True, "timeout": 1800, "assumes": tuple(assumes)}


@register
class Migrate(Action):
    name = "migrate"
    version = 1
    tier = "mutation"
    why = "run a project's own migrations with one of four fixed runners"
    params = {
        "container": Param(types.CONTAINER,
                           why="the app container (sql_dir: the Postgres container)"),
        "runner": Param(types.enum(*MIGRATE_RUNNERS)),
        "workdir": Param(types.ABS_PATH, required=False,
                         why="docker exec -w; sql_dir: the directory of .sql files"),
        "db": Param(types.PG_IDENT, required=False, why="sql_dir only"),
    }
    samples = (
        {"container": "shop-api", "runner": "prisma_deploy", "workdir": "/app"},
        {"container": "shop-api", "runner": "alembic_upgrade_head"},
        {"container": "shop-api", "runner": "node_pg_migrate_up"},
        {"container": "pg-main", "runner": "sql_dir", "db": "shop",
         "workdir": "/migrations"},
    )

    def build(self, p, host):
        runner = p["runner"]
        wd = " -w %s" % sq(p["workdir"]) if "workdir" in p else ""
        if runner == "sql_dir":
            if "workdir" not in p or "db" not in p:
                raise ParamError("runner sql_dir needs workdir (the .sql directory) and db")
            script = (PG_PASSWORD + "LC_ALL=C; export LC_ALL; set -e; n=0; "
                      'for f in ./*.sql; do test -e "$f" || { echo "vpscfg: no .sql files" '
                      '>&2; exit 2; }; psql -X -q -v ON_ERROR_STOP=1 ' + PG_USER
                      + ' -1 -f "$f"; n=$((n+1)); done; echo "vpscfg: applied $n file(s)"')
            body = "docker exec%s -e PGDATABASE=%s %s sh -c %s" % (
                wd, sq(p["db"]), sq(p["container"]), sq(script))
            assumes = ({"container": p["container"]},)
        else:
            if "db" in p:
                raise ParamError("db is for runner sql_dir only; %s reads its own "
                                 "environment" % runner)
            body = "docker exec%s %s %s" % (wd, sq(p["container"]), RUNNER_CMDS[runner])
            assumes = ({"container": p["container"],
                        "env_names_any_of": [list(s) for s in APP_DB_ENV]},)
        return {"body": body, "idempotent": False, "timeout": 600, "assumes": assumes}
