"""Read-only SQL. The credential stays on the host.

Threats:
  - Protects against: a write, a second statement, a comment, a dollar
    quote, or SELECT INTO reaching the database (the query is classified
    before any SSH); a superuser role (a separate precheck refuses before
    the user script); the query being interpolated into a shell string
    (it is stdin bytes); a password echoed in the result (stdout is masked).
  - Does NOT protect against: a SELECT that reads a secret the role can
    already see. Rows are masked, not suppressed. The journal records the
    host, the database, the query's sha256, and the exit code — never the
    text and never the rows. A precheck refusal is not journaled.
"""
import hashlib
import re
import shlex
import subprocess
import sys

from . import journal, secretmask
from .gates import DENY_ALWAYS_FLOOR, Refused, deny_scan
from .probe import HOST_RE
from .secretscensus import PATH_RE

MAX_QUERY = 8192
MAX_OUT_BYTES = 64 * 1024
MAX_OUT_LINES = 200
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_DOLLAR_QUOTE = re.compile(r"\$[A-Za-z0-9_]*\$")
_WORD = re.compile(r"[A-Za-z_]+")
_OPENERS = frozenset(["select", "with", "show", "explain"])
_WRITE_WORDS = frozenset([
    "insert", "update", "delete", "drop", "truncate", "alter", "create",
    "copy", "grant", "revoke", "vacuum", "analyze", "call", "do", "execute",
    "prepare", "listen", "notify", "load", "set", "reset", "begin", "commit",
    "rollback", "lock", "discard", "cluster", "reindex", "into",
])
_PRECHECK = "SELECT rolsuper FROM pg_roles WHERE rolname = current_user\n"
_USER_PREFIX = "BEGIN READ ONLY;\nSET statement_timeout = '5s';\n"


def _reject_raw(query):
    if not isinstance(query, str) or "\x00" in query:
        raise Refused("sql query refused")
    if query.strip() == "":
        raise Refused("sql query refused")
    if len(query.encode("utf-8")) > MAX_QUERY:
        raise Refused("sql query exceeds %d bytes" % MAX_QUERY)
    if "--" in query or "/*" in query or "*/" in query:
        raise Refused("sql refuses comments")
    if "\\" in query:
        raise Refused("sql refuses backslash escapes")
    if _DOLLAR_QUOTE.search(query):
        raise Refused("sql refuses dollar quotes")


def _strip_literals(query):
    """Replace quoted literals and identifiers with a space. Unclosed quotes
    and '' / "" escapes are handled. The returned text is only for the
    keyword scan; the script that runs is the original query."""
    out = []
    i = 0
    n = len(query)
    while i < n:
        char = query[i]
        if char not in ("'", '"'):
            out.append(char)
            i += 1
            continue
        quote = char
        i += 1
        closed = False
        while i < n:
            if query[i] == quote:
                if i + 1 < n and query[i + 1] == quote:
                    i += 2
                    continue
                i += 1
                closed = True
                break
            i += 1
        if not closed:
            raise Refused("sql refuses an unclosed quote")
        out.append(" ")
    return "".join(out)


def classify(query, select_only=False):
    """Return the query with one trailing semicolon removed, or raise Refused.

    String literals and double-quoted identifiers are stripped before the
    keyword and semicolon scan, so SELECT 'insert' and SELECT ';' pass.
    The raw text is then deny-scanned, so SELECT 'DROP TABLE …' still refuses.
    """
    _reject_raw(query)
    body = _strip_literals(query).strip()
    if body.endswith(";"):
        body = body[:-1].rstrip()
    if ";" in body or body.strip() == "":
        raise Refused("sql refuses a second statement")
    words = [w.lower() for w in _WORD.findall(body)]
    if not words or words[0] not in _OPENERS:
        raise Refused("sql only accepts SELECT, WITH, SHOW, or EXPLAIN")
    if select_only and words[0] != "select":
        raise Refused("drill postgres canary must be a single SELECT")
    for word in words:
        if word in _WRITE_WORDS:
            raise Refused("sql refuses %s" % word.upper())
    deny_scan(query, DENY_ALWAYS_FLOOR)
    cleaned = query.strip()
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].rstrip()
    return cleaned


def classify_redis(command):
    """Allow a fixed set of redis-cli reads. Everything else refuses."""
    if not isinstance(command, str) or command == "" or "\x00" in command:
        raise Refused("redis command refused")
    if "\n" in command or "\r" in command or ";" in command:
        raise Refused("redis command refused")
    if len(command.encode("utf-8")) > MAX_QUERY:
        raise Refused("redis command exceeds %d bytes" % MAX_QUERY)
    parts = command.split()
    if not parts:
        raise Refused("redis command refused")
    upper = [part.upper() for part in parts]
    if any(word in ("CONFIG", "KEYS", "MONITOR") for word in upper):
        raise Refused("redis command refused")
    allowed = False
    if upper == ["INFO"] or upper == ["PING"] or upper == ["DBSIZE"]:
        allowed = True
    elif upper == ["CLIENT", "LIST"] or upper == ["LATENCY", "LATEST"]:
        allowed = True
    elif len(upper) == 2 and upper[0] == "INFO" and NAME_RE.fullmatch(parts[1]):
        allowed = True
    elif upper[:2] == ["SLOWLOG", "GET"] and len(parts) in (2, 3):
        if len(parts) == 2 or (parts[2].isdigit() and len(parts[2]) <= 6):
            allowed = True
    if not allowed:
        raise Refused("redis command refused")
    deny_scan(command, DENY_ALWAYS_FLOOR)
    return command


def _path_ok(path):
    return isinstance(path, str) and ".." not in path and bool(PATH_RE.match(path))


def validate_block(block, label):
    """Validate one contract's sql block. A malformed block refuses even
    when its database is not the one the operator named."""
    if not isinstance(block, dict):
        raise Refused("sql block on %s is malformed" % label)
    engine = block.get("engine")
    container = block.get("container")
    database = block.get("database")
    password_file = block.get("password_file")
    if engine not in ("postgres", "redis"):
        raise Refused("sql.engine on %s must be postgres or redis" % label)
    if not isinstance(container, str) or not NAME_RE.fullmatch(container):
        raise Refused("sql.container on %s refused" % label)
    if not isinstance(database, str) or not NAME_RE.fullmatch(database):
        raise Refused("sql.database on %s refused" % label)
    if not _path_ok(password_file):
        raise Refused("sql.password_file on %s refused" % label)
    checked = {
        "engine": engine,
        "container": container,
        "database": database,
        "password_file": password_file,
    }
    if engine == "postgres":
        role = block.get("role")
        if not isinstance(role, str) or not NAME_RE.fullmatch(role):
            raise Refused("sql.role on %s refused" % label)
        checked["role"] = role
        return checked
    index = block.get("db")
    if type(index) is not int or index < 0 or index > 15:
        raise Refused("sql.db on %s must be an integer 0-15" % label)
    checked["db"] = index
    return checked


def find_sql(contracts_on_host, db):
    """The CLI database must equal exactly one contract's sql.database."""
    if not isinstance(db, str) or not NAME_RE.fullmatch(db):
        raise Refused("sql database name refused")
    matches = []
    for name in sorted(contracts_on_host):
        contract = contracts_on_host[name]
        if not isinstance(contract, dict) or "sql" not in contract:
            continue
        block = validate_block(contract["sql"], name)
        if block["database"] == db:
            matches.append((name, contract, block))
    if len(matches) != 1:
        raise Refused("sql database %r must match exactly one contract" % db)
    return matches[0]


def _psql_command(block, tuples_only):
    flags = "-tA " if tuples_only else ""
    return (
        "PGPASSWORD=$(cat -- %s); exec docker exec -i -e PGPASSWORD %s "
        "psql -v ON_ERROR_STOP=1 %s-U %s -d %s --no-password -f -"
        % (shlex.quote(block["password_file"]), shlex.quote(block["container"]),
           flags, shlex.quote(block["role"]), shlex.quote(block["database"]))
    )


def _redis_command(block):
    return (
        "REDISCLI_AUTH=$(cat -- %s); exec docker exec -i -e REDISCLI_AUTH %s "
        "redis-cli -n %d --no-auth-warning"
        % (shlex.quote(block["password_file"]), shlex.quote(block["container"]),
           block["db"])
    )


def _cap(text):
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    lines = text.splitlines()
    capped = False
    if len(lines) > MAX_OUT_LINES:
        lines = lines[:MAX_OUT_LINES]
        capped = True
    body = "\n".join(lines)
    raw = body.encode("utf-8")
    if len(raw) > MAX_OUT_BYTES:
        body = raw[:MAX_OUT_BYTES].decode("utf-8", "ignore")
        capped = True
    if capped:
        body += "\n[output capped]"
    return body


def _show(text, stream):
    shown = secretmask.mask(_cap(text or ""))
    if not shown:
        return
    stream.write(shown)
    if not shown.endswith("\n"):
        stream.write("\n")


def _journal(host, db, query, rc):
    journal.append("sql", {
        "event": "sql-read",
        "host": host,
        "db": db,
        "sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "rc": rc,
    })


def _call(runner, host, command, stdin):
    result = runner(host, command, stdin)
    if not isinstance(result, tuple) or len(result) != 3:
        raise Refused("sql runner returned an unexpected result")
    rc, out, err = result
    if type(rc) is not int or not isinstance(out, str) or not isinstance(err, str):
        raise Refused("sql runner returned an unexpected result")
    return rc, out, err


def _role_is_nosuper(out, rc):
    if rc != 0 or not isinstance(out, str) or len(out) > 32:
        return False
    return out.strip() == "f"


def execute(host, block, query, runner):
    """Classify first. A bad query never reaches the host. Postgres runs a
    rolsuper precheck as its own invocation and only then the user script."""
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    if block["engine"] == "redis":
        command_text = classify_redis(query)
        command = _redis_command(block)
        deny_scan(command, DENY_ALWAYS_FLOOR)
        rc, out, err = _call(runner, host, command, command_text.encode("utf-8") + b"\n")
        _journal(host, block["database"], command_text, rc)
        _show(out, sys.stdout)
        if rc != 0:
            _show(err, sys.stderr)
            return 1
        return 0

    cleaned = classify(query)
    precheck = _psql_command(block, True)
    user_cmd = _psql_command(block, False)
    deny_scan(precheck, DENY_ALWAYS_FLOOR)
    deny_scan(user_cmd, DENY_ALWAYS_FLOOR)
    rc, out, err = _call(runner, host, precheck, _PRECHECK.encode("utf-8"))
    if not _role_is_nosuper(out, rc):
        raise Refused("sql role is missing or is a superuser")
    script = (_USER_PREFIX + cleaned + "\n").encode("utf-8")
    rc, out, err = _call(runner, host, user_cmd, script)
    _journal(host, block["database"], cleaned, rc)
    _show(out, sys.stdout)
    if rc != 0:
        _show(err, sys.stderr)
        return 1
    return 0


def default_runner(host, command, stdin=None):
    """Bytes on stdin. Tests inject a runner; this default is not used by them."""
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    payload = stdin if isinstance(stdin, bytes) else None
    if isinstance(stdin, str):
        payload = stdin.encode("utf-8")
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, command],
        input=payload, capture_output=True, timeout=60)
    if result.returncode == 255:
        raise OSError("SSH connection lost; remote completion is unknown")
    return (result.returncode,
            result.stdout.decode("utf-8", "replace"),
            result.stderr.decode("utf-8", "replace"))


def cli(host, argv, contracts_on_host, runner=None):
    """vpscfg <host> sql <db> 'SELECT …' — the query is one argument."""
    if len(argv) != 4 or argv[1] != "sql":
        raise Refused("usage: vpscfg <host> sql <db> 'SELECT …'")
    _name, _contract, block = find_sql(contracts_on_host, argv[2])
    return execute(host, block, argv[3], runner or default_runner)
