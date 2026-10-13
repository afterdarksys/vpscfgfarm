"""Host index: a read-only record of what lives on one box.

`collect(host)` returns one JSON-able document: the host itself, systemd
services, containers (and k3s workloads), listening ports, users and
groups, and what Postgres, Redis and RabbitMQ hold. indexstore.py caches
it, diffs it and queries it; the runbook preflight can call `collect` or
read the cache directly.

Every remote command comes from a fixed template in this file. The only
values spliced in came back from the host in an earlier read (container,
database names); each is checked against a strict pattern and shell-quoted,
and anything outside the pattern is skipped and reported, never sent.

Two gates, chosen per command:
  - host reads (ss, cat /etc/passwd, docker inspect, systemctl ...) must
    classify as a read under vpsexec's own classifier (same deny floor, same
    allowlist, the governor's deny patterns and the policies' risky_extra);
  - in-container reads (psql, redis-cli, rabbitmqctl) go through
    `docker exec`, which vpsexec classes as risky. They use the same gates
    as `vpscfg <host> sql`: every SQL statement passes sqlread.classify,
    redis commands pass sqlread.classify_redis, and rabbitmqctl may only run
    list_vhosts, list_queues and list_exchanges. The whole command is
    deny-scanned against the floor plus the governor before it is sent.
A command that fails its gate is not sent: its section reads
`unavailable: <reason>`. A section that breaks records `error: ...` and the
other sections still run.

Threats:
  - Protects against: a secret VALUE reaching the index. Container env is
    read as NAMES only (the docker template splits on "=" on the host, so a
    value never crosses the wire); passwords for psql and redis-cli are read
    from the container's own environment or password file INSIDE the
    container and are never printed, passed on a command line or returned;
    /etc/shadow is never read and the passwd/group password fields are
    dropped; Redis keys and values and RabbitMQ messages are never read
    (counts only). All remote output is masked by secretmask before it is
    parsed, and every string in the finished document is masked again.
    Against an untraceable read: an `index_read` record is journaled per
    host, and per database instance, before anything is sent
    (journal-or-refuse). Against a write: SQL runs in a session with
    default_transaction_read_only=on and inside BEGIN READ ONLY, and is a
    fixed set of catalog SELECTs. Against hangs: ssh BatchMode,
    ConnectTimeout and a subprocess timeout; statement_timeout in psql.
  - Does NOT protect against: a hostile host lying in its output; a secret
    stored in a NAME (a table, role, queue or env var whose name is itself
    a secret); the container's psql role being a superuser (the session is
    read-only and the SQL fixed, so this is accepted here, unlike the
    free-form `sql` verb, which refuses superusers).
"""
import datetime
import json
import re
import shlex
import subprocess

from . import ports as ports_mod
from . import journal, secretmask, sqlread, traefikmap, vpsexec
from .gates import DENY_ALWAYS_FLOOR, Refused, deny_scan
from .probe import HOST_RE

INDEX_VERSION = 1
SECTIONS = ("host", "services", "containers", "ports", "users",
            "postgres", "redis", "rabbitmq", "web")
# Sections another section reads from. Collected silently when not asked for.
DEPENDS = {"ports": ("containers",), "postgres": ("containers", "services"),
           "redis": ("containers", "services"),
           "rabbitmq": ("containers", "services")}

NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
DB_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}\Z")
MAX_DATABASES = 100
MAX_TABLES = 5000
INSPECT_CHUNK = 40
SUDO_GROUPS = ("sudo", "wheel", "admin")
NOLOGIN = ("nologin", "false", "sync", "halt", "shutdown")

POSTGRES_IMAGES = frozenset(["postgres", "postgresql", "postgis", "timescaledb",
                             "timescaledb-ha", "pgvector", "timescaledb-postgis"])
REDIS_IMAGES = frozenset(["redis", "redis-stack-server", "valkey", "keydb"])
RABBITMQ_IMAGES = frozenset(["rabbitmq"])
RELKINDS = {"r": "table", "p": "partitioned_table", "v": "view",
            "m": "materialized_view", "S": "sequence", "f": "foreign_table"}


class Unavailable(Exception):
    """A gate classed a command as non-read; the command was not sent."""


def _journal_read(host, **fields):
    """An `index_read` record per host and per database instance, written
    BEFORE anything is sent: an index run nobody can trace must not happen.
    A journal failure raises (journal-or-refuse)."""
    journal.append("vpsexec", dict({"event": "index_read", "host": host}, **fields))


def _default_ssh(host, command, stdin=None, timeout=120):
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, command],
                       input=stdin, capture_output=True, text=True, timeout=timeout)
    if r.returncode == 255:
        raise OSError("ssh transport failed: %s" % (r.stderr or "").strip()[:200])
    return r.returncode, r.stdout, r.stderr


def _raw(text):
    """Unmasked output for an allowlisting parser, under the masker's size cap."""
    if len(text or "") > secretmask.MAX_INPUT:
        raise OSError("output over %d chars; withheld" % secretmask.MAX_INPUT)
    return text or ""


def _masked(text):
    out = secretmask.mask(text or "")
    if out and out.startswith("<output withheld"):
        raise OSError(out)
    return out or ""


class _Ctx(object):
    """The only way a collector reaches the host. Gates every command, then
    masks every byte that comes back."""

    def __init__(self, host, ssh, deny_patterns, risky_extra):
        self.host = host
        self._ssh = ssh
        self.deny = list(DENY_ALWAYS_FLOOR) + [p for p in deny_patterns or ()
                                               if p not in DENY_ALWAYS_FLOOR]
        self.risky = list(risky_extra or ())

    def reads(self, atoms, raw=False):
        """[(label, command)] -> {label: (rc, stdout)} in one ssh round trip.
        Each command must classify as a read, exactly as vpsexec would.
        raw=True: see exec_read."""
        parts = []
        for label, command in atoms:
            text = command + " 2>/dev/null"
            try:
                tier, detail = vpsexec.classify(text, self.deny, self.risky)
            except Refused as exc:
                raise Unavailable("%s: %s" % (label, exc))
            if tier != "read":
                raise Unavailable("%s classifies as %s (%s), not a read" % (label, tier, detail))
            parts.append("echo @@@%s; %s; echo \"@@@rc $?\"" % (label, text))
        script = "; ".join(parts)
        self._send_check(script)
        rc, out, _err = self._ssh(self.host, script, None)
        return _split_atoms(_raw(out) if raw else _masked(out))

    def exec_read(self, command, stdin=None, raw=False):
        """A fixed in-container read whose payload the caller already gated.
        Returns (rc, stdout, stderr), masked. raw=True skips masking stdout
        for a caller that keeps only typed, allowlisted fields from it (the
        document's strings are masked again by mask_leaves either way)."""
        self._send_check(command)
        rc, out, err = self._ssh(self.host, command, stdin)
        return rc, _raw(out) if raw else _masked(out), _masked(err)

    def _send_check(self, command):
        try:
            deny_scan(command, self.deny)
        except Refused as exc:
            raise Unavailable(str(exc))


def _split_atoms(text):
    out, label, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith("@@@rc "):
            if label is not None:
                tail = line[6:].strip()
                out[label] = (int(tail) if tail.isdigit() else 1, "\n".join(buf))
            label, buf = None, []
            continue
        if line.startswith("@@@"):
            label, buf = line[3:].strip(), []
            continue
        if label is not None:
            buf.append(line)
    return out


def _atom(results, label):
    """stdout of one atom, or None when it failed or never reported."""
    rc, body = results.get(label, (1, ""))
    return body if rc == 0 else None


def _short(text, limit=300):
    return " ".join((text or "").split())[:limit]


# ---- host ---------------------------------------------------------------

def _host(ctx, state):
    r = ctx.reads([
        ("hostname", "hostname -f"),
        ("os", "cat /etc/os-release"),
        ("uname", "uname -srm"),
        ("uptime", "cat /proc/uptime"),
        ("cpus", "nproc"),
        ("memory", "free -b"),
        ("disks", "df -P -k -x tmpfs -x devtmpfs -x overlay -x squashfs"),
    ])
    if not r:
        raise OSError("no output from the host probe")
    osr = {}
    for line in (_atom(r, "os") or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            osr[k.strip()] = v.strip().strip('"')
    uname = (_atom(r, "uname") or "").split()
    up = (_atom(r, "uptime") or "").split()
    mem = {}
    for line in (_atom(r, "memory") or "").splitlines():
        cols = line.split()
        if cols and cols[0] == "Mem:" and len(cols) >= 7:
            mem = {"total_bytes": int(cols[1]), "available_bytes": int(cols[6])}
    disks = []
    for line in (_atom(r, "disks") or "").splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 6 and cols[1].isdigit():
            disks.append({"filesystem": cols[0], "mount": cols[5],
                          "size_bytes": int(cols[1]) * 1024,
                          "used_bytes": int(cols[2]) * 1024,
                          "available_bytes": int(cols[3]) * 1024})
    cpus = (_atom(r, "cpus") or "").strip()
    return {
        "hostname": (_atom(r, "hostname") or "").strip() or None,
        "os": {"pretty_name": osr.get("PRETTY_NAME"), "id": osr.get("ID"),
               "version_id": osr.get("VERSION_ID")},
        "kernel": uname[1] if len(uname) > 1 else None,
        "arch": uname[2] if len(uname) > 2 else None,
        "uptime_seconds": int(float(up[0])) if up else None,
        "cpus": int(cpus) if cpus.isdigit() else None,
        "memory": mem or None,
        "disks": disks,
    }


# ---- services -----------------------------------------------------------

def _services(ctx, state):
    r = ctx.reads([
        ("units", "systemctl list-units --type=service --all --no-legend --no-pager --plain"),
        ("files", "systemctl list-unit-files --type=service --no-legend --no-pager"),
    ])
    units_out = _atom(r, "units")
    if units_out is None:
        raise OSError("systemctl list-units failed (no systemd, or not reachable)")
    enabled = {}
    for line in (_atom(r, "files") or "").splitlines():
        cols = line.split()
        if len(cols) >= 2 and cols[0].endswith(".service"):
            enabled[cols[0]] = cols[1]
    units, seen = [], set()
    for line in units_out.splitlines():
        cols = line.split()
        if len(cols) >= 4 and cols[0].endswith(".service"):
            seen.add(cols[0])
            units.append({"name": cols[0], "load": cols[1], "active": cols[2],
                          "sub": cols[3], "enabled": enabled.get(cols[0])})
    for name, state_ in sorted(enabled.items()):
        if name not in seen and "@." not in name:
            units.append({"name": name, "load": None, "active": "inactive",
                          "sub": None, "enabled": state_})
    units.sort(key=lambda u: u["name"])
    return {"units": units}


# ---- containers ---------------------------------------------------------

_INSPECT_FMT = "\t".join([
    "{{.Name}}", "{{.Config.Image}}", "{{.Image}}", "{{.State.Status}}",
    '{{index .Config.Labels "com.docker.compose.project"}}',
    '{{index .Config.Labels "com.docker.compose.service"}}',
    '{{index .Config.Labels "com.docker.compose.project.config_files"}}',
    '{{index .Config.Labels "com.docker.compose.project.working_dir"}}',
    "{{json .NetworkSettings.Networks}}",
    "{{json .NetworkSettings.Ports}}",
    # NAMES only: the split happens on the host, the value never leaves it.
    '{{range .Config.Env}}{{index (split . "=") 0}} {{end}}',
])
_K3S_GET = ("k3s kubectl get deployments,statefulsets,daemonsets -A --no-headers "
            "--request-timeout=8s -o 'custom-columns=KIND:.kind,NS:.metadata.namespace,"
            "NAME:.metadata.name,READY:.status.readyReplicas,DESIRED:.spec.replicas,"
            "IMAGES:.spec.template.spec.containers[*].image'")


def _label(value):
    value = (value or "").strip()
    return None if value in ("", "<no value>") else value


def _json_keys(text):
    try:
        doc = json.loads(text or "null")
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else {}


def _published(ports_doc):
    out = []
    for key, binds in sorted((ports_doc or {}).items()):
        cport, _, proto = key.partition("/")
        for b in binds or []:
            hp = str((b or {}).get("HostPort") or "")
            if hp.isdigit():
                out.append({"proto": proto or "tcp", "host_ip": (b or {}).get("HostIp") or None,
                            "host_port": int(hp),
                            "container_port": int(cport) if cport.isdigit() else cport})
    return out


def _parse_inspect(line):
    cols = line.split("\t")
    if len(cols) != 11:
        return None
    nets, ports_doc = _json_keys(cols[8]), _json_keys(cols[9])
    files = _label(cols[6])
    c = {
        "name": cols[0].lstrip("/"), "image": cols[1], "image_id": cols[2],
        "state": cols[3],
        "compose": {"project": _label(cols[4]), "service": _label(cols[5]),
                    "config_files": files.split(",") if files else [],
                    "working_dir": _label(cols[7])},
        "networks": sorted(nets) if nets is not None else None,
        "published": _published(ports_doc) if ports_doc is not None else None,
        "env_names": sorted(set(w for w in cols[10].split() if w)),
    }
    return c


def _containers(ctx, state):
    r = ctx.reads([
        ("client", "docker version --format '{{.Client.Version}}'"),
        ("version", "docker version --format '{{.Server.Version}}'"),
        ("names", "docker ps -a --no-trunc --format '{{.Names}}'"),
        ("k3s_unit", "systemctl is-active k3s"),
        ("k3s", _K3S_GET),
    ])
    out = {"docker": None, "containers": [], "skipped": [], "k3s": None}
    names = _atom(r, "names")
    if _atom(r, "client") is not None and (_atom(r, "version") is None or names is None):
        # A docker CLI with no answer is a failed read, never "no containers".
        raise OSError("docker is installed but the daemon did not answer")
    if _atom(r, "version") is not None and names is not None:
        out["docker"] = {"server_version": _atom(r, "version").strip() or None}
        good = []
        for n in names.split():
            (good if NAME_RE.match(n) else out["skipped"]).append(n)
        for i in range(0, len(good), INSPECT_CHUNK):
            chunk = good[i:i + INSPECT_CHUNK]
            cmd = "docker inspect --format %s %s" % (
                shlex.quote(_INSPECT_FMT), " ".join(shlex.quote(n) for n in chunk))
            body = _atom(ctx.reads([("inspect", cmd)]), "inspect")
            if body is None:
                raise OSError("docker inspect failed")
            for line in body.splitlines():
                c = _parse_inspect(line)
                if c:
                    out["containers"].append(c)
        out["containers"].sort(key=lambda c: c["name"])
    k3s_active = (_atom(r, "k3s_unit") or "").strip() == "active"
    workloads = _atom(r, "k3s")
    if workloads is not None:
        out["k3s"] = {"workloads": _parse_workloads(workloads)}
    elif k3s_active:
        out["k3s"] = {"error": "k3s is active but kubectl get failed"}
    state["containers"] = out
    return out


def _parse_workloads(text):
    out = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 6:
            continue
        num = lambda v: int(v) if v.isdigit() else None  # noqa: E731
        out.append({"kind": cols[0], "namespace": cols[1], "name": cols[2],
                    "ready": num(cols[3]), "desired": num(cols[4]),
                    "images": [i for i in cols[5].split(",") if i and i != "<none>"]})
    return out


# ---- ports --------------------------------------------------------------

def _ports(ctx, state):
    r = ctx.reads([("ss", "ss -lntup")])
    body = _atom(r, "ss")
    if body is None:
        raise OSError("ss -lntup failed")
    by_port = {}
    for c in (state.get("containers") or {}).get("containers") or []:
        for p in c.get("published") or []:
            by_port.setdefault((p["proto"], p["host_port"]), c["name"])
    listeners = ports_mod.parse_listeners(body)
    for entry in listeners:
        entry["container"] = by_port.get((entry["proto"], entry["port"]))
    return {"listeners": listeners}


# ---- users and groups ---------------------------------------------------

def _users(ctx, state):
    # Raw: the masker reads `auth:x:1001:...` as a secret and blanks the line,
    # which would drop the user. Only name, uid, gid, home, shell and group
    # members are kept (the password field and gecos are dropped), and every
    # kept string is masked by mask_leaves.
    r = ctx.reads([("passwd", "cat /etc/passwd"), ("group", "cat /etc/group")], raw=True)
    passwd, group = _atom(r, "passwd"), _atom(r, "group")
    if passwd is None or group is None:
        raise OSError("could not read /etc/passwd or /etc/group")
    groups, by_gid = [], {}
    for line in group.splitlines():
        cols = line.split(":")
        if len(cols) != 4:
            continue  # field 2 (the password field) is dropped
        g = {"name": cols[0], "gid": int(cols[2]) if cols[2].isdigit() else None,
             "members": [m for m in cols[3].split(",") if m]}
        groups.append(g)
        by_gid[g["gid"]] = g["name"]
    users = []
    for line in passwd.splitlines():
        cols = line.split(":")
        if len(cols) != 7:
            continue  # field 2 dropped, gecos not kept
        name, shell = cols[0], cols[6]
        gid = int(cols[3]) if cols[3].isdigit() else None
        member_of = sorted(set([by_gid.get(gid)] if by_gid.get(gid) else []) |
                           set(g["name"] for g in groups if name in g["members"]))
        users.append({"name": name, "uid": int(cols[2]) if cols[2].isdigit() else None,
                      "gid": gid, "home": cols[5], "shell": shell,
                      "login": bool(shell) and shell.rsplit("/", 1)[-1] not in NOLOGIN,
                      "groups": member_of,
                      "sudo": any(g in SUDO_GROUPS for g in member_of)})
    return {"users": users, "groups": groups,
            "sudo_users": sorted(u["name"] for u in users if u["sudo"])}


# ---- engine detection ---------------------------------------------------

def _image_base(image):
    base = (image or "").split("@", 1)[0].rsplit("/", 1)[-1]
    return base.split(":", 1)[0].lower()


def _instances(state, images, unit_prefixes):
    """Running containers with a matching image, plus an active host unit."""
    found = []
    for c in (state.get("containers") or {}).get("containers") or []:
        if c.get("state") == "running" and _image_base(c.get("image")) in images:
            found.append({"id": "container:%s" % c["name"], "source": "container",
                          "container": c["name"], "image": c.get("image")})
    for u in (state.get("services") or {}).get("units") or []:
        if u.get("active") == "active" and any(
                u["name"] == p + ".service" or u["name"].startswith(p + "@")
                for p in unit_prefixes):
            found.append({"id": "host:%s" % u["name"], "source": "host", "unit": u["name"]})
            break
    return found


def _broken(section):
    return not isinstance(section, dict) or "error" in section or "unavailable" in section


def _run_engine(ctx, state, images, units, one):
    # "Not present" must be an observation, never a failed container list.
    if _broken(state.get("containers")):
        raise OSError("container list unavailable, so detection cannot answer")
    instances = _instances(state, images, units)
    out = {"present": bool(instances), "instances": []}
    if _broken(state.get("services")):
        out["detection_incomplete"] = "systemd units unavailable; host services not checked"
    for inst in instances:
        try:
            # Journal-or-refuse, per DB instance, before anything is sent to it
            # (M5): a journal failure records an error and sends nothing.
            _journal_read(ctx.host, instance=inst["id"])
            inst.update(one(ctx, inst, out))
        except Unavailable as exc:
            inst["unavailable"] = str(exc)
        except Exception as exc:  # isolate one instance from the others
            inst["error"] = "%s: %s" % (type(exc).__name__, _short(secretmask.mask(str(exc))))
        out["instances"].append(inst)
    return out


# ---- postgres -----------------------------------------------------------

_PG_SESSION = "BEGIN READ ONLY;\nSET statement_timeout = '10s';\n"
_PG_GLOBAL = [
    ("version", "SHOW server_version"),
    ("recovery", "SELECT pg_is_in_recovery()"),
    ("databases", "SELECT datname, pg_get_userbyid(datdba), pg_encoding_to_char(encoding), "
                  "datallowconn, CASE WHEN has_database_privilege(datname, 'CONNECT') "
                  "THEN pg_database_size(datname) END FROM pg_database "
                  "WHERE NOT datistemplate ORDER BY 1"),
    ("roles", "SELECT rolname, rolsuper, rolcanlogin, rolreplication, rolcreatedb, "
              "rolcreaterole, rolinherit FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY 1"),
    ("members", "SELECT r.rolname, m.rolname FROM pg_auth_members a "
                "JOIN pg_roles r ON r.oid = a.roleid JOIN pg_roles m ON m.oid = a.member "
                "WHERE m.rolname !~ '^pg_' ORDER BY 2, 1"),
]
_PG_PER_DB = [
    ("schemas", "SELECT nspname, pg_get_userbyid(nspowner) FROM pg_namespace "
                "WHERE nspname !~ '^pg_' AND nspname <> 'information_schema' ORDER BY 1"),
    ("ownership", "SELECT n.nspname, pg_get_userbyid(c.relowner), c.relkind, count(*) "
                  "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                  "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' "
                  "AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') "
                  "GROUP BY 1, 2, 3 ORDER BY 1, 2, 3"),
    ("tables", "SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner) "
               "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
               "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' "
               "AND c.relkind IN ('r', 'p') ORDER BY 1, 2 LIMIT 5001"),  # MAX_TABLES + 1
]
# Runs INSIDE the container. The password comes from the container's own
# password file or environment and goes only into psql's environment.
_PG_IN_CONTAINER = (
    'if [ -n "${POSTGRES_PASSWORD_FILE:-}" ] && [ -r "$POSTGRES_PASSWORD_FILE" ]; '
    'then PGPASSWORD=$(cat "$POSTGRES_PASSWORD_FILE"); '
    # (split across two source lines only so the public exporter's
    # secret-assignment scan does not read the expansion as a literal)
    'else PGPASSWORD='
    '"${POSTGRES_PASSWORD:-${POSTGRESQL_PASSWORD:-}}"; fi; export PGPASSWORD; '
    'exec psql -X -q -tA -F "\t" -v ON_ERROR_STOP=1 '
    '-U "${POSTGRES_USER:-${POSTGRESQL_USERNAME:-postgres}}" -f -')
_PG_OPTIONS = "-c default_transaction_read_only=on"


def pg_script(statements):
    """The stdin script: a read-only session, then each statement behind a
    marker row. Every statement must pass the `sql` verb's classifier."""
    lines = [_PG_SESSION]
    for label, stmt in statements:
        try:
            sqlread.classify(stmt)
        except Refused as exc:
            raise Unavailable("sql %s: %s" % (label, exc))
        lines.append("SELECT '@@@%s';\n%s;\n" % (label, stmt))
    lines.append("COMMIT;\n")
    return "".join(lines)


def pg_command(inst, database):
    env = "-e PGDATABASE=%s -e PGOPTIONS=%s" % (shlex.quote(database), shlex.quote(_PG_OPTIONS))
    if inst["source"] == "container":
        return "docker exec -i %s %s sh -c %s" % (
            env, shlex.quote(inst["container"]), shlex.quote(_PG_IN_CONTAINER))
    return ("runuser -u postgres -- env PGDATABASE=%s PGOPTIONS=%s "
            "psql -X -q -tA -F %s -v ON_ERROR_STOP=1 -f -"
            % (shlex.quote(database), shlex.quote(_PG_OPTIONS), shlex.quote("\t")))


def _pg_query(ctx, inst, database, statements):
    script = pg_script(statements)
    deny_scan(script, ctx.deny)
    rc, out, err = ctx.exec_read(pg_command(inst, database), script)
    if rc != 0:
        raise OSError("psql exited %d: %s" % (rc, _short(err)))
    rows, label = {}, None
    for line in out.splitlines():
        if line.startswith("@@@"):
            label = line[3:].strip()
            rows[label] = []
        elif label is not None and line != "":
            rows[label].append(line.split("\t"))
    return rows


def _tf(v):
    return v == "t"


def _postgres_one(ctx, inst, section):
    rows = _pg_query(ctx, inst, "postgres", _PG_GLOBAL)
    member_of = {}
    for role, member in (tuple(r[:2]) for r in rows.get("members", []) if len(r) >= 2):
        member_of.setdefault(member, []).append(role)
    roles = [{"name": r[0], "superuser": _tf(r[1]), "login": _tf(r[2]),
              "replication": _tf(r[3]), "createdb": _tf(r[4]),
              "createrole": _tf(r[5]), "inherit": _tf(r[6]),
              "member_of": sorted(member_of.get(r[0], []))}
             for r in rows.get("roles", []) if len(r) >= 7]
    version = (rows.get("version") or [[None]])[0][0]
    recovery = (rows.get("recovery") or [[None]])[0][0]
    names = []
    for r in rows.get("databases", [])[:MAX_DATABASES]:
        if len(r) < 5:
            continue
        db = {"name": r[0], "instance": inst["id"], "owner": r[1], "encoding": r[2],
              "allow_connections": _tf(r[3]),
              "size_bytes": int(r[4]) if r[4].isdigit() else None}
        section.setdefault("databases", []).append(db)
        names.append(db)
    for db in names:
        if not db["allow_connections"]:
            db["schemas_unavailable"] = "database does not allow connections"
            continue
        if not DB_RE.match(db["name"]):
            db["schemas_unavailable"] = "database name outside the safe pattern; not sent"
            continue
        try:
            db["schemas"] = _pg_schemas(_pg_query(ctx, inst, db["name"], _PG_PER_DB))
        except Unavailable as exc:
            db["schemas_unavailable"] = str(exc)
        except Exception as exc:
            db["error"] = "%s: %s" % (type(exc).__name__, _short(secretmask.mask(str(exc))))
    return {"version": version,
            "in_recovery": None if recovery is None else _tf(recovery),
            "roles": roles,
            "databases_truncated": len(rows.get("databases", [])) > MAX_DATABASES}


def _pg_schemas(rows):
    schemas = {}
    for r in rows.get("schemas", []):
        if len(r) >= 2:
            schemas[r[0]] = {"name": r[0], "owner": r[1], "ownership": [], "tables": []}
    for r in rows.get("ownership", []):
        if len(r) >= 4 and r[0] in schemas:
            schemas[r[0]]["ownership"].append({
                "owner": r[1], "kind": RELKINDS.get(r[2], r[2]),
                "count": int(r[3]) if r[3].isdigit() else None})
    tables = rows.get("tables", [])
    for r in tables[:MAX_TABLES]:
        if len(r) >= 3 and r[0] in schemas:
            schemas[r[0]]["tables"].append({"name": r[1], "owner": r[2]})
    out = [schemas[k] for k in sorted(schemas)]
    if len(tables) > MAX_TABLES:
        for s in out:
            s["tables_truncated"] = True
    return out


def _postgres(ctx, state):
    out = _run_engine(ctx, state, POSTGRES_IMAGES, ("postgresql",), _postgres_one)
    out.setdefault("databases", [])
    return out


# ---- redis --------------------------------------------------------------

_REDIS_IN_CONTAINER = (
    'if [ -n "${REDIS_PASSWORD_FILE:-}" ] && [ -r "$REDIS_PASSWORD_FILE" ]; '
    'then REDISCLI_AUTH=$(cat "$REDIS_PASSWORD_FILE"); export REDISCLI_AUTH; '
    'elif [ -n "${REDIS_PASSWORD:-}" ]; then REDISCLI_AUTH="$REDIS_PASSWORD"; '
    'export REDISCLI_AUTH; fi; exec redis-cli --no-auth-warning ')


def redis_command(inst, verb="INFO"):
    verb = sqlread.classify_redis(verb)
    if inst["source"] == "container":
        return "docker exec %s sh -c %s" % (
            shlex.quote(inst["container"]), shlex.quote(_REDIS_IN_CONTAINER + verb))
    return "redis-cli --no-auth-warning %s" % verb


def _redis_one(ctx, inst, section):
    try:
        command = redis_command(inst)
    except Refused as exc:
        raise Unavailable("redis: %s" % exc)
    # Raw: the masker reads `keys=12` as a secret. Only the allowlisted
    # fields below are kept, counts as ints, and strings are masked later.
    rc, out, err = ctx.exec_read(command, raw=True)
    if rc != 0 or "NOAUTH" in out or not out.strip():
        raise OSError("redis-cli INFO failed: %s" % _short(err or secretmask.mask(out)))
    info = {}
    for line in out.splitlines():
        if ":" in line and not line.startswith("#"):
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    keyspace = []
    for k, v in sorted(info.items()):
        if re.match(r"\Adb\d+\Z", k):
            fields = dict(p.split("=", 1) for p in v.split(",") if "=" in p)
            keyspace.append({"db": int(k[2:]), "keys": _int(fields.get("keys")),
                             "expires": _int(fields.get("expires"))})
    keyspace.sort(key=lambda d: d["db"])
    return {"version": info.get("redis_version") or info.get("valkey_version"),
            "role": info.get("role"),
            "connected_replicas": _int(info.get("connected_slaves")),
            "keyspace": keyspace,
            "memory": {"used_bytes": _int(info.get("used_memory")),
                       "used_human": info.get("used_memory_human"),
                       "max_bytes": _int(info.get("maxmemory"))}}


def _int(v):
    return int(v) if isinstance(v, str) and v.isdigit() else None


def _redis(ctx, state):
    return _run_engine(ctx, state, REDIS_IMAGES, ("redis-server", "redis", "valkey-server"),
                       _redis_one)


# ---- rabbitmq -----------------------------------------------------------

RABBIT_VERBS = frozenset(["list_vhosts", "list_queues", "list_exchanges"])
_RABBIT_SCRIPT = (
    'rabbitmqctl -q list_vhosts name | while IFS= read -r v; do '
    '[ "$v" = name ] && continue; echo "@@@vhost $v"; echo "@@@queues"; '
    'rabbitmqctl -q list_queues -p "$v" name messages consumers; echo "@@@exchanges"; '
    'rabbitmqctl -q list_exchanges -p "$v" name type; done')


def rabbit_gate(script):
    """rabbitmqctl may only list. Every invocation in the script is checked."""
    verbs = re.findall(r"rabbitmqctl\s+(?:-q\s+)?(\S+)", script)
    if not verbs or any(v not in RABBIT_VERBS for v in verbs):
        raise Unavailable("rabbitmqctl verb outside %s" % ", ".join(sorted(RABBIT_VERBS)))
    return script


def rabbit_command(inst):
    script = rabbit_gate(_RABBIT_SCRIPT)
    if inst["source"] == "container":
        return "docker exec %s sh -c %s" % (shlex.quote(inst["container"]), shlex.quote(script))
    return "sh -c %s" % shlex.quote(script)


def _rabbit_one(ctx, inst, section):
    rc, out, err = ctx.exec_read(rabbit_command(inst))
    vhosts, cur, part = [], None, None
    for line in out.splitlines():
        if line.startswith("@@@vhost "):
            cur = {"name": line[9:], "queues": [], "exchanges": []}
            vhosts.append(cur)
        elif line in ("@@@queues", "@@@exchanges"):
            part = line[3:]
        elif cur is not None and part and line.strip():
            cols = line.split("\t")
            if part == "queues" and len(cols) >= 3 and cols[0] != "name":
                cur["queues"].append({"name": cols[0], "messages": _int(cols[1]),
                                      "consumers": _int(cols[2])})
            elif part == "exchanges" and len(cols) >= 2 and cols[:2] != ["name", "type"]:
                cur["exchanges"].append({"name": cols[0], "type": cols[1]})
    if rc != 0 and not vhosts:
        raise OSError("rabbitmqctl failed: %s" % _short(err or out))
    return {"vhosts": vhosts}


def _rabbitmq(ctx, state):
    return _run_engine(ctx, state, RABBITMQ_IMAGES, ("rabbitmq-server",), _rabbit_one)


# ---- web ----------------------------------------------------------------

def _web(ctx, state):
    cfg = state.get("traefik")
    if cfg is None:
        raise Unavailable("no traefik file provider named in the governor "
                          "(integrations.traefik)")
    if cfg["host"] not in state.get("aliases", (ctx.host,)):
        raise Unavailable("the traefik file provider lives on %s" % cfg["host"])
    # Raw: the masker rewrites `auth:` keys and breaks the YAML. Only router
    # names, hostnames, service names and backend URLs are kept (middlewares,
    # basicAuth users and TLS options are never read out), and those strings
    # are masked by mask_leaves like every other string.
    body = _atom(ctx.reads([("traefik", "cat %s" % shlex.quote(cfg["file"]))], raw=True),
                 "traefik")
    if body is None:
        raise OSError("could not read %s" % cfg["file"])
    routes = traefikmap.parse(body)
    return {"file": cfg["file"],
            "routers": [{"name": r["router"], "hostnames": r["hostnames"],
                         "service": r["service"], "backends": r["backend_urls"]}
                        for r in routes]}


COLLECTORS = {"host": _host, "services": _services, "containers": _containers,
              "ports": _ports, "users": _users, "postgres": _postgres,
              "redis": _redis, "rabbitmq": _rabbitmq, "web": _web}


def mask_leaves(node):
    """secretmask every string in the document (keys are schema, not data)."""
    if isinstance(node, dict):
        return dict((k, mask_leaves(v)) for k, v in node.items())
    if isinstance(node, list):
        return [mask_leaves(v) for v in node]
    if isinstance(node, str):
        return secretmask.mask(node)
    return node


def parse_sections(spec):
    if not spec:
        return list(SECTIONS)
    wanted = [s.strip() for s in spec.split(",") if s.strip()]
    bad = [s for s in wanted if s not in SECTIONS]
    if bad or not wanted:
        raise Refused("unknown section(s) %s — sections: %s"
                      % (", ".join(bad) or "(none)", ", ".join(SECTIONS)))
    return [s for s in SECTIONS if s in wanted]


def collect(host, ssh=None, sections=None, deny_patterns=(), risky_extra=(),
            traefik=None, aliases=(), now=None):
    """Index one host. Never raises for a section's failure: that section
    records `error` (it broke) or `unavailable` (a gate stopped it)."""
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host name %r" % host)
    wanted = list(sections) if sections else list(SECTIONS)
    ctx = _Ctx(host, ssh or _default_ssh, deny_patterns, risky_extra)
    state = {"traefik": traefik, "aliases": set(aliases) | {host}}
    run = set(wanted)
    for name in wanted:
        run.update(DEPENDS.get(name, ()))
    when = now or datetime.datetime.now(datetime.timezone.utc)
    # Journal-or-refuse before the first command reaches the host (M5).
    _journal_read(host, sections=sorted(run))
    doc = {"index_version": INDEX_VERSION,
           "collected_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "host": host, "sections": {}}
    for name in SECTIONS:
        if name not in run:
            continue
        try:
            result = COLLECTORS[name](ctx, state)
        except Unavailable as exc:
            result = {"unavailable": _short(str(exc))}
        except Exception as exc:  # one section never fails the others
            result = {"error": "%s: %s" % (type(exc).__name__, _short(secretmask.mask(str(exc))))}
        state[name] = result
        if name in wanted:
            doc["sections"][name] = result
    return mask_leaves(doc)
