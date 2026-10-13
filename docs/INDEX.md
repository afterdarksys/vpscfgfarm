# INDEX — what lives on each host, recorded

```
vpscfg index <host> [--json|--yaml] [--section host,postgres,...] [--no-save]
vpscfg index --all [--json|--yaml]
vpscfg index diff <host> [--json]
vpscfg index query '<expr>' [--json|--hosts]
vpscfg fleet index ...                 # the same grammar under `fleet`
```

Deploys fail on facts nobody wrote down: which role owns which tables, which
env var names a container reads, which compose project and files a container
came from, which databases live on which Postgres. `vpscfg index` reads them
off the host, over SSH and read-only, into one JSON document per host. The
document is cached, can be diffed against the previous run and can be queried
across the fleet. Run it on demand, or every 12 hours from the templates in
`contrib/index-schedule/`.

## What it records

| Section | Contents |
|---|---|
| `host` | hostname, OS (`/etc/os-release`), kernel, arch, uptime, CPUs, memory, disks (`df`, real filesystems only) |
| `services` | systemd service units: name, load, active, sub, enabled |
| `containers` | every docker container: name, image, image id, state, compose project/service/config files/working dir, networks, published ports, **env var names only**; k3s Deployments/StatefulSets/DaemonSets with ready counts and images |
| `ports` | listening sockets (`ss -lntup`) with process, pid, and the container that publishes the port |
| `users` | `/etc/passwd` and `/etc/group`: name, uid, gid, home, shell, whether the shell allows login, groups, sudo membership (`sudo`, `wheel`, `admin`). Never `/etc/shadow`; the password field and gecos are dropped |
| `postgres` | each Postgres container (by image) or active `postgresql` unit: version, recovery state, roles (attributes and memberships), databases (owner, encoding, size), and per database its schemas, object ownership counts per role and kind, and table owners |
| `redis` | each Redis/Valkey/KeyDB container or unit: version, role, replicas, keyspace (db, key and expiry counts), memory. Never keys or values |
| `rabbitmq` | each RabbitMQ container or unit: vhosts, queues (name, messages, consumers), exchanges (name, type). Never messages |
| `web` | Traefik routers from the governor's file provider (`integrations.traefik`): name, hostnames, service, backend URLs. Only on the host the governor names |

## The document

```
{"index_version": 1, "collected_at": "...Z", "host": "<alias>", "sections": {<name>: ...}}
```

`docs/index.schema.json` is the JSON Schema. A section is one of three things:

- its data;
- `{"error": "..."}` — the read broke (transport, parse, a tool missing). The
  other sections still run. A section whose input broke reports an error too:
  if the container list failed, `postgres` says `error`, never `present: false`;
- `{"unavailable": "..."}` — a gate refused to send the command (below).
  Nothing was sent.

Inside the database sections, one instance or one database can carry its own
`error`, `unavailable` or `schemas_unavailable` without failing the rest.

An example, collected from the test suite's fake host (trimmed):

```json
{
  "collected_at": "2026-10-12T12:00:00Z",
  "host": "web1",
  "index_version": 1,
  "sections": {
    "containers": {
      "containers": [
        {
          "compose": {"config_files": ["/srv/auth/docker-compose.yml"], "project": "auth",
                      "service": "auth", "working_dir": "/srv/auth"},
          "env_names": ["DB_HOST", "DB_PASSWORD", "JWT_SECRET"],
          "image": "example/auth:1.4",
          "image_id": "sha256:2222",
          "name": "auth",
          "networks": ["shop_default", "web"],
          "published": [{"container_port": 3001, "host_ip": "0.0.0.0", "host_port": 3001, "proto": "tcp"}],
          "state": "running"
        }
      ],
      "docker": {"server_version": "27.3.1"},
      "k3s": null,
      "skipped": ["bad$(name)"]
    },
    "host": {
      "arch": "x86_64", "cpus": 8, "hostname": "web1.example.internal",
      "kernel": "6.1.0-25-amd64",
      "memory": {"available_bytes": 30000000000, "total_bytes": 33554432000},
      "os": {"id": "debian", "pretty_name": "Debian GNU/Linux 12 (bookworm)", "version_id": "12"},
      "disks": [{"available_bytes": 61440000, "filesystem": "/dev/vda1", "mount": "/",
                 "size_bytes": 102400000, "used_bytes": 40960000}],
      "uptime_seconds": 86400
    },
    "ports": {
      "listeners": [
        {"address": "127.0.0.1", "container": "app-postgres", "pid": 901, "port": 5432,
         "process": "docker-proxy", "proto": "tcp"}
      ]
    },
    "postgres": {
      "present": true,
      "instances": [
        {
          "id": "container:app-postgres", "source": "container", "container": "app-postgres",
          "image": "postgres:16-alpine", "version": "16.4", "in_recovery": false,
          "databases_truncated": false,
          "roles": [{"name": "login", "superuser": false, "login": true, "replication": false,
                     "createdb": false, "createrole": false, "inherit": true,
                     "member_of": ["app_readers"]}]
        }
      ],
      "databases": [
        {
          "name": "shop_auth", "instance": "container:app-postgres", "owner": "login",
          "encoding": "UTF8", "allow_connections": true, "size_bytes": 8000000,
          "schemas": [
            {
              "name": "shop", "owner": "login",
              "ownership": [{"count": 12, "kind": "table", "owner": "login"},
                            {"count": 8, "kind": "table", "owner": "postgres"},
                            {"count": 4, "kind": "sequence", "owner": "login"}],
              "tables": [{"name": "users", "owner": "login"},
                         {"name": "sessions", "owner": "postgres"}]
            }
          ]
        }
      ]
    },
    "rabbitmq": {
      "present": true,
      "instances": [
        {"id": "container:mq", "source": "container", "container": "mq",
         "image": "rabbitmq:3.13-management",
         "vhosts": [{"name": "/",
                     "queues": [{"name": "jobs", "messages": 12, "consumers": 1}],
                     "exchanges": [{"name": "amq.topic", "type": "topic"}]}]}
      ]
    },
    "redis": {
      "present": true,
      "instances": [
        {"id": "container:cache", "source": "container", "container": "cache",
         "image": "redis:7", "version": "7.2.4", "role": "master", "connected_replicas": 0,
         "keyspace": [{"db": 0, "expires": 3, "keys": 12}],
         "memory": {"max_bytes": 0, "used_bytes": 1048576, "used_human": "1.00M"}}
      ]
    },
    "services": {
      "units": [{"active": "active", "enabled": "enabled", "load": "loaded",
                 "name": "docker.service", "sub": "running"}]
    },
    "users": {
      "groups": [{"gid": 27, "members": ["alice"], "name": "sudo"}],
      "sudo_users": ["alice"],
      "users": [{"gid": 1000, "groups": ["alice", "docker", "sudo"], "home": "/home/alice",
                 "login": true, "name": "alice", "shell": "/bin/bash", "sudo": true, "uid": 1000}]
    },
    "web": {
      "file": "/root/traefik/dynamic/services.yml",
      "routers": [{"backends": ["http://auth:3001"], "hostnames": ["auth.example.com"],
                   "name": "auth", "service": "auth"}]
    }
  }
}
```

The 8 tables owned by `postgres` in schema `shop` are the kind of fact that
stopped a migration this weekend: a role cannot `ALTER` a table it does not own.

## Read-only, and how that is enforced

Every remote command comes from a fixed template in `vpscfg/hostindex.py`.
The only values spliced in are names the host returned in an earlier read
(container and database names). Each must match a strict pattern and is
shell-quoted; a name outside the pattern is skipped and listed (`skipped`,
`schemas_unavailable`), never sent.

Each command passes a gate before it is sent:

| Command | Gate |
|---|---|
| host reads: `hostname`, `cat /etc/os-release`, `uname`, `free`, `df`, `systemctl list-units`, `docker ps`/`inspect`/`version`, `k3s kubectl get`, `ss`, `cat /etc/passwd`, `cat` of the Traefik file | must classify as `read` under vpsexec's classifier, with the deny floor, the governor's `deny_always`, the policies' `deny_extra` and `risky_extra` |
| psql inside the Postgres container | every SQL statement passes `sqlread.classify` (the `vpscfg <host> sql` gate: SELECT/SHOW only, one statement, no comments). The session is `default_transaction_read_only=on` (PGOPTIONS) and the script runs inside `BEGIN READ ONLY` with a 10 s statement timeout |
| redis-cli inside the Redis container | the command (`INFO`) passes `sqlread.classify_redis` |
| rabbitmqctl inside the RabbitMQ container | only `list_vhosts`, `list_queues`, `list_exchanges` |
| every command, whole line | deny-scanned against the floor plus the governor and policies before it is sent |

A command that fails its gate is not sent, and its section (or instance)
reads `unavailable: <reason>`. It does not fall back to anything broader.

**Journal-or-refuse.** Before the first command reaches a host, `collect`
journals `index_read` (`vpsexec.jsonl`: host and sections); before anything is
sent to a database instance it journals `index_read` with that `instance`
(`container:<name>` or `host:<unit>`). A journal write that fails stops the
whole run (host) or that instance (it records `error`, nothing is sent to it).

`docker exec` is in vpsexec's risky tier, so the in-container reads do not go
through the vpsexec classifier; they go through the narrower gates above,
the same ones the `sql` verb uses. Unlike `sql`, the index does not refuse a
superuser role: its SQL is a fixed set of catalog SELECTs in a read-only
session, not an operator's query.

### Credentials

The database password is read **inside the container**, from
`POSTGRES_PASSWORD_FILE` or `POSTGRES_PASSWORD` (or the Bitnami
`POSTGRESQL_PASSWORD`), into `PGPASSWORD` in the shell that `exec`s psql.
It never appears on a command line, in the ssh payload or in the output.
Redis uses `REDIS_PASSWORD_FILE` or `REDIS_PASSWORD` into `REDISCLI_AUTH` the
same way. A host-service Postgres is read as `runuser -u postgres` (peer
auth); a password-protected host-service Redis records an `error`.

### No secret values

- Env vars are read as **names**: the docker template splits each `KEY=value`
  on the host (`{{index (split . "=") 0}}`), so values never cross the wire.
- Remote output passes `secretmask.mask` before it is parsed, and every string
  in the finished document passes it again.
- Three reads are parsed before masking, because the masker blanks lines
  shaped like `auth:x:1001:...`, `keys=12` or a YAML `auth:` key: `/etc/passwd`
  and `/etc/group`, Redis `INFO`, and the Traefik file. From each, only an
  allowlist of fields is kept (no password field, no gecos, no middleware or
  basicAuth blocks; Redis counts as integers), and those strings are masked
  with the rest.
- Tests assert that a fake container's env values and a fake database
  password never appear in the document, the output or any command sent.

What this does not protect against: a secret stored in a name (a table, role,
queue or env var named after its value), and a hostile host lying in its
output.

## Cache

`vpscfg index <host>` writes `<estate>/index/<host>.json` (mode 0600) and
moves the previous file to `<host>.prev.json`. The index names roles,
databases, users and env-var names, so it must never be committed: when the
cache directory is inside a git repository, every write first asks
`git check-ignore`, and refuses (writing nothing) unless both files are
ignored — or if git cannot answer. `index/` is gitignored in the tool
checkout; an estate that lives in its own repository needs this line in that
repository's `.gitignore`:

```
/index/
```
A run limited by `--section`, a run where every section failed, and
`--no-save` leave the cache alone, so a partial document never rotates a
good one away.

`vpscfg index diff <host>` compares the two files' sections. List items are
matched by `id`, `name` or `router`, so reordering is not a change; only
`collected_at` is ignored. Exit 0 means no change, 1 means changes.

```
index diff web1: 2026-10-12T00:00:00Z -> 2026-10-12T12:00:00Z
  ~ host.cpus: 8 -> 16
  - containers.containers["mq"].state = "running"
  ...
```

## Query

`vpscfg index query` runs one expression across every cached host. Paths start
at the sections. The output is `host<TAB>value-as-json` per match;
`--hosts` prints only the matching hosts, and `--json` prints a list.

| Expression | Answers |
|---|---|
| `postgres.databases[] \| select(name=="shop_auth")` | which host (and instance) has that database |
| `redis \| select(present)` (with `--hosts`) | which hosts run Redis |
| `containers.containers[] \| select(published[].host_port == 5432) \| name` | which containers publish 5432 |
| `containers.containers[] \| select(env_names[] ~ "DATABASE_URL") \| name` | who reads `DATABASE_URL` |
| `postgres.databases[].schemas[].ownership[] \| select(owner == "postgres" and kind == "table")` | tables an app role does not own |
| `users.users[] \| select(sudo and not name == "root") \| name` | who has sudo |

The grammar: stages joined by `|`. A stage is a path (`a.b[]`, `a[0]`, `.`)
or `select(<cond>)`. A condition is `path` (truthy), `path OP literal` with
`==`, `!=`, `<`, `<=`, `>`, `>=` or `~` (substring), combined with `and`,
`or`, `not` and parentheses. A path through `[]` matches when any element
does. Literals are `"strings"`, numbers, `true`, `false` and `null`. The
expression is parsed by a fixed grammar; nothing is evaluated or handed to
`jq`.

## As a library

```python
from vpscfg import hostindex, indexstore

doc = hostindex.collect("web1", deny_patterns=guard.deny_patterns())   # one host, live
cached = indexstore.load("web1", indexstore.cache_dir())                 # last cached run
hits = indexstore.query('postgres.databases[] | select(name=="shop_auth")',
                        indexstore.load_all(indexstore.cache_dir()))
```

`collect` takes `ssh=` (a `(host, command, stdin) -> (rc, stdout, stderr)`
transport) and `sections=`, so a caller such as the runbook preflight can ask
for `postgres` alone, or tests can supply a fake host.

`indexstore.cache_status(host, directory, max_age, now=None)` is the
preflight-facing freshness check (`vpsexec runbook preflight`, "Index-backed
preflight" in VPSEXEC.md): `(doc, age_seconds, None)` when the cache at
`<directory>/<host>.json` is a regular, non-symlink, `0600` file owned by the
caller, with a known `index_version` and a `collected_at` that is neither
future-dated by more than 60s nor older than `max_age`; otherwise
`(None, None, reason)`. It never dials and never raises — a reason to fall
back to a live read, or to `skip` under `--index-only`, is exactly what it
returns. `indexstore.max_age_seconds(limits)` reads the governor's
`limits.index_max_age_hours` (default 12, clamped to a ceiling of 24).
Preflight calls `cache_status` at most once per host per run and journals the
result as `preflight_source`; the section-specific check (is `postgres`
itself fresh, does this container appear in `containers`) is the caller's
job, since only it knows which section it needs.

## Doors

`index` is a read-only group word in both doors, like `fleet`. The outer door
(`vpscfg-control.py`) still requires the governor to list `index` in
`allowed_verbs`; until it does, use `vpscfg fleet index ...`, which `fleet`
already covers. `--all` indexes the governor's canonical hosts (aliases
collapsed).

## Scheduling

`contrib/index-schedule/` has a launchd agent and a systemd service and timer
for every 12 hours. Neither is installed by anything in this repo. Each runs
`/path/to/vpscfgfarm/vpscfg-control.py index --all` BY PATH (its pinned
shebang picks the interpreter; never `python3 <door>`), so the outer door
journals the run.

Implementation: `vpscfg/hostindex.py` (collection), `vpscfg/indexstore.py`
(cache, diff, query, CLI). Tests: `tests/test_hostindex.py` (hermetic: a fake
host behind the ssh transport, a temp-dir cache).
