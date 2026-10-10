# vpscfgfarm

Contract-based configuration and deployment safety for a fleet of servers
reached over ssh. It puts a door in front of production: every command goes
through it, and the door decides.

> Don't run commands by hand in prod. Humans make mistakes, AI makes mistakes,
> cats make mistakes, blind humans make mistakes — **contract-based, verifiable
> code protects all of them.** The checking lives in the door, not the operator.

## Why it exists

It was born from a near-miss. A `docker volume prune` had already been
approved, and it was one keystroke from running on a host whose volumes were
named **one character** away from the volumes of live production databases.
Nothing in the operator's tooling would have stopped it. Careful people and
careful agents both make that mistake eventually, so the check has to live
somewhere that does not get tired: in code that every command passes through,
and that refuses by default.

## What is in the box

- **`vpscfg-control.py`** — the door for contracted work. It validates the
  governor, judges every invocation, journals everything (allowed AND
  refused), then hands off to the `vpscfg` package with a policy-hash token.
  The package re-validates independently and refuses a token it cannot match.
- **`vpscfg/`** — the package. Read-only observation (containers, services,
  k3s, drift, ports, logs, firewall and k3s audits, and more) and the
  contracted mutation path: lock, live outage check, backup, sync, build,
  verify, drift confirmation, unlock. Every mutation passes through the
  governor and the executor, and only for scopes the governor has released.
- **`vpsexec`** — the other door: gated ad-hoc commands across the fleet or
  inside its containers, for the things a contract cannot express (restart a
  wedged process on several machines during an outage; read five machines'
  logs at once). Reads fan out in parallel; mutations run serially and report
  per host. Three tiers (read / mutating / risky), per-plan approval,
  break-glass only through committed runbooks, and the same deny-always floor.
  See [docs/VPSEXEC.md](docs/VPSEXEC.md).
- **`vpsrun`** — the queue runner: an agent queues a multi-step play, and a
  human reads every plan and approves it once in a real terminal
  ([plays/README.md](plays/README.md)).
- **`contrib/`** — a complete fictional example estate and a runbook walker.

The **governor** (`vpscfg-control.json`) is the one file that grants anything:
host postures (`frozen`, `lockdown`, `test`, `released`), the master switch,
the mode and the released scopes. **Policy files** (`policies/*.yaml`) can
only make the doors stricter: name host groups, add deny patterns, list
credential paths that are never readable, and authorise exact commands on
exact hosts as reviewed, expiring runbooks
([policies/README.md](policies/README.md)).

## Fail-closed, and refuses with no governor

This repository does **not** ship a governor. Until you configure an estate,
every door refuses: `control file missing — nothing runs without the
governor`. That is the intended default for a door.

Beyond that:

- **The deny-always floor** (`volume|system|image|network prune`,
  `volume rm`, `compose down -v`, `DROP TABLE|DATABASE|SCHEMA`, `TRUNCATE`,
  `rm -rf /...`, `kubectl delete ns`, `mkfs`, `dd if=`, `terraform destroy`)
  is compiled into all three doors. A governor that omits an entry is treated
  as tampered and refuses everything. No policy file, runbook, `--break-glass`
  or approval reaches it.
- **Unknown is a mutation.** The read tier is an allowlist with per-command
  option grammars; anything not on it needs `--run`, a reason and approval.
  Command substitution is refused outright, because it cannot be scanned.
- **Can't journal, can't mutate.** The journal is a locked, fsynced,
  hash-chained JSONL file. If it cannot be written, nothing changes.
- **No environment variable, flag or search path chooses the governor.** The
  doors find it by location only and run under an isolated interpreter
  (below), so being able to start a process is never enough to choose which
  governor it obeys.
- **Secret values are masked** in all remote output before it is shown,
  compared or journaled. If the masker fails, the output is withheld.

The test suite proves the refusals: deny-floor tampering, wrapper
impersonation via environment variables, one-character volume twins, frozen
contracts, ungraduated scopes, source/approval drift, a floor command that
survives no combination of policy file, runbook, `--break-glass` and approval,
and an ad-hoc override file that cannot grant elevation at all.

## Quick start

Requirements: Python 3.9 or newer, `ssh`, `rsync`, `tar`, and PyYAML
(hash-pinned in `requirements.txt`).

```sh
git clone https://github.com/afterdarksys/vpscfgfarm.git
cd vpscfgfarm
python3 -m pip install --require-hashes -r requirements.txt
```

### 1. Pin the interpreter (the install step)

The three doors carry one shebang naming a real interpreter binary with `-I`
(isolated mode: every `PYTHON*` variable, the user site and the script
directory are ignored). The committed shebang is the maintainer's machine, so
point it at yours, using the interpreter that has PyYAML:

```sh
tools/pin-interpreter.sh "$(python3 -c 'import os,sys;print(os.path.realpath(sys.executable))')"
```

It rewrites line 1 of `vpscfg-control.py`, `vpsexec` and `vpsrun`. It refuses,
writing nothing, unless the target is an absolute, real (not symlinked),
executable binary that is not group- or world-writable, in a directory that is
not either, that actually reports isolation under `-I`, and that on macOS is
not one of the `/usr/bin` xcrun shims. Never use `#!/usr/bin/env`: it lets
`PATH` choose the program that reads the governor.

Start the doors **by path** (`./vpsexec`, or a symlink such as
`~/bin/vpsexec`). The `python3 vpsexec` form cannot be protected against a
hostile startup hook in the first interpreter; wrappers and agent harnesses
should deny it.

### 2. Point the tool at an estate

The **estate** is the set of files that describe one fleet: the governor,
`policies/`, `contracts/`, `playbooks/`, `plays/` and `inventory/`. By default
the estate is the tool checkout itself. To keep it in its own directory (for
example a private repository), write a pointer file, `estate.path`, at the
root of the tool checkout. To try the tool, point it at a copy of the example:

```sh
cp -R contrib/example-estate ~/vpscfg-estate
printf '%s\n' "$(cd ~/vpscfg-estate && pwd -P)" > estate.path
chmod 600 estate.path
./vpscfg-control.py status     # the example's three hosts and their postures
```

The pointer is deliberately strict. Anything doubtful refuses, and nothing
falls back to the default once a pointer exists:

- it holds **one line**: an **absolute, normalised path that is already its
  own real path** (no symlink anywhere in it, no `..`, no trailing slash, no
  surrounding whitespace);
- the pointer is a regular file **owned by you** and **not group- or
  world-writable** (0600 or 0644);
- the target directory, the governor and everything the tool reads inside it
  are owned by you, not writable by others, and contain no symlinks; each
  ancestor directory is owned by you or root and is not writable by others
  unless sticky (like `/tmp`); extended ACLs that grant write refuse;
- it is **never committed**. It is gitignored, and a pointer that git tracks
  or has staged refuses: a committed pointer would move every clone's estate.

There is no flag or environment variable for this, on purpose. Delete
`estate.path` to go back to the default. The journal stays in the tool
checkout (`journal/`, gitignored) either way.

### 3. Walk the example

[contrib/README.md](contrib/README.md) walks the example estate end to end: the
governor and its postures, the ssh config aliases every governed host needs
(`vpsexec` refuses a group member it cannot reach), a groups-only policy, a
first read, a reviewed release runbook, an approval grant and the runbook
walker. Then replace the example hosts with your own, start every host at
`frozen` or `test`, and change postures only in reviewed commits.

### Run the proof

```sh
python3 -m unittest discover -s tests
```

CI treats a skipped test as a failure.

## Documentation

| Doc | What |
|---|---|
| [docs/README.md](docs/README.md) | Architecture map of the repository |
| [docs/VPSEXEC.md](docs/VPSEXEC.md) | The fleet command door: tiers, policy, break-glass, grants, push |
| [docs/HOWTO.md](docs/HOWTO.md) | The contracted-deploy door: reads, preflight, the release ritual |
| [docs/STABILITY.md](docs/STABILITY.md) | The release ratchet: how controls come off, in order |
| [docs/DESIGN.md](docs/DESIGN.md) | The contract → plan → gate → apply → verify pipeline |
| [docs/SECURITY-TOOLING.md](docs/SECURITY-TOOLING.md) | The read-only watchers |
| [docs/RECOVERY.md](docs/RECOVERY.md) | Retained locks, partial deployments, release checks |
| [docs/REPAIR-PROTOCOL.md](docs/REPAIR-PROTOCOL.md) | The versioned machine interface for goodfarm, badfarm's repair-planning module |

### Optional integrations (off by default)

A few features talk to systems outside the tool. Each is an optional governor
setting and does nothing until you configure it:

- **Telemetry**: an endpoint that receives a copy of each journal record. The
  local journal stays authoritative, and push failures never block a mutation.
  The API key is yours, not the governor's: `$VPSCFG_TELEMETRY_KEY` or
  `~/.config/vpscfgfarm/telemetry-key`. Redirects and environment proxies are
  never followed.
- **Traefik file-provider path**: lets probes and `tools/traefik_verify.py`
  read a host's Traefik dynamic config to suggest `http:` verify checks.
- **Firewall manager**: the desired-state JSON `vpscfg fleet firewall` judges
  live firewall state against, plus the manager's lockdown script path, boot
  unit and installer name.
- **Maintenance windows**: a JSON export of active windows. Plans and
  preflight say which hosts are inside one, and `--require-blackout` refuses
  hosts that are not. Unset, every host's window status is "unknown".
- **Secret source**: the command `secret-put --from-pipe` runs (no shell) to
  read one secret from your keystore. Unset, `--from-pipe` refuses.

## Scope

In scope: an operator or small team running a fleet of Linux hosts over ssh
(Docker, docker compose, k3s) who want every production command to pass
through reviewed, tested, journaled code, including agents working on such a
fleet under a human's approval.

Out of scope: it is not a configuration-management system (it can drive
ansible behind the same gates, but does not replace it), not a multi-tenant
service, not a secrets store, and not a sandbox against a local user who can
already edit the doors. It protects production from mistakes made through the
door. It cannot stop someone who goes around it with raw ssh;
`vpscfg fleet changes` exists to notice when that happens.

## Related projects

- **badfarm** — a read-only discovery companion that inventories
  infrastructure and emits findings; its **goodfarm** module plans repairs
  against vpscfgfarm contracts and drives them through the repair protocol
  ([docs/REPAIR-PROTOCOL.md](docs/REPAIR-PROTOCOL.md)). To be released
  separately.

## Security and contributing

To report a way past a door, see [SECURITY.md](SECURITY.md). To contribute,
see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
