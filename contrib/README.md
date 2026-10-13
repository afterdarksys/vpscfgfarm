# contrib/

Material for setting vpscfgfarm up on your own fleet. Nothing in here is loaded
by the tools. Every door reads the governor (`vpscfg-control.json`) and
`policies/*.yaml` from ONE estate root: the tool checkout itself, or the one
directory named by a pinned `estate.path` file in the tool checkout (one line,
an absolute real path; the file and the estate must be yours and not writable
by others — never an environment variable or a flag). So these files do
nothing until you copy them into place, either into the checkout or into an
estate directory that `estate.path` names.

| Path | What it is |
|---|---|
| `example-estate/` | A fictional three-host estate: a governor, ssh stanzas, a groups file, a checks file, a credential-path deny list and one release runbook with its artifact |
| `runbook-walker/walk.sh` | Runs the steps of one runbook in order, each through `vpsexec` |
| `runbook-walker/deploy.sh` | Mints one approval contract for a runbook, then runs `walk.sh` under it |
| `index-schedule/` | Templates (launchd agent; systemd service and timer) that run `vpscfg index --all` every 12 hours. Not installed by anything; see [docs/INDEX.md](../docs/INDEX.md) |

`tests/test_contrib.py` loads the example with the real policy loader and runs
the walker's `--list` mode, so the example cannot drift out of step with the
tool. Run it with `python3 -m pytest -q tests/test_contrib.py`.

## The example estate

| Host | Address | Posture | Role |
|---|---|---|---|
| `web1` (also `web1.example.internal`) | 192.0.2.10 | `frozen` | serves www.example.com; no failover |
| `db1` | 192.0.2.20 | `lockdown` | the database |
| `edge1` | 198.51.100.5 | `test` | reverse proxy; where it is safe to be wrong first |

The release runbook ships version 1.4.0 of a web app called "shop", a docker
compose project in `/srv/shop` on `web1`. Addresses are from the RFC 5737
documentation ranges. Replace all of it with your own.

Read [docs/VPSEXEC.md](../docs/VPSEXEC.md) and [policies/README.md](../policies/README.md)
before or alongside this; the steps below link into them rather than repeat
them.

## Quick start

Work in your own clone. Install the pinned dependencies first:
`python3 -m pip install --require-hashes -r requirements.txt`.

### 1. The governor

`vpscfg-control.json` at the estate root (the repo root, unless `estate.path`
names another directory) is the governor. Every door reads it, and nothing in
`policies/` can loosen it. Start from the example:

```
cp contrib/example-estate/vpscfg-control.json vpscfg-control.json
```

Then list your own machines under `hosts`. Each one gets a posture:

| Posture | Reads | Mutations through vpsexec |
|---|---|---|
| `released` | yes | yes, with `--run`, `--reason` and approval |
| `test` | yes | yes, the same way. Use it for the host where a mistake is cheap |
| `lockdown` | yes | only with `--break-glass` and a committed runbook naming the exact command |
| `frozen` | yes | the same as `lockdown` |

A host missing from `hosts` is treated as frozen. Other keys that matter:

- `mode` and `mutation_enabled` are the master controls. `mode: lockdown` or
  `mutation_enabled: false` refuses every mutation, break-glass included.
- `allowed_verbs` must contain `exec` for `vpsexec` to work at all. Removing it
  turns `vpsexec` off everywhere in one edit.
- `alias_of` says two names are one machine (`web1.example.internal` is
  `web1`). Postures are read from the canonical host, and an alias whose
  posture differs refuses to load.
- `deny_always` must contain at least the floor compiled into the doors. You
  can add patterns; removing one is treated as tampering and refuses everything.
- `integrations` (optional) names the outside systems the tool may talk to.
  Each is off until named here, and only here: no environment variable or
  flag can set them.
  - `telemetry.url`: an `https://` control plane that receives a copy of
    each journal event (`<url>/telemetry/events`).
  - `traefik.host` and `traefik.file`: a Traefik file provider to read for
    suggested http verify entries.
  - `firewall`: the firewall audit's firewall manager. `desired_state` is
    its desired-state JSON, as a path relative to the estate root; `script`
    is the absolute path of its lockdown script on each host (sha256-compared
    across hosts); `unit` is the systemd unit that re-applies it at boot;
    `installer` is the text remedies name for (re)installing it.
  - `blackout.file`: the absolute path of a maintenance-window export
    (JSON). Unset, no windows are known: every host reads "unknown", the
    same as a missing file, and `--require-blackout` refuses.
  - `secret_source.command`: an argv list (no shell), e.g.
    `["keystore", "pipe", "--"]`. `secret-put --from-pipe NAME` appends NAME
    and reads the secret from its stdout. Unset, `--from-pipe` refuses.
- On a host entry, `failover: false` marks a host with no failover (an outage
  there is total), and `audit_by_default: false` leaves it out of fleet-wide
  audits unless it is named.

Start every new host at `frozen` or `test` and change postures in reviewed
commits. [docs/STABILITY.md](../docs/STABILITY.md) describes how controls are
released for contracted deploys; `scopes` in the governor belongs to that path
and can stay empty while you only use `vpsexec`.

### 2. ssh config aliases

`vpsexec` connects with plain `ssh <alias>` and treats `~/.ssh/config` as the
host list. Add the stanzas from `example-estate/ssh_config.example` (with
your own addresses and key) to `~/.ssh/config`, or keep them in their own file
and `Include` it: includes are followed as OpenSSH follows them (relative to
`~/.ssh`, globs, nesting; a loop or an unreadable include refuses).

Every governed host must be a `Host` alias there, or be declared `alias_of`
one in the governor. Two aliases with the same `HostName` collapse to one
machine in a plan, so a command never runs twice on one box.

### 3. A groups-only policy

Policy files live in `policies/*.yaml` (not recursive, so
`policies/examples/` is inert). Move any file there that does not describe
your fleet out of the way first: every group member and runbook host is checked
against your governor and your ssh config, and a file naming hosts you do not
have refuses to load.

```
cp contrib/example-estate/policies/groups.yaml policies/
cp contrib/example-estate/policies/checks-example.yaml policies/
cp contrib/example-estate/policies/secrets.yaml policies/
./vpsexec hosts       # postures, as the governor sees them
./vpsexec groups      # @web, @db, @edge, @docker, @shop, @test
./vpsexec checks      # the named read plays
```

A file with only `groups:` and `checks:` grants nothing, so it needs no
`expires`. Keys and rules: [policies/README.md](../policies/README.md).

### 4. A first read

Reads need no `--run`, no reason and no approval, and work on frozen hosts:

```
./vpsexec @all 'uptime'
./vpsexec @docker 'docker ps' --compare
./vpsexec check failed
./vpsexec check shop-health port=8080
```

Whether a command counts as a read is decided by an allowlist with per-command
option grammars ([docs/VPSEXEC.md, "The three tiers"](../docs/VPSEXEC.md#the-three-tiers)).
Anything not on it is a mutation. One example of how strict that is: `curl`
counts as a read only when its first argument is `-q` (so it ignores
`~/.curlrc`), which is why the example's health checks say `curl -qfsS`.

Try a mutation without `--run` to see a plan and nothing else:
`./vpsexec edge1 'touch /tmp/hello'`. On `web1` the same command is refused
by posture. `systemctl restart nginx` is refused even on `edge1`: restarts are
in the risky tier, which needs a runbook naming the command on every host.

### 5. A reviewed runbook

A runbook is a policy file with `runbooks:`. Each entry authorises one exact
command on exact hosts. `example-estate/policies/web-release-example.yaml` is
a complete release; the parts to copy:

- **`expires`** (required when a file has runbooks). Date it a few days out.
  After that day its runbooks are disarmed and `vpsexec` warns on every run;
  other files are unaffected.
- **`break_glass: true`** on every step that must reach a `frozen` or
  `lockdown` host. Leave it off for steps on `test` hosts and for reads.
- **`verify`**: a post-condition that runs on the host right after the step.
  It must be a read, and it must exit non-zero on failure:
  `echo '<sha>  <path>' | sha256sum --check --status` checks bytes,
  `docker ps ... | grep -qx NAME` checks a container is running,
  `curl -qfsS URL` checks an HTTP endpoint. `sha256sum FILE` alone is not a
  check: it exits 0 whatever it prints. A service that takes a few seconds to
  come up can get `verify_retry: {tries: 10, interval: 3}` on the same entry.
- **`container: NAME`** on a `where: container` entry names the one container
  it authorises; the walker turns it into `--in NAME`.
- **Artifacts by hash.** A step whose `cmd` is `vpscfg-push <sha256> <name>`
  authorises pushing exactly those bytes (`./vpsexec web1 push FILE --sha256 SHA`).
  The next step re-checks the hash on the host before using the file. Get the
  hash with `shasum -a 256 FILE` (or `sha256sum`).
- **A READ-ONLY precheck** first, and verify reads last. They need no
  authorisation; they are in the runbook so they run in order and so the
  reviewer sees them. `vpsexec grant new` lists them as `read: runs without a
  grant`.
- **A rollback tag** before anything changes (step T1 keeps the running image
  under another tag), and **rollback steps** at the end marked
  `rollback: true`. The older spelling, a `why` containing `(rollback only`,
  still works. Grants and the walker skip rollback steps unless asked.
- **`timeout`** (seconds, up to 3600) on slow steps such as image builds.
- **"Stop if"** in a `why` is a walker convention, not a policy key: the walker
  pauses after that step so you read its output before going on.

Commit the file to `policies/` in a reviewed change, then check what loaded:
`./vpsexec runbooks`. Pushing details: [docs/VPSEXEC.md, "Pushing a file"](../docs/VPSEXEC.md#pushing-a-file).

### 6. Mint a grant and walk the runbook

Each break-glass step normally asks you to type `BREAK-GLASS:<n>`. An approval
contract (a grant) replaces that phrase for one runbook's steps, for a bounded
time, and nothing else ([docs/VPSEXEC.md, "Approval contracts"](../docs/VPSEXEC.md#approval-contracts-vpsexec-grant)).

```
contrib/runbook-walker/walk.sh --runbook web-release-example --list
./vpsexec grant new web-release-example --ttl 30m       # preview, writes nothing
contrib/runbook-walker/deploy.sh web-release-example --ttl 30m \
    --reason "shop 1.4.0 release" --artifacts contrib/example-estate/artifacts
```

`deploy.sh` mints the grant (you type `GRANT:web-release-example:30m` once),
then runs `walk.sh`, which:

1. finds every pushed artifact under `--artifacts` by sha256 and stops before
   the first step if one is missing or does not match;
2. runs each step with `vpsexec <hosts> '<cmd>' --run --reason ...`, adding
   `--break-glass --approval-contract=FILE` to `break_glass: true` steps only,
   and `--in NAME` to steps with `container: NAME`;
3. records each finished step, so after an interruption you resume with
   `--from N`, and a finished walk is not re-run by accident;
4. skips rollback steps, and pauses after "Stop if" steps.

To approve each step by typing instead, run `walk.sh` with `--reason` and no
`--grant`. To roll back, run the rollback steps one at a time:
`walk.sh --runbook web-release-example --only 10 --reason "shop 1.4.0 rollback"`.
The grant above does not cover them; type the phrase, or mint a grant with
`--include-rollback`. `walk.sh --help` lists every option; the policies
directory, the `vpsexec` path and the state directory default to this repo and
`~/.local/state/vpscfg-walk`, and each can be overridden by flag or
environment variable.

The walker needs a real terminal for the same reason `vpsexec` does: approvals
and grants are refused without one. Each step's output is journaled;
`./vpsexec last` prints it again.

### 7. Retire the runbook

When the release is done, move the runbook out of `policies/` in a reviewed
commit, so it stops authorising anything:

```
git mv policies/web-release-example.yaml policies/examples/superseded/
```

`policies/examples/` is not loaded, so the file stays in history as a record of
what was authorised. If you forget, it disarms on its `expires` date and
`vpsexec` prints a warning on every run until you retire it.

## Product notes

Places where the example had to work around the tool, kept here so they can
be fixed rather than rediscovered:

- The governor and the policies directory live in the estate root, which is
  this repo unless a pinned `estate.path` file at the repo root names another
  directory by its absolute real path (owned by you, not group/world-writable;
  see `vpscfg/estate.py`). There is deliberately no flag or environment
  variable for it. Pointing it at a copy of `contrib/example-estate/` works;
  copying files into place still does too.
- Fixed since: `Include` in `~/.ssh/config` is followed; a `where: container`
  entry can name its container (`container:`), and the walker builds `--in`
  from it (an entry without the key is still refused by the walker);
  `verify_retry` lets a verify wait for a service to settle; an approval
  contract approves a listed `break_glass: true` step whose hosts need no
  elevation, as a normal mutation; a curl refused for its form says which
  form is a read. The example still checks "container running" in the
  step's verify and the HTTP check in a separate read step, which works
  either way.
