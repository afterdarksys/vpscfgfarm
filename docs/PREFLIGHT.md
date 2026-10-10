# PREFLIGHT — the pre-deployment go/no-go

```
vpscfg <host> deploy <service> --preflight [--json]
vpscfg <host> deploy <service> --preflight --allow-unhealthy-baseline --reason "repair: crashloop since 02:00"
vpscfg deploy --preflight            # verb-first, from a mapped directory
```

One report answers two questions before anything is mutated:

1. **Is this plan safe and deployable?**
2. **Will it break the service that is working right now?**

It ends in exactly one verdict:

| Verdict | Exit | Meaning |
|---|---|---|
| `GO` | 0 | every check passed or was not applicable (`skip`) |
| `GO-WITH-WARNINGS` | 1 | at least one `warn`, no `fail`/`error` — deployable, read the warnings |
| `NO-GO` | 2 | at least one `fail` **or `error`** — a probe that could not answer is never a pass |

`--json` prints the same report as one object: `verdict`, `exit_code`,
`plan_hash`, `counts`, `recorded`, `allow_unhealthy_baseline`, and `checks[]`,
each with `name`, `status` (`pass|warn|fail|skip|error`), `evidence`, and for
the baseline `data` (the individual verify results).

**Read-only end to end.** Remote commands are fixed templates, and validated
paths are shell-quoted. Every command is deny-scanned against the floor
before it is sent. Local commands are allowlisted in code: `rsync` only with
`--dry-run` and `ansible-playbook` only with `--check`. The `git log/show`
history lookup reads the object store only. The one write is the local
journal record. The outer door already classifies `deploy` without `--run`
as a read. `--preflight` combined with `--run` is refused.

## The gate: `deploy --run` needs a fresh GO for the same plan

Every preflight appends a record to the hash-chained `preflight` journal
stream. The record is keyed by a **plan hash**: sha256 over the parsed
contract, the exact sync argv, the mode and sha256 of every file under the
include list (including `__pycache__`, since rsync would carry it), the host
and the service. `deploy <svc> --run` refuses unless the **most recent**
preflight for that exact plan hash:

- had the verdict `GO` or `GO-WITH-WARNINGS`,
- is at most **30 minutes** old (records dated in the future are refused),
- sits in a preflight journal whose hash chain verifies,
- **has not already been used**. A GO is single-use: the gate records
  `deploy_gate_passed` with a per-run token. The re-check under the lock
  accepts only that same token. A second `--run` needs a new preflight. For
  example, after a failed first deploy, the new preflight runs against the
  service's *current* health, not the healthy baseline of the old GO.

The check runs twice. It runs first in the CLI, before the executor, so a
refusal comes fast and is journaled as `deploy_gate_refused`. It runs again
inside the executor, **under the host lock**, via its existing `preflight=`
hook. That second check closes the gap between checking and locking: a
source edit made after the first check still refuses the deploy.

There is no escape hatch. If the record is stale, missing, NO-GO or for a
different plan, the fix is to run `--preflight` again. When the contract,
the include list or any source file changes, the plan hash changes, so the
earlier GO no longer applies.

Scope: the gate covers `deploy --run`. It does **not** cover `rollback --run`,
because recovery must not depend on a healthy baseline. It also does not cover
the goodfarm repair protocol (`--repair-action`), which has its own live
preflight bound into a single-use approval digest (REPAIR-PROTOCOL.md).

## The checks — what each proves, and what it does NOT

| Check | fail (NO-GO) | warn | Does NOT prove |
|---|---|---|---|
| `contract` | `lint.py` errors; a planned command hits the deny floor | lint warnings (TODOs, no http verify, …) | that the contract describes the service correctly — lint is a floor, not a review |
| `posture` | contract frozen; governor refuses deploy for this host/scope (master switch, lockdown, posture, ungraduated scope) | — | anything about the wrapper token: preflight is a read, and `--run` must still come through `vpscfg-control.py` (a note says so when run outside it) |
| `plan` | the plan hash cannot be computed (missing repo, invalid include) | — | — |
| `sync_plan` | `rsync --dry-run` itemizes a `sync.never` path, or a declared input is missing or escapes the source root | — | what the new bytes *do*; it lists the files that would change |
| `drift` | a synced file on the host has an md5 that matches **no** committed git revision (the newest 50), so someone changed it outside the door and deploying would overwrite it; a declared include is missing in git. `error` when the remote md5sum fails for any reason other than "No such file", or when the repo is not a git repo | same finding when the contract says `preflight.drift: warn`; the file list was truncated | anything inside `sync.never` (expected divergence), or any file outside the include list. A host file equal to an *old* revision counts as "behind git" and passes: this deploy moves it forward |
| `outage` | `outage.assess` says PREVENT (volume twin, blast radius over `max_other_containers`), or the live observation failed | findings such as databases present or no failover (the shared-host count is informational) | that the other containers survive the build; it measures the blast radius and does not simulate it |
| `baseline` | the contract's `verify` block fails **now** | the same, when `--allow-unhealthy-baseline --reason` was given (journaled) | health beyond what `verify` asks. A weak verify block gives a weak baseline |
| `backup` | the contract has no `pre` backup step (the executor would refuse anyway); **`migrations:` declared and no verified backup** | the latest prior backup is missing or unverifiable (the deploy still takes and readability-checks a fresh one) | that the backup holds the *right* state. Only a restore drill proves that (DESIGN item 8) |
| `ports` | one of this service's declared ports collides with another contract on this host | a declared port has no listener | reachability (the check reads bind state, not firewalls), or binds that happen after the probe |
| `fingerprint` | — | a container or pod changed since the baseline with **zero** journaled mutations on this host (prod was changed outside the doors) | changes inside a running container (`docker cp`). `skip` when the host has no baseline |
| `capacity` | free space on `/` or on `deploy_dir`'s filesystem is below `min_free_gb`; `MemAvailable` is below `min_free_mem_mb` | — | peak usage during the build; image pulls can need far more than the threshold |
| `blackout` | — (never) | window status unknown (the tool is unavailable) | anything; windows inform and never grant |
| `deployability:compose_config` | `docker compose -f <deploy_dir>/<file> config -q` fails on the host | — | runtime behaviour; it validates syntax and interpolation only, against the host's **current** compose file, *before* the sync |
| `deployability:nginx_test` | `nginx -t` (or `docker exec <container> nginx -t`) fails | — | that the new config is valid, since it tests what is on the host now. Host-level `nginx -t` may create a missing log or pid file; prefer the `{container: …}` form |
| `ansible` | `ansible-playbook --check --diff` exits non-zero; **any YAML under `playbooks/` uses a construct that runs even under `--check`** (`check_mode: false`, `always_run`, `local_action`, `delegate_to`, `pipe`). In that case ansible is not run at all | — | **Check mode skips `command`/`shell` tasks** and cannot predict tasks that depend on earlier changes. A clean check is necessary, not sufficient. `skip` when there is no `playbook:` |

Any check that raises a transport or parse error becomes `error`, and the
verdict becomes NO-GO. The exception is the blackout tool: its documented
behaviour is that information fails open, so an unknown window is a `warn`.

## Honest limits

- **A GO is not a guarantee.** There is no staging (DESIGN item 7). The
  preflight observes production and checks it; it does not rehearse the
  deploy.
- Live state can change between the preflight and `--run`. The 30-minute
  window bounds that gap. The executor's own live outage gate and the
  post-deploy verify and rollback still apply; the preflight replaces
  neither.
- The gate hashes the working tree under the lock, and the executor's rsync
  reads it again moments later. An edit made in that gap is not bound. Do not
  edit the source tree while a deploy runs.
- The backup check streams the whole latest archive (read-only, capped at
  16 GiB). On a large service this is the slow part.
- The journal is local. An actor with write access to `journal/` can forge a
  GO record. The hash chain makes that detectable after the fact; it does not
  make it impossible.

## Contract schema

```yaml
preflight:                 # optional; every key optional
  min_free_gb: 2           # default 2   — "/" and deploy_dir's filesystem
  min_free_mem_mb: 256     # default 256 — MemAvailable
  drift: fail              # fail (default) | warn — unexplained live divergence
  checks:                  # NAMED checks from a fixed allowlist, never commands
    compose_config: true   #   or {file: docker-compose.prod.yml} (relpath under deploy_dir)
    nginx_test: true       #   or {container: edge-nginx}
migrations:
  irreversible: true       # exactly this key, boolean
playbook: baseline         # optional: playbooks/<name>.yml, run in check mode as evidence
```

Validation happens when the contract loads, so a bad block refuses the whole
contract. That covers an unknown key under `preflight`, a check name outside
`{compose_config, nginx_test}`, or a check given as a string, which would
amount to a command. Two examples that refuse the contract:

```yaml
preflight: {checks: {shell: "curl … | sh"}}               # refused: not in the allowlist
preflight: {checks: {compose_config: "docker compose up"}} # refused: a string is a command
```

k3s contracts (`apply: {mode: k3s}`) swap the file-sync checks for live
Deployment state; see [K3S-APPLY.md](K3S-APPLY.md).

The maintenance-window input reads a JSON export of active maintenance
windows, as written by an external `blackout` maintenance-window tool. The
governor names it (`integrations.blackout.file`, an absolute path); no
environment variable can. Nothing in this repository produces that file.
Unset, missing, stale (older than 15 minutes) or unreadable, the check says
"unknown".

Implementation: `vpscfg/preflight.py`. Tests: `tests/test_preflight.py`
(hermetic: every transport is injected, and no test dials a host).
