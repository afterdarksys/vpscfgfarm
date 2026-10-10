# vpscfg — Design

> **Thesis.** Don't run commands by hand in prod. Humans make mistakes, AI makes
> mistakes, cats make mistakes, blind humans make mistakes. Robust, contract-based,
> verifiable code protects all of them. The checking lives in the door — vpscfg is
> the only door — and the door does not care who is knocking.

## The model: five stages, no exceptions

Every operation, from `show` to `deploy`, passes through the same pipeline:

```
CONTRACT  →  PLAN  →  GATE  →  APPLY  →  VERIFY
(declared     (diff     (refuse    (execute   (post-conditions
 in git)       vs live)   or allow)  the plan)   or rollback+alert)
```

- **Read operations** stop after PLAN. They are always safe and never prompt.
- **Mutations** require `--run`. Without it, every verb prints the plan and exits.
  (`--show` is the default behavior, not an option you remember to pass.)
- **Destructive operations** (anything on the deny-class list) additionally require
  the module to be explicitly *unfrozen* — two independent switches, like a missile key.

## Contracts

One YAML file per service, in git, in `contracts/`:

```yaml
# contracts/shop-api.yaml
service: shop-api
host: web1                      # must resolve in ~/.ssh/config
deploy_dir: /srv/shop-api
sync:
  include: ["server.js", "routes/", "middleware/", "migrations/"]
  never:   [".env.production", "Dockerfile", "package.json", "package-lock.json"]
  #         ^ the divergences that are LOAD-BEARING are declared, not remembered
build:   "docker compose up -d --build --force-recreate"
freeze:  false
pre:
  - backup: "tar czf /root/{service}-pre-{ts}.tar.gz {deploy_dir}"
verify:
  - http: { url: "https://api.example.com/health", expect: 200, timeout: 10 }
  - http: { url: "https://api.example.com/v1/catalog", expect: 200 }
  - container: { name: "shop-api", state: "healthy", within: "90s" }
blast_radius:
  shares_host_with: "every other service on web1"
  volumes: []                   # names this service may touch; everything else is denied
```

The contract encodes exactly what operators otherwise learn by near-miss: what to sync,
what must never be overwritten, what "healthy" means, and what else lives in the
blast radius. **A new operator (human or AI) with zero context inherits all of it.**

## Gates (the part that saves us)

1. **Deny-classes, enforced in the executor** — not in any operator's tool config:
   `* prune`, `docker volume rm`, `compose down -v`, `DROP …`, `TRUNCATE`,
   `rm -rf` outside the contract's `deploy_dir`, `kubectl delete ns`. The executor
   refuses these even inside an approved `--run`. Overriding requires editing the
   contract in git — which leaves a diff, which is the point.
2. **outage-check** — before any apply, compute blast radius from *observed* state:
   what shares this host, this network, these volumes; is a postgres in the container
   set; is this the only replica. `deploy outage-check --prevent` refuses applies
   whose radius exceeds the contract's declaration.
3. **freeze** — `vpscfg module <svc> --freeze` writes a lock into the contract.
   Frozen modules refuse all mutation regardless of flags. Unfreezing is a git commit.
4. **Volume name-distance check** — any operation naming a volume within edit-distance 1
   of a live volume on that host halts and demands the exact name typed in full.
   (`shop_postgres-data` vs `shop_postgres_data` — never again.)

## Preflight (deploys have pre-conditions too)

`vpscfg <host> deploy <svc> --preflight` is the GATE stage run as one read-only
report: contract lint, governor posture, sync dry-run, three-way drift, outage,
a **health baseline** (the verify block, run *before* the deploy), backup
readiness, ports, unjournaled changes, capacity, maintenance window, allowlisted
deployability checks and ansible check mode. It returns GO / GO-WITH-WARNINGS /
NO-GO. `deploy --run` refuses without a fresh GO for the same plan hash,
checked again under the host lock. See [PREFLIGHT.md](PREFLIGHT.md) for what
each check proves and what it does not.

## Verify (deploys have post-conditions now)

After every apply, the contract's `verify` block runs. Failure triggers rollback from
the `pre` backup where possible, and always alerts. Separately, `vpscfg fleet watch`
sweeps all contracts' verify blocks on a schedule — **a service that has been quietly
failing its health check is caught on day 0, not day 70.**

## Journal

Every PLAN and APPLY appends to `journal/` (hash-chained JSONL, local to the tool
checkout and gitignored): timestamp, operator, host, service, plan diff, result,
verify outcome. It can optionally be mirrored to a telemetry endpoint the governor
names (off unless configured), so "what changed on web1 this week?" is a query.

## Inventory: a query, not a registry

vpscfg does **not** create a new inventory store. It joins the ones that exist:

| Source | Provides |
|---|---|
| `~/.ssh/config` | The host list (the operator's source of truth) |
| DNS zones | name→host mapping, what *should* resolve |
| Live probe (ssh, read-only) | containers, k3s ns/pods, /opt, versions |
| An optional telemetry API (configured in the governor; off by default) | persisted observations |
| `contracts/` | desired state |

`show`/`details`/`drift` are joins across these. Drift = git ↔ contract ↔ live,
three-way. A hand-patched dependency on the host becomes `vpscfg web1 drift shop-api`
→ one line of red.

## Command sketch → model (the TODO's CLI survives intact)

| Sketch | Pipeline stage |
|---|---|
| `vpscfg <host> show/details/containers/services/overlays` | PLAN (read-only join) |
| `vpscfg <host> ansible <playbook> --show/--run` | ansible `--check --diff` / apply, behind the same gates |
| `vpscfg <host> deploy --test/--run` | full pipeline; `--test` stops after GATE |
| `vpscfg <host> deploy outage-check --show/--prevent` | GATE stage exposed directly |
| `vpscfg module dir= --register/--freeze` | contract create / lock |
| `vpscfg module sync <host>` | APPLY (sync per contract's include/never lists) |

## Implementation (stated default, overridable)

**Python 3.11+** — ansible is Python-native, iteration is fast, and rich/typer give a
good CLI cheaply. Contracts are YAML and the journal is JSONL, so a later Go rewrite
(single static binary per host) changes nothing about the data. Ansible drives
host-level mutation (packages, files, users); docker/k3s operations go through vpscfg's
own executors — both behind the same GATE layer. It is meant to sit beside the
inventory, monitoring and maintenance-window tools an estate already has (a
maintenance window becomes a GATE input), not replace them.

## What a contract layer surfaces

Writing contracts for a real estate tends to turn up the same classes of problem.
Each one has a place in the model:

1. **Uncontracted deploy paths.** An auto-updater pulling `:latest` is a deploy
   with no plan and no journal. Bring it under contract or remove it.
2. **Secrets that exist only on the host.** If every credential lives in a host's
   `.env.production`, the host is not disposable. Declare those files in
   `sync.never` so nothing overwrites them, and plan to source them from a
   secrets store.
3. **Unverified DR.** A `verify:` block for replication lag turns "we have DR"
   from a hope into a checked invariant.
4. **Duplicate deployments** need an authority declaration in contracts, then
   decommission of the loser, or both drift forever.
5. **OS lifecycle.** End-of-life operating systems belong in the contract too
   (`host_os: ..., eol: true` should make `fleet watch` nag).
6. **Key hygiene is inventory hygiene.** A host that cannot be probed cannot be
   protected.
7. **No staging.** `--test` against production is still production. The
   cheapest viable staging is a scratch project on a `test`-posture host.
8. **Untested restore.** An unrestorable backup is a feeling, not a backup.
9. **Port allocation as tribal knowledge.** Contracts should declare ports; the
   GATE should catch collisions.
10. **DNS is config too.** Hand-synced zones deserve the same
    contract/plan/apply/verify treatment as services.
