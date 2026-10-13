# Repo architecture

```
vpscfg-control.py      the outer door (stdlib-only wrapper; judges + journals + tokens)
vpscfg-control.json    the governor (NOT shipped: it lives in your estate; no governor = every door refuses)
vpscfg/
  control.py           the inner door (independent re-validation; token check;
                       refuses control-path spoofing via env)
  estate.py            where the governor, policies/ and contracts/ live: this
                       checkout, or the one directory a pinned estate.path names
                       (owner/mode-checked, never an env var; see the top-level README)
  gates.py             pure refusal logic: deny-scan, edit-distance volume twin
                       check, freeze — with the DENY_ALWAYS_FLOOR both doors share
  executor.py          contracted deploy/rollback, backup, verification and recovery
  preflight.py         read-only go/no-go before deploy; its journaled GO gates
                       deploy --run (PREFLIGHT.md)
  k3sapply.py          k3s apply mode: schema, content-addressed image ref, fixed
                       commands; executor.py runs them (K3S-APPLY.md)
  translate.py         draft-only compose <-> Deployment translator; fleet translate;
                       never applies (WORKLOAD-DRAFT.md)
  iacgate.py           badfarm static IaC scan of a local path: preflight `iac` check
                       and `fleet iac`; never --repo (PREFLIGHT.md)
  vpsexec.py           separately governed ad-hoc fleet command execution
  actions/             typed actions: typed params, pure expansion, the reserved
                       canonical string, the expands: digest (ACTIONS.md)
  runbookcheck.py      `vpsexec runbook lint|preflight`: runbook checks at authoring
                       time; preflight sends fixed reads only (VPSEXEC.md)
  commandtext.py       preserves literal arguments and command boundaries
  readpolicy.py        positive option grammars for automatic read execution
  cli.py               the vpscfg command grammar: reads → probe, mutations → executor
  probe.py             read-only ssh observation; fixed command strings only
  secretmask.py        masks secret values in remote output before display/journal
  hostindex.py         read-only host index: services, containers, ports, users,
                       postgres/redis/rabbitmq contents, traefik routers (INDEX.md)
  indexstore.py        the index cache (<estate>/index/), diff and query (INDEX.md)
  contracts.py         desired-state loading + validation (sync.never required)
  journal.py           locked, fsynced, hash-chained JSONL; failures block mutation
  lock.py              operation-owned host lock; uncertain/partial deploys retain it
  detach.py            vpsexec mutation steps run detached in /run/vpscfg-ops/<op>/,
                       each in its own process group; re-attach after a drop;
                       evidence for `vpsexec reconcile` (and its --stop)
  gitcmd.py            git as the doors run it: pinned binary, minimal env, no
                       global config or fsmonitor (reusable grants, index cache)
vpsexec                the fleet command door (outer): host groups, tiers, break-glass
vpsrun                 the queue runner: a human approves a queued play once (plays/README.md)
policies/              vpsexec policy files (estate; only README.md ships)
contracts/             one YAML per service (estate)
inventory/             probe snapshots and fingerprint baselines (estate, generated)
index/                 cached host indexes, <host>.json + <host>.prev.json (estate, generated, gitignored)
contrib/example-estate a complete fictional estate to start from
journal/               control.jsonl / executor.jsonl / vpsexec.jsonl (gitignored, machine-local)
tests/                 unit, refusal, concurrency and local filesystem integration tests
```

"Estate" means the files that describe one fleet: the governor, `policies/`,
`contracts/`, `inventory/`, `plays/`. They live in the tool checkout or in the
one directory a pinned `estate.path` names; see the top-level README.

Two-door design: the wrapper and package validate **independently**, each with
its own copy of the deny floor. `vpsexec` carries a third copy. Three copies,
kept identical by tests (`tests/test_control_and_executor.py::FloorSyncTest`
and `tests/test_vpsexec.py::FloorSyncTest`) that fail the build if they ever
drift.

Trust chain: wrapper hashes the policy → passes sha256 as token → package
re-hashes the canonical policy file and compares. Direct invocation (no token)
degrades to read-only. A token with a foreign policy path is refused as spoofing
— found by the test suite on its first run, then pinned as a regression test.

See [RECOVERY.md](RECOVERY.md) for interrupted execution and release checks.

## The docs

| Doc | What |
|---|---|
| [HOWTO.md](HOWTO.md) | Using the contracted-deploy door: reads, preflight, the release ritual |
| [STABILITY.md](STABILITY.md) | The release ratchet: how controls come off, in order |
| [DESIGN.md](DESIGN.md) | The contract → plan → gate → apply → verify pipeline |
| [VPSEXEC.md](VPSEXEC.md) | The fleet command door: tiers, policy, break-glass, grants, push |
| [ACTIONS.md](ACTIONS.md) | Typed actions: the declarative step vocabulary and its contract |
| [MAPFILE.md](MAPFILE.md) | `.vpscfgfarm.map`: a per-directory baseline and leash (tightens only) |
| [PREFLIGHT.md](PREFLIGHT.md) | The read-only go/no-go a deploy must pass first |
| [K3S-APPLY.md](K3S-APPLY.md) | Deploying a k3s workload through the door |
| [SECURITY-TOOLING.md](SECURITY-TOOLING.md) | The read-only watchers: journal chain, change detector, key survey, ... |
| [NO-PASTE.md](NO-PASTE.md) | Closing the loop between an agent and the human who approves |
| [RECOVERY.md](RECOVERY.md) | Interrupted execution, retained locks, release checks |
| [REPAIR-PROTOCOL.md](REPAIR-PROTOCOL.md) | The versioned machine interface for an external repair client |
| [WORKLOAD-DRAFT.md](WORKLOAD-DRAFT.md) | Draft-only compose and Deployment translation |
| [INDEX.md](INDEX.md) | `vpscfg index`: a cached, queryable record of what lives on each host |
