# HOWTO

## Today (v0 — observation only)

```
./vpscfg-control.py status                  # governor state: mode, postures, scopes
./vpscfg-control.py web1 containers         # live docker ps (read-only)
./vpscfg-control.py db1 overlays            # k3s namespaces
./vpscfg-control.py edge1 details           # host identity/os/uptime
./vpscfg-control.py web1 deploy x --run     # REFUSED — and journaled. Try it.
```

Every invocation lands in `journal/control.jsonl` — allowed and refused alike.
Refusals exit 2 with the reason on stderr.

**Note:** even read probes reach production hosts over ssh. v0's probes are fixed
command strings (no operator input interpolated), but treat first runs with the
same care as any new code touching prod: one host, watched.

## Before any deploy: preflight

```
./vpscfg-control.py edge1 deploy shop-proxy --preflight          # GO=0 / warnings=1 / NO-GO=2
./vpscfg-control.py edge1 deploy shop-proxy --preflight --json   # machine-readable
./vpscfg-control.py edge1 deploy shop-proxy --run --reason "why" # only within 30 min of a GO
```

Read-only. `--run` refuses unless the latest preflight for the *same* plan
(contract + sync argv + source bytes) was GO or GO-WITH-WARNINGS in the last 30
minutes. If the service is already failing, the preflight is NO-GO. For a
repair deploy, add `--allow-unhealthy-baseline --reason "..."`, which is
journaled. Optional contract knobs (`preflight:`, `migrations:`, `playbook:`)
are documented in [PREFLIGHT.md](PREFLIGHT.md).

## Writing a contract

Start from the example contract in [DESIGN.md](DESIGN.md#contracts). The parts that matter:

- `sync.never` — REQUIRED. The host files that must never be overwritten from
  git (`.env.production`, host Dockerfiles). The validator refuses contracts
  without it: load-bearing divergence must be declared, not remembered.
- `verify` — what "it worked" means, checked after every future apply.
- `freeze: true` — hard lock. Unfreezing is a git commit, not a flag.

## Releasing a control (the ritual — see STABILITY.md for the full ratchet)

1. Pick ONE scope, smallest first: `container:edge1/<name>`.
2. Test it end-to-end with the mutation you intend. Verify. Record the result
   in `vpscfg-control.json` → `scopes.tested` with `result: pass`.
3. Add the scope to `scopes.unlocked`, set the host posture and mode as the
   ratchet allows. One scope per commit. Say why in the commit message.
4. The executor STILL refuses until the firing pin lands (its own reviewed
   commit, `vpscfg/executor.py`, marked block).

## What can never be released

The `deny_always` floor (prune/volume rm/DROP/TRUNCATE/`rm -rf /`…) is compiled
into BOTH doors. Deleting entries from the JSON is detected as tampering and
refuses everything. That's not a bug in your workflow; it's the point.

## More verbs

- `vpscfg lint` — contract quality floor: TODOs, missing http verify, empty
  include/blast-radius. Errors exit 1; warnings inform.
- Rename includes — `sync.include` entries may be `{src, dest}` (file-level
  only). syncplan issues a dedicated transfer per rename; drift hashes src
  under the dest name.
- `vpscfg <host> ansible <playbook> --show` — check+diff through a pinned
  ansible-core 2.15 in `.venv-ansible/` (older managed hosts' Python
  refuses newer ansible-core). `--run` still refused in v0.
- Scheduled fleet watch — `tools/install-fleetwatch.sh` installs a launchd
  agent (600s) on macOS. On failures: a macOS notification, plus a
  best-effort telemetry event if telemetry is configured. Log:
  `journal/watch-cron.log`.
- Journal → telemetry (optional, off by default) — when the governor names a
  telemetry endpoint and a key is available, every journal.append also POSTs
  the record to it. Local JSONL stays authoritative; push failures are
  swallowed, and `vpsexec last` says plainly when entries are local only.
- `tools/traefik_verify.py` — when the governor names a Traefik file-provider
  path (optional, off by default), parses that file on the host (read-only
  probe) and injects real `http:` verify entries into matching contract
  skeletons (`--apply`). Real contracts are never auto-edited.
