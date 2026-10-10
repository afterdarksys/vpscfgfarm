# STABILITY — the release ratchet

The scaffold ships maximally locked. Controls come off in this order, each step
gated on the one before it, each step ONE git commit with test evidence.

## Stage 0 — now (v0)
- mode: lockdown; mutation_enabled: false; scopes.unlocked: []
- executor: NO FIRING PIN. All-gates-green still refuses (pinned by test).
- Allowed: read-only probes, status, plans.

## Stage 1 — read verification in anger
- Run every read verb against every reachable host. Fix probe bugs.
- Exit criteria: `show/containers/services/overlays/details` clean on
  every reachable host; journal shows the runs.

## Stage 2 — first mutation, container scope, on the test host
- Pick one designated test host: the one with the lowest blast radius
  (`edge1` in the example estate).
- Choose ONE disposable container. Write its contract. Set:
  mode: test, mutation_enabled: true, hosts.edge1.posture: test,
  scopes.unlocked: ["container:edge1/<name>"], and add the tested record.
- Install the firing pin (executor.py marked block) in its OWN commit.
- Deploy it. Verify block must pass. Roll back from the pre-backup to prove
  rollback works. Record both results in scopes.tested.

## Stage 3 — pod scope (k3s), test host first
- Same ritual, one namespace at a time. cert-manager and kube-* are frozen forever.
- Mechanism: `apply: {mode: k3s}` contracts (scope_kind `pod`). The step-by-step
  ritual is in [K3S-APPLY.md](K3S-APPLY.md) §Stage 3.

## Stage 4 — service scope on lockdown hosts
- One contracted service per lockdown host, posture test → supervised.

## Stage 5 — host scope
- Only after every service on that host has a contract.
- The host with no failover (`web1` in the example) stays `frozen` until every
  other host has completed Stage 4 AND its DR story (replication, restore) is
  answered and verified.
- DNS servers stay frozen until DNS zones are under contract (plan/apply/verify).

## Never
- The deny_always floor. Both doors carry it compiled-in; the JSON can add
  entries but any removal is tampering and refuses everything.
- Unjournaled mutations. Can't write the journal ⇒ can't mutate.
- Free-form remote shell through the executor. Commands come from contract
  fields only. This survives `vpsexec`: ad-hoc commands go through
  a SEPARATE door with its own gate stack, and no operator string ever reaches
  `vpscfg/executor.py`. If you ever find yourself routing one there, stop —
  that is the invariant this line exists to protect. See `docs/VPSEXEC.md`.
- Lifting the deny-always floor with an override file. `--override` reaches
  tier 2 only; an override that names a floor pattern rejects the whole file.

## Rollback of the ratchet itself
Any incident ⇒ revert the unlock commit. That single revert restores lockdown
for the affected scope; the journal shows exactly what ran in the window.
