# plays/ — queued multi-step mutations for a human to run with `vpsrun`

The agent writes `plays/<name>.yaml`; the human runs `vpsrun plays/<name>.yaml`
in a real terminal, reads every step's plan, and types one phrase
(`PLAY:<n>:<tag>`, or `PLAY:<n>:BREAK-GLASS:<m>:<tag>`, where the tag is 6 hex of the plans shown). The agent then reads the outcome
with `vpsexec last -n <n>`. Plays are gitignored: they are one-off intent, not
policy. Authority still comes only from `policies/` and `overrides/`.

```yaml
version: 1
reason: "edge1 CNI lease leak: stop the crashlooping deployment"
steps:
  - hosts: edge1
    cmd: "k3s kubectl scale deployment shop-worker -n shop --replicas=0"
    flags: ["--override=overrides/edge1-crashloop-scaledown.yml"]
    why: "shop-worker: stale image, crashlooping"
```

Allowed step flags: `--override=`, `--in=`, `--in-match=`, `--verify=`,
`--break-glass`, `--canary[=N]`, `--timeout=`, `--require-blackout`. A read
step is never planned (plan mode would run it before approval): it runs at its
own position after the phrase, as a plain read with no `--run`, approval or
contract, may carry only `--in=`, `--in-match=` and `--timeout=`, and halts the
play if the door does not report it as tier read.

## Typed-action steps

A step may carry `action:` + `with:` instead of `cmd:` — a typed action from
the closed vocabulary in `docs/ACTIONS.md`:

```yaml
  - hosts: web1
    action: wait_healthy
    with: {container: shop-web, tries: 20, interval: 3}
    why: "H1: wait until shop-web reports healthy"
```

vpsrun hands the door `--action NAME --with JSON`; it never builds the body
itself, exactly as for a plain `cmd:` it never builds the command. An action
step owns its own placement and verify, so it may carry only `--override=`,
`--break-glass`, `--canary[=N]`, `--timeout=` and `--require-blackout` — not
`--in=`, `--in-match=` or `--verify=`. Its tier (read or mutation) is fixed in
code per action, never guessed from text: a `wait_healthy`-shaped read runs in
place after the phrase like any read step; a mutation action is planned and
approved like any mutation step.

A hand-typed `vpscfg-action ...` string in a step's `cmd:` is refused as
reserved — the only way to reach an action is `action:` + `with:` (or
`vpsexec <hosts> --action NAME --with JSON` typed by a human).

### Plan review: a long body is collapsed

`vpsrun plays/NAME.yaml` (and `vpsrun release NAME`) collapse an action
step's body after 15 lines in the plan shown for approval; `--full` shows
every line. The plan-hash — and so what actually runs — covers the whole
body either way; `--full` only changes what scrolls past before you approve.

### Resume: an idempotent action settles itself

A mutation action that declares `idempotent: true` carries its own
"already done?" check. If vpsrun dies mid-step and a host's check had
already reported `VPSCFG-DONE` before the door died, resume settles that
host as `[done]` straight from the door's own record — no SKIP-DONE/RERUN
phrase is asked, because there is nothing to decide. A **retained lock**
still needs a human to run `vpsexec reconcile <host>` first — a check never
releases a lock (docs/ACTIONS.md, S7) — and a non-idempotent action, or one
whose check cannot settle every host, still goes through the unchanged
SKIP-DONE/RERUN prompt described below.

## Prechecks

`precheck: [k3s, firewall]` at the top of a play runs `vpscfg fleet k3s` /
`vpscfg fleet firewall` against every host the play touches, before anything
is planned. Any CRITICAL or HIGH finding refuses the whole play. Plays that
touch netfilter-persistent, reboot a host, or stop/disable k3s or Docker must
declare `precheck: [k3s]` (enforced by tests/test_vpsrun.py).

## Step ids and optional steps

```yaml
  - hosts: db1
    cmd: "psql -At -c 'select owner_report()'"
    id: w9
    why: "W 9: who owns the tables"
  - hosts: db1
    cmd: "psql -c 'alter table t owner to app'"
    when: "w9 reports NOT OWNED"
    why: "W 10: take ownership, only if W 9 found tables we do not own"
```

`when: "<earlier step id> reports <regex>"` runs the step only if that earlier
step's remote output matches; otherwise it is skipped and journaled. The
regex never sees the plan text.

## Resume

Every run has an id and is journaled step by step. After a halt, fix the
cause and run `vpsrun plays/<name>.yaml --resume`: steps whose exact plan
already succeeded in that run are not run again, the failed step and the rest
run. If the failed step is refused only by the door's 5-minute identical-plan
guard, and the earlier attempt was this run's own failed step, vpsrun counts
the window down and retries; another run's identical plan still refuses (and
vpsrun says until when).

A step whose outcome is UNCERTAIN (the door lost contact, or vpsrun was killed
after the step reached the door) refuses the resume and names
`vpsexec reconcile <host>`. After the reconcile: a step reconciled
`COMPLETED rc=0` on every host asks you to type `SKIP-DONE:<play>:<n>` or
`RERUN:<play>:<n>`; one that completed on only some hosts accepts only
`RERUN:<play>:<n>` (it runs again on all of them); any other verdict runs it
again. A step that reached the door and now plans
differently refuses outright. Details: docs/VPSEXEC.md, "Run ids and resume".

## Releases: `releases/<name>.yaml`

```yaml
version: 1
reason: "weekend release: login stage A, inventory rekey"
policies: [login-stage-a.yaml, inventory.yaml]   # for the one reusable grant
grant_ttl: 12h                                    # optional, default 12h
plays:
  - login-stage-a                                 # plays/login-stage-a.yaml
  - play: inventory-rekey
    hold_before: "login dashboard green for 10 minutes?"
on_fail:                                          # printed on a halt, never run
  - runbook: login-rollback.yaml
    step: 2
```

```
vpsexec grant new login-stage-a.yaml,inventory.yaml --kind reusable --ttl 12h --run
vpsrun release weekend            # every plan shown, one phrase: RELEASE:weekend:<n>:<tag>
vpsrun release weekend --resume   # after a halt or a hold
```

A play name is a file in `plays/` (no paths). `hold_before` stops before
that play and asks for `GO:<play>`. Each play runs once per release. At each
play boundary the play is planned again; changed plans need
`REPLAN:<play>:<n>[:BREAK-GLASS:<m>]:<tag>` before any of its steps run.

With no covering grant, vpsrun has the door mint one narrowed to the release
(`--hosts` its break-glass steps' hosts, `--max-uses` their count,
`--for-release <name>` so nothing else auto-picks it); it is revoked when the
release completes. A plain `vpsexec` never spends a grant without `--grant`.
See docs/VPSEXEC.md, **Releases**.

## `vpsrun release new`: scaffolding a release from a runbook

```
vpsrun release new shop-1.5 --from policies/shop-1.5.0.yaml[,policies/other.yaml]
vpsrun release new shop-1.5 --from policies/shop-1.5.0.yaml --replace
```

Writes `plays/shop-1.5-shop-1.5.0.yaml` (one play per `--from` policy) and
`releases/shop-1.5.yaml` from that policy's committed `runbooks:` — every
step, in order, with each `timeout:` carried as `--timeout=N` (an action
step's template timeout when the runbook gives none), `break_glass: true`
carried as `--break-glass`, and a `rollback: true` (or a `why` that says
"rollback only") step left OUT of the play and listed instead under the
release's `on_fail:`. A policy is named in `policies:` and `on_fail:` by its
bare file name (an action policy in `policies/actions/` too; vpsrun looks
there itself). Every value is written as a quoted YAML scalar.

A STOP / probe / precheck / check step (the same words `runbook lint` reads:
uppercase `STOP`, "probe", "precheck", "check" — and lint requires such a
step to be a read that can fail) gets an `id:`. Only an OPTIONAL step (its
`why` says "optional" or "only if") after one gets a `when:` stub naming
that id, with a placeholder regex (`CHANGEME-REVIEW-THIS-CONDITION`) a human
must rewrite or delete. A required step never gets a `when:`, and lint fails
(NO-GO) any play that still carries the placeholder, so a stub can never
silently skip a step.

It never contacts a host, never mints a grant, and never writes under
`policies/`. `--from` must resolve inside `policies/` (including
`policies/actions/`); anything else, or a path that escapes it, is refused.
Without `--replace` it refuses to overwrite a file that already exists, and
it never writes through a symlink (an existing symlink at an output path is
refused; files are created with `O_EXCL|O_NOFOLLOW`). `--replace` rewrites
only a file carrying its own header line — the generator version, the source
policy's sha256 and the sha256 of the file's own body — whose body still
hashes to that value: a hand-written file, a hand-edited one (even under an
intact header), or one from an older generator with no body hash is never
replaced; move the edit into the policy, or delete the file yourself.

It then runs `vpsexec runbook lint` and `vpsexec runbook preflight
--index-only` (never a live host) over the policy and prints one verdict:
GO, GO-WITH-WARNINGS, or NO-GO. The files are written either way — the
verdict says whether they are ready, not whether they get written. For a
`pg_dump` step without `min_free_gb` it also prints ADVICE: the size a fresh
index records for the database x 1.2, as the line to add to the policy.

## Lint on save, and `vpsrun release check`

`vpsrun release NAME` runs `vpsexec runbook lint` and `vpsexec runbook
preflight --index-only` over every policy named in the release's `policies:`
before anything is planned. NO-GO refuses right there, before any phrase — a
stale play (its policy changed since `release new` wrote it, and nobody
re-ran `release new`) is caught this way: lint fails a play step (a `cmd:`,
`push:` or `action:` + `with:`, matched by its canonical string) that is a
mutation and matches no step of the policy or of any other committed policy.
A plain read needs no runbook and is fine. A play counts as the policy's when
any of its steps matches, or when a release that lists the policy runs it. GO-WITH-WARNINGS prints the
warning lines (including anything still MANUAL) above the plan and
continues.

`vpsrun release check NAME` runs the same lint, plus a full preflight (live
where the index cannot answer), and nothing else — read-only, safe for the
agent to run any time:

```
vpsrun release check shop-1.5
```
