# Interrupted execution and release checks

## Normal execution

Deployments require a nonempty verification block, present declared source
inputs, and a pre-change backup. The archive is checked before sync. Container
checks honor their `within` deadlines. Success requires verification, a clean
checksum-based sync rehearsal, and release of the owning operation's host lock.

The local journal serializes writers and synchronizes each append and directory
entry before returning. Telemetry remains best-effort: a successful local write
does not promise replication. Preserve the controller's `journal/` directory and
repair SQLite database with appropriate access controls and backups.

## When a lock is retained

The executor retains `/run/vpscfg.lock` after a partial deployment, failed
restoration, or unknown remote outcome. A stopped SSH client does not prove that
a remote build stopped. Neither lock age nor a fresh operation ID makes it safe
to continue.

`vpsexec` runs every mutation step **detached** on the host (`systemd-run`
with `KillMode=mixed`; `setsid nohup` only on a host the governor lists in
`allow_unmanaged_steps`), writing stdout, stderr and the
exit code to `/run/vpscfg-ops/<operation id>/`. The step itself runs in its own
process group (`setsid`, else `perl` setpgrp; a host with neither never runs
it: rc 125), so a stop reaches every process it started. A dropped SSH session
no longer decides anything: the door re-attaches with backoff until the step's
timeout and reads the real exit code. It retains the lock only when it cannot
reach the host for the whole timeout, or the step outlives its timeout.
Details (the `dd` log reader, LOG_GRACE, rc 125/143): docs/VPSEXEC.md,
"Detached steps".

### The sanctioned path: `vpsexec reconcile HOST`

When a lock is retained, a play halts and prints the exact command. A human
runs it in a real terminal:

```
vpsexec reconcile web1
```

It reads, and prints as evidence: the lock owner (operator, reason, operation
id), every step's exit code and log tail from the op dir, whether the step's
unit, its runner or any process in the step's process group is still alive,
any process naming the op dir, this controller's journal record of the
operation, and the result of the runbook entry's `verify` (run as a read).
For a typed action, the verify is re-expanded by this door from the journaled
canonical string and run through the same gate and runner as a run: a SQL
check in its read-only session, a token-only check (`ensure_secret`) with its
output withheld (only the token or "output withheld" is shown). A verify that
is not a plain read, or an action this door can no longer expand, is shown as
"not run" — it is evidence, never a reason to abort: the verdict and the
phrase below still apply. Then the verdict:

| Verdict | Meaning | What happens |
|---|---|---|
| `COMPLETED rc=N` | exit file present, nothing running | asks for the phrase |
| `STILL RUNNING` | unit, runner, op-dir process, or ANY process left in the step's process group alive | refuses; nothing to do yet (or stop it: `--stop`, below) |
| `UNKNOWN` | no exit file, nothing running (or no op dir at all) | asks for the phrase; read the evidence first |

The phrase is `RECONCILE:<host>:<first 8 of the operation id>`; pending
keystrokes are flushed before the prompt. After the phrase the op is inspected
again; the lock is removed only if its owner and token are still byte-identical
to what was read, in the same remote command, which also removes the op dir.
The evidence is journaled (`reconcile_attempt`) before the lock is touched, and
`reconciled` after.

What it can and cannot prove. It refuses a lock whose operation is visibly
running on the host (a live unit, runner, op-dir process, or any process left
in the step's own process group), and a lock whose controller — recorded in
the lock owner as `controller: {host, pid, started}`, `started` being that
process's own start time — is THIS machine with that pid alive AND started at
that time, whatever the journal says (a running `vpscfg deploy` journals no
vpsexec attempt). The same pid number on a process that started at another
time is a recycled pid: the controller is dead. A malformed controller field,
a live pid whose start time cannot be read, or a `started: null` (the door
could not read its own start time, and never guesses one), counts as alive. It never
releases a different operation's lock. A step whose group leader's pid now
belongs to a process with another start time (recorded at launch in
`<i>.cstart`) is reported UNKNOWN and is never signalled. It **cannot** prove
that nothing runs for a lock with no op dir (taken by `vpscfg deploy`, a push,
or a door from before detached steps), for a process a step started in a
session of its own on a host without systemd (a daemon that called setsid
itself — such hosts run detached steps only if the governor lists them in
`allow_unmanaged_steps`, accepting exactly that), or for a controller on
another machine;
for a lock with no op dir it therefore also refuses until the lock is at least
**7200 s** old — twice the longest step any lock holder may run (the larger of
the 3600 s runbook timeout cap, the executor's 1800 s step cap and the 900 s
k3s rollout cap + 60 s) — and says so. UNKNOWN remains a human judgment made
with the evidence in front of you.

`vpsexec reconcile <host> --stop` stops a STILL RUNNING operation: TTY only,
phrase `STOP:<host>:<op8>`, journaled before (`reconcile_stop_attempt`) and
after (`reconcile_stopped`). It sends TERM to every process of the step's
systemd unit (units are also bounded by `RuntimeMaxSec` = the step's timeout +
60 s, and `KillMode=mixed` kills whatever is left), to the step's whole process
group when its leader is alive with the start time recorded at launch, and to
the runner if its argv still names the op dir. It **refuses, signalling
nothing**, when a step's group cannot be proven to be the step's: its leader's
pid now belongs to a process started at another time (REUSED), or its leader is
gone while members of the group remain (LEADERLESS). It then names the group;
act by hand on the host (`ps -o pid,pgid,lstart,args -g <pgid>`, end what
belongs to the operation) and reconcile. It releases nothing; afterwards run
`vpsexec reconcile <host>` as usual. A leaderless group is signalled only when
every member proves it is the step's, from Linux `/proc`: it is in the session
the step's `setsid` created, started no earlier than the leader, AND carries
the step's tag `VPSCFG_OP=<op>.<i>` (set by the runner, inherited by every
process of the step) in its environment. Session and start time alone are
not proof — a reused group can pass both. A member without the tag, or off
Linux, refuses.

On a systemd host that the governor has not listed in `allow_unmanaged_steps`,
a failing `systemd-run` never falls back to `setsid`/`nohup`: the step is
fenced (it can no longer start), the door says "systemd-run failed … NOT
started", and the lock is released. If the step's single-run guard was
already taken by an earlier fence or launch and no runner is recorded, the
launch says `VPSCFG-FENCED-BY-OTHER`: the outcome is UNKNOWN and the lock
stays for `vpsexec reconcile`.

If the lost step belonged to a `vpsrun` play or release, `vpsrun … --resume`
refuses that step until each of its hosts is settled: by a `reconciled` (or
`reconcile_free`) record, or — in a multi-host attempt where the door died
mid-way — by the door's own `host_done` record for that host. The door writes
`host_done` (rc, verify rc, operation id, and the attempt's reason and plan
hash) only after that host's every step, its verify AND its lock release; a
per-step record is never enough, because the door may have died between
container steps or during the verify with the lock still held. Resume accepts
only a `host_done` that carries this attempt's reason and plan hash and comes
before the next attempt on that host — never a later, unrelated operation's —
and a `reconciled` record for the operation outranks it. A host whose
operation is known but whose lock a reconcile found free with no `host_done`
(the door released it and died before writing that record) is settled as
"released by the door, outcome unknown": it is not completed, so the step runs
again (never SKIP-DONE). Then:

- completed (rc 0, verify passed or none) on every host: type
  `SKIP-DONE:<play>:<n>` (count it done) or `RERUN:<play>:<n>`. The prompt
  names, per host, what it rests on — "reconciled COMPLETED rc=0" only where a
  reconcile actually ran, "finished by the door (host_done rc=0)" otherwise —
  and the journal records `settled_from: reconcile|door|door+reconcile`;
- completed on some hosts only: only `RERUN:<play>:<n>` is accepted, and the
  step runs again on all its hosts — the prompt names the completed ones;
  otherwise nothing runs (finish the rest by hand and start a fresh run);
- completed nowhere: it runs again through the door, never counted as done.

See docs/VPSEXEC.md, "Run ids and resume". A step that reached the door and
now plans differently refuses the resume outright.
It requires the master switch on and mode not lockdown, but not posture: the
lock is the door's own bookkeeping, and break-glass is what took it.

A lock with **no op dir** (taken by `vpscfg deploy`, a `push`, or a door from
before detached steps) reports `UNKNOWN` with a warning: whether its work still
runs is not provable by the tool, so follow the manual steps below before
typing the phrase (and it cannot be released before it is 7200 s old). There is
still no automatic stale-lock expiry: a lock is released only by a human, with
the evidence in front of them.

### Manual reconciliation (no op dir, or the evidence does not settle it)

1. Inspect `./vpsexec locks HOST` and the executor journal. Record the operation
   identifier, reason, current backup, last completed step, and affected service.
   For goodfarm, also retrieve the existing repair receipt with its operation ID.
2. Establish whether the original controller and remote process are still
   running. Reconnect for read-only observation. If completion cannot be proved,
   leave the lock held and escalate to the responsible operator.
3. Inspect service health, deployment files, and the exact archive from this
   operation. A restore-health pass is not proof of complete rollback: newly
   introduced files can remain after tar extraction. Preserve `sync.never` paths
   and assess database state separately from application files.
4. Prepare a service-specific recovery plan. The responsible operator must
   reconcile partial files and any continuing processes, then release the lock
   with `vpsexec reconcile HOST` (above), which records the evidence. There is
   intentionally no automatic stale-lock expiry and no unconditional
   force-unlock; do not broadly unlock governor scopes to work around it.
5. Confirm the owner operation still matches the investigated incident before
   removing its lock. Record who reconciled it and what proved it safe. Use a new
   reviewed operation for subsequent deployment; never discard repair receipts
   or reuse a consumed approval.

If journal writes fail, mutation must stop. Restore storage availability first.
An incomplete final record refuses future appends; preserve the original stream
and reconcile it with operation receipts and host state before repairing it.
Never silently truncate history to make chain verification green.

## Reusable grants need the policy remote

A reusable grant is bound to policy PUSHED to the governor's `policy_remote`
(default `origin/main`) at the remote URL recorded at mint: it fetches that
URL at mint and at every use — into a private scratch repository, never
reading the policy repository's own git config (your global config is
trusted for credentials; a global `insteadOf` that rewrites the bound URL
refuses; only https and ssh are allowed) — and refuses on
a fetch failure, no network, a missing remote, a changed remote URL, a
force-pushed branch, or a scope file whose bytes are not pushed. **Outage
note:** when the remote (GitHub) is unreachable, use a short grant
(`vpsexec grant new <runbook> --ttl 1h --run`) or an incident — neither
fetches. **Pushed is not reviewed** unless the remote branch is protected to
require pull-request review; enable that protection on the policy branch.

## Customer outage on a frozen host

When the fix is a command no committed break_glass runbook names, do not reach
for raw ssh. Open an incident (see "Incident override" in `docs/VPSEXEC.md`):

1. **Open**, in your own terminal, naming only the hosts you need, for the
   shortest window that will do:
   `vpsexec incident open --hosts web1 --ttl 1h --reason "OUTAGE-123 checkout down"`
   and type `INCIDENT:web1:1h`.
2. **Read first.** Reads need no incident: `vpsexec web1 'journalctl -u redis -n 200'`.
3. **Fix**, one command at a time, each with its own reason, and type
   `GO:<host>` (for several hosts `GO:<first 6 of the plan-hash>`; the prompt
   shows it):
   `vpsexec web1 'systemctl restart redis' --break-glass --incident ic_... --run --reason "redis wedged" --verify 'systemctl is-active redis'`.
   The floor, `deny_extra`, the map, the lock and the journal still apply; a
   refusal there is not something an incident can lift.
4. **Need more time or another host?** Open a new incident. There is no extend.
5. **Close** as soon as the customer is back: `vpsexec incident close ic_...`,
   type `CLOSE:ic_<first 8 hex>`. Read the report it prints.
6. **Backfill** the same day. Copy the draft from
   `journal/incidents/ic_....md` into a `policies/*.yaml` change, set `expires`,
   `shape` and `verify`, drop the one-offs, and send it for review, so the next
   outage of this shape is a lookup again.

## Command compatibility

Automatic reads now use a positive option grammar. Unknown options, custom
executable paths (including `./cat`), git commands, wget, and kubectl diff require
mutation authorization. Curl observations require `-q` first (for example,
`curl -qsf localhost/health`) to disable user configuration that can write or
upload. Documented named read plays continue to use the normal gate stack.

Quoted argument whitespace and newlines are preserved. Variable expansion,
unquoted globs/brace expansion, and command substitution are refused. For file
matching use a quoted pattern with find, such as `find /var/log -name '*.log'`.
Equivalent literal spellings of forbidden
operations are refused too. Plan hash version 2 invalidates approvals produced
by the older command grammar. Regenerate plans after upgrading.

These gates assume trusted host binaries, configuration, and reviewed scripts.
They do not sandbox root or prove the runtime behavior of arbitrary programs.
The deny floor applies to inspectable command operations; a reviewed script's
contents still require review.

## Release validation

Local/CI checks:

- Install `requirements.txt` with `--require-hashes` into an isolated environment.
- Run the full unittest suite with no skips on the supported Python matrix.
- Run the production-safety tripwires. These exercise real local rsync/tar,
  multiprocessing journal writes, lock ownership, transport failures, and fake
  clock health polling without contacting fleet hosts.
- Review the final diff and scan source for secrets; keep the governor's existing
  released scopes unchanged during rollout of the controller fixes.

Before increasing released scopes, run a controlled scratch-host drill using a
disposable service: successful deploy; slow startup; partial sync; failed build;
lost SSH session while work continues; competing operation refusal; archive
restoration; and explicit lock reconciliation. Check both the receipt and the
actual host state. Local tests are not evidence that a production service's
backup includes its database or that its health checks cover every failure mode.
The detached-step half of that drill (lost SSH, timeout, competing operation,
retained-lock reconcile and `--stop`) is now automated: see "The automated
detach drill" below, and run it after every release of the tool, before
widening `drill_hosts` or any released scope.

## The automated detach drill: `vpscfg drill detach`

`vpscfg drill detach <host>` re-proves the detached-step guarantees above
(`vpscfg/detach.py`, `vpscfg/lock.py`, `vpsexec reconcile`) on a real host,
instead of the hand-run steps this chapter used to require. It is the
automated form of the "controlled scratch-host drill using a disposable
service" called for under "Release validation": run it after every release
of the tool, before increasing released scopes.

```
vpscfg drill detach edge1                             # plan only: lists the 8
                                                        # scenarios, contacts nothing
vpscfg drill detach edge1 --run --reason "post-release drill"
```

**Opt-in is two independent switches, both required, checked before any host
is contacted.** The host's governor posture — read from its CANONICAL name;
an alias resolves to its target first, so naming a frozen host's alias cannot
launder it — must be `test`, and the canonical name must appear in a new
governor key:

```json
"drill_hosts": ["edge1"]
```

Anything else — frozen, lockdown, released, a `test` host missing from
`drill_hosts`, an alias of a frozen host, or `drill_hosts` absent entirely —
refuses before any dial. The drill never uses `--break-glass` and never opens
an incident; it is an ordinary governed mutation (master switch, mode,
`--reason`, the verified-token requirement) scoped by posture and
`drill_hosts` alone.

Each of the 8 scenarios runs as a disposable unit, built only from
`sleep`/`true`/`false`/`test`/`while`/`done` and a file under
`/tmp/vpscfg-drill-*` — never from arbitrary shell — and is driven through the
same `detach.run`, `lock.acquire`/`release` and `vpsexec reconcile` every real
mutation and every real reconcile use:

1. a normal step (rc 0, verify passes);
2. slow start — the result arrives only after more than one poll;
3. a failing step (rc 1); the lock releases on the known outcome;
4. lost SSH while work continues — the drill kills its own ssh client
   mid-step; the door re-attaches with backoff and reads the real rc;
5. timeout — the step outlives the drill's own patience, the lock is
   retained as unknown, then ended the same way a real `RuntimeMaxSec` would,
   and the real rc (143) is read back;
6. a competing operation is refused while the first still holds the host
   lock;
7. a retained lock reports STILL RUNNING, then — once the step ends —
   COMPLETED. **The release phrase is still typed by a human** at the
   `vpsexec reconcile` prompt this scenario drives; the drill prints it and
   waits, and never writes a phrase to anything itself;
8. `vpsexec reconcile <host> --stop` ends a running step; the stop phrase,
   too, is typed by a human.

A receipt (`journal/drill.jsonl`, event `drill_detach_receipt`, plus one
`drill_detach_scenario` event per scenario) is written whether the drill
passes or not; the command exits non-zero on any mismatch. It cleans up its
own transient op dirs and locks, and leaves the `/tmp/vpscfg-drill-*` scratch
directory in place, like the restore drill (`vpscfg <host> drill <service>`).

Scenarios 7 and 8 need a real controlling terminal, because they are the
sanctioned reconcile path itself (`vpsexec reconcile <host>` / `--stop`) —
run the drill interactively, not from cron or CI.

On a hermetic test host with no systemd at all, scenario 5 cannot exercise a
real `RuntimeMaxSec`; it reproduces the outcome (rc=143) with the same TERM
delivery `reconcile --stop` uses. A real scratch host's systemd enforcement
of `RuntimeMaxSec` is still the operator's own check, by hand, after the drill passes.
