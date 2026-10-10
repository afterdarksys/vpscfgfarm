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
| `--approval-contract=FILE` | a grant from `vpsexec grant new` replaces the typed `BREAK-GLASS:<n>` for a step it lists (TTY still required); on a listed step whose hosts need no elevation it replaces that step's ordinary phrase. See "Approval contracts" |
| `--timeout N` | per-host timeout in seconds. Without it: the matching runbook's `timeout:` (1-3600 s), else a prediction from the command (read 60 s, service restart 90 s, default mutation 120 s, DB/migration 180 s, rollout/image pull/compose up 240 s, script or package install 300 s), never above 300 s. The plan prints the value and why. |

Introspection verbs take no host and change nothing (`grant` is reserved
too; it writes only under `~/.vpscfg`, never to a host):
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

```
# 1. See exactly what it would authorise (writes nothing)
vpsexec grant new shop-wave5-deploy --ttl 3h [--steps 1-20,23,25-30] [--hosts web1]

# 2. Mint it: TTY only, type GRANT:shop-wave5-deploy:3h
vpsexec grant new shop-wave5-deploy --ttl 3h --run
#    MINTED ~/.vpscfg/grants/<session_id>.json   code ABCD-EFGH-JK23

# 3. Use it for each step, in a real terminal
vpsexec web1 '<step cmd>' --break-glass --run --reason "wave5" \
    --approval-contract=~/.vpscfg/grants/<session_id>.json
#    both spellings work: `--approval-contract FILE` (the shell expands ~) and
#    `--approval-contract=~/...` (vpsexec expands ~ itself). An empty value refuses.

vpsexec grant list                 # ACTIVE / EXPIRED / REVOKED / INVALID
vpsexec grant show <file>          # VALID, or INVALID and why
vpsexec grant revoke <session_id>  # TTY; type REVOKE:<first 8>. Permanent.
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

The file (`~/.vpscfg/grants/<session_id>.json`, 0600, dir 0700) is version 1
JSON with a fixed key set: `version, session_id` (128-bit CSPRNG hex),
`approval_code` (3×4 base32, CSPRNG — printed and journaled on every use so a
human can correlate), `operator, issued_at, expires_at` (UTC), `ttl, runbook
{file, sha256}, hosts, steps [{index, why, where, cmd, cmd_sha256}], options
{break_glass, include_rollback}, mac`. `mac` is HMAC-SHA256 over the canonical
JSON of every other field, keyed by `~/.vpscfg/grant.key` (32 random bytes,
created 0600 on first mint; a key that is not 0600 or not yours is refused).

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

Journal (`vpsexec.jsonl`): `grant_minted`, `grant_used` (session_id,
approval_code, step index, plan-hash), `grant_refused` (reason),
`grant_revoked`. The key and the MAC are never printed or journaled.

What it protects against: a tampered, hand-edited or wrong-key grant; a stale
grant after the runbook changed; expired or revoked grants; scope creep to
another command, host or runbook; unattended use (TTY required); other local
users reading or planting grants; accidental keystrokes. What it does **not**:
a process running as you can read `grant.key` and forge a grant, and can
allocate a pty — the TTY check is the same barrier the typed phrase is today,
not a stronger one; root on the workstation; a stolen, unexpired grant used
from your own terminal; a same-user process deleting the revocations file. The
full note is the `Threats:` docstring of `vpscfg/vpsexecgrant.py`.

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
vpsexec grant new <runbook> --ttl 1h --run          # once, in your terminal
vpsrun plays/<name>.yaml --approval-contract=~/.vpscfg/grants/<id>.json
```

vpsrun reads each step's plan from the door; a step whose plan elevates a host
gets `--approval-contract=<absolute path>` alongside its `--approve=<hash>`, so
the door's combined path runs (hash match **and** the contract's full check,
controlling terminal included). Other steps get no contract. Checked **before**
the play is approved, so it never fails halfway for want of an approval:

- break-glass steps and no `--approval-contract` → refused, naming the steps
  and saying to mint a grant for that runbook;
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
