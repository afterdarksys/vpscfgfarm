# policies/ — vpsexec's YAML policy framework

Files here are loaded by `vpsexec` on every invocation. This directory lives in
your estate (the tool checkout, or the directory a pinned `estate.path` names);
the public repository ships only this README. Working examples are in
`contrib/example-estate/policies/`. `policies/*.yaml` only —
**the loader does not recurse**, so `policies/examples/` is inert by design.

## The asymmetry

A policy file can only ever make vpsexec **stricter**:

| A policy file CAN | A policy file CANNOT |
|---|---|
| name host groups (`@web`, `@dns`) | change any host's posture |
| add deny patterns (`deny_extra`) | remove a deny pattern |
| add risky patterns (`risky_extra`) | widen the read-only allowlist |
| authorise an exact command on exact hosts (`runbooks`) | lift the deny-always floor |

Loosening lives in exactly two reviewed places: `vpscfg-control.json` (postures,
master switch, mode) and Python (`READ_ONLY_HEADS`). Not here.

An **unknown top-level key is refused, not ignored** — so a hopeful `allow_floor:`
fails loudly, and an older reader never silently skips a key a newer file relies on.
A **duplicate key at any depth refuses the whole load** too: plain YAML keeps the
last one, so a second `expires:` or `shape:` would silently replace the reviewed
value. (Parsing is still YAML 1.1: `yes`/`no`/`on`/`off` are booleans.)

## Keys

| Key | Required | Meaning |
|---|---|---|
| `version` | yes | must be `1` |
| `reason` | yes | why this file exists |
| `expires` | only if it grants | `YYYY-MM-DD`; required when `runbooks` is present |
| `shape` | only if it grants | `{steps, hosts, break_glass}` — what review approved; missing or mismatched, the file is disarmed (see below) |
| `groups` | no | `{name: [host, ...]}` — every host must exist in the governor |
| `runbooks` | no | standing authorisations (see below) |
| `checks` | no | named read plays — `vpsexec check <name>` |
| `deny_extra` | no | extra always-refused patterns — **absolute**, like the floor: no runbook, override, break-glass or approval lifts them |
| `risky_extra` | no | extra tier-2 patterns |

## Runbooks

A runbook authorises one **exact** command (whitespace-collapsed, no globs, no
prefixes) on an **exact** host list, for one placement:

```yaml
runbooks:
  - hosts: [web1, web2, web3]
    cmd: "systemctl restart nginx"
    where: host              # "host" | "container"
    verify: "systemctl is-active nginx"   # post-condition; must be a read
    break_glass: true        # may reach frozen/lockdown hosts during an incident
    why: "runbook 07 — wedged nginx worker pool"
    timeout: 120             # optional, seconds (1-3600): how long the reviewer expects it to take
    rollback: false          # optional; true = an undo step, excluded from grants and step-by-step runs unless asked
    verify_retry: {tries: 10, interval: 3}   # optional: retry the verify while the service settles
```

A container step may name its container:

```yaml
  - hosts: [web1]
    cmd: "nginx -s reload"
    where: container
    container: shop-web      # optional; this entry then authorises ONLY --in shop-web
    why: "..."
```

`verify` travels with the authorisation, so the check is written by whoever
reviewed the runbook rather than remembered at 3am. It runs per host, after the
command, and its failure fails that host (and halts a canary).

`verify_retry` runs the verify up to `tries` times, `interval` seconds apart,
passing on the first success (default: one try). Both sub-keys are required
and nothing else is allowed; `tries` 1-30, `interval` 1-60 whole seconds,
`tries × interval` at most 600, and it needs a `verify` on the same entry.
The verify must still be a read. Each attempt is journaled. The whole retry,
attempts included, ends by a 600 s monotonic deadline, and each retried
attempt times out after at most 60 s.

`container` names the one container a `where: container` entry authorises,
validated with the CLI's `--in` name rule. With it, the entry matches only
`--in <that name>`: never another container, a glob, `--in-all`, or several
`--in`s. Without `where: container` it refuses at load. Entries without it
match any container, as before. `vpsexec runbooks` shows it.

Neither key is accepted in an ad-hoc `--override` file: an override that named
a container and was read without it would authorise every container.

A runbook entry whose `cmd` classifies as a **read** needs no authorisation;
it is in the runbook so it runs in order and the reviewer sees it. `vpsexec
grant new` lists it as `read: runs without a grant` and never puts it in a
grant. A `break_glass: true` step whose hosts are all `test`/`released` needs
no elevation; a grant listing it still approves it, as a normal mutation.

An unknown key inside a runbook is refused too, not just at the top level.

A file that defines runbooks must carry `expires: "YYYY-MM-DD"` (zero-padded).
The day after it, the file's runbooks are disarmed — they authorise nothing and
vpsexec warns on every run — while everything else keeps working. Retire the
file to `examples/superseded/` when its work is done or it lapses.

Right after `expires:`, a runbook file declares its `shape`:

```yaml
shape: {steps: 6, hosts: [web1, edge1], break_glass: mixed}
```

`steps` = the number of runbook entries; `hosts` = the set of host names they
name, as written (aliases are not collapsed); `break_glass` = `true` if every
entry is break-glass, `false` if none is, `mixed` otherwise. All three are
required, and a malformed shape (unknown or missing field, wrong type, or a
`shape` on a file without runbooks) refuses the whole load. If the runbooks do
not match, or a file with runbooks has no `shape` at all (`no shape declared`),
the file is **disarmed exactly like a lapsed one**: validated in
full, its deny/risky/groups/checks kept, its runbooks merged nowhere and not
grantable, with a `WARNING ... does not match its declared shape ... DISARMED`
line on every run and a `DISARMED (misshapen: ...)` entry in `vpsexec runbooks`.
`container` and `verify_retry` are deliberately not part of the shape: like
`cmd`, `verify` and `timeout` they are per-entry content, which review (and
the file's sha256, which every grant binds) covers; the shape stays the three
values a diff makes obvious.
Update the shape in the same reviewed commit that changes the runbooks. The
test suite requires a shape on every shipped runbook file, so a new file needs
no hand-edited counts in the tests.

`break_glass: true` is the **only** sanctioned loosening in this whole layer, and
it is narrow on purpose:

- it reaches **posture only** — the floor still refuses, the master switch still
  applies, `mode: lockdown` still refuses
- it requires `--break-glass` on the command line as well
- it requires a human to type `BREAK-GLASS:<n>` where n is the host count
- it is journaled as its own `break_glass` event, naming the runbook file

The point is that outage response becomes a **lookup, not an improvisation**.
You write the runbook on a calm Tuesday with review; you use it at 3am.

A runbook naming a deny-always pattern rejects the **whole file** as tampered.

## Checks

A check is a named read play. It grants nothing: the command must classify as a
**read**, which vpsexec enforces at run time and a test pins over the shipped
file. Checks exist so nobody re-derives `df -i -x tmpfs` at 3am.

```yaml
checks:
  disk:
    cmd: "df -h -x tmpfs -x devtmpfs -x overlay"
    hosts: "@all"          # default target; an argument overrides it
    compare: true          # group hosts by identical output
    why: "..."
```

Run with `vpsexec check disk [hosts]`; list with `vpsexec checks`. Set
`compare: true` wherever hosts *should* agree (paired DNS, enabled units) — the
odd one out is the finding. Leave it off where they legitimately differ.

## Groups

Groups grant nothing — they are naming. Every member must have a posture in
`vpscfg-control.json` and must be reachable — either an alias in
`~/.ssh/config`, or a name the governor declares `alias_of` one. Both are checked
when the file loads, so an unreachable member fails on a calm day rather than
mid-incident. A group name defined in two files refuses rather than one winning
silently. `all` is reserved: `@all` is built in.

A group may use either name of an aliased machine — `web1` and
`web1.example.internal` are the same box, and naming both runs the command once.

See `docs/VPSEXEC.md` for the tool itself.
