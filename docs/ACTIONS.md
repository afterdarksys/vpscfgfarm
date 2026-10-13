# Typed actions: the contract

A typed action is one declarative step from a small, closed vocabulary. A
policy names it with typed literal parameters. The door expands it, in reviewed
tool code, into the exact text that runs, prints that text in full, and binds
its sha256 into the plan-hash. Every action also knows its own "already done?"
check, so a step that is already done costs nothing: no new step, no re-hash,
no extra phrase.

This file is the interface that the action modules, preflight and `vpsrun`
build against. The code lives in `vpscfg/actions/`. Phase 2 freezes the shape
described here; a change to it is a change to this file first.

## In a policy

A runbook entry carries `action:` and `with:` **instead of** `cmd:`:

```yaml
version: 1
expires: "2026-12-31"
reason: shop 1.5 health gate
shape: {steps: 1, hosts: [web1], break_glass: false}
runbooks:
  - hosts: [web1]
    action: wait_healthy
    with: {container: shop-web, tries: 20, interval: 3}
    timeout: 60
    why: "H1: wait until shop-web reports healthy"
assumes:
  - host: web1
    container: shop-web
expands: "sha256:<64 hex>"    # lint prints the correct line
```

These rules refuse the **whole load**, naming the field:

- `cmd:` and `action:` on one entry.
- An unknown action, or `action: name@N` (the version is the door's own).
- An unknown parameter, a missing required parameter, or a value of the wrong
  type.
- `where:` other than `host`, `container:`, `verify:` or `verify_retry:` beside
  `action:`. An action owns its placement, its verify and its retry.
- A `cmd:` (in a runbook, an override or a check) that spells the reserved word
  `vpscfg-action`.
- An expansion that names a deny pattern.

`break_glass`, `rollback`, `timeout`, `why` and `hosts` mean what they mean for
`cmd:`. If `timeout:` is absent, the action's own default applies.

YAML type rules for `with:` values: `"48"` is not an integer, `48` is not a
string, and a list or map is never a scalar. `0644` (which YAML loads as the
integer 420) is not the string `"0644"`. YAML 1.1's `yes`, `no`, `on` and `off`
are refused where a boolean belongs: write `true` or `false`. Outside `with:`
those words keep their old meaning.

## Where action policies live: `policies/actions/`

A policy that uses `action:`, `with:` or `expands:` lives in
`policies/actions/*.yaml`, never at the top of `policies/`. The reason is
backward compatibility with older doors:

- Every door copy built before phase 2 globs only `policies/*.yaml`, and it
  refuses the whole load on a key it does not know.
- So one action policy at the top level would make every older checkout, and
  any `vpsexec` still on an older tool, refuse every mutation, break-glass
  included. That is an outage lockout.
- One directory down, those older loaders never read the file.

The new loader reads both levels and enforces the split:

- A top-level file that uses action keys refuses the load and names the move.
- A file in `policies/actions/` may not define `groups:`. The outer door reads
  groups from the top level only, and the two doors must agree on what a group
  is. Those files may still carry plain `cmd:` steps, `checks:` and the deny
  lists.
- A file name that appears in both directories refuses the load, because grants
  and releases name a policy by its file name.

`tests/test_actions_core.py` (OldDoorCompatTest) loads main's loader, frozen in
`tests/data/old_door/`, against an estate holding both kinds of file. The old
loader keeps every top-level runbook. The same test proves the old loader
refuses once an action policy sits at the top level.

## `expands:` (decision D2)

`expands:` is a top-level key, like `shape:`. It is `sha256:` over the
canonical JSON of the sorted list of every action step's
`[step, host, canonical, sha256(body), sha256(check), verify, retry, timeout,
assumes]`:

- the host is the name as written in the policy;
- `check` is null when the action has no check;
- `verify` is the verify text, or null when there is none;
- `timeout` is the template's timeout in seconds, and `assumes` the facts the
  template assumes (with the step's host filled in), so a template change that
  only moves a timeout or an assumed fact still disarms the file.

If `expands:` is missing or does not match, the file is DISARMED. It is still
validated in full, it authorises nothing, and every run prints a WARNING. A
file that has no action step and still declares `expands:` is disarmed too.

`actions.lint_expands(doc, runbooks)` returns a lint result. On a failure that
result prints the line to paste. `actions.expands_line(runbooks)` gives the
same line on its own. A tool upgrade that changes any template therefore
disarms each affected policy until a human has read the new expansion and
pasted the new digest.

## On the command line

```
vpsexec <hosts> --action NAME[@VERSION] --with '{"param": value}' [--run --reason "why"]
```

`--with` takes exactly one JSON object. Duplicate keys, NaN, Infinity and
anything over 8 KiB are refused.

`--action` refuses `--in`, `--in-match`, `--in-all`, `--verify` and
`--incident` (decision D9: no actions under an incident in v1).

`NAME@VERSION` must equal the door's version. A play that recorded an older
version therefore re-plans; the door never runs it as the newer one.

## The canonical string

```
vpscfg-action <name>@<version> '<canonical JSON of the validated params>'
```

The canonical JSON uses sorted keys, `separators=(",", ":")` and ASCII only.
Every default is written into it, so two spellings of one call are one string.

The canonical string is what the deny floor, `deny_extra`, `risky_extra`, the
runbook matcher, grants, `shape:` and the plan-hash see. It runs nothing.
Typing it (as a command, in a runbook, override or check `cmd:`, or in a play
`cmd:`) is refused as reserved, exactly like `vpscfg-push`.

## Tier

The tier is fixed in code:

- A `read` action runs like any read: no `--run`, no approval. Its **body
  itself must classify as a read** under the door's `classify()`.
- A `mutation` action is tier **risky**. It runs only on hosts that a committed
  runbook, or a non-break-glass `--override` entry, names by its canonical
  string. Break-glass comes only from a committed `break_glass: true` entry.
- A `risky_extra` pattern that matches the canonical string makes even a read
  action risky. Policies only tighten.

## The Python interface

```python
from vpscfg import actions
from vpscfg.actions import types
from vpscfg.actions.base import Action, Param, SqlCheck, TokenCheck, register, sq

@register
class EnsureThing(Action):
    name = "ensure_thing"          # [a-z][a-z0-9_]{0,31}, unique
    version = 1                    # bump on ANY template change (golden test)
    tier = "mutation"              # or "read"
    params = {"container": Param(types.CONTAINER),
              "force": Param(types.FLAG, required=False, default=False)}
    samples = ({"container": "shop-db"},)   # golden + fuzz corpus, every param

    def build(self, p, host):      # pure: no clock, env, randomness or I/O
        return {"body": "...", "check": "...", "verify": "...",
                "verify_retry": (tries, interval), "assumes": ({...},),
                "timeout": 120, "idempotent": True}
```

`actions.expand(name, params, host) -> Expansion` validates the parameters and
calls `build()`. It returns a frozen object with these fields: `name`,
`version`, `params`, `host`, `canonical`, `body`, `check`, `verify`,
`verify_retry`, `assumes`, `timeout`, `idempotent`, `tier`. The door passes
the host after aliases are resolved, and the loader passes the name as written.
**A template must not depend on how a host is spelled.** Per-host data belongs
in a typed parameter.

Every module in `vpscfg/actions/` other than `base`, `types` and `expand` is
imported automatically, so a new `<kind>.py` needs no edit to `__init__.py`.

### Parameter types (`vpscfg/actions/types.py`)

Each type is a fullmatch regex compiled ASCII-only, plus a type check that
never coerces. Every string type also has to pass the door's ceiling,
`PARAM_VALUE_RE`: 1-128 characters from `[A-Za-z0-9_.:/@%+,=-]`, not starting
with `-` or `@`.

| type | accepts |
|---|---|
| `CONTAINER` | `[A-Za-z0-9][A-Za-z0-9.-]*` (the CLI's container rule) |
| `PG_IDENT` | `[a-z_][a-z0-9_]{0,62}`. Lowercase only, so there is no quoting game |
| `ENV_KEY` | `[A-Za-z_][A-Za-z0-9_]*` |
| `ABS_PATH` | an absolute path. No `.` or `..` segment, no `//`, no trailing `/`, not `/` |
| `LOCAL_URL` | `http://127.0.0.1:<1-65535>[/path]` |
| `IMAGE_REF` | `[registry[:port]/]repo[:tag][@sha256:<64 hex>]` |
| `SHA256` | 64 lowercase hex |
| `BASENAME` | `[A-Za-z0-9._-]{1,64}`. Not `.` or `..`, and not starting with `-` or `.` |
| `int_range(lo, hi)` | an integer (not a boolean) from lo to hi |
| `enum(*values)` | one of the given strings |
| `FLAG` | `true` or `false`. YAML 1.1 words are refused |
| `list_of(type, most, least=1)` | a list of `least` to `most` unique items |

### Templates

- Quote **every** value with `sq()`. It always single-quotes; `shlex.quote`
  does not. The floor-sweep test checks that each string value only ever
  appears between single quotes in the body and in a shell check or verify.
- SQL identifiers are `PG_IDENT`. Inside SQL, use them as string literals that
  the server compares, or through `format('%I', ...)` server-side.
- A password or DSN never reaches argv. Read it inside the container, the way
  `hostindex._PG_IN_CONTAINER` does.
- No `$(...)`-built destructive verbs. The deny floor runs over the whole body,
  check and verify, and over the canonical string.

### Check (decision D3): "already done?"

- A **shell** check must classify as a `read` under `classify()`. A
  `risky_extra` hit makes it non-read and refuses the plan.
- A **`SqlCheck(container, database, sql)`** goes through the host index's
  sqlread gate. That means one statement passing `sqlread.classify`,
  `default_transaction_read_only=on`, `BEGIN READ ONLY`, a 10 s
  `statement_timeout`, and the password read inside the container. The script
  is sent on stdin.
- A **`TokenCheck(key, script, values)`** is a reviewed shell script fixed in
  tool code and registered with `register_token_script("<action>@<version>",
  script, sha256, binds, file_param)`, which refuses bytes that do not hash to
  the pinned sha256. The door sends the fixed argv `sh -s`, and on stdin the
  `sq()`-quoted parameter assignments followed by the script; no parameter is
  ever on argv. It is the **only** exemption from the credential-file rule,
  and the door's gate (`vpsexec._gate_token`) grants it only when the check is
  the registered script of this very action and version (byte-equal, sha256
  re-checked at plan time and again before sending), carries exactly this
  expansion's parameters, and the registry's named file parameter is an
  environment file or an ordinary file: never a device, `/proc`, `/sys`, an
  ssh host key, a `.key`/`.private` file or `registries.yaml`. A plain `cmd`,
  a shell check and a SqlCheck still meet the credential rule on every tier.
  The floor, `deny_always` and `deny_extra` scan the command and the whole
  stdin. Its output is never echoed, printed or journaled: the journal gets
  the token, or the fixed error class `not-a-token` / `transport`, with rc and
  duration. `check_sha256`, the plan-hash and `expands:` cover the script's
  bytes, because the check text includes them. A template change is a version
  bump and a new golden file, as for any template.
- A check prints exactly `VPSCFG-DONE` or `VPSCFG-NEEDED`, with at most one
  trailing newline. A SqlCheck prints the marker row and then one token row.
  Anything else fails the host closed and the body does not run. That includes
  extra lines, another letter case, empty output, rc not 0, a timeout and a
  lost transport.
- The order on each host is: take the lock, run the check. On DONE, journal
  `action_already_done`, report `[done]`, skip the body and the verify, release
  the lock, and write `host_done` with `already_done: true`. On NEEDED, run the
  body, then the verify.
- A check runs only under THIS operation's lock. It never releases a lock and
  never stands in for `vpsexec reconcile`.

### Idempotency

- `idempotent: true` requires a check. It also requires a test that runs the
  action twice against the fake host and asserts the second run is a no-op.
- `idempotent: false` means no check, for example a forced rotation. It
  resumes exactly like a plain `cmd` (SKIP-DONE / RERUN).
- A read action has no check. Its body is its probe, and `verify_retry` retries
  that body: up to `tries` attempts, `interval` seconds apart, within the
  runbook bounds of 30 tries, 60 s and 600 s total.

### Verify

A verify is shell text that must classify as a read, or a `SqlCheck` or a
`TokenCheck`, which pass only on the exact `VPSCFG-DONE` token (a TokenCheck
verify journals only the token, never its output). `verify_retry` has the runbook's
semantics and bounds.

### Assumes

`build()` may return `assumes:`-shaped facts without `host:`. The step's host
is filled in, and the loader's own `check_assumes` validates them. Use
`actions.step_assumes(runbooks)` to get `[(step, item)]`, which lint and
preflight treat like hand-written items labelled `(from action step N)`. They
grant nothing.

## What the plan, the hash and the journal carry

- **Plan:** an `action :` line (tier, and whether it is idempotent), a
  `check :` line, a `retry :` line for a read action, and, under WILL RUN, each
  host's body in full followed by its check.
- **Plan-hash:** the canonical command, plus `action = {name, version, params,
  tier, per_host: {body_sha256, check_sha256, verify, retry}}`. Any changed
  byte means REPLAN.
- **Journal:**
  - `action_planned`: action, action_version, params (masked), body_sha256 and
    check_sha256 per host, plan_hash.
  - `action_check`: token, rc, duration.
  - `action_already_done`.
  - `step`: carries action, action_version, params and body_sha256.
  - `host_done`: carries `already_done`.
  - `mutation_attempt` and `mutation_complete`: carry `action_body_sha256`.

## Tests every action ships

- A golden file `tests/golden/actions/<name>@<version>.json` that expands every
  sample. Changing a template without bumping `version` fails it.
- An injection corpus: every parameter is refused for `;`, quotes, `$(...)`,
  backticks, newline, NUL, CR, tab, a leading `-`, Unicode lookalikes, NFKC
  forms, 10 000-character values, `../`, a trailing slash and uppercase
  identifiers.
- A twice-run idempotency test on the fake host for each `idempotent: true`
  action.
- For anything that touches credentials: a `Threats:` note, and a test that
  seeds fake secrets and greps every captured stream and journal line for them.

## Vocabulary (decision D7)

| action | owner | tier | file |
|---|---|---|---|
| `wait_healthy {container \| url, tries, interval}` | P0 (reference) | read | `container.py` |
| `ensure_owner`, `pg_dump`, `migrate` | P1a | mutation | `db.py` |
| `recreate`, `tag_image` | P1b | mutation | `container.py` |
| `ensure_secret` | P1b | mutation | `secret.py` |
| `install_pushed` | P1b | mutation | `file.py` |

### `wait_healthy` (v1)

`wait_healthy` takes exactly one of `container` or `url`.

- With `container`, the body is
  `docker inspect --format '{{.State.Health.Status}}' '<c>' | grep -qx healthy`.
  A container without a healthcheck never passes; use `url` for it. This form
  also assumes `container: <c>`.
- With `url`, the body is `curl -qfsS --max-time 5 '<url>'`.

`tries` defaults to 10 and `interval` to 3, and `tries x interval` may not
exceed 600 s.

### `ensure_owner` (v1)

`ensure_owner {container, db, role, schema}` gives `role` ownership of
`schema` and of every table, partitioned table, view, materialized view and
sequence in it. It is idempotent, its timeout is 300 s, and it assumes
`container: <container>`.

- `container` is the Postgres container. `db`, `role` and `schema` are
  `PG_IDENT`. A `pg_*` role, a `pg_*` schema and `information_schema` are
  refused.
- **Check**, and also the verify: a `SqlCheck` in the host index's read-only
  session. It prints DONE when the schema and every such object in it are
  already owned by `role`. A missing role or schema reads as NEEDED, and the
  body then fails.
- **Body**: `docker exec -i` into the container, with the password read
  inside it exactly as the host index reads it. The SQL goes in on stdin
  through a quoted heredoc and runs as one transaction with a 10 s
  `lock_timeout`. A `DO` block refuses if the role or the schema is missing,
  then runs `ALTER ... OWNER TO` through `format('%I')`: first the schema,
  then tables, views and matviews, then whatever sequences are left. Tables
  come first because `ALTER TABLE` also moves the sequences a table owns. If
  anything is still not owned at the end, it raises and the whole transaction
  rolls back.
- **Output**: counts only, `pending <kind> <n>` before the change and
  `owned <n>` after it. No object names are printed.
- "The role exists" has no `assumes:` fact today. The body checks it itself
  and fails closed.

### `pg_dump` (v2)

`pg_dump {container, db, dest_dir, label, min_free_gb?}` writes a
custom-format dump of `db` on the host, at
`<dest_dir>/<db>-<label>-<p8>.dump`, mode 0600. It is idempotent and its
timeout is 1800 s.

- `p8` is the first 8 hex of sha256 over the canonical JSON of `container`,
  `db`, `dest_dir` and `label`. The same call therefore always names the same
  file. The plan-hash cannot be used here, because the body is part of what
  the plan-hash covers.
- `dest_dir` (`ABS_PATH`) must already exist; the action does not create it.
  It may not be world-writable or sticky (`/tmp`, `/var/tmp`): there anyone
  could plant a name first, so the body refuses (exit 2).
  `label` (`BASENAME`) is the release or the reason, for example `shop-1.5`.
- **Body**:
  1. Refuses if the dump file already exists. A dump is never overwritten.
  2. Streams `pg_dump -Fc` out of the container into a `mktemp` file in
     `dest_dir` (the record gets a second one); no fixed temp name is ever
     used. The password is read inside the container.
  3. Requires the temp file to be non-empty and readable by `pg_restore
     --list`, which runs inside the container.
  4. Writes `<file>.sha256` and renames that record into place, then renames
     the dump into place.
  5. Prints the size and the sha256. On any failure the temp file is
     removed.
- **Check**: `sha256sum --check --status <file>.sha256`, a shell read. A dump
  is only renamed into place after `pg_restore --list` has accepted it, so a
  matching record vouches for it. A missing or mismatching record is NEEDED.
  If the dump file is still there, the body then refuses rather than
  overwrite it. **Verify**: the same `sha256sum --check`.
- **Assumes**: `container: <container>`, and `min_free_gb: {<dest_dir>: N}`
  when `min_free_gb` is given. For a `pg_dump` step without it, `vpsrun
  release new` prints ADVICE: the database's `size_bytes` from a fresh index
  x 1.2, rounded up to whole GB, as the `min_free_gb:` to add to the step's
  `with:` in the POLICY (it never writes it: the play's `with:` must equal the
  policy's, and `release new` never writes under `policies/`; with no usable
  index it says it cannot size it). The expansion itself never reads the
  index.

### `migrate` (v1)

`migrate {container, runner, workdir?, db?}` runs one of four fixed runners
(decision D8). Adding a runner is a code change.

| runner | command, run inside `container` |
|---|---|
| `prisma_deploy` | `./node_modules/.bin/prisma migrate deploy` |
| `alembic_upgrade_head` | `alembic upgrade head` |
| `node_pg_migrate_up` | `./node_modules/.bin/node-pg-migrate up` |
| `sql_dir` | `psql -1 -f` on each `./*.sql` in `workdir`, in C-locale name order, stopping at the first error; this one runs in the Postgres container and needs `db` |

- `workdir` becomes `docker exec -w`. Without it, the container's own working
  directory is used. `db` is refused for any runner except `sql_dir`.
- **Not idempotent.** Each runner's status command (`prisma migrate status`,
  `alembic current`) would need `docker exec`, which the classifier rates
  risky, so it cannot be a done-check. A `migrate` step therefore resumes like
  a plain `cmd:` (SKIP-DONE / RERUN). **Known limitation (L4):** `sql_dir`
  keeps no record of which files it applied, so a RERUN applies EVERY file in
  `workdir` again, including the ones that already succeeded before the
  failure or the lost session. Write them to be safe to re-apply, or answer
  SKIP-DONE and finish by hand. `vpsrun --resume` prints this caution above
  the SKIP-DONE / RERUN prompt for a `migrate` step (the app runners' own
  tools normally skip what they already applied; that is their guarantee,
  not the door's).
- The runners read their own database settings from the container's
  environment. Nothing secret is ever in the template.
- **Assumes**: for the three app runners, `container: <container>` with
  `env_names_any_of: [[DATABASE_URL], [DB_HOST, DB_NAME, DB_USER, DB_PASS]]`.
  For `sql_dir`, `container: <container>` only. The read-only `privileges`
  fact from P2 is not used in v1.
- Timeout: 600 s.

### `recreate` (v1)

`recreate {container, project, service, working_dir, config_files, healthy,
tries, interval}`. A mutation, **not idempotent**: it has no done-check,
because recreating is the point. It resumes like a plain `cmd`.

```yaml
- hosts: [web1]
  action: recreate
  with: {container: shop-web-1, project: shop, service: web,
         working_dir: /srv/shop, config_files: [/srv/shop/docker-compose.yml]}
  why: "R1: pick up the rotated SESSION_SECRET"
```

- The compose project, service, working directory and files are typed
  parameters, committed in the policy (S11). Nothing is read from the index,
  from the host or from free text to build the command. `project` and `service`
  are `BASENAME`, `working_dir` is `ABS_PATH` and `config_files` is a list of 1
  to 4 `ABS_PATH`s.
- It emits one assumes item: `container`, `compose_labels` with the four
  `com.docker.compose.*` labels (project, service, `project.working_dir`, and
  `project.config_files` as the files joined with `,` in the given order) and
  `compose_files`. So preflight proves that the live container was started
  from exactly these values before anyone types a phrase.
- The body checks the same four labels again on the host. If any label
  differs, it prints what it found, exits 3 and recreates nothing. Then it runs
  `docker compose -p <project> --project-directory <working_dir> -f <file>...
  up -d --no-deps --force-recreate --pull never <service>`. The image does not
  change.
- Verify: `docker inspect` shows the container `Running` (or `healthy` with
  `healthy: true`), retried `tries` (default 20) times `interval` (default 3)
  seconds apart, at most 600 s. Timeout: 300 s.
- **Known limitation (INFO-2):** the assumes pin the compose file *paths*,
  not their *contents*. A compose file edited on the host after the policy
  was reviewed (a new image, an extra volume) is recreated from as it now is;
  neither the expansion, the plan-hash nor preflight carries a sha256 of the
  file. Review the compose file on the host (or ship it with `push` +
  `install_pushed`, whose sha256 is pinned) when that matters.

### `tag_image` (v1)

`tag_image {image_ref, new_tag}`. A mutation, idempotent.

- `image_ref` must name a tag or a digest. `new_tag` is a full reference with
  a tag and no digest (`shop/web:rollback`). The two may not be equal.
- Body: `docker image tag '<image_ref>' '<new_tag>'`.
- Check (a read): `docker inspect` lists the source image's `RepoTags`, and
  `grep -qxF` looks for `new_tag`. If it is there, the tag already points at
  the same image ID and the check prints DONE. Verify: the same test.
- Write references the way docker prints them (`postgres:16`, not
  `docker.io/library/postgres:16`). A long form never matches, so the check
  says NEEDED and the tag is applied again. That is harmless.

### `install_pushed` (v1)

`install_pushed {sha256, basename, dest, mode, owner}`. A mutation,
idempotent. This is the content-addressed install from VPSEXEC.md as one
action. Use `push` first: moving the file is transport, not an action.

- `mode` is one of `"0644"`, `"0755"` or `"0600"`. Quote it: YAML reads a
  bare `0644` as the integer 420, which is refused. `owner` is `root`.
- Body: refuses a `dest` that is a symlink or a directory. Re-checks the staged
  `/var/tmp/vpscfg-push/<sha256>/<basename>` against the hash and refuses on a
  mismatch. Runs `install -m <mode> -o <owner> -g <owner>` into a temp file
  in `dest`'s directory, checks the temp's hash again, then renames it over
  `dest` with `mv -fT`. Exit 3 means nothing was installed.
- Check (a read): `echo '<sha256>' '' '<dest>' | sha256sum --check --status`
  (the empty word makes the two-space check line while every value stays one
  quoted word), and `stat` shows the mode and the owner. Verify: the same three
  facts. Timeout: 120 s.

### `ensure_secret` (v3)

`ensure_secret {file, key, length, distinct_from, force}`. A mutation,
idempotent unless `force: true`. `length` is 32 to 128 (default 48).
`distinct_from` is up to 8 `ENV_KEY`s (default none) and may not name `key`.

```yaml
- hosts: [web1]
  action: ensure_secret
  with: {file: /srv/shop/app.conf, key: SESSION_SECRET, length: 48,
         distinct_from: [JWT_SECRET]}
  why: "S1: SESSION_SECRET must not equal JWT_SECRET"
```

- **Check** (a token-only check, see "Check" above; the reviewed script
  `secret.CHECK_SCRIPT`, pinned by sha256 as `ensure_secret@3`, built only
  from `grep`, `cut`, `sort`, `uniq` and `printf`; values move only over
  pipes): NEEDED when `key` is missing or appears twice, is shorter than
  `length`, or is byte-equal to any `distinct_from` key's value, or `file` is
  not a regular file (a symlink is NEEDED, and the body then refuses it).
  Otherwise DONE. Verify: the same check, passing only on DONE. A key line is
  `KEY=value` or `export KEY=value`, in the check and the body alike (the body
  removes both spellings and keeps `export` when the file used it). Each
  `distinct_from` key's values are de-duplicated before the comparison, so two
  identical `JWT_SECRET=` lines are not a "shared" value. It works on
  environment files (`.env`, `.env.production`, `prod.env`, ...).
- Versions: v1's check was a shell content read, refused at plan time for an
  environment file. v2 made it a token-only check. v3 fixed v2 rotating on
  every run when a `distinct_from` line was repeated, and counts `export KEY=`
  lines. Only v3 is registered: a policy pinned to an older version refuses
  until it is re-planned and its `expands:` line re-pasted.
- **Body:** generated on the host with `openssl rand -hex`, or from
  `/dev/urandom` through `od` if openssl is missing. If neither is present it
  refuses. Before use, the value is checked to be `length` lowercase hex
  characters. The old file is kept as `<file>.vpscfg-bak.<op8>` at 0600 (op8 is
  the first 8 hex of the door's operation id, from `VPSCFG_OP`; without it the
  body refuses). The new file is a temp in the same directory, with mode and
  owner copied by `cp -p`, then `mv`'d over `file`. The `key` line moves to the
  end of the file and every other line stays as it was. The only output is
  `rotated <key> (<length> chars)`. Exit 3 means nothing changed (not a
  regular file, a symlink, an existing backup name, no generator).
- It restarts nothing. Put a `recreate` after it in the play. A container that
  bind-mounts the single file keeps the old inode until it is recreated.
- `force: true` means a deliberate rotation: no done-check, `idempotent:
  false`, and SKIP-DONE / RERUN on resume.
- `vpsexec runbook preflight --secrets-compare` runs this same check to
  answer an `assumes: env_distinct` pair (docs/VPSEXEC.md).
- Threats: it protects against values in output, logs, argv, the plan, the
  journal and the policy, and against a torn write. It does NOT protect
  against root on the host reading the file, or against the old value left in
  the 0600 backup, which is named by operation and removed by hand.
