# NO-PASTE — closing the loop so the agent stops asking a human to copy text

Status:
- BUILT: F1 `vpsexec last`, F3a investigation reads, F4 typed check params, F2 `vpsrun`.
- F3b gate-order waiver: NOT built (refused as a gate weakening). Instead, an
  estate that needs firewall listings authorises the exact listings as
  break-glass runbooks in a policy file. They stay mutation-tier: --run,
  --reason, approval, host lock, break_glass event.
- DEFERRED to the secrets pass: F5, F6/F6a (keystore source), F7 redaction.

## Why pastes happen today (evidence, not guesses)

From one estate's `journal/vpsexec.jsonl` (about a thousand rows) and past
agent transcripts:

| Cause | Evidence | Fix below |
|---|---|---|
| Break-glass needs a typed phrase at a real TTY; `!` has no TTY, so the human runs it in another terminal and the output lives there | every frozen-host deploy | F1, F2 |
| Ordinary diagnostics classify as *mutating* or *risky*, so they need approval or a runbook | 10× `iptables` risky refusals on the test host; `ip addr`, `postqueue -p`, `lsof`, `last`, `vmstat`, `certbot certificates` all tier *mutating* | F3 (the lists) |
| `$` is refused outright, so anything needing a variable goes to a human | 9 refusals | F4 |
| Reads that need a credential (psql as a role) cannot run without a password | one service's prerequisite check: six paste round-trips | F5 |
| A secret has to reach a host (Stripe key) | a billing service's API key | F6 (stays human, but no chat paste) |

Mutation output is **already journaled** (`step` rows carry `detail`). Reads are
not. So half of F1 is exposing what exists.

## Features

### F1. `vpsexec last` / `vpsexec show <plan-hash>`: read back what the human ran
Prints the step output for a run from the journal. The human runs break-glass in
their own terminal and says "done"; the agent reads the result itself.
Output passes through the F7 redactor before display. Small; no new authority.

### F2. `vpsplay` + `vpsrun`: queue a play, approve it once, get the output back
- **vpsplay** (agent side): writes an ordered, multi-step play to `queue/`:
  steps, per-step `--verify`, `on_fail: stop`, reason. Each step is still
  classified; a frozen host still needs a committed break-glass runbook. The
  plan-hash covers the whole play, byte for byte.
- **vpsrun** (human side, **refuses without a TTY**, so the agent cannot use it
  to approve itself): `vpsrun` with no arguments lists the queued plays, shows
  the full plan, asks for the approval phrase **once**, runs the steps, and
  journals everything. The agent watches the journal for completion.
- Net effect: the human types `vpsrun` and one phrase. Nothing to copy or paste
  in either direction. The per-step `BREAK-GLASS:1` ritual becomes one phrase
  per play: `BREAK-GLASS:<steps>@<hosts>`.
- Deliberately NOT `vpsexec` flags: the thing that approves stays a separate,
  TTY-only binary, the same reason vpsexec is separate from the executor.

### F3. Expanded read allowlist (the lists below)
Additions to `vpscfg/readpolicy.py` grammars. Each entry is a **positive
grammar** (named subcommands and flags only), never a head-word allow. One
structural change is needed: today the risky-pattern check (step 3 of
`classify`) runs before the read check, so `iptables -S` can never be a read.
Proposal: a segment that parses fully under an exact read grammar skips the
risky match for that segment only. This touches gate order, so it gets its own
PR, its own tests, and a reviewer who is not the author.

### F4. Parameterised checks (instead of `$`)
`policies/checks.yaml` entries gain typed parameters, each validated by a
regex before substitution: `vpsexec check container-logs edge1 name=shop-proxy
since=2h`. Substitution happens in Python after validation, so `$` stays
banned in the classifier.

### F5. `vpscfg <host> sql <db> '<SELECT…>'`: read-only SQL with no password in chat
- Runs as a declared read-only database role, with the
  credential resolved **on the host** from a path named in the contract. It
  never crosses the wire to the agent.
- Runs inside `BEGIN READ ONLY` plus `SET statement_timeout`, and the text must
  start with `SELECT`, `WITH`, `SHOW`, or `EXPLAIN` (no `ANALYZE`). Postgres
  enforces read-only itself; the prefix check is only for fast feedback.
- Same shape for Redis (`INFO`, `PING`, `DBSIZE`, `SLOWLOG GET`, `CLIENT LIST`,
  `LATENCY LATEST`; never `CONFIG GET`, `KEYS`, or `MONITOR`).
- Threats: SQL injection is moot because the role cannot write; data
  exfiltration is bounded by the role's grants and `LIMIT`-capped output.
  Needs negative tests: rejects `INSERT` or `COPY … TO PROGRAM`, fails closed
  when the role is missing, rejects when the role is superuser.

### F6. `vpsexec <host> secret-put <dest>`: secret intake without the transcript
Silent TTY prompt → ssh stdin → `install -m 600` at a path declared in a
contract. The journal records the sha256 fingerprint only. TTY-only, so the
agent cannot run it. The human types one command and pastes into a silent
prompt, not into chat.

### F6a. A local keystore as the source for F6
A keystore CLI (called `keystore` here) stores secrets locally (AES-256-GCM file vault or macOS Keychain) under
stable names. The split:
- **Human, once:** `keystore set stripe/shop_secret prod` (silent prompt).
  That is the only moment a value is typed, and it never goes into chat.
- **Agent, any time:** `vpsexec db1 secret-put --from keystore:stripe/shop_secret@prod
  --to k8s:shop/shop-billing:STRIPE_SECRET_KEY`. The door calls the keystore
  itself, pipes the value straight to ssh stdin, and journals only
  `name@version` plus a sha256 fingerprint. The agent handles a **name**,
  never a value.
- Destinations are an allowlist declared in contracts (`secrets.sinks`), so a
  name cannot be sent to an arbitrary path or host. Push is a mutation: posture,
  approval, and break-glass all still apply.
- **Required keystore property:** if its agent policy allows
  `keystore get`, which prints the raw value to the agent's stdout and therefore
  into the transcript, it needs a `keystore pipe NAME --to-fd N` (or `--exec-stdin`)
  mode that the door uses, and drop `get` from the agent policy. Otherwise the
  "agent never sees it" property is only a convention.
- Unlocking stays the human's job (an OS keychain dialog or a vault password).
  An OS keychain gives a per-use prompt; a file vault unlocked by an
  environment variable gives none.
- F5 does **not** use the keystore: DB credentials stay on the host, so a DB password
  never has to exist on the laptop at all.

### F7. Output redaction on reads (a security fix, needed now)
These classify as **read** today and print credentials into the agent's
transcript:
`kubectl get secret X -o yaml|json`, `printenv`, `docker inspect` (Config.Env),
`docker compose config`, `kubectl describe` on some CRDs.
Fix: (a) refuse `get secret(s)` with `-o yaml|json|jsonpath|go-template`;
(b) run every read's output through a redactor that masks values whose key
matches `(?i)(pass|secret|token|key|credential|auth|dsn|private)` and anything
shaped like a PEM block, a JWT, or `scheme://user:pass@`. Show the key and a
short hash of the value so equality checks still work.

## F3 lists: what the agent should be able to run without asking

Legend: **have** = already a read. **add** = new grammar. **exact** = only the
listed form qualifies.

### Outage triage (first five minutes)
- have: `uptime`, `free -h`, `df -h`, `df -i`, `ps` (forest), `journalctl -p err -b`, `systemctl --failed`, `docker ps -a`, `docker logs --tail`, `docker stats --no-stream`, `kubectl get/describe/logs/top/events`, `dmesg -T`
- add: `vmstat N C`, `iostat -xz N C`, `mpstat -P ALL N C`, `pidstat N C`, `top -b -n 1`, `cat /proc/loadavg|meminfo|pressure/*` (cat already works; confirm the path is not on the deny list)
- add: `kubectl rollout status|history`, `k3s crictl ps|pods|logs|stats` (not `crictl inspect`: it leaks env)
- add: `docker compose ls`, `docker events --since T --until T` (**exact**: both bounds required, so it can never hang)
- add: `timedatectl status`, `chronyc tracking|sources`, `ntpq -p` (clock skew breaks TLS and Kerberos)
- add: `findmnt`, `mount` (**exact**: bare, no args), `swapon --show`, `lsblk` (have)
- add: `smartctl -H -A /dev/X`, `mdadm --detail /dev/X`, `cat /proc/mdstat`

### Network and firewall
- add: `ip addr|link|route|rule|neigh` (+ `-s`, `-4`, `-6`, `-br`, `show`; never `add`, `del`, `flush`, `set`)
- add (**needs the F3 gate-order change**): `iptables|ip6tables -S|-L [-n -v --line-numbers -t TABLE]`, `iptables-save` (stdout only; **not** `-f`), `nft list ruleset|tables|table|chain`
- add: `ufw status [verbose|numbered]`, `fail2ban-client status [JAIL]` (**exact**: `status` only)
- add: `conntrack -C`, `conntrack -S` (counts only; never `-D` or `-F`)
- add: `lsof -nP -i [:PORT]`, `ss -s` (ss have)
- add: `curl` grows `-o /dev/null` (**exact** target), `-w FMT`, `-k`, `--resolve H:P:A`, `-H HDR`, `-4`, `-6`. Still GET/HEAD only: no `-X`, `-d`, `-F`, `-T`
- add: `dig` (have), `host`, `nslookup`, `traceroute -n`, `mtr -r -n -c N`, `nc -z -v -w N HOST PORT` (**exact**: `-z` required, so it never sends data)

### Containers and k8s
- have: see triage
- add: `docker network inspect`, `docker volume inspect` (metadata only; **never** `rm` or `prune`: the floor is untouched)
- add: `helm list|status|history` (not `helm get values`: it leaks secrets)
- change: `kubectl get secret(s)` with `-o yaml|json|jsonpath|go-template` → **refused** (F7)

### Web and TLS
- have: `openssl s_client`, `openssl x509 -noout -dates …`
- add: `nginx -t`, `nginx -T` (after F7 redaction), `apachectl -S`, `caddy validate --config P`, `caddy version`
- add: `certbot certificates` (**exact**), `ls /etc/letsencrypt/live` (have)
- Traefik: via `curl localhost:8080/api/http/routers` (after the curl grammar grows)

### Mail (relay hosts)
- add: `postqueue -p`, `mailq`, `postconf -n`, `postconf -d PARAM`, `postconf PARAM` (never `-e` or `-X`)
- add: `postmulti -l`, `postmulti -i NAME -x postqueue -p` (**exact**: `-x` accepts only `postqueue -p` or `postconf -n`, since `-x` otherwise runs anything)
- add: `postcat -hq QUEUEID` (headers only; `-b` bodies are private mail)
- add: `opendkim-testkey -d D -s S -vvv` (a DNS read)

### DNS servers
- have: `dig`
- add: `named-checkconf`, `named-checkzone ZONE FILE`, `rndc status` (**exact**: `status` only)
- A custom DNS daemon's status and query CLI, once someone confirms which subcommands are pure reads

### Security investigation
- add: `last -n N [-F -i]`, `lastb -n N`, `lastlog`, `who`, `w`
- add: `getent passwd|group|hosts [KEY]`, `id USER` (have)
- add: `crontab -l -u USER` (**exact**: `-l` required), `ls /etc/cron.*` (have)
- add: `find` grows `-perm:`, `-newer:`, `-xdev`, `-uid:`, `-nouser`, `-nogroup` (`-exec`, `-delete`, and `-fprint` stay banned)
- add: `dpkg -l`, `dpkg -V [PKG]`, `dpkg -S PATH`, `debsums -s`, `apt list --installed|--upgradable`, `apt-cache policy PKG` (never `apt-get update`: that writes the cache)
- add: `readlink -f`, `realpath`, `file`, `strings -n N` (on binaries), `lsattr`, `getfacl`
- add: `auditctl -l`, `auditctl -s`, `ausearch -ts T [-m TYPE -k KEY -i]`, `aa-status`
- add: `sysctl -n KEY`, `sysctl -a` (never `-w` or `-p`)
- add: `jq` (no `--rawfile` or `--slurpfile` on secret paths; the deny_extra scan already covers the paths)
- add: `diff -u A B`, `cmp`, `zcat`, `zgrep` (same flag grammar as grep), `tr`, `column -t`

### Deliberately NOT on the list (and why)
- `awk`, `sed` (any form), `perl -e`, `python -c`: each has a code-execution escape (`system()`, GNU sed `e`). Use grep/cut/jq, or a parameterised check (F4).
- `xargs`, `env CMD`, `nice`, `timeout CMD`, `sudo`: they wrap an arbitrary command.
- `tcpdump`: it can write files (`-w`) and exposes payloads. If needed, add it as an exact check: `-c N -nn` with no `-w`.
- `docker exec` as a head word stays risky. Use `--in CONTAINER`, which classifies the inner command with these same lists.
- Anything in `secrets.yaml` `deny_extra`: absolute, unchanged.

## Build order (proposed)
1. **F7 redaction plus secret-output refusal.** It is a live leak, and the other features widen reads.
2. **F1 `vpsexec last`.** Removes the break-glass paste today, with no new authority.
3. **F3 lists, minus firewall.** Pure grammar additions, one test per entry, both positive and negative.
4. **F3 firewall and the gate-order change.** Separate PR, independent review.
5. **F2 vpsplay/vpsrun.**
6. **F5 sql, F4 parameterised checks, F6/F6a secret-put via a keystore** (its `pipe` mode first).
