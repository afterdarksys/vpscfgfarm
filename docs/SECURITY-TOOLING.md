# Security tooling — what watches the watchers

Seven watchers, built together. Everything here is read-only
against the fleet, journaled, and weighted toward negative tests
(see CONTRIBUTING.md). The common thread: the platform's
guarantees stop being claims and become checked facts.

## The seven

| Tool | Invocation | What it proves |
|---|---|---|
| Journal hash chain | `vpscfg journal verify [--against DIR]` (auto in fleet watch) | Past journal entries were not edited, deleted, or spliced. Legacy prefix tolerated. `journal verify --against DIR` alarms when a mirror is longer or the shared prefix disagrees. |
| Unjournaled-change detector | `vpscfg fleet baseline` / `vpscfg fleet changes` | Every observed container change — and, on k3s hosts, every pod change (spec image, uid) — has a journaled mutation behind it. Zero coverage = Watchtower, a raw-ssh hotfix, or an intruder. Refused/read entries never count as coverage. A pre-pods baseline with live pods flags `unbaselined` until re-baselined. |
| SSH access survey | `vpscfg fleet keys` | Every alias in ~/.ssh/config actually authenticates; aliases of one machine agree; every governed host answers somewhere. Built after an ssh key-rot incident. |
| Secrets census + escrow | `vpscfg fleet secrets` / `vpscfg fleet escrow <svc> --reason` | Declared credential files (contract `credentials:` lists) exist and haven't silently changed; encrypted lifeboat via `age` to committed recipients (`policies/escrow-recipients.txt`). Plaintext never touches local disk; `escrow/` is gitignored. |
| Port audit | `vpscfg <host> ports` + lint cross-pass | Contract-declared ports vs kernel bind state. COLLISION and DOWN fail; undeclared listeners are the coverage to-do. |
| Perimeter + DR checks | contract `verify:` types `smtp_banner`, `smtp_relay_refused`, `tls_expiry`, `pg_replication` | The public MX answers as itself, refuses foreign relay (never sends DATA), its cert outlives 14 days, and a standby is actually in recovery with bounded lag. |
| Backup verification | `vpscfg <host> backup-verify <svc>` | The newest pre-backup streams, gunzips, and tar-walks end to end. Truncated/corrupt/empty/absent all fail loudly. |

Named read plays in a `checks:` policy file (`unhealthy`, `restarting`,
`mail-queue` and so on) cover the rest; see `policies/README.md`.

## Honest limits (each module's Threats note is authoritative)

- The hash chain cannot see a shortened tail or a full rewrite of every
  copy. `vpscfg journal verify --against DIR` compares a mirror: a longer
  mirror or a disagreeing prefix is truncation. A longer local file is lag.
  The telemetry POST is best-effort and is not that witness.
- The change detector sees image/created/status changes (and pod
  spec-image/uid changes on k3s hosts), not `docker cp` into a running
  container or `kubectl cp` into a running pod — that is drift's file
  hashing. A k3s host whose API server is down fails the probe loudly
  (SKIP + alarm), never reads as "no pods".
- `fleet keys` proves reachability, not host integrity. Who else can
  log in is `fleet authkeys` (hashes of authorized_keys and sudoers
  lines). An empty allowlist is UNPINNED, not "no keys allowed".
- Escrow currently encrypts to the ops machine's own key — protects
  against host loss, not ops-machine compromise. Upgrade path (offline
  age keypair) is documented in the recipients file.
- `tls_expiry` falls back to an unverified, inspection-only read for
  self-signed perimeter certs. It sends nothing; it must never be copied
  into code that transmits data.
- `backup-verify` proves the archive is readable, not that its contents
  are right. `vpscfg <host> drill <service>` is the scratch-project receipt
  (`restore-drill`, verified only when the canary and `compose down` with no
  volume flag both succeed). It does not widen `scopes.unlocked`.

## Not built, on purpose

CVE scanning on an end-of-life OS: it receives no patches, so the scan's
answer is always "everything". The fix is the Stage-5 OS-upgrade-under-
contract path (and `vpscfg fleet os`), not a scanner.

## Firewall audit: `vpscfg fleet firewall [host ...]` (optional)

This verb came out of an outage in which `iptables-persistent` replayed an
old `rules.v4` over live Docker/k3s state. A separate firewall manager (a
reconciler and stale-NAT detector) had judged that over raw ssh; this verb
ports its judgement through the door. One reviewed probe string
(`probe.firewall_command()`: iptables `-S`/`-L` listings, docker ps/inspect,
kubectl get, ss, systemctl is-*, grep, sha256sum) gathers the facts, and
`vpscfg/firewall.py` judges them locally. It is read-only, journaled as a
`fleet_firewall` watch event, and exits 1 on any CRITICAL or HIGH finding.

| Finding | Severity | Meaning |
|---|---|---|
| `missing-drop` | CRITICAL | an estate port listens on a public address with no DROP |
| `landmine-armed` | HIGH | netfilter-persistent is enabled and `rules.v4` holds Docker/k8s NAT, so a boot replays stale IPs |
| `stale-dnat` / `stale-hostport` / `stale-kube-endpoint` | HIGH | NAT aims at an IP that is not live, so traffic is blackholed now |
| `allow-below-drop` | HIGH | an ACCEPT sits under the DROP and never matches |
| `not-persistent` | HIGH | a reboot drops the lockdown |
| `missing-allow`, `missing-drop-no-listener`, `snapshot-persistence`, `script-drift` | MEDIUM | a gap that is not live yet |
| `orphan-dnat`, `unverified-enforcement` | INFO | leftovers, or a rule present but not yet proven |

Desired state is the firewall manager's JSON (`servers`, `admin`,
`private`, `ports`, optional `host_ports`, `public`, `undecided`). The
governor names it, together with the manager's lockdown script path on each
host, its boot unit and the installer that remedies point at
(`integrations.firewall`: `desired_state`, `script`, `unit`, `installer`).
It is **off by default**: with nothing configured, the audit has no desired
state to judge against and says so instead of guessing. A CNI hostPort is
judged against live
pod IPs, not by opening a TCP connection, so the audit stays a pure read.
Ports bound only on loopback are not counted as exposed.

## k3s and iptables backends: `vpscfg fleet k3s [host ...]`

The outage behind this verb: after a reboot, k3s on one host crash-looped.
kube-router panicked on Debian 10's iptables-nft 1.8.2 (`Chain
'KUBE-ROUTER-INPUT' does not exist`), each restart left the filter table
without Docker's chains, and Docker could not start until the host was
switched to iptables-legacy. The likely trigger was netfilter-persistent
being disabled shortly before, which changed which iptables first wrote the
nft tables at boot.

`vpscfg fleet k3s` is a read (one fixed probe; rules are counted, never
printed). It reports each host's iptables backend and version, rule counts
per backend, the k3s unit state and restarts, this boot's panics, node
readiness and failing pods, and a **REBOOT-SAFE** verdict. It blocks on:
k3s on iptables-nft 1.8.2 (`k3s-nft-boot-race`), rules live in both
backends (`mixed-backends`), a crash loop, and k3s stopped but still enabled
(it would auto-start unsupervised at boot). Exit 1 on any CRITICAL or HIGH.

**The rule: on a k3s host, iptables is ONE backend, and on Debian 10 that is
legacy.** Plays declare `precheck: [k3s]` (vpsrun runs it through vpscfg
against every host the play touches, and refuses the play on failure).
tests/test_vpsrun.py makes that mandatory for any committed play that
touches netfilter-persistent, reboots a host, or stops or disables k3s or
Docker.

## Drill receipt, journal witness, read-only sql, secret-put

`vpscfg <host> drill <service> [--run] [--reason why]` runs a fixed scratch
compose project. The plan is the default. `--run` is a mutation through the
same gate as deploy. Teardown is `docker compose … down` with no volume flag.
A `restore-drill` receipt is printed and journaled only when the canary and
the teardown both succeed. The receipt is what `repair.check_request` already
requires; that check is unchanged. A contract with no drill block is BLOCKED,
and nothing is sent. The scratch directory is left in place.

`vpscfg journal verify --against DIR [stream]` compares a mirror copy. A
longer mirror, or a shared prefix that disagrees, is truncation (exit 1). A
longer local file is lag (exit 0 when the chain is intact). A missing mirror
is UNVERIFIED. `chain_verify` alone still cannot see a shortened tail.
Telemetry remains best-effort.

`vpscfg <host> sql <db> 'SELECT …'` is a read on both doors. The credential
stays on the host. The script is stdin, wrapped in `BEGIN READ ONLY` and a
statement timeout. A superuser role is refused before the user query. Rows
are masked. The journal records the host, the database, the query sha256, and
the exit code.

`vpscfg <host> secret-put --from-pipe NAME PATH` is a mutation. `--run`
requires a controlling terminal and a keystore command named in the governor
(`integrations.secret_source.command`, an argv list such as
`["keystore", "pipe", "--"]`; NO-PASTE.md F6a). The door appends NAME, runs it
without a shell and reads the secret from its stdout. With no source named,
`--from-pipe` refuses. The path must be an exact `secrets.sinks`
entry on exactly one contract. The journal records the name and the sha256.

## Replica hashes, never fingerprints, DNS pins, key census

`replica_of` is a verify check: sha256, or the certificate end date, of
a file on a source host against the copy on the contract host. A drift
fails. The remote command is `sha256sum` or `openssl x509 -noout -enddate`.
The file body is not returned. A dest certificate that is already expired
fails even when the dates match.

`vpscfg fleet never` fingerprints every contract `sync.never` path (hash
and mode) and journals that on the `never` stream, not the secrets census.
It does not rewrite the file and it does not escrow it. Contracts with no
`sync.never` are skipped. A hash or mode change since the last fingerprint
is drift. The first observation is the baseline.

`vpscfg fleet dns` checks `estate/dns-pins.yaml`. `zones: []`, or a zone
with no sha256, is UNPINNED: exit 1, no SSH. A pinned zone must match
that sha256 and pass `named-checkzone`. The file grants no write.

`vpscfg fleet authkeys` checks `estate/authorized-keys.yaml`. `allowlist:
{}` is UNPINNED: exit 1, no SSH. It is not a statement that no keys are
allowed. A file may be empty only with `pinned_empty: true`. The host
prints the mode and the sha256 of each non-comment line. Group- or
world-writable modes fail. A missing file fails. The line set must match
the pin. Key material is not a field this command stores.

## Coverage, duration, twins, pins, postgres shape, host OS

`vpscfg fleet coverage` joins live containers and pods to promoted contracts
and to `contracts/skeletons/`. A running workload with neither is uncovered.
Exit 1. Stopped containers are ignored. `kube-system`, `kube-public`,
`kube-node-lease`, and `cert-manager` are excluded here only.

`vpscfg fleet health` is the same shape as firewall and k3s: one fixed probe,
local judgment, journaled. The fleet ceiling is 600s. A contract's
`watch.unhealthy_max` may only tighten that. CrashLoop with a high restart
count alarms even when the current start is recent. Infra namespaces are
included.

`vpscfg fleet twins` reports a second live copy (the same `authority.name`,
or the same running container name on two hosts). It does not stop the loser.

`vpscfg fleet images` judges contracted workloads. No `image_policy` plus a
floating ref (`:latest` or untagged) is UNPINNED. `updates: watch` notes the
floating ref and does not fail for that alone. A digest mismatch always fails.
Digests are compared in constant time. This does not touch Watchtower.

`vpscfg fleet postgres` is a shape lint. Fewer than two contracts declaring
`postgres:` is UNPINNED and the command does not SSH and does not guess a
primary. A complete shape still needs exactly one primary and a
`pg_replication` verify on every replica.

`vpscfg fleet os`, and the end of `fleet watch`, read `estate/host-os.yaml`.
`eol: true` fails the sweep. A governed canonical host missing from the file
is UNPINNED. This is not a CVE scanner and it does not upgrade a host.
