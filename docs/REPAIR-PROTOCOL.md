# Governed repair protocol v1

`vpscfg/repair.py` implements the machine interface used by goodfarm 0.3.
goodfarm is the repair-planning module of badfarm, a read-only discovery
companion that inventories infrastructure and emits findings; goodfarm binds
those findings to vpscfgfarm contracts and plans repairs against them. badfarm
is to be released separately. The existing sanctioned wrapper remains the
entry point. No new governor permission
is granted and no production policy file is changed by this feature.

```text
python3 vpscfg-control.py HOST deploy SERVICE --repair-action describe
python3 vpscfg-control.py HOST deploy SERVICE --repair-action approve --request FILE --approve-digest sha256:DIGEST
python3 vpscfg-control.py HOST deploy SERVICE --repair-action apply --request FILE --approval-file PRIVATE_FILE --run
python3 vpscfg-control.py HOST deploy SERVICE --repair-action status --operation-id OPERATION_ID
```

Run from the vpscfgfarm checkout so the wrapper can import its package. The
goodfarm client sets this working directory. Describe/status perform no target
mutations. Approve performs live read-only preflight and records local approval;
apply requires `--run`, a matching single-use approval, and all normal executor
gates. Protocol JSON goes to stdout and execution progress goes to stderr.

## Request and authorization

Schema 1 `repair-request` includes an operation ID, exact goodfarm plan checksum,
host/service, generated/expiry times, recipe ID, source/executor binding,
ownership digest, affected services, restore-drill record and expected asset
transitions. The implemented recipe is `service-deploy/v1`.

The binding names the clean source Git revision and tracked file content/mode
digest, the parsed contract digest, governor file digest, package/wrapper code
digest and source directory constraints. Source symlinks and submodules are refused.
Approval names the canonical SHA-256 request digest explicitly; edits cannot reuse
an approval. Private staged source files are rehashed against the approved content
before being used for deployment.

The source map can restrict hosts, tier, commands and flags. It cannot grant
permission. A contract requires backup/verification steps and a reviewed
`blast_radius.max_other_containers` limit. Its recent restore-drill reference is
operator-supplied evidence; scope, freshness and shape are checked, while its
veracity is part of the operator's review.

Approval is subject to the governor and uses local OS access as its authentication
boundary. It does not create a separate identity provider. The returned random
approval value is a bearer capability; only its hash is stored in the executor DB.
It binds an operation request and live preflight snapshot and expires after five
minutes or the request expiry, whichever is earlier. It cannot bypass a freeze,
deny floor, ungraduated scope, disabled master switch or host posture.

## Execution, rollback and crash semantics

Under a SQLite immediate transaction, apply consumes the approval and inserts a
running operation before invoking the executor. An existing operation ID returns
its existing receipt; a different request at that ID is refused. This prevents
repeat execution after client timeouts. The database is local to this controller:
never discard it to clear a failed operation, and do not assume a different
controller database inherits its idempotency history.

The executor acquires its existing remote host lock, rechecks authorization and
live conditions, and refuses stale or changed approval snapshots. Both container
and volume observations must succeed. Volume twins and excess container count
prevent mutation. These live outage checks also run for normal executor apply,
not only the protocol or the displayed plan.

Deployment creates a distinct backup, checks archive readability, syncs verified
source bytes, builds, verifies the contract, confirms a clean checksum-based dry-run sync, and
unlocks. A known partial sync or failed build/verification can restore only the newly observed backup
from this operation. It never chooses an older archive merely because no new one
was produced. Drift or unlock failure prevents a successful operation result.
After partial mutation or an archive restoration attempt, the lock remains held:
an archive overlay cannot prove that added files were removed. SSH timeout,
disconnect, and interrupted rsync also retain the lock because remote completion
is unknown. Follow [RECOVERY.md](RECOVERY.md); a different operation ID must not
be used to bypass this state. The remote owner metadata has its own operation
identifier, recorded alongside protocol steps in the local executor journal.

Every protocol step is persisted in `journal/repair.sqlite3`, with full SQLite
synchronization. Receipts contain operation/request/plan identities, source binding,
timestamps, step outcomes, backup references and journal linkage. States include
applied, refused, rollback-required and execution-unknown. Archive restoration
is an overlay: added files may remain, so even passing restore health checks
retain rollback-required until an operator establishes complete recovery. Readability
of an archive is not proof of a full application restore; the separate restore
drill remains necessary.

An interrupted process may leave the operation running and the host lock held.
Status reports such a record as execution-unknown, since it could still be active.
It never restarts it. Inspect the actual host and journal before making another
repair decision. Snapshot the operation database through SQLite backup, including
committed WAL data. Keep operation history with the associated goodfarm store.

Goodfarm independently scans after completion and validates the receipt before
claiming both execution and recovery. An applied receipt alone does not prove the
finding was repaired, and a clean scan alone does not prove the executor ran.

## Tests

`tests/test_repair_protocol.py` covers digest binding, source changes, single-use
approval/replay, interruption, governor rechecks, outage refusals, backup freshness
and post-apply drift. The badfarm repository (released separately) includes an
opt-in end-to-end wrapper test with fake SSH/rsync and disabled fixture
telemetry:

```bash
python3 -m unittest discover -s tests
# From badfarm:
VPSCFGFARM_TEST_REPO=../vpscfgfarm python3 -m unittest tests.test_repair_integration
```

No test requires or authorizes real fleet mutation. Live qualification and
additional scope graduation remain explicit operational decisions.

Automatic backup requires one `tar czf` or `tar -czf` command naming an explicit
`/root/{service}-pre-{ts}.tar.gz` archive. An existing archive path is refused.
