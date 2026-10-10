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
to continue. `vpsexec` also retains its lock after transport interruption.

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
   reconcile partial files and any continuing processes before releasing the
   lock. There is intentionally no automatic stale-lock expiry or force-unlock
   CLI. Emergency manual recovery requires the operator to verify the plan and
   record the evidence; do not broadly unlock governor scopes to work around it.
5. Confirm the owner operation still matches the investigated incident before
   removing its lock. Record who reconciled it and what proved it safe. Use a new
   reviewed operation for subsequent deployment; never discard repair receipts
   or reuse a consumed approval.

If journal writes fail, mutation must stop. Restore storage availability first.
An incomplete final record refuses future appends; preserve the original stream
and reconcile it with operation receipts and host state before repairing it.
Never silently truncate history to make chain verification green.

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
