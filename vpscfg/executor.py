"""The executor — the ONLY module that mutates a fleet host.

FIRING PIN INSTALLED per docs/STABILITY.md Stage 2, for the first graduated
scope (one container on the designated test host). Reverting the single marked
block in apply() restores the v0 NotReleased refusal — that revert IS the
ratchet's incident response.

Threats:
  - Protects against: free-form remote shell (every remote command is built
    from contract fields, never operator-supplied strings, and deny-scanned
    AGAIN at execution time after template substitution); unjournaled
    mutations (journal-or-refuse ordering, every step journaled); concurrent
    mutations (operation-owned locks retained on uncertain or partial outcomes); a failed deploy
    left in place (verify failure triggers rollback from THIS run's backup).
  - Does NOT protect against: a future edit deleting the gates along with the
    firing pin — the tests pin each gate's refusal independently, so that
    edit fails CI loudly; nor a compromised host lying about step success.
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from . import journal, k3sapply, lock, probe, secretmask, syncplan, outage, contracts
from . import verify as verify_mod
from .gates import Refused, deny_scan, assert_not_frozen


def released_sequence(contract, host):
    """The ordered step list the firing pin will execute — pure data, so the
    order itself is test-pinned long before the pin exists:

    lock -> backup -> sync -> build -> verify -> drift-confirm -> unlock

    verify failure => rollback from the backup taken in this run, then unlock.
    drift-confirm failure => report loudly (the deploy 'succeeded' but the host
    does not match git — exactly the 002_grants.sql class of gap).
    """
    if k3sapply.is_k3s(contract):
        # k3s: the "backup" is the live image recorded before the change;
        # verify failure sets it back (an exact revert, unlike an archive).
        return [
            {"step": "lock", "host": host},
            {"step": "record_previous_image"},
            {"step": "build", "where": "local"},
            {"step": "import", "cmd": k3sapply.IMPORT_CMD},
            {"step": "set_image"},
            {"step": "rollout_status"},
            {"step": "verify", "on_fail": "set_previous_image"},
            {"step": "confirm_live_image", "on_fail": "report"},
            {"step": "unlock", "host": host},
        ]
    return [
        {"step": "lock", "host": host},
        {"step": "backup", "cmd": [p["backup"] for p in contract.get("pre", []) if "backup" in p]},
        {"step": "sync", "dry_run": False},
        {"step": "build", "cmd": contract.get("build")},
        {"step": "verify", "on_fail": "rollback"},
        {"step": "drift_confirm", "on_fail": "report"},
        {"step": "unlock", "host": host},
    ]


class NotReleased(Refused):
    pass


# The longest any single executor step may run (local build/save, the image
# import). `vpsexec reconcile` derives how old an unproven lock must be from it.
MAX_STEP_SECONDS = 1800


def apply(guard, contract, verb, host, scope, planned_commands, reason=None,
          ssh=None, run_local=None, checks=None, latest_backup=None,
          preflight=None, event_sink=None, require_backup=False, ssh_stdin=None):
    """Run a mutation plan.

    Gate order matters and is load-bearing:
      1. policy judgment (verb/master switch/mode/posture/scope graduation)
      2. contract freeze
      3. deny-always sweep over every planned command
      4. journal the intent (cannot journal => cannot mutate)
      5. the firing pin — released_sequence, every step journaled

    The ssh/run_local/checks/latest_backup kwargs are TEST INJECTION points
    for the transport only; they cannot skip a gate (gates run above, inline).
    """
    guard.assert_verb(verb)
    guard.assert_mutation_allowed(verb, host, scope)
    assert_not_frozen(contract)
    if contract.get('monitor_only'):
        raise Refused('monitor_only contracts cannot mutate')

    for cmd in planned_commands:
        deny_scan(cmd, guard.deny_patterns())

    if not reason or not reason.strip():
        raise Refused("every mutation requires --reason \"why\" — the 2am "
                      "question is always 'why was this deployed'")
    verify_mod.validate_checks(contract)
    contracts._validate(contract, 'executor')
    if contract['host'] != host:
        raise Refused('contract host does not match execution host')
    if verb == 'deploy':
        syncplan.validate_sources(contract)

    journal.append("executor", {
        "event": "mutation_attempt",
        "verb": verb, "host": host, "scope": scope,
        "commands": planned_commands,
        "reason": reason,
        "released": True,
    })

    # ------------------------------------------------------------------
    # FIRING PIN — installed at Stage 2 (the first container scope on
    # the designated test host graduated). Executes released_sequence order: lock -> backup -> sync ->
    # build -> verify(-> rollback) -> drift-confirm -> unlock. Reverting this
    # block to `raise NotReleased(...)` restores the v0 scaffold refusal.
    # ------------------------------------------------------------------
    return _fire(guard, contract, verb, host, scope, planned_commands, reason,
                 ssh=ssh, run_local=run_local, checks=checks,
                 latest_backup=latest_backup, preflight=preflight,
                 event_sink=event_sink, require_backup=require_backup,
                 ssh_stdin=ssh_stdin)


def observe_outage(contract, host, ssh):
    """Live observations fail closed on daemon errors; absent Docker is explicit."""
    results = {}
    for kind, command in (
        ("containers", "command -v docker >/dev/null 2>&1 || { echo NO_DOCKER; exit 0; }; docker ps -a --format '{{.Names}}\\t{{.Image}}'"),
        ("volumes", "command -v docker >/dev/null 2>&1 || { echo NO_DOCKER; exit 0; }; docker volume ls --format '{{.Name}}'"),
    ):
        rc, out, _ = ssh(host, command)
        if rc:
            raise Refused("live outage observation failed: " + kind)
        results[kind] = sorted(out.strip().splitlines())
    containers = []
    for line in results["containers"]:
        if line == "NO_DOCKER":
            continue
        parts = line.split("\t")
        if len(parts) != 2 or not all(parts):
            raise Refused("malformed live container observation")
        containers.append({"name": parts[0], "image": parts[1]})
    volumes = [v for v in results["volumes"] if v != "NO_DOCKER"]
    assessment = outage.assess(contract, containers, volumes)
    if assessment["prevent"]:
        raise Refused(outage.render(contract["service"], host, assessment))
    return results


def _default_ssh(host, cmd, timeout=120):
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, cmd],
        capture_output=True, text=True, timeout=timeout)
    if r.returncode == 255:
        raise OSError('SSH connection lost; remote completion is unknown')
    return r.returncode, r.stdout, r.stderr


def _default_local(argv, timeout=300):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _step(verb, host, name, rc, detail=""):
    detail = secretmask.mask(detail or "")
    journal.append("executor", {"event": "step", "verb": verb, "host": host,
                                "step": name, "rc": rc, "detail": detail[:500]})
    print("  [%s] %s rc=%s %s" % ("ok" if rc == 0 else "FAIL", name, rc,
                                  detail[:200].strip()))
    if rc != 0:
        raise Refused("step %r failed (rc=%s): %s" % (name, rc, detail[:500]))


def _restore(guard, contract, host, ssh, backup):
    """tar-restore the pre-backup and re-run build. Used by the rollback verb
    and by deploy's verify-failure path. The backup path comes from probe's
    validated newest-backup glob, never from the operator."""
    deploy_dir = contract["deploy_dir"]
    restore_cmd = "tar xzf %s -C /" % shlex.quote(backup)
    deny_scan(restore_cmd, guard.deny_patterns())
    rc, out, err = ssh(host, restore_cmd)
    _step("rollback", host, "restore", rc, err or out)
    build = contract.get("build")
    if build:
        deny_scan(build, guard.deny_patterns())
        rc, out, err = ssh(host, "cd %s && %s" % (shlex.quote(deploy_dir), build))
        _step("rollback", host, "build", rc, err or out)


def _default_ssh_stdin(host, cmd, path, timeout=MAX_STEP_SECONDS):
    """Stream a local file into a fixed remote command's stdin (image import:
    no tarball ever lands on the host)."""
    with open(path, "rb") as f:
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, cmd],
                           stdin=f, capture_output=True, timeout=timeout)
    if r.returncode == 255:
        raise OSError("SSH connection lost during image import; remote state unknown")
    return (r.returncode, r.stdout.decode("utf-8", "replace"),
            r.stderr.decode("utf-8", "replace"))


def _k3s_state(contract, host, ssh):
    rc, out, err = ssh(host, k3sapply.read_state_cmd(contract))
    if rc != 0:
        raise Refused("cannot read live deployment state (rc=%s): %s"
                      % (rc, secretmask.mask(err or out or "")[:200]))
    return k3sapply.parse_state(out)


def _k3s_rollback_target(host, scope, live_image, journal_dir=None):
    """The image to roll back TO: the `previous_image` of the most recent
    completed door deploy of this scope — and only if that deploy's image is
    what is live now. Anything else (no door deploy yet, or the live image
    changed since) means the target is unknown: refuse."""
    import json as _json
    from pathlib import Path
    path = Path(journal_dir or journal.JOURNAL_DIR) / "executor.jsonl"
    last = None
    try:
        raw = journal._read_snapshot(path)
    except FileNotFoundError:
        raw = ""
    for line in raw.splitlines():
        try:
            rec = _json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("event") == "mutation_complete" and \
                rec.get("host") == host and rec.get("scope") == scope and rec.get("image"):
            last = rec
    if last is None or not last.get("previous_image"):
        raise Refused("no completed door deploy of %s is journaled — the rollback target is "
                      "unknown; deploy a known-good commit instead" % scope)
    if last["image"] != live_image:
        raise Refused("live image %s is not the last door-deployed image %s — something "
                      "changed it since; rollback target unknown" % (live_image, last["image"]))
    return last["previous_image"]


def _fire_k3s(guard, contract, verb, host, scope, ssh, run_local, ssh_stdin, checks,
              report, started):
    """k3s released sequence. `started` gets an entry the moment the running
    workload may have changed; the caller retains the host lock on failure
    after that point unless the previous image was provably restored."""
    deny = guard.deny_patterns()
    service = contract["service"]
    rollout_timeout = k3sapply.timeout_seconds(contract["apply"].get("rollout_timeout"))

    def remote(name, cmd, timeout=120):
        deny_scan(cmd, deny)
        return ssh(host, cmd, timeout=timeout)

    def rollout(name):
        rc, out, err = remote(name, k3sapply.rollout_status_cmd(contract),
                              timeout=rollout_timeout + 60)
        journal.append("executor", {"event": "step", "verb": verb, "host": host,
                                    "step": name, "rc": rc,
                                    "detail": secretmask.mask(err or out or "")[:500]})
        return rc == 0

    before = _k3s_state(contract, host, ssh)
    if before["pull_policy"] == "Always":
        raise Refused("imagePullPolicy is Always — a side-loaded image would be re-pulled "
                      "(registry pulls 401 on this fleet); set IfNotPresent in the manifest first")
    report("record-previous", image=before["image"], ready=before["ready"],
           replicas=before["replicas"])

    def set_and_confirm(name, image):
        """set image -> rollout -> verify -> re-read live state. True only when
        the Deployment provably runs `image` with every replica ready AND
        verify passes."""
        rc, out, err = remote(name, k3sapply.set_image_cmd(contract, image))
        journal.append("executor", {"event": "step", "verb": verb, "host": host,
                                    "step": name, "rc": rc,
                                    "detail": secretmask.mask(err or out or "")[:500]})
        if rc != 0:
            return False, False
        rolled = rollout(name + "-rollout-status")
        ok, results = checks(contract, host) if rolled else (False, [])
        if results:
            print(verify_mod.render(service, ok, results))
        live = _k3s_state(contract, host, ssh)
        confirmed = live["image"] == image and live["ready"] >= max(1, live["replicas"])
        report(name + "-confirm", ok=confirmed, image=live["image"],
               ready=live["ready"], replicas=live["replicas"])
        return rolled, ok and confirmed

    if verb == "rollback":
        # Exact inverse of the LAST door deploy of this scope — never
        # `rollout undo`, which after a set-back revision would bring the
        # failed image back and would also revert the whole pod template.
        target = _k3s_rollback_target(host, scope, before["image"])
        started.append(True)
        report("set-image", phase="started", image=target, previous=before["image"])
        _, ok = set_and_confirm("rollback-set-image", target)
        if not ok:
            raise Refused("k3s rollback to %s did not verify — lock retained, human eyes "
                          "needed" % target)
        journal.append("executor", {"event": "mutation_complete", "verb": verb, "host": host,
                                    "scope": scope, "image": target,
                                    "previous_image": before["image"]})
        return 0

    from .preflight import _source_manifest
    ref = k3sapply.image_ref(contract, _source_manifest(contract))
    if before["image"] == ref:
        raise Refused("live image is already %s — these sources are deployed; nothing to do" % ref)
    tmp = tempfile.mkdtemp(prefix="vpscfg-k3s-")
    try:
        tar = os.path.join(tmp, "image.tar")
        for name, argv in (("build", k3sapply.build_argv(contract, ref)),
                           ("save", k3sapply.save_argv(ref, tar))):
            deny_scan(" ".join(argv), deny)
            rc, out, err = run_local(argv, timeout=MAX_STEP_SECONDS)
            _step(verb, host, name, rc, err or out)
        report("image-built", image=ref)
        # The tag names the commit + sources read BEFORE the build; if either
        # moved while docker read them, the image under this tag is unknown.
        try:
            after_build = k3sapply.image_ref(contract, _source_manifest(contract))
        except Refused as r:
            after_build = "unknown (%s)" % r
        if after_build != ref:
            raise Refused("build sources changed while building (now %s) — refusing to "
                          "import an image whose tag does not name its contents" % after_build)
        deny_scan(k3sapply.IMPORT_CMD, deny)
        rc, out, err = ssh_stdin(host, k3sapply.IMPORT_CMD, tar)
        _step(verb, host, "import", rc, err or out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    started.append(True)
    report("set-image", phase="started", image=ref, previous=before["image"])
    rolled, ok = set_and_confirm("set-image", ref)
    report("verify", ok=ok, rollout=rolled)
    if not ok:
        report("restore", phase="started", image=before["image"])
        _, ok2 = set_and_confirm("restore-image", before["image"])
        report("restore-health", ok=ok2, image=before["image"])
        journal.append("executor", {"event": "deploy_failed_restore_attempted", "verb": verb,
                                    "host": host, "scope": scope, "restore_health": ok2,
                                    "previous_image": before["image"]})
        if ok2:
            # set image back is an exact revert (unlike an archive overlay),
            # and set_and_confirm re-read the live Deployment: it runs the
            # recorded image, all replicas ready, verify passing. Only then
            # may the lock be released.
            del started[:]
        raise Refused("k3s deploy verify FAILED (rollout %s) — previous image %s set back, "
                      "restore health %s%s" % (
                          "ok" if rolled else "FAILED", before["image"], "PASS" if ok2 else "FAIL",
                          "" if ok2 else "; lock retained, human eyes needed NOW"))
    journal.append("executor", {"event": "mutation_complete", "verb": verb, "host": host,
                                "scope": scope, "image": ref, "previous_image": before["image"]})
    return 0


def _fire(guard, contract, verb, host, scope, planned, reason,
          ssh=None, run_local=None, checks=None, latest_backup=None,
          preflight=None, event_sink=None, require_backup=False, ssh_stdin=None):
    """Execute the released sequence. Injection kwargs swap the transport for
    tests, never the gates — those already ran in apply()."""
    ssh = ssh or _default_ssh
    run_local = run_local or _default_local
    checks = checks or verify_mod.run_checks
    latest_backup = latest_backup or probe.latest_backup
    service = contract["service"]
    deploy_dir = contract.get("deploy_dir")  # absent for k3s contracts
    operator = journal.operator()  # the password database, never $USER
    sink = event_sink or (lambda event: None)
    def report(name, ok=True, **data):
        event = {"step": name, "ok": ok, **data}
        # Ordinary deploys need the same durable recovery evidence as repairs.
        journal.append('executor', {'event': 'operation_step', 'host': host,
                                   'scope': scope, 'operation_id': token, **event})
        sink(event)

    token = lock.acquire(host, operator, reason, runner=ssh)
    mutation_started = False
    retain_lock = False
    try:
        _step(verb, host, "lock", 0, "acquired")
        report("lock")
        guard.assert_mutation_allowed(verb, host, scope)
        assert_not_frozen(contract)
        if preflight:
            preflight()
        observe_outage(contract, host, ssh)
        report("outage-preflight")
        if k3sapply.is_k3s(contract):
            started = []
            try:
                return _fire_k3s(guard, contract, verb, host, scope, ssh, run_local,
                                 ssh_stdin or _default_ssh_stdin, checks, report, started)
            finally:
                mutation_started = bool(started)
        if verb == "rollback":
            backup = latest_backup(host, service)
            if not backup:
                raise Refused("no pre-backup found for %r on %s" % (service, host))
            mutation_started = True
            _restore(guard, contract, host, ssh, backup)
            ok, results = checks(contract, host)
            print(verify_mod.render(service, ok, results))
            if not ok:
                raise Refused("rollback completed but verify STILL fails — "
                              "the backup itself may be bad; human eyes needed")
            journal.append("executor", {"event": "mutation_complete", "verb": verb,
                                        "host": host, "scope": scope, "backup": backup})
            return 0

        # ---- deploy: released_sequence order ----
        current_backup = None
        backup_steps = [p for p in contract.get("pre", []) if "backup" in p]
        if not backup_steps:
            raise Refused("deployment requires a pre-change backup")
        if len(backup_steps) > 1:
            raise Refused("automatic restore requires one unambiguous pre-backup archive")
        ts = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
        for pre in contract.get("pre", []):
            if "backup" in pre:
                cmd = pre["backup"].format(service=service, ts=ts, deploy_dir=deploy_dir)
                deny_scan(cmd, guard.deny_patterns())
                parts = shlex.split(cmd)
                if len(parts) < 4 or parts[:2] not in (["tar", "czf"], ["tar", "-czf"]) or not re.fullmatch(
                        r"/root/" + re.escape(service) + r"-pre-[A-Za-z0-9-]+\.tar\.gz", parts[2]):
                    raise Refused("pre-backup must identify one explicit /root/service-pre-*.tar.gz archive")
                current_backup = parts[2]
                rc, out, err = ssh(host, "test ! -e %s" % shlex.quote(current_backup))
                _step(verb, host, "backup-new-path", rc, err or out)
                rc, out, err = ssh(host, cmd)
                _step(verb, host, "backup", rc, err or out)
        if backup_steps:
            # Test archive readability before changing service files.
            rc, out, err = ssh(host, "tar tzf %s >/dev/null" % shlex.quote(current_backup))
            _step(verb, host, "backup-verify", rc, err or out)
            report("backup", backup=current_backup)
        for argv in syncplan.rsync_argvs(contract, dry_run=False):
            deny_scan(" ".join(argv), guard.deny_patterns())
            report("sync", phase="started")
            mutation_started = True
            rc, out, err = run_local(argv)
            if rc in (10, 12, 20, 30, 35, 255) or rc < 0:
                raise OSError('rsync transport interrupted; remote completion is unknown (rc=%s)' % rc)
            if rc != 0 and current_backup:
                report('restore', phase='started', backup=current_backup)
                _restore(guard, contract, host, ssh, current_backup)
                restored, health = checks(contract, host)
                report('restore-health', ok=restored, backup=current_backup)
                journal.append('executor', {'event': 'sync_failed_restore_attempted',
                                           'host': host, 'scope': scope, 'rc': rc,
                                           'restore_health': restored, 'operation_id': token})
            _step(verb, host, "sync", rc, err or out)
        build = contract.get("build")
        build_rc = 0
        if build:
            deny_scan(build, guard.deny_patterns())
            report("build", phase="started")
            mutation_started = True
            build_rc, out, err = ssh(host, "cd %s && %s" % (shlex.quote(deploy_dir), build))
            journal.append("executor", {"event": "step", "verb": verb, "host": host,
                                        "step": "build", "rc": build_rc,
                                        "detail": secretmask.mask(err or out or "")[:500]})
            print("  [%s] build rc=%s" % ("ok" if build_rc == 0 else "FAIL", build_rc))
        ok, results = (checks(contract, host) if build_rc == 0 else (False, []))
        report("verify", ok=ok)
        if results:
            print(verify_mod.render(service, ok, results))
        if not ok:
            backup = current_backup
            if backup:
                report("restore", phase="started", backup=backup)
                _restore(guard, contract, host, ssh, backup)
                ok2, results2 = checks(contract, host)
                report("restore-health", ok=ok2, backup=backup)
                print(verify_mod.render(service, ok2, results2))
                journal.append("executor", {"event": "deploy_failed_restore_attempted",
                                            "verb": verb, "host": host, "scope": scope,
                                            "restore_health": ok2})
                raise Refused("deploy verify FAILED — archive restored from %s; rollback remains required "
                              "(health: %s; added files may remain)" % (backup, "PASS" if ok2 else "FAIL"))
            raise Refused("deploy verify FAILED and no pre-backup exists — "
                          "host left as-is; human eyes needed NOW")
        for argv in syncplan.rsync_argvs(contract, dry_run=True):
            rc, out, err = run_local(argv)
            clean = rc == 0 and not out.strip()
            report("drift-confirm", ok=clean)
            _step(verb, host, "drift-confirm", 0 if clean else 1, err or out)
        journal.append("executor", {"event": "mutation_complete", "verb": verb,
                                    "host": host, "scope": scope, "ts": ts})
        return 0
    except BaseException as exc:
        # An archive restore may leave added files. A lost SSH session may
        # leave a build running. Neither state permits another deployment.
        retain_lock = mutation_started or isinstance(exc, (subprocess.TimeoutExpired, OSError, KeyboardInterrupt, SystemExit))
        raise
    finally:
        original_error = sys.exc_info()[1]
        if retain_lock:
            print('  [BLOCKED] lock retained; reconcile operation %s before further mutation'
                  ' — next: vpsexec reconcile %s' % (token, host))
            try:
                report('lock-retained', ok=False, operation_id=token)
            except Exception as exc:
                print('  [ERROR] cannot persist retained-lock receipt: %s' % exc, file=sys.stderr)
                if original_error is None:
                    raise
        else:
            try:
                released = lock.release(host, runner=ssh, token=token)
                report("unlock", ok=released)
                if not released:
                    raise Refused("host lock release failed; inspect lock before another repair")
                print('  [ok] unlock')
            except Exception:
                print('  [BLOCKED] lock release failed; inspect operation %s' % token)
                if original_error is None:
                    raise
