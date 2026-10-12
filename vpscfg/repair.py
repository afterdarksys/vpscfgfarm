"""Version 1 repair protocol through the governed deploy door.

Approvals and operation receipts are local controller state. Exactly-once claim
is limited to this controller database; running/unknown operations never retry.

Threats:
  - Protects against: replaying or transplanting an approval (only the SHA-256
    of the bearer is stored, and it binds one request digest); a host recipe
    becoming a shell command (package names and versions are shape-checked and
    never interpolated; apply records refused and does not call the executor
    or SSH); approving a host recipe from a live snapshot (preflight contact
    is none); a service-deploy request smuggling a change object.
  - Does NOT protect against: a later package-install or reboot muscle (none
    is installed here); a dirty service checkout blocking describe for every
    recipe, including host recipes; the operator's restore-drill veracity
    (shape and freshness are checked, the drill itself is not re-run);
    stage-0 mutation staying off (approve still requires the existing deploy
    gate). The raw approval bearer is never logged.
"""

import argparse
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from . import contracts, estate, executor, journal, syncplan, mapfile
from .control import Guard
from .gates import Refused, deny_scan, assert_not_frozen

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "journal" / "repair.sqlite3"
GOVERNOR = Path(estate.current().governor)
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:+~_-]{0,127}\Z")
# apt prints the archive as origin:release/suite, e.g. Debian-Security:12/stable-security.
ARCHIVE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:+~_-]*(?:/[A-Za-z0-9][A-Za-z0-9.:+~_-]*)*\Z")
RECIPE = "service-deploy/v1"
DISTRO_SECURITY_UPGRADE = "distro-security-upgrade/v1"
REBOOT = "reboot/v1"
SUPPORTED_RECIPES = (RECIPE, DISTRO_SECURITY_UPGRADE, REBOOT)
HOST_RECIPES = frozenset((DISTRO_SECURITY_UPGRADE, REBOOT))
HOST_NOT_GRADUATED = "host recipe is bound and not graduated; no command was sent"
PACKAGE_KEYS = frozenset(("name", "installed", "candidate", "archive"))
UPGRADE_KEYS = frozenset(("family", "packages", "reboot"))
REBOOT_KEYS = frozenset(("family", "packages", "reboot", "running_kernel"))
MAX_PACKAGES = 64


def now():
    return datetime.now(timezone.utc).isoformat()


def timestamp(text):
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise Refused("timestamps require a timezone")
    return value


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def file_hash(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Refused("repair snapshots require regular files")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_snapshot(contract):
    source = Path(contract.get("repo", "")).expanduser().resolve()
    if not contract.get("repo") or not source.is_dir():
        raise Refused("recipe requires a source repository")
    def git(*args):
        result = subprocess.run(["git", "-C", str(source), *args], capture_output=True, timeout=30)
        if result.returncode:
            raise Refused("cannot inspect source repository")
        return result.stdout
    if git("status", "--porcelain", "--untracked-files=all").strip():
        raise Refused("repair source must be a clean committed checkout")
    files = git("ls-files", "-z").decode().split("\0")
    contents = {f: {"sha256": file_hash(source / f), "mode": (source / f).stat().st_mode & 0o777}
                for f in files if f}
    # Submodules and symlinks are refused by file_hash; no unpinned content.
    return {"revision": git("rev-parse", "HEAD").decode().strip(), "content_digest": digest(contents)}


@contextmanager
def isolated_source(contract, expected):
    """Use private verified source bytes so concurrent checkout edits cannot ship."""
    source_snapshot(contract)
    source = Path(contract["repo"]).expanduser().resolve()
    result = subprocess.run(["git", "-C", str(source), "ls-files", "-z"], capture_output=True, check=True, timeout=30)
    with tempfile.TemporaryDirectory(prefix="vpscfg-repair-source-") as temporary:
        staging = Path(temporary)
        contents = {}
        for name in result.stdout.decode().split("\0"):
            if not name:
                continue
            source_file = source / name
            if source_file.is_symlink() or not source_file.is_file():
                raise Refused("source contains a symlink or submodule")
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, destination)
            contents[name] = {"sha256": file_hash(destination), "mode": destination.stat().st_mode & 0o777}
        if digest(contents) != expected["content_digest"]:
            raise Refused("source changed while preparing immutable deployment bytes")
        yield dict(contract, repo=str(staging))


def constraints(contract):
    doc = mapfile.resolve(contract.get("repo"))
    if doc:
        if doc.get("service") and doc["service"] != contract["service"]:
            raise Refused("source directory map names a different service")
        mapfile.enforce_hosts_allow(doc, [contract["host"]])
        mapfile.enforce_tier_cap(doc, "mutating")
        commands = [p["backup"] for p in contract.get("pre", []) if "backup" in p]
        commands += [" ".join(a) for a in syncplan.rsync_argvs(contract, dry_run=False)]
        commands += [contract.get("build") or ""]
        for command in commands:
            deny_scan(command, doc["constraints"]["deny_extra"])
            mapfile.enforce_forbid_flags(doc, command)
    return digest(doc) if doc else None


def describe(contract, root=ROOT):
    root = Path(root)
    code = {str(p.relative_to(root)): file_hash(p) for p in sorted((root / "vpscfg").glob("*.py"))}
    code["vpscfg-control.py"] = file_hash(root / "vpscfg-control.py")
    return {"schema_version": 1, "recipe": RECIPE, "supported_recipes": list(SUPPORTED_RECIPES),
            "host": contract["host"], "service": contract["service"],
            "contract_digest": digest(contract), "policy_digest": file_hash(GOVERNOR if root == ROOT else root / "vpscfg-control.json"),
            "executor_digest": digest(code), "source": source_snapshot(contract), "directory_constraints": constraints(contract)}


@contextmanager
def database(path=STATE):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    os.close(fd)
    db = sqlite3.connect(str(path), timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, payload TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)")
    db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, payload TEXT NOT NULL)")
    db.commit()
    try:
        yield db
    finally:
        db.close()


def check_request(value, contract, root=ROOT):
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("kind") != "repair-request":
        raise Refused("unsupported repair request")
    if any(not isinstance(value.get(k), str) or not value[k] for k in
           ("operation_id", "recipe", "host", "service", "generated_at", "expires_at", "plan_checksum")):
        raise Refused("request is missing required string fields")
    if not NAME.fullmatch(value.get("operation_id", "")) or value.get("recipe") not in SUPPORTED_RECIPES:
        raise Refused("invalid operation or recipe")
    if value.get("host") != contract["host"] or value.get("service") != contract["service"]:
        raise Refused("request host/service mismatch")
    if value.get("binding") != describe(contract, root):
        raise Refused("contract, policy, executor or source changed")
    generated, expires, current = timestamp(value["generated_at"]), timestamp(value["expires_at"]), timestamp(now())
    if not generated <= current < expires or (expires - generated).total_seconds() > 86400:
        raise Refused("expired or invalid request window")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", value.get("plan_checksum", "")):
        raise Refused("request must bind an exact goodfarm plan")
    proof = value.get("rollback_proof", {})
    if not isinstance(proof, dict) or proof.get("kind") != "restore-drill" or proof.get("verified") is not True or \
            proof.get("host") != contract["host"] or proof.get("service") != contract["service"] or \
            not proof.get("reference") or not proof.get("verifier") or not isinstance(proof.get("tested_at"), str) or \
            not 0 <= (current - timestamp(proof["tested_at"])).total_seconds() <= 30 * 86400:
        raise Refused("recipe requires a recent, scoped restore drill record")
    if not contract.get("verify") or not any("backup" in p for p in contract.get("pre", [])):
        raise Refused("recipe requires contract backup and verification steps")
    limit = contract.get("blast_radius", {}).get("max_other_containers")
    if type(limit) is not int or limit < 0:
        raise Refused("recipe requires an explicit max_other_containers blast-radius limit")
    if not value.get("ownership_digest") or not value.get("affected_services"):
        raise Refused("recipe requires reviewed ownership and dependencies")
    _check_recipe_shape(value)
    return value


def _token(value, pattern):
    return isinstance(value, str) and ".." not in value and pattern.fullmatch(value) is not None


def _check_package(item):
    if not isinstance(item, dict) or set(item) != PACKAGE_KEYS:
        raise Refused("invalid package record")
    if not _token(item["name"], TOKEN_RE):
        raise Refused("invalid package name")
    for key in ("installed", "candidate"):
        if item[key] == "":
            continue
        if not _token(item[key], VERSION_RE):
            raise Refused("invalid package version")
    archive = item["archive"]
    if archive != "" and not (_token(archive, ARCHIVE_RE) and len(archive) <= 128):
        raise Refused("invalid package archive")


def _check_host_change(recipe, change):
    if not isinstance(change, dict):
        raise Refused("host recipe requires a reviewed change")
    if recipe == DISTRO_SECURITY_UPGRADE:
        if set(change) != UPGRADE_KEYS:
            raise Refused("invalid upgrade change")
        if change.get("reboot") is not False:
            raise Refused("upgrade reboot flag must be false")
        if change.get("family") not in ("debian", "rpm"):
            raise Refused("invalid package family")
        packages = change.get("packages")
        if not isinstance(packages, list) or not 1 <= len(packages) <= MAX_PACKAGES:
            raise Refused("invalid package list")
        seen = set()
        for item in packages:
            _check_package(item)
            if item["name"] in seen:
                raise Refused("duplicate package name")
            seen.add(item["name"])
        return
    if set(change) != REBOOT_KEYS:
        raise Refused("invalid reboot change")
    if change.get("reboot") is not True:
        raise Refused("reboot flag must be true")
    if change.get("packages") != []:
        raise Refused("reboot change must not name packages")
    if change.get("family") not in ("debian", "rpm"):
        raise Refused("invalid package family")
    if not _token(change.get("running_kernel"), TOKEN_RE):
        raise Refused("invalid running kernel")


def _check_recipe_shape(value):
    if value["recipe"] == RECIPE:
        if "change" in value:
            raise Refused("service deploy does not accept a change object")
        return
    if value.get("transitions") != []:
        raise Refused("host recipe does not accept asset transitions")
    _check_host_change(value["recipe"], value.get("change"))


def live_snapshot(contract, ssh=None, run_local=None):
    observation = executor.observe_outage(contract, contract["host"], ssh or executor._default_ssh)
    outputs = []
    for argv in syncplan.rsync_argvs(contract, dry_run=True):
        rc, out, _ = (run_local or executor._default_local)(argv)
        if rc:
            raise Refused("cannot observe deployment drift before approval")
        outputs.append(out)
    return digest({"outage": observation, "sync_diff": outputs})


def approve(value, contract, guard, approve_digest, path=STATE, root=ROOT, observe=None):
    check_request(value, contract, root)
    assert_not_frozen(contract)
    guard.assert_verb("deploy")
    guard.assert_mutation_allowed("deploy", contract["host"], "%s:%s/%s" %
                                  (contract.get("scope_kind", "service"), contract["host"], contract["service"]))
    if approve_digest != digest(value):
        raise Refused("approval must name the exact request digest")
    approval = secrets.token_hex(32)
    if value["recipe"] in HOST_RECIPES:
        preflight = digest({"recipe": value["recipe"], "change": value["change"], "contact": "none"})
    else:
        preflight = (observe or live_snapshot)(contract)
    payload = {"approved_at": now(), "operator": os.getuid(), "preflight": preflight,
               "request_digest": digest(value)}
    journal.append("repair", {"event": "approved", "operation_id": value["operation_id"], "request_digest": digest(value)})
    with database(path) as db, db:
        db.execute("INSERT INTO approvals(id,request_digest,payload) VALUES(?,?,?)",
                   (hashlib.sha256(approval.encode()).hexdigest(), digest(value), json.dumps(payload)))
    return {"schema_version": 1, "approval": approval, "request_digest": digest(value), "operation_id": value["operation_id"],
            "expires_at": value["expires_at"], "preflight_valid_seconds": 300}


def status(operation_id, path=STATE):
    if not NAME.fullmatch(operation_id):
        raise Refused("invalid operation ID")
    with database(path) as db:
        row = db.execute("SELECT payload FROM operations WHERE id=?", (operation_id,)).fetchone()
    if row is None:
        return {"schema_version": 1, "operation_id": operation_id, "state": "not-found"}
    value = json.loads(row[0])
    if value["state"] == "running":
        value["state"] = "execution-unknown"
        value["detail"] = "May still be running or interrupted; never retry this operation"
    return value


def execute(value, contract, guard, approval, path=STATE, root=ROOT, observe=None, apply=None, recheck=None):
    operation_id = value.get("operation_id", "")
    if not isinstance(operation_id, str) or not NAME.fullmatch(operation_id):
        raise Refused("invalid operation ID")
    request_digest = digest(value)
    with database(path) as db:
        row = db.execute("SELECT request_digest FROM operations WHERE id=?", (operation_id,)).fetchone()
        if row:
            if row[0] != request_digest:
                raise Refused("operation ID already binds a different request")
            return status(operation_id, path)
    check_request(value, contract, root)
    scope = "%s:%s/%s" % (contract.get("scope_kind", "service"), contract["host"], contract["service"])
    guard.assert_verb("deploy")
    guard.assert_mutation_allowed("deploy", contract["host"], scope)
    host_recipe = value.get("recipe") in HOST_RECIPES
    if host_recipe:
        current_guard = (recheck or Guard.load)()
        current_guard.assert_verb("deploy")
        current_guard.assert_mutation_allowed("deploy", contract["host"], scope)
    receipt = {"schema_version": 1, "kind": "repair-receipt", "operation_id": operation_id,
               "request_digest": request_digest, "plan_checksum": value["plan_checksum"],
               "host": contract["host"], "service": contract["service"], "binding": value["binding"],
               "state": "running", "started_at": now(), "finished_at": None, "steps": []}
    if host_recipe:
        receipt["state"] = "refused"
        receipt["error"] = HOST_NOT_GRADUATED
        receipt["finished_at"] = now()
        receipt["steps"] = [{"step": "host-recipe", "ok": False}]
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute("SELECT request_digest FROM operations WHERE id=?", (operation_id,)).fetchone()
        if existing:
            db.rollback()
            if existing[0] != request_digest:
                raise Refused("operation identity conflict")
            return status(operation_id, path)
        approval_hash = hashlib.sha256(approval.encode()).hexdigest()
        row = db.execute("SELECT request_digest,payload,used FROM approvals WHERE id=?", (approval_hash,)).fetchone()
        if row is None or row[0] != request_digest or row[2]:
            raise Refused("approval missing, consumed, or bound to another request")
        approved = json.loads(row[1])
        if not 0 <= (timestamp(now()) - timestamp(approved["approved_at"])).total_seconds() <= 300:
            raise Refused("approval preflight expired")
        db.execute("UPDATE approvals SET used=1 WHERE id=?", (approval_hash,))
        db.execute("INSERT INTO operations VALUES(?,?,?)", (operation_id, request_digest, json.dumps(receipt)))
        db.commit()
    if host_recipe:
        journal_record = journal.append("repair", {"event": "refused", "operation_id": operation_id,
                                                   "recipe": value["recipe"], "request_digest": request_digest})
        receipt["journal"] = {"stream": "repair", "record_digest": digest(journal_record)}
        with database(path) as db, db:
            db.execute("UPDATE operations SET payload=? WHERE id=?", (json.dumps(receipt), operation_id))
        return receipt

    def persist():
        with database(path) as db, db:
            db.execute("UPDATE operations SET payload=? WHERE id=?", (json.dumps(receipt), operation_id))

    def step(event):
        receipt["steps"].append(event)
        persist()

    def preflight():
        check_request(value, contract, root)
        current_guard = (recheck or Guard.load)()
        current_guard.assert_mutation_allowed("deploy", contract["host"], scope)
        if not 0 <= (timestamp(now()) - timestamp(approved["approved_at"])).total_seconds() <= 300 or \
                (observe or live_snapshot)(contract) != approved["preflight"]:
            raise Refused("live preconditions changed since approval")

    try:
        journal_record = journal.append("repair", {"event": "submitted", "operation_id": operation_id,
                                                   "request_digest": request_digest})
        receipt["journal"] = {"stream": "repair", "record_digest": digest(journal_record)}
        persist()
        planned = [p["backup"] for p in contract.get("pre", []) if "backup" in p]
        planned += [" ".join(a) for a in syncplan.rsync_argvs(contract, dry_run=False)]
        if contract.get("build"):
            planned.append(contract["build"])
        with isolated_source(contract, value["binding"]["source"]) as isolated:
            result = (apply or executor.apply)(guard, isolated, "deploy", contract["host"], scope, planned,
                                              reason="goodfarm " + operation_id, preflight=preflight, event_sink=step,
                                              require_backup=True)
            if result != 0:
                raise Refused("executor did not return success")
        receipt["state"] = "applied"
    except Refused as exc:
        receipt["state"] = "rollback-required" if any(e.get("step") in ("sync", "build", "restore") for e in receipt["steps"]) else "refused"
        receipt["error"] = str(exc)[:1000]
    except BaseException:
        receipt["state"] = "execution-unknown"
        receipt["error"] = "Execution interrupted; inspect operation and host lock before further action"
        receipt["finished_at"] = now()
        persist()
        raise
    receipt["finished_at"] = now()
    persist()
    return receipt


def cli(argv, host, service, guard):
    parser = argparse.ArgumentParser(prog="vpscfg repair protocol")
    parser.add_argument("--repair-action", required=True, choices=("describe", "approve", "apply", "status"))
    parser.add_argument("--request", type=Path)
    parser.add_argument("--approve-digest")
    parser.add_argument("--approval-file", type=Path)
    parser.add_argument("--operation-id")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args(argv[3:])
    if not NAME.fullmatch(service):
        raise Refused("invalid service")
    contract = contracts.load(service)
    if contract["host"] != host:
        raise Refused("contract host mismatch")
    if args.repair_action == "describe":
        result = describe(contract)
    elif args.repair_action == "status":
        result = status(args.operation_id or "")
        if result.get("host", host) != host or result.get("service", service) != service:
            raise Refused("operation scope mismatch")
    else:
        if not args.request or args.request.stat().st_size > 16 * 1024 * 1024:
            raise Refused("request file required and limited to 16 MiB")
        value = json.loads(args.request.read_text())
        if args.repair_action == "approve":
            result = approve(value, contract, guard, args.approve_digest)
        else:
            if not args.run or not args.approval_file or args.approval_file.stat().st_size > 1024:
                raise Refused("apply requires --run and a single-use --approval-file (at most 1 KiB)")
            approval = args.approval_file.read_text().strip()
            with redirect_stdout(sys.stderr):
                result = execute(value, contract, guard, approval)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("state") in (None, "applied") else 1
