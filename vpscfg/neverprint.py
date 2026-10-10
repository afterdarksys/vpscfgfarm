"""Fingerprints of sync.never paths: hash and mode, never the file.

sync.never is the list of host files a deploy must not overwrite
(.env.production, a host Dockerfile, and, when a contract says so,
k3s.yaml). The secrets census covers credential paths. This sibling
covers every never-path, including ones that are not credentials, and
journals on its own stream. It does not escrow them and it does not
rewrite them.

Threats:
  - Protects against: a load-bearing host file changing hash or mode
    without a journaled fingerprint to compare; a relative never-path
    being joined outside deploy_dir; the file body leaving the host
    (the remote command is sha256sum and stat).
  - Does NOT protect against: the first observation (there is no earlier
    fingerprint to differ from); a contract that never lists the path.
    A missing file is a problem. Contents are never stored.
"""
import hmac
import re
import shlex
import subprocess

from . import journal
from .gates import Refused
from .probe import HOST_RE
from .secretscensus import PATH_RE
from .syncplan import protected_path

_MODE = re.compile(r"\A[0-7]{3,4}\Z")
_SHA = re.compile(r"\A[0-9a-f]{64}\Z")


def _same(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def never_paths(contract):
    """Absolute sync.never paths. No sync.never → empty, not an error.

    Relative entries join deploy_dir after protected_path. A k3s contract
    with no deploy_dir may only list absolute entries. Dot-dot refuses.
    """
    if not isinstance(contract, dict):
        raise Refused("neverprint contract is not a mapping")
    sync = contract.get("sync")
    if not isinstance(sync, dict):
        return []
    never = sync.get("never")
    if not never:
        return []
    if not isinstance(never, list):
        raise Refused("sync.never must be a list")
    deploy = contract.get("deploy_dir")
    out = []
    for entry in never:
        cleaned = protected_path(entry)
        if ".." in cleaned:
            raise Refused("sync.never %r fails validation — no dot-dot" % entry)
        if cleaned.startswith("/"):
            full = cleaned
        else:
            if not isinstance(deploy, str) or not deploy.startswith("/") or deploy == "/":
                raise Refused("sync.never %r is relative and the contract has "
                              "no deploy_dir" % entry)
            if ".." in deploy:
                raise Refused("deploy_dir %r fails validation — no dot-dot" % deploy)
            full = "%s/%s" % (deploy.rstrip("/"), cleaned)
        if ".." in full or not PATH_RE.match(full):
            raise Refused("never path %r fails validation — absolute, plain "
                          "characters, no dot-dot" % full)
        out.append(full)
    return out


def remote_command(path):
    """sha256 and mode. Never cat."""
    if ".." in path or not PATH_RE.match(path or ""):
        raise Refused("never path %r fails validation" % path)
    quoted = shlex.quote(path)
    return ("sha256sum -- %s 2>/dev/null; stat -c '%%a %%s' -- %s 2>/dev/null"
            % (quoted, quoted))


def _ssh(host, remote):
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    from . import secretmask, sshconfig
    known = sshconfig.load()
    if known and host not in known:
        raise Refused("host %r is not an alias in ~/.ssh/config" % host)
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, remote],
        capture_output=True, text=True, timeout=60)
    out = secretmask.mask(result.stdout)
    if result.returncode == 0 and (out or "").startswith("<output withheld"):
        return 1, ""
    return result.returncode, out


def _parse(path, out):
    lines = [line for line in (out or "").splitlines() if line.strip()]
    if len(lines) < 2:
        return {"path": path, "exists": False}
    digest = lines[0].split()[0]
    mode, size = (lines[1].split() + ["", ""])[:2]
    if not _SHA.match(digest) or not _MODE.match(mode):
        return {"path": path, "exists": False}
    try:
        size_i = int(size)
    except ValueError:
        return {"path": path, "exists": False}
    return {"path": path, "exists": True, "sha256": digest, "mode": mode, "size": size_i}


def fingerprint(contract, runner=None):
    """[{path, exists, sha256, mode, size}]. Missing is a fact, not a body."""
    host = contract.get("host")
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    runner = runner or _ssh
    found = []
    for path in never_paths(contract):
        _rc, out = runner(host, remote_command(path))
        found.append(_parse(path, out))
    return found


def last(service, journal_dir=None):
    """Latest journaled never-fingerprints for a service: {path: {sha256, mode}}."""
    import json
    try:
        text = journal.read_stream("never", journal_dir)
    except OSError as exc:
        raise Refused("never journal unreadable (%s) — failing closed" % exc)
    latest = {}
    for raw in text.splitlines():
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if rec.get("event") != "neverprint" or rec.get("service") != service:
            continue
        for item in rec.get("files") or []:
            if item.get("exists") and item.get("path"):
                latest[item["path"]] = {"sha256": item.get("sha256"), "mode": item.get("mode")}
            elif item.get("path"):
                latest.pop(item["path"], None)
    return latest


def judge(files, previous):
    """Problems since the last fingerprint. First sight is not drift.

    A missing file is a problem. Hash or mode change is drift. The file
    body is not a field on either side.
    """
    problems = []
    previous = previous or {}
    for item in files or []:
        if not item.get("exists"):
            problems.append({"path": item.get("path"), "kind": "MISSING",
                             "detail": "declared sync.never path is gone"})
            continue
        before = previous.get(item["path"])
        if not before:
            continue
        hash_same = _same(before.get("sha256"), item.get("sha256"))
        mode_same = _same(str(before.get("mode") or ""), str(item.get("mode") or ""))
        if not hash_same and not mode_same:
            problems.append({"path": item["path"], "kind": "CHANGED",
                             "detail": "hash and mode changed"})
        elif not hash_same:
            problems.append({"path": item["path"], "kind": "HASH",
                             "detail": "hash changed"})
        elif not mode_same:
            problems.append({"path": item["path"], "kind": "MODE",
                             "detail": "mode changed from %s to %s" % (
                                 before.get("mode"), item.get("mode"))})
    return problems


def report(contract, runner=None, journal_dir=None, record=None):
    """Fingerprint, compare, journal on the never stream. Not the secrets stream."""
    files = fingerprint(contract, runner=runner)
    problems = judge(files, last(contract.get("service"), journal_dir=journal_dir))
    payload = {"event": "neverprint", "service": contract.get("service"),
               "host": contract.get("host"), "files": files}
    if record is None:
        journal.append("never", payload)
    else:
        record(payload)
    return files, problems


def render(service, files, problems):
    by_path = dict((item["path"], item) for item in problems)
    lines = []
    for item in files:
        problem = by_path.get(item["path"])
        if not item.get("exists"):
            lines.append("!!   %-24s %s  MISSING" % (service, item["path"]))
        elif problem:
            lines.append("!!   %-24s %s  %s  sha256=%s…  mode=%s" % (
                service, item["path"], problem["detail"], item["sha256"][:16], item["mode"]))
        else:
            lines.append("ok   %-24s %s  sha256=%s…  mode=%s" % (
                service, item["path"], item["sha256"][:16], item["mode"]))
    return "\n".join(lines)
