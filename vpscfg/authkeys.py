"""authorized_keys and sudoers census. Hashes of lines, never the lines.

fleet keys proves this laptop can log in. It does not say who else can.
An empty allowlist is UNPINNED, not "nobody is allowed", unless a file
is explicitly pinned_empty. This module does not invent key hashes and
does not write authorized_keys.

Threats:
  - Protects against: an unpinned census being reported as "no extra
    keys"; a line set that drifted from the pin; a group- or
    world-writable keys file; key material in the output (the host
    prints sha256 of each non-comment line, and an unparseable line is
    dropped rather than shown).
  - Does NOT protect against: a pin that records an attacker key on
    purpose; access that is not an authorized_keys or sudoers line
    (agent forwarding, a key the pin forgot to list is a mismatch,
    which fails closed). This file grants no write.
"""
import hmac
import re
import shlex
import subprocess
from pathlib import Path

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False

from . import estate
from .gates import Refused
from .probe import HOST_RE
from .secretscensus import PATH_RE

PIN_NAME = "authorized-keys.yaml"
_SHA = re.compile(r"\A[0-9a-f]{64}\Z")
_MODE = re.compile(r"\A[0-7]{3,4}\Z")
_HASH_LINE = re.compile(r"\A([0-9a-f]{64})(?:\s+\S+)?\Z")


def pin_path():
    return estate.root() / "estate" / PIN_NAME


def _path_ok(path):
    return isinstance(path, str) and ".." not in path and PATH_RE.match(path) is not None


def _writable(mode):
    return int(mode, 8) & 0o022 != 0


def load(path=None):
    path = Path(path or pin_path())
    if not _HAVE_YAML:
        raise Refused("PyYAML is unavailable — key census fails closed")
    try:
        raw = path.read_text()
    except OSError as exc:
        raise Refused("authorized_keys pin %s unreadable (%s) — failing closed" % (path, exc))
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get("allowlist"), dict):
        raise Refused("authorized_keys pin must contain an allowlist mapping")
    if set(doc) - {"allowlist"}:
        raise Refused("authorized_keys pin has unknown keys")
    allowlist = {}
    for host, spec in doc["allowlist"].items():
        if not isinstance(host, str) or not HOST_RE.match(host):
            raise Refused("authorized_keys host %r fails validation" % host)
        if not isinstance(spec, dict) or set(spec) != {"files"} or not isinstance(spec.get("files"), list):
            raise Refused("authorized_keys host %r must be exactly {files: [...]}" % host)
        files = []
        for item in spec["files"]:
            if not isinstance(item, dict) or set(item) - {"path", "lines", "pinned_empty"} \
                    or not {"path", "lines"} <= set(item):
                raise Refused("authorized_keys file on %r needs path, lines, "
                              "and optional pinned_empty" % host)
            if not _path_ok(item["path"]):
                raise Refused("authorized_keys path %r fails validation" % item.get("path"))
            if not isinstance(item["lines"], list) or any(
                    not isinstance(line, str) or not _SHA.match(line) for line in item["lines"]):
                raise Refused("authorized_keys lines must be sha256 hex, not key material")
            pinned_empty = item.get("pinned_empty", False)
            if not isinstance(pinned_empty, bool):
                raise Refused("pinned_empty must be true or false")
            files.append({"path": item["path"], "lines": list(item["lines"]),
                          "pinned_empty": pinned_empty})
        allowlist[host] = {"files": files}
    return allowlist


def readiness(allowlist, governed):
    """Empty, partial, or unpinned-empty is UNPINNED. Do not SSH."""
    if not allowlist:
        return {"ok": False, "detail": "allowlist is empty — UNPINNED, not 'no keys allowed'"}
    governed = list(governed or [])
    missing = sorted(host for host in governed if host not in allowlist)
    extra = sorted(host for host in allowlist if host not in set(governed))
    if missing or extra:
        return {"ok": False, "detail": "pin does not match governed hosts"}
    for host, spec in allowlist.items():
        if not spec["files"]:
            return {"ok": False, "detail": "%s lists no files — UNPINNED" % host}
        for item in spec["files"]:
            if not item["lines"] and not item["pinned_empty"]:
                return {"ok": False,
                        "detail": "%s %s has an empty line list and is not pinned_empty — UNPINNED"
                        % (host, item["path"])}
    return {"ok": True, "detail": "pinned"}


def remote_command(path):
    """Mode, then sha256 of each non-comment line. The line stays in the pipe."""
    if not _path_ok(path):
        raise Refused("authorized_keys remote command refused")
    quoted = shlex.quote(path)
    return (
        "if [ ! -f %s ]; then echo MISSING; exit 0; fi; "
        "stat -c '%%a' -- %s; "
        "awk '/^[[:space:]]*#/ { next } /^[[:space:]]*$/ { next } { print }' %s "
        "| while IFS= read -r line; do printf '%%s' \"$line\" | sha256sum; done"
    ) % (quoted, quoted, quoted)


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


def _canon(items):
    return "\n".join(sorted(items))


def _same(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def judge_output(host, item, rc, out):
    """Set equality on line hashes. Unparseable output is not echoed."""
    name = "%s %s" % (host, item["path"])
    text = out or ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if any("ssh-" in line or "BEGIN " in line for line in lines):
        return {"name": name, "ok": False, "state": "UNVERIFIED",
                "detail": "unparseable key census"}
    if not lines or lines[0] == "MISSING":
        return {"name": name, "ok": False, "state": "MISSING",
                "detail": "file is missing"}
    if rc != 0:
        return {"name": name, "ok": False, "state": "UNVERIFIED",
                "detail": "census failed rc=%d" % rc}
    if not _MODE.match(lines[0]):
        return {"name": name, "ok": False, "state": "UNVERIFIED",
                "detail": "unparseable key census"}
    mode = lines[0]
    digests = []
    for line in lines[1:]:
        match = _HASH_LINE.match(line)
        if not match:
            return {"name": name, "ok": False, "state": "UNVERIFIED",
                    "detail": "unparseable key census"}
        digests.append(match.group(1))
    if _writable(mode):
        return {"name": name, "ok": False, "state": "MODE", "mode": mode,
                "detail": "mode %s is group- or world-writable" % mode}
    if not _same(_canon(item["lines"]), _canon(digests)):
        return {"name": name, "ok": False, "state": "MISMATCH", "mode": mode,
                "detail": "line set does not match the pin (%d live, %d pinned)" % (
                    len(digests), len(item["lines"]))}
    return {"name": name, "ok": True, "state": "ok", "mode": mode,
            "detail": "line set matches, mode %s" % mode}


def check(host, item, runner):
    rc, out = runner(host, remote_command(item["path"]))
    return judge_output(host, item, rc, out)


def run(allowlist, governed, runner=None):
    gate = readiness(allowlist, governed)
    if not gate["ok"]:
        return {"ok": False, "state": "UNPINNED", "detail": gate["detail"],
                "findings": [], "probed": False}
    runner = runner or _ssh
    findings = []
    for host in sorted(allowlist):
        for item in allowlist[host]["files"]:
            findings.append(check(host, item, runner))
    return {"ok": all(item["ok"] for item in findings), "state": "checked",
            "detail": "", "findings": findings, "probed": True}


def render(result):
    if result["state"] == "UNPINNED":
        return "fleet authkeys: UNPINNED — %s" % result["detail"]
    lines = []
    for item in result["findings"]:
        mark = "ok  " if item["ok"] else "!!  "
        lines.append("%s %s — %s" % (mark, item["name"], item["detail"]))
    lines.append("fleet authkeys: %d file(s), %d problem(s)" % (
        len(result["findings"]), sum(1 for item in result["findings"] if not item["ok"])))
    return "\n".join(lines)
