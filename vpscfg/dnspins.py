"""DNS zone pins. Verify-first. An empty pin file is UNPINNED.

Authoritative DNS hosts stay frozen until zone files are under contract. This module
does not apply a zone and does not invent a hash. With zones: [] it
reports UNPINNED and does not SSH. A listed zone with no sha256 is the
same answer.

Threats:
  - Protects against: a zone file whose on-host sha256 drifted from the
    reviewed pin; a zone file named-checkzone rejects; an unpinned estate
    being reported as clean; operator strings reaching the remote command
    (host, path and zone name come from the pin file and are validated).
  - Does NOT protect against: a pin that was reviewed wrong. The sha256
    is the on-host hash the operator recorded. This file grants no write.
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

PIN_NAME = "dns-pins.yaml"
_SHA = re.compile(r"\A[0-9a-f]{64}\Z")
_HASH_LINE = re.compile(r"\A([0-9a-f]{64})(?:\s|\Z)")
_ZONE_KEYS = frozenset(("name", "host", "path", "sha256"))


def pin_path():
    return estate.root() / "estate" / PIN_NAME


def _path_ok(path):
    return isinstance(path, str) and ".." not in path and PATH_RE.match(path) is not None


def load(path=None):
    path = Path(path or pin_path())
    if not _HAVE_YAML:
        raise Refused("PyYAML is unavailable — DNS pins fail closed")
    try:
        raw = path.read_text()
    except OSError as exc:
        raise Refused("DNS pin %s unreadable (%s) — failing closed" % (path, exc))
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get("zones"), list):
        raise Refused("DNS pin must contain a zones list")
    if set(doc) - {"zones"}:
        raise Refused("DNS pin has unknown keys")
    zones = []
    for spec in doc["zones"]:
        if not isinstance(spec, dict) or set(spec) - _ZONE_KEYS or not {"name", "host", "path"} <= set(spec):
            raise Refused("DNS zone entries require name, host, path, and optional sha256")
        if not isinstance(spec["name"], str) or not HOST_RE.match(spec["name"]):
            raise Refused("DNS zone name %r fails validation" % spec.get("name"))
        if not isinstance(spec["host"], str) or not HOST_RE.match(spec["host"]):
            raise Refused("DNS zone host %r fails validation" % spec.get("host"))
        if not _path_ok(spec["path"]):
            raise Refused("DNS zone path %r fails validation" % spec.get("path"))
        digest = spec.get("sha256") or ""
        if digest and (not isinstance(digest, str) or not _SHA.match(digest)):
            raise Refused("DNS zone %r sha256 must be 64 lowercase hex" % spec["name"])
        zones.append({"name": spec["name"], "host": spec["host"],
                      "path": spec["path"], "sha256": digest})
    return zones


def readiness(zones):
    """UNPINNED until every zone has a sha256. Callers must not SSH otherwise."""
    if not zones:
        return {"ok": False, "detail": "no zones pinned"}
    for zone in zones:
        if not zone.get("sha256"):
            return {"ok": False, "detail": "zone %s has no sha256 — UNPINNED" % zone.get("name")}
    return {"ok": True, "detail": "pinned"}


def remote_command(zone):
    if not zone.get("sha256") or not _path_ok(zone.get("path")) or not HOST_RE.match(zone.get("name") or ""):
        raise Refused("DNS remote command refused — zone is not pinned")
    path = shlex.quote(zone["path"])
    name = shlex.quote(zone["name"])
    return "sha256sum -- %s; named-checkzone %s %s" % (path, name, path)


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


def _same(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def judge_output(zone, rc, out):
    """Hash first. named-checkzone failure does not echo zone text."""
    name = "%s %s:%s" % (zone["name"], zone["host"], zone["path"])
    line = ""
    for raw in (out or "").splitlines():
        if raw.strip():
            line = raw.strip()
            break
    match = _HASH_LINE.match(line)
    if not match:
        return {"name": name, "ok": False, "state": "UNVERIFIED",
                "detail": "unparseable zone hash"}
    digest = match.group(1)
    if not _same(digest, zone["sha256"]):
        return {"name": name, "ok": False, "state": "DRIFT",
                "detail": "zone hash does not match the pin: live %s pin %s" % (
                    digest, zone["sha256"])}
    if rc != 0:
        return {"name": name, "ok": False, "state": "CHECKZONE",
                "detail": "named-checkzone failed rc=%d" % rc}
    return {"name": name, "ok": True, "state": "ok", "detail": "hash matches and named-checkzone passed"}


def check(zone, runner):
    rc, out = runner(zone["host"], remote_command(zone))
    return judge_output(zone, rc, out)


def run(zones, runner=None):
    gate = readiness(zones)
    if not gate["ok"]:
        return {"ok": False, "state": "UNPINNED", "detail": gate["detail"],
                "findings": [], "probed": False}
    runner = runner or _ssh
    findings = [check(zone, runner) for zone in zones]
    return {"ok": all(item["ok"] for item in findings), "state": "checked",
            "detail": "", "findings": findings, "probed": True}


def render(result):
    if result["state"] == "UNPINNED":
        return "fleet dns: UNPINNED — %s" % result["detail"]
    lines = []
    for item in result["findings"]:
        mark = "ok  " if item["ok"] else "!!  "
        lines.append("%s %s — %s" % (mark, item["name"], item["detail"]))
    lines.append("fleet dns: %d zone(s), %d problem(s)" % (
        len(result["findings"]), sum(1 for item in result["findings"] if not item["ok"])))
    return "\n".join(lines)
