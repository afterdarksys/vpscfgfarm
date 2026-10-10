"""replica_of — a copied file must still match its source.

The incident behind it: a hand-copied TLS certificate drifted from its source. This check reads
one hash, or one certificate end date, from the source host and from the
contract host. It never prints the file.

Threats:
  - Protects against: a replica whose bytes or notAfter drifted from the
    declared source; a dest certificate that is already expired; file
    bodies coming back through this check (the remote command is sha256sum
    or openssl enddate, and an unparseable answer is dropped, not echoed).
  - Does NOT protect against: both copies being replaced with the same
    wrong bytes (equality is not a signature); a path the contract did
    not name. Apply stays a separate, frozen door.
"""
import hmac
import re
import shlex
import subprocess
from datetime import datetime, timezone

from .gates import Refused
from .probe import HOST_RE
from .secretscensus import PATH_RE

COMPARES = frozenset(("sha256", "expiry"))
_FIELDS = frozenset(("source_host", "source_path", "dest_path", "compare"))
_SHA = re.compile(r"\A([0-9a-f]{64})(?:\s|\Z)")
_END = re.compile(r"\AnotAfter=(.+)\Z")
_WHEN = re.compile(r"\A([A-Za-z]{3}) (\d{1,2}) (\d{2}:\d{2}:\d{2}) (\d{4}) GMT\Z")
_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def _path_ok(path):
    return isinstance(path, str) and ".." not in path and PATH_RE.match(path) is not None


def validate(spec):
    """Called from verify.validate_checks. Exact keys, or refuse."""
    if not isinstance(spec, dict) or set(spec) != _FIELDS:
        raise Refused("replica_of requires exactly source_host, source_path, "
                      "dest_path, compare")
    if not isinstance(spec["source_host"], str) or not HOST_RE.match(spec["source_host"]):
        raise Refused("replica_of source_host %r fails validation" % spec.get("source_host"))
    for field in ("source_path", "dest_path"):
        if not _path_ok(spec[field]):
            raise Refused("replica_of %s %r fails validation — absolute, "
                          "plain characters, no dot-dot" % (field, spec.get(field)))
    if spec["compare"] not in COMPARES:
        raise Refused("replica_of compare must be sha256 or expiry")


def remote_command(path, compare):
    """Fixed command. Only a validated, quoted path varies."""
    if not _path_ok(path) or compare not in COMPARES:
        raise Refused("replica_of remote command refused")
    quoted = shlex.quote(path)
    if compare == "sha256":
        return "sha256sum -- %s" % quoted
    return "openssl x509 -in %s -noout -enddate" % quoted


def _ssh(host, remote):
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    from . import secretmask, sshconfig
    known = sshconfig.load()
    if known and host not in known:
        raise Refused("host %r is not an alias in ~/.ssh/config" % host)
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, remote],
        capture_output=True, text=True, timeout=30)
    out = secretmask.mask(result.stdout)
    if result.returncode == 0 and (out or "").startswith("<output withheld"):
        return 1, ""
    return result.returncode, out


def _same(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def _one_line(text):
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    return lines[0]


def _parse_sha(text):
    line = _one_line(text)
    if line is None:
        return None
    match = _SHA.match(line)
    return match.group(1) if match else None


def _parse_end(text):
    line = _one_line(text)
    if line is None:
        return None
    match = _END.match(line)
    if not match:
        return None
    flattened = re.sub(r"\s+", " ", match.group(1).strip())
    found = _WHEN.match(flattened)
    month = _MONTHS.get(found.group(1)) if found else None
    if month is None:
        return None
    try:
        hour, minute, second = (int(part) for part in found.group(3).split(":"))
        return datetime(int(found.group(4)), month, int(found.group(2)),
                        hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def _fail(name, detail):
    return {"check": "replica_of", "name": name, "ok": False, "detail": detail}


def check(spec, dest_host, runner=None, now=None):
    """Compare source_path on source_host with dest_path on dest_host."""
    validate(spec)
    if not HOST_RE.match(dest_host or ""):
        raise Refused("invalid host %r" % dest_host)
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise Refused("replica_of clock must be timezone-aware")
    runner = runner or _ssh
    name = "%s:%s -> %s:%s" % (
        spec["source_host"], spec["source_path"], dest_host, spec["dest_path"])
    src_rc, src_out = runner(spec["source_host"], remote_command(spec["source_path"], spec["compare"]))
    dst_rc, dst_out = runner(dest_host, remote_command(spec["dest_path"], spec["compare"]))
    if src_rc != 0 or dst_rc != 0:
        return _fail(name, "read failed rc=%d/%d" % (src_rc, dst_rc))
    if spec["compare"] == "sha256":
        src, dst = _parse_sha(src_out), _parse_sha(dst_out)
        if src is None or dst is None:
            return _fail(name, "unparseable hash")
        if not _same(src, dst):
            return _fail(name, "sha256 differs: source %s dest %s" % (src, dst))
        return {"check": "replica_of", "name": name, "ok": True, "detail": "sha256 matches"}
    src, dst = _parse_end(src_out), _parse_end(dst_out)
    if src is None or dst is None:
        return _fail(name, "unparseable end date")
    src_iso, dst_iso = src.isoformat(), dst.isoformat()
    if dst < now:
        return _fail(name, "dest certificate is already expired (%s)" % dst_iso)
    if not _same(src_iso, dst_iso):
        return _fail(name, "end dates differ: source %s dest %s" % (src_iso, dst_iso))
    return {"check": "replica_of", "name": name, "ok": True,
            "detail": "end dates match, dest not expired"}
