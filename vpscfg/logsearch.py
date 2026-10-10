"""Log & config search — quick, gated, read-only access to a host's logs and
config files, time-windowed and pattern-filtered.

Until now logs were reachable only ad-hoc through vpsexec (`vpsexec web1
'journalctl -u nginx ...'`). This is the ergonomic layer: one verb that reads
a systemd unit's journal, a container's logs, or a config file, filters it,
and windows it by time.

  vpscfg <host> logs <unit> --search ERROR --since 2h
  vpscfg <host> logs --in mail-proxy --search 554 --since 1d
  vpscfg <host> logs <unit> --file /opt/app/config.yaml --search timeout

It is a READ: no --run, works on frozen hosts, mutates nothing. The command it
builds is scanned by the SAME deny stack the doors use (floor + secrets.yaml),
so `--file /opt/app/.env.production` refuses exactly as vpsexec would — a new
door must not become a credential-exfiltration path.

Threats:
  - Protects against: this verb becoming a way to read secret files
    (--file paths run through deny_scan against the merged secrets deny list;
    a match refuses); operator input reaching a remote shell unsafely (unit /
    container / path are regex-validated, the search pattern is shell-quoted
    and passed as a single `grep -e` arg, time windows come from a fixed unit
    map); unbounded output (hard --max line cap).
  - Does NOT protect against: a service that logs its own secrets (log
    hygiene is the service's job, not this reader's) — only the --file path
    is gated, because that is the one that reads arbitrary paths on request.
"""
import re
import shlex
import subprocess

from . import secretmask
from .gates import Refused, deny_scan

UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@_.:-]{0,127}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9._/-]*$")
SINCE_RE = re.compile(r"^\d{1,4}(h|d|mo|yr)$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$")

# Relative-window unit -> the word GNU `date -d` understands. A fixed map, so
# no operator string reaches `date`; only the integer count varies.
_SINCE_UNIT = {"h": "hours", "d": "days", "mo": "months", "yr": "years"}

MAX_CAP = 5000       # never return more than this many lines, whatever --max asks
DEFAULT_MAX = 400


def _since_clause(since, kind):
    """Build the time-window fragment for journalctl or docker.

    kind is 'journalctl' or 'docker'. Returns (prefix_args, since_is_tail):
    for 'current' there is no --since, we just tail; otherwise a --since
    computed on the REMOTE host via `date -d` (uniform across h/d/mo/yr and
    accepted by both journalctl and docker).
    """
    if since == "current":
        return "", True
    if TS_RE.match(since):
        stamp = since
        if kind == "journalctl":
            return '--since %s' % shlex.quote(stamp), False
        return '--since %s' % shlex.quote(stamp), False
    m = SINCE_RE.match(since)
    if not m:
        raise Refused("--since %r: use current, <N>h/<N>d/<N>mo/<N>yr, or a "
                      "YYYY-MM-DD[ HH:MM:SS] timestamp" % since)
    n = int(since[:m.start(1)])
    unit = _SINCE_UNIT[m.group(1)]
    if kind == "journalctl":
        fmt = "+%Y-%m-%d %H:%M:%S"
    else:  # docker --since takes a unix timestamp cleanly
        fmt = "+%s"
    # $(date ...) lives in THIS reviewed template with a validated int and a
    # fixed unit word — no operator string reaches the shell here.
    return '--since "$(date -d %s %s)"' % (
        shlex.quote("%d %s ago" % (n, unit)), shlex.quote(fmt)), False


def build_command(spec):
    """Construct the fixed remote command from a validated spec dict.

    spec keys: target (unit, optional if in_container), in_container, file,
    searches (list), regex (bool), since, max.
    Returns the remote command string. Raises Refused on any validation miss.
    """
    container = spec.get("in_container")
    unit = spec.get("target")
    path = spec.get("file")
    since = spec.get("since") or "current"
    maxn = min(int(spec.get("max") or DEFAULT_MAX), MAX_CAP)
    if maxn < 1:
        raise Refused("--max must be >= 1")

    if container is not None and not NAME_RE.match(container):
        raise Refused("container name %r fails validation" % container)
    if unit is not None and not UNIT_RE.match(unit):
        raise Refused("unit name %r fails validation" % unit)
    if container is None and unit is None:
        raise Refused("logs needs a systemd unit (positional) or a container "
                      "(--in NAME)")

    # ---- source: file, or logs ------------------------------------------
    if path is not None:
        if ".." in path or not PATH_RE.match(path):
            raise Refused("--file %r must be an absolute path, plain "
                          "characters, no dot-dot" % path)
        if container is not None:
            source = "docker exec %s cat -- %s" % (
                shlex.quote(container), shlex.quote(path))
        else:
            source = "cat -- %s" % shlex.quote(path)
        cap = "head -n %d" % maxn      # top of a file
    elif container is not None:
        prefix, _tail = _since_clause(since, "docker")
        source = "docker logs %s %s 2>&1" % (prefix, shlex.quote(container))
        cap = "tail -n %d" % maxn      # most-recent log lines
    else:
        prefix, _tail = _since_clause(since, "journalctl")
        if since == "current":
            source = "journalctl -u %s -n %d --no-pager 2>/dev/null" % (
                shlex.quote(unit), maxn)
        else:
            source = "journalctl -u %s %s --no-pager 2>/dev/null" % (
                shlex.quote(unit), prefix)
        cap = "tail -n %d" % maxn

    # ---- filter: chained grep (AND), literal or regex -------------------
    greps = ""
    flag = "-E" if spec.get("regex") else "-F"
    for pat in spec.get("searches") or []:
        if not isinstance(pat, str) or pat == "":
            raise Refused("empty --search pattern")
        greps += " | grep %s -e %s" % (flag, shlex.quote(pat))

    return "%s%s | %s" % (source, greps, cap)


def run(host, spec, deny_patterns, runner=None):
    """Validate, gate against the deny stack, then execute read-only.

    deny_patterns is the merged floor + secrets deny list. The constructed
    command is scanned before it runs, so a secret --file path (or any floor
    pattern) refuses here exactly as it would at either door.
    """
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    command = build_command(spec)
    # The gate: identical semantics to the doors. A secret path in a --file
    # read is caught here (e.g. 'cat -- /opt/app/.env.production').
    deny_scan(command, deny_patterns)
    if runner is None:
        def runner(h, cmd):
            r = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", h, cmd],
                capture_output=True, text=True, timeout=60)
            return r.returncode, r.stdout, r.stderr
    rc, out, err = runner(host, command)
    out, err = secretmask.mask(out or ""), secretmask.mask(err or "")
    # grep exits 1 on "no matches" — that is a clean empty result, not an error.
    return {"host": host, "command": command, "rc": rc,
            "stdout": out, "stderr": err,
            "matched": bool(out.strip())}


def render(host, spec, result):
    src = ("file %s" % spec["file"] if spec.get("file")
           else ("container %s" % spec["in_container"] if spec.get("in_container")
                 else "unit %s" % spec.get("target")))
    scope = "in %s " % spec["in_container"] if (spec.get("in_container")
                                                and spec.get("file")) else ""
    pats = ", ".join(spec.get("searches") or []) or "(no filter)"
    head = "LOGS %s  %s%s  since=%s  search=%s" % (
        host, scope, src, spec.get("since") or "current", pats)
    body = result["stdout"].rstrip("\n")
    if not body:
        note = ("no matches" if (spec.get("searches") and result["rc"] != 0)
                else "no output")
        return "%s\n  %s" % (head, note)
    return "%s\n%s" % (head, body)
