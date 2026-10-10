"""Maintenance windows from an external `blackout` tool, as a GATE INPUT.

docs/DESIGN.md names blackout as a planned gate input; this is that wiring.

THE DIRECTION MATTERS: a blackout is **advisory by default and can only ever
tighten**. Being inside a maintenance window never grants permission — postures
and runbooks decide that, and a second, weaker authorisation path would quietly
become the easy one. What a window does is inform ("you are about to restart
nginx on a host that is NOT in a maintenance window") and, with
--require-blackout, refuse hosts that are outside one.

Fail direction: information fails OPEN (an unavailable blackout tool shows
"unknown" in the plan and blocks nothing), strictness fails CLOSED (if
--require-blackout was asked for and the answer cannot be determined, refuse).

WHERE THE WINDOWS COME FROM: the governor only (integrations.blackout.file,
vpscfg/integrations.py). No environment variable names the file or its
freshness limit. Unset means no windows are known: status "unconfigured",
which every caller treats like a missing export file (unknown, advisory;
--require-blackout refuses). A malformed entry reads as "error", the same.

Threats:
  - Protects against: unplanned mutations sliding through unnoticed (every plan
    states each host's window status); a broken or missing blackout binary
    silently reading as "everything is in a window" (unknown is never treated as
    yes, and --require-blackout refuses on unknown).
  - Does NOT protect against: a blackout someone opened purely to satisfy
    --require-blackout. It records intent; it does not verify it.
"""

import json
import os
import subprocess

from . import integrations
from .gates import Refused

# The machine interface of a `blackout` tool is the JSON export file it
# maintains for alert suppression (a CLI listing is text for humans), so that
# is what the default runner reads. The governor names the file.
EXPORT_MAX_BYTES = 1024 * 1024
# The exporter rewrites the file whenever windows change and on cleanup; a
# file older than this is not evidence of anything current. Windows are
# answered "unknown", never "inside".
EXPORT_MAX_AGE_SECONDS = 900
END_KEYS = ("end_time", "ends_at", "end", "expires_at", "expiry", "until")
HOST_KEYS = ("host", "hostname", "target", "server", "node")


def _default_runner(argv, timeout=10):
    """Read the export file named in argv[1]. Absent file -> OSError, which
    reads as "unavailable" (unknown, never "in a window")."""
    import time
    path = argv[1]
    age = time.time() - os.stat(path).st_mtime
    if age > EXPORT_MAX_AGE_SECONDS:
        return 1, "", "export file is %ds old (max %ds) — stale" % (age, EXPORT_MAX_AGE_SECONDS)
    with open(path, "rb") as f:
        raw = f.read(EXPORT_MAX_BYTES + 1)
    if len(raw) > EXPORT_MAX_BYTES:
        return 1, "", "export file exceeds %d bytes" % EXPORT_MAX_BYTES
    return 0, raw.decode("utf-8", "replace"), ""


def _entry_current(entry):
    """An entry counts only if nothing in it says it is over. An end time
    that is present but unparseable excludes the entry (unknown != inside)."""
    import datetime
    status = entry.get("status")
    if isinstance(status, str) and status.strip().lower() not in ("active", "open", "in_progress"):
        return False
    if entry.get("active") is False:
        return False
    for key in END_KEYS:
        if key not in entry or entry[key] in (None, ""):
            continue
        value = str(entry[key]).strip().replace("Z", "+00:00")
        try:
            end = datetime.datetime.fromisoformat(value)
        except ValueError:
            return False
        if end.tzinfo is None:
            end = end.replace(tzinfo=datetime.timezone.utc)
        return end > datetime.datetime.now(datetime.timezone.utc)
    return True


def active_hosts(runner=None, timeout=10):
    """({hosts in an active window}, status). Never raises.

    status: "ok" | "unconfigured" (the governor names no export file) |
    "unavailable" (no export file) | "error" (present but unreadable, or a
    malformed governor entry). Only "ok" ever answers a host.
    """
    if runner is None:
        try:
            path = integrations.blackout_file()
        except Refused:
            return set(), "error"
        if path is None:
            return set(), "unconfigured"
        runner, argv = _default_runner, ["blackout-export", path]
    else:
        argv = ["blackout-export"]
    try:
        rc, out, err = runner(argv, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return set(), "unavailable"
    if rc != 0:
        return set(), "unavailable" if not (out or "").strip() else "error"
    try:
        doc = json.loads(out or "null")
    except json.JSONDecodeError:
        return set(), "error"

    if isinstance(doc, dict):
        for key in ("blackouts", "active", "results", "items", "data"):
            if isinstance(doc.get(key), list):
                doc = doc[key]
                break
        else:
            doc = [doc]
    if not isinstance(doc, list):
        return set(), "error"

    hosts = set()
    for entry in doc:
        if isinstance(entry, str):
            hosts.add(entry)
        elif isinstance(entry, dict):
            if not _entry_current(entry):
                continue
            for key in HOST_KEYS:
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    hosts.add(value.strip())
                    break
                if isinstance(value, list):
                    hosts.update(h for h in value if isinstance(h, str))
                    break
    return hosts, "ok"


def assess(hosts, runner=None):
    """{host: True|False|None} — None means the answer is unknown."""
    active, status = active_hosts(runner=runner)
    if status != "ok":
        return dict((h, None) for h in hosts), status
    return dict((h, h in active) for h in hosts), status


def require(windows, status):
    """--require-blackout: refuse any host not provably inside a window."""
    if status != "ok":
        raise Refused(
            "--require-blackout was asked for, but the blackout tool is %s — "
            "an unverifiable maintenance window is not a maintenance window. "
            "(name the export JSON in the governor, integrations.blackout.file, "
            "or drop the flag)" % status)
    outside = sorted(h for h, inside in windows.items() if not inside)
    if outside:
        raise Refused(
            "--require-blackout: %d host(s) are not in an active maintenance "
            "window: %s. Open one (`blackout <ticket> <host> <dur> \"why\"`) or "
            "drop the flag." % (len(outside), ", ".join(outside)))
