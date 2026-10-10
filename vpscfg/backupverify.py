"""Backup verification — an unrestorable backup is a feeling, not a backup.

DESIGN.md item 8: pre-deploy tars and pg_dumps exist, and no restore has
ever been rehearsed. Full sandbox restores need a mutation scope the
ratchet has not released; what CAN be proven today, read-only, is that the
newest backup is a complete, readable archive: stream it off the host and
walk every member through gzip+tar locally. Truncation, corruption, and
empty archives all fail. The bytes flow through memory only — nothing is
written to local disk.

Threats:
  - Protects against: the day-of-disaster discovery that the backup is
    truncated, corrupt, or empty; a backup path outside /root/<svc>-pre-*
    being verified as if it were the real thing (path shape is validated);
    a runaway stream (hard byte cap, rule 10).
  - Does NOT protect against: a backup that restores cleanly but contains
    the WRONG state — only an actual restore drill proves that, and that
    is Stage-2-style work for a scratch project on the test host (documented next
    step, not silently skipped).
"""
import re
import subprocess
import tarfile

from . import journal, probe
from .gates import Refused

# A service pre-backup is a deploy_dir tar: tens of MB, maybe GBs with data
# directories. Past this, something is wrong — refuse rather than stream on.
MAX_BACKUP_BYTES = 16 * 1024 * 1024 * 1024

_BACKUP_PATH_RE = re.compile(r"^/root/[A-Za-z0-9][A-Za-z0-9_-]{0,63}-pre-[A-Za-z0-9-]+\.tar\.gz$")


class _CappedReader(object):
    """File-like wrapper that refuses past the byte cap. tarfile pulls from
    this, so the cap holds no matter what the remote sends."""

    def __init__(self, raw, cap):
        self._raw = raw
        self._cap = cap
        self.total = 0

    def read(self, n=-1):
        chunk = self._raw.read(n if n is not None and n >= 0 else 65536)
        self.total += len(chunk)
        if self.total > self._cap:
            raise Refused("backup stream exceeded %d bytes — refusing to keep "
                          "reading; verify the backup job itself" % self._cap)
        return chunk


def verify_backup(host, service, opener=None, cap=MAX_BACKUP_BYTES):
    """Stream the newest /root/<service>-pre-*.tar.gz and walk it end to end.

    Returns {"backup", "members", "bytes", "ok", "detail"}; refuses when no
    backup exists (nothing to verify is a finding, not a pass).
    """
    if not probe.HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    backup = probe.latest_backup(host, service)
    if not backup:
        raise Refused("no /root/%s-pre-*.tar.gz on %s — there is nothing to "
                      "restore FROM. That is the finding." % (service, host))
    if not _BACKUP_PATH_RE.match(backup):
        raise Refused("backup path %r does not look like a pre-backup — "
                      "refusing to touch it" % backup)
    if opener is None:
        def opener(h, path):
            import shlex
            p = subprocess.Popen(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                 h, "cat -- %s" % shlex.quote(path)],
                stdout=subprocess.PIPE)
            return p.stdout
    stream = _CappedReader(opener(host, backup), cap)
    members = 0
    try:
        with tarfile.open(fileobj=stream, mode="r|gz") as tar:
            for _member in tar:
                members += 1
    except Refused:
        raise
    except Exception as e:
        result = {"backup": backup, "members": members, "bytes": stream.total,
                  "ok": False,
                  "detail": "archive is NOT fully readable: %s — the backup "
                            "would fail you on the day it matters" % e}
        journal.append("watch", {"event": "backup_verify", "host": host,
                                 "service": service, **result})
        return result
    if members == 0:
        result = {"backup": backup, "members": 0, "bytes": stream.total,
                  "ok": False, "detail": "archive is EMPTY"}
    else:
        result = {"backup": backup, "members": members, "bytes": stream.total,
                  "ok": True,
                  "detail": "%d member(s), %d bytes, gzip+tar walk clean"
                            % (members, stream.total)}
    journal.append("watch", {"event": "backup_verify", "host": host,
                             "service": service, **result})
    return result


def render(service, host, result):
    mark = "PASS" if result["ok"] else "FAIL"
    return ("BACKUP-VERIFY %s on %s: %s\n  %s\n  %s"
            % (service, host, mark, result["backup"], result["detail"]))
