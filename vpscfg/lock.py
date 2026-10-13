"""Per-host mutation lock — one mutation in flight per host, ever.

Remote mkdir is atomic: two operators racing get exactly one winner. The lock
directory carries the operator + reason so the loser knows who to find, and
the controller (machine, pid, start time) so `vpsexec reconcile` can refuse
to release a lock whose door is still alive on this machine. Its age comes
from the host's own clock. A release can remove the operation's op dir in
the same remote command.

Threats:
  - Protects against: two concurrent mutations interleaving on one host (the
    classic self-inflicted outage); stale locks silently blocking forever
    (staleness is REPORTED with age + owner, never auto-broken — breaking a
    lock is a human decision made with eyes open).
  - Does NOT protect against: mutations that bypass vpscfg entirely — the lock
    only guards this door, which is why this door must be the only one.
"""
import base64
import hmac
import json
import os
import re
import shlex
import secrets
import socket
import subprocess
import time

from .gates import Refused

LOCK_DIR = "/run/vpscfg.lock"


def _default_runner(host, remote_cmd):
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, remote_cmd],
        capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout, r.stderr


# Two readings of one process's start time (each `now - elapsed`, to the
# second) may differ by a second or two; a recycled pid differs by far more.
START_TOLERANCE = 5
_PS = ("/bin/ps", "/usr/bin/ps")


def _etime_seconds(text):
    """`ps -o etime=`: [[dd-]hh:]mm:ss -> seconds, or None."""
    text = (text or "").strip()
    m = re.match(r"^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)\Z", text)
    if not m:
        return None
    d, h, mi, s = (int(x) if x else 0 for x in m.groups())
    return ((d * 24 + h) * 60 + mi) * 60 + s


def process_start(pid):
    """Epoch seconds at which local process `pid` started, or None when it
    cannot be read (no such process, no ps). Used to tell a live lock
    controller from a recycled pid."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None
    ps = next((p for p in _PS if os.path.isfile(p)), None)
    if ps is None:
        return None
    try:
        r = subprocess.run([ps, "-o", "etime=", "-p", str(pid)], capture_output=True,
                           text=True, timeout=10, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    secs = _etime_seconds(r.stdout) if r.returncode == 0 else None
    return None if secs is None else int(time.time()) - secs


def controller():
    """Which process on which machine holds a lock it takes, and when that
    process started: reconcile refuses to release a lock whose controller is
    this machine and still alive — the same pid with the same start time, not
    a recycled pid number. When ps cannot say, `started` is None — never a
    guess — and an unknown start time counts as ALIVE (reconcile refuses)."""
    pid = os.getpid()
    return {"host": socket.gethostname(), "pid": pid, "started": process_start(pid)}


def acquire(host, operator, reason, runner=None):
    """Atomic: mkdir fails if the lock exists. On failure, surface the owner."""
    runner = runner or _default_runner
    token = secrets.token_hex(32)
    meta = json.dumps({"operator": operator, "reason": reason, 'operation_id': token,
                       "controller": controller()})
    cmd = ("umask 077; mkdir %s && printf '%%s\\n' %s > %s/owner && printf '%%s\\n' %s > %s/token"
           % (shlex.quote(LOCK_DIR), shlex.quote(meta), shlex.quote(LOCK_DIR),
              shlex.quote(token), shlex.quote(LOCK_DIR)))
    rc, _, _ = runner(host, cmd)
    if rc != 0:
        orc, out, _ = runner(host, "cat %s/owner 2>/dev/null; stat -c %%Y %s 2>/dev/null"
                             % (shlex.quote(LOCK_DIR), shlex.quote(LOCK_DIR)))
        raise Refused("host %s is LOCKED by another mutation: %s — a lock is only "
                      "released by a human, deliberately: next, run `vpsexec reconcile %s` "
                      "in a terminal (it shows the evidence and asks before releasing)"
                      % (host, (out.strip() or "owner unreadable"), host))
    return token


def _drop_op_dir(op_dir):
    """Appended to a release, in the SAME remote command: once the lock is
    gone its op dir (step scripts, logs, exit codes) goes too, so evidence
    never outlives the lock that made it meaningful and /run cannot fill.
    Only a path detach.op_dir() itself builds (OPS_DIR/<hex op id>) is removed."""
    if not op_dir:
        return ""
    from . import detach  # late: detach imports this module
    if detach.op_dir(str(op_dir).rsplit("/", 1)[-1]) != str(op_dir):
        raise ValueError("not an op dir: %r" % (op_dir,))
    return " && { rm -rf -- %s; true; }" % shlex.quote(str(op_dir))


def release(host, runner=None, token=None, op_dir=None):
    if not token:
        return False  # no authority to release another operation's lock
    runner = runner or _default_runner
    directory = shlex.quote(LOCK_DIR)
    rc, _, err = runner(host, "test \"$(cat %s/token)\" = %s && rm -f %s/owner %s/token && rmdir %s%s"
                        % (directory, shlex.quote(token), directory, directory, directory,
                           _drop_op_dir(op_dir)))
    if rc != 0:
        # Failing to release is loud but not fatal — the NEXT mutation will
        # refuse with this run's owner metadata, which is recoverable.
        return False
    return True


_B64 = re.compile(r"^[A-Za-z0-9+/=]*$")


def read_owner(host, runner=None):
    """None when the host is not locked, else {"owner": raw text, "token": raw
    text, "meta": parsed owner dict or None}. Both files travel base64, so no
    byte of them can be mistaken for the reply's own framing."""
    runner = runner or _default_runner
    d = shlex.quote(LOCK_DIR)
    rc, out, err = runner(host, "if test -d %s; then echo VPSCFG-LOCK held; printf 'OWNER '; "
                                "base64 < %s/owner 2>/dev/null | tr -d '\\n'; echo; printf 'TOKEN '; "
                                "base64 < %s/token 2>/dev/null | tr -d '\\n'; echo; "
                                "m=$(stat -c %%Y %s 2>/dev/null || stat -f %%m %s 2>/dev/null); "
                                "test -n \"$m\" && echo \"AGE $(( $(date +%%s) - m ))\"; "
                                "else echo VPSCFG-LOCK free; fi" % (d, d, d, d, d))
    lines = [l.strip() for l in (out or "").splitlines() if l.strip()]
    if rc != 0 or not lines or lines[0] not in ("VPSCFG-LOCK held", "VPSCFG-LOCK free"):
        raise Refused("cannot read the lock on %s (rc=%s): %s"
                      % (host, rc, (err or out or "no reply").strip()[:120]))
    if lines[0] == "VPSCFG-LOCK free":
        return None
    fields, age = {}, None
    for line in lines[1:]:
        key, _, body = line.partition(" ")
        if key in ("OWNER", "TOKEN") and _B64.match(body.strip()):
            fields[key] = base64.b64decode(body.strip()).decode("utf-8", "replace").rstrip("\n")
        elif key == "AGE" and re.match(r"^-?\d{1,12}$", body.strip()):
            age = int(body.strip())  # seconds, by the host's own clock
    owner, token = fields.get("OWNER", ""), fields.get("TOKEN", "")
    try:
        meta = json.loads(owner) if owner else None
    except ValueError:
        meta = None
    return {"owner": owner, "token": token, "meta": meta if isinstance(meta, dict) else None,
            "age": age}


def consistent(held):
    """The lock this door writes names its token as the owner's operation_id."""
    meta = (held or {}).get("meta") or {}
    op, token = str(meta.get("operation_id") or ""), (held or {}).get("token") or ""
    return bool(op and token) and hmac.compare_digest(op.encode(), token.encode())


def release_matching(host, held, runner=None, op_dir=None):
    """Release ONLY the lock that was read: owner and token must both still be
    byte-identical on the host, checked in the same remote command that removes
    them. A lock re-taken by another operation in between is left alone. With
    `op_dir`, that operation's op dir is removed in the same command, after
    the lock (the caller journals the evidence first)."""
    if not consistent(held):
        return False
    runner = runner or _default_runner
    d = shlex.quote(LOCK_DIR)
    rc, _, _ = runner(host, "test -d %s && test \"$(cat %s/owner)\" = %s && "
                            "test \"$(cat %s/token)\" = %s && rm -f %s/owner %s/token && rmdir %s%s"
                      % (d, d, shlex.quote(held["owner"]), d, shlex.quote(held["token"]),
                         d, d, d, _drop_op_dir(op_dir)))
    return rc == 0
