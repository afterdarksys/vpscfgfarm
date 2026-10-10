"""Per-host mutation lock — one mutation in flight per host, ever.

Remote mkdir is atomic: two operators racing get exactly one winner. The lock
directory carries the operator + reason so the loser knows who to find.

Threats:
  - Protects against: two concurrent mutations interleaving on one host (the
    classic self-inflicted outage); stale locks silently blocking forever
    (staleness is REPORTED with age + owner, never auto-broken — breaking a
    lock is a human decision made with eyes open).
  - Does NOT protect against: mutations that bypass vpscfg entirely — the lock
    only guards this door, which is why this door must be the only one.
"""
import json
import shlex
import secrets
import subprocess

from .gates import Refused

LOCK_DIR = "/run/vpscfg.lock"


def _default_runner(host, remote_cmd):
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, remote_cmd],
        capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout, r.stderr


def acquire(host, operator, reason, runner=None):
    """Atomic: mkdir fails if the lock exists. On failure, surface the owner."""
    runner = runner or _default_runner
    token = secrets.token_hex(32)
    meta = json.dumps({"operator": operator, "reason": reason, 'operation_id': token})
    cmd = ("umask 077; mkdir %s && printf '%%s\\n' %s > %s/owner && printf '%%s\\n' %s > %s/token"
           % (shlex.quote(LOCK_DIR), shlex.quote(meta), shlex.quote(LOCK_DIR),
              shlex.quote(token), shlex.quote(LOCK_DIR)))
    rc, _, _ = runner(host, cmd)
    if rc != 0:
        orc, out, _ = runner(host, "cat %s/owner 2>/dev/null; stat -c %%Y %s 2>/dev/null"
                             % (shlex.quote(LOCK_DIR), shlex.quote(LOCK_DIR)))
        raise Refused("host %s is LOCKED by another mutation: %s — a lock is only "
                      "broken by a human, deliberately (rmdir after reading owner)"
                      % (host, (out.strip() or "owner unreadable")))
    return token


def release(host, runner=None, token=None):
    if not token:
        return False  # no authority to release another operation's lock
    runner = runner or _default_runner
    directory = shlex.quote(LOCK_DIR)
    rc, _, err = runner(host, "test \"$(cat %s/token)\" = %s && rm -f %s/owner %s/token && rmdir %s"
                        % (directory, shlex.quote(token), directory, directory, directory))
    if rc != 0:
        # Failing to release is loud but not fatal — the NEXT mutation will
        # refuse with this run's owner metadata, which is recoverable.
        return False
    return True
