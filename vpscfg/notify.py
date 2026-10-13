"""Tell a human when a play or release halts, finishes, leaves a host lock
retained, is refused before or while planning, or is aborted (Ctrl-C) — so a
halt at 2am is not found by the human at 9am.

OFF unless the governor names integrations.notify.command (vpscfg/
integrations.py): an argv list for a LOCAL command, for example a script that
sends a push notification. This module makes no network call of its own; with
nothing configured it sends nothing. The command gets the event name as its
last argument and one JSON object on stdin:

    {"event": "halt", "kind": "release", "name": "weekend", "run_id": "r_...",
     "at": "play stage-a step 3", "rc": 1,
     "resume": "vpsrun release weekend --resume", "rollback": [...]}

Threats:
  - Protects against: a notifier breaking or stalling a release (best-effort:
    bounded by NOTIFY_TIMEOUT, every failure reduced to one stderr line, the
    caller never sees an exception — the journal, not the notifier, is the
    record); a shell interpreting event data (argv list, no shell; event
    fields travel on stdin as JSON, the event name is one of EVENTS); an
    environment variable or flag choosing the command (the governor only);
    step output leaking into notifications (the payload carries names, run
    ids, step positions, return codes and commands to type, never output);
    PATH or the environment choosing or steering the notifier (its first word
    is an absolute path, and it runs with a minimal environment from /).
  - Does NOT protect against: a governor naming a hostile command (the
    governor is the operator's reviewed, committed file); what the configured
    command does with the payload, including sending it over the network —
    that is its job.
"""
import json
import os
import subprocess
import sys

from . import integrations
from .gates import Refused

EVENTS = ("halt", "finish", "lock_retained", "refused", "aborted")
NOTIFY_TIMEOUT = 15
MAX_PAYLOAD = 16 * 1024
# The notifier sees none of the operator's environment (L3): no credentials,
# no SSH agent, no PYTHON*/LD_* variables. It names everything it needs.
MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def _run(argv, payload):
    env = dict(MINIMAL_ENV)
    home = os.environ.get("HOME")
    if home:
        env["HOME"] = home
    return subprocess.run(argv, input=payload, text=True, capture_output=True,
                          timeout=NOTIFY_TIMEOUT, env=env, cwd="/").returncode


def send(event, fields, governor=None, runner=None):
    """Run the configured notifier once. True when it exited 0; False when it
    is off or failed. Never raises for anything the notifier does."""
    if event not in EVENTS:
        raise ValueError("unknown notify event %r" % event)
    try:
        argv = integrations.notify_command(governor)
    except Refused as r:
        print("  notify: not sent — %s" % r, file=sys.stderr)
        return False
    if not argv:
        return False
    payload = json.dumps(dict(fields, event=event), sort_keys=True, default=str)
    if len(payload) > MAX_PAYLOAD:
        payload = json.dumps({"event": event, "truncated": True,
                              "run_id": fields.get("run_id"),
                              "name": fields.get("name")}, sort_keys=True)
    try:
        rc = (runner or _run)(argv + [event], payload)
    except Exception as e:  # a notifier must never fail the release it reports
        print("  notify: %s failed (%s)" % (argv[0], e), file=sys.stderr)
        return False
    if rc != 0:
        print("  notify: %s exited %s" % (argv[0], rc), file=sys.stderr)
    return rc == 0
