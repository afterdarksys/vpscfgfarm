"""Gate logic — the pure, testable core of every refusal.

Threats:
  - Protects against: destructive command classes reaching any executor
    (deny-scan is case-insensitive substring over the WHOLE command line, so a
    payload hidden inside `ssh host '<...>'` quoting is still caught); the
    one-character-volume-name disaster (edit-distance check: any volume name
    within distance 1 of a live volume is refused and the operation demands the
    exact name); mutations against frozen contracts.
  - Does NOT protect against: obfuscation that assembles a destructive string
    at runtime on the remote host ($(echo pr)une) — that is what the executor's
    "no free-form remote shell" rule is for; nor semantic disasters expressed
    in perfectly safe-looking commands (that is what plans and verify are for).
"""

import os
from .commandtext import literal_words

# The floor. vpscfg-control.py carries its own copy by design — two independent
# doors. tests/test_floor_sync.py asserts they never drift apart.
DENY_ALWAYS_FLOOR = [
    "volume prune", "system prune", "image prune", "network prune",
    "volume rm",
    "compose down -v", "compose down --volumes",
    "DROP TABLE", "DROP DATABASE", "DROP SCHEMA",
    "TRUNCATE",
    "rm -rf /",
    "kubectl delete ns", "kubectl delete namespace",
    "mkfs", "dd if=",
    "terraform destroy",
]

READ_ONLY_VERBS = frozenset(
    ["show", "details", "containers", "services", "overlays",
     "drift", "verify", "fleet", "plan", "status", "help", "lint", "journal", "ports",
     "backup-verify", "map", "logs", "sql", "index"]
)


class Refused(Exception):
    """Raised by any gate. Callers convert to exit code + journal entry.
    Deliberately NOT catchable-and-continue anywhere in this package: the only
    handler prints and exits."""


def deny_scan(text, patterns):
    """Refuse if any deny pattern appears anywhere in the text (case-insensitive).

    Substring, not prefix: the near-miss commands all lived mid-string inside
    ssh payloads. Returns None; raises Refused with the matching pattern.
    """
    lowered = " ".join(text.split()).lower()  # collapse whitespace tricks
    try:
        words = literal_words(text)
    except ValueError:
        words = []
    # Quote removal and backslash escapes are shell syntax, not a new verb.
    # Keep the raw scan as well: it sees literal payloads inside ssh/sql strings.
    canonical = ' '.join(words).lower()
    without_flags = ' '.join(w for w in words if not w.startswith('-')).lower()
    for pattern in patterns:
        if any(pattern.lower() in candidate for candidate in (lowered, canonical, without_flags)):
            raise Refused(
                "matches deny-always pattern %r — never allowed through this door"
                % pattern
            )
    lower = [os.path.basename(w).lower() if w.startswith('/') else w.lower() for w in words]
    if 'prune' in lower:
        raise Refused('prune operations are deny-always through this door')
    # Equivalent rm flag orders must not turn the absolute-path floor into
    # an overridable risk. Scan each rm suffix conservatively.
    for i, word in enumerate(lower):
        if word != 'rm':
            continue
        tail = words[i + 1:]
        recursive = any(w in ('--recursive',) or (w.startswith('-') and not w.startswith('--') and 'r' in w.lower()) for w in tail)
        force = any(w == '--force' or (w.startswith('-') and not w.startswith('--') and 'f' in w.lower()) for w in tail)
        if recursive and force and any(w.startswith('/') for w in tail):
            raise Refused('matches deny-always pattern rm -rf / — never allowed through this door')
    if 'compose' in lower or 'docker-compose' in lower:
        if 'down' in lower and any(w == '--volumes' or (w.startswith('-') and not w.startswith('--') and 'v' in w) for w in words):
            raise Refused('matches deny-always pattern compose down --volumes')


def edit_distance(a, b):
    """Levenshtein, small-string implementation. Only ever called on volume
    names (short), so O(len*len) is fine."""
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def volume_name_check(requested, live_volumes):
    """The volume-twin rule (shop_postgres-data next to a live shop_postgres_data).

    An operation naming a volume that is NOT itself live but sits within edit
    distance 1 of a live volume is almost certainly a typo'd reference to the
    live one — or worse, a cleanup that will hit the twin. Refuse and demand
    the exact live name be dealt with deliberately.
    """
    if requested in live_volumes:
        return  # exact reference to a real volume: allowed to proceed to later gates
    for live in live_volumes:
        if edit_distance(requested, live) == 1:
            raise Refused(
                "volume %r is one character away from LIVE volume %r — "
                "refusing; name the exact volume you mean" % (requested, live)
            )


def assert_not_frozen(contract):
    if contract.get("freeze", False):
        raise Refused(
            "contract %r is frozen — unfreezing requires a git commit to the "
            "contract, not a flag" % contract.get("service", "?")
        )
