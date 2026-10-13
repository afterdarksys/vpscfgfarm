#!/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9 -I
"""vpscfg-control — the ONLY sanctioned entry point to vpscfg.

Threats:
  - Protects against: any operator (human, AI, cat) invoking a mutation the
    control policy has not affirmatively unlocked; a corrupted or hand-mangled
    policy file silently loosening rules (schema + invariant validation fails
    CLOSED — an invalid policy refuses everything); bypass via calling the
    package directly (the package requires the policy-hash token this wrapper
    mints; without it, vpscfg hard-locks to read-only); deny_always ever being
    released (validated as a non-empty superset of a floor list compiled into
    this file — a policy that drops entries is rejected as tampered).
  - Does NOT protect against: an operator with a shell on the fleet host —
    the wrapper governs this door, and this door only; root editing both this
    file and the policy together (that is a git-visible act, which is the
    point); bugs in the underlying tool once a scope is legitimately unlocked.

Every invocation — allowed or refused — is journaled to journal/control.jsonl.

Fail-closed rule: any error in loading, validating, or judging => refuse.
"""

import os
import sys

# Run isolated (-I): ignore every PYTHON* variable (PYTHONPATH, PYTHONHOME,
# PYTHONUSERBASE, PYTHONSTARTUP...), the user site-packages and the script's
# directory. Without it a sitecustomize.py on PYTHONPATH can patch
# Path.read_bytes in BOTH doors, so both obey a forged governor and the token
# still verifies (W4 review H1). The shebang names an ABSOLUTE interpreter with
# -I (`env python3` would let PATH pick a fake python3 that drops -I; W4 R1),
# so a door started by path is isolated from its first instruction. Public
# installs set the shebang to their own interpreter's absolute path. This
# re-exec only catches `python3 vpscfg-control.py`, which cannot be fully protected: a
# hostile startup hook in THAT first interpreter has run before this line.
# Callers must start the doors by path and deny the `python3 door` form.
# The shebang names the REAL interpreter binary (tools/pin-interpreter.sh):
# on macOS /usr/bin/python3 is an xcrun shim that honours DEVELOPER_DIR,
# TOOLCHAINS and SDKROOT, so it lets the environment pick the interpreter too.
# Every re-exec and child below uses _PYTHON, sys.executable resolved to its
# real file, and refuses a shim rather than run through one.


def _interpreter():
    exe = os.path.realpath(sys.executable or "")
    if not os.path.isabs(exe) or not os.path.isfile(exe) or (
            sys.platform == "darwin" and os.path.dirname(exe) == "/usr/bin"):
        sys.stderr.write("REFUSED: interpreter %r is not a real interpreter binary "
                         "(macOS /usr/bin entries are xcrun shims that honour "
                         "DEVELOPER_DIR); pin one with tools/pin-interpreter.sh\n"
                         % (sys.executable,))
        sys.exit(2)
    return exe


_PYTHON = _interpreter()

if __name__ == "__main__" and not sys.flags.isolated:
    os.execv(_PYTHON, [_PYTHON, "-I", os.path.realpath(__file__)] + sys.argv[1:])

import hashlib
import json
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Start the inner door by path, never by the current directory. `python -m`
# puts the working directory first on sys.path, so from any other directory
# the package was not found, and a directory holding its own `vpscfg/` would
# have run that instead of this repo's door. (-P needs Python 3.11.)
_LAUNCH = ("import runpy, sys; root = sys.argv.pop(1); "
           "sys.path[:] = [root] + [p for p in sys.path if p not in ('', '.')]; "
           "runpy.run_module(%r, run_name='__main__', alter_sys=True)")
# The governor: <estate root>/vpscfg-control.json, set by main() from
# resolve_estate(). Default estate root = ROOT, i.e. exactly the old path.
CONTROL_PATH = ROOT / "vpscfg-control.json"
JOURNAL_DIR = ROOT / "journal"

# The floor under deny_always. A policy file whose deny_always is missing any of
# these is treated as tampered and refused outright. Releasing controls NEVER
# means editing this list down — it is compiled into the door itself.
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

VALID_MODES = ("lockdown", "test", "supervised", "released")


def floor_spellings(argv):
    """Independent outer-door quote/escape and flag-order normalization."""
    forms = [' '.join(' '.join(argv).split()).lower()]
    for value in argv:
        try:
            lexer = shlex.shlex(value.replace('\\\n', ''), posix=True, punctuation_chars=';&|<>')
            lexer.whitespace_split = True
            lexer.commenters = ''
            words = list(lexer)
        except ValueError:
            continue  # reasons/paths are argv data; the inner command parser validates syntax
        forms.append(' '.join(words).lower())
        if 'prune' in [w.lower() for w in words]:
            forms.append('volume prune')
        forms.append(' '.join(w for w in words if not w.startswith('-')).lower())
        if any(os.path.basename(w) == 'rm' for w in words):
            recursive = any(w == '--recursive' or (w.startswith('-') and not w.startswith('--') and 'r' in w.lower()) for w in words)
            force = any(w == '--force' or (w.startswith('-') and not w.startswith('--') and 'f' in w.lower()) for w in words)
            if recursive and force and any(w.startswith('/') for w in words):
                forms.append('rm -rf /')
        if any(w in ('compose', 'docker-compose') for w in words) and 'down' in words:
            if any(w == '--volumes' or (w.startswith('-') and not w.startswith('--') and 'v' in w) for w in words):
                forms.append('compose down --volumes')
    return forms
VALID_POSTURES = ("frozen", "lockdown", "test", "released")

# Verbs that can never mutate anything, no matter what the policy says.
READ_ONLY_VERBS = frozenset(
    ["show", "details", "containers", "services", "overlays",
     "drift", "verify", "fleet", "plan", "status", "help", "lint", "journal", "ports",
     "backup-verify", "map", "logs", "sql", "index"]
)


def refuse(reason: str, code: int = 2) -> "NoReturn":  # noqa: F821
    journal({"event": "refused", "reason": reason})
    print(f"REFUSED: {reason}", file=sys.stderr)
    print("(every refusal is journaled; see journal/control.jsonl)", file=sys.stderr)
    sys.exit(code)


def journal(entry: dict) -> None:
    """Append-only invocation log, written through the package's hash-chained
    writer so `vpscfg journal verify` covers this door too (the control
    stream was once the one stream with no tamper evidence at all).
    Journaling failure is itself fatal for mutations — an unauditable mutation
    must not happen — but tolerated for reads so a full disk cannot brick
    observation. The judgment is already made by the time this runs, so
    importing the package here cannot open the door: a broken or hostile
    journal module can only make a mutation refuse (fail-closed)."""
    entry = {"argv": sys.argv[1:], "interpreter": sys.executable,
             "isolated": bool(sys.flags.isolated), **entry}
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from vpscfg import journal as _journal
        _journal.append("control", entry)
    except Exception as exc:  # noqa: BLE001 — any journaling failure is the same failure
        if entry.get("event") == "allowed_mutation":
            print("REFUSED: cannot journal, so cannot mutate", file=sys.stderr)
            sys.exit(3)
        print(f"(warning: vpscfg-control could not journal this read: {exc})",
              file=sys.stderr)


def resolve_estate():
    """Where the governor lives: the tool checkout, or the one directory named
    by its pinned `estate.path` file. Resolved by vpscfg/estate.py loaded BY
    FILE PATH from this checkout (not via sys.path or the working directory),
    so this door and the inner one apply one rule and reach one root; the inner
    door still refuses a VPSCFG_CONTROL_PATH that is not the root it resolves
    itself. No environment variable is consulted. Any doubt refuses."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_vpscfg_estate_outer", str(ROOT / "vpscfg" / "estate.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.resolve(str(ROOT))
    except Exception as e:  # noqa: BLE001 — any doubt about the estate is the same doubt
        refuse(f"estate root: {e}")


def load_policy() -> dict:
    try:
        raw = CONTROL_PATH.read_bytes()
        policy = json.loads(raw)
    except FileNotFoundError:
        refuse(f"control file missing: {CONTROL_PATH} — nothing runs without the governor")
    except (json.JSONDecodeError, OSError) as e:
        refuse(f"control file unreadable/invalid JSON ({e}) — failing closed")

    # Schema + invariants. Anything off => tampered => refuse.
    problems = []
    if policy.get("version") != 1:
        problems.append("version must be 1")
    if policy.get("mode") not in VALID_MODES:
        problems.append(f"mode must be one of {VALID_MODES}")
    if not isinstance(policy.get("mutation_enabled"), bool):
        problems.append("mutation_enabled must be a boolean")
    verbs = policy.get("allowed_verbs")
    if not isinstance(verbs, list) or not all(isinstance(v, str) for v in verbs):
        problems.append("allowed_verbs must be a list of strings")
    deny = policy.get("deny_always")
    if not isinstance(deny, list) or not deny:
        problems.append("deny_always missing or empty")
    else:
        missing = [d for d in DENY_ALWAYS_FLOOR if d not in deny]
        if missing:
            problems.append(f"deny_always is missing floor entries (tampering?): {missing}")
    hosts = policy.get("hosts", {})
    for h, cfg in hosts.items():
        if cfg.get("posture") not in VALID_POSTURES:
            problems.append(f"host {h}: invalid posture {cfg.get('posture')!r}")
    scopes = policy.get("scopes", {})
    if not isinstance(scopes.get("unlocked", None), list):
        problems.append("scopes.unlocked must be a list")

    if problems:
        refuse("control file failed validation: " + "; ".join(problems))

    policy["_hash"] = hashlib.sha256(raw).hexdigest()
    return policy


def judge(policy: dict, argv: list) -> dict:
    """Decide. Returns the judgment for journaling; refuses on any violation."""
    if not argv:
        return {"verb": "help", "read_only": True}

    # Grammar: vpscfg <host> <verb> [...] | vpscfg module|fleet|index ...
    first = argv[0]
    if first in ("module", "fleet", "index"):
        # The group word IS the verb; subactions (fleet hosts, module register,
        # index diff) are judged inside the package. 'fleet' and 'index' are
        # read-only; 'module' is not in allowed_verbs in v0, so it refuses
        # here — correctly.
        target_host, verb = None, first
    else:
        target_host, verb = first, (argv[1] if len(argv) > 1 else "show")

    # 1. Verb must be affirmatively allowed.
    if verb not in policy["allowed_verbs"]:
        refuse(f"verb {verb!r} is not in allowed_verbs — the governor has not released it")

    # Flag-sensitive judgment: deploy/ansible/rollback/drill/secret-put
    # without --run are plans (read-only); with --run they are mutations.
    # Judged identically in the inner door (vpscfg/cli.py) — two doors, same rule.
    read_only = verb in READ_ONLY_VERBS or (
        verb in ("deploy", "ansible", "rollback", "drill", "secret-put") and "--run" not in argv
    )

    # 2. deny_always sweep over the ENTIRE argv, case-insensitive substring.
    #    Catches destructive strings anywhere, including inside quoted payloads.
    spellings = floor_spellings(argv)
    for pattern in policy["deny_always"]:
        if any(pattern.lower() in text for text in spellings):
            refuse(f"argument matches deny_always pattern {pattern!r} — never allowed through this door")

    # 3. Mutations need the master switch AND a non-lockdown mode AND host posture.
    if not read_only:
        if not policy["mutation_enabled"]:
            refuse("mutation_enabled is false — the master switch is off")
        if policy["mode"] == "lockdown":
            refuse("mode is 'lockdown' — no mutations in lockdown")
        if target_host:
            posture = policy["hosts"].get(target_host, {}).get("posture", "frozen")
            if posture in ("frozen", "lockdown"):
                refuse(f"host {target_host!r} posture is {posture!r} — mutations refused")
        # 4. Scope must be explicitly unlocked (checked coarsely here; the tool
        #    re-checks with full scope resolution).
        if not policy["scopes"]["unlocked"]:
            refuse("scopes.unlocked is empty — nothing has graduated test+verify yet")

    return {"verb": verb, "host": target_host, "read_only": read_only}


def main() -> int:
    global CONTROL_PATH
    argv = sys.argv[1:]
    estate = resolve_estate()
    CONTROL_PATH = Path(estate.governor)
    policy = load_policy()
    judgment = judge(policy, argv)

    journal({
        "event": "allowed_read" if judgment["read_only"] else "allowed_mutation",
        "judgment": {k: v for k, v in judgment.items()},
        "policy_hash": policy["_hash"][:12],
        "mode": policy["mode"],
        **estate.record(policy["_hash"]),
    })

    # Hand off to the package with the policy-hash token. The package refuses
    # mutations without a token matching its own hash of the same file — so
    # bypassing this wrapper degrades to read-only, never to unguarded.
    env = os.environ.copy()
    env["VPSCFG_CONTROL_TOKEN"] = policy["_hash"]
    env["VPSCFG_CONTROL_PATH"] = str(CONTROL_PATH)

    os.execve(
        _PYTHON,
        [_PYTHON, "-I", "-c", _LAUNCH % "vpscfg", str(ROOT), *argv],
        env,
    )
    return 0  # unreachable; execve replaces the process


if __name__ == "__main__":
    sys.exit(main())
