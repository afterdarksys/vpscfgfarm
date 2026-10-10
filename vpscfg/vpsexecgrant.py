"""vpsexec approval contracts ("grants") — approve a reviewed break-glass
runbook once, then run its steps for a bounded window without retyping
`BREAK-GLASS:<n>` at every step.

Why it exists: a 40-step break-glass runbook meant typing the exact phrase 40
times, every repetition is a chance for a mistyped key, and stray keystrokes
typed before a prompt were consumed as the answer and aborted the step. A grant replaces ONLY
that typed phrase. Every other gate — the floor, deny_extra, map constraints,
posture / master switch / lockdown, runbook matching, --reason, verify, the
journal — runs unchanged on every use. When a listed step's hosts are all
already test/released, nothing is elevated: the step runs as a normal
mutation and the contract stands in for its ordinary typed phrase (journaled
`grant_used` with `elevated: false`), so a grant-driven walk does not break
on a break_glass step that happens to need no elevation.

A grant is a JSON file (version 1) minted by `vpsexec grant new`:

  * bound to ONE runbook file in policies/ by the sha256 of its bytes, so
    editing the runbook invalidates every grant over it;
  * listing the exact steps (index, why, placement, whitespace-collapsed cmd)
    it may approve, and the hosts it may reach;
  * time-boxed to one of TTLS, never longer than the runbook policy itself;
  * MACed (HMAC-SHA256, canonical JSON) with a 32-byte local key,
    ~/.vpscfg/grant.key, which must be 0600 and owned by the operator;
  * revocable, permanently, via a revocations file in the grants directory.

Use still requires stdin to be a TTY — the same check the typed phrase has.
A contract that is present but invalid for the plan REFUSES; it never falls
back to prompting, so a broken grant cannot quietly turn into a different
approval path.

Threats:
  - Protects against: a tampered or hand-edited grant (HMAC over canonical
    JSON of every other field, compared in constant time; exact key sets at
    every level, duplicate JSON keys refused, 256 KiB cap); a stale grant after
    the runbook was edited (sha256 of the runbook file bytes must equal the
    file vpsexec loaded for this run); expired or revoked grants (expiry
    checked at use, issued_at more than 60 s in the future refused, TTL must be
    one of the allowed values and match expires_at - issued_at, revocation is
    permanent and journaled); scope creep (the planned command and placement
    must equal a listed step that still exists in the loaded runbook with
    break_glass: true, and the planned hosts must be a subset of the grant's
    hosts and of that runbook entry's hosts, and an entry naming a container
    must be the plan's only target — another command, host, container or
    runbook refuses, with or without elevation; a read step is never put in
    a grant); unattended use (stdin must be a TTY at use time, and at mint and
    revoke); other users on the workstation reading or planting grants (grant,
    grants dir and key must be owned by the operator and not group/world
    accessible); accidental keystrokes (pending terminal input is flushed
    before every prompt, and minting/revoking still need an exact typed
    phrase).
  - Does NOT protect against: a process running as the operator — it can read
    grant.key and forge any grant, and it can allocate a pty, so the TTY check
    is the same barrier the typed phrase is today, not a stronger one; root on
    the workstation; a stolen, unexpired grant used from the operator's own
    terminal; a same-user process deleting the revocations file (revocation
    defends against mistakes and lost files, not against the operator's own
    account); a reviewed runbook step that is simply a bad idea — the grant
    approves what the runbook says, which is why runbooks are reviewed.
"""

import datetime
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import stat
import sys
from pathlib import Path

from . import journal
from .commandtext import normalize
from .gates import Refused
from .vpsexecpolicy import ROLLBACK_MARK

try:
    import termios
except ImportError:  # non-POSIX: flushing is best-effort, the exact match is not
    termios = None

VERSION = 1
TTLS = {"15m": 900, "30m": 1800, "1h": 3600, "3h": 10800, "6h": 21600,
        "12h": 43200, "24h": 86400}
MAX_BYTES = 256 * 1024
FUTURE_SKEW_SECONDS = 60
KEY_BYTES = 32

# From the password database, never $HOME: `HOME=/tmp/h` with a copied key
# must not find an empty revocations file and resurrect a revoked grant.
BASE_DIR = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".vpscfg"
GRANT_DIR = BASE_DIR / "grants"
KEY_PATH = BASE_DIR / "grant.key"
REVOCATIONS = "revocations.jsonl"

TOP_KEYS = frozenset(["version", "session_id", "approval_code", "operator",
                      "issued_at", "expires_at", "ttl", "runbook", "hosts",
                      "steps", "options", "mac"])
RUNBOOK_KEYS = frozenset(["file", "sha256"])
STEP_KEYS = frozenset(["index", "why", "where", "cmd", "cmd_sha256"])
OPTION_KEYS = frozenset(["break_glass", "include_rollback"])

SESSION_RE = re.compile(r"^[0-9a-f]{32}$")
CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
CODE_RE = re.compile(r"^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"


# ---------------------------------------------------------------------------
# terminal
# ---------------------------------------------------------------------------

def flush_input(stream):
    """Discard keystrokes typed before a prompt, so they cannot become its
    answer. Best-effort: anything that is not a real terminal is left alone,
    and this never weakens the exact-match check that follows."""
    if termios is None:
        return
    try:
        if stream.isatty():
            termios.tcflush(stream.fileno(), termios.TCIFLUSH)
    except (AttributeError, OSError, ValueError, termios.error):
        pass


def _is_controlling_tty(stream):
    """stdin is THIS process's controlling terminal, and we are in its
    foreground process group. isatty() alone is not enough: a process with no
    terminal can redirect `< /dev/ttys000` (the operator's own tty, owned by
    the operator) and pass it without anyone typing."""
    fd = stream.fileno()
    if not os.isatty(fd):
        return False
    # ENXIO here: this process has no controlling terminal at all.
    os.close(os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY))
    # tcgetpgrp() succeeds only on the CALLER'S controlling terminal (ENOTTY on
    # any other tty), so this is the identity check as well as the foreground
    # check. Comparing fstat() of /dev/tty does not work: on macOS /dev/tty is
    # its own device node, not an alias of the underlying ttys.
    return os.tcgetpgrp(fd) == os.getpgrp()


def _require_tty(stream, what):
    try:
        ok = _is_controlling_tty(stream)
    except (OSError, ValueError, AttributeError):
        ok = False
    if not ok:
        raise Refused("%s needs your real terminal (stdin must be this process's "
                      "controlling TTY, in the foreground) — approval contracts "
                      "are for a human at a keyboard, never for cron, CI or an "
                      "agent" % what)


def _open_regular(path, flags, what, mode=0o600):
    """Open without following a symlink and without blocking on a FIFO, then
    insist on a regular file before anything is read or written."""
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, mode)
    except OSError as e:
        raise Refused("%s %s unreadable (%s)" % (what, path, e))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused("%s %s is not a regular file" % (what, path))
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def _confirm(stream, prompt, want, what):
    _require_tty(stream, what)
    flush_input(stream)
    prompt = prompt or (lambda msg: input(msg))
    typed = prompt("Type %s to %s, anything else aborts: " % (want, what))
    if typed.strip() != want:
        raise Refused("typed text did not match %r — aborted" % want)


# ---------------------------------------------------------------------------
# time, canonical form, key
# ---------------------------------------------------------------------------

def _now(now=None):
    return now or datetime.datetime.now(datetime.timezone.utc)


def _fmt(when):
    return when.astimezone(datetime.timezone.utc).strftime(TIME_FMT)


def _parse_time(text, field):
    try:
        return datetime.datetime.strptime(text, TIME_FMT).replace(
            tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise Refused("grant %s %r is not UTC YYYY-MM-DDTHH:MM:SSZ" % (field, text))


def canonical(fields):
    """The bytes the MAC covers: every field except `mac`, sorted keys,
    compact separators, UTF-8."""
    body = dict((k, v) for k, v in fields.items() if k != "mac")
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _mac(key, fields):
    return hmac.new(key, canonical(fields), hashlib.sha256).hexdigest()


def _private_dir(path, create=False):
    """A directory owned by the operator that nobody else can enter."""
    if create and not path.exists():
        # Every level we create is 0700 (parents=True would use the umask).
        missing = [path] + [p for p in path.parents if not p.exists()]
        for p in reversed(missing):
            p.mkdir(mode=0o700)
    try:
        st = os.lstat(path)
    except OSError as e:
        raise Refused("grant directory %s unavailable (%s)" % (path, e))
    if not stat.S_ISDIR(st.st_mode):
        raise Refused("%s is not a directory" % path)
    if st.st_uid != os.getuid():
        raise Refused("%s is not owned by you — refusing" % path)
    if st.st_mode & 0o077:
        raise Refused("%s is group/world accessible (mode %o) — chmod 700 it"
                      % (path, stat.S_IMODE(st.st_mode)))


def load_key(path=None, create=False):
    """The 32-byte MAC key. Created 0600 with os.urandom on first mint; a key
    file that is not exactly 0600, not ours, or not 32 bytes is refused."""
    path = Path(path or KEY_PATH)
    if create and not path.exists():
        _private_dir(path.parent, create=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(KEY_BYTES))
    fd, st = _open_regular(path, os.O_RDONLY, "grant key")
    with os.fdopen(fd, "rb") as f:
        if st.st_uid != os.getuid():
            raise Refused("grant key %s is not owned by you — refusing" % path)
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise Refused("grant key %s has mode %o, not 600 — refusing to use a "
                          "key others may have read" % (path, stat.S_IMODE(st.st_mode)))
        key = f.read(KEY_BYTES + 1)
    if len(key) != KEY_BYTES:
        raise Refused("grant key %s is not %d bytes" % (path, KEY_BYTES))
    return key


# ---------------------------------------------------------------------------
# selecting what a grant covers
# ---------------------------------------------------------------------------

def find_runbook(policy, name):
    """policy['files'] record for `name` (with or without .yaml/.yml)."""
    wanted = {name, name + ".yaml", name + ".yml"}
    found = [f for f in (policy.get("files") or [])
             if Path(f["path"]).name in wanted
             and not f.get("lapsed") and not f.get("misshapen")]
    if len(found) != 1:
        raise Refused("no loaded runbook policy named %r — see `vpsexec runbooks` "
                      "(only policies/*.yaml that loaded, are unexpired and match "
                      "their declared shape count)" % name)
    return found[0]


def runbook_entries(policy, filename):
    """The entries of one runbook file, in file order: position + 1 is the
    index the policy loader reports in its errors."""
    return [e for e in (policy.get("runbooks") or []) if e.get("source") == filename]


def parse_steps(spec):
    """'1-20,23,25-30' -> sorted unique ints. Anything else refuses."""
    out = set()
    for part in (spec or "").split(","):
        part = part.strip()
        m = re.match(r"^(\d+)(?:-(\d+))?$", part)
        if not m:
            raise Refused("--steps %r: expected a list like 1-20,23,25-30" % spec)
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if lo < 1 or hi < lo:
            raise Refused("--steps range %r is empty or below 1" % part)
        out.update(range(lo, hi + 1))
    return sorted(out)


def _is_rollback(entry):
    return bool(entry.get("rollback")) or ROLLBACK_MARK in str(entry.get("why", "")).lower()


def _is_read_step(entry, classify):
    """True only when the door's own classifier says the step's command is a
    read. No classifier, or one that refuses the command, means NOT a read:
    a step is never called a read on a guess."""
    if classify is None:
        return False
    try:
        return classify(entry["cmd"]) == "read"
    except Refused:
        return False


READ_NOTE = "read: runs without a grant"


def select(policy, name, ttl, steps=None, hosts=None, include_rollback=False,
           aliases=None, now=None, classify=None, report=None):
    """Everything a grant would authorise, or Refused. Pure: writes nothing.

    `classify(cmd) -> tier` is the door's classifier. With it, a step that is
    not break_glass and classifies as a read is reported (READ_NOTE) instead of
    skipped in silence: reads need no approval, so a grant has nothing to add,
    and a read step never becomes a grant step. `report`, when a list, gets
    (index, entry, note) for every step left out and why."""
    report = report if report is not None else []
    if ttl not in TTLS:
        raise Refused("--ttl %r is not allowed — one of: %s"
                      % (ttl, ", ".join(TTLS)))
    aliases = aliases or {}
    record = find_runbook(policy, name)
    filename = Path(record["path"]).name
    entries = runbook_entries(policy, filename)
    issued = _now(now).replace(microsecond=0)
    expires = issued + datetime.timedelta(seconds=TTLS[ttl])
    if not record.get("expires"):
        raise Refused("%s has no expiry, so it grants no runbooks" % filename)
    # The policy is valid through its `expires` date (local, as the loader
    # compares it); a grant must not outlive it.
    if expires.astimezone().strftime("%Y-%m-%d") > record["expires"]:
        raise Refused("%s expires %s, before this %s grant would (%s) — use a "
                      "shorter --ttl or re-review the runbook"
                      % (filename, record["expires"], ttl, _fmt(expires)))

    explicit = parse_steps(steps) if steps else None
    chosen = []
    for index in (explicit or range(1, len(entries) + 1)):
        if index > len(entries):
            raise Refused("%s has %d runbook entries — there is no step %d"
                          % (filename, len(entries), index))
        entry = entries[index - 1]
        if not entry.get("break_glass"):
            if _is_read_step(entry, classify):
                report.append((index, entry, READ_NOTE))
                continue
            if explicit:
                raise Refused("%s step %d is not break_glass: true — a grant "
                              "covers break-glass steps only" % (filename, index))
            report.append((index, entry, "not break_glass: not in this grant; "
                                         "it takes its usual approval"))
            continue
        if _is_rollback(entry) and not include_rollback:
            if explicit:
                raise Refused("%s step %d is a rollback step (%s) — add "
                              "--include-rollback to grant it deliberately"
                              % (filename, index, entry["why"]))
            report.append((index, entry, "rollback: excluded (--include-rollback "
                                         "grants it)"))
            continue
        chosen.append((index, entry))

    union = []
    for _, entry in chosen:
        for h in entry["hosts"]:
            h = aliases.get(h, h)
            if h not in union:
                union.append(h)
    if hosts:
        wanted = []
        for h in (t.strip() for t in hosts.split(",")):
            if not h:
                continue
            if h.startswith("@"):
                raise Refused("--hosts takes host names, not groups (%r)" % h)
            h = aliases.get(h, h)
            if h not in union:
                raise Refused("--hosts names %r, which no selected step of %s "
                              "reaches (%s)" % (h, filename, ", ".join(union) or "none"))
            if h not in wanted:
                wanted.append(h)
        kept = [(i, e) for i, e in chosen
                if any(aliases.get(h, h) in wanted for h in e["hosts"])]
        if explicit and len(kept) != len(chosen):
            dropped = sorted(set(i for i, _ in chosen) - set(i for i, _ in kept))
            raise Refused("--steps %s reach none of --hosts %s"
                          % (",".join(map(str, dropped)), ",".join(wanted)))
        chosen, union = kept, wanted
    if not chosen:
        raise Refused("%s has no eligible break-glass steps for this selection "
                      "(rollback steps need --include-rollback)" % filename)

    return {
        "version": VERSION,
        "operator": getpass.getuser(),
        "issued_at": _fmt(issued),
        "expires_at": _fmt(expires),
        "ttl": ttl,
        "runbook": {"file": filename, "sha256": record["sha256"]},
        "hosts": union,
        "steps": [{"index": i, "why": str(e["why"]), "where": e["where"],
                   "cmd": e["cmd"],
                   "cmd_sha256": hashlib.sha256(e["cmd"].encode("utf-8")).hexdigest()}
                  for i, e in chosen],
        "options": {"break_glass": True, "include_rollback": bool(include_rollback)},
    }


def render(grant, verdict=None, skipped=None):
    lines = []
    if verdict:
        lines.append(verdict)
    if grant.get("session_id"):
        lines.append("  session : %s" % grant["session_id"])
        lines.append("  code    : %s" % grant["approval_code"])
        lines.append("  operator: %s" % grant["operator"])
    lines.append("  runbook : %s  sha256=%s" % (grant["runbook"]["file"],
                                              grant["runbook"]["sha256"]))
    lines.append("  hosts   : %s" % ", ".join(grant["hosts"]))
    lines.append("  window  : %s -> %s (%s)" % (grant["issued_at"],
                                               grant["expires_at"], grant["ttl"]))
    lines.append("  rollback: %s" % ("INCLUDED" if grant["options"]["include_rollback"]
                                     else "excluded"))
    lines.append("  steps   : %d" % len(grant["steps"]))
    for s in grant["steps"]:
        lines.append("    %3d  [%s] %s" % (s["index"], s["where"], s["why"]))
        lines.append("         %s" % s["cmd"])
    if skipped:
        lines.append("  not in this grant: %d step(s)" % len(skipped))
        for index, entry, note in skipped:
            lines.append("    %3d  %s — %s" % (index, note, entry["why"]))
            lines.append("         %s" % entry["cmd"])
    return "\n".join(lines)


def mint(fields, key_path=None, grant_dir=None):
    """Seal and write a grant. Journal-or-refuse: a grant nobody can trace
    must not exist."""
    grant_dir = Path(grant_dir or GRANT_DIR)
    _private_dir(grant_dir, create=True)
    key = load_key(key_path, create=True)
    grant = dict(fields)
    grant["session_id"] = secrets.token_hex(16)
    grant["approval_code"] = "-".join(
        "".join(secrets.choice(CODE_ALPHABET) for _ in range(4)) for _ in range(3))
    grant["mac"] = _mac(key, grant)
    journal.append("vpsexec", {
        "event": "grant_minted", "session_id": grant["session_id"],
        "approval_code": grant["approval_code"], "runbook": grant["runbook"],
        "hosts": grant["hosts"], "steps": [s["index"] for s in grant["steps"]],
        "ttl": grant["ttl"], "expires_at": grant["expires_at"],
        "include_rollback": grant["options"]["include_rollback"]})
    path = grant_dir / ("%s.json" % grant["session_id"])
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(grant, f, indent=2, sort_keys=True)
        f.write("\n")
    return path, grant


# ---------------------------------------------------------------------------
# revocation
# ---------------------------------------------------------------------------

def revoked_ids(grant_dir=None):
    """Session ids revoked so far. A revocations file that exists but cannot
    be trusted or parsed refuses — never reads as "nothing revoked"."""
    path = Path(grant_dir or GRANT_DIR) / REVOCATIONS
    if not os.path.lexists(path):
        return set()
    fd, st = _open_regular(path, os.O_RDONLY, "revocations file")
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise Refused("revocations file %s is not a private regular file owned "
                          "by you — failing closed" % path)
        ids = set()
        try:
            lines = f.read().splitlines()
        except ValueError:
            raise Refused("revocations file %s is not UTF-8 — failing closed" % path)
        for n, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                sid = json.loads(line)["session_id"]
            except (ValueError, KeyError, TypeError):  # UnicodeError is a ValueError
                raise Refused("revocations file %s line %d is invalid — failing "
                              "closed" % (path, n))
            if not isinstance(sid, str) or not SESSION_RE.match(sid):
                raise Refused("revocations file %s line %d has a bad session id"
                              % (path, n))
            ids.add(sid)
    return ids


def revoke(session_id, grant_dir=None, now=None):
    grant_dir = Path(grant_dir or GRANT_DIR)
    _private_dir(grant_dir, create=True)
    path = grant_dir / REVOCATIONS
    revoked_ids(grant_dir)  # an untrusted existing file refuses before we append
    journal.append("vpsexec", {"event": "grant_revoked", "session_id": session_id})
    fd, _ = _open_regular(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                          "revocations file")
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps({"session_id": session_id, "revoked_at": _fmt(_now(now)),
                            "operator": getpass.getuser()}, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key in JSON object")
    return dict(pairs)


def _read_grant(path):
    path = Path(path)
    fd, st = _open_regular(path, os.O_RDONLY, "approval contract")
    with os.fdopen(fd, "rb") as f:
        if st.st_size > MAX_BYTES:
            raise Refused("approval contract %s is %d bytes (limit %d)"
                          % (path, st.st_size, MAX_BYTES))
        if st.st_uid != os.getuid():
            raise Refused("approval contract %s is not owned by you" % path)
        if st.st_mode & 0o077:
            raise Refused("approval contract %s has mode %o — it must not be "
                          "group/world accessible (chmod 600)"
                          % (path, stat.S_IMODE(st.st_mode)))
        raw = f.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise Refused("approval contract %s exceeds %d bytes" % (path, MAX_BYTES))
    _private_dir(path.resolve().parent)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as e:
        raise Refused("approval contract %s is not valid JSON (%s)" % (path, e))
    if not isinstance(doc, dict):
        raise Refused("approval contract %s is not a JSON object" % path)
    return doc


def _exact_keys(obj, keys, where):
    if not isinstance(obj, dict):
        raise Refused("grant %s is not an object" % where)
    extra, missing = sorted(set(obj) - keys), sorted(keys - set(obj))
    if extra or missing:
        raise Refused("grant %s key set is wrong (unknown: %s; missing: %s) — "
                      "refusing rather than guessing" % (where, extra, missing))


def _check_shape(g):
    if g["version"] != VERSION or isinstance(g["version"], bool):
        raise Refused("grant version must be %d" % VERSION)
    if not isinstance(g["mac"], str) or not HEX64_RE.match(g["mac"]):
        raise Refused("grant mac is malformed")
    for key in ("session_id", "approval_code", "operator", "issued_at",
                "expires_at", "ttl"):
        if not isinstance(g[key], str):
            raise Refused("grant %s must be a string" % key)
    if not SESSION_RE.match(g["session_id"]):
        raise Refused("grant session_id is malformed")
    if not CODE_RE.match(g["approval_code"]):
        raise Refused("grant approval_code is malformed")
    _exact_keys(g["runbook"], RUNBOOK_KEYS, "runbook")
    _exact_keys(g["options"], OPTION_KEYS, "options")
    if g["options"]["break_glass"] is not True or not isinstance(
            g["options"]["include_rollback"], bool):
        raise Refused("grant options are invalid")
    if (not isinstance(g["hosts"], list) or not g["hosts"]
            or not all(isinstance(h, str) and h for h in g["hosts"])):
        raise Refused("grant hosts must be a non-empty list of names")
    if not isinstance(g["steps"], list) or not g["steps"]:
        raise Refused("grant steps must be a non-empty list")
    for n, s in enumerate(g["steps"], 1):
        _exact_keys(s, STEP_KEYS, "step %d" % n)
        if (isinstance(s["index"], bool) or not isinstance(s["index"], int)
                or s["index"] < 1 or s["where"] not in ("host", "container")
                or not all(isinstance(s[k], str) for k in ("why", "cmd", "cmd_sha256"))):
            raise Refused("grant step %d is malformed" % n)
        if not hmac.compare_digest(
                s["cmd_sha256"], hashlib.sha256(s["cmd"].encode("utf-8")).hexdigest()):
            raise Refused("grant step %d cmd_sha256 does not match its cmd" % n)


def check(path, policy, now=None, key_path=None, grant_dir=None):
    """Every plan-independent check. Returns the grant or raises Refused.
    Any malformed value (a lone surrogate, a wrong type) is a refusal, never
    an uncaught exception that skips the journal."""
    if policy is None:  # only preflight() may skip the runbook binding
        raise Refused("approval contract cannot be checked without the loaded runbook policy")
    try:
        return _check(path, policy, now, key_path, grant_dir)
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        raise Refused("approval contract %s is malformed (%s)"
                      % (path, type(e).__name__))


def _check(path, policy, now, key_path, grant_dir):
    g = _read_grant(path)
    _exact_keys(g, TOP_KEYS, "top-level")
    key = load_key(key_path)
    if not isinstance(g["mac"], str) or not hmac.compare_digest(
            g["mac"].encode("utf-8"), _mac(key, g).encode("utf-8")):
        raise Refused("approval contract %s failed its MAC — edited, forged, or "
                      "sealed with another key" % path)
    _check_shape(g)

    now = _now(now)
    issued = _parse_time(g["issued_at"], "issued_at")
    expires = _parse_time(g["expires_at"], "expires_at")
    if g["ttl"] not in TTLS:
        raise Refused("grant ttl %r is not one of %s" % (g["ttl"], ", ".join(TTLS)))
    if (expires - issued).total_seconds() != TTLS[g["ttl"]]:
        raise Refused("grant expires_at - issued_at does not equal its ttl %s"
                      % g["ttl"])
    if (issued - now).total_seconds() > FUTURE_SKEW_SECONDS:
        raise Refused("grant issued_at %s is in the future" % g["issued_at"])
    if now >= expires:
        raise Refused("grant %s expired at %s" % (g["session_id"][:8], g["expires_at"]))
    if g["session_id"] in revoked_ids(grant_dir):
        raise Refused("grant %s is revoked (permanently)" % g["session_id"][:8])
    if policy is None:  # preflight(): the runbook binding is checked at use
        return g

    record = find_runbook(policy, g["runbook"]["file"])
    if Path(record["path"]).name != g["runbook"]["file"] or not hmac.compare_digest(
            record["sha256"], g["runbook"]["sha256"]):
        raise Refused("runbook %s changed since this grant was minted (sha256 %s "
                      "now, %s in the grant) — an edited runbook needs a new grant"
                      % (g["runbook"]["file"], record["sha256"][:12],
                         g["runbook"]["sha256"][:12]))
    return g


def preflight(path, now=None, key_path=None, grant_dir=None):
    """Everything check() does except the runbook sha256, which needs the
    loaded policy. For vpsrun to refuse a play UP FRONT; it never approves
    anything — each step's use() in vpsexec does the full check again."""
    path = os.path.expanduser(str(path))
    try:
        return _check(path, None, now, key_path, grant_dir)
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        raise Refused("approval contract %s is malformed (%s)"
                      % (path, type(e).__name__))


def authorize(g, plan, policy, aliases=None):
    """Plan-specific checks. Returns the step that authorises this plan.

    A plan that elevates no host (every host already test/released) is still
    matched against the contract's listed steps exactly as an elevating one
    is: the contract then stands in for that step's ordinary typed phrase
    instead of BREAK-GLASS. The plan stays a normal mutation (break_glass false
    in its hash, no break_glass event); every gate already ran in dispatch.
    A command, placement, host or container the contract does not list still
    refuses — elevation or not."""
    aliases = aliases or {}
    entries = runbook_entries(policy, g["runbook"]["file"])
    command = normalize(plan["command"])
    hosts = [aliases.get(h, h) for h in plan["hosts"]]
    granted = set(aliases.get(h, h) for h in g["hosts"])
    outside = [h for h in hosts if h not in granted]
    if outside:
        raise Refused("approval contract does not cover host(s) %s (it covers %s)"
                      % (", ".join(outside), ", ".join(g["hosts"])))
    for step in g["steps"]:
        if step["cmd"] != command or step["where"] != plan["placement"]:
            continue
        if step["index"] > len(entries):
            continue
        entry = entries[step["index"] - 1]
        if (entry["cmd"] != step["cmd"] or entry["where"] != step["where"]
                or entry.get("break_glass") is not True):
            continue
        # A step whose entry names a container covers only that container,
        # even when another (ungranted) entry would authorise this plan.
        named = entry.get("container")
        if named is not None and any(
                ((plan.get("per_host") or {}).get(h) or {}).get("targets") != [named]
                for h in plan["hosts"]):
            continue
        reach = set(aliases.get(h, h) for h in entry["hosts"])
        if all(h in reach for h in hosts):
            return step
    raise Refused("approval contract does not authorise this plan: no step of %s "
                  "is `%s` (%s) on %s"
                  % (g["runbook"]["file"], command, plan["placement"], ", ".join(hosts)))


def use(path, plan, digest, policy, stream, aliases=None, now=None,
        key_path=None, grant_dir=None):
    """Approve `plan` with the contract at `path`, or Refused. Never prompts:
    an invalid contract refuses instead of falling back to the typed phrase."""
    path = os.path.expanduser(str(path))  # `--approval-contract=~/...` is not shell-expanded
    try:
        _require_tty(stream if stream is not None else sys.stdin,
                     "--approval-contract")
        g = check(path, policy, now=now, key_path=key_path, grant_dir=grant_dir)
        step = authorize(g, plan, policy, aliases=aliases)
    except Refused as r:
        journal.append("vpsexec", {"event": "grant_refused", "contract": str(path),
                                   "plan_hash": digest, "reason": str(r)})
        raise Refused("%s\n  The contract was NOT used and nothing was prompted. "
                      "Drop --approval-contract to type the phrase instead." % r)
    elevated = bool(plan.get("break_glass"))
    journal.append("vpsexec", {
        "event": "grant_used", "session_id": g["session_id"],
        "approval_code": g["approval_code"], "runbook": g["runbook"]["file"],
        "step": step["index"], "hosts": list(plan["hosts"]),
        "command": plan["command"], "plan_hash": digest,
        "expires_at": g["expires_at"], "elevated": elevated})
    print("  approval contract %s  code %s  step %d of %s  (expires %s)%s"
          % (g["session_id"][:8], g["approval_code"], step["index"],
             g["runbook"]["file"], g["expires_at"],
             "" if elevated else "\n  no host needs elevation: a normal mutation, "
                                 "the contract standing in for its typed phrase"))
    return "approval-contract:%s" % g["session_id"]


# ---------------------------------------------------------------------------
# CLI: vpsexec grant new|list|show|revoke
# ---------------------------------------------------------------------------

GRANT_USAGE = """vpsexec grant — approval contracts for break-glass runbooks

  vpsexec grant new <runbook> --ttl <15m|30m|1h|3h|6h|12h|24h>
                    [--steps 1-20,23] [--hosts h1,h2] [--include-rollback] [--run]
                    without --run: print exactly what it would authorise, stop.
                    with --run: TTY only; type GRANT:<runbook>:<ttl> to mint.
  vpsexec grant list            active, expired and revoked grants
  vpsexec grant show <file>     verify one, print VALID or INVALID and why
  vpsexec grant revoke <id>     TTY only; type REVOKE:<first 8 of id>. Permanent.

  use: vpsexec <hosts> '<cmd>' --break-glass --run --reason "why" \\
           --approval-contract=~/.vpscfg/grants/<id>.json
"""


def _status(path, policy, now, key_path, grant_dir):
    try:
        return "VALID", check(path, policy, now=now, key_path=key_path,
                              grant_dir=grant_dir)
    except Refused as r:
        return "INVALID: %s" % r, None


def cli(argv, policy, aliases=None, stream=None, prompt=None, now=None,
        key_path=None, grant_dir=None, classify=None):
    stream = stream if stream is not None else sys.stdin
    grant_dir = Path(grant_dir or GRANT_DIR)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(GRANT_USAGE)
        return 0
    verb, rest = argv[0], argv[1:]

    if verb == "new":
        opts = {"ttl": None, "steps": None, "hosts": None, "rollback": False,
                "run": False}
        positional, i = [], 0
        while i < len(rest):
            a = rest[i]
            if a == "--run":
                opts["run"] = True
            elif a == "--include-rollback":
                opts["rollback"] = True
            elif a.split("=", 1)[0] in ("--ttl", "--steps", "--hosts"):
                name = a.split("=", 1)[0][2:]
                if "=" in a:
                    opts[name] = a.split("=", 1)[1]
                else:
                    if i + 1 >= len(rest):
                        raise Refused("%s needs a value" % a)
                    opts[name] = rest[i + 1]
                    i += 1
            elif a.startswith("-"):
                raise Refused("unknown flag %r for `vpsexec grant new`" % a)
            else:
                positional.append(a)
            i += 1
        if len(positional) != 1 or not opts["ttl"]:
            raise Refused("usage: vpsexec grant new <runbook> --ttl <ttl> "
                          "[--steps ...] [--hosts ...] [--include-rollback] [--run]")
        skipped = []
        fields = select(policy, positional[0], opts["ttl"], steps=opts["steps"],
                        hosts=opts["hosts"], include_rollback=opts["rollback"],
                        aliases=aliases, now=now, classify=classify, report=skipped)
        print(render(fields, "GRANT PLAN — what this approval contract would "
                             "authorise (break-glass phrase only; every other "
                             "gate still runs):", skipped=skipped))
        if not opts["run"]:
            print("")
            print("Plan only. Nothing was written. Re-run with --run to mint it.")
            return 0
        stem = Path(fields["runbook"]["file"]).stem
        _confirm(stream, prompt, "GRANT:%s:%s" % (stem, opts["ttl"]),
                 "mint this grant")
        # Re-select after the prompt: the window starts when it is minted.
        fields = select(policy, positional[0], opts["ttl"], steps=opts["steps"],
                        hosts=opts["hosts"], include_rollback=opts["rollback"],
                        aliases=aliases, now=now, classify=classify)
        path, grant = mint(fields, key_path=key_path, grant_dir=grant_dir)
        print("")
        print("MINTED %s" % path)
        print("  session : %s" % grant["session_id"])
        print("  code    : %s   (printed and journaled on every use)"
              % grant["approval_code"])
        print("  expires : %s" % grant["expires_at"])
        return 0

    if verb == "list":
        if rest:
            raise Refused("`vpsexec grant list` takes no arguments")
        if not grant_dir.is_dir():
            print("no grants (%s does not exist)" % grant_dir)
            return 0
        _private_dir(grant_dir)
        revoked = revoked_ids(grant_dir)
        paths = sorted(p for p in grant_dir.glob("*.json"))
        if not paths:
            print("no grants in %s" % grant_dir)
            return 0
        for p in paths:
            verdict, g = _status(p, policy, now, key_path, grant_dir)
            sid = p.stem
            if sid in revoked:
                label = "REVOKED"
            elif g:
                label = "ACTIVE"
            elif "expired at" in verdict:
                label = "EXPIRED"
            else:
                label = verdict
            if g:
                print("  %-8s %s  %s  %s  %d step(s)  until %s"
                      % (label, sid[:8], g["approval_code"], g["runbook"]["file"],
                         len(g["steps"]), g["expires_at"]))
            else:
                print("  %-8s %s  %s" % (label.split(":")[0], sid[:8],
                                          verdict if label.startswith("INVALID")
                                          else p.name))
        return 0

    if verb == "show":
        if len(rest) != 1:
            raise Refused("usage: vpsexec grant show <file>")
        verdict, g = _status(rest[0], policy, now, key_path, grant_dir)
        print(render(g, "VALID — %s" % rest[0]) if g else verdict)
        return 0 if g else 1

    if verb == "revoke":
        if len(rest) != 1:
            raise Refused("usage: vpsexec grant revoke <session_id>")
        sid = rest[0].strip().lower()
        if not SESSION_RE.match(sid):
            if not re.match(r"^[0-9a-f]{8,31}$", sid):
                raise Refused("session id must be 32 hex characters, or a unique "
                              "prefix of at least 8")
            matches = [p.stem for p in grant_dir.glob("%s*.json" % sid)
                       if SESSION_RE.match(p.stem)]
            if len(matches) != 1:
                raise Refused("prefix %r matches %d grant(s) in %s — give the full id"
                              % (sid, len(matches), grant_dir))
            sid = matches[0]
        print("REVOKE grant %s — permanent; it can never be used again." % sid)
        _confirm(stream, prompt, "REVOKE:%s" % sid[:8], "revoke it")
        revoke(sid, grant_dir=grant_dir, now=now)
        print("REVOKED %s" % sid)
        return 0

    raise Refused("unknown grant verb %r — new, list, show, revoke" % verb)
