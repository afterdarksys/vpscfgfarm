"""Append-only JSONL journal. An unauditable mutation must not happen, so a
journaling failure on the mutation path raises rather than passes silently.

Entries are hash-chained: each record carries `prev`, the SHA-256 of the raw
line above it ("genesis" for the first). Editing or deleting ANY past line
breaks every link after it, so tampering is detectable by `vpscfg journal
verify` — cheap enough that fleet watch runs it on every sweep.

Threats:
  - Protects against: silent edit or deletion of past entries (any change
    invalidates every later `prev`); records spliced in after the fact
    (an unchained line following chained ones is flagged); a mirror whose
    shared prefix disagrees or whose tail is longer than the local file
    (`compare_witness`, `vpscfg journal verify --against DIR`).
  - Does NOT protect against: an attacker with write access rewriting the
    whole chain in every copy at once. `chain_verify` alone is blind to a
    shortened tail. The telemetry POST (vpscfg/telemetry.py) is best-effort
    and is not that witness: it swallows failures and is absent when no API
    key is configured. A local file longer than the mirror is lag, not
    truncation.
"""
import hashlib
import fcntl
import hmac
import json
import os
import re
import stat
import time
from pathlib import Path

JOURNAL_DIR = Path(__file__).resolve().parent.parent / "journal"

GENESIS = "genesis"
STREAM_RE = re.compile(r"^[A-Za-z0-9_-]+\Z")


def _line_hash(raw_line):
    return hashlib.sha256(raw_line.encode("utf-8")).hexdigest()


def _read_snapshot(path):
    """Readers must not observe a writer halfway through an append."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r', encoding='utf-8') as stream:
        fcntl.flock(stream, fcntl.LOCK_SH)
        return stream.read()


def operator():
    """Who is acting: the password database's name for the real uid — never
    $USER, $LOGNAME or anything else the environment can set."""
    import pwd
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return "uid%d" % os.getuid()


def append(stream, entry):
    if not stream or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in stream):
        raise ValueError('invalid journal stream')
    JOURNAL_DIR.mkdir(exist_ok=True, mode=0o700)
    path = JOURNAL_DIR / ("%s.jsonl" % stream)
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "operator": operator(),
        **entry,
    }
    # The chain link is system-owned: an entry that tried to carry its own
    # `prev` would forge the chain, so it is set last and unconditionally.
    # flock covers the complete read/hash/append transaction across processes
    # and threads (each append opens a distinct file description).
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a+', encoding='utf-8') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        contents = f.read()
        if contents and not contents.endswith('\n'):
            raise OSError('journal has an incomplete tail; reconcile before appending')
        lines = [line for line in contents.splitlines() if line.strip()]
        record['prev'] = _line_hash(lines[-1]) if lines else GENESIS
        f.write(json.dumps(record) + '\n')
        f.flush()
        os.fsync(f.fileno())
        # Persist the directory entry too, including a newly created stream.
        directory = os.open(JOURNAL_DIR, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    # Local write is done and authoritative; the control-plane copy is
    # best-effort and must never fail the caller (see vpscfg/telemetry.py).
    from . import telemetry
    telemetry.push_event({"stream": stream, **record})
    return record


def chain_verify(stream, journal_dir=None):
    """Walk one stream and check every hash link.

    Returns {"stream", "entries", "chained", "ok", "problems": [(lineno, why)]}.
    Records written before chaining existed (no `prev`) are tolerated as a
    legacy prefix; once a chained record appears, an unchained one after it is
    a violation — that shape is exactly what a spliced-in line looks like.
    """
    path = Path(journal_dir or JOURNAL_DIR) / ("%s.jsonl" % stream)
    problems = []
    entries = chained = 0
    try:
        snapshot = _read_snapshot(path)
        raw_lines = [l for l in snapshot.splitlines() if l.strip()]
        if snapshot and not snapshot.endswith('\n'):
            problems.append((len(raw_lines), 'incomplete journal tail'))
    except FileNotFoundError:
        return {"stream": stream, "entries": 0, "chained": 0, "ok": True,
                "problems": []}
    except (OSError, UnicodeError) as exc:
        return {"stream": stream, "entries": 0, "chained": 0, "ok": False,
                "problems": [(0, 'cannot read journal: %s' % exc)]}
    seen_chained = False
    prev_raw = None
    for lineno, raw in enumerate(raw_lines, 1):
        entries += 1
        try:
            rec = json.loads(raw)
        except ValueError:
            problems.append((lineno, "not valid JSON — journal lines are "
                                     "written by code, never edited"))
            prev_raw = raw
            continue
        if not isinstance(rec, dict) or "prev" not in rec:
            if seen_chained:
                problems.append((lineno, "unchained record after chained ones "
                                         "— spliced in after the fact?"))
            prev_raw = raw
            continue
        seen_chained = True
        chained += 1
        expect = GENESIS if prev_raw is None else _line_hash(prev_raw)
        if not hmac.compare_digest(str(rec["prev"]), expect):
            problems.append((lineno, "prev hash mismatch — this line or the "
                                     "one above it was altered"))
        prev_raw = raw
    return {"stream": stream, "entries": entries, "chained": chained,
            "ok": not problems, "problems": problems}


def streams(journal_dir=None):
    d = Path(journal_dir or JOURNAL_DIR)
    if not d.is_dir():
        return []
    return sorted(p.stem for p in d.glob("*.jsonl"))


def compare_witness(local_text, mirror_text):
    """Compare a local stream with a mirror copy, line by line.

    Returns (ok, problems, local_count, mirror_count). `ok` is False when
    the shared prefix disagrees or the mirror is longer (the local tail was
    cut). A longer local file is lag: ok stays True and problems is
    [(line, "lag")]. Line identity is the SHA-256 of each raw line, compared
    with hmac.compare_digest. The walk stops at the first disagreeing line.
    """
    if not isinstance(local_text, str) or not isinstance(mirror_text, str):
        return False, [(0, "witness text is not text")], 0, 0
    local_lines = local_text.splitlines()
    mirror_lines = mirror_text.splitlines()
    shared = min(len(local_lines), len(mirror_lines))
    for index in range(shared):
        local_hash = _line_hash(local_lines[index])
        mirror_hash = _line_hash(mirror_lines[index])
        if not hmac.compare_digest(local_hash, mirror_hash):
            return False, [(index + 1, "shared prefix disagrees at line %d" % (index + 1))], \
                len(local_lines), len(mirror_lines)
    if len(mirror_lines) > len(local_lines):
        return False, [(len(local_lines) + 1, "mirror tail is longer than local — truncation")], \
            len(local_lines), len(mirror_lines)
    if len(local_lines) > len(mirror_lines):
        return True, [(len(mirror_lines) + 1, "lag")], len(local_lines), len(mirror_lines)
    return True, [], len(local_lines), len(mirror_lines)


def _read_checked(path):
    """Read a regular file. Symlinks and other non-regular files fail closed."""
    if not os.path.lexists(path):
        raise FileNotFoundError(path)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OSError("refusing non-regular journal file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_SH)
        return stream.read()


def read_stream(stream, journal_dir=None):
    """Local stream text. A missing file is an empty stream (lag or genesis)."""
    if not STREAM_RE.fullmatch(stream or ""):
        raise ValueError("invalid journal stream")
    path = Path(journal_dir or JOURNAL_DIR) / ("%s.jsonl" % stream)
    try:
        return _read_checked(path)
    except FileNotFoundError:
        return ""


def mirror_file(mirror_dir, stream):
    """Resolved `<mirror_dir>/<stream>.jsonl`, or raise. The path stays inside
    the mirror directory. `..` in the stream name cannot escape."""
    if not isinstance(mirror_dir, str) or not mirror_dir or not STREAM_RE.fullmatch(stream or ""):
        raise ValueError("invalid mirror stream")
    root = os.path.realpath(mirror_dir)
    if not os.path.isdir(root):
        raise FileNotFoundError(mirror_dir)
    candidate = os.path.normpath(os.path.join(root, "%s.jsonl" % stream))
    if os.path.dirname(candidate) != root:
        raise ValueError("mirror path escapes the mirror dir")
    return candidate


def read_mirror(mirror_dir, stream):
    """Mirror stream text. Missing, symlinked, or non-regular files raise."""
    return _read_checked(mirror_file(mirror_dir, stream))
