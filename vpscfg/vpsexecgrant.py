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

A grant is a JSON file minted by `vpsexec grant new`, of one of two KINDS.
The kind is a MACed field AND the session id's prefix, and the two must agree:

  * short (`st_<32 hex>`; also every version-1 grant, whose id is bare hex):
    bound to ONE runbook file in policies/ by the sha256 of its bytes, so
    editing the runbook invalidates every grant over it; listing the exact
    steps (index, why, placement, whitespace-collapsed cmd) it may approve,
    and the hosts it may reach; time-boxed to one of TTLS.
  * reusable (`ru_<32 hex>`, version 2 only): survives edits to the runbook
    file. It binds a SCOPE instead — one or more policy-file names, a host
    set, and a max-uses count — and at every use matches the plan against
    the break_glass: true entries those files hold AT THAT MOMENT (rollback
    entries only with include_rollback). Time-boxed to one of REUSABLE_TTLS.
    Every use is counted in a per-grant ledger in the grants dir and witnessed
    by `grant_used` journal events; the higher count wins, and at max_uses
    it refuses.

Both kinds: never longer than the runbook policy's own expires; MACed
(HMAC-SHA256, canonical JSON) with a 32-byte local key, ~/.vpscfg/grant.key,
which must be 0600 and owned by the operator; revocable, permanently, via a
revocations file in the grants directory.

Use still requires stdin to be a TTY — the same check the typed phrase has.
A contract that is present but invalid for the plan REFUSES; it never falls
back to prompting, so a broken grant cannot quietly turn into a different
approval path. Auto-pick (`candidates`) only ever offers grants that pass the
full check() and authorize() for the exact plan; an invalid one is skipped,
never chosen, and the chosen one is checked again in full by use().

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
    phrase). Kinds: a kind field that disagrees with the session-id prefix,
    or a v1 grant claiming a kind, refuses (both are under the MAC, so a
    short grant cannot be relabelled reusable without the key); a reusable
    grant over policy that is not pushed to the governor's policy_remote, a
    changed remote URL, a force-pushed remote, or no remote/network (it
    fetches at mint and every use and refuses — fail closed); the policy
    repository's own git config steering that fetch (it fetches the URL
    bound at mint into a private scratch repository; only the operator's
    global config is trusted, and a global rewrite of the bound URL
    refuses); a reusable
    grant covers only break_glass: true entries of the files in its scope,
    only while each file is loaded, unexpired and shape-valid, only hosts in
    its host set, and refuses once its use count (max of the 0600 ledger and
    the hash-chained journal; a broken chain or an untrusted ledger fails
    closed) reaches max_uses. Auto-pick never selects a grant that fails any
    check, prefers the narrower kind, and is printed and journaled.
  - Does NOT protect against: a process running as the operator — it can read
    grant.key and forge any grant, and it can allocate a pty, so the TTY check
    is the same barrier the typed phrase is today, not a stronger one; root on
    the workstation; a stolen, unexpired grant used from the operator's own
    terminal; a same-user process deleting the revocations file (revocation
    defends against mistakes and lost files, not against the operator's own
    account); a reviewed runbook step that is simply a bad idea — the grant
    approves what the runbook says, which is why runbooks are reviewed. For
    a reusable grant specifically: an edit pushed to the policy remote by
    anyone who can push there (pushed is not reviewed unless the branch is
    protected to require review); a same-user process steering the one fetch
    through the operator's global git config; a reviewed-and-pushed edit that ADDS a
    break_glass step to a scoped file is covered by the live grant (that is
    the point of the kind — keep the TTL short and the scope narrow); a
    same-user process deleting BOTH the use ledger and the journal resets the
    count (the same limit the revocations file has).
"""

import datetime
import fcntl
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

VERSION = 2          # what `grant new` writes
VERSIONS = (1, 2)    # what is accepted: a v1 grant is kind short
TTLS = {"15m": 900, "30m": 1800, "1h": 3600, "3h": 10800, "6h": 21600,
        "12h": 43200, "24h": 86400}
REUSABLE_TTLS = {"1h": 3600, "3h": 10800, "6h": 21600, "12h": 43200,
                 "24h": 86400, "72h": 259200, "7d": 604800}
# Auto-pick order: the narrower kind first.
KINDS = ("short", "reusable")
KIND_TTLS = {"short": TTLS, "reusable": REUSABLE_TTLS}
KIND_PREFIX = {"short": "st_", "reusable": "ru_"}
DEFAULT_MAX_USES = 50
MAX_USES_LIMIT = 500
USES_SUFFIX = ".uses"
MAX_BYTES = 256 * 1024
FUTURE_SKEW_SECONDS = 60
KEY_BYTES = 32

# From the password database, never $HOME: `HOME=/tmp/h` with a copied key
# must not find an empty revocations file and resurrect a revoked grant.
BASE_DIR = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".vpscfg"
GRANT_DIR = BASE_DIR / "grants"
KEY_PATH = BASE_DIR / "grant.key"
REVOCATIONS = "revocations.jsonl"


# ---------------------------------------------------------------------------
# A reusable grant is bound to its scope files' PUSHED history (H4a, round
# 5): the governor's `policy_remote` ({name, ref}, default origin/main) is
# fetched at mint and at every use. At mint: the remote URL, the fetched
# commit, and each file's blob there — which must be exactly the bytes the
# policy loader hashed. At use: the same URL, a branch that only moved forward
# from the minted commit (a force-push refuses), and each file's loaded bytes
# equal to the minted blob or to a version pushed to that branch since. The
# blob id is computed here from those bytes, never taken from git's index or
# `git status`. git is pinned (gitcmd.py): an absolute binary and, for every
# call but the fetch, a minimal environment with no system/global config and
# no fsmonitor; the fetch alone uses the operator's credentials, hardened
# separately. An uncommitted or unpushed edit, a local-only commit, a URL
# change, a rewritten remote, no remote, no network or no git at all refuses —
# fail closed. Short grants and incidents never fetch: they keep working
# offline.
#
# Pushing is not review: anyone who can push to the branch (or a process
# holding the operator's credentials) gets the edit covered. The binding
# proves an edit is on the shared remote (visible, attributable, revertable);
# it is REVIEWED only if the branch is protected to require pull-request
# review — enable that (docs/VPSEXEC.md).
# ---------------------------------------------------------------------------

GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


def _git(repo, *args):
    """(rc, stdout) of the pinned git in `repo`. No git at all is a refusal."""
    from . import gitcmd
    return gitcmd.run(repo, *args)


def _scope_repo(policy, filename):
    """(repo top level, path of the file relative to it, the loader's record).

    The file must sit INSIDE its policy directory's own repository worktree,
    reached without a single symlink between the worktree top and the file: a
    scope file symlinked to a private clone (where an edit is "committed") or
    anywhere else refuses. A symlink at or above the top (the estate reached
    through a link) is allowed; the resolved file must still be inside the
    top."""
    record = find_runbook(policy, filename)
    lexical = os.path.abspath(record["path"])
    rc, top = _git(os.path.dirname(lexical), "rev-parse", "--show-toplevel")
    if rc != 0 or not top:
        raise Refused("%s is not in a git repository — a reusable grant covers only "
                      "committed policy files" % filename)
    top = os.path.realpath(top)
    node = lexical
    while True:
        # The walk stops AT the worktree top, before the symlink check: a
        # symlink at or above the top (an estate checkout reached through a
        # link) is how the operator reaches the repository, not a way out of
        # it. Every node between the file and the top must be a real entry.
        if os.path.realpath(node) == top:
            break
        if os.path.islink(node):
            raise Refused("%s reaches its repository through a symlink (%s) — a reusable "
                          "grant covers only a regular file inside the policy repository's "
                          "own worktree" % (filename, node))
        parent = os.path.dirname(node)
        if parent == node:
            raise Refused("%s is not inside its repository's worktree (%s)" % (filename, top))
        node = parent
    real = os.path.realpath(lexical)
    if not real.startswith(top + os.sep):
        raise Refused("%s resolves outside its repository's worktree (%s)" % (filename, top))
    return top, os.path.relpath(real, top), record


MAX_POLICY_BYTES = 1024 * 1024
MAX_HISTORY = 1000   # commits of one scope file searched between minted and remote
DEFAULT_POLICY_REMOTE = {"name": "origin", "ref": "main"}


def policy_remote(policy):
    """(remote name, branch) the governor names (`policy_remote`), which the
    door puts into the loaded policy; the default is origin/main."""
    cfg = (policy or {}).get("policy_remote") or DEFAULT_POLICY_REMOTE
    from . import gitcmd
    if (not isinstance(cfg, dict) or set(cfg) != {"name", "ref"}
            or not gitcmd.valid_remote(cfg["name"], cfg["ref"])):
        raise Refused("policy_remote %r is malformed — failing closed" % (cfg,))
    return cfg["name"], cfg["ref"]


def _loaded_bytes(repo, rel, filename, record):
    """The scope file's bytes, proven to be the very bytes the policy loader
    hashed (so the blob id below is of what the door actually runs)."""
    try:
        with open(os.path.join(repo, rel), "rb") as f:
            data = f.read(MAX_POLICY_BYTES + 1)
    except OSError as e:
        raise Refused("cannot read %s (%s)" % (filename, e))
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), str(record["sha256"])):
        raise Refused("%s changed since the policy was loaded — refusing" % filename)
    return data


def _blob_at(repo, commit, rel):
    """The blob of `rel` at `commit` if it is there as a plain file (mode
    100644: not a symlink, not executable, not a submodule), else None."""
    rc, tree = _git(repo, "ls-tree", commit, "--", rel)
    if rc != 0 or len(tree.splitlines()) != 1 or not tree.startswith("100644 blob "):
        return None
    rc, blob = _git(repo, "rev-parse", "--verify", "--quiet", "%s:%s" % (commit, rel))
    return blob if rc == 0 and GIT_SHA_RE.match(blob) else None


def _remote_url(repo, name, ref):
    """The raw `remote.<name>.url` of the policy repository (read, never
    rewritten, through the hardened git). At mint it becomes the URL the
    grant is bound to; the fetch itself never runs in this repository."""
    rc, url = _git(repo, "config", "--get", "remote.%s.url" % name)
    if rc != 0 or not url:
        raise Refused("the policy repository %s has no remote %r — a reusable grant "
                      "covers only policy pushed to %s/%s (use a short grant or an "
                      "incident instead)" % (repo, name, name, ref))
    return url


def _fetched(repo, url, ref):
    """gitcmd.fetched() for the bound URL, in a scratch repository of the
    policy repository's object format (so blob ids compare)."""
    from . import gitcmd
    rc, fmt = _git(repo, "rev-parse", "--show-object-format")
    return gitcmd.fetched(url, ref, object_format=fmt if rc == 0 and fmt else "sha1")


def _check_fetched(scratch, commit, name, ref):
    rc, _ = _git(scratch, "cat-file", "-e", "%s^{tree}" % commit)
    if rc != 0:
        raise Refused("the fetched %s/%s commit %s is incomplete — failing closed"
                      % (name, ref, commit[:12]))


def _unpushed(filename, name, ref):
    return Refused("%s has uncommitted or unpushed changes (its bytes are not the blob "
                   "pushed to %s/%s; local commits and index flags are not trusted) — "
                   "push (review) them first; a reusable grant never covers an "
                   "unpushed edit" % (filename, name, ref))


def scope_git(policy, files):
    """The mint-time binding of the scope files, which must all live in one
    repository and be, byte for byte, what is pushed to the governor's
    policy remote branch: {commit (the fetched remote commit), blobs,
    toplevel, remote: {name, ref, url}}."""
    from . import gitcmd
    name, ref = policy_remote(policy)
    repo, found = None, []
    for filename in files:
        top, rel, record = _scope_repo(policy, filename)
        if repo is not None and top != repo:
            raise Refused("reusable grant scope files live in different git "
                          "repositories (%s, %s)" % (repo, top))
        repo = top
        found.append((filename, rel, record))
    url = _remote_url(repo, name, ref)
    blobs = {}
    with _fetched(repo, url, ref) as (scratch, commit):
        _check_fetched(scratch, commit, name, ref)
        for filename, rel, record in found:
            data = _loaded_bytes(repo, rel, filename, record)
            blob = _blob_at(scratch, commit, rel)
            if blob is None:
                raise Refused("%s is not a plain file (mode 100644) pushed to %s/%s — "
                              "push it before a reusable grant can cover it"
                              % (filename, name, ref))
            if not hmac.compare_digest(gitcmd.blob_id(data, len(blob)), blob):
                raise _unpushed(filename, name, ref)
            blobs[filename] = blob
    return {"commit": commit, "blobs": blobs, "toplevel": repo,
            "remote": {"name": name, "ref": ref, "url": url}}


def _pushed_since(repo, rel, minted, head, blob):
    """True when `blob` is the file at the remote head, or at a commit
    between the minted remote commit and it (the operator has not pulled the
    newest push yet). Bounded to MAX_HISTORY commits."""
    if _blob_at(repo, head, rel) == blob:
        return True
    rc, out = _git(repo, "rev-list", "--max-count=%d" % MAX_HISTORY,
                   "%s..%s" % (minted, head), "--", rel)
    if rc != 0:
        return False
    return any(_blob_at(repo, c, rel) == blob for c in out.split() if GIT_SHA_RE.match(c))


def verify_scope_git(g, policy):
    """Refused unless every scope file is in the SAME repository worktree
    the grant was minted in, that repository's policy remote still has the
    minted URL, its branch moved only forward from the minted commit, and the
    file's bytes (as loaded) are the minted blob or a version pushed to that
    branch since — fetched now, fail closed."""
    from . import gitcmd
    minted = g["scope"]["git"]
    name, ref = policy_remote(policy)
    if (name, ref) != (minted["remote"]["name"], minted["remote"]["ref"]):
        raise Refused("the governor's policy_remote is now %s/%s; this grant was minted "
                      "against %s/%s — mint a new grant"
                      % (name, ref, minted["remote"]["name"], minted["remote"]["ref"]))
    checked = []
    for filename in g["scope"]["files"]:
        top, rel, record = _scope_repo(policy, filename)
        if top != minted["toplevel"]:
            raise Refused("%s now lives in the repository at %s, not the one this grant "
                          "was minted in (%s) — mint a new grant"
                          % (filename, top, minted["toplevel"]))
        checked.append((filename, rel, record))
    url = _remote_url(minted["toplevel"], name, ref)
    if url != minted["remote"]["url"]:
        raise Refused("remote %s of the policy repository now points at %s, not %s "
                      "where this grant was minted — mint a new grant"
                      % (name, url, minted["remote"]["url"]))
    # Fetch the URL BOUND AT MINT, in a private scratch repository: the
    # policy repository's own config is never read by the network call.
    bound = minted["remote"]["url"]
    with _fetched(minted["toplevel"], bound, ref) as (scratch, head):
        _check_fetched(scratch, head, name, ref)
        rc, _ = _git(scratch, "merge-base", "--is-ancestor", minted["commit"], head)
        if rc != 0:
            raise Refused("%s/%s no longer descends from commit %s this grant was minted "
                          "over (force-pushed or rewritten) — mint a new grant"
                          % (name, ref, minted["commit"][:12]))
        for filename, rel, record in checked:
            want = minted["blobs"][filename]
            then = _blob_at(scratch, minted["commit"], rel)
            if then is None or not hmac.compare_digest(then, want):
                raise Refused("%s at the minted commit %s is not the minted blob %s — "
                              "failing closed" % (filename, minted["commit"][:12], want[:12]))
            if _blob_at(scratch, head, rel) is None:
                raise Refused("%s is not a plain file (mode 100644) on %s/%s now (removed, "
                              "made a symlink, executable or a submodule) — refusing"
                              % (filename, name, ref))
            data = _loaded_bytes(minted["toplevel"], rel, filename, record)
            blob = gitcmd.blob_id(data, len(want))
            if hmac.compare_digest(blob, want):
                continue
            if not _pushed_since(scratch, rel, minted["commit"], head, blob):
                raise _unpushed(filename, name, ref)
    return True


def operator():
    """Who is acting, from the password database of the real uid — never
    $USER, $LOGNAME (getpass) or anything else the environment can set. One
    definition, journal.operator(), so every record agrees."""
    return journal.operator()

TOP_KEYS = frozenset(["version", "session_id", "approval_code", "operator",
                      "issued_at", "expires_at", "ttl", "runbook", "hosts",
                      "steps", "options", "mac"])
RUNBOOK_KEYS = frozenset(["file", "sha256"])
STEP_KEYS = frozenset(["index", "why", "where", "cmd", "cmd_sha256"])
OPTION_KEYS = frozenset(["break_glass", "include_rollback"])
# Version 2: the v1 short key set plus `kind`; reusable swaps runbook+steps
# for scope+max_uses.
SHORT_KEYS = TOP_KEYS | frozenset(["kind"])
REUSABLE_KEYS = frozenset(["version", "kind", "session_id", "approval_code",
                           "operator", "issued_at", "expires_at", "ttl", "scope",
                           "hosts", "max_uses", "options", "mac", "release"])
# `git`: {commit, blobs} at mint (H4a). `release` (top level): the vpsrun
# release a grant was minted for, or null; auto-pick never spends a
# release-bound grant on anything but that release (M6).
SCOPE_KEYS = frozenset(["files", "git"])
RELEASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SCOPE_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$")

# Any accepted spelling: bare hex (v1) or a kind prefix (v2).
SESSION_RE = re.compile(r"^(?:(?:st|ru)_)?[0-9a-f]{32}$")
V1_SESSION_RE = re.compile(r"^[0-9a-f]{32}$")
V2_SESSION_RE = re.compile(r"^(?:st|ru)_[0-9a-f]{32}$")
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


def kind_of(g):
    """A checked grant's kind: version 1 grants carry none and are short."""
    return g.get("kind", "short")


def short_id(sid):
    """What a human reads and types: the kind prefix plus 8 hex, or 8 hex."""
    return sid[:11] if sid[2:3] == "_" else sid[:8]


def _check_expiry_cap(record, filename, expires, ttl):
    if not record.get("expires"):
        raise Refused("%s has no expiry, so it grants no runbooks" % filename)
    # The policy is valid through its `expires` date (local, as the loader
    # compares it); a grant must not outlive it.
    if expires.astimezone().strftime("%Y-%m-%d") > record["expires"]:
        raise Refused("%s expires %s, before this %s grant would (%s) — use a "
                      "shorter --ttl or re-review the runbook"
                      % (filename, record["expires"], ttl, _fmt(expires)))


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
    _check_expiry_cap(record, filename, expires, ttl)

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
        "kind": "short",
        "operator": operator(),
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


def _parse_max_uses(value):
    try:
        n = int(str(value).strip(), 10)
    except ValueError:
        n = 0
    if not 1 <= n <= MAX_USES_LIMIT:
        raise Refused("--max-uses %r: expected a whole number 1-%d"
                      % (value, MAX_USES_LIMIT))
    return n


def select_reusable(policy, names, ttl, hosts=None, include_rollback=False,
                    max_uses=DEFAULT_MAX_USES, aliases=None, now=None,
                    classify=None, report=None, preview=None, release=None):
    """A reusable grant over the policy files in `names` (comma-separated), or
    Refused. Pure: writes nothing. `preview`, when a list, gets (file, index,
    entry) for every step it would cover TODAY — at use it covers whatever
    break_glass entries those files hold then, so this is a snapshot."""
    report = report if report is not None else []
    preview = preview if preview is not None else []
    if ttl not in REUSABLE_TTLS:
        raise Refused("--ttl %r is not allowed for a reusable grant — one of: %s"
                      % (ttl, ", ".join(REUSABLE_TTLS)))
    max_uses = _parse_max_uses(max_uses)
    aliases = aliases or {}
    issued = _now(now).replace(microsecond=0)
    expires = issued + datetime.timedelta(seconds=REUSABLE_TTLS[ttl])
    files, union = [], []
    for name in (n.strip() for n in (names or "").split(",")):
        if not name:
            continue
        record = find_runbook(policy, name)
        filename = Path(record["path"]).name
        if filename in files:
            continue
        _check_expiry_cap(record, filename, expires, ttl)
        files.append(filename)
        for index, entry in enumerate(runbook_entries(policy, filename), 1):
            if not entry.get("break_glass"):
                report.append((index, entry, READ_NOTE if _is_read_step(entry, classify)
                               else "not break_glass: never covered by a grant"))
                continue
            if _is_rollback(entry) and not include_rollback:
                report.append((index, entry, "rollback: excluded (--include-rollback "
                                             "grants it)"))
                continue
            preview.append((filename, index, entry))
            for h in entry["hosts"]:
                h = aliases.get(h, h)
                if h not in union:
                    union.append(h)
    if not files:
        raise Refused("a reusable grant needs at least one policy file name")
    if hosts:
        wanted = []
        for h in (t.strip() for t in hosts.split(",")):
            if not h:
                continue
            if h.startswith("@"):
                raise Refused("--hosts takes host names, not groups (%r)" % h)
            h = aliases.get(h, h)
            if h not in union:
                raise Refused("--hosts names %r, which no break-glass step of %s "
                              "reaches (%s)" % (h, ", ".join(files),
                                               ", ".join(union) or "none"))
            if h not in wanted:
                wanted.append(h)
        preview[:] = [(f, i, e) for f, i, e in preview
                      if any(aliases.get(h, h) in wanted for h in e["hosts"])]
        union = wanted
    if not preview:
        raise Refused("%s has no eligible break-glass steps for this selection "
                      "(rollback steps need --include-rollback)" % ", ".join(files))
    if release is not None and not RELEASE_NAME_RE.match(str(release)):
        raise Refused("--for-release %r is not a release name" % (release,))
    return {
        "version": VERSION,
        "kind": "reusable",
        "operator": operator(),
        "issued_at": _fmt(issued),
        "expires_at": _fmt(expires),
        "ttl": ttl,
        "scope": {"files": files, "git": scope_git(policy, files)},
        "hosts": union,
        "max_uses": max_uses,
        "options": {"break_glass": True, "include_rollback": bool(include_rollback)},
        "release": release,
    }


def render(grant, verdict=None, skipped=None, preview=None, used=None):
    lines = []
    if verdict:
        lines.append(verdict)
    kind = kind_of(grant)
    lines.append("  kind    : %s" % kind)
    if grant.get("session_id"):
        lines.append("  session : %s" % grant["session_id"])
        lines.append("  code    : %s" % grant["approval_code"])
        lines.append("  operator: %s" % grant["operator"])
    if kind == "reusable":
        remote = grant["scope"]["git"]["remote"]
        lines.append("  scope   : %s — the break_glass steps these files hold AT "
                     "EACH USE (pushed edits only: bound to %s/%s at commit %s, %s)"
                     % (", ".join(grant["scope"]["files"]), remote["name"], remote["ref"],
                        grant["scope"]["git"]["commit"][:12], remote["url"]))
        if grant.get("release"):
            lines.append("  release : %s only (auto-pick never spends it elsewhere)"
                         % grant["release"])
    else:
        lines.append("  runbook : %s  sha256=%s" % (grant["runbook"]["file"],
                                                  grant["runbook"]["sha256"]))
    lines.append("  hosts   : %s" % ", ".join(grant["hosts"]))
    lines.append("  window  : %s -> %s (%s)" % (grant["issued_at"],
                                               grant["expires_at"], grant["ttl"]))
    lines.append("  rollback: %s" % ("INCLUDED" if grant["options"]["include_rollback"]
                                     else "excluded"))
    if kind == "reusable":
        lines.append("  uses    : %s of %d" % ("?" if used is None else used,
                                               grant["max_uses"]))
        if preview is not None:
            lines.append("  steps today: %d" % len(preview))
            for filename, index, e in preview:
                lines.append("    %s %3d  [%s] %s" % (filename, index, e["where"], e["why"]))
                lines.append("         %s" % e["cmd"])
    else:
        lines.append("  steps   : %d" % len(grant["steps"]))
    for s in grant.get("steps") or []:
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
    kind = grant.get("kind")
    if grant.get("version") != VERSION or kind not in KINDS:
        raise Refused("mint takes version-%d fields of a known kind" % VERSION)
    # Same 128-bit CSPRNG id for every kind; the prefix names the kind.
    grant["session_id"] = KIND_PREFIX[kind] + secrets.token_hex(16)
    grant["approval_code"] = "-".join(
        "".join(secrets.choice(CODE_ALPHABET) for _ in range(4)) for _ in range(3))
    grant["mac"] = _mac(key, grant)
    event = {
        "event": "grant_minted", "kind": kind, "session_id": grant["session_id"],
        "approval_code": grant["approval_code"], "hosts": grant["hosts"],
        "ttl": grant["ttl"], "expires_at": grant["expires_at"],
        "include_rollback": grant["options"]["include_rollback"]}
    if kind == "reusable":
        event.update(scope=grant["scope"], max_uses=grant["max_uses"])
    else:
        event.update(runbook=grant["runbook"],
                     steps=[s["index"] for s in grant["steps"]])
    journal.append("vpsexec", event)
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
                            "operator": operator()}, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------------------
# reusable use count: ledger in the grants dir, witnessed by the journal
# ---------------------------------------------------------------------------

def _ledger_lines(text, sid, path):
    n = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            ok = isinstance(rec, dict) and rec["session_id"] == sid
        except (ValueError, KeyError, TypeError):
            ok = False
        if not ok:
            raise Refused("use ledger %s line %d is invalid — failing closed"
                          % (path, lineno))
        n += 1
    return n


def _open_ledger(path, flags):
    fd, st = _open_regular(path, flags, "use ledger")
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        os.close(fd)
        raise Refused("use ledger %s is not a private regular file owned by you "
                      "— failing closed" % path)
    return fd


def _journal_uses(sid):
    """`grant_used` events for `sid` in a journal whose hash chain verifies.
    A broken chain is not a count anyone can trust: refuse."""
    report = journal.chain_verify("vpsexec")
    if not report["ok"]:
        raise Refused("the vpsexec journal's hash chain does not verify (%s) — a "
                      "reusable grant's use count cannot be trusted; failing closed"
                      % "; ".join("line %s: %s" % p for p in report["problems"][:3]))
    try:
        text = journal.read_stream("vpsexec")
    except (OSError, ValueError) as e:  # UnicodeError is a ValueError
        raise Refused("the vpsexec journal cannot be read (%s) — failing closed" % e)
    n = 0
    for line in text.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if (isinstance(rec, dict) and rec.get("event") == "grant_used"
                and rec.get("session_id") == sid):
            n += 1
    return n


def uses(g, grant_dir=None):
    """Uses so far: the higher of the ledger and the journal, so truncating
    either one alone does not reset the count."""
    sid = g["session_id"]
    path = Path(grant_dir or GRANT_DIR) / (sid + USES_SUFFIX)
    ledger = 0
    if os.path.lexists(path):
        fd = _open_ledger(path, os.O_RDONLY)
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                ledger = _ledger_lines(f.read(), sid, path)
            except ValueError:  # not UTF-8
                raise Refused("use ledger %s is not UTF-8 — failing closed" % path)
    return max(ledger, _journal_uses(sid))


def _reserve_use(g, digest, grant_dir=None, now=None):
    """Count this use, or Refused at max_uses. The count and the append happen
    under one exclusive lock, so two terminals cannot both take the last use."""
    sid = g["session_id"]
    grant_dir = Path(grant_dir or GRANT_DIR)
    _private_dir(grant_dir)
    path = grant_dir / (sid + USES_SUFFIX)
    fd = _open_ledger(path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
    with os.fdopen(fd, "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        try:
            used = max(_ledger_lines(f.read(), sid, path), _journal_uses(sid))
        except ValueError:
            raise Refused("use ledger %s is not UTF-8 — failing closed" % path)
        if used >= g["max_uses"]:
            raise Refused("reusable grant %s has been used %d of %d time(s) — it is "
                          "spent; mint a new one" % (short_id(sid), used, g["max_uses"]))
        f.write(json.dumps({"session_id": sid, "plan_hash": digest,
                            "at": _fmt(_now(now))}, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return used + 1


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


def _top_keys(g):
    """The exact key set this grant must have: v1 is the original short set;
    v2 is chosen by its kind. Anything else falls back to the v1 set, so the
    refusal names the wrong keys, and _check_shape names the version."""
    v = g.get("version")
    if v == 2 and not isinstance(v, bool):
        kind = g.get("kind")
        if kind == "short":
            return SHORT_KEYS
        if kind == "reusable":
            return REUSABLE_KEYS
        raise Refused("grant kind %r is not one of: %s" % (kind, ", ".join(KINDS)))
    return TOP_KEYS


def _check_shape(g):
    v = g["version"]
    if isinstance(v, bool) or not isinstance(v, int) or v not in VERSIONS:
        raise Refused("grant version must be one of %s"
                      % ", ".join(str(n) for n in VERSIONS))
    kind = kind_of(g)
    if v == 1 and "kind" in g:
        raise Refused("a version-1 grant has no kind field")
    if kind not in KINDS:
        raise Refused("grant kind is malformed")
    if not isinstance(g["mac"], str) or not HEX64_RE.match(g["mac"]):
        raise Refused("grant mac is malformed")
    for key in ("session_id", "approval_code", "operator", "issued_at",
                "expires_at", "ttl"):
        if not isinstance(g[key], str):
            raise Refused("grant %s must be a string" % key)
    if not (V1_SESSION_RE if v == 1 else V2_SESSION_RE).match(g["session_id"]):
        raise Refused("grant session_id is malformed")
    if v == 2 and not g["session_id"].startswith(KIND_PREFIX[kind]):
        raise Refused("grant session_id prefix %r does not match its kind %r "
                      "(a %s grant's id starts %r) — refusing"
                      % (g["session_id"][:3], kind, kind, KIND_PREFIX[kind]))
    if not CODE_RE.match(g["approval_code"]):
        raise Refused("grant approval_code is malformed")
    _exact_keys(g["options"], OPTION_KEYS, "options")
    if g["options"]["break_glass"] is not True or not isinstance(
            g["options"]["include_rollback"], bool):
        raise Refused("grant options are invalid")
    if (not isinstance(g["hosts"], list) or not g["hosts"]
            or not all(isinstance(h, str) and h for h in g["hosts"])):
        raise Refused("grant hosts must be a non-empty list of names")
    if kind == "reusable":
        _exact_keys(g["scope"], SCOPE_KEYS, "scope")
        files = g["scope"]["files"]
        if (not isinstance(files, list) or not files
                or not all(isinstance(f, str) and SCOPE_FILE_RE.match(f) for f in files)
                or len(set(files)) != len(files)):
            raise Refused("grant scope files must be a non-empty list of distinct "
                          "policy file names")
        m = g["max_uses"]
        if isinstance(m, bool) or not isinstance(m, int) or not 1 <= m <= MAX_USES_LIMIT:
            raise Refused("grant max_uses must be a whole number 1-%d" % MAX_USES_LIMIT)
        git = g["scope"]["git"]
        from . import gitcmd
        remote = git.get("remote") if isinstance(git, dict) else None
        if (not isinstance(git, dict) or set(git) != {"commit", "blobs", "toplevel", "remote"}
                or not isinstance(remote, dict) or set(remote) != {"name", "ref", "url"}
                or not gitcmd.valid_remote(remote["name"], remote["ref"])
                or not isinstance(remote["url"], str) or not remote["url"]
                or not isinstance(git["toplevel"], str) or not git["toplevel"].startswith("/")
                or not isinstance(git["commit"], str) or not GIT_SHA_RE.match(git["commit"])
                or not isinstance(git["blobs"], dict) or set(git["blobs"]) != set(files)
                or not all(isinstance(b, str) and GIT_SHA_RE.match(b)
                           for b in git["blobs"].values())):
            raise Refused("grant scope git binding is malformed (a reusable grant minted "
                          "before policy_remote binding must be minted again)")
        rel = g["release"]
        if rel is not None and not (isinstance(rel, str) and RELEASE_NAME_RE.match(rel)):
            raise Refused("grant release is malformed")
        return
    _exact_keys(g["runbook"], RUNBOOK_KEYS, "runbook")
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
    _exact_keys(g, _top_keys(g), "top-level")
    key = load_key(key_path)
    if not isinstance(g["mac"], str) or not hmac.compare_digest(
            g["mac"].encode("utf-8"), _mac(key, g).encode("utf-8")):
        raise Refused("approval contract %s failed its MAC — edited, forged, or "
                      "sealed with another key" % path)
    _check_shape(g)

    now = _now(now)
    issued = _parse_time(g["issued_at"], "issued_at")
    expires = _parse_time(g["expires_at"], "expires_at")
    kind = kind_of(g)
    ttls = KIND_TTLS[kind]
    if g["ttl"] not in ttls:
        raise Refused("grant ttl %r is not one of %s for a %s grant"
                      % (g["ttl"], ", ".join(ttls), kind))
    if (expires - issued).total_seconds() != ttls[g["ttl"]]:
        raise Refused("grant expires_at - issued_at does not equal its ttl %s"
                      % g["ttl"])
    if (issued - now).total_seconds() > FUTURE_SKEW_SECONDS:
        raise Refused("grant issued_at %s is in the future" % g["issued_at"])
    if now >= expires:
        raise Refused("grant %s expired at %s" % (short_id(g["session_id"]),
                                                  g["expires_at"]))
    if g["session_id"] in revoked_ids(grant_dir):
        raise Refused("grant %s is revoked (permanently)" % short_id(g["session_id"]))
    if policy is None:  # preflight(): the runbook binding is checked at use
        return g

    if kind == "reusable":
        # No file hash: each scoped file must be loaded, unexpired and
        # shape-valid NOW (find_runbook skips lapsed and misshapen files), and
        # committed: the minted blob or a later commit of it (H4a).
        for filename in g["scope"]["files"]:
            record = find_runbook(policy, filename)
            if Path(record["path"]).name != filename:
                raise Refused("reusable grant scope names %s, which is not a loaded "
                              "policy file" % filename)
        verify_scope_git(g, policy)
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


def _entry_reaches(entry, plan, hosts, aliases):
    """The runbook entry covers every planned host, and — if it names a
    container — the plan targets exactly that container on every host (even
    when another, ungranted entry would authorise this plan)."""
    named = entry.get("container")
    if named is not None and any(
            ((plan.get("per_host") or {}).get(h) or {}).get("targets") != [named]
            for h in plan["hosts"]):
        return False
    reach = set(aliases.get(h, h) for h in entry["hosts"])
    return all(h in reach for h in hosts)


def authorize(g, plan, policy, aliases=None):
    """Plan-specific checks. Returns the step that authorises this plan.

    A plan that elevates no host (every host already test/released) is still
    matched against the contract's listed steps exactly as an elevating one
    is: the contract then stands in for that step's ordinary typed phrase
    instead of BREAK-GLASS. The plan stays a normal mutation (break_glass false
    in its hash, no break_glass event); every gate already ran in dispatch.
    A command, placement, host or container the contract does not list still
    refuses — elevation or not.

    A reusable grant has no step list: the plan must match a break_glass: true
    entry (not a rollback entry unless include_rollback) of a file in its
    scope, as that file reads now. The returned step carries that entry's
    index and file."""
    aliases = aliases or {}
    command = normalize(plan["command"])
    hosts = [aliases.get(h, h) for h in plan["hosts"]]
    granted = set(aliases.get(h, h) for h in g["hosts"])
    outside = [h for h in hosts if h not in granted]
    if outside:
        raise Refused("approval contract does not cover host(s) %s (it covers %s)"
                      % (", ".join(outside), ", ".join(g["hosts"])))
    if kind_of(g) == "reusable":
        for filename in g["scope"]["files"]:
            for index, entry in enumerate(runbook_entries(policy, filename), 1):
                if (entry.get("break_glass") is not True or entry["cmd"] != command
                        or entry["where"] != plan["placement"]):
                    continue
                if _is_rollback(entry) and not g["options"]["include_rollback"]:
                    continue
                if _entry_reaches(entry, plan, hosts, aliases):
                    return {"index": index, "file": filename}
        raise Refused("approval contract does not authorise this plan: no "
                      "break_glass step of %s is `%s` (%s) on %s"
                      % (", ".join(g["scope"]["files"]), command, plan["placement"],
                         ", ".join(hosts)))
    entries = runbook_entries(policy, g["runbook"]["file"])
    for step in g["steps"]:
        if step["cmd"] != command or step["where"] != plan["placement"]:
            continue
        if step["index"] > len(entries):
            continue
        entry = entries[step["index"] - 1]
        if (entry["cmd"] != step["cmd"] or entry["where"] != step["where"]
                or entry.get("break_glass") is not True):
            continue
        if _entry_reaches(entry, plan, hosts, aliases):
            return step
    raise Refused("approval contract does not authorise this plan: no step of %s "
                  "is `%s` (%s) on %s"
                  % (g["runbook"]["file"], command, plan["placement"], ", ".join(hosts)))


def use(path, plan, digest, policy, stream, aliases=None, now=None,
        key_path=None, grant_dir=None, flag="--approval-contract"):
    """Approve `plan` with the contract at `path`, or Refused. Never prompts:
    an invalid contract refuses instead of falling back to the typed phrase.
    `flag` is how the operator asked for it, so the refusal names that."""
    path = os.path.expanduser(str(path))  # `--approval-contract=~/...` is not shell-expanded
    try:
        _require_tty(stream if stream is not None else sys.stdin,
                     "--approval-contract")
        g = check(path, policy, now=now, key_path=key_path, grant_dir=grant_dir)
        step = authorize(g, plan, policy, aliases=aliases)
        kind = kind_of(g)
        # Counted only once every check has passed; refused at max_uses.
        count = (_reserve_use(g, digest, grant_dir=grant_dir, now=now)
                 if kind == "reusable" else None)
    except Refused as r:
        journal.append("vpsexec", {"event": "grant_refused", "contract": str(path),
                                   "plan_hash": digest, "reason": str(r)})
        raise Refused("%s\n  The contract was NOT used and nothing was prompted. "
                      "Drop %s to type the phrase instead." % (r, flag))
    elevated = bool(plan.get("break_glass"))
    runbook = step.get("file") or g["runbook"]["file"]
    event = {
        "event": "grant_used", "kind": kind, "session_id": g["session_id"],
        "approval_code": g["approval_code"], "runbook": runbook,
        "step": step["index"], "hosts": list(plan["hosts"]),
        "command": plan["command"], "plan_hash": digest,
        "expires_at": g["expires_at"], "elevated": elevated}
    if count is not None:
        event.update(use=count, max_uses=g["max_uses"])
    journal.append("vpsexec", event)
    print("  approval contract %s %s  code %s  step %d of %s  (expires %s)%s%s"
          % (kind, short_id(g["session_id"]), g["approval_code"], step["index"],
             runbook, g["expires_at"],
             "" if count is None else "  use %d of %d" % (count, g["max_uses"]),
             "" if elevated else "\n  no host needs elevation: a normal mutation, "
                                 "the contract standing in for its typed phrase"))
    return "approval-contract:%s" % g["session_id"]


def candidates(plan, policy, aliases=None, now=None, key_path=None, grant_dir=None):
    """Every grant in the grants dir that is VALID and covers this exact plan,
    in auto-pick order: the narrower kind first (short before reusable), then
    the soonest-expiring, then the lowest session id (deterministic). Pure
    reads: nothing is counted, journaled or prompted here. A grant that fails
    ANY check is skipped — never offered. A grants dir that exists but is not
    private refuses (fail closed), as it does for an explicit contract."""
    grant_dir = Path(grant_dir or GRANT_DIR)
    if not os.path.lexists(grant_dir):
        return []
    _private_dir(grant_dir)
    found = []
    for p in sorted(grant_dir.glob("*.json")):
        if not SESSION_RE.match(p.stem):
            continue
        try:
            g = check(p, policy, now=now, key_path=key_path, grant_dir=grant_dir)
            if g["session_id"] != p.stem:  # a renamed copy is not offered
                continue
            step = authorize(g, plan, policy, aliases=aliases)
            left = None
            if kind_of(g) == "reusable":
                left = g["max_uses"] - uses(g, grant_dir=grant_dir)
                if left <= 0:
                    continue
        except (Refused, ValueError, TypeError, KeyError, AttributeError):
            continue
        found.append({"path": str(p), "grant": g, "step": step, "left": left})
    found.sort(key=_rank)
    return found


def _rank(c):
    g = c["grant"]
    return (KINDS.index(kind_of(g)), g["expires_at"], g["session_id"])


def render_candidates(found):
    """Plan-mode lines (vpsrun reads the id lines; the door re-checks all)."""
    if not found:
        return "  grants  : none valid for this plan"
    lines = ["  grants  : %d valid for this plan (auto-pick order):" % len(found)]
    for c in found:
        g = c["grant"]
        lines.append("            %s %s until %s code %s%s%s"
                     % (g["session_id"], kind_of(g), g["expires_at"],
                        g["approval_code"],
                        "" if c["left"] is None else " uses-left %d" % c["left"],
                        " release %s" % g["release"] if g.get("release") else ""))
    return "\n".join(lines)


def unbound(found):
    """Candidates an ad-hoc `--grant auto` may spend: never a grant minted for
    a vpsrun release (M6) — that one is spent only by naming it."""
    return [c for c in found if not c["grant"].get("release")]


def announce(found, digest):
    """Pick the first candidate, print why, journal it. Returns its path."""
    chosen = found[0]
    g = chosen["grant"]
    ties = [c for c in found[1:] if _rank(c)[:2] == _rank(chosen)[:2]]
    print("  grant   : auto-picked %s %s  code %s  (expires %s)%s"
          % (kind_of(g), short_id(g["session_id"]), g["approval_code"], g["expires_at"],
             "" if chosen["left"] is None else "  %d use(s) left" % chosen["left"]))
    if ties:
        print("            %d other grant(s) ranked equal (%s); picked the lowest "
              "session id" % (len(ties), ", ".join(short_id(c["grant"]["session_id"])
                                                  for c in ties)))
    journal.append("vpsexec", {
        "event": "grant_autopicked", "kind": kind_of(g), "session_id": g["session_id"],
        "approval_code": g["approval_code"], "plan_hash": digest,
        "candidates": len(found), "ties": len(ties)})
    return chosen["path"]


# ---------------------------------------------------------------------------
# CLI: vpsexec grant new|list|show|revoke
# ---------------------------------------------------------------------------

GRANT_USAGE = """vpsexec grant — approval contracts for break-glass runbooks

  vpsexec grant new <runbook> --ttl <15m|30m|1h|3h|6h|12h|24h>
                    [--steps 1-20,23] [--hosts h1,h2] [--include-rollback] [--run]
                    kind short (the default): one runbook, bound by its sha256.
                    with --run: TTY only; type GRANT:<runbook>:<ttl> to mint.
  vpsexec grant new <policy>[,<policy>] --kind reusable
                    --ttl <1h|3h|6h|12h|24h|72h|7d>
                    [--hosts h1,h2] [--max-uses N] [--for-release NAME]
                    [--include-rollback] [--run]
                    survives PUSHED runbook edits: covers the break_glass
                    steps the files hold at each use, on those hosts, at most
                    N uses (default 50). Bound to the governor's policy_remote
                    (default origin/main), fetched at mint and every use: each
                    file must be exactly a version pushed there since mint.
                    Offline? Use a short grant or an incident.
                    --for-release: only that vpsrun release auto-picks it.
                    with --run: TTY only; type
                    REUSABLE-GRANT:<policy>[+<policy>]:<ttl> to mint.
                    without --run (either kind): print exactly what it would
                    authorise, write nothing.
  vpsexec grant list            active/expired/spent/revoked grants, with kind
  vpsexec grant show <file>     verify one, print VALID or INVALID and why
  vpsexec grant revoke <id>     TTY only; type REVOKE:<short id>. Permanent.
                                (short id: st_/ru_ plus 8 hex; 8 hex for v1)

  use: vpsexec <hosts> '<cmd>' --break-glass --run --reason "why"
           no contract flag: the typed phrase (plan mode lists the valid
           grants). --grant auto (or --approval-contract=auto) auto-picks a
           VALID grant that covers it (short before reusable, then
           soonest-expiring; never one minted --for-release) and refuses if
           none does. --grant FILE names one grant. --no-grant: never a grant.
           vpsrun auto-picks for plays and releases.
"""


def _status(path, policy, now, key_path, grant_dir):
    try:
        return "VALID", check(path, policy, now=now, key_path=key_path,
                              grant_dir=grant_dir)
    except Refused as r:
        return "INVALID: %s" % r, None


def _status_with_uses(path, policy, now, key_path, grant_dir):
    """_status, plus the use count of a reusable grant (None for short)."""
    verdict, g = _status(path, policy, now, key_path, grant_dir)
    if g and kind_of(g) == "reusable":
        try:
            return verdict, g, uses(g, grant_dir=grant_dir)
        except Refused as r:
            return "INVALID: %s" % r, None, None
    return verdict, g, None


def _parse_new(rest):
    opts = {"ttl": None, "steps": None, "hosts": None, "rollback": False,
            "run": False, "kind": "short", "max_uses": None, "for_release": None}
    positional, i = [], 0
    while i < len(rest):
        a = rest[i]
        if a == "--run":
            opts["run"] = True
        elif a == "--include-rollback":
            opts["rollback"] = True
        elif a.split("=", 1)[0] in ("--ttl", "--steps", "--hosts", "--kind",
                                    "--max-uses", "--for-release"):
            name = a.split("=", 1)[0][2:].replace("-", "_")
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
    if opts["kind"] not in KINDS:
        raise Refused("--kind %r: one of %s" % (opts["kind"], ", ".join(KINDS)))
    if len(positional) != 1 or not opts["ttl"]:
        raise Refused("usage: vpsexec grant new <runbook> --ttl <ttl> [--kind "
                      "short|reusable] [--steps ...] [--hosts ...] [--max-uses N] "
                      "[--include-rollback] [--run]")
    if opts["kind"] == "short" and opts["for_release"] is not None:
        raise Refused("--for-release applies to --kind reusable")
    if opts["kind"] == "short" and opts["max_uses"] is not None:
        raise Refused("--max-uses applies to --kind reusable; a short grant is "
                      "bounded by its runbook's sha256 and steps instead")
    if opts["kind"] == "reusable" and opts["steps"] is not None:
        raise Refused("--steps applies to --kind short; a reusable grant covers "
                      "every break_glass step of its policy files (narrow it with "
                      "--hosts, or use a short grant)")
    return positional[0], opts


def _select_new(policy, name, opts, aliases, now, classify, report=None,
                preview=None):
    if opts["kind"] == "reusable":
        return select_reusable(
            policy, name, opts["ttl"], hosts=opts["hosts"],
            include_rollback=opts["rollback"],
            max_uses=(DEFAULT_MAX_USES if opts["max_uses"] is None
                      else opts["max_uses"]),
            aliases=aliases, now=now, classify=classify, report=report,
            preview=preview, release=opts.get("for_release"))
    return select(policy, name, opts["ttl"], steps=opts["steps"],
                  hosts=opts["hosts"], include_rollback=opts["rollback"],
                  aliases=aliases, now=now, classify=classify, report=report)


def mint_phrase(fields):
    """The exact text a human types to mint: distinct per kind."""
    if fields["kind"] == "reusable":
        return "REUSABLE-GRANT:%s:%s" % (
            "+".join(Path(f).stem for f in fields["scope"]["files"]), fields["ttl"])
    return "GRANT:%s:%s" % (Path(fields["runbook"]["file"]).stem, fields["ttl"])


def cli(argv, policy, aliases=None, stream=None, prompt=None, now=None,
        key_path=None, grant_dir=None, classify=None):
    stream = stream if stream is not None else sys.stdin
    grant_dir = Path(grant_dir or GRANT_DIR)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(GRANT_USAGE)
        return 0
    verb, rest = argv[0], argv[1:]

    if verb == "new":
        name, opts = _parse_new(rest)
        skipped, preview = [], []
        fields = _select_new(policy, name, opts, aliases, now, classify,
                             report=skipped, preview=preview)
        print(render(fields, "GRANT PLAN — what this %s approval contract would "
                             "authorise (break-glass phrase only; every other "
                             "gate still runs):" % opts["kind"], skipped=skipped,
                     preview=preview if opts["kind"] == "reusable" else None,
                     used=0))
        if not opts["run"]:
            print("")
            print("Plan only. Nothing was written. Re-run with --run to mint it.")
            return 0
        _confirm(stream, prompt, mint_phrase(fields), "mint this grant")
        # Re-select after the prompt: the window starts when it is minted.
        fields = _select_new(policy, name, opts, aliases, now, classify)
        path, grant = mint(fields, key_path=key_path, grant_dir=grant_dir)
        print("")
        print("MINTED %s" % path)
        print("  kind    : %s" % grant["kind"])
        print("  session : %s" % grant["session_id"])
        print("  code    : %s   (printed and journaled on every use)"
              % grant["approval_code"])
        print("  expires : %s" % grant["expires_at"])
        if grant["kind"] == "reusable":
            print("  uses    : at most %d" % grant["max_uses"])
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
            verdict, g, used = _status_with_uses(p, policy, now, key_path, grant_dir)
            sid = p.stem
            if sid in revoked:
                label = "REVOKED"
            elif g and used is not None and used >= g["max_uses"]:
                label = "SPENT"
            elif g:
                label = "ACTIVE"
            elif "expired at" in verdict:
                label = "EXPIRED"
            else:
                label = verdict
            if g:
                kind = kind_of(g)
                if kind == "reusable":
                    what = ", ".join(g["scope"]["files"])
                    size = "%d/%d use(s)" % (used, g["max_uses"])
                else:
                    what, size = g["runbook"]["file"], "%d step(s)" % len(g["steps"])
                print("  %-8s %s  %-8s %s  %s  %s  until %s"
                      % (label, short_id(sid), kind, g["approval_code"], what,
                         size, g["expires_at"]))
            else:
                print("  %-8s %s  %s" % (label.split(":")[0], short_id(sid),
                                          verdict if label.startswith("INVALID")
                                          else p.name))
        return 0

    if verb == "show":
        if len(rest) != 1:
            raise Refused("usage: vpsexec grant show <file>")
        verdict, g, used = _status_with_uses(rest[0], policy, now, key_path, grant_dir)
        print(render(g, "VALID — %s" % rest[0], used=used) if g else verdict)
        return 0 if g else 1

    if verb == "revoke":
        if len(rest) != 1:
            raise Refused("usage: vpsexec grant revoke <session_id>")
        sid = rest[0].strip().lower()
        if not SESSION_RE.match(sid):
            m = re.match(r"^((?:st|ru)_)?([0-9a-f]{8,31})$", sid)
            if not m:
                raise Refused("session id must be the full id, or a unique prefix "
                              "of at least 8 hex (st_/ru_ optional)")
            # `ab12cd34` matches a v1 id or the hex of a prefixed one;
            # `st_ab12cd34` matches only that kind.
            matches = [p.stem for p in grant_dir.glob("*.json")
                       if SESSION_RE.match(p.stem)
                       and (p.stem.startswith(sid) or (
                           not m.group(1)
                           and p.stem.split("_")[-1].startswith(m.group(2))))]
            if len(matches) != 1:
                raise Refused("prefix %r matches %d grant(s) in %s — give the full id"
                              % (sid, len(matches), grant_dir))
            sid = matches[0]
        print("REVOKE grant %s — permanent; it can never be used again." % sid)
        _confirm(stream, prompt, "REVOKE:%s" % short_id(sid), "revoke it")
        revoke(sid, grant_dir=grant_dir, now=now)
        print("REVOKED %s" % sid)
        return 0

    raise Refused("unknown grant verb %r — new, list, show, revoke" % verb)
