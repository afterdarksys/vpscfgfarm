"""Where the estate lives: the governor, policies/, contracts/ and the rest.

The tool and the estate it governs are separable. By default they are the same
directory, the tool checkout, exactly as before this module existed. An
operator who keeps the estate in its own repository names that directory in
ONE pinned pointer file at a FIXED path inside the tool checkout:

    <tool root>/estate.path      one line: the estate's absolute, real path

There is no other way to move it. No environment variable, no flag, no
home-directory file and no search path is consulted, by design: an earlier hole
let VPSCFG_CONTROL_PATH point the inner door at a foreign governor whose hash
the attacker could also supply (tests/test_wrapper.py,
test_wrapper_impersonation_via_env_is_refused). An env var is attacker-reachable
from anything that can launch a process; a file inside the tool checkout is
reachable only by someone who can already rewrite the doors themselves.

Threats:
  - Protects against: an environment variable, flag or $HOME redirecting the
    governor or the policies (none is read here; a test pins that); a pointer
    planted or edited by another local user (the pointer must be a regular
    file, not a symlink, owned by the operator's euid, and not group- or
    world-writable); a pointer whose target can be swapped later (the target
    must be absolute, normalised and already its own real path, so a symlink
    anywhere in it refuses; the target directory must be owned by the operator
    and not group/world-writable, and every ancestor must be owned by the
    operator or root and be either not group/world-writable or sticky); a
    pointed estate whose governor, policies, contracts, playbooks, plays or
    inventory files are symlinks or writable by others; extended ACLs (which
    can grant write while the mode bits look clean) on the pointer, the root,
    the governor or policies/; a case-variant pointer (`Estate.Path`) that a
    case-sensitive reader and a case-insensitive file system would disagree
    about; a pointer committed to git (it would move every clone; checked by
    reading the index directly, never by running a `git` found on $PATH);
    a tool checkout whose own directory or ancestors another user could
    rename; garbage, oversized, multi-line or relative pointer contents; two
    doors reading two governors (every door resolves through this one function,
    and the inner door still refuses a VPSCFG_CONTROL_PATH that is not the
    root resolved here, so a disagreement refuses rather than splits).
  - Does NOT protect against: someone who can write the tool checkout (they can
    edit the doors, which is a git-visible act); root; the operator pointing at
    an estate they should not use (the pointer is the operator's own choice,
    and the resolved root and the governor's hash are journaled by both outer
    doors so the choice is on the record). With NO pointer the behaviour is
    byte-for-byte the old one and none of the permission checks run, because
    the estate is then the tool checkout and today's threat model covers it.
    Extended ACLs are detected on macOS (acl_get_link_np) and Linux (POSIX ACL
    xattrs); elsewhere the check is a documented no-op. Content inside binary
    files and anything written after resolution are out of scope: resolution
    is a check at start-up, not a lock.

Fail-closed rule: any doubt about the pointer or its target raises
EstateRefused. Nothing falls back to the default after a pointer was found.

This file is loaded two ways: as `vpscfg.estate` by the package, and by file
path (no package, no sys.path) by the outer doors before they judge anything.
It therefore imports only the standard library, plus gates.Refused when it is
available so the package's single error handler catches it.
"""


import os
import stat
import struct

try:
    from .gates import Refused as _Base
except ImportError:  # loaded by file path from an outer door: no package
    _Base = Exception

TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
POINTER_NAME = "estate.path"
GOVERNOR_NAME = "vpscfg-control.json"
POLICIES_NAME = "policies"
# Every estate directory the package reads from a pointed estate. Each is
# walked in full (no symlinks, operator-owned, not writable by others).
READ_DIRS = ("policies", "contracts", "playbooks", "plays", "inventory")
MAX_POINTER_BYTES = 4096


class EstateRefused(_Base):
    """The estate root cannot be trusted. Every door refuses on it."""


class Estate(object):
    """A resolved estate root. `source` is "default" or "pointer"."""

    __slots__ = ("root", "source", "pointer")

    def __init__(self, root, source, pointer=None):
        self.root = root
        self.source = source
        self.pointer = pointer

    @property
    def governor(self):
        return os.path.join(self.root, GOVERNOR_NAME)

    @property
    def policies(self):
        return os.path.join(self.root, POLICIES_NAME)

    def record(self, governor_sha256=None):
        """What the doors journal LOCALLY: where the estate came from and which
        governor bytes were judged against. telemetry.push_event drops the
        paths before anything leaves the machine."""
        entry = {"estate_root": self.root, "estate_source": self.source,
                 "governor": self.governor}
        if self.pointer:
            entry["estate_pointer"] = self.pointer
        if governor_sha256:
            entry["governor_sha256"] = governor_sha256
        return entry


# --- extended ACLs -----------------------------------------------------------

# Darwin <sys/acl.h>: entry tags and the permission bits that let a holder
# create, remove or rename entries in a directory, or rewrite its security.
_DARWIN_ALLOW = 1
_DARWIN_DANGER = ((1 << 2)     # ACL_WRITE_DATA / ACL_ADD_FILE
                  | (1 << 4)   # ACL_DELETE
                  | (1 << 5)   # ACL_APPEND_DATA / ACL_ADD_SUBDIRECTORY
                  | (1 << 6)   # ACL_DELETE_CHILD
                  | (1 << 12)  # ACL_WRITE_SECURITY
                  | (1 << 13))  # ACL_CHANGE_OWNER


def _darwin_acl_probes():
    """(has_acl, grants_write) on macOS, via libc's ACL API."""
    import ctypes
    import ctypes.util
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    get = libc.acl_get_link_np
    get.restype, get.argtypes = ctypes.c_void_p, [ctypes.c_char_p, ctypes.c_int]
    entry = libc.acl_get_entry
    entry.restype = ctypes.c_int
    entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    tag_of = libc.acl_get_tag_type
    tag_of.restype = ctypes.c_int
    tag_of.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    permset_of = libc.acl_get_permset
    permset_of.restype = ctypes.c_int
    permset_of.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    perm_in = libc.acl_get_perm_np
    perm_in.restype = ctypes.c_int
    perm_in.argtypes = [ctypes.c_void_p, ctypes.c_int]
    free = libc.acl_free
    free.argtypes = [ctypes.c_void_p]
    acl_type_extended, first, following = 0x00000100, 0, -1

    def entries(path):
        """[(tag, permission bits)] or [] when the path has no ACL."""
        acl = get(os.fsencode(path), acl_type_extended)
        if not acl:
            err = ctypes.get_errno()
            if err in (2, 45, 102):  # ENOENT (no ACL), ENOTSUP, EOPNOTSUPP
                return []
            raise OSError(err, os.strerror(err), path)
        try:
            found, slot, which = [], ctypes.c_void_p(), first
            while entry(acl, which, ctypes.byref(slot)) == 0:
                which = following
                tag, permset = ctypes.c_int(), ctypes.c_void_p()
                if tag_of(slot, ctypes.byref(tag)) != 0 or permset_of(slot, ctypes.byref(permset)) != 0:
                    raise OSError(ctypes.get_errno(), "unreadable ACL entry", path)
                bits = 0
                for bit in (b for b in range(1, 14) if _DARWIN_DANGER & (1 << b)):
                    rc = perm_in(permset, 1 << bit)
                    if rc < 0:
                        raise OSError(ctypes.get_errno(), "unreadable ACL permset", path)
                    if rc:
                        bits |= 1 << bit
                found.append((tag.value, bits))
            return found
        finally:
            free(acl)

    def has_acl(path):
        return bool(entries(path))

    def grants_write(path):
        return any(tag == _DARWIN_ALLOW and bits & _DARWIN_DANGER
                   for tag, bits in entries(path))
    return has_acl, grants_write


def _linux_acl(path, name):
    """[(tag, perm)] from a POSIX ACL xattr, or [] when there is none."""
    try:
        raw = os.getxattr(path, name, follow_symlinks=False)
    except OSError as e:
        if e.errno in (61, 95, 2):  # ENODATA, EOPNOTSUPP, ENOENT
            return []
        raise
    if len(raw) < 4 or (len(raw) - 4) % 8:
        raise OSError(22, "malformed POSIX ACL", path)
    return [struct.unpack("<HHI", raw[i:i + 8])[:2] for i in range(4, len(raw), 8)]


def _linux_has_acl(path):
    return bool(_linux_acl(path, "system.posix_acl_access")
                or _linux_acl(path, "system.posix_acl_default"))


def _linux_grants_write(path):
    """A named user or group entry with write, not masked off. (The owning
    group's write is already visible in the mode bits, which show the mask.)"""
    acl = _linux_acl(path, "system.posix_acl_access")
    mask = [perm for tag, perm in acl if tag == 0x10]
    if mask and not mask[0] & 2:
        return False
    return any(tag in (0x02, 0x08) and perm & 2 for tag, perm in acl)


def _no_acl_support(path):
    return False


def default_acl_probes():
    """(has_acl, grants_write) for this platform. Documented fallback: a
    platform with neither probe gets no-ops (mode bits and ownership still
    apply)."""
    import sys
    if sys.platform == "darwin":
        try:
            return _darwin_acl_probes()
        except (OSError, AttributeError):
            pass
    if hasattr(os, "getxattr"):
        return _linux_has_acl, _linux_grants_write
    return _no_acl_support, _no_acl_support


def default_acl_probe():
    return default_acl_probes()[0]


def _no_acl(path, what, has_acl):
    try:
        found = has_acl(path)
    except OSError as e:
        raise EstateRefused("cannot read the ACL of %s %s (%s) — failing closed"
                            % (what, path, e))
    if found:
        raise EstateRefused(
            "%s %s carries an extended ACL — an ACL can grant another user write "
            "access that the mode bits do not show; remove it (macOS: chmod -N; "
            "Linux: setfacl -b). Failing closed" % (what, path))


# --- checks ------------------------------------------------------------------

def _who(st):
    return "uid %d mode %04o" % (st.st_uid, stat.S_IMODE(st.st_mode))


def _not_shared(st, euid, what, path):
    if st.st_uid != euid:
        raise EstateRefused(
            "%s %s is owned by uid %d, not the operator (uid %d) — another user "
            "could steer the governor; failing closed" % (what, path, st.st_uid, euid))
    if stat.S_IMODE(st.st_mode) & 0o022:
        raise EstateRefused(
            "%s %s is group- or world-writable (%s) — another user could steer "
            "the governor; chmod go-w it. Failing closed" % (what, path, _who(st)))


def _lstat(lstat, path):
    try:
        return lstat(path)
    except OSError as e:
        raise EstateRefused("cannot stat %s (%s) — failing closed" % (path, e))


def _safe_chain(path, euid, lstat, what, grants_write):
    """`path` and every directory above it: owned by the operator or root, not
    group/world-writable unless sticky (like /tmp), and with no ACL entry that
    ALLOWS anyone to add, delete or rename entries or rewrite its security.
    Otherwise their owner could rename what is below away and put something
    else in its place. Deny entries are fine (macOS puts `everyone deny
    delete` on every home directory)."""
    while True:
        pst = _lstat(lstat, path)
        try:
            dangerous = grants_write(path)
        except OSError as e:
            raise EstateRefused("cannot read the ACL of %s (%s) — failing closed" % (path, e))
        if dangerous:
            raise EstateRefused(
                "%s, %s, carries an ACL entry that lets someone add, delete or "
                "rename entries in it — failing closed" % (path, what))
        if pst.st_uid not in (euid, 0):
            raise EstateRefused(
                "%s, %s, is owned by uid %d — its owner could rename things "
                "away beneath it; failing closed" % (path, what, pst.st_uid))
        if stat.S_IMODE(pst.st_mode) & 0o022 and not pst.st_mode & stat.S_ISVTX:
            raise EstateRefused(
                "%s, %s, is group- or world-writable without the sticky bit "
                "(%s) — failing closed" % (path, what, _who(pst)))
        if path == os.path.dirname(path):
            return
        path = os.path.dirname(path)


def _case_variants(tool_root, listdir):
    try:
        names = listdir(tool_root)
    except OSError as e:
        raise EstateRefused("cannot list %s (%s) — failing closed" % (tool_root, e))
    variants = sorted(n for n in names
                      if n.casefold() == POINTER_NAME and n != POINTER_NAME)
    if variants:
        raise EstateRefused(
            "%s holds %s — a case-variant of %s. A case-insensitive file system "
            "and a case-sensitive reader would disagree about whether a pointer "
            "exists; delete it. Failing closed"
            % (tool_root, ", ".join(variants), POINTER_NAME))


def _git_index_path(tool_root):
    """The index of the git checkout at tool_root, or None if it is not one.
    Follows a worktree's `.git` file. Never runs git."""
    dotgit = os.path.join(tool_root, ".git")
    if os.path.isdir(dotgit):
        return os.path.join(dotgit, "index")
    if not os.path.isfile(dotgit):
        return None
    with open(dotgit, "rb") as f:
        line = f.read(4096).decode("utf-8", "strict").strip()
    if not line.startswith("gitdir: "):
        raise ValueError(".git file does not name a gitdir")
    gitdir = line[len("gitdir: "):]
    if not os.path.isabs(gitdir):
        gitdir = os.path.join(tool_root, gitdir)
    return os.path.join(gitdir, "index")


def _index_hash_lengths(data):
    """Which hash the index uses, from its trailing checksum: SHA-1 (20 bytes)
    or SHA-256 (32) over everything before it. A trailer of zeros is git's
    index.skipHash; then both lengths are tried. Anything else is corrupt."""
    import hashlib
    for n, algo in ((20, hashlib.sha1), (32, hashlib.sha256)):
        if len(data) > 12 + n and algo(data[:-n]).digest() == data[-n:]:
            return (n,)
    if len(data) > 32 and not data[-20:].strip(b"\0"):
        return (20, 32)
    raise ValueError("index checksum does not verify — corrupt or truncated")


def _index_names(data):
    """Every path in a git index (versions 2-4). Raises ValueError on anything
    unexpected, including a split index, whose entries live elsewhere."""
    if len(data) < 12 or data[:4] != b"DIRC":
        raise ValueError("not a git index")
    version, count = struct.unpack(">II", data[4:12])
    if version not in (2, 3, 4):
        raise ValueError("index version %d" % version)
    lengths = _index_hash_lengths(data)
    problem = None
    for hash_len in lengths:
        try:
            return _index_entries(data, version, count, hash_len)
        except (ValueError, struct.error, IndexError) as e:
            if "split index" in str(e):
                raise
            problem = e
    raise ValueError("index entries do not parse (%s)" % problem)


def _index_entries(data, version, count, hash_len):
    pos, names, previous = 12, [], b""
    for _ in range(count):
        start = pos
        pos += 40 + hash_len
        flags = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        if version >= 3 and flags & 0x4000:
            pos += 2
        if version == 4:
            strip, c = 0, data[pos]
            pos += 1
            strip = c & 0x7F
            while c & 0x80:
                c = data[pos]
                pos += 1
                strip = ((strip + 1) << 7) | (c & 0x7F)
            end = data.index(b"\0", pos)
            if strip > len(previous):
                raise ValueError("bad prefix")
            name = previous[:len(previous) - strip] + data[pos:end]
            pos = end + 1
        else:
            end = data.index(b"\0", pos)
            name = data[pos:end]
            pos = start + ((end - start) // 8 + 1) * 8
            if data[end:pos].strip(b"\0"):
                raise ValueError("bad padding")
        if (flags & 0x0FFF) != min(len(name), 0x0FFF):
            raise ValueError("name length mismatch")
        names.append(name.decode("utf-8", "surrogateescape"))
        previous = name
    if data[pos:pos + 4] == b"link":
        raise ValueError("split index (core.splitIndex) is not supported")
    if len(data) < pos + hash_len:
        raise ValueError("truncated index")
    return names


def _not_tracked(tool_root):
    """A committed or staged pointer would move every clone. Decided: the index
    is read directly; no `git` binary is run (it would be found on $PATH, an
    environment variable), so a missing git changes nothing. Not a git
    checkout: nothing can be tracked. That includes a tool checkout whose git
    directory lives elsewhere (core.worktree, --git-dir, GIT_DIR): with no
    `.git` in the tool root it is treated as "not a checkout", because finding
    such a git dir would mean reading the environment. An index that cannot be
    read, parsed or checksum-verified refuses, because "probably not tracked"
    is not an answer."""
    try:
        index = _git_index_path(tool_root)
        if index is None:
            return
        try:
            with open(index, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return  # a checkout with nothing staged yet
        names = _index_names(data)
    except (OSError, ValueError, UnicodeDecodeError, struct.error, IndexError) as e:
        raise EstateRefused(
            "cannot tell whether git tracks %s (%s) — failing closed"
            % (POINTER_NAME, e))
    tracked = sorted(n for n in names if n.casefold() == POINTER_NAME)
    if tracked:
        raise EstateRefused(
            "git tracks %s in %s — a committed pointer moves every clone's "
            "estate. `git rm --cached %s`; it is gitignored. Failing closed"
            % (", ".join(tracked), tool_root, tracked[0]))


def _read_pointer(path, euid, lstat, has_acl):
    """The pointer's one line, after the file itself passes its checks."""
    try:
        st = lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise EstateRefused("cannot stat %s (%s) — failing closed" % (path, e))
    if stat.S_ISLNK(st.st_mode):
        raise EstateRefused(
            "%s is a symlink — the pointer must be a regular file, so the "
            "estate cannot be redirected by changing a link; failing closed" % path)
    if not stat.S_ISREG(st.st_mode):
        raise EstateRefused("%s is not a regular file — failing closed" % path)
    _not_shared(st, euid, "estate pointer", path)
    _no_acl(path, "estate pointer", has_acl)
    if st.st_size > MAX_POINTER_BYTES:
        raise EstateRefused("%s is %d bytes; a pointer is one path — failing closed"
                            % (path, st.st_size))
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise EstateRefused("cannot open %s (%s) — failing closed" % (path, e))
    try:
        opened = os.fstat(fd)
        # The file read must be the file checked, not one swapped in between.
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            raise EstateRefused("%s changed while it was being read — failing closed" % path)
        raw = os.read(fd, MAX_POINTER_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_POINTER_BYTES:
        raise EstateRefused("%s is over %d bytes — failing closed" % (path, MAX_POINTER_BYTES))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise EstateRefused("%s is not UTF-8 — failing closed" % path)
    if text.endswith("\n"):
        text = text[:-1]
    if not text or "\n" in text or "\r" in text:
        raise EstateRefused(
            "%s must hold exactly one line: the estate's absolute path — failing "
            "closed" % path)
    if text != text.strip() or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise EstateRefused(
            "%s carries whitespace or control characters around or inside the "
            "path — failing closed" % path)
    return text


def _check_target(target, euid, lstat, has_acl, grants_write):
    if not os.path.isabs(target):
        raise EstateRefused(
            "estate pointer names %r, which is not an absolute path — a relative "
            "path would depend on the working directory; failing closed" % target)
    if os.path.normpath(target) != target or target.startswith("//"):
        raise EstateRefused(
            "estate pointer names %r, which is not normalised (no '..', '.', "
            "doubled or trailing slashes) — failing closed" % target)
    try:
        st = lstat(target)
    except FileNotFoundError:
        raise EstateRefused("estate root %s does not exist — failing closed" % target)
    except OSError as e:
        raise EstateRefused("cannot stat estate root %s (%s) — failing closed" % (target, e))
    if stat.S_ISLNK(st.st_mode):
        raise EstateRefused(
            "estate root %s is a symlink (to %s) — name the real directory in the "
            "pointer, so swapping a link cannot move the estate; failing closed"
            % (target, os.path.realpath(target)))
    if not stat.S_ISDIR(st.st_mode):
        raise EstateRefused("estate root %s is not a directory — failing closed" % target)
    real = os.path.realpath(target)
    if real != target:
        raise EstateRefused(
            "estate root %s passes through a symlink (its real path is %s) — "
            "write the real path into the pointer; failing closed" % (target, real))
    _not_shared(st, euid, "estate root", target)
    _no_acl(target, "estate root", has_acl)
    _safe_chain(os.path.dirname(target), euid, lstat, "above the estate root", grants_write)


def _check_contents(root, euid, lstat, has_acl):
    """In a pointed estate every file the package reads must be the operator's
    own, real and unshared: the governor and the whole of policies/,
    contracts/, playbooks/, plays/ and inventory/. Missing is left to the doors,
    which already refuse a missing governor."""
    governor = os.path.join(root, GOVERNOR_NAME)
    try:
        st = lstat(governor)
    except FileNotFoundError:
        st = None
    except OSError as e:
        raise EstateRefused("cannot stat %s (%s) — failing closed" % (governor, e))
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            raise EstateRefused(
                "%s is a symlink or the wrong kind of file — in a pointed estate "
                "the governor must be a real file; failing closed" % governor)
        _not_shared(st, euid, "estate file", governor)
        _no_acl(governor, "governor", has_acl)
    for name in READ_DIRS:
        top = os.path.join(root, name)
        try:
            st = lstat(top)
        except FileNotFoundError:
            continue
        except OSError as e:
            raise EstateRefused("cannot stat %s (%s) — failing closed" % (top, e))
        if not stat.S_ISDIR(st.st_mode):
            raise EstateRefused(
                "%s is a symlink or the wrong kind of file — in a pointed estate "
                "%s/ must be a real directory; failing closed" % (top, name))
        _not_shared(st, euid, "estate directory", top)
        if name == POLICIES_NAME:
            _no_acl(top, "policies directory", has_acl)
        for path in _walk(top):
            st = _lstat(lstat, path)
            if stat.S_ISLNK(st.st_mode):
                raise EstateRefused("%s is a symlink — failing closed" % path)
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise EstateRefused("%s is not a regular file — failing closed" % path)
            _not_shared(st, euid, "estate file", path)


def _walk(top):
    def fail(e):
        raise EstateRefused("cannot read %s (%s) — failing closed" % (e.filename, e))
    for dirpath, dirnames, filenames in os.walk(top, onerror=fail, followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames) + sorted(filenames):
            yield os.path.join(dirpath, name)


def resolve(tool_root=None, lstat=os.lstat, euid=None, has_acl=None, listdir=os.listdir,
            grants_write=None):
    """Resolve the estate root. Raises EstateRefused on any doubt.

    `lstat`, `euid`, `has_acl`, `grants_write` (the ancestor ACL probe) and
    `listdir` are injectable for tests only; at
    runtime the defaults are the real ones. Nothing here reads the environment.
    """
    tool_root = os.path.realpath(tool_root or TOOL_ROOT)
    euid = os.geteuid() if euid is None else euid
    _case_variants(tool_root, listdir)
    pointer = os.path.join(tool_root, POINTER_NAME)
    if has_acl is None or grants_write is None:
        default_has, default_grants = default_acl_probes()
        has_acl = has_acl or default_has
        grants_write = grants_write or default_grants
    target = _read_pointer(pointer, euid, lstat, has_acl)
    if target is None:
        return Estate(tool_root, "default")
    _safe_chain(tool_root, euid, lstat, "the tool checkout holding the pointer", grants_write)
    _not_tracked(tool_root)
    _check_target(target, euid, lstat, has_acl, grants_write)
    _check_contents(target, euid, lstat, has_acl)
    return Estate(target, "pointer", pointer)


_RESOLVED = []


def current():
    """The estate for this process, resolved once so every module in it sees
    the same root."""
    if not _RESOLVED:
        _RESOLVED.append(resolve())
    return _RESOLVED[0]


def root():
    """The estate root as a pathlib.Path (package convenience)."""
    from pathlib import Path
    return Path(current().root)
