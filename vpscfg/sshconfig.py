"""~/.ssh/config parser — the fleet host registry (the operator's source of truth).

Read-only, no network. Aliases resolve to one machine record each.

`Include` is followed the way OpenSSH follows it: a relative path resolves
against ~/.ssh, `~` expands, globs are allowed (sorted, as glob(3) returns
them), includes nest, a path that matches nothing is ignored, and an Include
that appears inside a `Host` or `Match` block is scoped to that block (the
included lines apply only to that block's names, and a `Host` line inside it
registers only names the enclosing block also matches).

Threats:
  - Protects against: an include loop or a runaway include chain hanging the
    door or recursing without bound (a file already on the include stack, or
    nesting deeper than OpenSSH's own limit of 16, refuses with the chain
    named); an included file that exists but cannot be read (a directory, no
    permission, not UTF-8) silently shrinking the host registry — it refuses;
    an included file another local user could have written (it must be owned
    by you or root and not group/world-writable, as ssh itself requires, else
    it refuses); a `Match` block's settings leaking into the `Host` block
    before it; a name that the block's own `!pattern` negates being
    registered; a later HostName/User overriding the first (ssh takes the
    first value, and so does this registry); and
    names inside a scoped include being registered for hosts ssh would never
    give them to (a `Match` condition is not evaluated here, so an include
    under `Match` registers nothing — fail closed: an unregistered host is
    refused as unreachable, never guessed at).
  - Does NOT protect against: a hostile ~/.ssh/config (it is the operator's
    own file; anyone who can edit it can point an alias anywhere); the full
    ssh_config grammar — only Host, Match, Include, HostName and User are
    read. The top-level ~/.ssh/config itself is not permission-checked here.
"""
import fnmatch
import glob
import os
import re
import shlex
import stat
from pathlib import Path

from .gates import Refused

# OpenSSH's READCONF_MAX_DEPTH.
MAX_INCLUDE_DEPTH = 16
# Scope marker for a `Match` block: its conditions are not evaluated here, so
# nothing scoped to it is ever taken to apply.
_MATCH = object()

_HOST_RE = re.compile(r"(?i)^Host(?:\s+|\s*=\s*)(.+)$")
_MATCH_RE = re.compile(r"(?i)^Match(?:\s+|\s*=\s*|$)")
_INCLUDE_RE = re.compile(r"(?i)^Include(?:\s+|\s*=\s*)(.+)$")
_HOSTNAME_RE = re.compile(r"(?i)^HostName(?:\s+|\s*=\s*)(\S+)")
_USER_RE = re.compile(r"(?i)^User(?:\s+|\s*=\s*)(\S+)")


class SshConfigError(Refused):
    """An ssh config that cannot be read faithfully. Refuses, never guesses."""


def load(path=None, ssh_dir=None):
    """Returns {alias: {"hostname": str|None, "user": str|None}} for every alias.

    `ssh_dir` is where relative Include paths resolve (default ~/.ssh, as
    OpenSSH does for a user config); tests pass a temporary directory.
    A missing top-level file is an empty registry; a broken Include refuses."""
    ssh_dir = Path(ssh_dir) if ssh_dir is not None else Path.home() / ".ssh"
    path = Path(path or ssh_dir / "config")
    hosts = {}
    try:
        text = path.read_text()
    except OSError:
        return {}
    _parse(text, path, hosts, ssh_dir, scope=[], current=[],
           stack=[os.path.realpath(str(path))])
    return hosts


def _matches(name, patterns):
    """OpenSSH match_pattern_list: a matching `!pattern` vetoes, otherwise
    any positive match wins. Host names compare case-insensitively."""
    name, hit = name.lower(), False
    for pattern in patterns:
        negated = pattern.startswith("!")
        if fnmatch.fnmatchcase(name, pattern.lstrip("!").lower()):
            if negated:
                return False
            hit = True
    return hit


def _in_scope(name, scope):
    return all(block is not _MATCH and _matches(name, block) for block in scope)


def _include_targets(source, value, ssh_dir):
    try:
        args = shlex.split(value)
    except ValueError as e:
        raise SshConfigError("%s: cannot parse `Include %s` (%s) — refusing rather "
                             "than guessing which file was meant" % (source, value, e))
    for arg in args:
        if arg.startswith("~"):
            target = os.path.expanduser(arg)
            if target.startswith("~"):
                raise SshConfigError("%s: Include %r names an unknown user's home"
                                     % (source, arg))
        elif os.path.isabs(arg):
            target = arg
        else:
            target = str(ssh_dir / arg)
        # A path or glob that matches nothing is ignored, as OpenSSH does.
        for match in sorted(glob.glob(target)):
            yield match


def _parse_file(path, source, hosts, ssh_dir, scope, current, stack):
    if len(stack) > MAX_INCLUDE_DEPTH:
        raise SshConfigError(
            "ssh config Include nesting is deeper than %d at %s (from %s) — "
            "refusing; ssh itself would stop here too" % (MAX_INCLUDE_DEPTH, path, source))
    real = os.path.realpath(path)
    if real in stack:
        raise SshConfigError(
            "ssh config Include loop: %s includes %s, which is already being read "
            "(chain: %s) — refusing" % (source, path, " -> ".join(stack + [real])))
    try:
        if os.path.isdir(path):
            return  # ssh skips directories an Include (or its glob) matches
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return  # vanished between glob and read: the same as never matching
    except OSError as e:
        raise SshConfigError("ssh config %s includes %s, which cannot be read (%s) "
                             "— refusing rather than reading part of the registry"
                             % (source, path, e))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SshConfigError("ssh config %s includes %s, which is not a regular "
                                 "file — refusing" % (source, path))
        # ssh's own rule for config it reads: owned by you or root, and not
        # writable by group or others. Otherwise another user writes your hosts.
        if st.st_uid not in (os.getuid(), 0) or st.st_mode & 0o022:
            raise SshConfigError(
                "ssh config %s includes %s, which has bad owner or permissions "
                "(uid %d, mode %o; must be yours or root's and not group/world-"
                "writable, as ssh requires) — refusing"
                % (source, path, st.st_uid, stat.S_IMODE(st.st_mode)))
        with os.fdopen(fd, "rb") as f:
            fd = None
            text = f.read().decode("utf-8")
    except (OSError, ValueError) as e:
        raise SshConfigError("ssh config %s includes %s, which cannot be read (%s) "
                             "— refusing rather than reading part of the registry"
                             % (source, path, e))
    finally:
        if fd is not None:
            os.close(fd)
    _parse(text, Path(path), hosts, ssh_dir, scope, current, stack + [real])


def _parse(text, source, hosts, ssh_dir, scope, current, stack):
    """`current` is the alias list the next keywords apply to; `block` is the
    enclosing Host pattern list (None at the top, _MATCH under Match). Both are
    local: when an include returns, the includer's block resumes, as in ssh."""
    current, block = list(current), None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _HOST_RE.match(line)
        if m:
            block = []
            for word in m.group(1).split():
                if word.startswith("#"):
                    break  # a trailing comment, as ssh reads it
                block.append(word)
            # A name the block itself negates (`Host db1 !db1`) is not one ssh
            # would ever apply this block to.
            current = [a for a in block
                       if "*" not in a and "?" not in a and not a.startswith("!")
                       and _matches(a, block) and _in_scope(a, scope)]
            for a in current:
                hosts.setdefault(a, {"hostname": None, "user": None})
            continue
        if _MATCH_RE.match(line):
            block, current = _MATCH, []
            continue
        m = _INCLUDE_RE.match(line)
        if m:
            inner = scope + [block] if block is not None else scope
            for target in _include_targets(source, m.group(1), ssh_dir):
                _parse_file(target, source, hosts, ssh_dir, inner, current, stack)
            continue
        # First value wins, as in ssh: a later stanza cannot re-point an alias.
        m = _HOSTNAME_RE.match(line)
        if m:
            for a in current:
                if hosts[a]["hostname"] is None:
                    hosts[a]["hostname"] = m.group(1)
            continue
        m = _USER_RE.match(line)
        if m:
            for a in current:
                if hosts[a]["user"] is None:
                    hosts[a]["user"] = m.group(1)


def machines(path=None, ssh_dir=None):
    """Collapse aliases to distinct machines keyed by effective target."""
    out = {}
    for alias, cfg in load(path, ssh_dir=ssh_dir).items():
        key = cfg["hostname"] or alias
        rec = out.setdefault(key, {"aliases": [], "user": cfg["user"]})
        rec["aliases"].append(alias)
        if cfg["user"]:
            rec["user"] = cfg["user"]
    return out
