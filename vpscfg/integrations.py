"""Optional outside systems the tool talks to, named by the governor only.

The governor (vpscfg-control.json at the estate root, located by
vpscfg/estate.py) may carry a top-level "integrations" mapping:

    "integrations": {
      "telemetry": {"url": "https://api.example.com/v1"},
      "traefik":   {"host": "web1", "file": "/srv/traefik/dynamic/services.yml"},
      "firewall":  {"desired_state": "estate/firewall.json",
                    "script": "/usr/local/sbin/lockdown.sh",
                    "unit": "lockdown.service",
                    "installer": "the firewall manager's installer"},
      "blackout":  {"file": "/var/lib/maintenance/active-windows.json"},
      "secret_source": {"command": ["keystore", "pipe", "--"]}
    }

Each one is OFF when the governor does not name it:
  - telemetry: journal events stay local (telemetry.py pushes nothing);
  - traefik:   the "traefik" probe refuses and traefik_verify skips;
  - firewall:  `vpscfg fleet firewall` refuses: no desired-state file, and
               no firewall manager (its lockdown script, its boot unit, and
               the installer to name in remedies) to judge the host against.
  - blackout:  no maintenance windows are known. Every host's window status is
               "unknown" (status "unconfigured"): advisory lines say so, and
               --require-blackout refuses, exactly as when a named export file
               is missing. Unset never reads as "inside a window".
  - secret_source: `secret-put --from-pipe` refuses: there is no command to
               read a secret from.

Nothing else can set them: no environment variable, flag, working directory
or $HOME is read here. The telemetry credential is the one exception that
stays with the operator (telemetry.py), because a secret does not belong in a
committed governor, and the credential alone cannot choose where events go.

Threats:
  - Protects against: an environment variable or flag redirecting journal
    events or choosing the desired state an audit judges against (only the
    governor is read); journal events and their API key leaving over plain
    http (https only); a governor value reaching a remote shell unchecked
    (the Traefik host and path are strict patterns, and the path is quoted);
    a desired-state path escaping the estate root (relative, normalised, no
    symlink anywhere below the root, a regular file); an environment variable
    choosing which maintenance-window file a gate reads; a secret source
    reaching a shell (an argv list of plain words, run without a shell).
  - Does NOT protect against: a governor that names a hostile endpoint. The
    governor is the operator's own reviewed, git-visible file.
"""
import json
import os
import re
import stat

from . import estate
from .gates import Refused

KEY = "integrations"
KNOWN = {"telemetry": ("url",), "traefik": ("host", "file"), "firewall": ("desired_state", "script", "unit", "installer"),
         "blackout": ("file",), "secret_source": ("command",)}

_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~-]*)*\Z")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}\Z")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,254}\Z")
# One argv word of the secret source: no shell metacharacters, no whitespace.
# The first word may be an absolute path; options like `--` or `--vault=x`
# are words too.
_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]{0,254}\Z")
# Remedy text only: printed, never run.
_HINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/<>:@+'-]{0,199}\Z")
_ARGV_RE = re.compile(r"^[A-Za-z0-9_./=:@+-]{1,255}\Z")


def _segments_ok(segments):
    return bool(segments) and all(
        _SEGMENT_RE.match(s) and s not in (".", "..") for s in segments)


def _abs_path(value):
    return isinstance(value, str) and value.startswith("/") \
        and _segments_ok(value[1:].split("/"))


def _governor(governor):
    """The governor document. A missing governor turns every integration off
    (the doors refuse it on their own); an unreadable one refuses."""
    path = governor or estate.current().governor
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise Refused("governor unreadable (%s) — integrations failing closed" % e)
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise Refused("governor is not JSON (%s) — integrations failing closed" % e)
    return doc if isinstance(doc, dict) else {}


def section(name, governor=None):
    """integrations.<name> from the governor, or None when it is not named."""
    if name not in KNOWN:
        raise Refused("no such integration %r" % name)
    integ = _governor(governor).get(KEY)
    if integ is None:
        return None
    if not isinstance(integ, dict):
        raise Refused("governor %s must be a mapping" % KEY)
    unknown = sorted(set(integ) - set(KNOWN))
    if unknown:
        raise Refused("governor %s has unknown integration(s) %r (known: %s)"
                      % (KEY, unknown, ", ".join(sorted(KNOWN))))
    cfg = integ.get(name)
    if cfg is None:
        return None
    if not isinstance(cfg, dict):
        raise Refused("governor %s.%s must be a mapping" % (KEY, name))
    extra = sorted(set(cfg) - set(KNOWN[name]))
    missing = [k for k in KNOWN[name] if k not in cfg]
    if extra or missing:
        raise Refused("governor %s.%s takes exactly %s (unknown %r, missing %r)"
                      % (KEY, name, ", ".join(KNOWN[name]), extra, missing))
    return cfg


def telemetry_url(governor=None):
    """The control-plane base URL, without a trailing slash, or None (off)."""
    cfg = section("telemetry", governor)
    if cfg is None:
        return None
    url = cfg["url"]
    if not isinstance(url, str) or not _URL_RE.match(url) or "/../" in url + "/" \
            or "/./" in url + "/":
        raise Refused("governor %s.telemetry.url must be a plain https:// URL" % KEY)
    return url.rstrip("/")


def traefik(governor=None):
    """{"host", "file"} for the Traefik file provider, or None (off)."""
    cfg = section("traefik", governor)
    if cfg is None:
        return None
    host, path = cfg["host"], cfg["file"]
    if not isinstance(host, str) or not _HOST_RE.match(host):
        raise Refused("governor %s.traefik.host is not a valid host name" % KEY)
    if not _abs_path(path):
        raise Refused("governor %s.traefik.file must be an absolute, normalised path "
                      "of plain names ([A-Za-z0-9._-])" % KEY)
    return {"host": host, "file": path}


FIREWALL_MAX_BYTES = 4 * 1024 * 1024


def firewall_manager(governor=None):
    """integrations.firewall, validated, or None (off): the desired-state
    path (relative to the estate root, checked when read), the lockdown
    script's absolute path on each host, its boot unit, and the installer a
    remedy names. The probe sha256s the script and asks systemd about the
    unit; both are passed through shlex.quote as well as these patterns."""
    cfg = section("firewall", governor)
    if cfg is None:
        return None
    rel = cfg["desired_state"]
    if not isinstance(rel, str) or rel.startswith("/") or not _segments_ok(rel.split("/")):
        raise Refused("governor %s.firewall.desired_state must be a normalised path relative "
                      "to the estate root, of plain names ([A-Za-z0-9._-])" % KEY)
    if not _abs_path(cfg["script"]):
        raise Refused("governor %s.firewall.script must be an absolute, normalised path "
                      "of plain names ([A-Za-z0-9._-])" % KEY)
    if not isinstance(cfg["unit"], str) or not _UNIT_RE.match(cfg["unit"]):
        raise Refused("governor %s.firewall.unit must be a systemd unit name "
                      "([A-Za-z0-9@._-])" % KEY)
    if not isinstance(cfg["installer"], str) or not _HINT_RE.match(cfg["installer"]):
        raise Refused("governor %s.firewall.installer must be one line of plain text "
                      "([A-Za-z0-9 ._/<>:@+'-])" % KEY)
    return dict(cfg)


def firewall_desired_state_read(governor=None, root=None):
    """(absolute path, bytes) of the firewall audit's desired-state file, or
    None (off).

    The governor names it relative to the estate root. The file is opened by
    walking from the root one component at a time with O_NOFOLLOW against the
    parent's descriptor, and the bytes come from that same descriptor after
    fstat says it is a regular file. A symlink swapped in after a check has
    nothing to win: there is no separate check."""
    cfg = firewall_manager(governor)
    if cfg is None:
        return None
    rel = cfg["desired_state"]
    root = root or estate.current().root
    segs = rel.split("/")
    nofollow = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    path = root
    try:
        # The root itself was resolved and ownership-checked by vpscfg/estate.py.
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise Refused("firewall desired state: estate root %s: %s" % (root, e.strerror or e))
    try:
        for i, seg in enumerate(segs):
            path = os.path.join(path, seg)
            last = i == len(segs) - 1
            flags = os.O_RDONLY | nofollow | (os.O_NONBLOCK if last else os.O_DIRECTORY)
            try:
                nfd = os.open(seg, flags, dir_fd=fd)
            except OSError as e:
                try:
                    is_link = stat.S_ISLNK(os.stat(seg, dir_fd=fd, follow_symlinks=False).st_mode)
                except OSError:
                    is_link = False
                if is_link:
                    raise Refused("firewall desired state %s passes through a symlink — name "
                                  "the real file inside the estate" % path)
                raise Refused("firewall desired state %s: %s" % (path, e.strerror or e))
            os.close(fd)
            fd = nfd
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused("firewall desired state %s is not a regular file" % path)
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > FIREWALL_MAX_BYTES:
                raise Refused("firewall desired state %s exceeds %d bytes" % (path, FIREWALL_MAX_BYTES))
            chunks.append(chunk)
        return path, b"".join(chunks)
    finally:
        os.close(fd)


def firewall_desired_state(governor=None, root=None):
    """Absolute path of the firewall audit's desired-state file, or None
    (off). It is opened and checked as firewall_desired_state_read does; the
    audit itself uses that function's bytes, never this path."""
    got = firewall_desired_state_read(governor, root)
    return None if got is None else got[0]


def blackout_file(governor=None):
    """Absolute path of the maintenance-window export file, or None (off).

    The file is local to the operator's machine and read by vpscfg/blackout.py.
    Only its location is checked here: a named file that is missing or stale
    reads as "unavailable", as it always has."""
    cfg = section("blackout", governor)
    if cfg is None:
        return None
    if not _abs_path(cfg["file"]):
        raise Refused("governor %s.blackout.file must be an absolute, normalised path "
                      "of plain names ([A-Za-z0-9._-])" % KEY)
    return cfg["file"]


def secret_source(governor=None):
    """argv (a list) of the command that prints one secret to stdout, or None
    (off). secret-put appends the secret's NAME as the last argument and runs
    it without a shell."""
    cfg = section("secret_source", governor)
    if cfg is None:
        return None
    argv = cfg["command"]
    if not isinstance(argv, list) or not argv or len(argv) > 16 \
            or not all(isinstance(a, str) and _ARGV_RE.match(a) for a in argv) \
            or argv[0].startswith("-") \
            or ("/" in argv[0] and not _abs_path(argv[0])):
        raise Refused("governor %s.secret_source.command must be a non-empty argv list "
                      "of plain words ([A-Za-z0-9_./=:@+-]); its first word a command "
                      "name or an absolute, normalised path" % KEY)
    return list(argv)
