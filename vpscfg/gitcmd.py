"""git, as the doors run it: a pinned binary, no inherited configuration.

Used where a gate depends on git's answer (a reusable grant's scope files are
committed; the host index cache is ignored). Anything that lets the caller's
environment or a repository's own config steer git is removed:

  - the binary is the first of a fixed list of absolute paths that exists, is
    a regular file owned by root, and sits in directories that are all
    root-owned and not group/other-writable (checked up to /, after
    resolving symlinks) — never PATH, and never a user-owned Homebrew git;
  - the environment is minimal (PATH=/usr/bin:/bin, LC_ALL=C), so GIT_DIR,
    GIT_WORK_TREE, GIT_INDEX_FILE, GIT_CONFIG_* and the rest cannot be set;
  - system and global config are ignored (GIT_CONFIG_NOSYSTEM=1,
    GIT_CONFIG_GLOBAL=/dev/null, HOME=/nonexistent);
  - `-c core.fsmonitor=false` so a repository config cannot make git execute
    a hook; only plumbing that runs no hooks (and no network) is used by the
    callers. A repository's own config is still READ by these local calls
    (it cannot run anything through them); it is NEVER read by a network
    call;
  - the one exception to "no inherited configuration" is fetched() (below):
    the network fetch trusts the operator's own GLOBAL config (credentials),
    never a repository's, and runs in a private scratch repository.

Threats:
  - Protects against: a fake `git` earlier on PATH answering for the real one;
    environment variables pointing git at another repository, index or config;
    a repository's core.fsmonitor running code when the door asks a question.
  - Does NOT protect against: root replacing the pinned binary; a repository
    whose object database itself was rewritten by the same user (callers that
    need content integrity hash the bytes themselves and compare them to the
    committed blob).
"""
import contextlib
import os
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

from .gates import Refused

GIT_CANDIDATES = ("/usr/bin/git", "/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git")
GIT_TIMEOUT = 30
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent",
       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
       "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}


def _root_owned_chain(path):
    """The file and every directory above it are owned by root and not
    writable by group or other: nobody but root can swap the binary or
    anything on the way to it. Symlinks are resolved first."""
    real = os.path.realpath(path)
    node = real
    while True:
        try:
            st = os.stat(node)
        except OSError:
            return False
        if st.st_uid != 0 or st.st_mode & 0o022:
            # / and /tmp-like dirs with the sticky bit are not on these paths
            return False
        parent = os.path.dirname(node)
        if parent == node:
            return True
        node = parent


def binary(candidates=None):
    """The pinned git binary — a regular file owned by root, in a chain of
    root-owned, non-group/other-writable directories — or Refused. Returns the
    RESOLVED path it validated, never the candidate name: a symlink in a
    user-writable directory could be repointed between the check and the
    exec."""
    for path in candidates or GIT_CANDIDATES:
        real = os.path.realpath(path)
        try:
            st = os.lstat(real)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and _root_owned_chain(real):
            return real
    raise Refused("git is not available (none of %s is a regular file owned by root "
                  "in root-owned, non-writable directories) — failing closed"
                  % ", ".join(candidates or GIT_CANDIDATES))


def run(repo, *args):
    """(rc, stdout stripped) of pinned git in `repo`. No git is a refusal."""
    argv = [binary(), "-c", "core.fsmonitor=false", "-C", str(repo)] + list(args)
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=GIT_TIMEOUT,
                           env=dict(ENV), cwd="/")
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Refused("git is not available (%s) — failing closed" % e)
    return r.returncode, r.stdout.strip()


# ---------------------------------------------------------------------------
# fetched(): the ONE network call, and the one that trusts the operator's
# GLOBAL git config.
#
# What is trusted, exactly:
#   - the operator's own global (~/.gitconfig, HOME from the password
#     database) and system config, for credentials (osxkeychain, a helper)
#     — the same account could forge the grant key anyway;
#   - SSH_AUTH_SOCK (the operator's ssh-agent).
# What is NEVER trusted:
#   - the policy repository's own config (.git/config): the fetch never runs
#     in it. It runs in a private scratch bare repository (0700, created per
#     call by mkdtemp, removed after), whose config is git's clean default,
#     and fetches the URL BOUND AT MINT — not a remote name — so a
#     repository-local url.<x>.insteadOf, protocol.*.allow, core.sshCommand,
#     credential helper or uploadpack is never read;
#   - a global url.<x>.insteadOf that rewrites the bound URL: the effective
#     URL (`ls-remote --get-url`, same environment as the fetch) must equal
#     the bound one, or it refuses.
# Pinned on the command line (overrides global config): protocol.allow=never
# with only https and ssh allowed (FETCH_PROTOCOLS; tests of a local bare
# "origin" also allow file via FETCH_FILE_PROTOCOL), core.sshCommand = the
# system ssh by absolute path (SSH_COMMAND), core.fsmonitor=false,
# core.hooksPath=/dev/null, submodule.recurse=false; --no-tags,
# --no-recurse-submodules; PATH=/usr/bin:/bin; GIT_TERMINAL_PROMPT=0 (no
# credentials is a refusal, never a hang); FETCH_TIMEOUT. The caller reads
# what was fetched with the hardened run() in the scratch repository, never
# trusting fetch's own output.
#
# Threats (fetched):
#   - Protects against: a repository-local config redirecting or executing
#     anything during the fetch; a global insteadOf silently redirecting the
#     bound URL; a non-https/ssh transport (git://, http://, ext::, a local
#     path) standing in for the real remote; a hung or prompting fetch.
#   - Does NOT protect against: a same-user process editing the operator's
#     global config to steal or swap credentials (the operator's own config
#     is trusted); a compromised remote or stolen push credentials (pushed is
#     not reviewed unless the branch is protected).
# ---------------------------------------------------------------------------

FETCH_TIMEOUT = 20
FETCH_FILE_PROTOCOL = "never"
FETCH_PROTOCOLS = ("https", "ssh")
SSH_COMMAND = "/usr/bin/ssh"
REMOTE_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
REMOTE_REF_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_SCP_RE = re.compile(r"\A(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*:(?!//)[^\s]+\Z")


def valid_remote(name, ref):
    """True when `name` is a plain remote name and `ref` a plain branch name
    (no option-looking, `..`, `//`, `@{`, trailing `/` or `.lock`)."""
    return (isinstance(name, str) and isinstance(ref, str)
            and bool(REMOTE_NAME_RE.match(name)) and bool(REMOTE_REF_RE.match(ref))
            and ".." not in ref and "//" not in ref and not ref.endswith(("/", ".lock"))
            and not name.endswith(".lock"))


def url_allowed(url):
    """True for an https:// or ssh URL (ssh:// or scp-like user@host:path) —
    or, only where the test harness allows the file transport, an absolute
    local path / file:// URL. Never option-looking, never whitespace."""
    if not isinstance(url, str) or not url or url.startswith("-") or any(
            c.isspace() or ord(c) < 32 for c in url):
        return False
    if "https" in FETCH_PROTOCOLS and url.startswith("https://"):
        return True
    if "http" in FETCH_PROTOCOLS and url.startswith("http://"):
        return True
    # "::" is git's transport::address form (ext::, fd::); never scp-like.
    if "ssh" in FETCH_PROTOCOLS and (url.startswith("ssh://") or (
            _SCP_RE.match(url) and "::" not in url)):
        return True
    if FETCH_FILE_PROTOCOL == "always" and (url.startswith("/") or url.startswith("file://")):
        return True
    return False


def _operator_home():
    """The operator's home from the password database, never $HOME."""
    return pwd.getpwuid(os.getuid()).pw_dir


def _net_env():
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0",
           "GIT_OPTIONAL_LOCKS": "0", "HOME": _operator_home()}
    if os.environ.get("SSH_AUTH_SOCK"):
        env["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    return env


def _net_argv(scratch):
    """The pinned prefix of every network-reachable git call: options that
    override even the operator's global config, run in the scratch repo."""
    argv = [binary(), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
            "-c", "protocol.allow=never"]
    for proto in FETCH_PROTOCOLS:
        argv += ["-c", "protocol.%s.allow=always" % proto]
    argv += ["-c", "protocol.file.allow=%s" % FETCH_FILE_PROTOCOL,
             "-c", "core.sshCommand=%s" % SSH_COMMAND,
             "-c", "submodule.recurse=false", "-C", str(scratch)]
    return argv


def _net(scratch, *args):
    try:
        return subprocess.run(_net_argv(scratch) + list(args), capture_output=True,
                              text=True, timeout=FETCH_TIMEOUT, env=_net_env(), cwd="/",
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Refused("could not reach the policy remote (%s) — failing closed" % e)


@contextlib.contextmanager
def fetched(url, ref, object_format="sha1"):
    """Fetch branch `ref` of the BOUND `url` into a private scratch bare
    repository; yields (scratch path, fetched commit). The scratch repository
    is removed afterwards, whatever happens. Refused on: a URL that is not
    https/ssh, a global insteadOf that rewrites it, no network, no
    credentials, a missing branch, a timeout — fail closed."""
    if not valid_remote("origin", ref):
        raise Refused("policy branch %r is not a plain branch name" % (ref,))
    if not url_allowed(url):
        raise Refused("policy remote URL %r is not an https or ssh URL — refusing"
                      % (url,))
    if object_format not in ("sha1", "sha256"):
        raise Refused("unknown object format %r — failing closed" % (object_format,))
    scratch = tempfile.mkdtemp(prefix="vpscfg-fetch-")  # 0700, private
    try:
        os.chmod(scratch, 0o700)
        init = [binary(), "init", "-q", "--bare"]
        if object_format != "sha1":
            init.append("--object-format=%s" % object_format)
        try:
            r = subprocess.run(init + [scratch], capture_output=True, text=True,
                               timeout=GIT_TIMEOUT, env=dict(ENV), cwd="/")
        except (OSError, subprocess.TimeoutExpired) as e:
            raise Refused("could not create a scratch repository (%s) — failing closed" % e)
        if r.returncode != 0:
            raise Refused("could not create a scratch repository — failing closed")
        # The effective URL, as the fetch below would see it (the operator's
        # global insteadOf applied): it must be the bound one.
        r = _net(scratch, "ls-remote", "--get-url", url)
        effective = r.stdout.strip()
        if r.returncode != 0 or effective != url:
            raise Refused("the policy remote URL %s is rewritten to %r by git config "
                          "(url.<x>.insteadOf) — refusing; the grant is bound to %s"
                          % (url, effective, url))
        r = _net(scratch, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
                 url, "+refs/heads/%s:refs/heads/vpscfg-fetched" % ref)
        if r.returncode != 0:
            raise Refused("could not fetch %s from %s (git fetch rc=%d: %s) — failing "
                          "closed" % (ref, url, r.returncode,
                                      (r.stderr.strip().splitlines()
                                       or ["no output"])[-1][:160]))
        rc, commit = run(scratch, "rev-parse", "--verify", "--quiet",
                         "refs/heads/vpscfg-fetched^{commit}")
        if rc != 0 or not re.match(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z", commit):
            raise Refused("fetched %s from %s but cannot read its commit — failing closed"
                          % (ref, url))
        yield scratch, commit
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def blob_id(data, length):
    """git's object id of a blob with these bytes, in the repository's hash
    (40 hex: SHA-1, 64 hex: SHA-256) — computed here, from the exact bytes,
    never from git's index or work tree."""
    import hashlib
    header = b"blob %d\0" % len(data)
    algo = hashlib.sha1 if length == 40 else hashlib.sha256
    return algo(header + data).hexdigest()
