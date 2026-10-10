"""vpscfg — contract-based fleet configuration & deployment safety.

Sanctioned entry point: ../vpscfg-control.py. Direct invocation of this
package is read-only by design (see control.py)."""
__version__ = "0.1.0"

import os as _os
import stat as _stat
import sys as _sys


def _operator_site_path():
    """The user site-packages of the user this process runs AS, located from
    the password database (never $HOME or PYTHONUSERBASE)."""
    import pwd
    import sysconfig
    home = pwd.getpwuid(_os.geteuid()).pw_dir
    if _sys.platform == "darwin" and sysconfig.get_config_var("PYTHONFRAMEWORK"):
        scheme = "osx_framework_user"
        base = _os.path.join(home, "Library", "Python", "%d.%d" % _sys.version_info[:2])
    else:
        scheme, base = "posix_user", _os.path.join(home, ".local")
    return sysconfig.get_path("purelib", scheme, vars={"userbase": base})


def _operator_site(path=None, lstat=None, euid=None, sys_path=None):
    """Under `python3 -I` (how every door runs) the user site-packages is not
    on sys.path, and dependencies such as PyYAML are often installed there.
    Re-add the operator's own site (see _operator_site_path). It is appended
    (it cannot shadow the standard library or this package), added as a plain
    path (no .pth files, no usercustomize), and only if the directory is a real
    directory owned by the operator and not group/world-writable. Otherwise a
    missing dependency refuses, as before. Returns True if it was added.
    The keyword arguments are injectable for tests only."""
    sys_path = _sys.path if sys_path is None else sys_path
    euid = _os.geteuid() if euid is None else euid
    try:
        path = path or _operator_site_path()
        st = (lstat or _os.lstat)(path)
    except (ImportError, KeyError, OSError, ValueError):
        return False
    if not _stat.S_ISDIR(st.st_mode) or st.st_uid != euid:
        return False
    if st.st_mode & 0o022:
        return False
    if path not in sys_path:
        sys_path.append(path)
    return True


if _sys.flags.isolated:
    _operator_site()
