"""Ansible playbook driver — --show only in v0 (check + diff, never apply).

Threats:
  - Protects against: mutation through the ansible verb (the argv this module
    builds ALWAYS carries --check; --run is additionally refused upstream in
    both doors); playbook path injection (validated name, resolved inside
    playbooks/ only); typo'd hosts (host must be a ~/.ssh/config alias, the
    same rule probes enforce).
  - Does NOT protect against: check-mode blind spots — command/shell tasks
    are SKIPPED in check mode, not proven. A clean --show is necessary,
    not sufficient.
"""
import re
import subprocess
from pathlib import Path

from . import estate
from .gates import Refused

PLAYBOOK_DIR = estate.root() / "playbooks"
# The compatibility floor is Debian 10 targets, whose Python is 3.7.3.
# ansible-core >= 2.16 refuses 3.7 targets, so a pinned 2.15 lives in
# .venv-ansible/ (gitignored; recreate with:
# python3 -m venv .venv-ansible && .venv-ansible/bin/pip install 'ansible-core>=2.15,<2.16').
# Targets on a newer OS can use any ansible-core.
_PINNED = Path(__file__).resolve().parent.parent / ".venv-ansible" / "bin" / "ansible-playbook"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$")


def show_argv(host, name, known_hosts=None):
    """Build the read-only ansible argv. Refuses before touching the network."""
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host name %r" % host)
    if known_hosts is None:
        from . import sshconfig
        known_hosts = sshconfig.load()
    if known_hosts and host not in known_hosts:
        raise Refused("host %r is not an alias in ~/.ssh/config — known: %s"
                      % (host, ", ".join(sorted(known_hosts))))
    if not name:
        raise Refused("ansible requires a playbook name (see playbooks/)")
    if not NAME_RE.match(name):
        raise Refused("playbook name %r fails validation" % name)
    path = PLAYBOOK_DIR / (name + ".yml")
    if not path.exists():
        raise Refused("no playbook %r in %s" % (name, PLAYBOOK_DIR))
    binary = str(_PINNED) if _PINNED.exists() else "ansible-playbook"
    return [binary, "--check", "--diff",
            "-i", "%s," % host, "--limit", host, str(path)]


def show(host, name):
    argv = show_argv(host, name)
    print("ANSIBLE --show (check+diff; no changes are made):")
    print("  " + " ".join(argv))
    r = subprocess.run(argv)
    return r.returncode
