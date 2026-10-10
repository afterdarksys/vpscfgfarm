#!/usr/bin/env python3
"""Regenerate a firewall-manager lockdown rollout: the per-host scripts and
boot unit to push, the break-glass runbook, and the vpsrun play.

    python3 tools/gen_firewall_rollout.py [SPEC]

Everything estate-specific comes from SPEC, by default
<estate>/estate/firewall-rollout.json (the estate root of vpscfg/estate.py):

    {
      "installer":     "/abs/path/to/the/firewall-manager/installer",
      "emit":          ["bash", "{installer}", "--emit", "{host}"],  # prints one host's script
      "unit_markers":  ["<line before the unit in the installer>\n", "<line after>\n"],
      "script_name":   "lockdown.sh",                    # file name in deploy_dir
      "script_path":   "/usr/local/sbin/lockdown.sh",    # where hosts run it
      "unit_name":     "lockdown.service",
      "unit_path":     "/etc/systemd/system/lockdown.service",
      "deploy_dir":    "deploy/firewall",                # under the estate root
      "runbook":       "policies/firewall-lockdown-rollout.yaml",
      "play":          "plays/firewall-lockdown-rollout.yaml",
      "header":        "estate/rollout-header.txt",      # optional; default
                                                         # tools/firewall_rollout_header.txt
      "hosts":         ["dns1", "dns2", "web2", "web1"],   # rollout order
      "backup_hosts":  ["web1", "web2"],  # keep the running script first
      "backup_suffix": "20260101",        # -> <script_path>.bak-<suffix>
      "unit_hosts":    ["dns1", "dns2"],  # new installs: also stage the unit
      "expires":       "2026-01-15",      # the runbook's expiry
      "reason":        "...",             # the runbook's reason
      "play_reason":   "...",             # the play's reason
      "notes":         ["# comment lines heading the runbook", "# ..."]
    }

`installer` may also be relative to the estate root. The emit argv runs with
no shell; `{installer}` and `{host}` are its only substitutions. The unit is
the installer's text between the two markers. Output is written under the
estate root: <deploy_dir>/<host>/<script_name>, <deploy_dir>/<unit_name>, the
runbook (the header with its `shape:`, then the entries) and the play.

Every push and install names the sha256 of the bytes written here, so the
runbook authorises exactly these scripts.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOL))

from vpscfg import estate  # noqa: E402

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}\Z")
SPEC_KEYS = ("installer", "emit", "unit_markers", "script_name", "script_path",
             "unit_name", "unit_path", "deploy_dir", "runbook", "play",
             "hosts", "backup_hosts", "backup_suffix", "unit_hosts",
             "expires", "reason", "play_reason", "notes")
NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9@._-]{0,254}\Z")


def _rel_ok(value):
    return isinstance(value, str) and not value.startswith("/") and all(
        NAME_RE.match(seg) and seg not in (".", "..") for seg in value.split("/"))


def _abs_ok(value):
    return isinstance(value, str) and value.startswith("/") and _rel_ok(value[1:])


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_spec(path):
    spec = json.loads(Path(path).read_text())
    missing = [k for k in SPEC_KEYS if k not in spec]
    if missing:
        raise SystemExit("%s: missing %s" % (path, ", ".join(missing)))
    hosts = spec["hosts"]
    for name in ("hosts", "backup_hosts", "unit_hosts"):
        if not isinstance(spec[name], list):
            raise SystemExit("%s: %s must be a list of host names" % (path, name))
        bad = [h for h in spec[name] if not isinstance(h, str) or not HOST_RE.match(h)]
        if bad:
            raise SystemExit("%s: %s has invalid host names %r" % (path, name, bad))
        if name != "hosts" and set(spec[name]) - set(hosts):
            raise SystemExit("%s: %s names hosts not in hosts" % (path, name))
    if not re.fullmatch(r"[0-9A-Za-z-]{1,32}", str(spec["backup_suffix"])):
        raise SystemExit("%s: backup_suffix must be plain [0-9A-Za-z-]" % path)
    for name in ("expires", "reason", "play_reason"):
        if not isinstance(spec[name], str) or any(c in spec[name] for c in ('"', "\\", "\n", "\r")):
            raise SystemExit("%s: %s must be a one-line string without quotes or backslashes"
                             % (path, name))
    for name in ("script_name", "unit_name"):
        if not isinstance(spec[name], str) or not NAME_RE.match(spec[name]):
            raise SystemExit("%s: %s must be a plain file name" % (path, name))
    for name in ("script_path", "unit_path"):
        if not _abs_ok(spec[name]):
            raise SystemExit("%s: %s must be an absolute, normalised path" % (path, name))
    for name in ("deploy_dir", "runbook", "play"):
        if not _rel_ok(spec[name]):
            raise SystemExit("%s: %s must be a normalised path relative to the estate root"
                             % (path, name))
    if "header" in spec and not _rel_ok(spec["header"]):
        raise SystemExit("%s: header must be a normalised path relative to the estate root"
                         % path)
    if not isinstance(spec["emit"], list) or not spec["emit"] or not all(
            isinstance(a, str) and a and "\n" not in a for a in spec["emit"]):
        raise SystemExit("%s: emit must be a non-empty argv list" % path)
    markers = spec["unit_markers"]
    if not isinstance(markers, list) or len(markers) != 2 or not all(
            isinstance(m, str) and m for m in markers):
        raise SystemExit("%s: unit_markers must be two non-empty strings" % path)
    if not isinstance(spec["notes"], list) or not all(
            isinstance(n, str) and n.startswith("#") and "\n" not in n for n in spec["notes"]):
        raise SystemExit("%s: notes must be a list of one-line '#' comments" % path)
    return spec


def main(argv):
    root = estate.root()
    spec = load_spec(argv[0] if argv else root / "estate" / "firewall-rollout.json")
    installer = Path(spec["installer"])
    if not installer.is_absolute():
        installer = root / installer
    hosts = spec["hosts"]
    name, spath = spec["script_name"], spec["script_path"]
    uname, upath = spec["unit_name"], spec["unit_path"]
    deploy = spec["deploy_dir"]
    backup = "cp -an %s %s.bak-%s" % (spath, spath, spec["backup_suffix"])

    out = root / deploy
    for host in hosts:
        (out / host).mkdir(parents=True, exist_ok=True)
        argv_ = [a.replace("{installer}", str(installer)).replace("{host}", host)
                 for a in spec["emit"]]
        script = subprocess.run(argv_, capture_output=True, text=True, check=True).stdout
        (out / host / name).write_text(script)
    before, after = spec["unit_markers"]
    unit_src = installer.read_text()
    if before not in unit_src or after not in unit_src.split(before, 1)[1]:
        raise SystemExit("%s: unit_markers not found" % installer)
    unit = unit_src.split(before, 1)[1].split(after, 1)[0]
    (out / uname).write_text(unit)
    unit_sha = sha(out / uname)

    rb, play = [], []

    def entry(host, cmd, why, verify=None):
        e = '  - hosts: [%s]\n    cmd: "%s"\n    where: host\n' % (host, cmd)
        if verify:
            e += '    verify: "%s"\n' % verify
        rb.append(e + '    break_glass: true\n    why: "%s"\n' % why)

    def step(host, why, cmd=None, push=None, sh=None):
        if push:
            play.append('  - hosts: %s\n    push: %s\n    sha256: "%s"\n    flags: ["--break-glass"]\n'
                        '    why: "%s"\n' % (host, push, sh, why))
        else:
            play.append('  - hosts: %s\n    cmd: "%s"\n    flags: ["--break-glass"]\n    why: "%s"\n'
                        % (host, cmd, why))

    for host in hosts:
        s = sha(out / host / name)
        staged = "/var/tmp/vpscfg-push/%s/%s" % (s, name)
        install = "install -m 0755 %s %s" % (staged, spath)
        entry(host, "vpscfg-push %s %s" % (s, name), "stage %s's generated lockdown script" % host)
        step(host, "stage %s's lockdown script" % host, push="%s/%s/%s" % (deploy, host, name), sh=s)
        if host in spec["backup_hosts"]:
            entry(host, backup, "keep the running script for rollback (-n: a re-run never clobbers it)")
            step(host, "back up %s's current script (rollback)" % host, cmd=backup)
        entry(host, install, "install the staged script by hash",
              "sha256sum %s | grep -c %s" % (spath, s))
        step(host, "install %s's script" % host, cmd=install)
        if host in spec["unit_hosts"]:
            ustaged = "/var/tmp/vpscfg-push/%s/%s" % (unit_sha, uname)
            uinstall = "install -m 0644 %s %s" % (ustaged, upath)
            entry(host, "vpscfg-push %s %s" % (unit_sha, uname), "stage the oneshot unit")
            step(host, "stage the unit on %s" % host, push="%s/%s" % (deploy, uname), sh=unit_sha)
            entry(host, uinstall, "install the unit",
                  "sha256sum %s | grep -c %s" % (upath, unit_sha))
            step(host, "install the unit on %s" % host, cmd=uinstall)
            entry(host, "systemctl daemon-reload", "load the new unit")
            step(host, "daemon-reload on %s" % host, cmd="systemctl daemon-reload")
            entry(host, "systemctl enable %s" % uname, "re-apply the lockdown at every boot",
                  "systemctl is-enabled %s" % uname)
            step(host, "enable at boot on %s" % host, cmd="systemctl enable %s" % uname)
        entry(host, spath,
              "apply now; the script exits non-zero on any error or failed self-check, which halts the play")
        step(host, "apply the lockdown on %s now (halts the play on failure)" % host, cmd=spath)

    notes = "\n".join(spec["notes"]) + "\n\n" if spec["notes"] else ""
    # The reviewed shape (vpscfg/vpsexecpolicy.py): every entry here is break-glass.
    shape = "{steps: %d, hosts: [%s], break_glass: true}" % (len(rb), ", ".join(sorted(set(hosts))))
    header_file = (root / spec["header"]) if "header" in spec else (
        TOOL / "tools" / "firewall_rollout_header.txt")
    header = header_file.read_text() % {
        "notes": notes, "expires": spec["expires"], "shape": shape, "reason": spec["reason"]}
    (root / spec["runbook"]).write_text(header + "\n".join(rb))
    play_text = ('version: 1\nreason: "%s"\nsteps:\n' % spec["play_reason"]) + "\n".join(play)
    (root / spec["play"]).write_text(play_text)
    print("%d runbook entries, %d play steps" % (len(rb), len(play)))
    for host in hosts:
        print("  %-6s %s" % (host, sha(out / host / name)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
