"""Declared host OS and end-of-life nag. Not a CVE scanner.

Threats:
  - Protects against: Debian 10 staying quiet just because no contract names
    the host. The nag is a declared fact, read on every fleet watch.
  - Does NOT protect against: a wrong declaration. A governed host missing
    from the file is UNPINNED, not "supported". This module never upgrades
    a host and never scans packages.
"""
from pathlib import Path

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False

import re

from . import estate
from .gates import Refused

PIN_NAME = "host-os.yaml"
_DEBIAN = re.compile(r"\ADebian ([0-9]+)\Z")


def _os_agrees(declared, pretty):
    """PRETTY_NAME is 'Debian GNU/Linux 10 (buster)', not 'Debian 10'."""
    text = pretty or ""
    match = _DEBIAN.fullmatch(declared or "")
    if match:
        return "Debian" in text and re.search(r"\b%s\b" % match.group(1), text) is not None
    return declared in text


def pin_path():
    return estate.root() / "estate" / PIN_NAME


def load(path=None):
    path = Path(path or pin_path())
    if not _HAVE_YAML:
        raise Refused("PyYAML is unavailable — host OS nag fails closed")
    try:
        raw = path.read_text()
    except OSError as exc:
        raise Refused("host OS pin %s unreadable (%s) — failing closed" % (path, exc))
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get("hosts"), dict):
        raise Refused("host OS pin must be a mapping of hosts")
    hosts = {}
    for name, spec in doc["hosts"].items():
        if not isinstance(name, str) or not isinstance(spec, dict):
            raise Refused("host OS entry %r is not a mapping" % name)
        if set(spec) - {"os", "eol"}:
            raise Refused("host OS entry %r has unknown keys" % name)
        if not isinstance(spec.get("os"), str) or not spec["os"]:
            raise Refused("host %r needs an os string" % name)
        if not isinstance(spec.get("eol"), bool):
            raise Refused("host %r eol must be true or false" % name)
        hosts[name] = {"os": spec["os"], "eol": spec["eol"]}
    return hosts


def nag(governed, declared=None, path=None, live=None):
    """Findings for canonical governed hosts. Aliases are the caller's job.

    `live` maps a host to a details-probe PRETTY_NAME. Omit it and this nag
    does not SSH. A supplied line that does not contain the declared OS is
    a mismatch. The line itself is not repeated.
    """
    declared = declared if declared is not None else load(path)
    live = live or {}
    findings = []
    for name in sorted(governed):
        spec = declared.get(name)
        if spec is None:
            findings.append({
                "host": name, "ok": False, "state": "UNPINNED",
                "detail": "no host_os declaration",
            })
            continue
        if spec["eol"]:
            findings.append({
                "host": name, "ok": False, "state": "EOL",
                "detail": spec["os"],
            })
        else:
            findings.append({
                "host": name, "ok": True, "state": "ok",
                "detail": spec["os"],
            })
        if name in live and not _os_agrees(spec["os"], live.get(name)):
            findings.append({
                "host": name, "ok": False, "state": "MISMATCH",
                "detail": "live OS line does not contain the declared OS",
            })
    return findings


def render(findings):
    lines = []
    for item in findings:
        mark = "ok" if item["ok"] else "!!"
        lines.append("  %s %-28s %-8s %s" % (mark, item["host"], item["state"], item["detail"]))
    bad = sum(1 for item in findings if not item["ok"])
    lines.append("host os: %d host(s), %d eol or unpinned" % (len(findings), bad))
    return "\n".join(lines)


def failing(findings):
    return sum(1 for item in findings if not item["ok"])
