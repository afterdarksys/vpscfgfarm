"""Second live copy of a service. Reports the twin. Does not stop it.

Threats:
  - Protects against: the same logical service running on Compose and k3s,
    or on two hosts, with nobody having named an owner.
  - Does NOT protect against: two copies that do not share a container name
    and do not declare the same authority.name. Decommission stays a
    reviewed play. Nothing here deletes a workload.
"""
import re

from .gates import Refused

NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
RUNTIMES = frozenset(["compose", "k3s"])


def validate(contract):
    block = contract.get("authority")
    if block is None:
        return
    if not isinstance(block, dict) or set(block) != {"name", "runtime"}:
        raise Refused("authority requires name and runtime, and nothing else")
    if not isinstance(block.get("name"), str) or not NAME_RE.fullmatch(block["name"]):
        raise Refused("authority.name must be a service name")
    if block.get("runtime") not in RUNTIMES:
        raise Refused("authority.runtime must be compose or k3s")


def declared_twins(contracts):
    """contracts are mappings that may carry authority. Others are ignored."""
    groups = {}
    for contract in contracts:
        block = contract.get("authority")
        if not isinstance(block, dict):
            continue
        groups.setdefault(block.get("name"), []).append(contract)
    findings = []
    for name, group in sorted(groups.items()):
        if len(group) < 2:
            continue
        runtimes = sorted(set(item["authority"]["runtime"] for item in group))
        hosts = sorted(set(item.get("host", "?") for item in group))
        services = sorted(item.get("service", "?") for item in group)
        findings.append({
            "name": name,
            "kind": "declared",
            "runtimes": runtimes,
            "hosts": hosts,
            "services": services,
            "detail": "declared %d times on %s via %s" % (
                len(group), ", ".join(hosts), ", ".join(runtimes)),
        })
    return findings


def live_twins(by_host):
    """by_host maps host -> iterable of running workload names."""
    seen = {}
    for host, names in (by_host or {}).items():
        for name in names:
            if not name:
                continue
            seen.setdefault(name, []).append(host)
    findings = []
    for name, hosts in sorted(seen.items()):
        unique = sorted(set(hosts))
        if len(unique) < 2:
            continue
        findings.append({
            "name": name,
            "kind": "live",
            "runtimes": [],
            "hosts": unique,
            "services": [],
            "detail": "running on %s" % ", ".join(unique),
        })
    return findings


def judge(contracts, by_host=None):
    findings = declared_twins(contracts) + live_twins(by_host or {})
    return {"ok": not findings, "findings": findings}


def render(report):
    lines = ["twins: %s (%d)" % ("OK" if report["ok"] else "FAIL", len(report["findings"]))]
    for item in report["findings"]:
        lines.append("  !! %-9s %s  %s" % (item["kind"], item["name"], item["detail"]))
    return "\n".join(lines)
