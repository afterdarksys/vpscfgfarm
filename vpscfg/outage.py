"""Outage-check — blast radius from OBSERVED state, before any apply.

Pure logic over probe data (injectable for tests). The questions it answers:
what shares this host, is a database in the container set, and does anything
live sit within one character of a name this operation touches.
"""
from .gates import edit_distance

DB_IMAGE_HINTS = ("postgres", "mysql", "mariadb", "redis", "mongo", "rabbitmq", "vault")

def assess(contract, live_containers, live_volumes, host_meta=None):
    """live_containers: [{"name":..,"image":..}], live_volumes: [names]."""
    findings = []
    owned = {contract.get("service")}
    owned.update(item["container"].get("name") for item in contract.get("verify", [])
                 if isinstance(item, dict) and isinstance(item.get("container"), dict))
    others = sum(c.get("name") not in owned for c in live_containers)
    findings.append(("shared_host", "%d other containers share this host" % others))
    dbs = [c["name"] for c in live_containers
           if any(h in (c.get("image") or "").lower() for h in DB_IMAGE_HINTS)]
    if dbs:
        findings.append(("databases_present",
                         "stateful services on this host: %s" % ", ".join(sorted(dbs)[:8])))
    declared = set(contract.get("blast_radius", {}).get("volumes", []))
    for vol in declared:
        for live in live_volumes:
            if vol != live and edit_distance(vol, live) == 1:
                findings.append(("volume_twin",
                                 "declared volume %r is 1 edit from live %r" % (vol, live)))
    if host_meta and host_meta.get("failover") is False:
        findings.append(("no_failover", "host has no failover — outage is total"))
    severe = [f for f in findings if f[0] in ("volume_twin",)]
    limit = contract.get("blast_radius", {}).get("max_other_containers")
    if limit is not None and (type(limit) is not int or limit < 0 or others > limit):
        severe.append(("blast_radius_exceeded", "observed containers exceed the reviewed blast-radius limit"))
        findings.extend(severe[-1:])
    return {"findings": findings, "prevent": bool(severe)}

def render(service, host, assessment):
    lines = ["OUTAGE-CHECK %s on %s:" % (service, host)]
    for kind, msg in assessment["findings"]:
        lines.append("  [%s] %s" % (kind, msg))
    lines.append("  verdict: %s" % ("PREVENT" if assessment["prevent"] else "proceed with care"))
    return "\n".join(lines)
