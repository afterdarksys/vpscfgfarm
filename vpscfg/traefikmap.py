"""Traefik file-provider map — turn the routing truth into http verify entries.

Where Traefik's file provider is THE routing authority (docker labels exist
but are not read), every router rule there names a public hostname, and every
contract verify block should be checking one. The governor names the host and
file (integrations.traefik; off when unset). This module parses that YAML
(fetched read-only over the probe channel, probe.traefik_command) and proposes
`http:` verify entries per backend container.

Threats:
  - Protects against: nothing by itself — pure parsing of an already-fetched
    document; suggestions go through git review before they gate anything.
  - Does NOT protect against: a router pointing at the wrong backend — it
    propagates what Traefik believes, which is exactly the point (drift
    between belief and reality shows up as a failing verify).
"""
import re

try:
    import yaml
except ImportError:
    yaml = None

from .gates import Refused

HOST_RULE_RE = re.compile(r"Host\(`([^`]+)`\)")
URL_HOST_RE = re.compile(r"^https?://([A-Za-z0-9._-]+)(?::\d+)?")


def parse(text):
    """-> [{router, hostnames, service, backend_urls, backend_names}]"""
    if yaml is None:
        raise Refused("PyYAML unavailable — cannot parse the traefik file provider")
    doc = yaml.safe_load(text) or {}
    http = doc.get("http") or {}
    routers = http.get("routers") or {}
    services = http.get("services") or {}

    def backends(svc_name):
        svc = services.get(svc_name) or {}
        lb = svc.get("loadBalancer") or {}
        return [s.get("url", "") for s in (lb.get("servers") or []) if s.get("url")]

    out = []
    for rname, router in sorted(routers.items()):
        if not isinstance(router, dict):
            continue
        hostnames = HOST_RULE_RE.findall(router.get("rule", ""))
        svc = router.get("service", "")
        urls = backends(svc)
        names = []
        for u in urls:
            m = URL_HOST_RE.match(u)
            if m:
                names.append(m.group(1))
        out.append({"router": rname, "hostnames": hostnames, "service": svc,
                    "backend_urls": urls, "backend_names": names})
    return out


def suggestions(routes):
    """-> {backend_container_name: [verify_http_dict, ...]} — the entries a
    contract for that container should carry. Backend names that are IPs or
    localhost are skipped (they don't identify a container)."""
    out = {}
    for r in routes:
        for name in r["backend_names"]:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", name) or name in ("localhost", "127.0.0.1", "host.docker.internal"):
                continue
            for h in r["hostnames"]:
                entry = {"http": {"url": "https://%s/" % h, "expect": 200}}
                out.setdefault(name, [])
                if entry not in out[name]:
                    out[name].append(entry)
    return out
