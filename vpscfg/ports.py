"""Port audit — tribal knowledge becomes declared, checkable fact.

Port allocation on a fleet lives in people's heads (DESIGN.md item 9: a
port on web1 belongs to some other app, not the API — a fact you learn by
breaking it). Contracts may declare `ports:`; this module compares the
declarations against what the kernel says is actually bound (`ss -lntup`)
and against each other. The `-p` column names the owning process, surfaced
next to each port so an undeclared listener points straight at its owner
instead of a naked number.

Three findings, two of them failures:
  - COLLISION  two contracts on one host claim the same port (also a lint E)
  - DOWN       a declared port with no listener — the service is not serving
  - undeclared a listener no contract claims — printed for coverage, not
               fatal (v1: most services have no contract yet; the list IS
               the to-do; ssh:22 is baselined out, and ephemeral-range
               listeners are counted not listed — see EPHEMERAL_MIN)

Threats:
  - Protects against: two services fighting over a port being discovered at
    deploy time instead of review time; a dead listener hiding behind a
    healthy container; unexpected public exposure going unlisted.
  - Does NOT protect against: firewalled-but-bound confusion (this reads
    bind state, not reachability) or processes that bind AFTER the probe.
"""
import re

from .gates import Refused

# Bound on every host by design; flagging them is noise that trains people
# to ignore the report.
BASELINE_PORTS = {("tcp", 22)}

# The kernel's ephemeral port range (Linux default 32768-60999). A listener
# here is almost always transient — an outbound socket caught mid-flight, or a
# WebRTC/media relay (which can bind hundreds of UDP ports in this range). None of it is a declarable service, and listing hundreds of
# them individually buries the ~20 real low ports the undeclared list exists to
# surface. So ephemeral undeclared listeners are COUNTED, not enumerated.
EPHEMERAL_MIN = 32768

_PORT_RE = re.compile(r"^\d{1,5}$")

# ss -p renders the owner column as users:(("name",pid=1234,fd=6),...).
# Grab the first quoted process name; that is enough to point a human at it.
_PROC_RE = re.compile(r'users:\(\("([^"]+)"')


def declared_ports(contract):
    """Host ports a contract claims, as {(proto, port)}. Sources: the
    `ports:` list (ints, "port", "port/udp", or "host:container" strings)
    and run.ports docker-style mappings."""
    out = set()
    entries = list(contract.get("ports") or [])
    run = contract.get("run") or {}
    entries += list(run.get("ports") or [])
    for e in entries:
        proto = "tcp"
        s = str(e).strip().strip('"')
        if "/" in s:
            s, proto = s.rsplit("/", 1)
            if proto not in ("tcp", "udp"):
                raise Refused("port entry %r: proto must be tcp or udp" % e)
        host_part = s.split(":")[0]  # "25:2525" -> host side
        if not _PORT_RE.match(host_part) or not 0 < int(host_part) < 65536:
            raise Refused("port entry %r does not name a host port" % e)
        out.add((proto, int(host_part)))
    return out


def parse_listening(ss_output):
    """`ss -lntu` (or netstat -lntu fallback) -> {(proto, port)}."""
    out = set()
    for line in ss_output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower().rstrip("6")
        if proto not in ("tcp", "udp"):
            continue
        # local address:port is the 5th column for ss, 4th for netstat;
        # take the first token that looks like addr:port.
        for token in parts[3:6]:
            m = re.match(r"^(.*):(\d{1,5})$", token)
            if m:
                out.add((proto, int(m.group(2))))
                break
    return out


def parse_process_owners(ss_output):
    """`ss -lntup` -> {(proto, port): process_name}. Best-effort: ports the
    kernel won't attribute (no -p data, netstat fallback, non-root) are simply
    absent, and the audit annotates only what it knows."""
    out = {}
    for line in ss_output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower().rstrip("6")
        if proto not in ("tcp", "udp"):
            continue
        key = None
        for token in parts[3:6]:
            m = re.match(r"^(.*):(\d{1,5})$", token)
            if m:
                key = (proto, int(m.group(2)))
                break
        if key is None:
            continue
        pm = _PROC_RE.search(line)
        if pm:
            out[key] = pm.group(1)
    return out


def audit(listening, contracts_by_service, owners=None):
    """Compare kernel truth against declarations across one host's contracts.
    `owners` (from parse_process_owners) is optional; when present it maps each
    bound port to its owning process for the report."""
    claims = {}
    for service, contract in sorted(contracts_by_service.items()):
        for key in declared_ports(contract):
            claims.setdefault(key, []).append(service)
    collisions = {k: v for k, v in claims.items() if len(v) > 1}
    down = {k: v for k, v in claims.items()
            if k not in listening and len(v) == 1}
    loose = listening - set(claims) - BASELINE_PORTS
    undeclared = sorted(k for k in loose if k[1] < EPHEMERAL_MIN)
    ephemeral = sorted(k for k in loose if k[1] >= EPHEMERAL_MIN)
    return {"collisions": collisions, "down": down, "undeclared": undeclared,
            "ephemeral": ephemeral, "declared": claims,
            "owners": owners or {}}


def render(host, report):
    owners = report.get("owners") or {}

    def _own(proto, port):
        name = owners.get((proto, port))
        return "  [%s]" % name if name else ""

    lines = ["PORTS %s:" % host]
    failures = 0
    for (proto, port), services in sorted(report["collisions"].items()):
        failures += 1
        lines.append("  COLLISION  %s/%-5d claimed by: %s — two contracts, "
                     "one port, one winner at deploy time%s"
                     % (proto, port, ", ".join(services), _own(proto, port)))
    for (proto, port), services in sorted(report["down"].items()):
        failures += 1
        lines.append("  DOWN       %s/%-5d declared by %s but nothing is "
                     "listening" % (proto, port, services[0]))
    for (proto, port), services in sorted(report["declared"].items()):
        if (proto, port) not in report["collisions"] and (proto, port) not in report["down"]:
            lines.append("  ok         %s/%-5d %s%s"
                         % (proto, port, services[0], _own(proto, port)))
    if report["undeclared"]:
        lines.append("  undeclared listeners (no contract claims them — the "
                     "tribal-knowledge to-do list):")
        for proto, port in report["undeclared"]:
            lines.append("    %s/%d%s" % (proto, port, _own(proto, port)))
    ephemeral = report.get("ephemeral") or []
    if ephemeral:
        etcp = sum(1 for p, _ in ephemeral if p == "tcp")
        eudp = len(ephemeral) - etcp
        lines.append("  + %d listener(s) in the ephemeral range (>=%d, tcp=%d "
                     "udp=%d) — transient/media, not individually declarable"
                     % (len(ephemeral), EPHEMERAL_MIN, etcp, eudp))
    lines.append("ports: %d declared, %d undeclared, %d ephemeral, %d failure(s)"
                 % (len(report["declared"]), len(report["undeclared"]),
                    len(ephemeral), failures))
    return "\n".join(lines), failures


def lint_collisions(loaded_contracts):
    """Cross-contract pass for lint: same host, same declared port -> error
    strings. Pure; lint decides how to report."""
    by_host = {}
    for name, contract in loaded_contracts.items():
        host = contract.get("host", "?")
        for key in declared_ports(contract):
            by_host.setdefault((host, key), []).append(name)
    errors = []
    for (host, (proto, port)), names in sorted(by_host.items()):
        if len(names) > 1:
            errors.append("port collision on %s: %s/%d declared by %s"
                          % (host, proto, port, " AND ".join(sorted(names))))
    return errors
