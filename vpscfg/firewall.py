"""`vpscfg fleet firewall` — a firewall manager's audit, through the door.

A port of a firewall manager's reconciler and stale-NAT detector as a READ:
facts are gathered by one reviewed probe string (probe.firewall_command())
and judged here, locally. Nothing on the host is changed; the firewall
manager's own apply and fix paths stay in the firewall manager.

It answers the four questions the outage taught:
  1. Is the Redis/Postgres lockdown present in a chain that is actually
     reached, and in the right order (ACCEPTs above the DROP)?
  2. Is any NAT rule aiming at a container or pod IP that no longer exists
     (STALE: traffic is blackholed now) or at a container that is gone
     (orphan: harmless until something claims the port)?
  3. Will the lockdown survive a reboot (the manager's boot unit enabled)?
  4. Is the landmine armed: iptables-persistent / netfilter-persistent
     enabled with a saved rules file that bakes in Docker/k8s NAT, which
     replays stale IPs over live state at boot?

Desired state (servers, admin, private, ports) is the firewall manager's
JSON, the same file its lockdown script is generated from. The governor
names it, relative to the estate root, together with the lockdown script's
path on each host, its boot unit and the installer remedies point at
(integrations.firewall, see vpscfg/integrations.py). With none named, the
audit refuses: there is nothing to judge against. No environment variable
can name any of it.

Threats:
  - Protects against: the probe mutating (fixed string, no operator input,
    only -S/-L listings, docker ps/inspect, kubectl get, ss, systemctl
    is-*, dpkg -l, grep -c, sha256sum); a false "you are exposed" from a
    parser that misses multiport or ranges (both handled); a
    false "protected" from presence alone (a missing DROP on a LISTENING
    port is CRITICAL, on an idle port MEDIUM, and DROP counters are shown).
  - Does NOT protect against: a lying host. From inside, you can prove a rule
    exists and has fired, not that the port is unreachable from outside;
    the definitive test is a probe from a non-allowlisted address.
"""
import hashlib
import json
import re
from pathlib import Path

from .gates import Refused

CRITICAL, HIGH, MEDIUM, INFO = "CRITICAL", "HIGH", "MEDIUM", "INFO"
FAILING = (CRITICAL, HIGH)
SECTION_RE = re.compile(r"^@@@([a-z0-9_]+)$")
_PUBLISHED = re.compile(r":(\d+)(?:-(\d+))?->")
# Lines in a saved ruleset that belong to Docker/k8s and go stale on restart.
# "-j DOCKER" = Docker's own jumps (FORWARD -> DOCKER-USER/ISOLATION, the
# addrtype LOCAL -> DOCKER hooks), which dockerd re-creates on start. The
# RULES inside DOCKER-USER are not listed here: nobody re-creates those.
_VOLATILE = ("DNAT", "KUBE-", "CNI-", "-A DOCKER ", "-A DOCKER-ISOLATION", ":DOCKER ", "-j DOCKER",
             "FLANNEL", " br-", "docker0", "MASQUERADE",
             "f2b-",  # fail2ban rebuilds its own chains when it starts
             "cni0", "flannel.", "kube-bridge", "veth", "10.42.", "10.43.")


def load_estate(path=None):
    """The desired state. `path` is for in-process tests only; at runtime it
    is the file the governor names, and nothing else."""
    if path is None:
        from . import integrations
        manager = integrations.firewall_manager()
        got = integrations.firewall_desired_state_read()
        if got is None or manager is None:
            raise Refused("firewall audit: no desired-state file configured — name one in "
                          "the governor (integrations.firewall.desired_state, relative to "
                          "the estate root, with its script, unit and installer)")
        path, raw = Path(got[0]), got[1]
    else:
        path = Path(path)
        raw = None
        manager = None
    try:
        if raw is None:
            raw = path.read_bytes()
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError("cannot read firewall desired state %s: %s — the lockdown's "
                         "desired state lives there (governor integrations.firewall.desired_state)"
                         % (path, e))
    for key in ("servers", "admin", "private", "ports"):
        if not isinstance(doc.get(key), list):
            raise ValueError("firewall desired state %s: %r must be a list" % (path, key))
    ports = [int(p) for p in doc["ports"]]

    def per_host(key):
        v = doc.get(key) or {}
        if not isinstance(v, dict):
            raise ValueError("firewall desired state %s: %r must be a mapping of host -> ports"
                             % (path, key))
        return dict((str(h), [int(p) for p in ps]) for h, ps in v.items())
    return {"servers": [str(s) for s in doc["servers"]],
            "admin": [str(a) for a in doc["admin"]],
            "private": [str(p) for p in doc["private"]],
            "ports": ports, "host_ports": per_host("host_ports"),
            "public": per_host("public"), "undecided": per_host("undecided"),
            "path": str(path), "manager": manager,
            "sha256": hashlib.sha256(raw).hexdigest()}


def for_host(estate, names):
    """The estate as it applies to one machine, looked up under any of its
    names (web1 IS web1.example.internal). Global ports unless host_ports
    names this machine."""
    def pick(key, default):
        for n in names:
            if n in (estate.get(key) or {}):
                return estate[key][n]
        return default
    out = dict(estate)
    out["ports"] = pick("host_ports", estate["ports"])
    out["public_ports"] = pick("public", [])
    out["undecided_ports"] = pick("undecided", [])
    return out


def sections(stdout):
    """Split the probe's @@@name-delimited output into {name: text}."""
    out, name, buf = {}, None, []
    for line in stdout.splitlines():
        m = SECTION_RE.match(line.strip())
        if m:
            if name:
                out[name] = "\n".join(buf)
            name, buf = m.group(1), []
        elif name:
            buf.append(line)
    if name:
        out[name] = "\n".join(buf)
    return out


def ports_in(line):
    """--dport N and multiport --dports a,b,c. Missing multiport makes a
    parser see zero rules and scream 'wide open'."""
    m = re.search(r"--dports ([0-9,:]+)", line)
    if m:
        out = []
        for part in m.group(1).split(","):
            lo, _, hi = part.partition(":")
            if lo:
                out.extend(range(int(lo), int(hi or lo) + 1))
        return out
    m = re.search(r"--(?:dport|ctorigdstport) (\d+)", line)
    return [int(m.group(1))] if m else []


def _norm(src):
    return src[:-3] if src and src.endswith("/32") else src


def collect(rules_s):
    """(ordered [(kind, port, src)], drops, accepts) from `iptables -S CHAIN`.
    Order is list order, which is evaluation order within the chain."""
    ordered, drops, accepts = [], set(), set()
    for line in rules_s.splitlines():
        ports = ports_in(line)
        if not ports:
            if re.search(r"-j (ACCEPT|RETURN)\b", line) and "-s " not in line and line.startswith("-A "):
                ordered.append(("accept-all", None, None))
            continue
        qualified = any(q in line for q in (" -i ", " -d ", " ! ")) or "-p tcp" not in line
        m = re.search(r"-s ([0-9./]+)", line)
        src = _norm(m.group(1)) if m else None
        for port in ports:
            if "-j DROP" in line and not src and not qualified:
                drops.add(port)
                ordered.append(("drop", port, None))
            elif ("-j ACCEPT" in line or "-j RETURN" in line) and not src:
                ordered.append(("accept-all", port, None))
            elif ("-j ACCEPT" in line or "-j RETURN" in line) and src:
                accepts.add((port, src))
                ordered.append(("accept", port, src))
    return ordered, drops, accepts


def drop_counters(rules_l):
    """{port: packets} for DROP rules in `iptables -L -n -v -x` output."""
    fired = {}
    for line in rules_l.splitlines():
        parts = line.split()
        if len(parts) < 3 or "DROP" not in parts:
            continue
        m = re.search(r"dpts?:([0-9:,]+)", line)
        if not m:
            continue
        try:
            pkts = int(parts[0])
        except ValueError:
            continue
        for port in ports_in("--dports " + m.group(1)):
            fired[port] = fired.get(port, 0) + pkts
    return fired


def docker_user_effective(forward_l):
    """Evidence, never chain order. Absent -> not traversed."""
    return "DOCKER-USER" in forward_l


def publisher_of(port, ps_lines):
    want = int(port)
    for line in ps_lines.splitlines():
        name, _, published = line.partition("\t")
        for lo, hi in _PUBLISHED.findall(published):
            if int(lo) <= want <= int(hi or lo):
                return name.strip()
    return ""


def listening(port, ss_out):
    """Bound on a non-loopback address. A port on 127.0.0.1/::1 only is not
    reachable from outside; grading it CRITICAL teaches people to skim."""
    for line in ss_out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        addr, _, lport = local.rpartition(":")
        if lport != str(int(port)):
            continue
        if addr.strip("[]") in ("127.0.0.1", "::1", "localhost") or addr.startswith("127."):
            continue
        return True
    return False


def listening_v6(port, ss_out):
    """Bound on [::] / * (dual-stack) or a global v6 address."""
    for line in ss_out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        addr, _, lport = parts[3].rpartition(":")
        if lport == str(int(port)) and (addr in ("*", "[::]") or
                                         (addr.startswith("[") and addr != "[::1]")):
            return True
    return False


def _f(sev, kind, detail, remedy=""):
    return {"severity": sev, "kind": kind, "detail": detail, "remedy": remedy}


def audit(stdout, estate):
    """Findings for one host from the probe's stdout. estate["manager"] names
    the firewall manager's unit and installer (integrations.firewall)."""
    s = sections(stdout)
    manager = estate.get("manager") or {}
    unit = manager.get("unit", "")
    script = manager.get("script", "the lockdown script")
    installer = manager.get("installer", "the firewall manager's installer")
    findings = []
    if "NO_IPTABLES" in s.get("nat", ""):
        return [_f(INFO, "no-iptables", "iptables is not installed here")], {}

    # --- 1. lockdown presence, order, enforcement evidence ----------------
    ordered, raw_drops, raw_acc = collect(s.get("raw_s", ""))
    du_on = docker_user_effective(s.get("forward_l", ""))
    _, du_drops, du_acc = collect(s.get("du_s", "")) if du_on else ([], set(), set())
    ps_published = s.get("docker_ps", "")
    du_drops = set(p for p in du_drops if publisher_of(p, ps_published))
    drops, accepts = raw_drops | du_drops, raw_acc | du_acc
    # filter/INPUT protects a HOST process, never a Docker-published port
    # (DNAT happens in PREROUTING, before INPUT is consulted).
    _, input_drops, _ = collect(s.get("input_s", ""))
    allow = estate["private"] + estate["servers"] + estate["admin"]
    ss_out = s.get("listen", "")
    ps_running = s.get("docker_ps", "")
    idle_gaps = []
    for port in estate["ports"]:
        if port not in drops and port in input_drops and not publisher_of(port, ps_running):
            findings.append(_f(INFO, "input-drop-only",
                               "port %d is dropped in filter/INPUT (host process), not by "
                               "the raw lockdown — no allowlist applies there" % port))
            continue
        if port not in drops:
            if listening(port, ss_out):
                findings.append(_f(
                    CRITICAL, "missing-drop",
                    "port %d is LISTENING on a public address with no DROP in "
                    "raw/PREROUTING or DOCKER-USER — open to the internet" % port,
                    "install/regenerate the lockdown from the desired state "
                    "(%s)" % installer))
            else:
                idle_gaps.append(port)
            continue
        missing = [src for src in allow if (port, _norm(src)) not in accepts]
        if missing:
            findings.append(_f(MEDIUM, "missing-allow",
                               "port %d lacks ACCEPT for %s — locked out"
                               % (port, ", ".join(missing)),
                               "run %s" % script))
        # In raw, an ACCEPT below the DROP never matches: the DROP wins.
        if port in raw_drops:
            first_drop = next(i for i, r in enumerate(ordered) if r[:2] == ("drop", port))
            if any(r[0] == "accept-all" and r[1] in (None, port) for r in ordered[:first_drop]):
                findings.append(_f(CRITICAL, "drop-shadowed",
                                   "port %d: an unconditional ACCEPT/RETURN sits ABOVE the DROP, "
                                   "so the lockdown never fires" % port,
                                   "remove the blanket ACCEPT or move it below the lockdown"))
            shadowed = [r[2] for i, r in enumerate(ordered)
                        if r[0] == "accept" and r[1] == port and i > first_drop]
            if shadowed:
                findings.append(_f(HIGH, "allow-below-drop",
                                   "port %d: ACCEPT for %s sits BELOW the DROP and "
                                   "never matches" % (port, ", ".join(shadowed)),
                                   "re-run %s (it inserts DROP first)" % script))
    if idle_gaps:
        findings.append(_f(MEDIUM, "missing-drop-no-listener",
                           "no DROP for port(s) %s — nothing public listens yet, a "
                           "latent gap" % ",".join(map(str, idle_gaps)),
                           "install/regenerate the lockdown from the desired state"))
    _, raw6_drops, _ = collect(s.get("raw6_s", ""))
    no_v6 = "NO_IP6TABLES" in s.get("raw6_s", "")
    for port in estate["ports"]:
        if listening_v6(port, ss_out) and port not in raw6_drops:
            findings.append(_f(HIGH, "v6-unprotected",
                               "port %d listens on [::] and has no IPv6 DROP%s — reachable "
                               "over IPv6 unless something upstream filters it"
                               % (port, " (ip6tables absent)" if no_v6 else ""),
                               "the lockdown adds a v6 DROP; confirm from a non-allowlisted "
                               "v6 address: nc -6 -zvw3 <addr> %d" % port))
    fired = drop_counters(s.get("raw_l", ""))
    idle = [p for p in estate["ports"] if p in raw_drops and not fired.get(p)]
    if idle and len(idle) < len([p for p in estate["ports"] if p in raw_drops]):
        findings.append(_f(INFO, "unverified-enforcement",
                           "DROP for port(s) %s has never fired: present, not proven"
                           % ", ".join(map(str, idle)),
                           "probe from an address NOT on the allowlist"))

    # --- 2. stale / orphan DNAT --------------------------------------------
    nat = s.get("nat", "")
    ps_run, ps_all = s.get("docker_ps", ""), s.get("docker_ps_all", "")
    ips = {}
    for line in s.get("docker_ips", "").splitlines():
        name, _, addrs = line.partition("\t")
        ips[name.strip().lstrip("/")] = set(addrs.split())
    for line in nat.splitlines():
        if not line.startswith("-A DOCKER ") or "-j DNAT" not in line:
            continue
        pm = re.search(r"--dport (\d+)", line)
        tm = re.search(r"--to-destination ([0-9.]+):", line)
        if not pm or not tm:
            continue
        port, target = pm.group(1), tm.group(1)
        owner = publisher_of(port, ps_run)
        if not owner:
            dead = publisher_of(port, ps_all)
            findings.append(_f(INFO, "orphan-dnat", "port %s -> %s has no running "
                               "publisher%s" % (port, target, " (was %s)" % dead if dead else ""),
                               "harmless now; hijacks the port if a new service claims it"))
        elif target not in ips.get(owner, set()):
            findings.append(_f(HIGH, "stale-dnat",
                               "port %s -> %s but %s is at %s — traffic is blackholed"
                               % (port, target, owner, " ".join(sorted(ips.get(owner, ()))) or "?"),
                               "restart %s AND delete the stale rule (docker appends, "
                               "it does not replace)" % owner))
    pod_ips = set(s.get("pods", "").split())
    live_eps = set(s.get("endpoints", "").split())
    for line in nat.splitlines():
        tm = re.search(r"--to-destination ([0-9.]+):(\d+)", line)
        if "-j DNAT" not in line or not tm:
            continue
        ip, port = tm.group(1), tm.group(2)
        if line.startswith("-A CNI-DN") and pod_ips and ip not in pod_ips:
            findings.append(_f(HIGH, "stale-hostport",
                               "CNI hostPort %s -> %s: not a live pod IP, hijacking host "
                               "port %s" % (port, ip, port),
                               "remove the hostPort from the workload; do not hand-edit"))
        if (line.startswith("-A KUBE-SEP-") and ip.startswith("10.42.") and live_eps
                and ip not in live_eps):
            findings.append(_f(HIGH, "stale-kube-endpoint",
                               "kube DNAT targets %s, which is not a live endpoint" % ip,
                               "bounce the owning workload so kube-proxy reprograms"))

    # --- 3 + 4. persistence and the landmine --------------------------------
    units = dict((ln.split()[0], ln.split()[1:]) for ln in s.get("units", "").splitlines()
                 if ln.split())
    unit_state = units.get(unit, []) if unit else []
    has_docker = bool(ps_all.strip()) and "NO_DOCKER" not in ps_all
    has_k3s = "NO_K3S" not in s.get("pods", "NO_K3S")
    if drops and (not unit_state or unit_state[0] != "enabled"):
        findings.append(_f(HIGH, "not-persistent",
                           "%s is not enabled — a reboot drops the lockdown"
                           % (unit or "the firewall manager's boot unit"),
                           "%s <host>" % installer))
    nfp = units.get("netfilter-persistent", [])
    saved_rules = [ln for ln in s.get("rules_v4", "").splitlines() if ln.startswith("-A ")]
    volatile = sum(1 for ln in saved_rules if any(v in ln for v in _VOLATILE))
    # Rules that live ONLY in the snapshot: disabling netfilter-persistent
    # drops them at the next boot unless they are ported first. The lockdown
    # itself is re-applied by the manager's unit, so its own rules are not unique.
    # A port-less, source-less DOCKER-USER RETURN only says "carry on"; losing
    # it opens nothing, so it is not worth a finding. Likewise an INPUT ACCEPT
    # when the saved INPUT policy is ACCEPT: it permits what is permitted anyway.
    input_accepts = bool(re.search(r"^:INPUT ACCEPT", s.get("rules_v4", ""), re.M))
    unique = [ln for ln in saved_rules
              if not any(v in ln for v in _VOLATILE) and not _is_lockdown(ln, estate)
              and not (input_accepts and ln.startswith("-A INPUT") and ln.rstrip().endswith("-j ACCEPT"))
              and not (ln.startswith("-A DOCKER-USER") and ln.rstrip().endswith("-j RETURN")
                       and not ports_in(ln) and "-s " not in ln)]
    if nfp and nfp[0] == "enabled" and (has_docker or has_k3s):
        findings.append(_f(HIGH if volatile else MEDIUM, "landmine-armed" if volatile
                           else "snapshot-persistence",
                           ("netfilter-persistent is enabled and /etc/iptables/rules.v4 "
                            "holds %d Docker/k8s NAT line(s): a boot replays stale IPs "
                            "over live state" % volatile) if volatile
                           else "netfilter-persistent is enabled on a docker/k8s host",
                           "disable netfilter-persistent; let %s persist only the "
                           "lockdown" % (unit or "the firewall manager's boot unit")))
    for port in estate.get("undecided_ports", []):
        if listening(port, ss_out):
            findings.append(_f(INFO, "undecided-exposure",
                               "port %d listens publicly and nobody has decided whether "
                               "it should (estate.json undecided)" % port))
    if unique and nfp and nfp[0] == "enabled":
        findings.append(_f(MEDIUM, "snapshot-unique-rules",
                           "%d rule(s) exist only in /etc/iptables/rules.v4 and are lost "
                           "at the next boot if netfilter-persistent is disabled: %s"
                           % (len(unique), " | ".join(unique[:6]) + (" | …" if len(unique) > 6 else "")),
                           "port them into the firewall manager BEFORE disabling"))
    facts = {"script_sha256": (s.get("script", "").split() or [""])[0],
             "snapshot_unique": unique,
             "raw_drops": sorted(raw_drops), "fired": fired,
             "netfilter_persistent": " ".join(nfp) or "absent",
             "manager_unit": " ".join(unit_state) or "absent",
             "docker": has_docker, "k3s": has_k3s}
    return findings, facts


def _is_lockdown(line, estate):
    """A saved rule the firewall manager re-creates at boot anyway: raw
    PREROUTING for a locked port. A DOCKER-USER rule is NOT re-created by
    anyone (Docker leaves the chain empty), so it counts as covered only when
    its port is a locked port, whose raw rule then protects the host port."""
    ports = ports_in(line)
    if not ports or not set(ports) <= set(estate["ports"]):
        return False
    # An INPUT DROP for a locked port is covered too: the raw DROP sees the
    # packet first, before INPUT is consulted.
    return ("-A PREROUTING" in line or "-A DOCKER-USER" in line
            or ("-A INPUT" in line and line.rstrip().endswith("-j DROP")))


def fleet_findings(facts_by_host, estate):
    """Cross-host: every lockdown script should be the same build."""
    by_hash = {}
    for host, facts in facts_by_host.items():
        if facts.get("script_sha256"):
            by_hash.setdefault(facts["script_sha256"], []).append(host)
    out = []
    if len(by_hash) > 1:
        out.append(_f(INFO, "script-drift",
                      "the lockdown script differs across hosts: %s"
                      % "; ".join("%s=%s" % (h[:12], ",".join(sorted(v)))
                                  for h, v in sorted(by_hash.items())),
                      "expected when host_ports differ; compare with the generated "
                      "scripts' hashes"))
    return out


def render(host, findings, facts):
    lines = ["── %s ──" % host]
    if facts:
        lines.append("   lockdown DROPs: %s   fired: %s   boot unit: %s   "
                     "netfilter-persistent: %s"
                     % (",".join(map(str, facts["raw_drops"])) or "none",
                        ",".join("%s=%s" % kv for kv in sorted(facts["fired"].items())) or "-",
                        facts["manager_unit"], facts["netfilter_persistent"]))
    if not findings:
        lines.append("   ok — no findings")
    order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3}
    for f in sorted(findings, key=lambda f: order[f["severity"]]):
        lines.append("   %-8s %-26s %s" % (f["severity"], f["kind"], f["detail"]))
        if f["remedy"] and f["severity"] != INFO:
            lines.append("   %-8s %-26s → %s" % ("", "", f["remedy"]))
    return "\n".join(lines)
