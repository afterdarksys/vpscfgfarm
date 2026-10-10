"""Read-only fleet observation over SSH.

Threats:
  - Protects against: probes accidentally mutating (every remote command here
    is a fixed, reviewed string with no operator input interpolated — host
    names come from ~/.ssh/config aliases only, validated against [A-Za-z0-9.-]);
    hangs (BatchMode + ConnectTimeout + subprocess timeout).
  - Does NOT protect against: a malicious remote returning lies. Observation
    trusts the fleet; contracts and verify exist to catch divergence, not fraud.
"""
import re
import subprocess

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}\Z")

_FIREWALL_PROBE = "; ".join([
    "command -v iptables >/dev/null 2>&1 || { echo @@@nat; echo NO_IPTABLES; exit 0; }",
    "echo @@@nat; iptables -t nat -S 2>/dev/null",
    "echo @@@raw_s; iptables -t raw -S PREROUTING 2>/dev/null",
    "echo @@@raw_l; iptables -t raw -L PREROUTING -n -v -x 2>/dev/null",
    "echo @@@raw6_s; if command -v ip6tables >/dev/null 2>&1; then ip6tables -t raw -S PREROUTING 2>/dev/null; else echo NO_IP6TABLES; fi",
    "echo @@@du_s; iptables -S DOCKER-USER 2>/dev/null",
    "echo @@@input_s; iptables -S INPUT 2>/dev/null",
    "echo @@@forward_l; iptables -L FORWARD -n -v -x 2>/dev/null",
    "echo @@@docker_ps; docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null",
    "echo @@@docker_ps_all; docker ps -a --format '{{.Names}}\t{{.Ports}}' 2>/dev/null || echo NO_DOCKER",
    "echo @@@docker_ips; docker ps -q 2>/dev/null | xargs -r docker inspect --format "
    "'{{.Name}}\t{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null",
    "echo @@@pods; if command -v k3s >/dev/null 2>&1; then k3s kubectl get pods -A "
    "-o jsonpath='{range .items[*]}{.status.podIP}{\"\\n\"}{end}' 2>/dev/null; else echo NO_K3S; fi",
    "echo @@@endpoints; command -v k3s >/dev/null 2>&1 && k3s kubectl get endpoints -A "
    "-o jsonpath='{range .items[*].subsets[*]}{range .addresses[*]}{.ip}{\"\\n\"}{end}{end}' 2>/dev/null",
    "echo @@@listen; ss -tln 2>/dev/null",
    "echo @@@units; for u in @@UNIT@@ netfilter-persistent; do "
    "echo \"$u $(systemctl is-enabled $u 2>/dev/null || echo absent) "
    "$(systemctl is-active $u 2>/dev/null)\"; done",
    "echo @@@script; sha256sum @@SCRIPT@@ 2>/dev/null",
    "echo @@@rules_v4; cat /etc/iptables/rules.v4 2>/dev/null",
    "true",
])

# k3s host health (vpscfg/k3s.py judges it). Read-only: versions, symlink
# targets, per-backend RULE COUNTS (never the rules), unit state, crash
# evidence from this boot's journal, kubectl get with a short timeout.
K3S_PROBE = "; ".join([
    "echo @@@present; command -v k3s >/dev/null 2>&1 && echo yes || echo NO_K3S",
    "echo @@@uptime; cat /proc/uptime",
    "echo @@@alternatives; readlink -f /usr/sbin/iptables /usr/sbin/ip6tables 2>/dev/null",
    "echo @@@version; iptables --version 2>/dev/null",
    "echo @@@legacy_rules; iptables-legacy-save 2>/dev/null | grep -c '^-A'",
    "echo @@@nft_rules; iptables-nft-save 2>/dev/null | grep -c '^-A'",
    "echo @@@unit; systemctl show k3s --property=ActiveState --property=SubState "
    "--property=NRestarts --property=UnitFileState --property=ActiveEnterTimestamp 2>/dev/null",
    "echo @@@panics; journalctl -u k3s -b --no-pager 2>/dev/null | grep -c 'panic: '",
    "echo @@@last_panic; journalctl -u k3s -b --no-pager 2>/dev/null | grep 'panic: ' | tail -1 | cut -c1-400",
    "echo @@@docker; systemctl is-active docker 2>/dev/null; systemctl is-enabled docker 2>/dev/null || echo absent",
    "echo @@@netfilter; systemctl is-enabled netfilter-persistent 2>/dev/null || echo absent",
    "echo @@@config; grep -hE '^(prefer-bundled-bin|flannel-backend|disable-network-policy|"
    "kube-proxy-arg|disable-kube-proxy|flannel-external-ip)' /etc/rancher/k3s/config.yaml 2>/dev/null",
    "echo @@@nodes; k3s kubectl get nodes --no-headers --request-timeout=8s 2>&1 | head -20",
    "echo @@@pods_bad; k3s kubectl get pods -A --no-headers --request-timeout=8s 2>&1 "
    "| grep -vE ' (Running|Completed) ' | head -40",
    "true",
])

# Running workloads for coverage and image pins. Fixed string. kubectl is
# last and unguarded: an API failure must not look like zero pods. No `true`.
WORKLOADS_PROBE = "; ".join([
    "echo @@@containers",
    "docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null || echo NO_DOCKER",
    "echo @@@pods",
    "if command -v k3s >/dev/null 2>&1; then k3s kubectl get pods -A --no-headers "
    "--request-timeout=8s -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,"
    "PHASE:.status.phase,WAITING:.status.containerStatuses[*].state.waiting.reason,"
    "RESTARTS:.status.containerStatuses[*].restartCount,"
    "IMAGES:.spec.containers[*].image; else echo NO_K3S; fi",
])

# Health duration. Counts and timestamps only. No `true` at the end.
HEALTH_PROBE = "; ".join([
    "echo @@@docker",
    "docker ps -aq 2>/dev/null | xargs -r docker inspect --format "
    "'{{.Name}}\t{{.State.Status}}\t{{if .State.Health}}{{.State.Health.Status}}"
    "{{else}}-{{end}}\t{{.State.StartedAt}}\t{{.RestartCount}}\t"
    "{{if .State.Health}}{{.State.Health.FailingStreak}}{{else}}0{{end}}' "
    "2>/dev/null || echo NO_DOCKER",
    "echo @@@pods",
    "if command -v k3s >/dev/null 2>&1; then k3s kubectl get pods -A --no-headers "
    "--request-timeout=8s -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,"
    "PHASE:.status.phase,WAITING:.status.containerStatuses[*].state.waiting.reason,"
    "RESTARTS:.status.containerStatuses[*].restartCount,"
    "STARTED:.metadata.creationTimestamp; else echo NO_K3S; fi",
])

# Fixed command strings only. NEVER interpolate operator input into these.
COMMANDS = {
    "containers": "docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null || echo NO_DOCKER",
    "services":   "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -40",
    "overlays":   "command -v k3s >/dev/null && k3s kubectl get ns --no-headers 2>/dev/null || echo NO_K3S",
    "details":    "hostname -f; uname -r; . /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\"; uptime",
    "opt":        "ls -1 /opt 2>/dev/null",
    # Change-detection fingerprint: name, image ID, status, created — for
    # every container INCLUDING stopped ones (a removal is a change too).
    "fingerprint": "docker ps -aq 2>/dev/null | xargs -r docker inspect --format '{{.Name}}\t{{.Image}}\t{{.State.Status}}\t{{.Created}}' 2>/dev/null || echo NO_DOCKER",
    # Pod change-detection fingerprint (k3s hosts): ns, name, uid, created,
    # spec images. NO_K3S (no binary) is a valid empty observation, but a k3s
    # host whose API server is down must FAIL (rc!=0), never read as "no pods"
    # — so kubectl runs unguarded and its stderr propagates.
    "fingerprint_pods": "command -v k3s >/dev/null 2>&1 || { echo NO_K3S; exit 0; }; k3s kubectl get pods -A --no-headers -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,UID:.metadata.uid,CREATED:.metadata.creationTimestamp,IMAGES:.spec.containers[*].image",
    # What is bound on the wire right now — kernel truth, not config claims.
    # -p adds the owning process (visible for all sockets when we land as root,
    # as we do on this fleet); parse_process_owners reads it best-effort and the
    # audit degrades cleanly to port-only when it is absent (netstat fallback).
    "listening":  "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null",
    "k3s": K3S_PROBE,
    "workloads": WORKLOADS_PROBE,
    "health": HEALTH_PROBE,
}


def firewall_command(manager=None):
    """The "firewall" probe for the firewall audit (vpscfg/firewall.py judges
    it locally). Listings only: iptables -S / -L -n -v -x (never -F/-D/-I/-Z/
    -P or restore), docker ps/inspect, kubectl get, ss, systemctl is-*, grep,
    sha256sum. Sections are @@@-delimited. The only values spliced in are the
    governor's firewall unit and script (integrations.firewall), validated
    there and shell-quoted here; no operator input reaches it. Refuses when
    the governor names no firewall manager."""
    import shlex
    from . import integrations
    from .gates import Refused
    cfg = manager or integrations.firewall_manager()
    if cfg is None:
        raise Refused("firewall audit skipped: no firewall manager configured — name "
                      "one in the governor (integrations.firewall)")
    return (_FIREWALL_PROBE.replace("@@UNIT@@", shlex.quote(cfg["unit"]))
            .replace("@@SCRIPT@@", shlex.quote(cfg["script"])))


def traefik_command():
    """The "traefik" probe: a read-only cat of the Traefik FILE provider the
    governor names (integrations.traefik.file). Docker labels are not read.
    Refuses when the governor names none: the mapping is off by default."""
    import shlex
    from . import integrations
    from .gates import Refused
    cfg = integrations.traefik()
    if cfg is None:
        raise Refused("traefik mapping skipped: no file provider configured — name "
                      "one in the governor (integrations.traefik.host and .file)")
    return "cat %s 2>/dev/null || echo NO_TRAEFIK_FILE" % shlex.quote(cfg["file"])


def run(host, what, connect_timeout=8, command_timeout=60):
    if not HOST_RE.match(host or ""):
        raise ValueError("invalid host name %r" % host)
    # Fail helpfully before dialing: the fleet registry is ~/.ssh/config.
    from . import sshconfig
    known = sshconfig.load()
    if known and host not in known:
        raise ValueError("host %r is not an alias in ~/.ssh/config — known: %s"
                         % (host, ", ".join(sorted(known))))
    if what == "traefik":
        command = traefik_command()
    elif what == "firewall":
        command = firewall_command()
    elif what in COMMANDS:
        command = COMMANDS[what]
    else:
        raise ValueError("no such probe %r (read-only probes: %s)"
                         % (what, sorted(set(COMMANDS) | {"traefik", "firewall"})))
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % connect_timeout,
         host, command],
        capture_output=True, text=True, timeout=command_timeout,
    )
    from . import secretmask
    out, err = secretmask.mask(result.stdout), secretmask.mask(result.stderr)
    rc = result.returncode
    if rc == 0 and (out or "").startswith("<output withheld"):
        # Withheld is "unobservable", never "no containers": a watch reading
        # an empty list would report everything removed.
        rc = 1
    return {"host": host, "probe": what, "rc": rc, "stdout": out, "stderr": err}


def latest_backup(host, service, connect_timeout=8):
    """Newest /root/<service>-pre-*.tar.gz on the host, or None. Service name
    is validated and quoted — it reaches a remote shell."""
    import shlex
    if not HOST_RE.match(host or ""):
        raise ValueError("invalid host name %r" % host)
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", service or ""):
        raise ValueError("invalid service name %r" % service)
    pattern = shlex.quote("/root/%s-pre-" % service) + "*.tar.gz"
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % connect_timeout,
         host, "ls -1t %s 2>/dev/null | head -1" % pattern],
        capture_output=True, text=True, timeout=30)
    line = result.stdout.strip()
    return line or None
