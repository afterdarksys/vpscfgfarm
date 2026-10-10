"""`vpscfg fleet k3s` — k3s host health and reboot safety, as a read.

Born from a k3s outage. After a reboot, k3s crash-looped: kube-router
panicked on `iptables -C ... Chain 'KUBE-ROUTER-INPUT' does not exist` from
Debian 10's iptables-nft 1.8.2, and every restart left the filter table
without Docker's chains, so Docker could not publish ports and then could not
start at all. The fix was switching the host to iptables-legacy. The likely
trigger: netfilter-persistent had been disabled shortly before, so the first
writer of the nft tables at boot was no longer Debian's 1.8.2.

Facts come from one fixed probe (probe.COMMANDS["k3s"]); this module only
judges. The rule it encodes: on a k3s host, iptables must be ONE backend, and
on Debian 10 that backend must be legacy. The nft backend at 1.8.2 alongside
k3s is a boot race waiting for the next reboot.

Threats:
  - Protects against: rebooting (or disabling netfilter-persistent on) a k3s
    host whose iptables state will not survive the boot; a crash-looping k3s
    going unnoticed (thousands of restarts with nothing alerting); a
    stopped-but-enabled k3s that will auto-start unsupervised at the next boot.
  - Does NOT protect against: other k3s failure modes (etcd, disk, certs).
    This checks the iptables/k3s interaction and basic liveness only.
"""
import re

CRITICAL, HIGH, MEDIUM, INFO = "CRITICAL", "HIGH", "MEDIUM", "INFO"
FAILING = (CRITICAL, HIGH)
SECTION_RE = re.compile(r"^@@@([a-z0-9_]+)$")
CRASHLOOP_RESTARTS = 5


def sections(stdout):
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


def _int(text, default=0):
    m = re.search(r"-?\d+", text or "")
    return int(m.group(0)) if m else default


def _props(text):
    return dict(line.split("=", 1) for line in (text or "").splitlines() if "=" in line)


def _f(sev, kind, detail, remedy=""):
    return {"severity": sev, "kind": kind, "detail": detail, "remedy": remedy}


def facts(stdout):
    s = sections(stdout)
    unit = _props(s.get("unit"))
    alts = [ln.strip() for ln in s.get("alternatives", "").splitlines() if ln.strip()]
    version = s.get("version", "").strip()
    backend = ("legacy" if "(legacy)" in version else "nft" if "(nf_tables)" in version
               else "unknown")
    return {
        "k3s": s.get("present", "").strip() == "yes",
        "backend": backend,
        "iptables_version": (re.search(r"v(\d+\.\d+\.\d+)", version) or [None, ""])[1],
        "alternatives": alts,
        "legacy_rules": _int(s.get("legacy_rules")),
        "nft_rules": _int(s.get("nft_rules")),
        "active": unit.get("ActiveState", ""),
        "substate": unit.get("SubState", ""),
        "enabled": unit.get("UnitFileState", ""),
        "restarts": _int(unit.get("NRestarts")),
        "panics": _int(s.get("panics")),
        "last_panic": s.get("last_panic", "").strip(),
        "docker": (s.get("docker", "").strip().splitlines() or [""])[0],
        "docker_enabled": (s.get("docker", "").strip().splitlines() + ["", ""])[1],
        "netfilter": (s.get("netfilter", "").strip().splitlines() or ["absent"])[0],
        "config": s.get("config", "").strip(),
        "nodes": s.get("nodes", ""),
        "pods_bad": s.get("pods_bad", ""),
        "uptime_s": _int(s.get("uptime")),
    }


def audit(stdout):
    """(findings, facts) for one host."""
    f = facts(stdout)
    out = []
    mixed = f["legacy_rules"] > 0 and f["nft_rules"] > 0

    # Backend hazards apply to any Docker/k3s host; they are sharpest with k3s.
    if mixed:
        out.append(_f(HIGH, "mixed-backends",
                      "%d legacy and %d nft iptables rules are BOTH live: two rule sets "
                      "filter and NAT the same traffic, and whichever tool is not on the "
                      "host backend no longer sees the other's rules"
                      % (f["legacy_rules"], f["nft_rules"]),
                      "clear the stale backend's rules in a reviewed window (after a "
                      "reboot the kernel starts empty; the host backend repopulates)"))
    if f["k3s"]:
        if f["backend"] == "nft" and f["iptables_version"].startswith("1.8.2"):
            out.append(_f(HIGH, "k3s-nft-boot-race",
                          "k3s on iptables-nft 1.8.2: at boot, whichever iptables writes "
                          "the nft tables first decides whether Debian's 1.8.2 can use them. "
                          "This is a known outage shape (kube-router panic loop, Docker "
                          "unable to start)",
                          "switch the host to iptables-legacy (update-alternatives) before "
                          "the next reboot"))
        if "prefer-bundled-bin: true" in f["config"] and f["backend"] == "legacy":
            out.append(_f(HIGH, "k3s-bundled-vs-host",
                          "k3s prefers its bundled iptables while the host (and Docker) use "
                          "legacy: two writers, two backends",
                          "drop prefer-bundled-bin, or align the host"))
        if f["active"] in ("activating", "active") and f["restarts"] > CRASHLOOP_RESTARTS:
            out.append(_f(CRITICAL, "k3s-crashloop",
                          "k3s restarted %d times this boot (%d panics)%s"
                          % (f["restarts"], f["panics"],
                             ": " + f["last_panic"][-200:] if f["last_panic"] else ""),
                          "stop k3s, fix the cause, start it under watch"))
        elif f["panics"] > 0 and f["active"] == "active":
            out.append(_f(MEDIUM, "k3s-panics",
                          "%d panic(s) in k3s's journal this boot" % f["panics"]))
        if f["active"] not in ("active", "activating") and f["enabled"] == "enabled":
            out.append(_f(HIGH, "k3s-stopped-but-enabled",
                          "k3s is %s but enabled: it will auto-start, unsupervised, at the "
                          "next boot%s" % (f["active"] or "not running",
                                          " (it stopped after %d restarts)" % f["restarts"]
                                          if f["restarts"] else ""),
                          "start it under watch now, or disable it until it is fixed"))
        if f["active"] == "active":
            nodes = [ln for ln in f["nodes"].splitlines() if ln.strip() and not ln.startswith("E")]
            if not nodes or any(" NotReady " in " %s " % ln for ln in nodes) or \
                    "refused" in f["nodes"]:
                out.append(_f(CRITICAL, "k3s-api-or-node-down",
                              "k3s is active but the API or node is not Ready: %s"
                              % (f["nodes"].strip().splitlines() or ["no output"])[-1][:160]))
            crash = [ln.split()[:2] for ln in f["pods_bad"].splitlines()
                     if "CrashLoopBackOff" in ln or "Error" in ln or "ImagePullBackOff" in ln]
            if crash:
                out.append(_f(MEDIUM, "pods-crashlooping",
                              "%d pod(s) failing: %s" % (len(crash), ", ".join(
                                  "%s/%s" % tuple(c) for c in crash[:8] if len(c) == 2))))
    # Only a Docker that is installed and meant to run counts as down.
    if f["docker"] == "failed" or (f["docker"] == "inactive" and f["docker_enabled"] == "enabled"):
        out.append(_f(HIGH, "docker-down", "docker.service is %s" % f["docker"],
                      "journalctl -u docker -b for the iptables error"))
    return out, f


def reboot_safe(findings):
    """A host is reboot-safe when nothing about iptables/k3s will break at boot."""
    blocking = {"k3s-nft-boot-race", "mixed-backends", "k3s-bundled-vs-host",
                "k3s-crashloop", "k3s-stopped-but-enabled"}
    return not any(f["kind"] in blocking for f in findings)


def render(host, findings, f):
    lines = ["── %s ──" % host]
    if f:
        lines.append("   k3s: %s   iptables: %s %s (legacy %d / nft %d rules)   "
                     "docker: %s   netfilter-persistent: %s   REBOOT-SAFE: %s"
                     % ("%s/%s, %d restarts" % (f["active"] or "-", f["enabled"] or "-",
                                                f["restarts"]) if f["k3s"] else "absent",
                        f["backend"], f["iptables_version"], f["legacy_rules"],
                        f["nft_rules"], f["docker"] or "-", f["netfilter"],
                        "yes" if reboot_safe(findings) else "NO"))
    if not findings:
        lines.append("   ok — no findings")
    order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3}
    for x in sorted(findings, key=lambda x: order[x["severity"]]):
        lines.append("   %-8s %-26s %s" % (x["severity"], x["kind"], x["detail"]))
        if x["remedy"] and x["severity"] != INFO:
            lines.append("   %-8s %-26s → %s" % ("", "", x["remedy"]))
    return "\n".join(lines)
