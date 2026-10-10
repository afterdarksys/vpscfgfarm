"""Host-wide unhealthy and restarting duration. No contract required.

Threats:
  - Protects against: a crash loop that fleet watch misses because the
    workload has no verify block. One fixed probe, judged locally.
  - Does NOT protect against: a healthcheck interval wildly different from
    30s (FailingStreak is scaled by that assumption). A contract may tighten
    unhealthy_max. It cannot raise it, and it cannot be the only signal.
"""
import re
from datetime import datetime, timezone

from .gates import Refused

DEFAULT_MAX = 600
RESTART_FLOOR = 5
ASSUMED_INTERVAL = 30
_DURATION = re.compile(r"\A([0-9]+)(s|m|h)\Z")
WAITING_BAD = frozenset([
    "CrashLoopBackOff", "Error", "ImagePullBackOff", "ErrImagePull",
    "CreateContainerError", "RunContainerError", "OOMKilled",
    "StartError", "ContainerCannotRun",
])


def parse_duration(value):
    match = _DURATION.fullmatch(str(value or ""))
    if not match:
        raise Refused("duration must look like 90s, 10m, or 1h")
    seconds = int(match.group(1))
    unit = match.group(2)
    if unit == "m":
        seconds *= 60
    elif unit == "h":
        seconds *= 3600
    if not 1 <= seconds <= 86400:
        raise Refused("duration must be between 1s and 24h")
    return seconds


def validate_watch(contract):
    block = contract.get("watch")
    if block is None:
        return
    if not isinstance(block, dict) or set(block) != {"unhealthy_max"}:
        raise Refused("watch accepts only unhealthy_max")
    seconds = parse_duration(block.get("unhealthy_max"))
    if seconds > DEFAULT_MAX:
        raise Refused(
            "watch.unhealthy_max cannot loosen the fleet maximum of %ds" % DEFAULT_MAX)


def parse_time(text):
    raw = (text or "").strip()
    if not raw or raw.startswith("0001-01-01"):
        return None
    raw = raw.replace("Z", "+00:00")
    if "." in raw:
        head, rest = raw.split(".", 1)
        frac = rest
        tz = ""
        for index, char in enumerate(rest):
            if char in "+-":
                frac = rest[:index]
                tz = rest[index:]
                break
        raw = "%s.%s%s" % (head, (frac + "000000")[:6], tz)
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _age(started, now):
    if started is None:
        return None
    return (now - started).total_seconds()


def parse_docker(text):
    if (text or "").strip() == "NO_DOCKER":
        return []
    rows = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            raise Refused("health probe line is short")
        try:
            restarts = int(parts[4])
            streak = int(parts[5])
        except ValueError:
            raise Refused("health probe counts are not integers")
        rows.append({
            "kind": "container",
            "name": parts[0].lstrip("/"),
            "status": parts[1],
            "health": parts[2],
            "started": parse_time(parts[3]),
            "restarts": restarts,
            "streak": streak,
        })
    return rows


def parse_pods(text):
    body = (text or "").strip()
    if body == "NO_K3S":
        return [], None
    if not body:
        return [], "pod probe produced nothing"
    rows = []
    for line in body.splitlines():
        if not line.strip():
            continue
        lowered = line.lower()
        if lowered.startswith("error") or "unable to connect" in lowered:
            return [], line.strip()[:200]
        parts = line.split()
        if len(parts) < 6:
            return [], "pod health line is short"
        namespace, name, phase, waiting, restarts, started = parts[:6]
        if waiting == "<none>":
            waiting = ""
        try:
            restart_count = int(str(restarts).split(",")[0])
        except ValueError:
            restart_count = 0
        rows.append({
            "kind": "pod",
            "name": "%s/%s" % (namespace, name),
            "status": phase,
            "health": waiting or phase,
            "started": parse_time(started),
            "restarts": restart_count,
            "streak": 0,
            "waiting": waiting,
        })
    return rows, None


def watches_from(contracts, names_of):
    """Ceilings a contract may tighten. No watch block means the fleet default."""
    found = []
    for contract in contracts or []:
        if not isinstance(contract, dict):
            continue
        block = contract.get("watch")
        if not isinstance(block, dict):
            continue
        found.append({
            "names": set(names_of(contract)),
            "unhealthy_max": parse_duration(block.get("unhealthy_max")),
        })
    return found


def limit_for(name, watches, default=DEFAULT_MAX):
    """Smallest declared ceiling for this workload. Larger values do not apply."""
    best = default
    for watch in watches or []:
        if name not in watch.get("names", ()):
            continue
        seconds = watch.get("unhealthy_max", default)
        if seconds < best:
            best = seconds
    return best


def _alarm(row, now, limit):
    age = _age(row["started"], now)
    status = row["status"]
    health = row["health"]
    bad = (
        status == "restarting"
        or health == "unhealthy"
        or row.get("waiting") in WAITING_BAD
        or status in WAITING_BAD
    )
    if not bad and row["restarts"] < RESTART_FLOOR:
        return None
    endured = False
    if row["restarts"] >= RESTART_FLOOR:
        endured = True
    if row["streak"] * ASSUMED_INTERVAL >= limit:
        endured = True
    if age is not None and age >= limit and bad:
        endured = True
    if bad and age is None and row["restarts"] >= RESTART_FLOOR:
        endured = True
    if not endured:
        return None
    return {
        "name": row["name"],
        "kind": row["kind"],
        "detail": "%s health=%s restarts=%d age=%s limit=%ds" % (
            status, health, row["restarts"],
            "unknown" if age is None else "%ds" % int(age), limit),
    }


def judge(docker_rows, pod_rows, now, watches=None, pod_error=None, default=DEFAULT_MAX):
    findings = []
    if pod_error:
        findings.append({"name": "pods", "kind": "probe", "detail": "UNVERIFIED %s" % pod_error})
    for row in list(docker_rows or []) + list(pod_rows or []):
        limit = limit_for(row["name"], watches, default)
        found = _alarm(row, now, limit)
        if found:
            findings.append(found)
    return {"ok": not findings, "findings": findings}


def render(host, report):
    lines = ["health %s: %s (%d)" % (
        host, "OK" if report["ok"] else "FAIL", len(report["findings"]))]
    for item in report["findings"]:
        lines.append("  !! %-10s %s  %s" % (item["kind"], item["name"], item["detail"]))
    return "\n".join(lines)
