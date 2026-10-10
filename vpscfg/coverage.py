"""Join live containers and pods to contracts and skeletons.

Threats:
  - Protects against: a running workload that fleet watch cannot see, because
    fleet watch only runs verify blocks on promoted contracts. Skeletons count
    as coverage so a named-but-unpromoted service is not shouted as unknown.
  - Does NOT protect against: a probe that lies, or a name collision that
    makes an unrelated container look covered. This read reports. It does not
    stop, delete, or promote anything. Frozen namespaces (kube-*, cert-manager)
    are excluded here on purpose; host health is a different read.
"""
import re
from pathlib import Path

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False

from .gates import Refused

# Pods the estate has frozen forever. They are not missing contracts.
SKIP_NAMESPACES = frozenset([
    "kube-system", "kube-public", "kube-node-lease", "cert-manager",
])
_HASH_PART = re.compile(r"^[a-z0-9]{5,10}$")


def pod_owner(name):
    """Deployment name for a ReplicaSet pod, or the pod name itself."""
    parts = (name or "").split("-")
    if (len(parts) >= 3 and _HASH_PART.fullmatch(parts[-1])
            and _HASH_PART.fullmatch(parts[-2])):
        return "-".join(parts[:-2])
    return name


def _names_from(doc):
    names = set()
    service = doc.get("service")
    if isinstance(service, str) and service:
        names.add(service)
    for check in doc.get("verify") or []:
        if isinstance(check, dict):
            spec = check.get("container")
            if isinstance(spec, dict) and isinstance(spec.get("name"), str):
                names.add(spec["name"])
    k3s = doc.get("k3s") if isinstance(doc.get("k3s"), dict) else {}
    namespace = k3s.get("namespace") if isinstance(k3s.get("namespace"), str) else None
    deployments = []
    for item in k3s.get("deployments") or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            deployments.append(item["name"])
            names.add(item["name"])
    apply = doc.get("apply") if isinstance(doc.get("apply"), dict) else {}
    if isinstance(apply.get("deployment"), str):
        deployments.append(apply["deployment"])
        names.add(apply["deployment"])
        if isinstance(apply.get("namespace"), str):
            namespace = apply["namespace"]
    return names, namespace, deployments


def _declaration(path, kind):
    if not _HAVE_YAML:
        raise Refused("PyYAML is unavailable — failing closed, not guessing coverage")
    with open(path) as handle:
        doc = yaml.safe_load(handle)
    if not isinstance(doc, dict):
        raise Refused("coverage source %s is not a mapping" % path)
    host = doc.get("host")
    service = doc.get("service")
    if not isinstance(host, str) or not isinstance(service, str):
        raise Refused("coverage source %s needs host and service" % path)
    names, namespace, deployments = _names_from(doc)
    return {
        "kind": kind,
        "path": str(path),
        "service": service,
        "host": host,
        "names": names,
        "namespace": namespace,
        "deployments": deployments,
    }


def load_index(contract_dir):
    """Promoted contracts plus skeletons. A broken file fails the read."""
    root = Path(contract_dir)
    found = []
    for path in sorted(root.glob("*.y*ml")):
        found.append(_declaration(path, "contract"))
    skeletons = root / "skeletons"
    if skeletons.is_dir():
        for path in sorted(skeletons.glob("*.y*ml")):
            found.append(_declaration(path, "skeleton"))
    return found


def _running_container(status):
    status = status or ""
    return status.startswith("Up") or status.startswith("Restarting")


def parse_containers(text):
    if (text or "").strip() == "NO_DOCKER":
        return []
    rows = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            raise Refused("container probe line is not name, image, status")
        name = parts[0].lstrip("/")
        rows.append({
            "name": name,
            "image": parts[1],
            "status": parts[2],
            "running": _running_container(parts[2]),
        })
    return rows


def parse_pods(text):
    """Return (rows, error). error set means the pod list is untrustworthy."""
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
        if len(parts) < 5:
            return [], "pod probe line is short: %s" % line.strip()[:120]
        namespace, name, phase, waiting, restarts = parts[:5]
        images = parts[5] if len(parts) > 5 else ""
        if waiting == "<none>":
            waiting = ""
        try:
            restart_count = int(str(restarts).split(",")[0])
        except ValueError:
            restart_count = 0
        running = phase not in ("Succeeded", "Completed")
        rows.append({
            "namespace": namespace,
            "name": name,
            "owner": pod_owner(name),
            "phase": phase,
            "waiting": waiting,
            "restarts": restart_count,
            "image": images.split(",")[0],
            "running": running,
        })
    return rows, None


def _covers_container(decls, aliases, name):
    for decl in decls:
        if decl["host"] in aliases and name in decl["names"]:
            return decl
    return None


def names_of(doc):
    """Workload names a declaration covers: service, container, deployment."""
    names, _namespace, _deployments = _names_from(doc or {})
    return names


def _covers_pod(decls, aliases, pod):
    if pod["namespace"] in SKIP_NAMESPACES:
        return "skipped"
    for decl in decls:
        if decl["host"] not in aliases:
            continue
        hit = (pod["owner"] in decl["deployments"]
               or pod["name"] in decl["names"]
               or pod["owner"] in decl["names"])
        if not hit:
            continue
        if decl["namespace"] and decl["namespace"] != pod["namespace"]:
            continue
        return decl
    return None


def judge(host, aliases, containers, pods, decls, pod_error=None):
    """Pure coverage judgment for one host.

    `aliases` includes the canonical name. A running workload with no
    contract and no skeleton is uncovered. A host whose every running
    workload is uncovered is bare. Exit-worthy when `ok` is false.
    """
    aliases = set(aliases or [host])
    aliases.add(host)
    uncovered = []
    covered = 0
    running = 0
    if pod_error:
        uncovered.append({"kind": "pods", "name": "", "detail": "UNVERIFIED %s" % pod_error})
    for row in containers:
        if not row["running"]:
            continue
        running += 1
        if _covers_container(decls, aliases, row["name"]):
            covered += 1
        else:
            uncovered.append({
                "kind": "container", "name": row["name"],
                "detail": row["status"],
            })
    for pod in pods:
        if not pod["running"] or pod["namespace"] in SKIP_NAMESPACES:
            continue
        running += 1
        if _covers_pod(decls, aliases, pod):
            covered += 1
        else:
            uncovered.append({
                "kind": "pod",
                "name": "%s/%s" % (pod["namespace"], pod["name"]),
                "detail": pod["phase"],
            })
    declared = any(d["host"] in aliases for d in decls)
    bare = running > 0 and not declared
    return {
        "host": host,
        "running": running,
        "covered": covered,
        "uncovered": uncovered,
        "bare": bare,
        "ok": not uncovered and not bare,
    }


def render(report):
    lines = ["coverage %s: %d running, %d covered, %d uncovered%s" % (
        report["host"], report["running"], report["covered"],
        len(report["uncovered"]), "  BARE" if report["bare"] else "")]
    for item in report["uncovered"]:
        label = item["name"] or item["kind"]
        lines.append("  !! %-12s %s  %s" % (item["kind"], label, item["detail"]))
    return "\n".join(lines)
