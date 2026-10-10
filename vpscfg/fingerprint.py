"""Unjournaled-change detector — the check that defends the platform's thesis.

Every mutation is supposed to pass through a door and land in the journal.
Nothing verified that claim until now. This module fingerprints each host's
observed container state (image IDs, created timestamps) and k3s pod state
(uids, spec images), stores the baseline in inventory/fingerprints/, and on
the next sweep reports every change that
has NO covering mutation entry in the journal — which is what Watchtower,
a hotfix over raw ssh, and an intruder all look like.

Threats:
  - Protects against: deploys that bypass both doors (Watchtower's :latest
    auto-pulls, `docker cp` hotfixes, raw-ssh compose runs, malicious
    container replacement) going unnoticed; refused/read journal entries
    being mistaken for coverage (only executed-mutation events cover).
  - Does NOT protect against: changes inside a container that alter neither
    image nor created-time (a `docker cp` into a running container is
    invisible here — drift's file hashing is the tool for that; likewise a
    `kubectl cp` into a running pod alters neither uid nor spec image); an attacker
    who also forges journal entries (the hash chain raises the bar); changes
    that happen and fully revert between sweeps.
"""
import json
import time
from pathlib import Path

from . import estate, journal, probe
from .gates import Refused

BASELINE_DIR = estate.root() / "inventory" / "fingerprints"

# Journal events that mean "a mutation actually ran here". `read` and
# `refused` NEVER cover a change — a refusal is proof the door was tried,
# not that the change was authorized.
COVERING_EVENTS = frozenset([
    "mutation_attempt", "mutation_complete", "step", "deploy_failed_rolled_back",
])


def snapshot(host, prober=None):
    """Observed container state: {name: {image, status, created}}.

    The probe command is fixed and read-only (docker ps + inspect). A host
    without docker yields {} — a valid, comparable observation.
    """
    prober = prober or probe.run
    res = prober(host, "fingerprint")
    if res["rc"] != 0 and not res["stdout"].strip():
        raise Refused("fingerprint probe failed on %s: %s"
                      % (host, (res["stderr"] or "no output").strip()[:200]))
    out = {}
    for line in res["stdout"].splitlines():
        line = line.strip()
        if not line or line == "NO_DOCKER":
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        name, image, status, created = parts
        out[name.lstrip("/")] = {"image": image, "status": status,
                                 "created": created}
    return out


def snapshot_pods(host, prober=None):
    """Observed k3s pod state: {"ns/name": {uid, created, images}}.

    NO_K3S (no k3s binary) is a valid, comparable empty observation. A host
    WITH k3s whose kubectl fails raises instead — an unverifiable overlay
    must never read as an empty one.
    """
    prober = prober or probe.run
    res = prober(host, "fingerprint_pods")
    if res["rc"] != 0 and not res["stdout"].strip():
        raise Refused("pod fingerprint probe failed on %s: %s"
                      % (host, (res["stderr"] or "no output").strip()[:200]))
    out = {}
    for line in res["stdout"].splitlines():
        line = line.strip()
        if not line or line == "NO_K3S":
            continue
        parts = line.split()
        if len(parts) != 5:
            continue
        ns, name, uid, created, images = parts
        out["%s/%s" % (ns, name)] = {"uid": uid, "created": created,
                                     "images": images}
    return out


def diff_pods(base_pods, current):
    """What changed since the pod baseline, as [(ns/name, kind, detail)]."""
    changes = []
    for key in sorted(set(base_pods) | set(current)):
        b, c = base_pods.get(key), current.get(key)
        if b and not c:
            changes.append((key, "removed", "was %s" % b["images"][:40]))
        elif c and not b:
            changes.append((key, "added", "images %s" % c["images"][:40]))
        elif b["images"] != c["images"]:
            changes.append((key, "image_changed",
                            "%s -> %s" % (b["images"][:28], c["images"][:28])))
        elif b["uid"] != c["uid"]:
            changes.append((key, "recreated",
                            "same images, new pod (created %s)" % c["created"]))
    return changes


def _baseline_path(host):
    if not probe.HOST_RE.match(host or ""):
        raise Refused("invalid host name %r" % host)
    return BASELINE_DIR / ("%s.json" % host)


def save_baseline(host, snap, now=None, pods=None):
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    doc = {"host": host, "ts": now or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "containers": snap}
    # pods=None means "not probed" and the key is omitted — report() treats a
    # missing key differently from an observed-empty overlay ({}).
    if pods is not None:
        doc["pods"] = pods
    _baseline_path(host).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    entry = {"event": "baseline", "host": host, "containers": len(snap)}
    if pods is not None:
        entry["pods"] = len(pods)
    journal.append("fingerprint", entry)
    return doc


def load_baseline(host):
    path = _baseline_path(host)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def baselined_hosts():
    if not BASELINE_DIR.is_dir():
        return []
    return sorted(p.stem for p in BASELINE_DIR.glob("*.json"))


def diff(base_containers, current):
    """What changed since the baseline, as [(container, kind, detail)]."""
    changes = []
    for name in sorted(set(base_containers) | set(current)):
        b, c = base_containers.get(name), current.get(name)
        if b and not c:
            changes.append((name, "removed", "was %s" % b["image"][:19]))
        elif c and not b:
            changes.append((name, "added", "image %s" % c["image"][:19]))
        elif b["image"] != c["image"]:
            changes.append((name, "image_changed",
                            "%s -> %s" % (b["image"][:19], c["image"][:19])))
        elif b["created"] != c["created"]:
            changes.append((name, "recreated",
                            "same image, new container (created %s)" % c["created"]))
    return changes


def _parse_ts(ts):
    """Journal timestamp -> epoch seconds, or None if unparseable.
    Unparseable timestamps must never grant coverage — fail closed."""
    for fmt in ("%Y-%m-%dT%H:%M:%S%z",):
        try:
            return time.mktime(time.strptime(ts, fmt))
        except (ValueError, TypeError):
            continue
    return None


def mutations_since(host, since_epoch, aliases=(), journal_dir=None):
    """Executed-mutation journal entries touching `host` after the baseline.

    Aliases collapse before matching (relay2 and relay2.example.net are one
    machine). Entries whose timestamp cannot be parsed do NOT count.
    """
    names = {host} | set(aliases or ())
    hits = []
    jdir = Path(journal_dir or journal.JOURNAL_DIR)
    for stream in ("executor", "vpsexec"):
        path = jdir / ("%s.jsonl" % stream)
        if not path.exists():
            continue
        for raw in path.read_text().splitlines():
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if rec.get("event") not in COVERING_EVENTS:
                continue
            when = _parse_ts(rec.get("ts", ""))
            if when is None or when < since_epoch:
                continue
            touched = set()
            if rec.get("host"):
                touched.add(rec["host"])
            for h in rec.get("hosts") or []:
                touched.add(h)
            if touched & names:
                hits.append(rec)
    return hits


def report(host, current, aliases=(), current_pods=None):
    """Compare live state to baseline; split changes into covered/uncovered."""
    base = load_baseline(host)
    if base is None:
        raise Refused("no baseline for %s — run `vpscfg fleet baseline` first" % host)
    changes = diff(base.get("containers", {}), current)
    pod_changes = []
    if current_pods is not None:
        base_pods = base.get("pods")
        if base_pods is None:
            # Baseline predates pod fingerprinting. Live pods with no pod
            # baseline is an UNVERIFIABLE overlay — one flagged line (not N
            # fake "added" lines) that still counts as a change, so the sweep
            # exits non-zero until the host is re-baselined. Fail closed.
            if current_pods:
                pod_changes = [("(pods)", "unbaselined",
                                "%d live pod(s) but baseline predates pod "
                                "fingerprinting — run `vpscfg fleet baseline "
                                "%s`" % (len(current_pods), host))]
        else:
            pod_changes = diff_pods(base_pods, current_pods)
    since = _parse_ts(base.get("ts", ""))
    if since is None:
        # A baseline whose timestamp cannot be read gives the journal no
        # window to search: treat every change as uncovered. Fail closed.
        covered = []
    else:
        covered = mutations_since(host, since, aliases=aliases)
    all_changes = changes + pod_changes
    return {
        "host": host,
        "baseline_ts": base.get("ts"),
        "changes": changes,
        "pod_changes": pod_changes,
        "covering_entries": len(covered),
        # Host-level coverage: SOME journaled mutation on this host since the
        # baseline. Per-container attribution would be guesswork with today's
        # journal shape; a host with zero journaled mutations and ANY observed
        # change is the unambiguous alarm this tool exists to raise.
        "uncovered": all_changes if not covered else [],
    }


def render(rep):
    lines = ["CHANGES %s (baseline %s):" % (rep["host"], rep["baseline_ts"])]
    listed = rep["changes"] + rep.get("pod_changes", [])
    if not listed:
        lines.append("  none — live state matches baseline")
        return "\n".join(lines)
    for name, kind, detail in listed:
        lines.append("  %-13s %-28s %s" % (kind, name, detail))
    if rep["uncovered"]:
        lines.append("  !! UNJOURNALED: %d change(s), ZERO journaled mutations on "
                     "this host since baseline — someone or something bypassed "
                     "the doors" % len(rep["uncovered"]))
    else:
        lines.append("  journal shows %d mutation entr(ies) since baseline — "
                     "changes are accounted for" % rep["covering_entries"])
    return "\n".join(lines)
