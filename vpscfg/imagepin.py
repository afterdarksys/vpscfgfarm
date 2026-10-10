"""Image tag versus a declared pin. Visibility, not a Watchtower killer.

Threats:
  - Protects against: a contracted workload moving to :latest (or any
    floating ref) without a digest, and a digest that no longer matches.
    Digests are compared in constant time.
  - Does NOT protect against: Watchtower itself. updates: watch records the
    floating tag and does not fail for that alone. Absent policy fails
    closed on a floating ref. This read never pulls, kills, or retags.
"""
import hmac
import re

from .gates import Refused

NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
DIGEST_RE = re.compile(r"sha256:[a-f0-9]{64}")
UPDATES = frozenset(["pinned", "watch"])


def validate(contract):
    block = contract.get("image_policy")
    if block is None:
        return
    if not isinstance(block, dict) or set(block) - {"updates", "pins"}:
        raise Refused("image_policy accepts updates and pins")
    if block.get("updates") not in UPDATES:
        raise Refused("image_policy.updates must be pinned or watch")
    pins = block.get("pins", [])
    if not isinstance(pins, list):
        raise Refused("image_policy.pins must be a list")
    for pin in pins:
        if not isinstance(pin, dict) or set(pin) - {"name", "digest"}:
            raise Refused("image pin accepts name and digest")
        if not isinstance(pin.get("name"), str) or not NAME_RE.fullmatch(pin["name"]):
            raise Refused("image pin name is invalid")
        digest = pin.get("digest")
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise Refused("image pin digest must be sha256:<64 hex>")


def floating(ref):
    text = (ref or "").strip()
    if not text or text == "<none>":
        return False
    if "@sha256:" in text:
        return False
    leaf = text.split("/")[-1]
    if ":" not in leaf:
        return True
    return leaf.rsplit(":", 1)[1] == "latest"


def _digest(ref):
    match = DIGEST_RE.search(ref or "")
    return match.group(0) if match else None


def _same_digest(live, want):
    if live is None or want is None:
        return False
    return hmac.compare_digest(live, want)


def policies_from(contracts, names_of):
    """names_of(contract) -> set of workload names that contract covers."""
    policies = []
    for contract in contracts:
        block = contract.get("image_policy")
        pins = {}
        if isinstance(block, dict):
            for pin in block.get("pins") or []:
                pins[pin["name"]] = pin["digest"]
            updates = block.get("updates", "pinned")
        else:
            updates = "pinned"
        policies.append({
            "service": contract.get("service"),
            "names": set(names_of(contract)),
            "updates": updates,
            "pins": pins,
            "declared": isinstance(block, dict),
        })
    return policies


def judge(rows, policies):
    """rows are {name, image}. Uncovered names are ignored (coverage's job)."""
    findings = []
    for row in rows:
        matched = [p for p in policies if row["name"] in p["names"]]
        if not matched:
            continue
        policy = matched[0]
        want = policy["pins"].get(row["name"])
        if want:
            if not _same_digest(_digest(row["image"]), want):
                findings.append({
                    "name": row["name"], "ok": False, "state": "MISMATCH",
                    "detail": "live digest does not match the pin",
                })
            continue
        if floating(row["image"]):
            if policy["updates"] == "watch":
                findings.append({
                    "name": row["name"], "ok": True, "state": "watch",
                    "detail": "floating ref acknowledged by updates: watch",
                })
            else:
                state = "UNPINNED" if not policy["declared"] else "FLOATING"
                findings.append({
                    "name": row["name"], "ok": False, "state": state,
                    "detail": row["image"],
                })
    bad = [item for item in findings if not item["ok"]]
    return {"ok": not bad, "findings": findings}


def render(report):
    lines = ["images: %s (%d findings)" % (
        "OK" if report["ok"] else "FAIL", len(report["findings"]))]
    for item in report["findings"]:
        mark = "ok" if item["ok"] else "!!"
        lines.append("  %s %-10s %s  %s" % (mark, item["state"], item["name"], item["detail"]))
    return "\n".join(lines)
