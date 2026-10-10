"""Postgres topology lint. Shape only. No guessed primary, no SQL.

Threats:
  - Protects against: calling replication "done" when the contracts do not
    name exactly one primary and replicas that point at it, each replica
    carrying a pg_replication verify. Fewer than two declared copies is
    UNPINNED, not healthy.
  - Does NOT protect against: a declaration that names the wrong host.
    This module does not connect to Postgres and does not write contracts.
"""
import re

from .gates import Refused

NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
ROLES = frozenset(["primary", "replica"])


def validate(contract):
    block = contract.get("postgres")
    if block is None:
        return
    if not isinstance(block, dict):
        raise Refused("postgres must be a mapping")
    allowed = {"role", "replicates", "container"}
    if set(block) - allowed or "role" not in block:
        raise Refused("postgres accepts role, replicates, and container")
    if block.get("role") not in ROLES:
        raise Refused("postgres.role must be primary or replica")
    if block["role"] == "primary" and "replicates" in block:
        raise Refused("postgres primary does not set replicates")
    if block["role"] == "replica":
        target = block.get("replicates")
        if not isinstance(target, str) or not NAME_RE.fullmatch(target):
            raise Refused("postgres replica requires replicates: <service>")
    container = block.get("container")
    if container is not None and (not isinstance(container, str) or not NAME_RE.fullmatch(container)):
        raise Refused("postgres.container must be a container name")


def _has_pg_check(contract):
    for check in contract.get("verify") or []:
        if isinstance(check, dict) and "pg_replication" in check:
            return True
    return False


def judge(contracts):
    marked = [c for c in contracts if isinstance(c.get("postgres"), dict)]
    if len(marked) < 2:
        return {
            "ok": False,
            "state": "UNPINNED",
            "detail": "fewer than two contracts declare postgres; this read "
                      "does not guess a primary",
            "copies": [c.get("service") for c in marked],
        }
    primaries = [c for c in marked if c["postgres"].get("role") == "primary"]
    replicas = [c for c in marked if c["postgres"].get("role") == "replica"]
    if len(primaries) != 1 or len(primaries) + len(replicas) != len(marked):
        return {
            "ok": False,
            "state": "UNPINNED",
            "detail": "topology needs exactly one primary and every other copy a replica",
            "copies": [c.get("service") for c in marked],
        }
    primary = primaries[0]["service"]
    for replica in replicas:
        if replica["postgres"].get("replicates") != primary:
            return {
                "ok": False,
                "state": "UNPINNED",
                "detail": "%s does not replicate %s" % (replica.get("service"), primary),
                "copies": [c.get("service") for c in marked],
            }
        if not _has_pg_check(replica):
            return {
                "ok": False,
                "state": "UNPINNED",
                "detail": "%s has no pg_replication verify" % replica.get("service"),
                "copies": [c.get("service") for c in marked],
            }
    return {
        "ok": True,
        "state": "declared",
        "detail": "one primary (%s) and %d replica(s) with pg_replication" % (
            primary, len(replicas)),
        "copies": [c.get("service") for c in marked],
    }


def render(report):
    mark = "ok" if report["ok"] else "!!"
    return "%s postgres topology: %s — %s" % (mark, report["state"], report["detail"])
