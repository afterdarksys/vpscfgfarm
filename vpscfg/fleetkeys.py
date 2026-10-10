"""SSH access verification — key hygiene is inventory hygiene.

~/.ssh/config is the fleet's host registry, and it can lie: two stanzas can
point at a key neither host accepts for weeks, and nobody knows until a probe
happens to try. This module makes that discovery a scheduled fact
instead of an accident: every alias is dialed with a no-op, results are
grouped per machine, and three shapes are flagged loudly — an alias whose
declared stanza fails, aliases of ONE machine that disagree (the alias
name-order trap), and governed hosts with no working path at all.

Threats:
  - Protects against: silent key rot (the config says id_rsa, the host says
    no); the two-names-one-machine trap where name order silently decides
    which key is offered; governed hosts drifting out of ssh reach without
    anyone noticing ("can't inventory it" means "can't protect it").
  - Does NOT protect against: a host that accepts the key but is otherwise
    compromised (this proves reachability, not integrity); keys that work
    but SHOULDN'T (that census is fleet authkeys: hashes of lines, and an
    empty allowlist stays UNPINNED); password or agent-forwarded access
    outside BatchMode's world.
"""
import subprocess

from . import journal, sshconfig

# The no-op. BatchMode forbids password prompts, so the result is a pure
# public-key answer; `true` executes nothing worth executing.
_SSH_ARGS = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]


def _dial(alias):
    """rc 0 = key accepted. Anything else = no non-interactive path."""
    r = subprocess.run(_SSH_ARGS + [alias, "true"],
                       capture_output=True, text=True, timeout=30)
    detail = (r.stderr or "").strip().splitlines()
    return {"alias": alias, "ok": r.returncode == 0,
            "detail": detail[-1][:120] if detail and r.returncode != 0 else ""}


def survey(dialer=None, machines=None):
    """Dial every alias of every machine. Returns per-machine results:
    [{"target", "aliases": [dial results], "reachable", "disagree"}]."""
    dialer = dialer or _dial
    machines = machines if machines is not None else sshconfig.machines()
    out = []
    for target, rec in sorted(machines.items()):
        dials = [dialer(a) for a in sorted(rec["aliases"])]
        oks = [d for d in dials if d["ok"]]
        out.append({
            "target": target,
            "aliases": dials,
            "reachable": bool(oks),
            # One machine, several names, different answers: whichever name an
            # operator (or a group expansion) picks silently decides the key.
            "disagree": bool(oks) and len(oks) != len(dials),
        })
    return out


def governor_gaps(results, governed_hosts):
    """Governed hosts that no surveyed machine answers for — the fleet the
    doors claim to guard but cannot currently reach."""
    answering = set()
    for m in results:
        for d in m["aliases"]:
            if d["ok"]:
                answering.add(d["alias"])
    gaps = []
    for name, cfg in sorted(governed_hosts.items()):
        if cfg.get("alias_of"):
            continue  # aliases are judged under their canonical name
        aliases = {name} | {a for a, c in governed_hosts.items()
                            if c.get("alias_of") == name}
        if not aliases & answering:
            gaps.append(name)
    return gaps


def render(results, gaps):
    lines = ["FLEET KEYS — every alias dialed, BatchMode (key-only):"]
    problems = 0
    for m in results:
        for d in m["aliases"]:
            mark = "ok " if d["ok"] else "DENIED"
            lines.append("  %-6s %-26s %s" % (mark, d["alias"], d["detail"]))
        if m["disagree"]:
            problems += 1
            lines.append("  !! %s: aliases of ONE machine disagree — name order "
                         "is silently picking the key; fix the stanza(s)" % m["target"])
        if not m["reachable"]:
            problems += 1
            lines.append("  !! %s: NO working alias — this machine cannot be "
                         "inventoried or protected" % m["target"])
    for name in gaps:
        problems += 1
        lines.append("  !! governed host %r answers on no surveyed alias — the "
                     "governor guards a door to nowhere" % name)
    lines.append("fleet keys: %d machine(s), %d problem(s)" % (len(results), problems))
    return "\n".join(lines), problems


def run(dialer=None, governed_hosts=None):
    results = survey(dialer=dialer)
    gaps = governor_gaps(results, governed_hosts or {})
    text, problems = render(results, gaps)
    journal.append("keys", {
        "event": "key_survey",
        "machines": len(results),
        "problems": problems,
        "unreachable": [m["target"] for m in results if not m["reachable"]],
        "disagreeing": [m["target"] for m in results if m["disagree"]],
        "governor_gaps": gaps,
    })
    return text, problems
