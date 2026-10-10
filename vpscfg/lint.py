"""Contract lint — refuse-to-forget for contract quality.

A contract that loads is not a contract that protects: verify blocks with no
outside signal, leftover skeleton TODOs, and undeclared blast radius are how
"covered" quietly means "not covered". Read-only; never touches the network.

Threats:
  - Protects against: weak contracts passing silently into the mutation path.
  - Does NOT protect against: checks the lint doesn't know to make — it is a
    floor, not a review.
"""
from . import ports
from .contracts import CONTRACT_DIR, load
from .gates import Refused


def lint_contract(name, raw_text, contract):
    """Pure: returns list of (level, message). Levels: E (error), W (warning)."""
    findings = []
    if "TODO" in raw_text:
        findings.append(("W", "TODO markers remain — skeleton guesses not yet verified"))
    if not contract.get("repo"):
        findings.append(("E", "no repo field — drift and sync are both blind"))
    checks = contract.get("verify") or []
    if not any(isinstance(c, dict) and "http" in c for c in checks):
        findings.append(("W", "no http verify — an outside-visible failure "
                              "(a crashlooping backend) would go unseen"))
    if not checks:
        findings.append(("E", "verify block is empty — deploy would prove nothing"))
    # A monitor_only contract ships nothing, so the sync/build/blast checks below
    # do not apply — it is watched by the sweep, never applied. repo + a real
    # (ideally http) verify are still wanted, so those checks above stand.
    if contract.get("monitor_only") is True:
        return findings
    sync = contract.get("sync") or {}
    if not sync.get("include"):
        findings.append(("W", "sync.include is empty — deploys move no files"))
    br = contract.get("blast_radius") or {}
    if not br:
        findings.append(("W", "no blast_radius — sharing/volumes undeclared"))
    elif not br.get("volumes"):
        findings.append(("W", "blast_radius.volumes empty — run docker inspect and list them"))
    return findings


def run():
    names = sorted(p.stem for p in CONTRACT_DIR.glob("*.y*ml"))
    if not names:
        print("lint: no contracts in %s" % CONTRACT_DIR)
        return 0
    errors = warnings = 0
    loaded = {}
    for name in names:
        path = next(CONTRACT_DIR / (name + ext) for ext in (".yaml", ".yml")
                    if (CONTRACT_DIR / (name + ext)).exists())
        raw = path.read_text()
        try:
            contract = load(name)
        except Refused as r:
            print("E %-24s %s" % (name, r))
            errors += 1
            continue
        loaded[name] = contract
        for level, msg in lint_contract(name, raw, contract):
            print("%s %-24s %s" % (level, name, msg))
            if level == "E":
                errors += 1
            else:
                warnings += 1
    # Cross-contract pass: two contracts claiming one port is an error at
    # review time, not a surprise at deploy time (DESIGN.md item 9).
    for msg in ports.lint_collisions(loaded):
        print("E %-24s %s" % ("(cross)", msg))
        errors += 1
    skeletons = len(list((CONTRACT_DIR / "skeletons").glob("*.y*ml")))
    print("lint: %d contract(s), %d error(s), %d warning(s); %d skeleton(s) awaiting promotion"
          % (len(names), errors, warnings, skeletons))
    return 1 if errors else 0
