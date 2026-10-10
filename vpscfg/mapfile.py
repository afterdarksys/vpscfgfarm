"""`.vpscfgfarm.map` — a per-directory baseline for deploys, and a leash.

Drop one next to a repo's deploy.sh and two things happen. First, the
directory gains an identity: `vpscfg deploy` run from inside it knows the
service and host without either being typed (the map names the contract;
the contract names everything else). Second, the directory gains a leash:
`constraints:` tighten what vpsexec — and anything the doors spawn — may
run when invoked from here.

THE ONE RULE: a map is UNTRUSTED input. It sits in arbitrary repos, often
outside this repo's review, sometimes written by a compromised dependency
or a helpful intern. So a map may ROUTE (name a contract) and RESTRICT
(add deny patterns, cap the tier, narrow hosts, forbid flags) — and may
never GRANT. There is no key in this schema that loosens anything, the
parser refuses unknown keys outright (a typo'd constraint that silently
does nothing is a hole, not a convenience), and any key that even smells
like elevation refuses the whole file.

Routing is bound both ways: the map names a service, and that service's
contract must name a repo that CONTAINS the map's directory. A map pasted
into the wrong repo — or a malicious one pointing your deploy at somebody
else's contract — refuses instead of routing.

Schema (all of it):

    version: 1
    service: shop-web                  # optional — enables routing
    deploy:                            # optional, documentation of the baseline
      entry: ./deploy.sh
      host: web1.example.internal      # must equal the contract's host
    constraints:                       # optional, TIGHTENING ONLY
      deny_extra: ["docker build"]     # more deny patterns, absolute
      risky_extra: ["systemctl restart"]
      max_tier: read                   # read | mutating — never risky
      hosts_allow: [edge1]             # commands from here touch ONLY these
      forbid_flags: ["--force", "-f"]  # options children may not carry
      require_blackout: true           # mutations need an active window
      forbid_break_glass: true         # no elevation launches from here

Threats:
  - Protects against: deploys launched from the wrong directory landing on
    the wrong service (two-way binding); a map file granting anything
    (grant-shaped keys refuse the file; unknown keys refuse the file); a
    constraint silently not applying because of a typo (strict schema).
  - Does NOT protect against: an operator cd-ing OUT of the directory to
    escape the leash — maps constrain a place, not a person; committed
    policy in policies/ is the fleet-wide layer. Nor a map being deleted:
    absence of a map is absence of extra constraints, never an error.
"""
import re
from pathlib import Path

from .gates import Refused

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False

MAP_NAME = ".vpscfgfarm.map"

_TOP_KEYS = {"version", "service", "deploy", "constraints"}
_DEPLOY_KEYS = {"entry", "host"}
_CONSTRAINT_KEYS = {"deny_extra", "risky_extra", "max_tier", "hosts_allow",
                    "forbid_flags", "require_blackout", "forbid_break_glass"}

# Keys that would only ever appear in an attempt to make a map GRANT
# something. Found anywhere — any nesting, any spelling of the value — the
# whole file refuses. This list errs wide on purpose.
_ELEVATION_KEYS = {"break_glass", "posture", "postures", "unlocked", "scopes",
                   "allowed_verbs", "mutation_enabled", "deny_remove",
                   "risky_remove", "override", "overrides", "allow_extra",
                   "tested", "mode"}

_TIER_ORDER = {"read": 0, "mutating": 1, "risky": 2}
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_HOSTISH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$")

MAX_MAP_BYTES = 64 * 1024  # a map is a page of YAML; a megabyte is an attack


def find(start=None):
    """Nearest .vpscfgfarm.map walking up from `start` (default: CWD).
    Returns a Path or None. Nearest wins; maps do not merge — one directory,
    one authority, no action-at-a-distance from a parent you forgot about."""
    d = Path(start or Path.cwd()).resolve()
    for candidate in [d] + list(d.parents):
        p = candidate / MAP_NAME
        if p.is_file():
            return p
    return None


def _scan_elevation(node, path="map"):
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k) in _ELEVATION_KEYS:
                raise Refused(
                    "%s contains key %r — a map can only ROUTE and RESTRICT, "
                    "never grant. Refusing the whole file." % (path, k))
            _scan_elevation(v, "%s.%s" % (path, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _scan_elevation(v, "%s[%d]" % (path, i))


def _str_list(doc, section, key, item_re=None, want_prefix=None):
    vals = doc.get(key)
    if vals is None:
        return []
    if not isinstance(vals, list) or not all(
            isinstance(v, str) and v.strip() for v in vals):
        raise Refused("%s.%s must be a list of non-empty strings" % (section, key))
    for v in vals:
        if item_re and not item_re.match(v):
            raise Refused("%s.%s entry %r fails validation" % (section, key, v))
        if want_prefix and not v.startswith(want_prefix):
            raise Refused("%s.%s entry %r must start with %r"
                          % (section, key, v, want_prefix))
    return list(vals)


def load(path):
    """Parse and strictly validate one map file. Refuses on ANY deviation.
    Returns the normalized document (never None)."""
    path = Path(path)
    if not _HAVE_YAML:
        raise Refused("%s exists but PyYAML is unavailable — a constraint file "
                      "that cannot be read cannot be enforced; failing closed"
                      % path)
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise Refused("cannot read %s: %s" % (path, e))
    if len(raw) > MAX_MAP_BYTES:
        raise Refused("%s is %d bytes — a map is a page of YAML, not %dKB. "
                      "Refusing." % (path, len(raw), len(raw) // 1024))
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise Refused("%s is not valid YAML: %s" % (path, e))
    if not isinstance(doc, dict):
        raise Refused("%s must be a YAML mapping" % path)

    _scan_elevation(doc)

    unknown = set(map(str, doc)) - _TOP_KEYS
    if unknown:
        raise Refused("%s has unknown key(s) %s — unknown keys refuse the file "
                      "so a typo'd constraint can never silently not apply"
                      % (path, sorted(unknown)))
    if doc.get("version") != 1:
        raise Refused("%s: version must be 1" % path)

    service = doc.get("service")
    if service is not None and (not isinstance(service, str)
                                or not _SERVICE_RE.match(service)):
        raise Refused("%s: service %r fails validation" % (path, service))

    deploy = doc.get("deploy") or {}
    if not isinstance(deploy, dict):
        raise Refused("%s: deploy must be a mapping" % path)
    unknown = set(map(str, deploy)) - _DEPLOY_KEYS
    if unknown:
        raise Refused("%s: deploy has unknown key(s) %s" % (path, sorted(unknown)))
    if "host" in deploy and not (isinstance(deploy["host"], str)
                                 and _HOSTISH_RE.match(deploy["host"])):
        raise Refused("%s: deploy.host %r fails validation" % (path, deploy.get("host")))

    cons = doc.get("constraints") or {}
    if not isinstance(cons, dict):
        raise Refused("%s: constraints must be a mapping" % path)
    unknown = set(map(str, cons)) - _CONSTRAINT_KEYS
    if unknown:
        raise Refused("%s: constraints has unknown key(s) %s — a constraint "
                      "that is not understood is a constraint that is not "
                      "applied; refusing" % (path, sorted(unknown)))
    normalized = {
        "deny_extra": _str_list(cons, "constraints", "deny_extra"),
        "risky_extra": _str_list(cons, "constraints", "risky_extra"),
        "hosts_allow": _str_list(cons, "constraints", "hosts_allow",
                                 item_re=_HOSTISH_RE),
        "forbid_flags": _str_list(cons, "constraints", "forbid_flags",
                                  want_prefix="-"),
        "require_blackout": bool(cons.get("require_blackout", False)),
        "forbid_break_glass": bool(cons.get("forbid_break_glass", False)),
        "max_tier": cons.get("max_tier"),
    }
    if normalized["max_tier"] is not None:
        if normalized["max_tier"] not in ("read", "mutating"):
            raise Refused("%s: constraints.max_tier must be 'read' or "
                          "'mutating' — 'risky' as a cap is no cap" % path)
    for flag in ("require_blackout", "forbid_break_glass"):
        if flag in cons and not isinstance(cons[flag], bool):
            raise Refused("%s: constraints.%s must be true or false" % (path, flag))

    return {"path": str(path), "dir": str(path.parent.resolve()),
            "service": service, "deploy": deploy, "constraints": normalized}


def bind(doc, contract_loader=None):
    """Two-way binding check for maps that route (declare a service).

    The contract's repo directory must CONTAIN the map's directory — the map
    says "this place is that service", and the service's contract must agree
    that this place is its repo. Returns the loaded contract.
    """
    if not doc.get("service"):
        raise Refused("map %s declares no service — it constrains but cannot "
                      "route a deploy" % doc["path"])
    if contract_loader is None:
        from . import contracts as _contracts
        contract_loader = _contracts.load
    contract = contract_loader(doc["service"])
    repo = contract.get("repo")
    if not repo:
        raise Refused("contract %r has no repo field — the map cannot be "
                      "bound both ways; add repo to the contract"
                      % doc["service"])
    repo_dir = Path(repo).resolve()
    map_dir = Path(doc["dir"]).resolve()
    if not (map_dir == repo_dir or repo_dir in map_dir.parents):
        raise Refused(
            "map %s names service %r, but that contract's repo is %s and the "
            "map lives in %s — the two do not agree this directory is that "
            "service. A map in the wrong repo routes nothing."
            % (doc["path"], doc["service"], repo_dir, map_dir))
    want_host = (doc.get("deploy") or {}).get("host")
    if want_host and want_host != contract.get("host"):
        raise Refused("map %s says deploy.host %r but contract %r is bound to "
                      "%r — refusing the ambiguity"
                      % (doc["path"], want_host, doc["service"], contract.get("host")))
    return contract


def resolve(start=None):
    """The one call sites use: nearest map, loaded and validated, or None.
    A map that EXISTS but fails validation refuses — it never degrades to
    'no map', because a broken leash must not mean no leash."""
    path = find(start)
    if path is None:
        return None
    return load(path)


def enforce_tier_cap(doc, tier):
    cap = doc["constraints"]["max_tier"]
    if cap is None:
        return
    if _TIER_ORDER[tier] > _TIER_ORDER[cap]:
        raise Refused(
            "command classifies as %r but %s caps this directory at %r — "
            "the map is a leash; run from elsewhere if you mean it, and the "
            "journal will show which directory ran what" % (tier, doc["path"], cap))


def enforce_hosts_allow(doc, hosts, aliases_of=None):
    """Every resolved host must be inside hosts_allow (alias-collapsed).
    One host outside refuses the WHOLE run — no silent partial fleets."""
    allow = set(doc["constraints"]["hosts_allow"])
    if not allow:
        return
    aliases_of = aliases_of or {}
    allowed = set(allow)
    for name in allow:
        allowed |= {a for a, t in aliases_of.items() if t == name}
        if name in aliases_of:
            allowed.add(aliases_of[name])
    outside = [h for h in hosts if h not in allowed]
    if outside:
        raise Refused(
            "%s allows hosts %s from this directory; the plan names %s — "
            "refusing the whole run rather than silently shrinking it"
            % (doc["path"], sorted(allow), sorted(outside)))


def enforce_forbid_flags(doc, command, flag_expander=None):
    forbidden = set(doc["constraints"]["forbid_flags"])
    if not forbidden:
        return
    import shlex
    try:
        tokens = shlex.split(command)
    except ValueError:
        raise Refused("%s forbids flags %s and the command cannot be parsed "
                      "to prove their absence — failing closed"
                      % (doc["path"], sorted(forbidden)))
    if flag_expander:
        tokens = list(flag_expander(tokens))
    hit = sorted(set(tokens) & forbidden)
    if hit:
        raise Refused("%s forbids option(s) %s from this directory"
                      % (doc["path"], hit))
