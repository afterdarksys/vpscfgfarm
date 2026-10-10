"""vpsexec's YAML policy framework — host groups, pre-authorised runbooks, and
extra deny/risky patterns, loaded from `policies/*.yaml` in git.

THE ASYMMETRY THAT MAKES THIS SAFE: a policy file can only ever make vpsexec
STRICTER. It can add deny patterns, add risky patterns, and name host groups.
It cannot remove a deny pattern, cannot widen the read-only allowlist, cannot
change a host's posture, and cannot lift the deny-always floor. Loosening lives
in exactly two places, both reviewed: the JSON governor (postures, master
switch) and Python code (the read allowlist).

The single sanctioned loosening here is a `break_glass` runbook — an exact
command, on an exact host set, with an expiry, written and reviewed during calm
so that outage response is a lookup rather than an improvisation. Even then it
only reaches posture: the floor still refuses, and a human still approves.

Threats:
  - Protects against: a policy file quietly weakening the door (unknown top-level
    keys are refused, not ignored, so a future `allow_floor:` cannot be silently
    honoured by an older reader; deny/risky lists are add-only by construction);
    a runbook that reaches for the floor (rejects the whole file as tampered);
    runbooks that rot (per-file expiry required; past it the file's runbooks
    are disarmed, not merged — one lapsed file no longer takes down every
    read and every other runbook with it. It is still validated, so a lapsed
    file naming a host since removed from the governor, or a group name since
    reused, still refuses the whole load: retire lapsed files); group names that
    drift from reality (every host must exist in the JSON governor); ambiguous
    groups (a name defined twice across files refuses rather than picking one);
    a group silently becoming the whole estate (`all` is reserved); a runbook
    file edited after review — `shape:` (steps, hosts, break_glass) declares
    what the reviewer approved, and a file whose runbooks no longer match it,
    or that grants without declaring one, is disarmed like a lapsed one
    (validated in full, tightenings kept, runbooks not merged, recorded in
    merged["misshapen"]); a duplicate YAML key at any depth (a second
    `expires:` silently winning) refuses the whole load.
  - Does NOT protect against: a reviewed-and-committed runbook that is simply a
    bad idea — `break_glass` on `systemctl stop postgres` will do what it says.
    Review is the control there, which is why these files belong in git.
"""

import datetime
import hashlib
import re
import time
from pathlib import Path

from . import estate as _estate
from .gates import Refused, deny_scan
from .probe import HOST_RE

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False

if _HAVE_YAML:
    class _StrictLoader(yaml.SafeLoader):
        """SafeLoader that refuses a duplicate mapping key at any depth.

        Plain safe_load keeps the LAST of two equal keys, so a second
        `expires:` or `shape:` further down a file would silently replace the
        reviewed one. Note this is still YAML 1.1: `yes`/`no`/`on`/`off` load
        as booleans, and the type checks below see them as such."""

        def construct_mapping(self, node, deep=False):
            if isinstance(node, yaml.MappingNode):
                self.flatten_mapping(node)
                seen = set()
                for key_node, _ in node.value:
                    key = self.construct_object(key_node, deep=True)
                    try:
                        dup = key in seen
                    except TypeError:
                        dup = False   # unhashable key: SafeLoader refuses it itself
                    if dup:
                        raise yaml.constructor.ConstructorError(
                            None, None, "duplicate key %r" % (key,),
                            key_node.start_mark)
                    try:
                        seen.add(key)
                    except TypeError:
                        pass
            return super().construct_mapping(node, deep=deep)

POLICY_DIR = Path(_estate.current().policies)

# Refused, not ignored: an older reader must not silently skip a key a newer
# file relies on, and a hopeful `allow_floor:` must fail loudly.
KNOWN_KEYS = frozenset(["version", "expires", "reason", "groups", "runbooks",
                        "deny_extra", "risky_extra", "checks", "shape"])
# `shape:` — what the reviewer approved, in three values a diff makes obvious.
# All three are required; a partial shape would pin less than it appears to.
SHAPE_KEYS = frozenset(["steps", "hosts", "break_glass"])
CHECK_KEYS = frozenset(["cmd", "why", "hosts", "compare", "params"])
PARAM_KEYS = frozenset(["re", "default", "why"])
PARAM_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,23}$")
PLACEHOLDER_RE = re.compile(r"@@([a-z][a-z0-9_]{0,23})@@")
# The door's own ceiling on a parameter VALUE, whatever the policy regex says:
# no whitespace, quotes, shell operators, globs, braces or `$`. A policy regex
# can narrow this; it can never widen it.
# A value may not START with `-` (it would become a flag) or `@` (curl and
# others read `@file`); a leading dash belongs in the template, not the value.
PARAM_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/%+,][A-Za-z0-9_.:/@%+,=-]{0,127}$")
CHECK_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
RUNBOOK_KEYS = frozenset(["host", "hosts", "cmd", "where", "why",
                          "break_glass", "verify", "timeout", "rollback",
                          "verify_retry", "container"])
# `verify_retry: {tries, interval}` — both required, nothing else.
VERIFY_RETRY_KEYS = frozenset(["tries", "interval"])
VERIFY_RETRY_TRIES_MAX = 30
VERIFY_RETRY_INTERVAL_MAX = 60
VERIFY_RETRY_TOTAL_MAX = 600
# The CLI's container-name rule: vpsexec.CONTAINER_RE is probe.HOST_RE. Used
# with fullmatch, so a trailing newline cannot ride along.
CONTAINER_NAME_RE = HOST_RE
# The older spelling of `rollback: true`, still honoured: a `why` that says
# "(rollback only". Grants exclude rollback steps unless --include-rollback.
ROLLBACK_MARK = "(rollback only"
RUNBOOK_TIMEOUT_MAX = 3600
GROUP_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
RESERVED_GROUPS = frozenset(["all"])

UNANALYZABLE = ("$(", "`", "<(", ">(")


def _normalize(text):
    from .commandtext import normalize
    return normalize(text)


def load(policy_dir=None, deny_patterns=None, today=None, governor_hosts=None,
         host_re=None, known_aliases=None):
    """Load and merge every policies/*.yaml. Fails closed on everything.

    Returns {groups, runbooks, deny_extra, risky_extra, checks, files, expired,
    misshapen}. A missing or empty directory is fine — it means no groups and
    no runbooks, not an error.
    """
    directory = Path(policy_dir) if policy_dir is not None else POLICY_DIR
    empty = {"groups": {}, "runbooks": [], "deny_extra": [], "risky_extra": [],
             "checks": {}, "files": [], "expired": [], "misshapen": []}
    if not directory.is_dir():
        return empty

    paths = sorted(list(directory.glob("*.yaml")) + list(directory.glob("*.yml")))
    if not paths:
        return empty
    if not _HAVE_YAML:
        raise Refused(
            "policies/ contains %d file(s) but PyYAML is unavailable — refusing "
            "to run with policy that cannot be read" % len(paths))

    deny_patterns = deny_patterns or []
    today = today or time.strftime("%Y-%m-%d")
    merged = {"groups": {}, "runbooks": [], "deny_extra": [], "risky_extra": [],
              "checks": {}, "files": [], "expired": [], "misshapen": []}
    group_source, check_source = {}, {}

    for path in paths:
        doc, raw = _read(path)
        unknown = sorted(set(doc) - KNOWN_KEYS)
        if unknown:
            raise Refused(
                "policy %s has unknown top-level key(s) %r — refusing rather "
                "than ignoring them; this reader does not know what they mean"
                % (path.name, unknown))
        if doc.get("version") != 1:
            raise Refused("policy %s: version must be 1" % path.name)
        if not str(doc.get("reason", "")).strip():
            raise Refused("policy %s has no top-level 'reason'" % path.name)

        expires = _check_expiry(path, doc, today)
        lapsed = expires is not None and expires < today
        shape = _check_shape(path, doc, host_re)

        for name, hosts in (doc.get("groups") or {}).items():
            _check_group(path, name, hosts, governor_hosts, host_re, known_aliases)
            if name in group_source and group_source[name] != path.name:
                raise Refused(
                    "host group %r is defined in both %s and %s — an ambiguous "
                    "group is a fleet-sized typo; define it once"
                    % (name, group_source[name], path.name))
            group_source[name] = path.name
            merged["groups"][name] = list(hosts)

        # An expired file's runbooks are still validated in full (a tampered
        # file refuses the whole load whether or not it has lapsed), but they
        # grant nothing: they are not merged. Its groups, checks and deny/risky
        # additions still apply — dropping a tightening would loosen the door.
        runbooks = [_check_runbook(path, n, entry, deny_patterns, governor_hosts,
                                   host_re, expires)
                    for n, entry in enumerate(doc.get("runbooks") or [], 1)]
        # A file that no longer matches its declared shape was edited after the
        # review that shape records: disarmed exactly like a lapsed file. A file
        # that grants without declaring one never had its shape recorded at all:
        # disarmed too, but only that file — not a refusal of the whole load.
        if not runbooks:
            mismatch = None
        elif shape is None:
            mismatch = "no shape declared"
        else:
            mismatch = _shape_mismatch(shape, runbooks)
        if mismatch:
            merged["misshapen"].append({"path": str(path), "reason": mismatch,
                                        "runbooks": len(runbooks)})
        if lapsed and runbooks:
            merged["expired"].append({"path": str(path), "expires": expires,
                                      "runbooks": len(runbooks)})
        if not (lapsed or mismatch):
            merged["runbooks"].extend(runbooks)

        for name, check in (doc.get("checks") or {}).items():
            if name in check_source and check_source[name] != path.name:
                raise Refused(
                    "check %r is defined in both %s and %s — define it once"
                    % (name, check_source[name], path.name))
            check_source[name] = path.name
            merged["checks"][name] = _check_check(path, name, check, deny_patterns)

        for key in ("deny_extra", "risky_extra"):
            values = doc.get(key) or []
            if not isinstance(values, list) or not all(
                    isinstance(v, str) and v.strip() for v in values):
                raise Refused("policy %s: %s must be a list of non-empty strings"
                              % (path.name, key))
            merged[key].extend(_normalize(v).lower() for v in values)

        merged["files"].append({"path": str(path),
                                "sha256": hashlib.sha256(raw).hexdigest(),
                                "expires": expires, "lapsed": lapsed,
                                "misshapen": bool(mismatch)})

    merged["deny_extra"] = sorted(set(merged["deny_extra"]))
    merged["risky_extra"] = sorted(set(merged["risky_extra"]))
    return merged


def _read(path):
    try:
        raw = path.read_bytes()
        doc = yaml.load(raw, Loader=_StrictLoader)
    except (OSError, yaml.YAMLError) as e:
        raise Refused("policy %s unreadable/invalid (%s) — failing closed"
                      % (path.name, e))
    if not isinstance(doc, dict):
        raise Refused("policy %s is not a mapping" % path.name)
    return doc, raw


def iso_date(text):
    """True only for a real, zero-padded YYYY-MM-DD. Expiry is compared as a
    string, so '2026-9-1' (which strptime accepts) would sort after
    '2026-10-08' and keep a file armed for months."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return False
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        return False
    return True


def _check_expiry(path, doc, today):
    """Required only when the file grants something. A file that merely defines
    groups or tightens the deny list does not rot, so it need not expire."""
    grants = bool(doc.get("runbooks"))
    expires = doc.get("expires")
    if not expires:
        if grants:
            raise Refused(
                "policy %s defines runbooks but has no 'expires' — a standing "
                "break-glass authorisation without an expiry is a permanent "
                "hole; date it (YYYY-MM-DD)" % path.name)
        return None
    expires = str(expires)
    if not iso_date(expires):
        raise Refused("policy %s: expires %r is not YYYY-MM-DD"
                      % (path.name, expires))
    return expires


def _check_shape(path, doc, host_re):
    """`shape: {steps: N, hosts: [...], break_glass: true|false|mixed}`, or None.

    Strict when present: a malformed shape refuses the whole load rather than
    being skipped, or a typo would silently pin nothing. Absent on a file with
    runbooks, load() disarms that file ("no shape declared")."""
    if "shape" not in doc:
        return None
    shape = doc["shape"]
    where = "policy %s: shape" % path.name
    if not isinstance(shape, dict):
        raise Refused("%s must be a mapping {steps, hosts, break_glass}" % where)
    unknown = sorted(set(shape) - SHAPE_KEYS)
    if unknown:
        raise Refused("%s has unknown key(s) %r — refusing rather than ignoring "
                      "them" % (where, unknown))
    missing = sorted(SHAPE_KEYS - set(shape))
    if missing:
        raise Refused("%s is missing %r — a partial shape pins less than it "
                      "appears to" % (where, missing))
    if not doc.get("runbooks"):
        raise Refused("%s is declared but the file has no runbooks" % where)
    steps = shape["steps"]
    if isinstance(steps, bool) or not isinstance(steps, int) or steps < 1:
        raise Refused("%s: steps must be a whole number >= 1" % where)
    hosts = shape["hosts"]
    if (not isinstance(hosts, list) or not hosts
            or not all(isinstance(h, str) and h.strip() for h in hosts)):
        raise Refused("%s: hosts must be a non-empty list of hosts" % where)
    if len(set(hosts)) != len(hosts):
        raise Refused("%s: hosts names a host twice" % where)
    for h in hosts:
        if host_re and not host_re.match(h):
            raise Refused("%s: invalid host %r" % (where, h))
    break_glass = shape["break_glass"]
    if not (isinstance(break_glass, bool) or break_glass == "mixed"):
        raise Refused("%s: break_glass must be true, false or mixed" % where)
    return {"steps": steps, "hosts": sorted(hosts), "break_glass": break_glass}


def runbook_shape(runbooks):
    """The shape a list of loaded runbook entries actually has. Hosts are the
    names as written (the loader does not collapse aliases), so respelling a
    host is a change of shape too."""
    flags = set(r["break_glass"] for r in runbooks)
    return {"steps": len(runbooks),
            "hosts": sorted(set(h for r in runbooks for h in r["hosts"])),
            "break_glass": flags.pop() if len(flags) == 1 else "mixed"}


def _shape_mismatch(declared, runbooks):
    """None when `runbooks` match the declared shape, else 'field: declared X,
    loaded Y; ...' naming every field that differs."""
    actual = runbook_shape(runbooks)
    diffs = ["%s: declared %s, loaded %s" % (k, _shape_text(declared[k]),
                                              _shape_text(actual[k]))
             for k in ("steps", "hosts", "break_glass") if declared[k] != actual[k]]
    return "; ".join(diffs) or None


def _shape_text(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[%s]" % ", ".join(value)
    return str(value)


def expiry_notes(policy, today=None, soon_days=3):
    """Lines that warn about authorisations that have lapsed, are about to, or
    no longer match their declared shape.

    An expired or misshapen file grants nothing (load() disarms its runbooks);
    these lines are how a human learns that, and that the file needs fixing or
    retiring in git.
    """
    today = today or time.strftime("%Y-%m-%d")
    notes = []
    for m in policy.get("misshapen", []):
        notes.append("WARNING: policy %s does not match its declared shape (%s) "
                     "— its %d runbook(s) are DISARMED. Re-review it, then fix the "
                     "shape or the runbooks in git."
                     % (Path(m["path"]).name, m["reason"], m["runbooks"]))
    for e in policy.get("expired", []):
        notes.append("WARNING: policy %s expired on %s — its %d runbook(s) are "
                     "DISARMED. Retire it in git (policies/examples/superseded/) "
                     "or re-review and re-date it."
                     % (Path(e["path"]).name, e["expires"], e["runbooks"]))
    horizon = (datetime.date.fromisoformat(today)
               + datetime.timedelta(days=soon_days)).isoformat()
    for f in policy.get("files", []):
        if f.get("expires") and today <= f["expires"] <= horizon:
            notes.append("note: policy %s expires %s — its runbooks disarm after "
                         "that day" % (Path(f["path"]).name, f["expires"]))
    return notes


def _check_group(path, name, hosts, governor_hosts, host_re, known_aliases=None):
    if not isinstance(name, str) or not GROUP_RE.match(name):
        raise Refused("policy %s: bad group name %r (lowercase, [a-z0-9_-], "
                      "32 chars)" % (path.name, name))
    if name in RESERVED_GROUPS:
        raise Refused("policy %s: group name %r is reserved — @all is built in "
                      "and means every governed host" % (path.name, name))
    if (not isinstance(hosts, list) or not hosts
            or not all(isinstance(h, str) and h.strip() for h in hosts)):
        raise Refused("policy %s: group %r must be a non-empty list of hosts"
                      % (path.name, name))
    if len(set(hosts)) != len(hosts):
        raise Refused("policy %s: group %r names a host twice" % (path.name, name))
    for h in hosts:
        if host_re and not host_re.match(h):
            raise Refused("policy %s: group %r has invalid host %r"
                          % (path.name, name, h))
        if governor_hosts is not None and h not in governor_hosts:
            raise Refused(
                "policy %s: group %r names host %r, which the governor does not "
                "know — every group member must have a posture in "
                "vpscfg-control.json" % (path.name, name, h))
        if known_aliases and h not in known_aliases:
            raise Refused(
                "policy %s: group %r names host %r, which is neither an alias "
                "in ~/.ssh/config nor a governor alias_of one — a group member "
                "that cannot be reached is a typo you would otherwise discover "
                "mid-incident. Usable: %s"
                % (path.name, name, h, ", ".join(sorted(known_aliases))))


def _check_check(path, name, check, deny_patterns):
    """A named read play: `vpsexec check disk`.

    Checks grant nothing — they name a command that must already be allowed to
    everyone. The load-bearing rule is enforced where classification lives (in
    vpsexec, at run time): a check's command MUST be a read. A "check" that
    could mutate would be a way to run mutations with no --run and no approval,
    which is the one thing this whole tool exists to prevent.
    """
    if not CHECK_RE.match(str(name)):
        raise Refused("policy %s: bad check name %r (lowercase, [a-z0-9_-])"
                      % (path.name, name))
    if not isinstance(check, dict):
        raise Refused("policy %s: check %r is not a mapping" % (path.name, name))
    unknown = sorted(set(check) - CHECK_KEYS)
    if unknown:
        raise Refused("policy %s: check %r has unknown key(s) %r — refusing "
                      "rather than ignoring them" % (path.name, name, unknown))
    for key in ("cmd", "why"):
        if not str(check.get(key, "")).strip():
            raise Refused("policy %s: check %r missing %r" % (path.name, name, key))
    cmd = _normalize(check["cmd"])
    try:
        deny_scan(cmd, deny_patterns)
    except Refused as r:
        raise Refused("policy %s: check %r names a denied pattern (%s)"
                      % (path.name, name, r))
    for bad in UNANALYZABLE:
        if bad in cmd:
            raise Refused("policy %s: check %r contains %r — substitution cannot "
                          "be scanned" % (path.name, name, bad))
    compare = check.get("compare", False)
    if not isinstance(compare, bool):
        raise Refused("policy %s: check %r: compare must be true or false"
                      % (path.name, name))
    params = _check_params(path, name, check.get("params") or {}, cmd)
    return {"name": name, "cmd": cmd, "why": check["why"],
            "hosts": check.get("hosts") or "@all", "compare": compare,
            "params": params, "source": path.name}


def _check_params(path, name, params, cmd):
    """`params:` on a check: typed values substituted for `@@name@@`.

    Every placeholder must be declared and every declaration used, so a typo
    refuses at load instead of reaching a host as a literal `@@nmae@@`.
    """
    where = "policy %s: check %r" % (path.name, name)
    if not isinstance(params, dict):
        raise Refused("%s: params must be a mapping" % where)
    used = set(PLACEHOLDER_RE.findall(cmd))
    if "@@" in PLACEHOLDER_RE.sub("", cmd):
        raise Refused("%s: malformed @@placeholder@@ in cmd" % where)
    if used != set(params):
        raise Refused("%s: placeholders %r do not match declared params %r"
                      % (where, sorted(used), sorted(params)))
    out = {}
    for pname, spec in params.items():
        if not PARAM_NAME_RE.match(str(pname)):
            raise Refused("%s: bad param name %r" % (where, pname))
        if not isinstance(spec, dict) or not spec.get("re"):
            raise Refused("%s: param %r needs a 're'" % (where, pname))
        unknown = sorted(set(spec) - PARAM_KEYS)
        if unknown:
            raise Refused("%s: param %r has unknown key(s) %r" % (where, pname, unknown))
        try:
            pattern = re.compile(str(spec["re"]))
        except re.error as e:
            raise Refused("%s: param %r regex does not compile: %s" % (where, pname, e))
        default = spec.get("default")
        if default is not None:
            default = str(default)
            if not (pattern.fullmatch(default) and PARAM_VALUE_RE.match(default)):
                raise Refused("%s: param %r default %r fails its own regex"
                              % (where, pname, default))
        out[pname] = {"re": pattern, "default": default, "why": spec.get("why", "")}
    return out


def bind_params(check, supplied):
    """Substitute validated values into a check's command. Raises Refused on a
    missing, unknown, repeated or out-of-grammar value."""
    params = check.get("params") or {}
    values = {}
    for item in supplied:
        key, _, value = item.partition("=")
        if key not in params:
            raise Refused("check %r has no param %r — it takes: %s"
                          % (check["name"], key, ", ".join(sorted(params)) or "none"))
        if key in values:
            raise Refused("param %r given twice" % key)
        if not PARAM_VALUE_RE.match(value) or not params[key]["re"].fullmatch(value):
            raise Refused("param %s=%r does not match %s (and the door's own "
                          "character ceiling)" % (key, value, params[key]["re"].pattern))
        values[key] = value
    for key, spec in params.items():
        if key not in values:
            if spec["default"] is None:
                raise Refused("check %r needs %s=… (%s)"
                              % (check["name"], key, spec["why"] or spec["re"].pattern))
            values[key] = spec["default"]
    return PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], check["cmd"])


def _check_runbook(path, n, entry, deny_patterns, governor_hosts, host_re, expires):
    if not isinstance(entry, dict):
        raise Refused("policy %s runbook %d is not a mapping" % (path.name, n))
    unknown = sorted(set(entry) - RUNBOOK_KEYS)
    if unknown:
        raise Refused("policy %s runbook %d has unknown key(s) %r — refusing "
                      "rather than ignoring them" % (path.name, n, unknown))

    hosts = entry.get("hosts", entry.get("host"))
    if isinstance(hosts, str):
        hosts = [hosts]
    if (not isinstance(hosts, list) or not hosts
            or not all(isinstance(h, str) and h.strip() for h in hosts)):
        raise Refused("policy %s runbook %d needs host: <name> or hosts: [...]"
                      % (path.name, n))
    for h in hosts:
        if host_re and not host_re.match(h):
            raise Refused("policy %s runbook %d: invalid host %r" % (path.name, n, h))
        if governor_hosts is not None and h not in governor_hosts:
            raise Refused("policy %s runbook %d names host %r, which the governor "
                          "does not know" % (path.name, n, h))

    for key in ("cmd", "why"):
        if not str(entry.get(key, "")).strip():
            raise Refused("policy %s runbook %d missing %r" % (path.name, n, key))

    where = entry.get("where", "host")
    if where not in ("host", "container"):
        raise Refused("policy %s runbook %d: where must be 'host' or 'container'"
                      % (path.name, n))

    break_glass = entry.get("break_glass", False)
    if not isinstance(break_glass, bool):
        raise Refused("policy %s runbook %d: break_glass must be true or false"
                      % (path.name, n))

    rollback = entry.get("rollback", False)
    if not isinstance(rollback, bool):
        raise Refused("policy %s runbook %d: rollback must be true or false"
                      % (path.name, n))
    marked = ROLLBACK_MARK in str(entry["why"]).lower()
    if "rollback" in entry and not rollback and marked:
        raise Refused("policy %s runbook %d says rollback: false but its why says "
                      "%r — say which it is" % (path.name, n, ROLLBACK_MARK))
    rollback = rollback or marked

    cmd = _normalize(entry["cmd"])
    try:
        deny_scan(cmd, deny_patterns)
    except Refused as r:
        raise Refused(
            "policy %s runbook %d names a deny-always pattern (%s) — the floor "
            "is not reachable from any policy file, so this whole file is "
            "rejected as tampered" % (path.name, n, r))
    for bad in UNANALYZABLE:
        if bad in cmd:
            raise Refused("policy %s runbook %d contains %r — substitution is "
                          "never authorisable" % (path.name, n, bad))

    verify = entry.get("verify")
    if verify is not None:
        if not isinstance(verify, str) or not verify.strip():
            raise Refused("policy %s runbook %d: verify must be a non-empty string"
                          % (path.name, n))
        verify = _normalize(verify)
        try:
            deny_scan(verify, deny_patterns)
        except Refused as r:
            raise Refused("policy %s runbook %d verify names a deny-always "
                          "pattern (%s)" % (path.name, n, r))
        for bad in UNANALYZABLE:
            if bad in verify:
                raise Refused("policy %s runbook %d verify contains %r"
                              % (path.name, n, bad))

    # How long the reviewer expects this command to take. It replaces the
    # predicted default, never an explicit --timeout.
    timeout = entry.get("timeout")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int)
                                or not 1 <= timeout <= RUNBOOK_TIMEOUT_MAX):
        raise Refused("policy %s runbook %d: timeout must be whole seconds, 1 to %d"
                      % (path.name, n, RUNBOOK_TIMEOUT_MAX))

    # Let a slow service settle: the verify runs up to `tries` times,
    # `interval` seconds apart, and passes on the first success. Still the
    # same verify, so still a read (checked where classification lives).
    verify_retry = entry.get("verify_retry")
    if verify_retry is not None:
        if verify is None:
            raise Refused("policy %s runbook %d: verify_retry without a verify "
                          "retries nothing" % (path.name, n))
        if not isinstance(verify_retry, dict) or set(verify_retry) != VERIFY_RETRY_KEYS:
            raise Refused("policy %s runbook %d: verify_retry must be exactly "
                          "{tries: <1-%d>, interval: <1-%d seconds>} — unknown or "
                          "missing keys refuse" % (path.name, n, VERIFY_RETRY_TRIES_MAX,
                                                   VERIFY_RETRY_INTERVAL_MAX))
        tries, interval = verify_retry["tries"], verify_retry["interval"]
        for key, value, top in (("tries", tries, VERIFY_RETRY_TRIES_MAX),
                                ("interval", interval, VERIFY_RETRY_INTERVAL_MAX)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= top:
                raise Refused("policy %s runbook %d: verify_retry.%s must be a whole "
                              "number, 1 to %d" % (path.name, n, key, top))
        if tries * interval > VERIFY_RETRY_TOTAL_MAX:
            raise Refused("policy %s runbook %d: verify_retry waits up to %ds "
                          "(tries x interval); the cap is %ds"
                          % (path.name, n, tries * interval, VERIFY_RETRY_TOTAL_MAX))
        verify_retry = {"tries": tries, "interval": interval}

    # The one container this entry authorises. Without it, a `where: container`
    # entry matches any container, as before.
    container = entry.get("container")
    if container is not None:
        if where != "container":
            raise Refused("policy %s runbook %d: container: needs where: container"
                          % (path.name, n))
        if not isinstance(container, str) or not CONTAINER_NAME_RE.fullmatch(container):
            raise Refused("policy %s runbook %d: invalid container name %r (the "
                          "CLI's rule: alnum first, then alnum . -)"
                          % (path.name, n, container))

    return {"hosts": list(hosts), "cmd": cmd, "where": where, "why": entry["why"],
            "break_glass": break_glass, "source": path.name, "expires": expires,
            "verify": verify, "timeout": timeout, "rollback": rollback,
            "verify_retry": verify_retry, "container": container}
