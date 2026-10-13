"""Parameter validation, the pure expansion, the reserved canonical spelling,
and the `expands:` digest.

    canonical = vpscfg-action <name>@<version> '<canonical JSON of the params>'

The canonical string is what the gates, the runbook matcher, grants and the
plan-hash see. It names no host and runs nothing: the door owns the body. Typed
by hand (as a command, a runbook or override `cmd:`, a check, a play `cmd:`) it
is refused as reserved, exactly like `vpscfg-push`. The JSON is shell-quoted so
the classifier and normalize() see one literal word.

Threats:
  - Protects against: an action reached by spelling its canonical string in a
    `cmd:` (reserved everywhere a command is accepted, so the only way in is
    `action:` + `with:`, which the expands digest pins); a version the door
    does not have (`name@N` must equal the registered version); a parameter
    set that is not exactly the declared one (unknown and missing names refuse,
    duplicate JSON keys refuse, defaults are written into the canonical JSON so
    two spellings of one call cannot hash differently); nondeterminism (sorted
    keys, fixed separators, ASCII; no clock, environment or randomness here);
    a template change slipping under a reviewed policy (the digest covers the
    canonical string and the sha256 of every body and check, per host, plus
    the verify text and retry; a mismatch disarms the file).
  - Does NOT protect against: a reviewer pasting the printed digest without
    reading the printed expansion. Lint shows both; reading is the control.
"""

import hashlib
import json
import re
import shlex

from .. import vpsexecpolicy
from ..commandtext import literal_words, normalize
from ..gates import Refused
from .base import REGISTRY, Expansion, ParamError, canonical_json

ACTION_CANONICAL = "vpscfg-action"
EXPANDS_RE = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
VERSIONED_RE = re.compile(r"([a-z][a-z0-9_]{0,31})(?:@([1-9][0-9]{0,5}))?", re.ASCII)
WITH_JSON_MAX = 8192


def get(name, where="action"):
    """The registered action for `name` or `name@version`. A version other
    than the registered one is refused: this door cannot expand it."""
    if not isinstance(name, str):
        raise Refused("%s: action must be a name, not %r" % (where, name))
    m = VERSIONED_RE.fullmatch(name)
    if not m or m.group(1) not in REGISTRY:
        raise Refused("%s: unknown action %r — this door knows: %s"
                      % (where, name, ", ".join(sorted(REGISTRY)) or "none"))
    action = REGISTRY[m.group(1)]
    if m.group(2) is not None and int(m.group(2)) != action.version:
        raise Refused("%s: %s is version %d in this door; @%s is not something it can "
                      "expand — re-plan with this door's version"
                      % (where, action.name, action.version, m.group(2)))
    return action


def validate(action, params, where="action"):
    """-> the complete, typed parameter dict (defaults applied, optional
    params without a default left out). Raises Refused naming the field."""
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise Refused("%s: with: must be a mapping of %s's parameters, not %s"
                      % (where, action.name, _kind(params)))
    unknown = sorted(str(k) for k in params if k not in action.params)
    if unknown:
        raise Refused("%s: with: has unknown parameter(s) %r — %s takes: %s"
                      % (where, unknown, action.name, ", ".join(sorted(action.params))))
    out = {}
    for pname, spec in sorted(action.params.items()):
        if pname in params:
            try:
                out[pname] = spec.type.check(params[pname])
            except ParamError as e:
                raise Refused("%s: with.%s: %s" % (where, pname, e))
        elif spec.required:
            raise Refused("%s: with.%s is missing — %s needs it (%s)"
                          % (where, pname, action.name, spec.type.name))
        elif spec.default is not None:
            out[pname] = spec.default
    return out


def _kind(value):
    from .types import yaml_type
    return yaml_type(value)


def canonical(action, params):
    """`vpscfg-action <name>@<version> '<json>'` for VALIDATED params."""
    return "%s %s@%d %s" % (ACTION_CANONICAL, action.name, action.version,
                            shlex.quote(canonical_json(params)))


def expand(name, params, host, where="action"):
    """The pure expansion of one action call on one host: an Expansion.

    `params` is validated here (raw YAML or JSON values are fine); `host` is
    passed to build() as written, so a template must not vary on how a host
    is spelled — per-host data belongs in a typed parameter."""
    action = get(name, where)
    p = validate(action, params, where)
    try:
        built = action.build(dict(p), host)
    except ParamError as e:
        raise Refused("%s: with: %s" % (where, e))
    unknown = sorted(set(built) - {"body", "check", "verify", "verify_retry", "assumes",
                                   "timeout", "idempotent"})
    if unknown:
        raise ValueError("action %s build() returned unknown key(s) %r" % (action.name, unknown))
    assumes = tuple(_assumes(action, built.get("assumes") or (), host))
    retry = built.get("verify_retry")
    return Expansion(name=action.name, version=action.version, params=p, host=host,
                     canonical=canonical(action, p), body=built["body"],
                     check=built.get("check"), verify=built.get("verify"),
                     verify_retry=tuple(retry) if retry is not None else None,
                     assumes=assumes, timeout=built.get("timeout"),
                     idempotent=bool(built.get("idempotent", False)), tier=action.tier)


class _Named(object):
    def __init__(self, name):
        self.name = name


def _assumes(action, items, host):
    """Each item is an assumes:-shaped fact without `host:` (the step's host is
    filled in), validated by the loader's own check_assumes."""
    out = []
    for item in items:
        if not isinstance(item, dict) or "host" in item or "verified_by" in item:
            raise ValueError("action %s: an assumes item is a fact mapping without "
                             "host:/verified_by:" % action.name)
        out.append(dict(item, host=host))
    if out:
        vpsexecpolicy.check_assumes(_Named("action %s" % action.name), {"assumes": out})
    return out


def is_reserved(command):
    """True when `command` names the reserved word anywhere (any segment, any
    path prefix). Unparseable text is left to the classifier, which refuses
    it on its own."""
    try:
        words = literal_words(normalize(command or ""))
    except ValueError:
        return ACTION_CANONICAL in (command or "")
    return any(w.rsplit("/", 1)[-1] == ACTION_CANONICAL for w in words)


def reserved_refusal(where):
    return Refused("%s: %r is the reserved spelling of a typed action — use `action:` "
                   "and `with:` (or `vpsexec <hosts> --action NAME --with JSON`); the "
                   "door builds the body, nothing else may name it"
                   % (where, ACTION_CANONICAL))


def parse_with_json(text, where="--with"):
    """The CLI's `--with JSON`: one object, no duplicate keys, no NaN or
    Infinity, under 8 KiB. Values are typed by validate() like YAML's."""
    if text is None:
        return {}
    if not isinstance(text, str) or len(text) > WITH_JSON_MAX:
        raise Refused("%s must be a JSON object under %d bytes" % (where, WITH_JSON_MAX))

    def pairs(items):
        seen = {}
        for k, v in items:
            if k in seen:
                raise Refused("%s names %r twice" % (where, k))
            seen[k] = v
        return seen

    def constant(name):
        raise Refused("%s: %s is not a value" % (where, name))

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except ValueError as e:
        raise Refused("%s is not valid JSON (%s)" % (where, e))
    if not isinstance(value, dict):
        raise Refused("%s must be a JSON object {\"param\": value, ...}" % where)
    return value


# ---- the expands: digest --------------------------------------------------

def digest_items(runbooks):
    """[(step, host, canonical, sha256(body), sha256(check), verify, retry,
    timeout, assumes)] for every action step of a file's loaded runbooks, in
    step order. The template's timeout and assumed facts are part of what a
    reviewer approved: changing either disarms the file like a body change."""
    items = []
    for n, r in enumerate(runbooks, 1):
        act = r.get("action")
        if not act:
            continue
        for host in r["hosts"]:
            exp = act["expansions"][host]
            items.append([n, host, exp.canonical, exp.body_sha256(), exp.check_sha256(),
                          exp.verify_text(), list(exp.verify_retry) if exp.verify_retry
                          else None, exp.timeout, [dict(a) for a in exp.assumes]])
    return items


def expands_digest(runbooks):
    """`sha256:<hex>` over digest_items, or None when the file has no action."""
    items = digest_items(runbooks)
    if not items:
        return None
    payload = json.dumps(sorted(items, key=lambda i: (i[0], i[1])), sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def check_declared(path, doc):
    """Strict syntax of a declared `expands:`; returns it or None."""
    if "expands" not in doc:
        return None
    value = doc["expands"]
    if not isinstance(value, str) or not EXPANDS_RE.fullmatch(value):
        raise Refused("policy %s: expands must be \"sha256:<64 hex>\" — `vpsexec runbook "
                      "lint` prints the correct line" % path.name)
    return value


def expands_mismatch(declared, runbooks):
    """None when the file's action steps match `declared`, else the reason the
    file is disarmed. A file with no action step must not declare one."""
    actual = expands_digest(runbooks)
    if actual is None:
        return None if declared is None else "expands: declared, but no step is an action"
    if declared is None:
        return "expands: not declared (the file has action steps)"
    if declared != actual:
        return ("expands: declared %s…, expanded %s… (an action template or a with: "
                "changed)" % (declared[:19], actual[:19]))
    return None


def expands_line(runbooks):
    digest = expands_digest(runbooks)
    return 'expands: "%s"' % digest if digest else None


def lint_expands(doc, runbooks):
    """One runbookcheck-shaped result {name, status, evidence} for lint
    (P2 wires it into lint's list). A failure prints the line to paste."""
    declared = doc.get("expands")
    actual = expands_digest(runbooks)
    if actual is None and declared is None:
        return {"name": "expands", "status": "skip", "evidence": "no action steps"}
    reason = expands_mismatch(declared, runbooks)
    if reason is None:
        return {"name": "expands", "status": "pass",
                "evidence": "%d action expansion(s) match %s…"
                % (len(digest_items(runbooks)), actual[:19])}
    fix = (" — after reading every expansion (vpsexec <hosts> --action NAME --with "
           "JSON shows each body and check), paste: %s" % expands_line(runbooks)
           if actual else " — remove the expands: line")
    return {"name": "expands", "status": "fail",
            "evidence": "%s; the file is DISARMED%s" % (reason, fix)}


def step_assumes(runbooks):
    """[(step, item)] for every fact an action step assumes, so lint and
    preflight can treat them like hand-written assumes: items, labelled
    `(from action step N)`. They grant nothing."""
    out = []
    for n, r in enumerate(runbooks, 1):
        act = r.get("action")
        if not act:
            continue
        for host in r["hosts"]:
            for item in act["expansions"][host].assumes:
                out.append((n, dict(item)))
    return out


def deny_check(expansion, deny_patterns, where):
    """Every byte the expansion would send, through the floor and the deny
    lists (S1). A hit refuses: templates are code, so a hit is a bug."""
    from ..gates import deny_scan
    for text in [expansion.canonical] + expansion.texts():
        try:
            deny_scan(text, deny_patterns)
        except Refused as r:
            raise Refused("%s: action %s expands to text that names a deny pattern (%s) "
                          "— refused" % (where, expansion.name, r))
