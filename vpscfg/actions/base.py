"""The action contract: what every typed action declares, and the shape of the
expansion the door runs. Frozen for phase 2; docs/ACTIONS.md is the spec.

An action is a class in tool code. It declares a name, a version, a tier, its
typed parameters, and `build(p, host)`, which turns VALIDATED parameters into
the exact texts the door runs: the body, the "already done?" check, the
post-condition, and the facts it assumes. Nothing in YAML can change a
template; YAML only supplies typed literals.

Threats:
  - Protects against: a template that runs more than it shows (Expansion is
    validated here: a mutation that claims idempotency must carry a check, a
    read carries no check, retry bounds are the runbook's verify_retry bounds,
    sizes are capped); an unquoted parameter (templates quote every value with
    sq(), and the core test sweeps the corpus to prove each value only ever
    appears inside single quotes); an in-container SQL check that writes
    (SqlCheck runs the hostindex read-only session: sqlread.classify on the
    statement, default_transaction_read_only, BEGIN READ ONLY, a 10 s
    statement_timeout, the password read in the container, never on argv);
    two actions sharing a name (register() refuses).
  - Does NOT protect against: a reviewed template that is simply wrong. The
    golden-file test pins every byte to an action_version, and the policy's
    `expands:` digest disarms a file whose expansion changed, so a template
    change is always seen again by a human; it is not proven correct.
"""

import hashlib
import json
import re

from .. import vpsexecpolicy
from ..gates import Refused
from .types import CONTAINER, PG_IDENT, ParamError, ParamType

ACTION_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}", re.ASCII)
PARAM_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,23}", re.ASCII)
TIERS = ("read", "mutation")
BODY_MAX = 65536

# A done-check prints exactly one of these, and nothing else.
DONE = "VPSCFG-DONE"
NEEDED = "VPSCFG-NEEDED"
TOKENS = (DONE, NEEDED)


def sq(value):
    """ALWAYS single-quote a parameter value for a shell template (shlex.quote
    leaves safe-looking words bare; a template quotes every value, so the core
    test can prove no value is ever outside quotes). Ints are rendered as
    digits. Types already exclude `'`; it is escaped regardless."""
    if isinstance(value, bool):
        raise ParamError("sq() is for strings and ints, not booleans")
    if isinstance(value, int):
        return str(value)
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def sha256_text(text):
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


# Every quoted-heredoc delimiter the expansions use: SqlCheck.text() (SQL),
# TokenCheck.text() (VPSCFG), the db actions' bodies (VPSCFG_SQL). A line of
# script or SQL equal to one would end the heredoc early, so the rest would
# run as shell (or the shown text would differ from what runs).
HEREDOC_DELIMS = ("VPSCFG", "SQL", "VPSCFG_SQL")


def heredoc_safe(text, where, openers=True):
    """Refuse `text` when a line equals a heredoc delimiter more often than
    `text` itself opens that heredoc (`<<'DELIM'`; with openers=False, a
    script that is sent inside one, any such line refuses)."""
    lines = (text or "").split("\n")
    for delim in HEREDOC_DELIMS:
        allowed = text.count("<<'%s'" % delim) if openers else 0
        if sum(1 for l in lines if l == delim) > allowed:
            raise ValueError("%s: a line equals the heredoc delimiter %r, which would end "
                             "the heredoc early" % (where, delim))


class Param(object):
    """One declared parameter: `Param(types.PG_IDENT)`, `Param(types.FLAG,
    required=False, default=False)`. An optional parameter with no default is
    simply absent from the canonical JSON when not given."""

    def __init__(self, ptype, required=True, default=None, why=""):
        if not isinstance(ptype, ParamType):
            raise TypeError("Param needs a types.ParamType")
        if required and default is not None:
            raise ValueError("a required param has no default")
        if default is not None:
            ptype.check(default)
        self.type, self.required, self.default, self.why = ptype, required, default, why


class SqlCheck(object):
    """An in-container SQL read through the host index's narrow gate: ONE
    statement, sqlread.classify'd, run in a read-only session. Used where a
    done-check or verify must look inside Postgres (a `docker exec` text would
    classify risky). The statement must print exactly one row: a token from
    TOKENS (use CASE ... THEN 'VPSCFG-DONE' ELSE 'VPSCFG-NEEDED' END).

    Identifiers belong in the SQL as string LITERALS compared server-side, or
    via format('%I'); the database and container are typed here."""

    MARK = "check"

    def __init__(self, container, database, sql):
        CONTAINER.check(container)
        PG_IDENT.check(database)
        if not isinstance(sql, str) or not sql.strip() or len(sql) > 8192:
            raise ParamError("SqlCheck sql must be a non-empty statement under 8 KiB")
        self.container, self.database, self.sql = container, database, sql.strip()

    def command(self):
        from .. import hostindex
        return hostindex.pg_command({"source": "container", "container": self.container},
                                    self.database)

    def script(self):
        from .. import hostindex
        try:
            return hostindex.pg_script([(self.MARK, self.sql)])
        except hostindex.Unavailable as e:
            raise Refused("action SQL check refused by the sqlread gate: %s" % e)

    def text(self):
        """What the plan shows and the plan-hash binds: the command and the
        exact stdin script."""
        return "%s <<'SQL'\n%s\nSQL" % (self.command(), self.script().rstrip("\n"))

    def token(self, out):
        """The token, or None when the output is anything but the marker row
        followed by exactly one token row."""
        lines = [l for l in (out or "").split("\n") if l != ""]
        if len(lines) == 2 and lines[0] == "@@@" + self.MARK and lines[1] in TOKENS:
            return lines[1]
        return None


# ---- token-only checks ------------------------------------------------------
#
# A TokenCheck is a REVIEWED shell script, fixed in tool code, that may read a
# file the door otherwise refuses to read as content (an environment file:
# readpolicy._credential_file), because it can only ever print one token.
#
# Threats:
#   - Protects against: a value leaving the host through the check (the script
#     moves values only over pipes and prints VPSCFG-DONE or VPSCFG-NEEDED;
#     the door accepts exactly one token on stdout with rc 0, and on anything
#     else fails closed WITHOUT echoing, printing or journaling the output:
#     the journal gets the token or a fixed error class, rc and duration);
#     a swapped or edited script (TOKEN_SCRIPTS is keyed by the action's
#     name@version and pins sha256(script); register_token_script refuses a
#     mismatch at import, and the door re-checks the bytes at plan time and
#     again before sending); the exemption spreading (it exists only on this
#     class, the door's gate binds it to the expansion of the registered
#     action, with exactly that expansion's parameters, and only the
#     registry's named file parameter is exempt: still never a device, /proc,
#     /sys, an ssh host key, a .key/.private file or registries.yaml; every
#     other read, a plain cmd, a shell check, a SqlCheck, still meets the
#     credential rule on every tier); a parameter on argv (the argv is the
#     fixed `sh -s`; the parameters are sq()-quoted assignments on stdin); the
#     deny floor (deny_always, deny_extra and the floor scan the command and
#     the whole stdin, S1).
#   - Does NOT protect against: a reviewed script that is wrong (the pinned
#     sha, the golden file and `expands:` make a change visible, they do not
#     prove it right); root on the host; a host that lies about the token.

TOKEN_COMMAND = "sh -s"
TOKEN_SCRIPT_MAX = 8192
TOKEN_VAR_RE = re.compile(r"[a-z][a-z0-9_]{0,15}|@", re.ASCII)
TOKEN_SCRIPTS = {}


class TokenScript(object):
    """One reviewed script: `key` is "<action>@<version>", `binds` maps shell
    variables to the action's parameters ("@" is the positional list, `set
    --`), and `file_param` names the one parameter that is the exempt file."""

    def __init__(self, key, script, sha256, binds, file_param):
        self.key, self.script, self.sha256 = key, script, sha256
        self.binds, self.file_param = binds, file_param


def register_token_script(key, script, sha256, binds, file_param):
    """Called once, at import, by the module that owns the action. Refuses a
    script whose bytes do not hash to the pinned sha256."""
    if key in TOKEN_SCRIPTS:
        raise ValueError("token script %r is registered twice" % key)
    if not isinstance(script, str) or not script.strip() or len(script) > TOKEN_SCRIPT_MAX:
        raise ValueError("token script %r must be non-empty text under %d bytes"
                         % (key, TOKEN_SCRIPT_MAX))
    if sha256_text(script) != sha256:
        raise ValueError("token script %r hashes to %s, not its pinned sha256 — a reviewed "
                         "script changed; review it, then pin the new hash"
                         % (key, sha256_text(script)))
    heredoc_safe(script, "token script %r" % key, openers=False)
    binds = tuple((var, param) for var, param in binds)
    if not binds or any(not TOKEN_VAR_RE.fullmatch(v) for v, _ in binds) \
            or file_param not in [p for _, p in binds]:
        raise ValueError("token script %r: bad binds or file_param" % key)
    TOKEN_SCRIPTS[key] = TokenScript(key, script, sha256, binds, file_param)


def _frozen(value):
    return tuple(value) if isinstance(value, list) else value


class TokenCheck(object):
    """A check or verify that runs a registered reviewed script. `values` are
    (variable, value) pairs, written as quoted assignments before the script
    on stdin. Constructing one proves nothing: the door's gate (bind()) and
    pinned() decide whether it may run."""

    def __init__(self, key, script, values):
        if not isinstance(script, str) or not script.strip() or len(script) > TOKEN_SCRIPT_MAX:
            raise ParamError("a token-only check needs a script under %d bytes"
                             % TOKEN_SCRIPT_MAX)
        self.key, self.reviewed = key, script
        self.values = tuple((var, _frozen(v)) for var, v in values)

    def command(self):
        return TOKEN_COMMAND

    def _prelude(self):
        lines = []
        for var, value in self.values:
            if not TOKEN_VAR_RE.fullmatch(var):
                raise ParamError("token-only check variable %r" % (var,))
            if var == "@":
                lines.append(" ".join(["set --"] + [sq(v) for v in value]))
            else:
                lines.append("%s=%s" % (var, sq(value)))
        return "\n".join(lines) + "\n"

    def script(self):
        """The exact stdin: quoted parameter assignments, then the script."""
        return self._prelude() + self.reviewed.rstrip("\n") + "\n"

    def text(self):
        """What the plan shows and the plan-hash and `expands:` bind."""
        return "# token-only check %s (reviewed script sha256:%s)\n%s <<'VPSCFG'\n%sVPSCFG" % (
            self.key, sha256_text(self.reviewed), self.command(), self.script())

    def pinned(self):
        """The registry entry, or Refused when the key is not registered or the
        bytes differ from the pinned script."""
        entry = TOKEN_SCRIPTS.get(self.key)
        if entry is None:
            raise Refused("token-only check %r is not a registered reviewed script — "
                          "refused" % (self.key,))
        if self.reviewed != entry.script or sha256_text(self.reviewed) != entry.sha256:
            raise Refused("token-only check %s: the script is not the reviewed one "
                          "(sha256 %s, pinned %s) — refused"
                          % (self.key, sha256_text(self.reviewed)[:12], entry.sha256[:12]))
        return entry

    def bind(self, exp):
        """The exempt file path, or Refused unless this check is the reviewed
        script of exactly `exp`'s action and version, carrying exactly `exp`'s
        parameters."""
        want = "%s@%s" % (exp.name, exp.version)
        if self.key != want:
            raise Refused("token-only check %r on action %s — a reviewed script runs "
                          "only for its own action and version" % (self.key, want))
        entry = self.pinned()
        expected = tuple((var, _frozen(exp.params.get(param))) for var, param in entry.binds)
        if self.values != expected:
            raise Refused("token-only check %s does not carry %s's own parameters — "
                          "refused" % (self.key, want))
        return exp.params[entry.file_param]

    def token(self, out):
        """The token, or None for anything but exactly one token line."""
        return plain_token(out)


def probe_text(probe):
    if probe is None:
        return None
    return probe.text() if isinstance(probe, (SqlCheck, TokenCheck)) else probe


def plain_token(out):
    """A shell check's token: the whole stdout is exactly one token (an
    optional single trailing newline). Anything else is None — an error."""
    for t in TOKENS:
        if out in (t, t + "\n"):
            return t
    return None


class Expansion(object):
    """The frozen result of expand(): everything the door needs, nothing it
    has to compute. Validated in __init__; instances are never mutated."""

    FIELDS = ("name", "version", "params", "host", "canonical", "body", "check",
              "verify", "verify_retry", "assumes", "timeout", "idempotent", "tier")

    def __init__(self, **kw):
        for f in self.FIELDS:
            object.__setattr__(self, f, kw[f])
        self._validate()

    def __setattr__(self, key, value):
        raise AttributeError("an Expansion is frozen")

    def _validate(self):
        where = "action %s@%s" % (self.name, self.version)
        if self.tier not in TIERS:
            raise ValueError("%s: tier must be read or mutation" % where)
        if not isinstance(self.body, str) or not self.body.strip() or len(self.body) > BODY_MAX:
            raise ValueError("%s: body must be non-empty text under %d bytes" % (where, BODY_MAX))
        for name in ("check", "verify"):
            probe = getattr(self, name)
            if probe is not None and not isinstance(probe, (SqlCheck, TokenCheck)) and not (
                    isinstance(probe, str) and probe.strip() and len(probe) <= BODY_MAX):
                raise ValueError("%s: %s must be text, a SqlCheck or a TokenCheck"
                                 % (where, name))
            if isinstance(probe, SqlCheck):
                # the statement itself (script() would run the sqlread gate,
                # which is the door's job at plan time, not the constructor's)
                heredoc_safe(probe.sql, "%s %s" % (where, name), openers=False)
            elif isinstance(probe, TokenCheck):
                heredoc_safe(probe.script(), "%s %s" % (where, name), openers=False)
            elif probe is not None:
                heredoc_safe(probe, "%s %s" % (where, name))
        heredoc_safe(self.body, "%s body" % where)
        if self.tier == "read":
            if self.check is not None or self.idempotent:
                raise ValueError("%s: a read action has no done-check" % where)
            if self.verify is not None:
                raise ValueError("%s: a read action's body IS its probe; it has no verify"
                                 % where)
        elif self.idempotent and self.check is None:
            raise ValueError("%s: idempotent: true needs a done-check" % where)
        elif not self.idempotent and self.check is not None:
            raise ValueError("%s: a check on a non-idempotent action could skip a step "
                             "that must run; declare idempotent or drop the check" % where)
        retry = self.verify_retry
        if retry is not None:
            if (not isinstance(retry, tuple) or len(retry) != 2
                    or any(isinstance(v, bool) or not isinstance(v, int) for v in retry)):
                raise ValueError("%s: verify_retry is (tries, interval)" % where)
            tries, interval = retry
            if not (1 <= tries <= vpsexecpolicy.VERIFY_RETRY_TRIES_MAX
                    and 1 <= interval <= vpsexecpolicy.VERIFY_RETRY_INTERVAL_MAX
                    and tries * interval <= vpsexecpolicy.VERIFY_RETRY_TOTAL_MAX):
                raise ValueError("%s: verify_retry is outside the runbook bounds" % where)
            if self.tier == "mutation" and self.verify is None:
                raise ValueError("%s: verify_retry without a verify retries nothing" % where)
        if self.timeout is not None and (
                isinstance(self.timeout, bool) or not isinstance(self.timeout, int)
                or not 1 <= self.timeout <= vpsexecpolicy.RUNBOOK_TIMEOUT_MAX):
            raise ValueError("%s: timeout must be 1-%d seconds"
                             % (where, vpsexecpolicy.RUNBOOK_TIMEOUT_MAX))
        if not isinstance(self.assumes, tuple):
            raise ValueError("%s: assumes must be a tuple" % where)

    # -- what the gates, the plan and the journal see ----------------------

    def check_text(self):
        return probe_text(self.check)

    def verify_text(self):
        return probe_text(self.verify)

    def body_sha256(self):
        return sha256_text(self.body)

    def check_sha256(self):
        return sha256_text(self.check_text()) if self.check is not None else None

    def params_json(self):
        return canonical_json(self.params)

    def texts(self):
        """Every byte this expansion sends, for the deny scans: body, check,
        verify (a SqlCheck contributes its command and its stdin script)."""
        out = [self.body]
        for probe in (self.check, self.verify):
            if isinstance(probe, (SqlCheck, TokenCheck)):
                out += [probe.command(), probe.script()]
            elif probe is not None:
                out.append(probe)
        return out


def canonical_json(params):
    """Sorted keys, no spaces, ASCII: the same bytes on every machine."""
    return json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Action(object):
    """Subclass, set the class attributes, implement build(), and decorate with
    @register. `samples` is the corpus the golden-file and floor-sweep tests
    expand: at least one valid parameter set, covering every parameter."""

    name = None
    version = None
    tier = "mutation"
    params = {}
    samples = ()
    why = ""

    def build(self, p, host):
        """-> dict(body=..., check=None, verify=None, verify_retry=None,
        assumes=(), timeout=None, idempotent=False). `p` holds validated
        values with defaults applied. Pure: no clock, environment, randomness
        or I/O. Raise types.ParamError for a combination of values the types
        alone cannot refuse."""
        raise NotImplementedError


REGISTRY = {}


def register(cls):
    """Class decorator. Validates the declaration once, at import."""
    name = cls.name
    if not isinstance(name, str) or not ACTION_NAME_RE.fullmatch(name):
        raise ValueError("action name %r: [a-z][a-z0-9_]{0,31}" % (name,))
    if name in REGISTRY:
        raise ValueError("action %r is registered twice" % name)
    if isinstance(cls.version, bool) or not isinstance(cls.version, int) or cls.version < 1:
        raise ValueError("action %s: version must be a whole number >= 1" % name)
    if cls.tier not in TIERS:
        raise ValueError("action %s: tier must be read or mutation" % name)
    for pname, spec in cls.params.items():
        if not PARAM_NAME_RE.fullmatch(pname) or not isinstance(spec, Param):
            raise ValueError("action %s: bad param %r" % (name, pname))
    if not cls.samples:
        raise ValueError("action %s: declare samples (the golden/fuzz corpus)" % name)
    REGISTRY[name] = cls()
    # Expand every sample once, here: an Expansion validates itself (sizes,
    # tiers, heredoc delimiters), so a template that breaks one refuses the
    # import rather than the first plan that uses it.
    from .expand import expand
    try:
        for sample in cls.samples:
            expand(name, dict(sample), "web1", "action %s sample" % name)
    except Exception:
        del REGISTRY[name]
        raise
    return cls
