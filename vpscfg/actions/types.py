"""Typed action parameters: the only values that ever reach an action template.

Every parameter is a literal of a closed type: a fullmatch regex (compiled
ASCII-only, so no Unicode digit or lookalike letter passes) plus a check of the
YAML/JSON type the value arrived as. A string type also has to pass the door's
own character ceiling (vpsexecpolicy.PARAM_VALUE_RE): no whitespace, quotes,
shell operators, globs, braces or `$`, never a leading `-` or `@`, at most 128
characters. A type can narrow that ceiling; it can never widen it.

Threats:
  - Protects against: free text reaching a template (every value is a typed
    literal checked here before any template sees it); shell and SQL injection
    through a value (`;`, quotes, `$(...)`, backticks, newline, NUL, CR, tab
    and spaces are outside every string type; SQL identifiers are lowercase
    `pg_ident` only, so there is no quoting game to play); option injection
    (no value starts with `-`); YAML type confusion (`length: "48"` is not an
    int, `48` is not a string, a list or map is never a scalar, YAML 1.1's
    `yes`/`no`/`on`/`off` are refused where a boolean belongs, `0644` loaded
    as the int 420 is not the string "0644"); Unicode lookalikes and NFKC
    tricks (ASCII-only classes); oversized values (the 128-char ceiling, list
    caps); path traversal (`..` and `.` segments, `//`, a trailing `/`).
  - Does NOT protect against: a well-formed value that names the wrong thing
    (`role: postgres` is a valid identifier). Review of the policy is the
    control for that, which is why parameters live in committed files.
"""

import re

from .. import vpsexecpolicy

# The door's ceiling, applied on top of every string type. Always fullmatch:
# PARAM_VALUE_RE ends in `$`, which .match() also accepts before a trailing
# newline.
CEILING_RE = vpsexecpolicy.PARAM_VALUE_RE


class ParamError(ValueError):
    """A parameter value failed its type. The loader names the field."""


def yaml_type(value):
    """How a value arrived, in words a policy author recognises."""
    if isinstance(value, vpsexecpolicy.YamlWord):
        return "the YAML 1.1 word %r (read as a boolean)" % value.text
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, int):
        return "an integer"
    if isinstance(value, float):
        return "a float"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, (list, tuple)):
        return "a list"
    if isinstance(value, dict):
        return "a mapping"
    return type(value).__name__


class ParamType(object):
    """One closed parameter type. `check(value)` returns the value or raises
    ParamError; it never coerces."""

    name = "?"

    def check(self, value):  # pragma: no cover - abstract
        raise NotImplementedError

    def __repr__(self):
        return self.name


class _Str(ParamType):
    def __init__(self, name, pattern, extra=None):
        self.name = name
        self.regex = re.compile(pattern, re.ASCII)
        self.extra = extra

    def check(self, value):
        if not isinstance(value, str) or isinstance(value, vpsexecpolicy.YamlWord):
            raise ParamError("must be a string (%s), not %s" % (self.name, yaml_type(value)))
        if not CEILING_RE.fullmatch(value):
            raise ParamError("%r is outside the door's character ceiling (1-128 of "
                             "[A-Za-z0-9_.:/@%%+,=-], not starting with - or @)" % value[:80])
        if not self.regex.fullmatch(value):
            raise ParamError("%r is not a valid %s" % (value[:80], self.name))
        if self.extra:
            self.extra(value)
        return value


def _path_rules(value):
    parts = value.split("/")
    if value != "/" and value.endswith("/"):
        raise ParamError("%r ends in '/' — name the path without a trailing slash" % value)
    if value == "/":
        raise ParamError("'/' is not an acceptable path parameter")
    if "" in parts[1:]:
        raise ParamError("%r has an empty segment ('//')" % value)
    if any(p in (".", "..") for p in parts):
        raise ParamError("%r has a '.' or '..' segment" % value)


def _basename_rules(value):
    if value in (".", "..") or value.startswith(("-", ".")):
        raise ParamError("%r must not be . or .. or start with '-' or '.'" % value)


def _url_rules(value):
    port = int(re.match(r"http://127\.0\.0\.1:([0-9]+)", value).group(1))
    if not 1 <= port <= 65535:
        raise ParamError("port %d is out of range" % port)


CONTAINER = _Str("container", r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}")
PG_IDENT = _Str("pg_ident", r"[a-z_][a-z0-9_]{0,62}")
ENV_KEY = _Str("env_key", r"[A-Za-z_][A-Za-z0-9_]{0,127}")
ABS_PATH = _Str("abs_path", r"/[A-Za-z0-9._/@+-]{0,127}", _path_rules)
# drill.URL_RE, narrowed by the ceiling (no `~`).
LOCAL_URL = _Str("local_url", r"http://127\.0\.0\.1:[0-9]{1,5}(/[A-Za-z0-9._/-]*)?", _url_rules)
# repo[:tag][@sha256:<64 hex>], with an optional registry host[:port]/ first.
IMAGE_REF = _Str("image_ref",
                 r"([a-z0-9][a-z0-9.-]*(:[0-9]{1,5})?/)?"
                 r"[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*"
                 r"(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[0-9a-f]{64})?")
SHA256 = _Str("sha256", r"[0-9a-f]{64}")
BASENAME = _Str("basename", r"[A-Za-z0-9._-]{1,64}", _basename_rules)


class IntRange(ParamType):
    def __init__(self, lo, hi):
        if not (isinstance(lo, int) and isinstance(hi, int) and lo <= hi):
            raise ValueError("int_range needs whole numbers lo <= hi")
        self.lo, self.hi = lo, hi
        self.name = "int_range(%d,%d)" % (lo, hi)

    def check(self, value):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ParamError("must be a whole number %d-%d, not %s"
                             % (self.lo, self.hi, yaml_type(value)))
        if not self.lo <= value <= self.hi:
            raise ParamError("%d is outside %d-%d" % (value, self.lo, self.hi))
        return value


class Enum(ParamType):
    def __init__(self, *values):
        if not values:
            raise ValueError("enum needs at least one value")
        for v in values:
            if not isinstance(v, str) or not CEILING_RE.fullmatch(v):
                raise ValueError("enum value %r is outside the ceiling" % (v,))
        self.values = tuple(values)
        self.name = "enum(%s)" % ", ".join(values)

    def check(self, value):
        if not isinstance(value, str) or isinstance(value, vpsexecpolicy.YamlWord):
            raise ParamError("must be one of %s (a string), not %s"
                             % (", ".join(self.values), yaml_type(value)))
        if value not in self.values:
            raise ParamError("%r is not one of %s" % (value[:80], ", ".join(self.values)))
        return value


class Flag(ParamType):
    """true or false, written as such. YAML 1.1's yes/no/on/off are refused."""

    name = "flag"

    def check(self, value):
        if isinstance(value, vpsexecpolicy.YamlWord):
            raise ParamError("write true or false, not %r — YAML 1.1 reads that word "
                             "as a boolean, which is too easy to mistype" % value.text)
        if not isinstance(value, bool):
            raise ParamError("must be true or false, not %s" % yaml_type(value))
        return value


class ListOf(ParamType):
    def __init__(self, item, most, least=1):
        if isinstance(item, ListOf):
            raise ValueError("list_of does not nest")
        if not (isinstance(most, int) and isinstance(least, int) and 0 <= least <= most):
            raise ValueError("list_of needs 0 <= least <= most")
        self.item, self.most, self.least = item, most, least
        self.name = "list_of(%s, %d)" % (item.name, most)

    def check(self, value):
        if not isinstance(value, list):
            raise ParamError("must be a list of %s, not %s" % (self.item.name, yaml_type(value)))
        if not self.least <= len(value) <= self.most:
            raise ParamError("must hold %d to %d item(s), has %d"
                             % (self.least, self.most, len(value)))
        out = []
        for n, v in enumerate(value, 1):
            try:
                out.append(self.item.check(v))
            except ParamError as e:
                raise ParamError("item %d: %s" % (n, e))
        if len(set(out)) != len(out):
            raise ParamError("names an item twice")
        return out


def int_range(lo, hi):
    return IntRange(lo, hi)


def enum(*values):
    return Enum(*values)


def list_of(item, most, least=1):
    return ListOf(item, most, least)


FLAG = Flag()
