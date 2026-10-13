"""Host index cache, diff and query, and the `vpscfg index` grammar.

  vpscfg index <host> [--json|--yaml] [--section a,b] [--no-save]
  vpscfg index --all [--json|--yaml]
  vpscfg index diff <host> [--json]
  vpscfg index query '<expr>' [--json|--hosts]

The cache is <estate>/index/<host>.json, the run before it <host>.prev.json.
A run that asks for a subset of sections, or whose every section failed,
does not touch the cache: a partial or empty document must never rotate a
good one into .prev.

Query expressions are a small jq-like language (see docs/INDEX.md): stages
joined by `|`; a stage is a path (`postgres.databases[]`, `.`) or
`select(<cond>)`, where a condition is `path`, `path OP literal`,
`not ...`, joined by `and` / `or`. OP is == != < <= > >= or `~`
(substring). A path through `[]` matches when ANY element matches.

`cache_status()` is the preflight-facing freshness check (vpsexec runbook
preflight, docs/PREFLIGHT.md "Index-backed preflight"): whether the cached
document for one host is trustworthy enough to answer from, without ever
contacting the host.

Threats:
  - Protects against: a host name escaping the cache directory (HOST_RE, no
    path separators); writing through a symlink planted at the cache path
    (refused); a query expression executing anything (it is parsed by a
    fixed grammar here, never handed to jq or eval); the index being
    committed (inside a git repository the cache path must be git-ignored,
    checked with `git check-ignore` before every write; no git, no write;
    git is pinned by vpscfg/gitcmd.py, so PATH, the environment, global
    config and a repository's core.fsmonitor cannot answer for it);
    preflight trusting a planted or stale cache (`cache_status` refuses
    anything but a regular, non-symlink, 0600 file owned by the caller's own
    uid, with a known index_version and a collected_at that is neither
    future-dated by more than 60s nor older than the caller's max age — any
    other shape is "not usable", never "usable", so the caller must fall
    back to a live read or skip, never treat it as a pass).
  - Does NOT protect against: someone with write access to the estate
    editing the cache. It is an observation record, not evidence; the
    journal is the evidence store. `cache_status` is advisory input only
    (S11): it never authorises anything and a caller that ignores its
    refusal and reads the file anyway is not this module's problem to stop.
"""
import datetime
import json
import os
import re
import stat
import sys
from pathlib import Path

from . import hostindex
from .gates import Refused
from .probe import HOST_RE

CACHE_DIRNAME = "index"
# A cache dated more than this far into the future is untrustworthy (clock
# skew, or something other than `vpscfg index` wrote it).
CACHE_FUTURE_SKEW_SECONDS = 60
INDEX_MAX_AGE_DEFAULT_HOURS = 12
INDEX_MAX_AGE_CEILING_HOURS = 24
_COLLECTED_AT_FMT = "%Y-%m-%dT%H:%M:%SZ"
# The document formats this tool can read: a cache from a newer (or forged)
# writer is not trusted to mean what this reader thinks it means.
KNOWN_INDEX_VERSIONS = frozenset([hostindex.INDEX_VERSION])


def cache_dir():
    from . import estate
    return estate.root() / CACHE_DIRNAME


def _paths(host, directory):
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host name %r" % host)
    d = Path(directory)
    return d / ("%s.json" % host), d / ("%s.prev.json" % host)


def max_age_seconds(limits, default_hours=INDEX_MAX_AGE_DEFAULT_HOURS,
                    ceiling_hours=INDEX_MAX_AGE_CEILING_HOURS):
    """The governor's `limits.index_max_age_hours`, clamped to (0, ceiling].
    Never raises: a missing or malformed value falls back to the default,
    exactly like every other `limits.*` read in this tool."""
    hours = (limits or {}).get("index_max_age_hours", default_hours)
    if isinstance(hours, bool) or not isinstance(hours, (int, float)) or hours <= 0:
        hours = default_hours
    return min(float(hours), float(ceiling_hours)) * 3600.0


def _parse_collected_at(text):
    if not isinstance(text, str):
        return None
    try:
        return datetime.datetime.strptime(text, _COLLECTED_AT_FMT).replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def cache_status(host, directory, max_age, now=None):
    """-> (doc, age_seconds, None) when the cached index for `host` at
    <directory>/<host>.json is usable, or (None, None, reason) when it is
    not. Never raises and never follows a symlink.

    Usable means: a regular file (not a symlink), owned by the CALLING
    user's uid, mode exactly 0600, a document for this same `host` with a
    known `index_version`, and a `collected_at` that parses, is not more than 60s in the future, and
    is no older than `max_age` seconds. The document's SECTIONS are not
    examined here — whether the section a caller needs has an `error` or
    `unavailable` is that caller's own check, since only it knows which
    section it needs."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cur, _ = _paths(host, directory)
    try:
        st = os.lstat(str(cur))
    except OSError:
        return None, None, "index missing"
    if stat.S_ISLNK(st.st_mode):
        return None, None, "index is a symlink"
    if not stat.S_ISREG(st.st_mode):
        return None, None, "index is not a regular file"
    if st.st_uid != os.getuid():
        return None, None, "index owned by uid %d, not this user" % st.st_uid
    mode = stat.S_IMODE(st.st_mode)
    if mode != 0o600:
        return None, None, "index mode %04o, not 0600" % mode
    try:
        # O_NOFOLLOW: the lstat above already proved this path is not itself
        # a symlink, but a TOCTOU swap between the two calls must not be
        # followed either. And the checks are repeated on the OPENED file
        # (fstat), so a regular file swapped in between — another owner, a
        # looser mode, a FIFO — is judged on what is actually read (L6).
        fd = os.open(str(cur), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "r") as f:
            fst = os.fstat(f.fileno())
            if not stat.S_ISREG(fst.st_mode):
                return None, None, "index is not a regular file (as opened)"
            if fst.st_uid != os.getuid():
                return None, None, "index owned by uid %d, not this user (as opened)" \
                    % fst.st_uid
            if stat.S_IMODE(fst.st_mode) != 0o600:
                return None, None, "index mode %04o, not 0600 (as opened)" \
                    % stat.S_IMODE(fst.st_mode)
            doc = json.load(f)
    except (OSError, ValueError) as e:
        return None, None, "index unreadable or corrupt (%s)" % e
    if not isinstance(doc, dict) or doc.get("index_version") is None:
        return None, None, "index has no index_version"
    # save() names the file after doc["host"], so an honest cache always
    # matches; a copied or renamed file describing another host never counts.
    if doc.get("host") != host:
        return None, None, "index describes host %r, not %r" % (doc.get("host"), host)
    version = doc.get("index_version")
    if isinstance(version, bool) or not isinstance(version, int) \
            or version not in KNOWN_INDEX_VERSIONS:
        return None, None, "index_version %r is not one this tool knows (%s)" % (
            version, ", ".join(str(v) for v in sorted(KNOWN_INDEX_VERSIONS)))
    when = _parse_collected_at(doc.get("collected_at"))
    if when is None:
        return None, None, "index collected_at is not parseable"
    age = (now - when).total_seconds()
    if age < -CACHE_FUTURE_SKEW_SECONDS:
        return None, None, "index is dated %.0fs in the future" % -age
    if age > max_age:
        return None, None, "index stale %.0fh" % (age / 3600.0)
    return doc, max(age, 0.0), None


def _git_repo_of(path):
    """The nearest ancestor holding .git, or None."""
    p = Path(os.path.realpath(str(path)))
    for d in [p] + list(p.parents):
        if (d / ".git").exists():
            return d
    return None


def require_ignored(path):
    """The index names roles, databases, users and env-var names: an
    observation record that must never be committed (M4). Inside a git
    repository the cache path must be ignored by git, or nothing is written;
    if git cannot answer, nothing is written either (fail closed)."""
    repo = _git_repo_of(Path(path).parent)
    if repo is None:
        return
    from . import gitcmd  # pinned binary, minimal env, no global config/fsmonitor
    try:
        rc, _ = gitcmd.run(repo, "check-ignore", "-q", "--",
                           os.path.relpath(os.path.realpath(str(path)), str(repo)))
    except Refused as e:
        raise Refused("cannot ask git whether %s is ignored (%s); not writing the "
                      "index into a repository that might commit it" % (path, e))
    if rc != 0:
        raise Refused("%s is inside the git repository %s and is NOT ignored — the "
                      "index must never be committed. Add `/%s/` to that repository's "
                      ".gitignore, then re-run." % (path, repo, CACHE_DIRNAME))


def save(doc, directory):
    """Write <host>.json, keeping the previous one as <host>.prev.json."""
    cur, prev = _paths(doc["host"], directory)
    d = Path(directory)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    for p in (cur, prev):
        require_ignored(p)
    for p in (cur, prev):
        if p.is_symlink():
            raise Refused("refusing to write through a symlink at %s" % p)
    tmp = d / (".%s.json.tmp" % doc["host"])
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")
    if cur.exists():
        os.replace(str(cur), str(prev))
    os.replace(str(tmp), str(cur))
    return cur


def load(host, directory, previous=False):
    cur, prev = _paths(host, directory)
    path = prev if previous else cur
    if not path.exists():
        return None
    return json.loads(path.read_text())


def load_all(directory):
    out = {}
    d = Path(directory)
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        if p.name.endswith(".prev.json") or p.name.startswith("."):
            continue
        try:
            doc = json.loads(p.read_text())
        except ValueError:
            continue
        if isinstance(doc, dict) and doc.get("host"):
            out[doc["host"]] = doc
    return out


def saveable(doc):
    """Full set of sections, and at least one that did not fail."""
    sections = doc.get("sections") or {}
    if sorted(sections) != sorted(hostindex.SECTIONS):
        return False
    return any(not (isinstance(v, dict) and "error" in v) for v in sections.values())


# ---- diff ---------------------------------------------------------------

_IDENTITY = ("id", "name", "router")


def _flatten(node, prefix, out):
    if isinstance(node, dict):
        if not node:
            out[prefix or "."] = {}
        for k, v in node.items():
            _flatten(v, "%s.%s" % (prefix, k) if prefix else k, out)
    elif isinstance(node, list):
        if not node:
            out[prefix] = []
        for i, v in enumerate(node):
            key = None
            if isinstance(v, dict):
                key = next((v[f] for f in _IDENTITY if isinstance(v.get(f), (str, int))), None)
            if key is None and isinstance(v, (str, int, float, bool)) and not isinstance(v, bool):
                key = v
            _flatten(v, "%s[%s]" % (prefix, json.dumps(key) if key is not None else i), out)
    else:
        out[prefix] = node


def diff(old, new):
    """[(op, path, old, new)] over two documents' sections, sorted by path.
    List items are matched by id/name/router (or by value), so a reorder is
    not a change. collected_at is not compared; index_version is."""
    a, b = {}, {}
    _flatten((old or {}).get("sections") or {}, "", a)
    _flatten((new or {}).get("sections") or {}, "", b)
    if (old or {}).get("index_version") != (new or {}).get("index_version"):
        a["index_version"] = (old or {}).get("index_version")
        b["index_version"] = (new or {}).get("index_version")
    out = []
    for path in sorted(set(a) | set(b)):
        if path not in a:
            out.append(("+", path, None, b[path]))
        elif path not in b:
            out.append(("-", path, a[path], None))
        elif a[path] != b[path]:
            out.append(("~", path, a[path], b[path]))
    return out


def render_diff(host, changes, old, new):
    lines = ["index diff %s: %s -> %s" % (host, (old or {}).get("collected_at"),
                                          (new or {}).get("collected_at"))]
    for op, path, before, after in changes:
        if op == "+":
            lines.append("  + %s = %s" % (path, json.dumps(after)))
        elif op == "-":
            lines.append("  - %s = %s" % (path, json.dumps(before)))
        else:
            lines.append("  ~ %s: %s -> %s" % (path, json.dumps(before), json.dumps(after)))
    lines.append("%d change(s)" % len(changes))
    return "\n".join(lines)


# ---- query --------------------------------------------------------------

_TOKEN = re.compile(r'\s*(?:(?P<str>"(?:[^"\\]|\\.)*")|(?P<num>-?\d+(?:\.\d+)?)|'
                    r'(?P<op>==|!=|<=|>=|<|>|~)|(?P<punct>[()|])|'
                    r'(?P<path>\.?[A-Za-z_][A-Za-z0-9_-]*(?:\[\d*\])*'
                    r'(?:\.[A-Za-z_][A-Za-z0-9_-]*(?:\[\d*\])*)*|\.))')
_SEG = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)((?:\[\d*\])*)")


def _tokens(expr):
    pos, out = 0, []
    expr = expr.rstrip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise Refused("query: cannot parse at %r" % expr[pos:pos + 20])
        pos = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


def _path(text):
    if text == ".":
        return []
    steps = []
    for name, brackets in _SEG.findall(text.lstrip(".")):
        steps.append(("key", name))
        for idx in re.findall(r"\[(\d*)\]", brackets):
            steps.append(("each", None) if idx == "" else ("index", int(idx)))
    return steps


def _walk(node, steps):
    if not steps:
        yield node
        return
    (kind, arg), rest = steps[0], steps[1:]
    if kind == "key":
        if isinstance(node, dict) and arg in node:
            for v in _walk(node[arg], rest):
                yield v
    elif kind == "index":
        if isinstance(node, list) and -len(node) <= arg < len(node):
            for v in _walk(node[arg], rest):
                yield v
    elif isinstance(node, list):
        for item in node:
            for v in _walk(item, rest):
                yield v


def _literal(kind, text):
    if kind == "str":
        return json.loads(text)
    if kind == "num":
        return float(text) if "." in text else int(text)
    if kind == "path" and text in ("true", "false", "null"):
        return {"true": True, "false": False, "null": None}[text]
    raise Refused("query: expected a literal, got %r" % text)


def _compare(value, op, lit):
    try:
        if op == "==":
            return value == lit
        if op == "!=":
            return value != lit
        if op == "~":
            return isinstance(value, str) and isinstance(lit, str) and lit in value
        if isinstance(value, bool) or value is None or isinstance(lit, bool) or lit is None:
            return False
        return {"<": value < lit, "<=": value <= lit, ">": value > lit, ">=": value >= lit}[op]
    except TypeError:
        return False


class _Cond(object):
    def __init__(self, toks):
        self.toks, self.i = toks, 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def parse_or(self):
        terms = [self.parse_and()]
        while self.peek() == ("path", "or"):
            self.take()
            terms.append(self.parse_and())
        return lambda n: any(t(n) for t in terms)

    def parse_and(self):
        terms = [self.parse_term()]
        while self.peek() == ("path", "and"):
            self.take()
            terms.append(self.parse_term())
        return lambda n: all(t(n) for t in terms)

    def parse_term(self):
        if self.peek() == ("path", "not"):
            self.take()
            inner = self.parse_term()
            return lambda n: not inner(n)
        if self.peek() == ("punct", "("):
            self.take()
            inner = self.parse_or()
            if self.take() != ("punct", ")"):
                raise Refused("query: missing )")
            return inner
        kind, text = self.take()
        if kind != "path":
            raise Refused("query: expected a path, got %r" % text)
        steps = _path(text)
        if self.peek()[0] == "op":
            op = self.take()[1]
            lit = _literal(*self.take())
            return lambda n: any(_compare(v, op, lit) for v in _walk(n, steps))
        return lambda n: any(v not in (None, False, [], {}, "", 0) for v in _walk(n, steps))


def compile_query(expr):
    """-> function(doc) -> [values]. Raises Refused on a bad expression."""
    if not isinstance(expr, str) or not expr.strip() or len(expr) > 1000:
        raise Refused("query: empty or too long")
    toks = _tokens(expr)
    stages, cur, depth = [], [], 0
    for tok in toks:
        if tok == ("punct", "("):
            depth += 1
        elif tok == ("punct", ")"):
            depth -= 1
        if tok == ("punct", "|") and depth == 0:
            stages.append(cur)
            cur = []
        else:
            cur.append(tok)
    stages.append(cur)
    fns = []
    for st in stages:
        if not st:
            raise Refused("query: empty stage")
        if st[0] == ("path", "select"):
            if len(st) < 3 or st[1] != ("punct", "(") or st[-1] != ("punct", ")"):
                raise Refused("query: select needs select(<condition>)")
            p = _Cond(st[2:-1])
            cond = p.parse_or()
            if p.i != len(p.toks):
                raise Refused("query: unexpected %r in select" % (p.toks[p.i][1],))
            fns.append(lambda vals, c=cond: [v for v in vals if c(v)])
        elif len(st) == 1 and st[0][0] == "path":
            steps = _path(st[0][1])
            fns.append(lambda vals, s=steps: [x for v in vals for x in _walk(v, s)])
        else:
            raise Refused("query: a stage is a path or select(...)")

    def run(doc):
        vals = [doc]
        for fn in fns:
            vals = fn(vals)
        return vals
    return run


def query(expr, docs):
    """[(host, value)] across cached documents, hosts in sorted order.
    Paths start at the document's sections: `postgres.databases[]`."""
    fn = compile_query(expr)
    return [(host, v) for host in sorted(docs)
            for v in fn(docs[host].get("sections") or {})]


# ---- output -------------------------------------------------------------

def dump(doc, fmt):
    if fmt == "yaml":
        try:
            import yaml
        except ImportError:
            raise Refused("PyYAML is unavailable — use --json")
        return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False)
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def summary(doc):
    parts = []
    for s, v in (doc.get("sections") or {}).items():
        if isinstance(v, dict) and "error" in v:
            parts.append("%s=ERROR" % s)
        elif isinstance(v, dict) and "unavailable" in v:
            parts.append("%s=unavailable" % s)
        else:
            parts.append("%s=ok" % s)
    return "%s: %s" % (doc.get("host"), " ".join(parts))


def _failed(doc):
    return [s for s, v in (doc.get("sections") or {}).items()
            if isinstance(v, dict) and "error" in v]


def cli(argv, hosts_for_all=None, collect_kwargs=None, directory=None, out=None, err=None):
    """`vpscfg index ...`. Read-only on every host; writes only the cache.
    hosts_for_all: callable returning the governed hosts (for --all)."""
    out, err = out or sys.stdout, err or sys.stderr
    args = list(argv)
    fmt = "yaml" if "--yaml" in args else "json"
    flags = [a for a in args if a.startswith("--")]
    words = [a for a in args if not a.startswith("--")]
    directory = directory or cache_dir()
    kw = dict(collect_kwargs or {})

    if words[:1] == ["diff"]:
        if len(words) != 2:
            raise Refused("usage: vpscfg index diff <host>")
        host = words[1]
        old, new = load(host, directory, previous=True), load(host, directory)
        if new is None:
            raise Refused("no cached index for %s — run `vpscfg index %s` first" % (host, host))
        if old is None:
            raise Refused("only one index for %s — diff needs two runs" % host)
        changes = diff(old, new)
        if "--json" in flags:
            out.write(json.dumps([{"op": o, "path": p, "old": a, "new": b}
                                  for o, p, a, b in changes], indent=2) + "\n")
        else:
            out.write(render_diff(host, changes, old, new) + "\n")
        return 1 if changes else 0

    if words[:1] == ["query"]:
        if len(words) != 2:
            raise Refused("usage: vpscfg index query '<expr>'")
        results = query(words[1], load_all(directory))
        if "--hosts" in flags:
            for h in sorted(set(h for h, _ in results)):
                out.write(h + "\n")
        elif "--json" in flags:
            out.write(json.dumps([{"host": h, "value": v} for h, v in results],
                                 indent=2, sort_keys=True) + "\n")
        else:
            for h, v in results:
                out.write("%s\t%s\n" % (h, json.dumps(v, sort_keys=True)))
        return 0 if results else 1

    known = {"--json", "--yaml", "--all", "--no-save"}
    section_spec = None
    for a in flags:
        if a.startswith("--section="):
            section_spec = a.split("=", 1)[1]
        elif a == "--section":
            i = args.index(a)
            if i + 1 >= len(args):
                raise Refused("--section needs a list, e.g. --section postgres,redis")
            section_spec = args[i + 1]
            words = [w for w in words if w != section_spec]
        elif a not in known:
            raise Refused("unknown flag %s" % a)
    sections = hostindex.parse_sections(section_spec)

    if "--all" in flags:
        if words:
            raise Refused("--all takes no host")
        targets = list(hosts_for_all() if hosts_for_all else [])
    else:
        if len(words) != 1:
            raise Refused("usage: vpscfg index <host>|--all [--json|--yaml] [--section a,b]")
        targets = words

    docs, failures = {}, 0
    for host in targets:
        doc = hostindex.collect(host, sections=sections, **kw)
        docs[host] = doc
        bad = _failed(doc)
        failures += 1 if bad else 0
        if "--no-save" not in flags and saveable(doc):
            path = save(doc, directory)
            err.write("wrote %s\n" % path)
        elif "--no-save" not in flags:
            err.write("%s: not cached (%s)\n" % (
                host, "partial section list" if sorted(doc["sections"]) != sorted(hostindex.SECTIONS)
                else "every section failed"))
        if bad:
            err.write("%s: section error(s): %s\n" % (host, ", ".join(bad)))
    if "--all" in flags and not ({"--json", "--yaml"} & set(flags)):
        for host in targets:
            out.write(summary(docs[host]) + "\n")
    else:
        out.write(dump(docs if "--all" in flags else docs[targets[0]], fmt))
    return 1 if failures else 0
