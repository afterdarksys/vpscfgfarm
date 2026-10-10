"""Mask secret VALUES in remote command output before anyone sees it.

The door already refuses credential PATHS (policies/secrets.yaml). That stops
`cat .env.production`; it does not stop the secret showing up anyway —
`kubectl get deploy -o yaml` with an inline DB password, `docker inspect`
Env, `ps` argv, a DSN in a log line. A database password can reach an agent
transcript exactly that way, through a local sed "filter" that does not
filter on macOS (BSD sed). Filters belong in the door, not in whoever is
holding the pipe.

So every byte of remote output that vpsexec, `vpscfg logs`, probes, preflight
and the executor hand back — to the terminal, to --compare, to the journal
(and via the journal to telemetry and `vpsexec last`) — passes through mask()
first.

A masked value reads `<masked>`. Internally each carries an HMAC-SHA256 tag
(`<masked:1a2b3c4d>`) under a key drawn from the OS CSPRNG once per process
and never stored; `mask(text, tags=True)` keeps it, and vpsexec uses that only
as --compare's grouping key, so two hosts with different passwords are not
reported as agreeing. Tags are never printed, journaled or sent: within one
process a planted `password=<guess>` log line would share the real secret's
tag, which is a guessing oracle.

Threats:
  - Protects against: secret values printed by a READ (env dumps, manifests
    in YAML/JSON/escaped JSON, k8s Secret data, Vault kv tables and JSON,
    DSNs/URLs with userinfo, Authorization/Cookie headers, CLI flags and
    argv lists, redis CONFIG GET, systemd unit continuations, PEM private
    keys, crypt/htpasswd/SCRAM hashes, known token formats, Vault init
    output) landing in a terminal, an agent transcript, the local journal or
    the control plane. ANSI escapes, zero-width and fullwidth characters are
    normalised first, so they cannot split a key from its value. Masking
    happens before storage, so nothing downstream can forget it. A masker bug
    or an input over MAX_INPUT fails CLOSED: withheld, never passed through.
  - Does NOT protect against: a bare secret with no context (a jsonpath that
    prints only the base64, `echo $PW`), secrets in shapes not listed above,
    a value that starts with `$` and looks like a variable reference, a
    secret that is itself a valid IP address/CIDR list under a key whose only
    secret word is bare `private` (PRIVATE="10.0.0.0/8 ..." is a firewall
    allowlist and is shown; any non-address token keeps it masked), or an
    operator who reads the host themselves. It does not scrub journal
    records written before it existed (hash-chained; they are masked on
    RENDER by vpsexeclog). The fix for a leaked value is rotation.

Over-masking is the accepted failure direction: `password_changed_at: 2024`
comes out masked. A masked timestamp costs a second look; an unmasked
password costs a rotation.
"""
import functools
import hashlib
import hmac
import ipaddress
import re
import secrets as _secrets
import unicodedata

MASK = "<masked"  # prefix; a full marker is <masked> or <masked:xxxxxxxx>
MAX_INPUT = 4 * 1024 * 1024
WITHHELD = "<output withheld: secret masker failed (%s) — nothing shown, fail closed>"
OVERSIZE = ("<output withheld: %d chars exceeds the secret masker's %d-char limit — "
            "narrow the read (tail -n, grep, --since)>")

_RUN_KEY = _secrets.token_bytes(32)


@functools.lru_cache(maxsize=8192)
def _tag(value):
    digest = hmac.new(_RUN_KEY, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()
    return "<masked:%s>" % digest[:8]


# ---------------------------------------------------------------------------
# vocabulary
# ---------------------------------------------------------------------------

# Identifier fragments that mark the value as secret. Whole words carry a
# right boundary that still allows a plural `s` or a separator, so
# `passwords`/`tokens`/`secret_key` count and container names such as
# `passwordcheck`, `secretstore`, `tokenmint` do not. Short fragments (pass,
# auth, pw, key, private) are letter-bounded on both sides.
_R = r"(?-i:(?![a-z]))"               # right boundary: camel hump or non-letter
_L = r"(?-i:(?<![a-zA-Z])|(?<=[a-z])(?=[A-Z]))"  # left: word start or camel hump
_WORD_STRONG = (r"(?:(?:password|passwd|passphrase|passwort|pwd|pgpass|secret|token|credential"
                r"|hmac|jwt|signing|basicauth|api-?key|apikey|access-?key|private-?key|privkey"
                r"|auth-?key|authkey|requirepass|masterauth|dsn|salt)s?" + _R +
                r"|secret[_-]?key|signing[_-]?key|database[_-]?url|db[_-]?url"
                r"|conn(?:ection)?[_-]?str(?:ing)?|webhook[_-]?url"
                r"|" + _L + r"pass" + _R + r"|" + _L + r"auth" + _R + r"|" + _L + r"pw" + _R +
                r"|" + _L + r"keys?" + _R + r")")
# Bare `private` is the one weak word: a generated firewall script sets
# PRIVATE="10.0.0.0/8 ..." (the RFC 1918 allowlist), and masking it broke the
# read-back of an installed firewall script against its committed copy.
# It stays a secret key; only a key that is secret SOLELY because of it, with
# a value that is strictly a list of IP addresses/CIDRs, is left readable
# (_address_list). private_key / privkey / PEM blocks are always masked.
_WORD = r"(?:" + _WORD_STRONG + r"|" + _L + r"private" + _R + r")"
# Bounded: an unbounded [\w.-]* around an alternation is quadratic on long
# word runs. 64 is longer than any real variable name.
_KEY_STRONG_FULL = re.compile(r"(?i)^[\w.\-]{0,64}?" + _WORD_STRONG + r"[\w.\-]{0,64}$")
_KEY = r"[\w.\-]{0,64}?" + _WORD + r"[\w.\-]{0,64}"
_KEY_FULL = re.compile(r"(?i)^[\w.\-]{0,64}?" + _WORD + r"[\w.\-]{0,64}$")
_FLAG_WORDS = r"(?:--?" + _KEY + r"|requirepass|masterauth)"

# Values that are references or already masked: keep them readable.
_KEEP = re.compile(r'^(?:\$\{?\w{1,128}\}?|<masked(?::[0-9a-f]{8})?>|""|\'\'|\*+'
                   r"|[|>][+-]?\d?)$")


_TAG_RE = re.compile(r"<masked:[0-9a-f]{8}>")


def untag(text):
    """<masked:1a2b3c4d> -> <masked>. Tags are an in-process grouping key for
    --compare; anywhere a reader or an injected log line could line one up
    with a guess (journal, telemetry, terminal), they are removed."""
    return _TAG_RE.sub("<masked>", text) if text else text


def _keep(value):
    return bool(_KEEP.match(value.strip()))


def _masked(value):
    return value if _keep(value) else _tag(value)


# A list of IPv4/IPv6 addresses or CIDRs, quoted or not, separated by spaces,
# tabs or commas. Each token must pass the charset check AND parse with the
# stdlib ipaddress module; anything else (a word, `10.0.0.1x`, a trailing
# secret, an escaped quote, a zone id, a newline) is not a list. Linear:
# a length cap first, then one split and one fixed-width fullmatch per token.
_ADDR_MAX_LEN = 4096
_ADDR_MAX_TOKENS = 256
_ADDR_SPLIT = re.compile(r"[ \t]*,[ \t]*|[ \t]+")
_ADDR_TOKEN = re.compile(r"[0-9A-Fa-f:.]{2,45}(?:/[0-9]{1,3})?")


def _address_list(key, value):
    """True only when `key` is secret solely through bare `private` and
    `value` is strictly an address/CIDR list. Fails closed: any doubt -> False."""
    if not value or len(value) > _ADDR_MAX_LEN or _KEY_STRONG_FULL.match(key):
        return False
    if value[0] in "\"'":
        if len(value) < 3 or value[-1] != value[0]:
            return False
        value = value[1:-1]
    toks = _ADDR_SPLIT.split(value.strip(" \t"))
    if not 0 < len(toks) <= _ADDR_MAX_TOKENS:
        return False
    for tok in toks:
        if not _ADDR_TOKEN.fullmatch(tok):
            return False
        try:
            ipaddress.ip_network(tok, strict=False)
        except ValueError:
            return False
    return True


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------

_ANSI = re.compile(r"\x1b\[[0-9;?]{0,32}[ -/]{0,4}[@-~]|\x1b\][^\x07\x1b]{0,4096}(?:\x07|\x1b\\)?"
                   r"|\x1b[@-Z\\-_]")
_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff\u00ad]")


def _normalise(text):
    """Colour codes and invisible characters can sit between a key and its
    `=` (`grep --color=always`, a pasted zero-width space). Strip them; fold
    fullwidth forms to ASCII so `PASSWORD＝x` is `PASSWORD=x`."""
    text = _ANSI.sub("", text).replace("\v", " ").replace("\f", " ")
    if not text.isascii():
        text = unicodedata.normalize("NFKC", _ZERO_WIDTH.sub("", text))
    return text


# ---------------------------------------------------------------------------
# structural passes
# ---------------------------------------------------------------------------

_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY[A-Z ]{0,20}-----"
                  r"(?:.*?-----END [A-Z0-9 ]{0,40}PRIVATE KEY[A-Z ]{0,20}-----|.*\Z)",
                  re.S)


def _balanced_end(text, i, limit=None):
    """Index just past the bracket closing the one at text[i], string-aware.
    Unterminated -> len(text) (masking to the end is the safe direction), or
    -1 when `limit` is given and no close comes within it."""
    depth, in_str, esc = 0, False, False
    stop = len(text) if limit is None else min(len(text), i + limit)
    for j in range(i, stop):
        c = text[j]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(text) if limit is None or stop == len(text) else -1


_SECRET_KIND = re.compile(r"(?m)^[ \t]*kind:[ \t]*[\"']?Secret[\"']?[ \t]*$"
                          r"|\"kind\"[ \t]*:[ \t]*\"Secret\"")
_JSON_DATA_OPEN = re.compile(r"\"(?:data|stringData)\"\s{0,64}:\s{0,64}\{")
_VAULT_JSON_OPEN = re.compile(r"\"data\"\s{0,64}:\s{0,64}\{\s{0,64}\"data\"\s{0,64}:\s{0,64}\{")
_JSON_STRING_VALUE = re.compile(r"(:\s{0,64})\"((?:[^\"\\]|\\.){0,1048576})\"")


def _mask_json_blocks(text, opener):
    """Mask every string VALUE inside each object `opener` opens: a k8s Secret's
    data (any size — helm release blobs run past 64 KB), Vault kv-v2 data."""
    out, pos = [], 0
    for m in opener.finditer(text):
        if m.start() < pos:
            continue
        start = m.end() - 1
        end = _balanced_end(text, start)
        block = _JSON_STRING_VALUE.sub(lambda v: v.group(1) + '"' + _masked(v.group(2)) + '"',
                                       text[start:end])
        out.append(text[pos:start] + block)
        pos = end
    out.append(text[pos:])
    return "".join(out)


def _json_pair_patterns():
    """k8s env {"name": KEY, "value": V} in both orders, pretty-printed or
    minified, plain or escaped inside an annotation string (last-applied)."""
    pats = []
    pats.append((re.compile(r"('(?i:" + _FLAG_WORDS + r")'\s{0,64},\s{0,64}('))([^'\n]{0,4096})(')"),
                 "fwd"))
    for q, val in (('"', r'(?:[^"\\]|\\.){0,4096}'),
                   (r'\\{1,3}"', r'(?:[^"\\]|\\{1,3}[^"\\]){0,4096}')):
        sp = r"\s{0,64}"
        name = q + "name" + q + sp + ":" + sp + q + "(?i:" + _KEY + ")" + q
        value_key = q + "value" + q + sp + ":" + sp
        pats.append((re.compile("(" + name + sp + "," + sp + value_key + "(" + q + "))(" + val
                                + ")(" + q + ")"), "fwd"))
        pats.append((re.compile("(" + value_key + "(" + q + "))(" + val + ")(" + q + sp + ","
                                + sp + name + ")"), "rev"))
        # argv lists: "--requirepass", "x"  /  "--token","x"
        pats.append((re.compile("(" + q + "(?i:" + _FLAG_WORDS + ")" + q + sp + "," + sp
                                + "(" + q + "))(" + val + ")(" + q + ")"), "fwd"))
    return pats


_JSON_PAIRS = _json_pair_patterns()


def _mask_json_pairs(text):
    for rx, _ in _JSON_PAIRS:
        text = rx.sub(lambda m: m.group(1) + _masked(m.group(3)) + m.group(4), text)
    return text


# ---------------------------------------------------------------------------
# line walker: structure a single regex cannot see
# ---------------------------------------------------------------------------

_YAML_DATA = re.compile(r"^([ \t]*)(?:-[ \t]+)?(?:data|stringData):[ \t]*$")
_YAML_NAME = re.compile(r"^([ \t]*)(-[ \t]+)?name:[ \t]*[\"']?([^\"'\s]{1,200})[\"']?[ \t]*$")
_YAML_KV = re.compile(r"^([ \t]*[^:\n]{1,256}?:)([ \t]*)(.*)$")
# `password: |`, `password: >-`, or `password:` with the value on the next,
# deeper line.
_YAML_HEADER = re.compile(r"(?i)^([ \t]*)(?:-[ \t]+)?[\"']?(" + _KEY + r")[\"']?[ \t]*:[ \t]*"
                          r"(?:[|>][+-]?\d?)?[ \t]*$")
# A secret flag alone on its line: `- --requirepass`, `'--token' \`,
# `1) "requirepass"`, `requirepass` (redis-cli --raw CONFIG GET).
_FLAG_LINE = re.compile(r"(?i)^[ \t]*(?:-[ \t]+)?(?:\d{1,3}\)[ \t]+)?[\"']?" + _FLAG_WORDS
                        + r"[\"']?,?[ \t]*\\?[ \t]*$")
_NEXT_VALUE = re.compile(r"^([ \t]*(?:-[ \t]+)?(?:\d{1,3}\)[ \t]+)?[\"']?)(.*?)([\"']?,?[ \t]*\\?[ \t]*)$")
_VAULT_TABLE_HEAD = re.compile(r"^Key[ \t]+Value[ \t]*$")
_VAULT_TABLE_RULE = re.compile(r"^-{3}[ \t]+-{5}[ \t]*$")
_VAULT_ROW = re.compile(r"^(\S{1,256})([ \t]+)(\S.*)$")


def _indent(line):
    return len(line) - len(line.lstrip(" \t"))


def _mask_deeper(lines, i, base):
    """Mask every non-blank line after i indented deeper than `base`."""
    j = i + 1
    while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > base):
        if lines[j].strip() and not _keep(lines[j]):
            lines[j] = lines[j][:_indent(lines[j])] + _tag(lines[j].strip())
        j += 1
    return j


def _line_pass(text, secret_doc):
    lines = text.split("\n")
    in_vault_data = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("====") and "Data" in stripped:
            in_vault_data = True
        if (_VAULT_TABLE_HEAD.match(line) and i + 1 < len(lines)
                and _VAULT_TABLE_RULE.match(lines[i + 1])):
            j = i + 2
            end = j
            while end < len(lines) and lines[end].strip():
                end += 1
            if any(lines[k].startswith("refresh_interval") for k in range(j, end)):
                in_vault_data = True  # kv-v1 read: no Data header, every row is secret
            while j < len(lines) and lines[j].strip():
                row = _VAULT_ROW.match(lines[j])
                if row and row.group(1) == "refresh_interval":
                    pass
                elif row and (in_vault_data or _KEY_FULL.match(row.group(1))):
                    lines[j] = row.group(1) + row.group(2) + _masked(row.group(3))
                j += 1
            in_vault_data = False
            i = j
            continue
        if ":" in line:
            if secret_doc and "ata:" in line and _YAML_DATA.match(line):
                base = _indent(line)
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > base):
                    kv = _YAML_KV.match(lines[j])
                    if kv and kv.group(3).strip():
                        lines[j] = kv.group(1) + (kv.group(2) or " ") + _masked(kv.group(3))
                    elif not kv and lines[j].strip():
                        lines[j] = lines[j][:_indent(lines[j])] + _masked(lines[j].strip())
                    j += 1
                i = j
                continue
            if line.rstrip()[-1:] in ":|>+-0123456789" and _YAML_HEADER.match(line):
                i = _mask_deeper(lines, i, _indent(line))
                continue
            m = _YAML_NAME.match(line) if "name:" in line else None
            if m and _KEY_FULL.match(m.group(3)):
                col = len(m.group(1)) + len(m.group(2) or "")
                for j in range(i + 1, min(i + 4, len(lines))):
                    nxt = lines[j]
                    if _indent(nxt) != col:
                        break
                    kv = re.match(r"^([ \t]*value:[ \t]*)(.*)$", nxt)
                    if kv:
                        val = kv.group(2).strip()
                        if not val or re.match(r"^[|>][+-]?\d?$", val):
                            _mask_deeper(lines, j, col)
                        else:
                            lines[j] = kv.group(1) + _masked(val)
                        break
        if stripped and len(stripped) < 200 and _FLAG_LINE.match(line):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                nv = _NEXT_VALUE.match(lines[j])
                if nv and nv.group(2) and not nv.group(2).startswith("-"):
                    lines[j] = nv.group(1) + _masked(nv.group(2)) + nv.group(3)
        i += 1
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# inline patterns
# ---------------------------------------------------------------------------

_VAULT_INIT = re.compile(r"(?im)^([ \t]*(?:unseal key \d{1,2}|initial root token|recovery key \d{1,2})"
                         r"[ \t]*:[ \t]*)(\S+)")
_AUTH_HEADER = re.compile(r"(?i)\b((?:proxy-)?authorization[\"']?[ \t]*[:=][ \t]*[\"']?"
                          r"(?:(?:bearer|basic|digest|token|negotiate)[ \t]+)?)([^\s\"',]{1,4096})")
_BEARER = re.compile(r"(?i)\b(bearer[ \t]+)([A-Za-z0-9._~+/=\-]{8,4096})")
_COOKIE = re.compile(r"(?i)(?<![\w-])((?:set-)?cookie[\"']?[ \t]*:[ \t]*[\"']?)([^\"\n\r]{1,4096})")
# scheme://user: — the password then runs to the LAST @ before the token
# ends (base64 passwords contain / and @). Found in Python, not by a greedy
# regex: backtracking 1 KB at every `://` was 19 s/MB on hostile input.
_URL_PREFIX = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{0,31}://[^\s:/@\"'<>]{0,256}):")
_URL_STOP = re.compile(r"[\s\"'<>]")
_MYSQL_DSN = re.compile(r"(?<![\w/])([\w.\-]{1,64}):([^\s@:\"']{1,256})(@(?:tcp|unix)\()")
_CURL_USER = re.compile(r"(?<!\S)(-u|--user)([ \t]+[^\s:]{0,256}):(\S{1,1024})")
_CLI_GATES = ("redis-cli", "mysql", "mariadb", "sshpass")
_TOKEN_RUN = re.compile(r"\S{1,4096}")
# Space-separated env/config, whole line: `CF_API_TOKEN abc`. Case-sensitive
# upper-case names only: "token refreshed ok" is a log line, not a pair.
_SPACED_ENV = re.compile(r"(?m)^([ \t]*[A-Z][A-Z0-9_]{0,64}(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY"
                         r"|PRIVATE_KEY|AUTHKEY|AUTH_KEY)[A-Z0-9_]{0,64}[ \t]+)(\S{1,4096})[ \t]*$")
# redis-cli prompt `redis> AUTH [user] pass`.
_REDIS_AUTH = re.compile(r"(?m)^((?:[\w.:\-]{0,64}>[ \t]*)?(?:AUTH|auth)[ \t]+)(\S{1,1024}(?:[ \t]+\S{1,1024})?)[ \t]*$")
# SQL: ALTER/CREATE ROLE ... PASSWORD '...' in postgres statement logs.
_SQL_PASSWORD = re.compile(r"(?i)(\bpassword[ \t]+)'((?:[^'\n]|''){1,4096})'")
# nginx header directives: proxy_set_header Authorization "Basic x";
_NGINX_HEADER = re.compile(r"(?i)\b((?:proxy_set_header|add_header|more_set_headers|grpc_set_header)[ \t]+"
                           r"[\"']?([\w\-]{1,64})[\"']?[ \t]+)(\"[^\"\n]{0,4096}\"|'[^'\n]{0,4096}'|[^;\s]{1,4096})")


def _nginx_header(m):
    name = m.group(2).lower()
    if name in ("authorization", "proxy-authorization", "cookie") or _KEY_FULL.match(name):
        v = m.group(3)
        if v[:1] in "\"'":
            return m.group(1) + v[0] + _masked(v[1:-1]) + v[0]
        return m.group(1) + _masked(v)
    return m.group(0)


def _line_repl(m):
    value = m.group(3).rstrip()
    if _address_list(m.group(2), value):
        return m.group(0)
    return m.group(1) + _masked(value)


def _mask_lines(text):
    """_LINE per line, only where a separator exists: a multiline regex tried
    its key alternation at every line start (15 us/line on a 250k-line log)."""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if ("=" in line or ": " in line or ":\t" in line) and len(line) > 2:
            lines[i] = _LINE.sub(_line_repl, line)
    return "\n".join(lines)


def _mask_urls(text):
    out, pos, stop = [], 0, -1
    for m in _URL_PREFIX.finditer(text):
        if m.start() < pos:
            continue
        if stop < m.end():
            s = _URL_STOP.search(text, m.end())
            stop = s.start() if s else len(text)
        at = text.rfind("@", m.end(), min(stop, m.end() + 1024))
        if at > m.end():
            out.append(text[pos:m.end()] + _masked(text[m.end():at]))
            pos = at
    out.append(text[pos:])
    return "".join(out)


def _mask_cli(text):
    """redis-cli -a X, mysql -pX, sshpass -p X: tokenised per line, linear.
    (A lazy regex re-scanned 512 chars per `mysql` occurrence: 10 s/MB.)"""
    lines = text.split("\n")
    for li, line in enumerate(lines):
        low = line.lower()
        if not any(g in low for g in _CLI_GATES):
            continue
        toks = list(_TOKEN_RUN.finditer(line))
        spans, mode, want_next = [], None, False
        for t in toks:
            w = t.group(0)
            base = w.rsplit("/", 1)[-1].lower()
            if want_next:
                if not w.startswith("-"):
                    spans.append((t.start(), t.end()))
                want_next = False
                continue
            if base in ("redis-cli", "sshpass") or base.startswith(("mysql", "mariadb")):
                mode = base
                continue
            if mode == "redis-cli" and w == "-a":
                want_next = True
            elif mode == "sshpass" and w == "-p":
                want_next = True
            elif mode == "sshpass" and w.startswith("-p") and len(w) > 2:
                spans.append((t.start() + 2, t.end()))
            elif mode and mode.startswith(("mysql", "mariadb")) and w.startswith("-p") and len(w) > 2:
                spans.append((t.start() + 2, t.end()))
        for a, b in reversed(spans):
            line = line[:a] + _masked(line[a:b]) + line[b:]
        lines[li] = line
    return "\n".join(lines)
# redis `requirepass x`, netrc `login u password x`. Bare "password <word>" is
# NOT matched: postgres says "password authentication failed", and that line
# is what an incident read is for.
_SPACED = re.compile(r"(?i)(?<![\w.\-])((?:requirepass|masterauth)[ \t]+"
                     r"|login[ \t]+\S{1,256}[ \t]+password[ \t]+)(\S{1,4096})")
_XML = re.compile(r"(?i)<([\w.\-:]{0,64}(?:password|passwd|secret|token|apikey|api_key|privatekey)"
                  r"[\w.\-:]{0,64})>([^<]{1,4096})</\1>")

# KEY=value / KEY: value at line start (.env, YAML, compose, `export`,
# systemd Environment=). Value runs to end of line: spaces included. `:`
# must be followed by whitespace — `tokenmint:v1.1.0` is an image, not a pair.
_LINE = re.compile(r"(?im)^([ \t]*(?:export[ \t]+|-[ \t]+|Environment=[\"']?)?(" + _KEY
                   + r")[ \t]*(?:=|:(?=[ \t]))[ \t]*)([^\s\"'][^\n]*)$")

# KEY=value anywhere. Generic key; the secret-word test runs in Python on the
# key alone (a 25-way alternation at every offset was 2 s/MB), and the value
# is parsed only for a secret key (parsing every `a=` was 90 s/MB).
_INLINE_KEY = re.compile(r"(?<![\w.\-])(\\{0,3}[\"']?)([\w.\-]{1,160})\1([ \t]*[:=][ \t]*)")
_BLOCK_LIMIT = 65536
_BLOCK_SCALAR = re.compile(r'"((?:[^"\\]|\\.){0,1048576})"(\s{0,64}:)?|([^\s,\[\]{}:"]{1,4096})(\s{0,64}:)?')
_TAGLIKE = re.compile(r"^(?:latest|stable|edge|main|master|alpine|slim|bookworm|bullseye|buster"
                      r"|\d{1,12}(?:\.\d{1,6}){0,4}(?:-[a-z0-9.]{1,32})?"
                      r"|v\d{1,6}(?:\.\d{1,6}){0,4}(?:-[\w.]{1,32})?)$")
_UNQUOTED = re.compile(r"[^\s\"',;&}\]\x00]{1,1024}")

# --password value / '--token' 'value' (space-separated flag, same line).
_FLAG = re.compile(r"(?i)(?<![\w\-'\"])(['\"]?--?" + _KEY + r"['\"]?)([ \t]+)(?!-)(\S{1,4096})")

# Token formats that are secret on sight, context or not. One pattern per
# family, each run only when its gate substrings occur: a single 17-way
# alternation tried at every offset was 3 s/MB. Each starts with a
# left-boundary lookbehind over its own charset, so a failed match never
# rescans the same run from the next offset.
_TOKEN_FAMILIES = [(gates, re.compile(rx)) for gates, rx in (
    (("AKIA", "ASIA"), r"(?<![0-9A-Z])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])"),
    (("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), r"(?<![\w])gh[pousr]_[A-Za-z0-9]{36,255}"),
    (("github_pat_",), r"(?<![\w])github_pat_[A-Za-z0-9_]{20,255}"),
    (("glpat-",), r"(?<![\w\-])glpat-[A-Za-z0-9_\-]{20,255}"),
    (("xox",), r"(?<![\w\-])xox[abprs]-[A-Za-z0-9\-]{10,255}"),
    (("sk-",), r"(?<![\w\-])sk-[A-Za-z0-9_\-]{20,255}"),
    (("k_live_", "k_test_"), r"(?<![\w])[rs]k_(?:live|test)_[A-Za-z0-9]{10,255}"),
    (("hvs.", "hvb."), r"(?<![\w.\-])hv[sb]\.[A-Za-z0-9_\-]{20,255}"),
    (("AIza",), r"(?<![\w\-])AIza[0-9A-Za-z_\-]{35}"),
    (("tskey-",), r"(?<![\w\-])tskey-(?:auth|api|client|scim|webhook)-[\w\-]{10,255}"),
    (("AGE-SECRET-KEY-1",), r"(?<![\w\-])AGE-SECRET-KEY-1[0-9A-Z]{58}"),
    (("K10",), r"(?<![\w])K10[0-9a-f]{20,128}::[\w.\-]{1,64}:[^\s'\"]{8,256}"),
    ((".eyJ", "eyJ"), r"(?<![\w\-])eyJ[A-Za-z0-9_\-]{8,4096}\.[A-Za-z0-9_\-]{8,4096}\.[A-Za-z0-9_\-]{8,4096}"),
    (("$apr1$", "$1$", "$2a$", "$2b$", "$2x$", "$2y$", "$5$", "$6$", "$7$", "$y$", "$gy$",
      "$argon2", "$pbkdf2", "$$apr1$$", "$$2y$$", "$$6$$"),
     r"(?<![\w$])\${1,2}(?:apr1|1|2[abxy]|5|6|7|y|gy|argon2id|argon2i|argon2d|pbkdf2[\w\-]{0,16})"
     r"\${1,2}[./\w$=,+\-]{8,1024}"),
    (("SCRAM-SHA-256$",), r"(?<![\w\-])SCRAM-SHA-256\$[^\s|\"']{8,1024}"),
    (("md5",), r"(?<![\w])md5[0-9a-f]{32}(?![\w])"),
    (("hooks.slack.com/services/",), r"(?<=hooks\.slack\.com/services/)[A-Za-z0-9/]{10,255}"),
    (("discord.com/api/webhooks/",), r"(?<=discord\.com/api/webhooks/)[A-Za-z0-9/_\-]{10,255}"),
)]


def _mask_inline(text):
    """KEY=value pairs anywhere: argv, libpq, ADO, docker inspect Env, JSON,
    /proc environ. When the key is NOT secret, resume right after the key,
    not after its value: in `x: password=abc` the value of `x` holds the pair."""
    out, pos, n = [], 0, len(text)
    while True:
        m = _INLINE_KEY.search(text, pos)
        if not m:
            out.append(text[pos:])
            return "".join(out)
        quote, key, sep = m.group(1), m.group(2), m.group(3)
        vstart = m.end()
        secret_key = vstart < n and _KEY_FULL.match(key)
        bare_colon = ":" in sep and not quote and sep.endswith(":")
        # Peek only for a secret key: peeking 1 KB after every `a:` was 30 s/MB.
        peek = _UNQUOTED.match(text, vstart) if secret_key and bare_colon else None
        if not secret_key or (bare_colon and (peek is None or _TAGLIKE.match(peek.group(0)))):
            # `cointokens-xyz:latest`, `auth-proxy:8080`: an unquoted key,
            # a bare colon and a tag/port value is an image or an address. A
            # Go map `map[db_password:S3cr]` is not, and is masked.
            out.append(text[pos:m.end(2)])
            pos = m.end(2)
            continue
        c = text[vstart]
        before = text[m.start() - 1] if m.start() > 0 else ""
        if c in "[{":
            vend = _balanced_end(text, vstart, limit=_BLOCK_LIMIT)
            if vend < 0:
                # Never closes nearby: not structure, just a `token={` in a log
                # line. Mask to end of line and carry on — an unclosed bracket
                # must not switch masking off for the rest of the output.
                eol = text.find("\n", vstart)
                eol = n if eol < 0 else eol
                out.append(text[pos:vstart] + _masked(text[vstart:eol]))
                pos = eol
                continue
            # Keep the structure; mask every scalar in it that is not a key:
            # `"password": {"value": "x"}` and `{user:admin,pass:x}` lose x.
            out.append(text[pos:vstart] + _BLOCK_SCALAR.sub(
                lambda v: v.group(0) if (v.group(2) or v.group(4))
                else ('"' + _masked(v.group(1)) + '"' if v.group(1) is not None
                      else _masked(v.group(3))),
                text[vstart:vend]))
            pos = vend
            continue
        elif c in "\"'" or text.startswith('\\"', vstart):
            q = '\\"' if text.startswith('\\"', vstart) else c
            k = vstart + len(q)
            while k < n and text[k] != "\n":
                if text[k] == "\\" and not text.startswith(q, k):
                    k += 2
                    continue
                if text.startswith(q, k):
                    break
                k += 1
            vend = min(k + len(q), n)
        elif before in "\"'" and not quote:
            # "POSTGRES_PASSWORD=S3cr;3t V4lue" — the pair is inside a
            # string, so the value runs to that string's closing quote.
            k = vstart
            while k < n and text[k] not in (before, "\n"):
                k += 2 if text[k] == "\\" else 1
            vend = min(k, n)
        else:
            u = _UNQUOTED.match(text, vstart)
            vend = u.end() if u else vstart
        value = text[vstart:vend]
        if not value or _keep(value) or _address_list(key, value):
            out.append(text[pos:vend])
        else:
            if value[:1] in "\"'" and len(value) >= 2 and value[-1] == value[0]:
                repl = value[0] + _masked(value[1:-1]) + value[0]
            elif value.startswith('\\"') and value.endswith('\\"') and len(value) >= 4:
                repl = '\\"' + _masked(value[2:-2]) + '\\"'
            else:
                repl = _masked(value)
            out.append(text[pos:vstart] + repl)
        pos = max(vend, m.end(2) + 1)


# (pattern, replacement, lowercase gate substrings). A pass whose gate is not
# in the text cannot match; skipping it is what keeps a clean 1 MB log fast.
_GATED = [
    (_VAULT_INIT, lambda m: m.group(1) + _masked(m.group(2)), ("unseal key", "root token", "recovery key")),
    (_AUTH_HEADER, lambda m: m.group(1) + _masked(m.group(2)), ("authorization",)),
    (_BEARER, lambda m: m.group(1) + _masked(m.group(2)), ("bearer",)),
    (_COOKIE, lambda m: m.group(1) + _masked(m.group(2)), ("cookie",)),
    (_MYSQL_DSN, lambda m: m.group(1) + ":" + _masked(m.group(2)) + m.group(3), ("@tcp(", "@unix(")),
    (_CURL_USER, lambda m: m.group(1) + m.group(2) + ":" + _masked(m.group(3)), ("-u", "--user")),
    (_SPACED, lambda m: m.group(1) + _masked(m.group(2)), ("requirepass", "masterauth", "login")),
    (_XML, lambda m: "<%s>%s</%s>" % (m.group(1), _masked(m.group(2)), m.group(1)), ("</",)),
    (_SQL_PASSWORD, lambda m: m.group(1) + "'" + _masked(m.group(2)) + "'", ("password '", "password\t'")),
    (_NGINX_HEADER, _nginx_header, ("_header",)),
    (_REDIS_AUTH, lambda m: m.group(1) + _masked(m.group(2)), ("auth ",)),
]


def _mask(text):
    text = _normalise(text)
    lower = text.lower()
    if "private key" in lower:
        text = _PEM.sub(lambda m: "-----PRIVATE KEY " + _tag(m.group(0)) + "-----", text)
    secret_doc = "secret" in lower and bool(_SECRET_KIND.search(text))
    if secret_doc:
        text = _mask_json_blocks(text, _JSON_DATA_OPEN)
    if '"data"' in text:
        text = _mask_json_blocks(text, _VAULT_JSON_OPEN)
        if '"lease_duration"' in text:  # a Vault read: every data value is the secret
            text = _mask_json_blocks(text, _JSON_DATA_OPEN)
    if "name" in text or "--" in text or "requirepass" in lower or "masterauth" in lower:
        text = _mask_json_pairs(text)
    text = _line_pass(text, secret_doc)
    for rx, repl, gates in _GATED:
        if any(g in lower for g in gates):
            text = rx.sub(repl, text)
    if "://" in text:
        text = _mask_urls(text)
    if any(g in lower for g in _CLI_GATES):
        text = _mask_cli(text)
    text = _SPACED_ENV.sub(lambda m: m.group(1) + _masked(m.group(2)), text)
    text = _mask_lines(text)
    text = _mask_inline(text)
    if "-" in text:
        text = _FLAG.sub(lambda m: m.group(1) + m.group(2) + _masked(m.group(3)), text)
    for gates, rx in _TOKEN_FAMILIES:
        if any(g in text for g in gates):
            text = rx.sub(lambda m: _masked(m.group(0)), text)
    return text


def mask(text, tags=False):
    """Return `text` with secret values replaced by <masked>.

    tags=True keeps <masked:1a2b3c4d> (per-process HMAC) so differing values
    stay distinguishable — for --compare grouping only; see untag().

    Never raises and never returns the input unmasked on error: if masking
    fails, or the input is larger than MAX_INPUT, the whole output is
    withheld. None and "" pass through.
    """
    if not text:
        return text
    try:
        if not isinstance(text, str):
            text = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
        if len(text) > MAX_INPUT:
            return OVERSIZE % (len(text), MAX_INPUT)
        return _mask(text) if tags else untag(_mask(text))
    except Exception as e:  # fail closed: withheld, never passed through
        return WITHHELD % type(e).__name__
