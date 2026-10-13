"""Secret actions: ensure_secret.

ensure_secret {file, key, length, distinct_from, force}
    A mutation. Makes `key` in the KEY=value file `file` a fresh random value of
    `length` (32-128) lowercase hex characters, generated ON THE HOST, unless it
    already holds a good one. Nothing about the value is ever in the policy,
    the plan, the canonical string or the journal.

    Check (v3: a token-only check, base.TokenCheck, the reviewed CHECK_SCRIPT
    pinned by sha256; only `grep`, `cut`, `sort`, `uniq` and `printf`, values
    only ever on pipes; it works on `.env` files; a key line is `KEY=value`
    or `export KEY=value`): prints VPSCFG-NEEDED when `key` is missing or
    appears more than once, is shorter than `length`, or is byte-equal to a
    value of any `distinct_from` key (each key's values de-duplicated first,
    so a repeated identical line is not a shared value), or `file` is not a
    regular file; otherwise VPSCFG-DONE. Verify: the same check, passing only
    on DONE.

    Body: refuses (exit 3, nothing changed) unless `file` is a regular file
    (not a symlink) and the door's operation id is in the environment
    (VPSCFG_OP, set by the detached runner). Generates with `openssl rand -hex`,
    else from /dev/urandom through `od`; with neither it refuses. Keeps
    `<file>.vpscfg-bak.<op8>` at 0600 (refusing if that name exists), writes
    the new file as a temp in the same directory whose mode and owner are
    copied from `file` (`cp -p`), then `mv`s it over `file`. The `key` line moves
    to the end of the file; every other line is kept as it was. It prints only
    `rotated <key> (<length> chars)`. It restarts nothing: pair it with
    `recreate` in the play. A process holding the old file open (a bind mount
    of the single file) keeps the old inode until it is recreated.

    `force: true` is a deliberate rotation: no done-check, `idempotent: false`,
    so it resumes like a plain `cmd` (SKIP-DONE / RERUN).

Threats:
  - Protects against: a secret value in stdout, stderr, argv, the plan, the
    journal or the policy (the value is generated on the host into a shell
    variable; it reaches only `printf`, a shell builtin, and pipes between
    `cut`; the check moves values only over pipes and prints a fixed token,
    and the door fails closed on any other output without showing it); the
    check being swapped for one that prints (TokenCheck: registered by
    ensure_secret@3 with a pinned sha256, re-checked at plan time and before
    sending, bound to this action's own parameters); a torn write (temp file in
    the same directory, then one rename); a weak or predictable value (the OS
    CSPRNG through openssl or /dev/urandom, at least 128 bits; the generated
    text is checked for length and alphabet before use); writing through a
    symlink (refused); clobbering an earlier backup (refused); two keys
    sharing one value, the SESSION_SECRET == JWT_SECRET case (distinct_from).
  - Does NOT protect against: root on the host reading `file`; the old value
    left in `<file>.vpscfg-bak.<op8>` (0600, named by operation, removed by
    hand); a host that lies about the check. The comparison is not constant
    time: it runs on the host over the host's own values, with no attacker
    input and no timing observer.
"""

from . import types
from .base import Action, Param, TokenCheck, register, register_token_script, sq
from .types import ParamError

# The reviewed token-only check (base.TokenCheck). The door sends it on stdin
# to `sh -s`, after `f=<file> k=<key> n=<length>` and `set -- <distinct_from>`,
# all sq()-quoted. Values only ever cross pipes; `$(...)` captures a COUNT,
# never a value; stderr is discarded; the one line printed is a token. A
# symlink is NEEDED (the body then refuses it). Changing one byte changes the
# sha256 below, which register_token_script refuses until it is re-pinned.
#
# v3: a key line is `KEY=value` or `export KEY=value` (one or more spaces), in
# the check and the body alike; `distinct_from` compares DE-DUPLICATED values
# (the key's one value, plus each other key's values through `sort -u`), so a
# repeated identical `JWT_SECRET=` line no longer reads as a shared value and
# rotates the key on every run.
CHECK_SCRIPT = """\
# vpscfg reviewed token-only check: ensure_secret@3. Prints VPSCFG-DONE or
# VPSCFG-NEEDED and nothing else; values move only over pipes.
set -u
exec 2>/dev/null
r=VPSCFG-NEEDED
if [ -f "$f" ] && [ ! -L "$f" ] \\
    && [ "$(grep -c -x -E -e "(export +)?$k=.*" -- "$f")" = 1 ] \\
    && grep -q -x -E -e "(export +)?$k=.{$n,}" -- "$f"; then
  r=VPSCFG-DONE
  for o in "$@"; do
    if [ "$({ grep -x -E -e "(export +)?$k=.*" -- "$f" | cut -d= -f2-; \\
        grep -x -E -e "(export +)?$o=.*" -- "$f" | cut -d= -f2- | sort -u; } \\
        | sort | uniq -d | grep -c .)" != 0 ]; then
      r=VPSCFG-NEEDED
    fi
  done
fi
printf '%s\\n' "$r"
"""
CHECK_SHA256 = "823fe12cd4416bae16dab9d27d7ca6bb00ad3d60b8920da0f364c959dda52674"
CHECK_KEY = "ensure_secret@3"
CHECK_BINDS = (("f", "file"), ("k", "key"), ("n", "length"), ("@", "distinct_from"))
register_token_script(CHECK_KEY, CHECK_SCRIPT, CHECK_SHA256, CHECK_BINDS, "file")


def _holds(p):
    """The DONE condition: the reviewed token-only check with this call's
    parameters. It may read an environment file; it can only print a token."""
    return TokenCheck(CHECK_KEY, CHECK_SCRIPT,
                      [(var, p[param]) for var, param in CHECK_BINDS])


@register
class EnsureSecret(Action):
    name = "ensure_secret"
    version = 3
    tier = "mutation"
    why = "rotate a KEY=value secret on the host when it is missing, short or shared"
    params = {
        "file": Param(types.ABS_PATH),
        "key": Param(types.ENV_KEY),
        "length": Param(types.int_range(32, 128), required=False, default=48),
        "distinct_from": Param(types.list_of(types.ENV_KEY, 8, least=0), required=False,
                               default=[]),
        "force": Param(types.FLAG, required=False, default=False),
    }
    samples = (
        {"file": "/srv/shop/.env", "key": "SESSION_SECRET", "length": 48,
         "distinct_from": ["JWT_SECRET"]},
        {"file": "/srv/shop/app.conf", "key": "API_TOKEN", "length": 64,
         "distinct_from": ["JWT_SECRET", "SESSION_SECRET"], "force": True},
    )

    def build(self, p, host):
        if p["key"] in p["distinct_from"]:
            raise ParamError("distinct_from names the key itself (%s)" % p["key"])
        body = "\n".join([
            "set -eu",
            "umask 077",
            "f=%s" % sq(p["file"]),
            "k=%s" % sq(p["key"]),
            "n=%d" % p["length"],
            # The backup is named by the door's operation id (detached runner).
            "op8=$(printf '%s' \"${VPSCFG_OP:-}\" | cut -c1-8)",
            'case "$op8" in',
            "  *[!0-9a-f]*|'') op8=bad ;;",
            "esac",
            'if [ "${#op8}" -ne 8 ]; then',
            '  echo "ensure_secret: no operation id (VPSCFG_OP); nothing changed" >&2',
            "  exit 3",
            "fi",
            'if [ -L "$f" ] || [ ! -f "$f" ]; then',
            '  echo "ensure_secret: $f is not a regular file; nothing changed" >&2',
            "  exit 3",
            "fi",
            'b="$f.vpscfg-bak.$op8"',
            'if [ -e "$b" ] || [ -L "$b" ]; then',
            '  echo "ensure_secret: $b already exists; nothing changed" >&2',
            "  exit 3",
            "fi",
            "if command -v openssl >/dev/null 2>&1; then",
            "  v=$(openssl rand -hex 64)",
            "elif [ -r /dev/urandom ]; then",
            "  v=$(head -c 64 /dev/urandom | od -An -vtx1 | tr -d ' \\n')",
            "else",
            '  echo "ensure_secret: neither openssl nor /dev/urandom is available;'
            ' nothing changed" >&2',
            "  exit 3",
            "fi",
            "v=$(printf '%s' \"$v\" | cut -c1-\"$n\")",
            'case "$v" in',
            "  *[!0-9a-f]*|'') v= ;;",
            "esac",
            'if [ "${#v}" -ne "$n" ]; then',
            '  echo "ensure_secret: the generator gave unexpected output; nothing changed" >&2',
            "  exit 3",
            "fi",
            'd=${f%/*}; [ -n "$d" ] || d=/',
            't=$(mktemp "$d/.vpscfg-secret.XXXXXX")',
            "trap 'rm -f \"$t\"' EXIT",
            'cp "$f" "$b"',
            'chmod 0600 "$b"',
            'cp -p "$f" "$t"',
            # `export KEY=` lines count as the key, as in the check; an
            # exported key stays exported.
            'pre=; if grep -q -E -e "^export +$k=" -- "$f"; then pre="export "; fi',
            'rc=0; grep -v -E -e "^(export +)?$k=" -- "$f" > "$t" || rc=$?',
            'if [ "$rc" -gt 1 ]; then',
            '  echo "ensure_secret: cannot read $f; nothing changed" >&2',
            "  exit 3",
            "fi",
            "printf '%s%s=%s\\n' \"$pre\" \"$k\" \"$v\" >> \"$t\"",
            'mv -f "$t" "$f"',
            "v=",
            "printf 'rotated %s (%s chars)\\n' \"$k\" \"$n\"",
        ])
        verify = _holds(p)
        if p["force"]:
            return {"body": body, "verify": verify, "timeout": 60, "idempotent": False}
        return {"body": body, "check": verify, "verify": verify, "timeout": 60,
                "idempotent": True}
