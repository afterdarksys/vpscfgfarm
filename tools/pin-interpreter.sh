#!/bin/sh
# pin-interpreter.sh — the install step: point the three doors' shebangs at ONE
# absolute, real, isolated Python interpreter.
#
#   tools/pin-interpreter.sh [--root DIR] /absolute/path/to/python3.X
#
# Rewrites line 1 of vpsexec, vpscfg-control.py and vpsrun (in DIR, default:
# this checkout) to `#!<interpreter> -I`, then checks the result.
#
# Why a pinned binary and not `env python3` or /usr/bin/python3 (W4 R1 and the
# W4 follow-up): `env` lets PATH choose the interpreter, and on macOS everything
# in /usr/bin (python3, xcrun) is an xcrun shim that honours DEVELOPER_DIR,
# TOOLCHAINS and SDKROOT. Either way the ENVIRONMENT picks the program that
# reads the governor, and a fake one drops -I and forges it.
#
# Refuses (exit 2, nothing written) unless the interpreter is:
#   - an absolute path with no whitespace, and the shebang fits in 127 bytes
#     (older Linux kernels truncate longer ones);
#   - a regular file, not a symlink (pass the real path: realpath/readlink -f);
#   - executable, and a binary: a `#!` script would itself pick an interpreter;
#   - owned by root or by you, and not group- or world-writable; its directory
#     likewise (otherwise someone else could swap it);
#   - on macOS, not anything in /usr/bin (the xcrun shims);
#   - actually isolated when run with -I.
#
# Threats:
#   - Protects against: the environment (PATH, DEVELOPER_DIR, TOOLCHAINS,
#     SDKROOT) choosing the interpreter that runs a door; pinning to a shim, a
#     script, a symlink that can be repointed, or a binary another user can
#     replace.
#   - Does NOT protect against: root, or the owner of the interpreter, replacing
#     it later; a door started as `python3 door` (the caller chose the
#     interpreter; deny that form at the caller).
set -eu

refuse() { echo "pin-interpreter: REFUSED: $*" >&2; exit 2; }

root="$(cd "$(dirname "$0")/.." && pwd -P)"
if [ "${1:-}" = "--root" ]; then
    [ $# -ge 2 ] || refuse "--root needs a directory"
    root="$(cd "$2" && pwd -P)" || refuse "no such directory: $2"
    shift 2
fi
[ $# -eq 1 ] || refuse "usage: $0 [--root DIR] /absolute/path/to/python3"
py="$1"

case "$py" in
    /*) ;;
    *) refuse "$py is not an absolute path" ;;
esac
case "$py" in
    *[[:space:]]*) refuse "$py contains whitespace; a shebang cannot quote it" ;;
esac
line="#!$py -I"
[ "${#line}" -le 127 ] || refuse "shebang would be ${#line} bytes; Linux may truncate past 127"
[ -L "$py" ] && refuse "$py is a symlink; pin the real binary it points at"
[ -f "$py" ] || refuse "$py is not a regular file"
[ -x "$py" ] || refuse "$py is not executable"
magic="$(head -c 2 "$py" | od -An -c | tr -d ' \n')"
[ "$magic" = "#!" ] && refuse "$py is a script (#!), not an interpreter binary"

if [ "$(uname -s)" = "Darwin" ]; then
    case "$py" in
        /usr/bin/*) refuse "$py is an xcrun shim on macOS (it honours DEVELOPER_DIR, TOOLCHAINS, SDKROOT); pin the framework binary it runs" ;;
    esac
fi

me="$(id -u)"
for target in "$py" "$(dirname "$py")"; do
    owner="$(ls -lnd "$target" | awk '{print $3}')"
    [ "$owner" = "0" ] || [ "$owner" = "$me" ] || refuse "$target is owned by uid $owner, not root or you (uid $me)"
    shared="$(find "$target" -prune \( -perm -020 -o -perm -002 \) -print)"
    [ -z "$shared" ] || refuse "$target is group- or world-writable"
done

"$py" -I -c 'import sys; sys.exit(0 if sys.flags.isolated else 1)' 2>/dev/null \
    || refuse "$py does not run isolated under -I (is it a Python 3 interpreter?)"

for door in vpsexec vpscfg-control.py vpsrun; do
    f="$root/$door"
    [ -f "$f" ] && [ ! -L "$f" ] || refuse "$f is missing or a symlink"
done
for door in vpsexec vpscfg-control.py vpsrun; do
    f="$root/$door"
    tmp="$(mktemp "${TMPDIR:-/tmp}/pin-interpreter.XXXXXX")"
    { printf '%s\n' "$line"; tail -n +2 "$f"; } > "$tmp"
    cat "$tmp" > "$f"   # in place: keeps the door's inode and mode
    rm -f "$tmp"
    [ "$(head -n 1 "$f")" = "$line" ] || refuse "rewriting $f did not take"
done
echo "pinned: $line"
