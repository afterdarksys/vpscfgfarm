"""File actions: install_pushed.

install_pushed {sha256, basename, dest, mode, owner}
    A mutation, idempotent. The content-addressed install from docs/VPSEXEC.md
    ("Content-addressed install") as one action. It pairs with the `push` verb,
    which stays separate: moving a local file is transport, not an action.

    Body: re-check the staged file `/var/tmp/vpscfg-push/<sha256>/<basename>`
    against the hash (refuse, exit 3, if it no longer matches), `install` it to
    a temp name in the destination's directory with the mode and owner, check
    the temp's hash again, then `mv -fT` it over `dest` (one rename: readers
    see the old file or the new one, never a partial one). A `dest` that is a
    directory or a symlink is refused.

    Check (a read): `dest` already has the hash, the mode and the owner. Verify:
    the same three facts. `mode` is one of 0644, 0755, 0600 and `owner` is root.

Threats:
  - Protects against: installing bytes other than the approved ones (the hash
    is a typed parameter in the canonical string; the staged file is checked
    before the install and the installed temp after it); a torn destination
    (rename, not an in-place write); a destination swapped for a symlink or a
    directory (refused); a caller-chosen source path (the staging path is
    derived from the hash and basename, never given).
  - Does NOT protect against: root on the host rewriting the staged file or
    the destination between the checks and the rename, or lying about
    sha256sum (content addressing assumes root on the target is honest, as for
    `push`); a wrong `dest` in a reviewed policy.
"""

from . import types
from .base import Action, Param, register, sq

STAGING = "/var/tmp/vpscfg-push"


@register
class InstallPushed(Action):
    name = "install_pushed"
    version = 1
    tier = "mutation"
    why = "install a file pushed with `vpsexec push` from its content-addressed path"
    params = {
        "sha256": Param(types.SHA256),
        "basename": Param(types.BASENAME),
        "dest": Param(types.ABS_PATH),
        "mode": Param(types.enum("0644", "0755", "0600")),
        "owner": Param(types.enum("root")),
    }
    samples = (
        {"sha256": "3f1c" + "0" * 56 + "a1e9", "basename": "diskwatch-0.8.0",
         "dest": "/usr/local/bin/diskwatch", "mode": "0755", "owner": "root"},
        {"sha256": "b" * 64, "basename": "shop.conf", "dest": "/etc/shop/app.conf",
         "mode": "0600", "owner": "root"},
    )

    def build(self, p, host):
        # `echo 'H' '' 'P'` prints `H  P` (two spaces), the sha256sum check
        # line, while each value stays a whole single-quoted word.
        has = ("echo %s '' %s | sha256sum --check --status && stat -c '%%a' %s | grep -qx %s "
               "&& stat -c '%%U' %s | grep -qx %s"
               % (sq(p["sha256"]), sq(p["dest"]), sq(p["dest"]), sq(p["mode"].lstrip("0")),
                  sq(p["dest"]), sq(p["owner"])))
        body = "\n".join([
            "set -eu",
            "sha=%s" % sq(p["sha256"]),
            "name=%s" % sq(p["basename"]),
            "dest=%s" % sq(p["dest"]),
            "mode=%s" % sq(p["mode"]),
            "owner=%s" % sq(p["owner"]),
            'src="%s/$sha/$name"' % STAGING,
            'if [ -L "$dest" ] || [ -d "$dest" ]; then',
            '  echo "install_pushed: $dest is a symlink or a directory; not installed" >&2',
            "  exit 3",
            "fi",
            'if ! echo "$sha  $src" | sha256sum --check --status; then',
            '  echo "install_pushed: $src is missing or does not have the approved hash;'
            ' not installed" >&2',
            "  exit 3",
            "fi",
            'd=${dest%/*}; [ -n "$d" ] || d=/',
            't=$(mktemp "$d/.vpscfg-install.XXXXXX")',
            "trap 'rm -f \"$t\"' EXIT",
            'install -m "$mode" -o "$owner" -g "$owner" "$src" "$t"',
            'if ! echo "$sha  $t" | sha256sum --check --status; then',
            '  echo "install_pushed: the installed copy does not have the approved hash;'
            ' not moved into place" >&2',
            "  exit 3",
            "fi",
            'mv -fT "$t" "$dest"',
            'echo "installed $dest ($mode $owner)"',
        ])
        return {"body": body,
                "check": has + " && echo VPSCFG-DONE || echo VPSCFG-NEEDED",
                "verify": has, "timeout": 120, "idempotent": True}
