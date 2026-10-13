#!/usr/bin/env python3
"""export-public — build a FRESH-history public tree from an allowlist.

    tools/export-public.py --commit HEAD --out /path/to/new-empty-dir
        [--repo .] [--allowlist tools/public-allowlist.txt]
        [--denylist tools/public-denylist.txt]
        [--exceptions tools/public-scan-exceptions.txt]
        [--binary-allowlist tools/public-binary-allowlist.txt]
        [--identity FILE]
        [--message "Initial public release"] [--no-commit]

What it does, in order, and nothing else:
  1. refuses unless --out is missing or an EMPTY directory;
  2. lists the tracked blobs at --commit (git ls-tree; the working tree, the
     index and untracked files are never read);
  3. copies ONLY the blobs the allowlist selects into --out (regular files
     only: symlinks and submodules are refused, not followed; any path whose
     name casefolds to `estate.path` refuses the whole export);
  4. scans the exported tree, paths and contents, for estate leaks: routable
     IPv4 literals (anything but RFC 5737 / RFC 1918 / loopback / other
     non-global ranges), denylisted estate terms, e-mail addresses outside the
     reserved example domains, private-key headers, and things shaped like
     tokens or secret assignments. Text must be strict UTF-8 without NUL
     bytes; anything else (UTF-16, an archive) is a hit unless its exact path
     is in the binary allowlist, and then only its name and raw bytes (gzip
     decompressed) are searched for denylisted terms. Before the denylist is
     matched, text is NFKC-normalised and zero-width characters are removed,
     so `after\u200bdark` and full-width letters do not slip through; with
     --identity, the listed public-identity strings are masked out of each
     folded line and path first (see below);
  5. on ANY hit not listed in the exceptions file, prints every hit with its
     exception key and exits 1, leaving the exported files in --out
     for review and NO git repository;
  6. otherwise runs `git init` in --out and makes ONE initial commit.

It never pushes, never adds a remote, and never rewrites the source repo's
history: the public repository starts from a new root commit, so nothing in
the private history (which carries estate data throughout) can leak through it.

Allowlist syntax (one per line, `#` comments): a path, a directory ending in
`/` (everything under it), or a glob where `*` and `?` stay inside one path
segment and `**` crosses segments. A line starting with `!` excludes. The
last matching line wins, as in .gitignore. No line matches by default.

Exceptions syntax: `path:line:kind:digest`, where digest is the first 16 hex
of sha256 of that line's text (line 0 = the path itself, digest of the path),
optionally followed by `#` and the reviewer's reason. The scan prints the key
for every hit. An exception therefore pins WHAT was reviewed, not only where:
a line that changes in place, or gains a hit of another kind, no longer
matches. An exception that matches no hit is reported as stale and also fails
the export. Undecodable-file hits cannot be excepted; use the binary
allowlist (exact paths, `#` comments).

Identity syntax (--identity FILE, default none; one entry per line, `#`
comments): an exact public-identity string the project publishes under a
denylisted name, such as a Go module path (`github.com/<org>/<repo>`) or a
launchd label (`com.<org>.<tool>`). Each entry must be printable ASCII without
whitespace, at least 12 characters, not itself a bare denylist term, and must
contain a denylist term (an entry that masks nothing the denylist would catch
is pointless or stale, and refuses the export). Before the denylist is
matched, every occurrence of an entry in a folded line or path is replaced by
a NUL placeholder, which no denylist term can span, so the text on either side
cannot combine into a term. An occurrence only counts when it stands alone:
the character before it may not be a letter, digit, `_`, `.` or `-`, and the
character after it may not be a letter, digit, `_` or `-`. So
`github.com/<org>/<repo>/internal/x` and `com.<org>.<tool>.daemon` pass, while
the org's hostnames, the bare org name, `github.com/<org>.com`,
`github.com/<org>/../`, `x<entry>` and `<entry>s` still hit. Only the
denylist check is masked: IP, e-mail, private-key, token and secret shapes
see the original line, and the bytes of binary-allowlisted files are never
masked (only their path is). The summary prints every entry so the reviewer
sees what was masked; an entry that matches nothing in the export is reported
as stale and fails the export, as a stale exception does.

Threats:
  - Protects against: estate data reaching a public repository through an
    export (default-deny allowlist; only committed blobs at a named commit;
    a fail-closed scan of every exported byte and path; exceptions pinned to
    an exact line); private history leaking (fresh root commit, no remote);
    clobbering an existing directory or repository (non-empty --out refuses);
    an identity entry widening into a blanket pass (exact, boundary-checked
    strings only; short, whitespace-bearing, non-ASCII, bare-term and
    term-free entries refuse; stale entries fail; entries are printed).
  - Does NOT protect against: leaks the patterns do not describe (an estate
    hostname missing from the denylist, a secret in an unrecognised shape,
    IPv6 literals, secrets inside binary-allowlisted files beyond the
    denylist terms); a reviewer approving an
    exception, or an identity entry (say an estate hostname), they should
    not have. The scan is a backstop to the allowlist,
    not a substitute for reading the diff before publishing.

Exit codes: 0 exported (and committed unless --no-commit), 1 scan hits,
2 usage or refusal.
"""

import argparse
import gzip
import hashlib
import ipaddress
import os
import re
import subprocess
import sys
import unicodedata

HERE = os.path.dirname(os.path.realpath(__file__))

# Reserved for documentation by RFC 2606 / RFC 6761: an address here is an example.
EXAMPLE_MAIL_DOMAINS = ("example.com", "example.net", "example.org")
EXAMPLE_MAIL_SUFFIXES = (".example", ".test", ".invalid", ".localhost",
                         ".example.com", ".example.net", ".example.org")

# Digits-and-dots boundaries only: `peer_<addr>`, `x<addr>` and `<addr>v2`
# are all still addresses. Octets are parsed with int(), so a leading zero
# (an octet written `085`) is read as the address it is meant to be.
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d])")
EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@"
                      r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.[A-Za-z]{2,24})\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
TOKEN_RES = (
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("vault-token", re.compile(r"\bhv[sb]\.[A-Za-z0-9_-]{24,}\b")),
)
# A secret-named key (`password`, `PGPASSWORD`, `db_pass`, ...) bound to a
# long literal with `=` or `:`. Quotes are optional; an UNQUOTED value must
# carry a digit and no call/subscript syntax, so `password = read_password()`
# is code, not a secret.
SECRET_ASSIGN_RE = re.compile(
    r"(?i)(?:[\w-]*(?:secret|passw(?:or)?d|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"private[_-]?key|client[_-]?secret|token)[\w-]*"
    # pass / passwd / pw only as a whole name segment: DB_PASS, pw, ADMIN-PW,
    # but not bypass, compass or upward.
    r"|(?<![A-Za-z0-9])(?:[A-Za-z0-9_-]*[_-])?(?:pass|passwd|pw)(?![A-Za-z0-9]))"
    r"[\"']?\s*[:=]\s*"
    r"(?:([\"'])([^\"'\s]{16,})\1|([^\"'\s,;)]{16,}))")
# A placeholder is a WHOLE value: `latest-real-secret-...` contains "test" and
# is still a secret.
PLACEHOLDER_RE = re.compile(r"(?i)(?:<[^>]*>|\$\{[^}]*\}|\{\{.*\}\}|%\([^)]*\)s|"
                            r"x{6,}|\*{4,}|\.{3,}|(?:your|my)[_-][\w-]*|"
                            r"(?:changeme|placeholder|redacted|dummy|example)[\w.-]*)")
ZERO_WIDTH = dict.fromkeys(map(ord, "\u00ad\u180e\u200b\u200c\u200d\u200e\u200f"
                               "\u2060\u2061\u2062\u2063\u2064\ufeff"))
POINTER_NAME = "estate.path"
GUNZIP_CAP = 64 << 20


class Refused(Exception):
    pass


# --- allowlist ---------------------------------------------------------------

def _glob_re(pattern):
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z")


def load_allowlist(path):
    rules = []
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            negate = line.startswith("!")
            pattern = line[1:] if negate else line
            if pattern.startswith("/") or ".." in pattern.split("/"):
                raise Refused("%s:%d: allowlist entries are repo-relative, without "
                              "'..': %r" % (path, n, line))
            if pattern.endswith("/"):
                regex = re.compile(re.escape(pattern) + ".*")
            else:
                regex = _glob_re(pattern)
            rules.append((negate, regex))
    if not any(not neg for neg, _ in rules):
        raise Refused("%s selects nothing — an empty allowlist exports nothing" % path)
    return rules


def allowed(path, rules):
    verdict = False
    for negate, regex in rules:
        if regex.match(path):
            verdict = not negate
    return verdict


# --- scanner -----------------------------------------------------------------

def load_terms(path):
    terms = []
    if path is None:
        return terms
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip().lower()
            if line:
                terms.append(line)
    return terms


def load_exceptions(path):
    keys = set()
    if path is None or not os.path.exists(path):
        return keys
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.rsplit(":", 3)
            if (len(parts) != 4 or not parts[0] or not parts[1].isdigit()
                    or not re.fullmatch(r"[a-z0-9-]+", parts[2])
                    or not re.fullmatch(r"[0-9a-f]{16}", parts[3])):
                raise Refused("%s:%d: an exception is `path:line:kind:digest16`, got %r"
                              % (path, n, line))
            keys.add("%s:%d:%s:%s" % (parts[0], int(parts[1]), parts[2], parts[3]))
    return keys


def load_identity(path, terms):
    """(regex, entries) for the public-identity masks, or (None, []) without a file.
    Refuses entries that are short, carry whitespace or non-ASCII, are a bare
    denylist term, or contain no denylist term at all."""
    if path is None:
        return None, []
    entries = []
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            entry = fold(line)
            if not re.fullmatch(r"[\x21-\x7e]+", line):
                raise Refused("%s:%d: an identity entry is printable ASCII without "
                              "whitespace, got %r" % (path, n, line))
            if len(entry) < 12:
                raise Refused("%s:%d: identity entry %r is shorter than 12 characters"
                              % (path, n, line))
            if entry in terms:
                raise Refused("%s:%d: identity entry %r is a bare denylist term; that "
                              "would switch the term off" % (path, n, line))
            if not any(t in entry for t in terms):
                raise Refused("%s:%d: identity entry %r contains no denylist term, so "
                              "it masks nothing — drop it" % (path, n, line))
            if entry not in entries:
                entries.append(entry)
    if not entries:
        raise Refused("identity file %s lists no entries" % path)
    alternatives = "|".join(re.escape(e) for e in sorted(entries, key=len, reverse=True))
    return re.compile(r"(?<![\w.-])(?:%s)(?![\w-])" % alternatives), entries


def mask_identity(folded, identity, seen):
    """`folded` with every standalone identity entry replaced by NUL, which no
    denylist term can span; the entries that matched are added to `seen`."""
    if identity is None:
        return folded
    def sub(m):
        seen.add(m.group(0))
        return "\0"
    return identity.sub(sub, folded)


def load_binary_allowlist(path):
    names = set()
    if path is None or not os.path.exists(path):
        return names
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if line:
                names.add(line)
    return names


def digest(text):
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def fold(text):
    """What the denylist is matched against: NFKC, zero-width removed, casefolded."""
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH).casefold()


def _ip_hit(text):
    octets = [int(o) for o in text.split(".")]  # int(): "085" is 85, not "invalid"
    if any(o > 255 for o in octets):
        return None  # 999.1.1.1: not an address
    ip = ipaddress.ip_address(".".join(map(str, octets)))
    return str(ip) if ip.is_global and not ip.is_multicast else None


def _mail_hit(addr):
    domain = addr.rsplit("@", 1)[1].lower()
    return not (domain in EXAMPLE_MAIL_DOMAINS or domain.endswith(EXAMPLE_MAIL_SUFFIXES))


def _mask(text):
    return text if len(text) <= 12 else text[:6] + "…" + text[-2:]


def scan_text(path, text, terms, identity=None, seen=None):
    """[(line, kind, evidence, line_text)] for one file's text; line 0 is the path.
    `identity` (from load_identity) masks the denylist check only; the entries
    it matched are added to `seen`."""
    hits = []
    seen = set() if seen is None else seen
    folded_path = mask_identity(fold(path), identity, seen)
    for term in terms:
        if term in folded_path:
            hits.append((0, "denylist", term, path))
    for n, line in enumerate(text.split("\n"), 1):
        folded = mask_identity(fold(line), identity, seen)
        for term in terms:
            if term in folded:
                hits.append((n, "denylist", term, line))
        for m in IPV4_RE.finditer(line):
            ip = _ip_hit(m.group(1))
            if ip:
                hits.append((n, "ipv4", m.group(1), line))
        for m in EMAIL_RE.finditer(line):
            if _mail_hit(m.group(1)):
                hits.append((n, "email", m.group(1), line))
        if PRIVATE_KEY_RE.search(line):
            hits.append((n, "private-key", PRIVATE_KEY_RE.search(line).group(0), line))
        for kind, regex in TOKEN_RES:
            for m in regex.finditer(line):
                hits.append((n, kind, _mask(m.group(0)), line))
        for m in SECRET_ASSIGN_RE.finditer(line):
            value = m.group(2) or m.group(3)
            if m.group(3) and (not re.search(r"\d", value) or re.search(r"[(\[{]", value)):
                continue  # unquoted and shaped like code, not a literal
            if not PLACEHOLDER_RE.fullmatch(value):
                hits.append((n, "secret-assignment", _mask(value), line))
    return hits


def scan_binary(path, data, terms, identity=None, seen=None):
    """A binary-allowlisted file: its name, and denylisted terms in its raw
    bytes (and, for gzip, the decompressed bytes). An archive that inflates
    past GUNZIP_CAP refuses the export: unscanned bytes are not clean bytes.
    Identity masking applies to the name only, never to the bytes."""
    seen = set() if seen is None else seen
    folded_path = mask_identity(fold(path), identity, seen)
    hits = [(0, "denylist", t, path) for t in terms if t in folded_path]
    blobs = [data]
    if data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=__import__("io").BytesIO(data)) as g:
                inflated = g.read(GUNZIP_CAP + 1)
            if len(inflated) > GUNZIP_CAP:
                raise Refused("%s inflates past %d bytes; the rest cannot be scanned — "
                              "refusing the export" % (path, GUNZIP_CAP))
            blobs.append(inflated)
        except (OSError, EOFError):
            hits.append((0, "binary-unreadable", "corrupt gzip", path))
    for blob in blobs:
        text = fold(blob.decode("latin-1"))
        for term in terms:
            if term in text:
                hits.append((0, "binary-denylist", term, path))
    return hits


def scan_tree(root, terms, binaries=frozenset(), identity=None, seen=None):
    """Every hit under root as [(key, kind, evidence)], key =
    path:line:kind:sha256(line)[:16], sorted. A file that is not strict UTF-8
    (or holds a NUL) is a `binary` hit unless its path is in `binaries`.
    Identity entries that matched anywhere are added to `seen`."""
    found = []
    seen = set() if seen is None else seen
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not (dirpath == root and d == ".git"))
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            with open(full, "rb") as f:
                data = f.read()
            try:
                if b"\0" in data:
                    raise UnicodeDecodeError("utf-8", data, 0, 1, "NUL byte")
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                if rel in binaries:
                    hits = scan_binary(rel, data, terms, identity, seen)
                else:
                    hits = [(0, "binary", "not strict UTF-8 text (or holds NUL); "
                             "list it in the binary allowlist if it must ship", rel)]
            else:
                hits = scan_text(rel, text, terms, identity, seen)
            for n, kind, evidence, line in hits:
                found.append(("%s:%d:%s:%s" % (rel, n, kind, digest(line)), kind, evidence))
    def order(hit):
        path, n, _, _ = hit[0].rsplit(":", 3)
        return (path, int(n), hit[1], hit[2])
    return sorted(set(found), key=order)


# --- export ------------------------------------------------------------------

def _git(repo, *args, **kw):
    r = subprocess.run(["git", "-C", repo] + list(args), capture_output=True, timeout=120, **kw)
    if r.returncode != 0:
        raise Refused("git %s failed: %s" % (" ".join(args[:2]),
                                             r.stderr.decode("utf-8", "replace").strip()))
    return r.stdout


def tracked_blobs(repo, commit):
    """[(mode, sha, path)] for every entry in the commit's tree."""
    out = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit)
    entries = []
    for item in out.split(b"\0"):
        if not item:
            continue
        meta, path = item.split(b"\t", 1)
        mode, kind, sha = meta.decode().split()
        entries.append((mode, kind, sha, path.decode("utf-8", "surrogateescape")))
    return entries


def prepare_out(out):
    if os.path.lexists(out):
        if os.path.islink(out) or not os.path.isdir(out):
            raise Refused("%s exists and is not a directory — refusing" % out)
        if os.listdir(out):
            raise Refused("%s is not empty — the export only ever writes into a "
                          "new or empty directory" % out)
    else:
        os.makedirs(out, mode=0o755)


def export(repo, commit, out, rules):
    """Copy the allowlisted blobs at `commit` into `out`. Returns the count."""
    sha = _git(repo, "rev-parse", "--verify", "--quiet", commit + "^{commit}").decode().strip()
    selected = [e for e in tracked_blobs(repo, sha) if allowed(e[3], rules)]
    for mode, kind, blob, path in selected:
        if kind != "blob" or mode not in ("100644", "100755"):
            raise Refused("%s is a %s (mode %s) — only regular files are exported; "
                          "drop it from the allowlist" % (path, kind, mode))
        if path.startswith("/") or ".." in path.split("/"):
            raise Refused("refusing tracked path %r" % path)
        if path.rsplit("/", 1)[-1].casefold() == POINTER_NAME:
            raise Refused("%s is an estate pointer (or a case-variant of one) — it "
                          "names a private path and never ships" % path)
    for mode, kind, blob, path in selected:
        dest = os.path.join(out, *path.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        data = _git(repo, "cat-file", "blob", blob)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     0o755 if mode == "100755" else 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    return sha, len(selected)


def commit_tree(out, message):
    """`git init` + exactly one commit. No remote is added; nothing is pushed."""
    for args in (["init", "-q"], ["add", "-A"],
                 ["commit", "-q", "--no-verify", "-m", message]):
        _git(out, *args)
    remotes = _git(out, "remote").decode().split()
    if remotes:
        raise Refused("the new repository has remotes %r — refusing" % remotes)
    return _git(out, "rev-parse", "HEAD").decode().strip()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", default=os.path.dirname(HERE))
    ap.add_argument("--commit", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--allowlist", default=os.path.join(HERE, "public-allowlist.txt"))
    ap.add_argument("--denylist", default=os.path.join(HERE, "public-denylist.txt"))
    ap.add_argument("--exceptions", default=os.path.join(HERE, "public-scan-exceptions.txt"))
    ap.add_argument("--binary-allowlist",
                    default=os.path.join(HERE, "public-binary-allowlist.txt"))
    ap.add_argument("--identity", default=None,
                    help="exact public-identity strings masked before the denylist "
                         "check (default: none)")
    ap.add_argument("--message", default="Initial public release")
    ap.add_argument("--no-commit", action="store_true",
                    help="export and scan only; never git init")
    args = ap.parse_args(argv)
    try:
        out = os.path.realpath(args.out)  # realpath on BOTH sides: no symlinked way in
        repo = os.path.realpath(args.repo)
        if out == repo or out.startswith(repo + os.sep):
            raise Refused("--out must be outside the source repository")
        rules = load_allowlist(args.allowlist)
        terms = load_terms(args.denylist)
        if not terms:
            raise Refused("denylist %s is empty — the scan would only look for "
                          "shapes, not for your estate's names" % args.denylist)
        excepted = load_exceptions(args.exceptions)
        binaries = load_binary_allowlist(args.binary_allowlist)
        identity, entries = load_identity(args.identity, terms)
        prepare_out(out)
        sha, count = export(repo, args.commit, out, rules)
        seen = set()
        hits = scan_tree(out, terms, binaries, identity, seen)
    except (Refused, OSError, subprocess.TimeoutExpired) as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        return 2

    open_hits = [h for h in hits if h[0] not in excepted or h[1] == "binary"]
    stale = sorted(excepted - {h[0] for h in hits})
    for key, kind, evidence in open_hits:
        print("%s  %s" % (key, evidence))
    for where in stale:
        print("%s: stale-exception: no hit here any more" % where)
    stale_ids = [e for e in entries if e not in seen]
    for entry in stale_ids:
        print("%s: stale-identity: matches nothing in the export" % entry)
    if args.identity is not None:
        print("identity: %d entr%s from %s masked before the denylist check:"
              % (len(entries), "y" if len(entries) == 1 else "ies", args.identity),
              file=sys.stderr)
        for entry in entries:
            print("  %s" % entry, file=sys.stderr)
    files_hit = len({h[0].rsplit(":", 3)[0] for h in open_hits})
    print("export: %d file(s) from %s into %s; %d scan hit(s) in %d file(s), "
          "%d excepted, %d stale exception(s), %d stale identity entr%s"
          % (count, sha[:12], out, len(open_hits), files_hit,
             len(hits) - len(open_hits), len(stale), len(stale_ids),
             "y" if len(stale_ids) == 1 else "ies"), file=sys.stderr)
    if open_hits or stale or stale_ids:
        print("NOT COMMITTED: fix or except every hit (its exact key in %s) and drop "
              "stale identity entries; the exported files stay in %s for review"
              % (args.exceptions, out), file=sys.stderr)
        return 1
    if args.no_commit:
        print("scan clean; --no-commit given, no repository created", file=sys.stderr)
        return 0
    try:
        head = commit_tree(out, args.message)
    except Refused as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        return 2
    print("committed %s in %s (fresh history, no remote, nothing pushed)" % (head[:12], out),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
