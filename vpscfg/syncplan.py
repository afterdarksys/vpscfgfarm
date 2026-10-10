"""Sync planning — builds the rsync argv from a contract. Never from operator input.

Threats:
  - Protects against: overwriting the load-bearing host files (every sync.never
    entry becomes --exclude and the list is REQUIRED by contract validation);
    path injection (validated relpaths, argv-list construction, '--' guard);
    accidental full-tree sync (only sync.include paths, never '.').
  - Does NOT protect against: an include list that names the wrong things —
    contracts are reviewed in git for exactly that reason.
"""
from pathlib import Path
import re
from .drift import validate_relpath
from .gates import Refused


def protected_path(path):
    """An optional leading slash anchors an rsync exclusion to the source root."""
    if not isinstance(path, str):
        raise Refused('sync.never entries must be paths')
    cleaned = path.rstrip('/')
    validate_relpath(cleaned[1:] if cleaned.startswith('/') else cleaned)
    return cleaned


def validate_sources(contract):
    """Filtering a tree must not turn a missing declared input into success."""
    root = Path(contract.get('repo', '')).expanduser().resolve()
    if not contract.get('repo') or not root.is_dir():
        raise Refused('deployment source repository is missing')
    includes = contract.get('sync', {}).get('include')
    if not isinstance(includes, list) or not includes:
        raise Refused('deployment requires explicit sync.include inputs')
    never = contract['sync']['never']
    for source, destination in normalize_includes(includes):
        if destination is None and any(source == protected_path(n).lstrip('/') or source.startswith(protected_path(n).lstrip('/') + '/') for n in never):
            continue
        path = root / source
        if not path.exists():
            raise Refused('declared deployment input is missing: %s' % source)
        if path.is_symlink() or root not in path.resolve().parents:
            raise Refused('deployment input escapes source root or is a symlink: %s' % source)
        if destination is not None and not path.is_file():
            raise Refused('rename input must be a regular file: %s' % source)


def normalize_includes(includes):
    """Each include is either a plain relpath string or a {src, dest} rename
    (both validated). Returns [(src, dest_or_None), ...]. Renames are
    file-level only: rsync + drift both need a 1:1 mapping, and a directory
    rename hides too much to review."""
    pairs = []
    for inc in includes:
        if isinstance(inc, dict):
            src, dest = inc.get("src"), inc.get("dest")
            if not src or not dest or set(inc) != {"src", "dest"}:
                raise Refused("rename include must be exactly {src, dest}, got %r" % (inc,))
            if src.endswith("/") or dest.endswith("/"):
                raise Refused("rename include %r is a directory — renames are file-level only" % (inc,))
            pairs.append((validate_relpath(src), validate_relpath(dest)))
        else:
            if not isinstance(inc, str):
                raise Refused('sync.include entries must be paths or {src, dest}')
            pairs.append((validate_relpath(inc.rstrip("/")), None))
    return pairs


def rsync_argvs(contract, dry_run=True):
    """One argv for the plain includes plus one per rename. A rename cannot
    ride the main transfer: rsync only renames when the destination path names
    the file itself."""
    repo = contract.get("repo")
    if not repo:
        raise Refused("contract has no 'repo' field — cannot plan a sync without "
                      "knowing the git-side source")
    host = contract["host"]
    deploy_dir = contract["deploy_dir"]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', host):
        raise Refused('invalid sync host')
    if not deploy_dir.startswith("/") or deploy_dir == '/':
        raise Refused("deploy_dir must be absolute")
    validate_relpath(deploy_dir.strip('/'))
    repo = str(Path(repo).expanduser().resolve())
    base = ["rsync", "-a", "--checksum", "--itemize-changes"]
    if dry_run:
        base.append("--dry-run")
    excludes = []
    for never in contract["sync"]["never"]:
        excludes += ["--exclude", protected_path(never)]
    plain, renames = [], []
    for src, dest in normalize_includes(contract["sync"]["include"]):
        (renames if dest else plain).append((src, dest))
    argvs = []
    if plain:
        # Transfer from a stable root with explicit filters. Unlike /./ with
        # --relative this also works with macOS openrsync, which otherwise
        # copies the absolute source hierarchy onto the destination.
        argv = list(base) + excludes
        included = set()
        for src, _ in plain:
            parts = src.split('/')
            for n in range(1, len(parts)):
                included.add('/' + '/'.join(parts[:n]) + '/')
            included.add('/' + src)
            included.add('/' + src + '/**')
        for path in sorted(included):
            argv.extend(['--include', path])
        argv += ['--exclude', '*', '--', repo.rstrip('/') + '/']
        argv.append("%s:%s/" % (host, deploy_dir.rstrip("/")))
        argvs.append(argv)
    for src, dest in renames:
        for never in contract["sync"]["never"]:
            protected = protected_path(never).lstrip('/')
            if any(path == protected or path.startswith(protected + "/") or protected.startswith(path + "/") for path in (src, dest)):
                raise Refused("rename transfer touches protected sync.never path %r" % protected)
        argvs.append(list(base) + ['--'] + [
            "%s/%s" % (str(repo).rstrip("/"), src),
            "%s:%s/%s" % (host, deploy_dir.rstrip("/"), dest)])
    return argvs


def rsync_argv(contract, dry_run=True):
    """Back-compat single-argv form. Refuses when the contract uses renames —
    those need rsync_argvs (each rename is its own transfer)."""
    if any(dest for _, dest in normalize_includes(contract["sync"]["include"])):
        raise Refused("contract uses rename includes — use rsync_argvs")
    argvs = rsync_argvs(contract, dry_run=dry_run)
    if len(argvs) != 1:
        raise Refused("contract plans %d transfers — use rsync_argvs" % len(argvs))
    return argvs[0]
