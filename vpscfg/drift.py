"""Drift — the three-way compare: git checkout <-> contract <-> live host.

This is the verb that catches a dependency landmine (git HEAD carrying a
package version that takes production down on deploy) as one line of red
instead of an outage.

Threats:
  - Protects against: silent divergence between the repo and the host going
    unnoticed until a deploy detonates it; drift checks accidentally mutating
    (remote side runs exactly one fixed binary, `md5sum --`, against validated
    paths); path injection from a hostile or typo'd contract (every path must
    match PATH_RE, reject '..', absolute paths only remote-side, and the remote
    command is built as an argv list — no shell string interpolation of
    operator input beyond the validated paths).
  - Does NOT protect against: a compromised host lying about its hashes, or
    semantic drift inside files that hash-compare can't rank (that is what the
    human reading the report is for). md5 here is a change detector, not a
    security control — collision resistance is irrelevant to "did it change".

Expected divergence is a first-class concept: paths in the contract's
`sync.never` list are reported as EXPECTED-DIVERGED, not as errors — the whole
point of that list is that those files are SUPPOSED to differ from git.
"""

import hashlib
import re
import subprocess
from pathlib import Path

from .gates import Refused

# Leading dot is legal (.env.production is the most important never-entry in
# the estate); leading dash is not (argv injection); '..' components are not.
PATH_RE = re.compile(r"^[A-Za-z0-9.][A-Za-z0-9._/-]*$")
MAX_FILES = 400  # one ssh round-trip; beyond this, report truncation loudly


def validate_relpath(p):
    """Contract-supplied paths are git-reviewed but still validated: no
    metacharacters, no traversal, no absolute paths, no leading dashes."""
    if not isinstance(p, str) or not PATH_RE.fullmatch(p) or any(c in ('', '.', '..') for c in p.split('/')) or p.startswith(".."):
        raise Refused("path %r fails validation (metacharacters/traversal) — refusing drift" % p)
    return p


def local_hashes(repo_root, includes):
    """md5 of every file under the contract's include list, relative paths.
    Rename includes ({src, dest}) are hashed from src but recorded under dest —
    the name the file has ON THE HOST — so compare() lines up both sides."""
    root = Path(repo_root).expanduser().resolve()
    if not root.is_dir():
        raise Refused("contract repo path %r is not a directory" % str(repo_root))
    hashes = {}
    for inc in includes:
        if isinstance(inc, dict):
            src, dest = inc.get("src"), inc.get("dest")
            if not src or not dest:
                raise Refused("rename include must be {src, dest}, got %r" % (inc,))
            validate_relpath(src)
            validate_relpath(dest)
            target = root / src
            if target.is_file():
                hashes[dest] = hashlib.md5(target.read_bytes()).hexdigest()
            else:
                hashes[dest] = None  # declared but absent locally (or a dir — refused upstream)
            continue
        validate_relpath(inc.rstrip("/"))
        target = root / inc
        if target.is_file():
            files = [target]
        elif target.is_dir():
            files = sorted(p for p in target.rglob("*") if p.is_file())
        else:
            hashes[inc] = None  # declared in contract but absent locally
            continue
        for f in files:
            rel = str(f.relative_to(root))
            if "__pycache__" in rel or rel.endswith(".pyc"):
                continue
            hashes[rel] = hashlib.md5(f.read_bytes()).hexdigest()
    return hashes


def remote_hashes(host, deploy_dir, relpaths, connect_timeout=8, command_timeout=90,
                  runner=None):
    """One ssh call, fixed binary, validated argv. Returns {relpath: md5|None}.
    `runner(argv) -> stdout` is a transport injection point (tests, preflight's
    strict-rc wrapper); the argv it receives is built here, never by the caller."""
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$", host or ""):
        raise Refused("invalid host %r" % host)
    if not deploy_dir.startswith("/"):
        raise Refused("deploy_dir must be absolute, got %r" % deploy_dir)
    validate_relpath(deploy_dir.lstrip("/"))

    relpaths = sorted(relpaths)
    truncated = len(relpaths) > MAX_FILES
    batch = [validate_relpath(p) for p in relpaths[:MAX_FILES]]
    remote_paths = ["%s/%s" % (deploy_dir.rstrip("/"), p) for p in batch]

    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % connect_timeout,
            host, "md5sum", "--"] + remote_paths
    if runner is None:
        stdout = subprocess.run(argv, capture_output=True, text=True,
                                timeout=command_timeout).stdout
    else:
        stdout = runner(argv)
    out = {}
    prefix = deploy_dir.rstrip("/") + "/"
    for line in stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].startswith(prefix):
            out[parts[1][len(prefix):]] = parts[0]
    for p in batch:
        out.setdefault(p, None)  # md5sum errored for it => missing remotely
    return out, truncated


def compare(local, remote, never_list):
    """Pure function: classify every path. Returns dict of lists."""
    report = {"in_sync": [], "drifted": [], "expected_diverged": [],
              "missing_on_host": [], "missing_in_git": []}

    def is_never(path):
        return any(path == n.strip("/") or path.startswith(n.strip("/") + "/")
                   for n in never_list)

    for path in sorted(set(local) | set(remote)):
        lh, rh = local.get(path), remote.get(path)
        if is_never(path):
            report["expected_diverged"].append(path)
        elif lh is None:
            report["missing_in_git"].append(path)
        elif rh is None:
            report["missing_on_host"].append(path)
        elif lh == rh:
            report["in_sync"].append(path)
        else:
            report["drifted"].append(path)
    return report


def render(service, host, report, truncated):
    lines = ["DRIFT %s on %s:" % (service, host)]
    labels = [("drifted", "DRIFTED (git != host)"),
              ("missing_on_host", "MISSING ON HOST"),
              ("missing_in_git", "MISSING IN GIT"),
              ("expected_diverged", "expected-diverged (sync.never)"),
              ("in_sync", "in sync")]
    for key, label in labels:
        entries = report[key]
        if key == "in_sync":
            lines.append("  %s: %d files" % (label, len(entries)))
        else:
            for e in entries:
                lines.append("  %-32s %s" % (label + ":", e))
    if truncated:
        lines.append("  WARNING: file list truncated at %d — coverage is PARTIAL" % MAX_FILES)
    clean = not (report["drifted"] or report["missing_on_host"])
    lines.append("  verdict: %s" % ("CLEAN" if clean else "DRIFT DETECTED"))
    return "\n".join(lines)
