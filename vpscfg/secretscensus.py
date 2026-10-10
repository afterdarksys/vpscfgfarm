"""Secrets census + escrow — the estate's credentials are single copies.

Host `.env.production` files and perimeter TLS keys often exist NOWHERE else
(a contract that notes "the ONLY copy" of an API key is typical). vpsexec
rightly refuses to even read those paths, but refusing to look is not the
same as knowing they are safe: a lost host is lost config, and a silently
changed credential file is either a rotation or an intruder. The census
records fingerprints (SHA-256, size, mtime — never contents) so loss and
tampering become detectable; the escrow pipes the declared files through
`age` to committed recipients so "lost host" stops meaning "lost estate".

Contracts declare what counts with an explicit `credentials:` list (paths
relative to deploy_dir, or absolute) — declared, not remembered, like every
other load-bearing fact in a contract. Contracts without one fall back to
sync.never entries containing ".env".

Threats:
  - Protects against: credential loss with the host (escrow); silent
    credential-file change going unseen (census hash drift); secrets leaking
    through THIS tool (contents never touch local disk unencrypted — remote
    tar is piped straight into age; logs carry fingerprints only, rule 6);
    encrypting to an unreviewed key (recipients live in git and every line
    is validated); a wrong path exploding the bundle (hard size cap).
  - Does NOT protect against: the recipient private key being lost (then the
    escrow is noise — keep it offline and safe); an attacker with root on
    the host (they already have the plaintext); rotation vs tamper being
    distinguished — a changed hash is a QUESTION for the operator, the
    census only guarantees it gets asked.
"""
import hashlib
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from . import estate, journal, probe
from .gates import Refused

ESCROW_DIR = estate.root() / "escrow"
RECIPIENTS = estate.root() / "policies" / "escrow-recipients.txt"

# Absolute, boring characters only, no dot-dot. These paths reach a remote
# shell (quoted) — the validation is belt, the quoting is suspenders.
PATH_RE = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9._/-]*$")

# An escrow bundle is credential files: kilobytes. A bundle past this size
# means a declared path caught a tree it should not have — refuse and delete.
MAX_ESCROW_BYTES = 50 * 1024 * 1024

_RECIPIENT_OK = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9-]+|age1)[ A-Za-z0-9+/=@.:-]*$")


def credential_paths(contract):
    """Declared credential files, absolute. `credentials:` wins; fallback is
    sync.never entries containing '.env' (the load-bearing divergences)."""
    deploy_dir = contract["deploy_dir"]
    declared = contract.get("credentials")
    if declared is None:
        declared = [n for n in contract["sync"]["never"]
                    if isinstance(n, str) and ".env" in n]
    out = []
    for p in declared:
        full = p if p.startswith("/") else "%s/%s" % (deploy_dir.rstrip("/"), p)
        if ".." in full or not PATH_RE.match(full):
            raise Refused("credential path %r fails validation — absolute, "
                          "plain characters, no dot-dot" % full)
        out.append(full)
    return out


def census(contract, runner=None):
    """Fingerprint each declared credential file on the host. Read-only.
    Returns [{path, exists, sha256, size, mtime}]. Missing files are FACTS,
    not errors — a vanished credential file is exactly what to surface."""
    host = contract["host"]
    if not probe.HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    paths = credential_paths(contract)
    if runner is None:
        def runner(h, remote):
            r = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", h, remote],
                capture_output=True, text=True, timeout=60)
            return r.returncode, r.stdout
    results = []
    for path in paths:
        q = shlex.quote(path)
        # Fixed shape; only the validated, quoted path varies.
        remote = ("sha256sum -- %s 2>/dev/null; stat -c '%%s %%Y' -- %s 2>/dev/null"
                  % (q, q))
        rc, out = runner(host, remote)
        lines = [l for l in out.splitlines() if l.strip()]
        if len(lines) < 2:
            results.append({"path": path, "exists": False})
            continue
        digest = lines[0].split()[0]
        size, mtime = lines[1].split()[:2]
        results.append({"path": path, "exists": True, "sha256": digest,
                        "size": int(size), "mtime": int(mtime)})
    return results


def last_census(service, journal_dir=None):
    """Most recent journaled fingerprints for a service: {path: sha256}."""
    import json
    path = Path(journal_dir or journal.JOURNAL_DIR) / "secrets.jsonl"
    if not path.exists():
        return {}
    latest = {}
    for raw in path.read_text().splitlines():
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if rec.get("event") == "census" and rec.get("service") == service:
            for f in rec.get("files", []):
                if f.get("exists"):
                    latest[f["path"]] = f["sha256"]
                else:
                    latest.pop(f["path"], None)
    return latest


def census_report(contract, runner=None, journal_dir=None):
    """Census + drift vs the last journaled census. Journals the new census."""
    service = contract["service"]
    previous = last_census(service, journal_dir=journal_dir)
    files = census(contract, runner=runner)
    drift = []
    for f in files:
        before = previous.get(f["path"])
        if not f["exists"]:
            drift.append((f["path"], "MISSING — a declared credential file is gone"))
        elif before and before != f["sha256"]:
            drift.append((f["path"], "hash changed since last census — rotation "
                                     "or tamper; either way, know which"))
    journal.append("secrets", {"event": "census", "service": service,
                               "host": contract["host"], "files": files})
    return files, drift


# ---------------------------------------------------------------------------
# escrow
# ---------------------------------------------------------------------------

def _require_age():
    if not shutil.which("age"):
        raise Refused("escrow needs the `age` binary (AEAD, reviewed, standard) "
                      "— refusing to hand-roll crypto. Install: brew install age")


def _load_recipients():
    try:
        raw = RECIPIENTS.read_text()
    except OSError:
        raise Refused("no %s — escrow refuses without committed, reviewed "
                      "recipient keys" % RECIPIENTS)
    lines = [l.strip() for l in raw.splitlines()
             if l.strip() and not l.strip().startswith("#")]
    if not lines:
        raise Refused("%s has no recipient keys — an escrow nobody can decrypt "
                      "is data loss with extra steps" % RECIPIENTS)
    for line in lines:
        if not _RECIPIENT_OK.match(line):
            raise Refused("recipient line %r is not an ssh or age public key — "
                          "refusing to encrypt to something unreviewable" % line[:60])
    return lines


def escrow(contract, reason, runner_argv=None):
    """Bundle the declared credential files off the host, encrypted in flight.

    ssh tar | age -R recipients -> escrow/<service>-<ts>.tar.age
    Plaintext exists only inside the pipe. Any failure deletes the output.
    """
    if not reason:
        raise Refused("escrow requires --reason — it reads credential files, "
                      "and the journal records why")
    _require_age()
    _load_recipients()  # validated; age re-reads the file itself via -R
    host = contract["host"]
    if not probe.HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    paths = credential_paths(contract)
    if not paths:
        raise Refused("contract %r declares no credential files — nothing to "
                      "escrow" % contract["service"])
    existing = [f["path"] for f in census(contract) if f["exists"]] \
        if runner_argv is None else paths
    if not existing:
        raise Refused("none of the declared credential files exist on %s — "
                      "refusing to write an empty escrow" % host)

    ESCROW_DIR.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_path = ESCROW_DIR / ("%s-%s.tar.age" % (contract["service"], ts))
    remote = "tar czf - -C / " + " ".join(shlex.quote(p.lstrip("/")) for p in existing)
    ssh_argv = runner_argv or ["ssh", "-o", "BatchMode=yes",
                               "-o", "ConnectTimeout=8", host, remote]
    age_argv = ["age", "-R", str(RECIPIENTS), "-o", str(out_path)]
    try:
        tar_p = subprocess.Popen(ssh_argv, stdout=subprocess.PIPE)
        age_p = subprocess.Popen(age_argv, stdin=tar_p.stdout)
        tar_p.stdout.close()
        age_rc = age_p.wait(timeout=300)
        tar_rc = tar_p.wait(timeout=10)
        if tar_rc != 0 or age_rc != 0:
            raise Refused("escrow pipeline failed (tar rc=%d, age rc=%d) — "
                          "partial output deleted" % (tar_rc, age_rc))
        size = out_path.stat().st_size
        if size == 0:
            raise Refused("escrow produced an empty file — deleted, not kept")
        if size > MAX_ESCROW_BYTES:
            raise Refused("escrow bundle is %d bytes — a credential bundle is "
                          "kilobytes; a declared path caught a tree. Deleted."
                          % size)
    except Exception:
        try:
            out_path.unlink()
        except OSError:
            pass
        raise
    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    journal.append("secrets", {"event": "escrow", "service": contract["service"],
                               "host": host, "files": existing, "bytes": size,
                               "ciphertext_sha256": digest, "reason": reason,
                               "output": out_path.name})
    return {"output": str(out_path), "bytes": size, "files": existing,
            "ciphertext_sha256": digest}
