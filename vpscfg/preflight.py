"""Pre-deployment go/no-go — `vpscfg <host> deploy <svc> --preflight`.

One report, one verdict, two questions:
  (1) is this plan safe and deployable, and
  (2) will it break the service that is working right now?

Verdict: GO (exit 0), GO-WITH-WARNINGS (exit 1), NO-GO (exit 2). Any check
that FAILS or ERRORS makes the verdict NO-GO — a probe that could not answer
is never read as a pass. Warnings never block; they are printed and recorded.

Every result is appended to the hash-chained `preflight` journal stream,
keyed by a plan hash (contract + sync argv + sha256 of every source byte +
host + service). `deploy --run` refuses unless the most recent preflight for
THAT plan was GO/GO-WITH-WARNINGS within FRESHNESS_SECONDS (require_fresh).
There is no escape hatch: the remedy for a stale or missing preflight is to
run it again.

READ-ONLY END TO END. Remote commands are fixed templates (validated paths
shell-quoted, nothing from the operator), scanned against the deny floor
before they leave; local commands are an allowlist (rsync only with
--dry-run, git only log/show, ansible-playbook only with --check). The only
write is the local journal.

Threats:
  - Protects against: deploying onto a service that is already failing (the
    post-deploy verify could not be attributed); deploying over a host file
    someone hand-edited (live md5 matches no git revision); a sync that would
    touch a sync.never path; a full disk or starved memory mid-build; an
    irreversible migration with no verified backup; declared-port collisions;
    a plan executed long after it was checked, or a different plan executed
    under an old GO (plan hash + freshness window, re-checked under the host
    lock); contract-supplied commands (named checks from a fixed allowlist
    only, validated at contract load).
  - Does NOT protect against: anything a probe cannot see. A GO is not a
    guarantee: there is no staging, ansible check mode SKIPS command/shell
    tasks, `compose config` validates syntax not behaviour, the baseline is
    only as strong as the contract's verify block, and live state can change
    between the preflight and the run (the window bounds it; the executor's
    own live outage gate re-checks under lock). The journal is local: an
    actor with write access to it can forge a GO record — the hash chain
    raises the bar, it does not remove it.
"""
import datetime
import hashlib
import json
import math
import re
import shlex
import subprocess

from . import (backupverify, blackout, drift, fingerprint, journal, k3sapply, lint,
               outage, playbook, ports as ports_mod, probe, secretmask, syncplan)
from . import verify as verify_mod
from .control import Guard
from .gates import DENY_ALWAYS_FLOOR, Refused, assert_not_frozen, deny_scan

STREAM = "preflight"
GO, GO_WARN, NO_GO = "GO", "GO-WITH-WARNINGS", "NO-GO"
EXIT_CODES = {GO: 0, GO_WARN: 1, NO_GO: 2}
STATUSES = ("pass", "warn", "fail", "skip", "error")
FRESHNESS_SECONDS = 30 * 60
CLOCK_SKEW_SECONDS = 5
DEFAULTS = {"min_free_gb": 2, "min_free_mem_mb": 256, "drift": "fail"}
PREFLIGHT_KEYS = frozenset(["min_free_gb", "min_free_mem_mb", "drift", "checks"])
# The ONLY deployability checks a contract may name. Each maps to a fixed,
# read-only remote command built below — a contract never supplies a command.
NAMED_CHECKS = frozenset(["compose_config", "nginx_test"])
GIT_HISTORY_LIMIT = 50
EVIDENCE_MAX = 2000
_REV_RE = re.compile(r"^[0-9a-f]{40,64}$")
_ITEM_RE = re.compile(r"^[<>ch.*][fdLDS][^ ]{9} (.+)$")


# ---- contract schema ---------------------------------------------------

def _number(value, field, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or not low < value <= high:
        raise Refused("preflight.%s must be a number in (%g, %g]" % (field, low, high))


def validate_contract_block(contract):
    """Contract-load validation for `preflight:`, `migrations:`, `playbook:`.
    Anything outside the schema refuses the whole contract — in particular a
    string where a named check belongs, because a string would be a command."""
    pf = contract.get("preflight")
    if pf is not None:
        if not isinstance(pf, dict):
            raise Refused("preflight must be a mapping")
        unknown = sorted(set(pf) - PREFLIGHT_KEYS)
        if unknown:
            raise Refused("preflight has unknown keys %r (allowed: %s)"
                          % (unknown, ", ".join(sorted(PREFLIGHT_KEYS))))
        if "min_free_gb" in pf:
            _number(pf["min_free_gb"], "min_free_gb", 0, 100000)
        if "min_free_mem_mb" in pf:
            _number(pf["min_free_mem_mb"], "min_free_mem_mb", 0, 10000000)
        if "drift" in pf and pf["drift"] not in ("fail", "warn"):
            raise Refused("preflight.drift must be 'fail' or 'warn'")
        checks = pf.get("checks", {})
        if not isinstance(checks, dict):
            raise Refused("preflight.checks must be a mapping of named checks")
        for name, spec in checks.items():
            if name not in NAMED_CHECKS:
                raise Refused("preflight check %r is not in the fixed allowlist (%s) "
                              "— contracts name checks, they never supply commands"
                              % (name, ", ".join(sorted(NAMED_CHECKS))))
            if isinstance(spec, bool):
                continue
            if not isinstance(spec, dict):
                raise Refused("preflight check %r must be true/false or a mapping "
                              "(never a command string)" % name)
            if name == "compose_config":
                if set(spec) != {"file"} or not isinstance(spec["file"], str):
                    raise Refused("compose_config accepts only {file: <relpath>}")
                drift.validate_relpath(spec["file"])
            else:
                if set(spec) != {"container"} or not isinstance(spec["container"], str) \
                        or not verify_mod.NAME_RE.fullmatch(spec["container"]):
                    raise Refused("nginx_test accepts only {container: <name>}")
    mig = contract.get("migrations")
    if mig is not None:
        if not isinstance(mig, dict) or set(mig) != {"irreversible"} \
                or not isinstance(mig["irreversible"], bool):
            raise Refused("migrations must be exactly {irreversible: true|false}")
    pb = contract.get("playbook")
    if pb is not None and (not isinstance(pb, str) or not playbook.NAME_RE.fullmatch(pb)):
        raise Refused("playbook must be a playbook name under playbooks/")


def settings(contract):
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in (contract.get("preflight") or {}).items() if k != "checks"})
    merged["checks"] = {k: v for k, v in ((contract.get("preflight") or {}).get("checks") or {}).items()
                        if v is not False}
    return merged


# ---- plan identity -----------------------------------------------------

def plan_hash(contract, host, service):
    """sha256 over everything the deploy will act on: the parsed contract,
    the exact sync argv, every source byte (sha256, not md5 — this binds a
    gate), host and service. Local only; no network."""
    doc = {
        "v": 1, "host": host, "service": service, "contract": contract,
        "sync": (k3sapply.planned(contract, k3sapply.image_ref(contract, _source_manifest(contract)))
                 if k3sapply.is_k3s(contract) else syncplan.rsync_argvs(contract, dry_run=False)),
        "source": _source_manifest(contract),
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _source_manifest(contract):
    """{relpath: [mode, sha256 | "link:" + target]} for everything rsync -a
    could carry from the include list — modes included (a chmod-only change
    is a different plan) and nothing skipped (unlike drift, which ignores
    __pycache__ for comparison)."""
    import os
    from pathlib import Path
    root = Path(contract["repo"]).expanduser().resolve()
    if not root.is_dir():
        raise Refused("contract repo path %r is not a directory" % contract["repo"])
    out = {}
    for src, dest in syncplan.normalize_includes(contract["sync"]["include"]):
        top = root / src
        if not os.path.lexists(top):
            out[dest or src] = None
            continue
        files = [top] if not top.is_dir() or top.is_symlink() else \
            sorted(p for p in top.rglob("*") if p.is_symlink() or not p.is_dir())
        for f in files:
            st = os.lstat(f)
            key = dest if dest else str(f.relative_to(root))
            if f.is_symlink():
                out[key] = [st.st_mode, "link:" + os.readlink(f)]
            else:
                out[key] = [st.st_mode, hashlib.sha256(f.read_bytes()).hexdigest()]
    return out


# ---- transports (read-only by construction) ----------------------------

def _default_ssh(host, cmd, timeout=90):
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, cmd],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode == 255:
        raise OSError("ssh transport failed: %s" % (r.stderr or "").strip()[:200])
    return r.returncode, r.stdout, r.stderr


def _default_local(argv, timeout=300):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _default_git_md5s(repo, relpath, limit=GIT_HISTORY_LIMIT):
    """md5 of every committed version of relpath (newest `limit` revisions).
    git log/show only — reads the object store, never the work tree."""
    drift.validate_relpath(relpath)
    r = subprocess.run(["git", "-C", repo, "log", "--format=%H", "-n", str(limit), "--", relpath],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise OSError("git log failed for %s: %s" % (relpath, r.stderr.strip()[:200]))
    out = set()
    for rev in r.stdout.split():
        if not _REV_RE.match(rev):
            continue
        s = subprocess.run(["git", "-C", repo, "show", "%s:./%s" % (rev, relpath)],
                           capture_output=True, timeout=30)
        if s.returncode == 0:
            out.add(hashlib.md5(s.stdout).hexdigest())
    return out


class _Ctx(object):
    """Carries the target and the transports. Every remote command passes the
    deny floor and every local argv passes the read-only allowlist HERE, so an
    injected transport sees exactly what production would send."""

    def __init__(self, contract, host, guard, ssh, local):
        self.contract, self.host, self.guard = contract, host, guard
        self.service = contract["service"]
        self._ssh, self._local = ssh, local
        self.sent = []

    def ssh(self, cmd, timeout=90):
        deny_scan(cmd, list(DENY_ALWAYS_FLOOR) + list(self.guard.deny_patterns()))
        self.sent.append(("ssh", cmd))
        return self._ssh(self.host, cmd, timeout=timeout)

    def local(self, argv, timeout=300):
        tool = argv[0].rsplit("/", 1)[-1]
        if tool == "rsync" and "--dry-run" not in argv:
            raise Refused("preflight rsync without --dry-run — refusing")
        if tool == "ansible-playbook" and "--check" not in argv:
            raise Refused("preflight ansible without --check — refusing")
        if tool not in ("rsync", "ansible-playbook"):
            raise Refused("preflight local command %r is not allowlisted" % tool)
        self.sent.append(("local", list(argv)))
        return self._local(argv, timeout=timeout)


def _clip(text):
    text = str(text)
    return text if len(text) <= EVIDENCE_MAX else text[:EVIDENCE_MAX] + "…"


# ---- checks: each returns (status, evidence[, data]) --------------------

def _check_contract(ctx, raw_text, planned):
    findings = lint.lint_contract(ctx.service, raw_text, ctx.contract)
    for cmd in planned:
        deny_scan(cmd, ctx.guard.deny_patterns())
    errors = [m for lvl, m in findings if lvl == "E"]
    warns = [m for lvl, m in findings if lvl != "E"]
    if errors:
        return "fail", "lint errors: " + "; ".join(errors)
    if warns:
        return "warn", "lint warnings: " + "; ".join(warns)
    return "pass", "contract valid, lint clean, planned commands clear the deny floor"


def _check_posture(ctx):
    assert_not_frozen(ctx.contract)
    scope = "%s:%s/%s" % (ctx.contract.get("scope_kind", "service"), ctx.host, ctx.service)
    # Judge-only copy: evaluates the governor as `--run` would see it through
    # the wrapper. It is never handed to the executor.
    judge = Guard(ctx.guard.policy, True)
    judge.assert_verb("deploy")
    judge.assert_mutation_allowed("deploy", ctx.host, scope)
    note = "" if ctx.guard.verified else \
        " (this preflight ran outside the wrapper; --run must go through vpscfg-control.py)"
    return "pass", "scope %s is released, host posture permits deploy, contract not frozen%s" % (scope, note)


def _check_sync_plan(ctx):
    syncplan.validate_sources(ctx.contract)
    never = [syncplan.protected_path(n).lstrip("/") for n in ctx.contract["sync"]["never"]]
    renames = [dest for _, dest in syncplan.normalize_includes(ctx.contract["sync"]["include"]) if dest]
    argvs = syncplan.rsync_argvs(ctx.contract, dry_run=True)
    changed = []
    plain_count = len(argvs) - len(renames)
    for i, argv in enumerate(argvs):
        rc, out, err = ctx.local(argv)
        if rc != 0:
            raise OSError("rsync --dry-run rc=%s: %s" % (rc, secretmask.mask((err or out or "").strip())[:300]))
        for line in out.splitlines():
            m = _ITEM_RE.match(line.strip())
            if not m:
                continue
            path = m.group(1).rstrip("/")
            if i >= plain_count:
                path = renames[i - plain_count]
            if path in ("", "."):
                continue  # the transfer root's own attribute line
            changed.append(path)
    touched = sorted(p for p in changed if any(p == n or p.startswith(n + "/") for n in never))
    if touched:
        return "fail", "sync would touch sync.never path(s): %s" % ", ".join(touched)
    if not changed:
        return "pass", "dry-run: nothing would change (deploy would only rebuild)"
    return "pass", "dry-run: %d path(s) would change: %s%s" % (
        len(changed), ", ".join(changed[:20]), " …" if len(changed) > 20 else "")


def _check_drift(ctx, remote_runner, git_md5s, mode):
    c = ctx.contract
    includes = c["sync"]["include"]
    local = drift.local_hashes(c["repo"], includes)
    src_of = {dest: src for src, dest in syncplan.normalize_includes(includes) if dest}

    def runner(argv):
        remote = " ".join(argv[argv.index(ctx.host) + 1:])
        deny_scan(remote, list(DENY_ALWAYS_FLOOR) + list(ctx.guard.deny_patterns()))
        ctx.sent.append(("ssh", remote))
        rc, out, err = remote_runner(argv)
        # md5sum exits 1 when some files are absent. ANY other failure (no
        # binary, permission denied, unreadable deploy_dir) must not turn into
        # "every file is new on the host" — that would silently pass drift.
        if rc not in (0, 1):
            raise OSError("remote md5sum rc=%s: %s" % (rc, secretmask.mask((err or "").strip())[:200]))
        if rc == 1:
            odd = [l for l in (err or "").splitlines()
                   if l.strip() and "No such file or directory" not in l]
            if odd or not (err or "").strip():
                raise OSError("remote md5sum failed for a reason other than absent "
                              "files: %s" % secretmask.mask("; ".join(odd) or "no stderr")[:200])
        return out
    remote, truncated = drift.remote_hashes(ctx.host, c["deploy_dir"], list(local), runner=runner)
    rep = drift.compare(local, remote, c["sync"]["never"])
    if rep["missing_in_git"]:
        return "fail", "declared include(s) missing in git: %s" % ", ".join(rep["missing_in_git"])
    explained, unexplained = [], []
    for path in rep["drifted"]:
        (explained if remote[path] in git_md5s(c["repo"], src_of.get(path, path))
         else unexplained).append(path)
    parts = ["%d in sync" % len(rep["in_sync"])]
    if explained:
        parts.append("%d behind git (live matches a committed revision — this deploy "
                     "moves it forward): %s" % (len(explained), ", ".join(explained[:10])))
    if rep["missing_on_host"]:
        parts.append("%d new on host: %s" % (len(rep["missing_on_host"]),
                                            ", ".join(rep["missing_on_host"][:10])))
    if unexplained:
        parts.append("%d UNEXPLAINED (live matches NO git revision — changed on the host "
                     "outside the door; deploying overwrites it): %s"
                     % (len(unexplained), ", ".join(unexplained)))
    if truncated:
        parts.append("file list truncated at %d — coverage PARTIAL" % drift.MAX_FILES)
    evidence = "; ".join(parts)
    if unexplained:
        return ("warn" if mode == "warn" else "fail"), evidence
    return ("warn" if truncated else "pass"), evidence


def _check_k3s_state(ctx):
    """k3s replacement for the rsync dry-run: what is live, and can the
    side-loaded image actually be used."""
    c = ctx.contract
    ap = c["apply"]
    from pathlib import Path
    if not (Path(c["repo"]).expanduser() / ap["dockerfile"]).is_file():
        return "fail", "dockerfile %s not found in %s" % (ap["dockerfile"], c["repo"])
    rc, out, err = ctx.ssh(k3sapply.read_state_cmd(c))
    if rc != 0:
        raise OSError("deployment read rc=%s: %s" % (rc, secretmask.mask((err or out or "").strip())[:200]))
    live = k3sapply.parse_state(out)
    rc, nodes, err = ctx.ssh(k3sapply.NODES_CMD)
    if rc != 0:
        raise OSError("node list rc=%s: %s" % (rc, secretmask.mask((err or nodes or "").strip())[:200]))
    count = len([n for n in nodes.splitlines() if n.strip()])
    if count != 1:
        return "fail", ("cluster has %d node(s): the image is side-loaded onto %s only, so a "
                        "pod scheduled elsewhere would try a registry pull (401 on this "
                        "fleet). k3s mode supports single-node clusters only" % (count, ctx.host))
    ref = k3sapply.image_ref(c, _source_manifest(c))
    facts = "%s/%s container %s: live %s (pull %s, ready %d/%d); this plan builds %s" % (
        ap["namespace"], ap["deployment"], ap["container"], live["image"],
        live["pull_policy"], live["ready"], live["replicas"], ref)
    if live["pull_policy"] == "Always":
        return "fail", facts + " — imagePullPolicy Always would re-pull the side-loaded image"
    if live["image"] == ref:
        return "warn", facts + " — already live; deploy --run will refuse (nothing to do)"
    return "pass", facts


def _check_outage(ctx):
    from .executor import observe_outage
    results = observe_outage(ctx.contract, ctx.host, lambda h, cmd: ctx.ssh(cmd))
    containers = [{"name": l.split("\t")[0], "image": l.split("\t")[1]}
                  for l in results["containers"] if l != "NO_DOCKER"]
    volumes = [v for v in results["volumes"] if v != "NO_DOCKER"]
    assessment = outage.assess(ctx.contract, containers, volumes,
                               host_meta={"failover": False if ctx.guard.no_failover(ctx.host) else None})
    info = [m for k, m in assessment["findings"] if k == "shared_host"]
    warns = ["[%s] %s" % (k, m) for k, m in assessment["findings"] if k != "shared_host"]
    if warns:
        return "warn", "; ".join(info + warns)
    return "pass", "; ".join(info) or "no findings"


def _check_baseline(ctx, checks, allow_unhealthy):
    ok, results = checks(ctx.contract, ctx.host)
    data = [{k: r.get(k) for k in ("check", "name", "url", "ok", "detail") if r.get(k) is not None}
            for r in results]
    summary = "; ".join("%s %s %s" % ("ok" if r["ok"] else "FAIL", r["check"],
                                      r.get("url") or r.get("name", "")) for r in results)
    if ok:
        return "pass", "service is healthy NOW: " + summary, data
    if allow_unhealthy:
        return "warn", ("service is FAILING NOW (%s) — --allow-unhealthy-baseline accepted "
                        "(journaled): a post-deploy verify failure cannot be attributed "
                        "to this deploy" % summary), data
    return "fail", ("service is FAILING NOW (%s) — deploying onto a broken service makes a "
                    "post-deploy verify failure unattributable. For a repair deploy, re-run "
                    "with --allow-unhealthy-baseline --reason \"...\"" % summary), data


def _check_backup(ctx, backup_verifier):
    mig = ctx.contract.get("migrations")
    steps = [p for p in ctx.contract.get("pre", []) if "backup" in p]
    if not steps:
        return "fail", "no pre backup step — the executor refuses deploys without one"
    try:
        res = backup_verifier(ctx.host, ctx.service)
    except Refused as r:
        res, why = None, str(r)
    else:
        why = "%s — %s" % (res["backup"], res["detail"])
    if res and res["ok"]:
        return "pass", "latest pre backup verified: " + why
    if mig:
        return "fail", ("migrations declared (irreversible=%s) and no VERIFIED backup exists: %s"
                        % (mig["irreversible"], why))
    return "warn", ("no verified prior backup (%s); the deploy still takes and "
                    "readability-checks a fresh one" % why)


def _check_k3s_backup(ctx):
    mig = ctx.contract.get("migrations")
    if mig:
        return "fail", ("migrations declared (irreversible=%s) but k3s mode takes no data "
                        "backup — only the previous image is restorable" % mig["irreversible"])
    return "pass", ("rollback target is the live image, recorded under the lock and set back "
                    "if verify fails (image-level only: volumes/data are not snapshotted)")


def _check_ports(ctx, host_contracts):
    declared = ports_mod.declared_ports(ctx.contract)
    if not declared:
        return "skip", "contract declares no ports"
    rc, out, err = ctx.ssh(probe.COMMANDS["listening"])
    if rc != 0:  # partial output would under-report collisions
        raise OSError("listening probe rc=%s: %s" % (rc, (err or "no output").strip()[:200]))
    on_host = dict(host_contracts)
    on_host[ctx.service] = ctx.contract
    rep = ports_mod.audit(ports_mod.parse_listening(out), on_host,
                          ports_mod.parse_process_owners(out))
    mine = lambda d: {k: v for k, v in d.items() if ctx.service in v}
    fmt = lambda d: ", ".join("%s/%d(%s)" % (k[0], k[1], "+".join(v)) for k, v in sorted(d.items()))
    if mine(rep["collisions"]):
        return "fail", "declared port collision: " + fmt(mine(rep["collisions"]))
    if mine(rep["down"]):
        return "warn", "declared but nothing listening: " + fmt(mine(rep["down"]))
    return "pass", "declared ports bound: " + ", ".join("%s/%d" % k for k in sorted(declared))


def _check_fingerprint(ctx, fingerprint_report):
    rep = fingerprint_report(ctx)
    if rep is None:
        return "skip", "no fingerprint baseline for %s (run `vpscfg fleet baseline`)" % ctx.host
    changes = rep["changes"] + rep.get("pod_changes", [])
    if rep["uncovered"]:
        return "warn", ("UNJOURNALED: %d change(s) since baseline %s with zero journaled "
                        "mutations — prod was changed outside the doors: %s"
                        % (len(rep["uncovered"]), rep["baseline_ts"],
                           ", ".join("%s %s" % (k, n) for n, k, _ in rep["uncovered"][:10])))
    return "pass", "%d change(s) since baseline %s, all covered by journaled mutations" % (
        len(changes), rep["baseline_ts"])


def _default_fingerprint_report(aliases):
    def report(ctx):
        if fingerprint.load_baseline(ctx.host) is None:
            return None

        def prober(host, what):
            rc, out, err = ctx.ssh(probe.COMMANDS[what])
            # Same masking as probe.run, so a baseline saved by either agrees.
            return {"rc": rc, "stdout": secretmask.mask(out), "stderr": secretmask.mask(err)}
        current = fingerprint.snapshot(ctx.host, prober=prober)
        pods = fingerprint.snapshot_pods(ctx.host, prober=prober)
        return fingerprint.report(ctx.host, current, aliases=aliases, current_pods=pods)
    return report


def _check_capacity(ctx, cfg):
    # k3s images land in containerd's store, not a deploy_dir.
    deploy_dir = "/var/lib/rancher" if k3sapply.is_k3s(ctx.contract) else ctx.contract["deploy_dir"]
    cmd = ("df -Pk -- / %s && grep -E '^(MemAvailable|MemFree):' /proc/meminfo"
           % shlex.quote(deploy_dir))
    rc, out, err = ctx.ssh(cmd)
    if rc != 0:
        raise OSError("capacity probe rc=%s (does %s exist?): %s"
                      % (rc, deploy_dir, secretmask.mask((err or out or "").strip())[:200]))
    fs, mem = [], {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[3].isdigit():
            fs.append((parts[5], int(parts[3])))
        elif len(parts) >= 2 and parts[0] in ("MemAvailable:", "MemFree:") and parts[1].isdigit():
            mem[parts[0][:-1]] = int(parts[1])
    if len(fs) != 2 or not mem:
        raise OSError("capacity probe output unparseable")
    min_gb, min_mb = float(cfg["min_free_gb"]), float(cfg["min_free_mem_mb"])
    problems, facts = [], []
    for label, (mount, avail_kb) in zip(("/", deploy_dir), fs):
        gb = avail_kb / 1048576.0
        facts.append("%s (on %s) %.1fG free" % (label, mount, gb))
        if gb < min_gb:
            problems.append("%s has %.2fG free < %gG" % (label, gb, min_gb))
    mem_mb = mem.get("MemAvailable", mem.get("MemFree")) / 1024.0
    facts.append("memory %.0fM available" % mem_mb)
    if mem_mb < min_mb:
        problems.append("memory %.0fM available < %gM" % (mem_mb, min_mb))
    if problems:
        return "fail", "; ".join(problems)
    return "pass", "; ".join(facts) + " (min %gG disk, %gM mem)" % (min_gb, min_mb)


def _check_blackout(ctx, blackout_runner):
    windows, status = blackout.assess([ctx.host], runner=blackout_runner)
    if status != "ok":
        return "warn", "maintenance-window status unknown (blackout tool %s) — advisory only" % status
    if windows[ctx.host]:
        return "pass", "inside an active maintenance window (informs; never grants)"
    return "pass", "not inside a maintenance window (advisory; windows never grant or block here)"


_COMPOSE_CMD = ("if docker compose version >/dev/null 2>&1; then docker compose -f {f} config -q; "
                "else docker-compose -f {f} config -q; fi")


def _named_command(ctx, name, spec):
    if name == "compose_config":
        rel = spec["file"] if isinstance(spec, dict) else "docker-compose.yml"
        path = "%s/%s" % (ctx.contract["deploy_dir"].rstrip("/"), drift.validate_relpath(rel))
        return _COMPOSE_CMD.format(f=shlex.quote(path))
    if name == "nginx_test":
        if isinstance(spec, dict):
            return "docker exec %s nginx -t" % shlex.quote(spec["container"])
        return "nginx -t"
    raise Refused("named check %r is not in the allowlist" % name)


def _check_named(ctx, name, spec):
    rc, out, err = ctx.ssh(_named_command(ctx, name, spec))
    tail = secretmask.mask((err or out or "").strip())[-300:]
    if rc == 0:
        return "pass", "%s ok%s" % (name, (": " + tail) if tail else "")
    return "fail", "%s rc=%s: %s" % (name, rc, tail)


# Constructs that run for real even under --check, or run on the controller.
_CHECK_MODE_ESCAPE_RE = re.compile(
    r"check_mode\s*:\s*(false|no|off|0)\b|always_run|local_action|delegate_to\s*:|"
    r"lookup\s*\(\s*['\"]pipe|query\s*\(\s*['\"]pipe|\bpipe\b", re.IGNORECASE)


def _check_mode_escapes():
    """Scan every YAML under playbooks/ (a playbook may pull in any of them).
    Conservative by design: a false positive refuses, it never runs."""
    hits = []
    for path in sorted(playbook.PLAYBOOK_DIR.rglob("*")):
        if path.suffix not in (".yml", ".yaml") or not path.is_file():
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if _CHECK_MODE_ESCAPE_RE.search(line):
                hits.append("%s:%d" % (path.relative_to(playbook.PLAYBOOK_DIR), lineno))
    return hits


def _check_ansible(ctx):
    name = ctx.contract.get("playbook")
    if not name:
        return "skip", "contract names no playbook"
    argv = playbook.show_argv(ctx.host, name)
    escapes = _check_mode_escapes()
    if escapes:
        return "fail", ("refusing to run ansible for preflight: playbooks/ contains tasks that "
                        "execute even under --check (%s) — check mode would not be read-only"
                        % ", ".join(escapes[:5]))
    rc, out, err = ctx.local(argv, timeout=600)
    recap = [l.strip() for l in out.splitlines() if "ok=" in l and "failed=" in l]
    blind = ("check mode SKIPS command/shell tasks — a clean check is necessary, "
             "not sufficient")
    if rc == 0:
        return "pass", "ansible --check %s: %s; %s" % (name, "; ".join(recap) or "clean", blind)
    return "fail", "ansible --check %s rc=%s: %s; %s" % (
        name, rc, "; ".join(recap) or (err or out).strip()[-300:], blind)


# ---- orchestration -----------------------------------------------------

def _guarded(name, fn):
    try:
        res = fn()
    except Refused as r:
        res = ("fail", str(r))
    except Exception as e:  # noqa: BLE001 — a probe that cannot answer is never a pass
        res = ("error", "%s: %s — failing closed" % (type(e).__name__, e))
    status, evidence = res[0], res[1]
    if status not in STATUSES:
        status, evidence = "error", "check returned invalid status %r" % (status,)
    # Evidence can carry remote output and is journaled: mask it once, here,
    # for every check (defence in depth over the per-check masks).
    out = {"name": name, "status": status,
           "evidence": _clip(secretmask.mask(str(evidence)))}
    if len(res) > 2 and res[2] is not None:
        out["data"] = res[2]
    return out


def verdict(checks):
    statuses = {c["status"] for c in checks}
    if not checks or statuses & {"fail", "error"}:
        return NO_GO
    if "warn" in statuses:
        return GO_WARN
    return GO


def run(contract, host, guard, raw_text, planned, host_contracts=None,
        allow_unhealthy=False, aliases=(), ssh=None, local=None, checks=None,
        backup_verifier=None, blackout_runner=None, fingerprint_report=None,
        remote_runner=None, git_md5s=None, now=None):
    """Run every check and return the report dict (not yet journaled).
    Keyword transports are TEST injection points; the checks and their
    read-only guards are the same either way."""
    if contract.get("monitor_only"):
        raise Refused("contract %r is monitor_only — nothing to deploy, nothing to preflight"
                      % contract.get("service"))
    if contract["host"] != host:
        raise Refused("contract %r is bound to host %r, not %r"
                      % (contract["service"], contract["host"], host))
    ctx = _Ctx(contract, host, guard, ssh or _default_ssh, local or _default_local)
    cfg = settings(contract)
    k3s = k3sapply.is_k3s(contract)
    if remote_runner is None:
        def remote_runner(argv):
            r = subprocess.run(argv, capture_output=True, text=True, timeout=90)
            if r.returncode == 255:
                raise OSError("ssh transport failed: %s" % secretmask.mask(r.stderr.strip())[:200])
            return r.returncode, r.stdout, r.stderr
    try:
        phash, plan_error = plan_hash(contract, host, contract["service"]), None
    except Exception as e:  # noqa: BLE001 — no plan identity, no GO
        phash, plan_error = None, "%s: %s" % (type(e).__name__, e)

    results = [
        _guarded("contract", lambda: _check_contract(ctx, raw_text, planned)),
        _guarded("posture", lambda: _check_posture(ctx)),
        _guarded("plan", lambda: ("fail", "cannot compute the plan hash: " + plan_error)
                 if plan_error else ("pass", phash)),
        _guarded("sync_plan", lambda: _check_k3s_state(ctx) if k3s else _check_sync_plan(ctx)),
        _guarded("drift", lambda: ("skip", "k3s mode: no host files — the image tag binds the "
                                          "sources") if k3s else _check_drift(
                                              ctx, remote_runner, git_md5s or _default_git_md5s,
                                               cfg["drift"])),
        _guarded("outage", lambda: _check_outage(ctx)),
        _guarded("baseline", lambda: _check_baseline(ctx, checks or verify_mod.run_checks,
                                                     allow_unhealthy)),
        _guarded("backup", lambda: _check_k3s_backup(ctx) if k3s else
                 _check_backup(ctx, backup_verifier or backupverify.verify_backup)),
        _guarded("ports", lambda: _check_ports(ctx, host_contracts or {})),
        _guarded("fingerprint", lambda: _check_fingerprint(
            ctx, fingerprint_report or _default_fingerprint_report(aliases or (host,)))),
        _guarded("capacity", lambda: _check_capacity(ctx, cfg)),
        _guarded("blackout", lambda: _check_blackout(ctx, blackout_runner)),
    ]
    for name, spec in sorted(cfg["checks"].items()):
        results.append(_guarded("deployability:" + name,
                                lambda name=name, spec=spec: _check_named(ctx, name, spec)))
    results.append(_guarded("ansible", lambda: _check_ansible(ctx)))
    v = verdict(results)
    return {
        "host": host, "service": contract["service"], "plan_hash": phash,
        "generated_at": (now or datetime.datetime.now(datetime.timezone.utc)).isoformat(),
        "allow_unhealthy_baseline": bool(allow_unhealthy),
        "verdict": v, "exit_code": EXIT_CODES[v],
        "counts": {s: sum(c["status"] == s for c in results) for s in STATUSES},
        "checks": results, "commands_sent": ctx.sent,
    }


def record(report, reason=None):
    """Append the result to the hash-chained preflight stream — this record
    is what deploy --run looks up. Raises if it cannot be written."""
    entry = {"event": "preflight", "host": report["host"], "service": report["service"],
             "plan_hash": report["plan_hash"], "verdict": report["verdict"],
             "allow_unhealthy_baseline": report["allow_unhealthy_baseline"],
             "checks": [{"name": c["name"], "status": c["status"],
                         "evidence": c["evidence"][:300]} for c in report["checks"]]}
    if reason:
        entry["reason"] = reason
    return journal.append(STREAM, entry)


def _parse_ts(ts):
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")
    except (TypeError, ValueError):
        return None


def require_fresh(contract, host, now=None, window=FRESHNESS_SECONDS, token=None,
                  consume=False):
    """The deploy --run gate. Refuses (and journals the refusal) unless the
    MOST RECENT preflight for this exact plan passed GO/GO-WITH-WARNINGS
    within `window` seconds AND that GO has not been used by another deploy.
    A GO is single-use: consume=True records `deploy_gate_passed` with this
    run's token; the re-check under the host lock (consume=False, same token)
    accepts only its own consumption. A second deploy after a failed first
    one therefore needs a new preflight — against the now-current health.
    A broken journal chain refuses: a record we cannot trust is not a record."""
    service = contract["service"]
    why = None
    try:
        phash = plan_hash(contract, host, service)
    except Exception as e:  # noqa: BLE001 — no plan identity, no deploy
        phash, why = None, "cannot compute the plan hash (%s: %s)" % (type(e).__name__, e)
    if why is None:
        why = _freshness_problem(host, service, phash, now, window, token)
    if why is None and consume:
        try:
            journal.append(STREAM, {"event": "deploy_gate_passed", "host": host,
                                    "service": service, "plan_hash": phash, "token": token})
        except Exception as exc:  # noqa: BLE001 — cannot journal => cannot mutate
            why = "cannot journal the gate consumption (%s)" % exc
    if why is None:
        return phash
    try:
        journal.append(STREAM, {"event": "deploy_gate_refused", "host": host,
                                "service": service, "plan_hash": phash, "why": why})
    except Exception as exc:  # noqa: BLE001 — refusing regardless; say so
        why += " (and the refusal could not be journaled: %s)" % exc
    raise Refused("deploy --run needs a passing preflight for THIS plan within %d min: %s. "
                  "Run `vpscfg %s deploy %s --preflight` and deploy while it is fresh."
                  % (window // 60, why, host, service))


def _freshness_problem(host, service, phash, now, window, token=None):
    chain = journal.chain_verify(STREAM)
    if not chain["ok"]:
        return "the preflight journal chain is broken (%s) — no record can be trusted" % (
            "; ".join("line %d: %s" % p for p in chain["problems"][:3]))
    path = journal.JOURNAL_DIR / ("%s.jsonl" % STREAM)
    try:
        raw = journal._read_snapshot(path)
    except FileNotFoundError:
        return "no preflight has ever been recorded"
    latest, used_by = None, []
    for line in raw.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("event") == "preflight" and \
                rec.get("host") == host and rec.get("service") == service and \
                rec.get("plan_hash") == phash:
            latest, used_by = rec, []
        elif isinstance(rec, dict) and rec.get("event") == "deploy_gate_passed" and \
                latest is not None and rec.get("host") == host and \
                rec.get("service") == service:
            used_by.append(rec.get("token"))
    if latest is not None and any(t is None or t != token for t in used_by):
        return ("the latest GO for this plan was already used by a deploy — a GO is "
                "single-use; preflight again against the service as it is now")
    if latest is None:
        return ("no preflight recorded for this plan (%s) — the contract, sync plan or "
                "source changed since the last one, or none was run" % phash)
    when = _parse_ts(latest.get("ts"))
    if when is None:
        return "latest preflight record has an unreadable timestamp"
    now = now or datetime.datetime.now(datetime.timezone.utc)
    age = (now - when).total_seconds()
    if age < -CLOCK_SKEW_SECONDS:
        return "latest preflight record is dated in the future (%s)" % latest.get("ts")
    if age > window:
        return "latest preflight for this plan is stale (%d min old)" % (age // 60)
    if latest.get("verdict") not in (GO, GO_WARN):
        return "latest preflight for this plan was %s" % latest.get("verdict")
    return None


def render(report):
    lines = ["PREFLIGHT %s on %s" % (report["service"], report["host"]),
             "  plan: %s" % (report["plan_hash"] or "(none — plan could not be computed)")]
    for c in report["checks"]:
        lines.append("  [%-5s] %-28s %s" % (c["status"], c["name"],
                                          c["evidence"].replace("\n", " ")[:400]))
    if report["allow_unhealthy_baseline"]:
        lines.append("  NOTE: --allow-unhealthy-baseline was used (journaled with its reason)")
    lines.append("  counts: %s" % ", ".join("%s=%d" % (s, n) for s, n in report["counts"].items() if n))
    lines.append("VERDICT: %s (exit %d)" % (report["verdict"], report["exit_code"]))
    lines.append("  A GO is evidence, not a guarantee — see docs/PREFLIGHT.md for what "
                 "each check does NOT prove.")
    return "\n".join(lines)
