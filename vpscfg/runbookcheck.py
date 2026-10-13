"""Runbook lint and preflight — find at authoring time what used to halt a
release at deploy time.

  vpsexec runbook lint <policy.yaml>       static: this checkout only, no host
  vpsexec runbook preflight <policy.yaml>  read tier only, against the real hosts

Both end in one verdict, the docs/PREFLIGHT.md convention: GO (exit 0),
GO-WITH-WARNINGS (exit 1), NO-GO (exit 2). `fail` and `error` make NO-GO. A
`manual` result (a fact this tool cannot observe from the read tier) is never
a pass: it makes the verdict GO-WITH-WARNINGS at best and names the runbook
step that verifies it by hand.

LINT reads the policy file, the plays beside it (`<estate>/plays`), the
releases that run them (`<estate>/releases`, or --releases) and the push
artifacts (`<estate>/artifacts`, or --artifacts). It reports push steps whose
local file is missing or hashes differently, steps without a timeout,
optional / "only if" steps no play includes (or a play runs with no `when:`),
plays that drop a step's timeout or name hashes the policy does not, a play
step (cmd, push or action, by canonical string) that is a mutation matching
no step of this or any other committed policy (a stale play), a play still
carrying `release new`'s placeholder `when:`, a play
`id:` / `when:` that vpsrun would refuse, releases that name a missing play,
run this policy's break-glass steps without listing it in `policies:`, or
offer an `on_fail` entry that is not a rollback step here, a wrong or missing
`shape`, STOP steps whose command cannot exit non-zero, and an `expires`
within 48 hours.

PREFLIGHT compares the policy's `assumes:` block with the hosts, using only
fixed read commands (`docker inspect --format …`, `ls -d`, `df -P -k`), PLUS,
where usable, the cached `vpscfg index` document for that host instead of
dialing at all (docs/PREFLIGHT.md "Index-backed preflight"). Every live
command is classified by the door's own classifier and must come back
`read`, is deny-scanned, journaled as a read, and its output passes
secretmask.mask() before anything parses it. Environment variables are read
as NAMES ONLY: the inspect template splits each `NAME=value` on the host and
prints the name, so no value crosses the wire, and the parser drops anything
after `=` anyway. `assumes.privileges` is answered live too, but through the
host index's narrow sqlread gate (one has_table_privilege() SELECT, a
read-only session) rather than the plain-read allowlist, so a check cannot be
a disguised write.

Index-backed preflight: a cached document is fetched at most once per host
per run, via `indexstore.cache_status()`. It is used only when it is a
regular, non-symlink, 0600 file owned by the calling user, with a known
`index_version` and a `collected_at` neither future-dated by more than 60s
nor older than the governor's `limits.index_max_age_hours` (default 12,
ceiling 24); even then, a section with an `error` or is `unavailable` is not
used. Anything else falls back to a live read, with the evidence naming why
(`index stale 31h`, `index missing`, `section error`). `--live` skips the
index entirely; `--index-only` never dials a host at all — anything the
index cannot answer is `skip`, never `pass`. Every result names its source:
`(index, 3h old)` or `(live)`. A container's state, image id, env NAMES and
recorded compose labels/files come from the index when it answers all of
them, else from a live read journaled as `preflight_live_fallback` with the
reason. `owner_of_tables` is the one MANUAL fact the
index turns into a real pass/fail, naming the not-owned tables (never a pass
on a truncated or empty table list); `env_distinct`
stays MANUAL — the index records no VALUES, by design — unless the opt-in
`--secrets-compare` runs the policy's own ensure_secret token-only check
(a read that prints a token, never a value; SKIP under `--index-only`).

Threats:
  - Protects against: a runbook armed against a world that is not there — a
    missing or rebuilt push artifact, a container on a different image or env
    shape (DATABASE_URL vs DB_*), a path it creates that already exists, too
    little disk, a role that does not own what a release will touch; a play
    generated from a runbook that silently drops steps or timeouts, or pushes
    bytes the runbook does not name; a STOP, probe, precheck or check step
    whose command cannot exit non-zero, or that classifies as a write instead
    of a read (the weekend's "a probe wrote text into an integer column");
    a file that is disarmed (shape, `expands:`) or about to be (expiry); a
    stale, planted, wrongly-owned or wrongly-permissioned index cache being
    trusted (S11: it is advisory input only, and anything not cleanly fresh
    falls back to live or skips — never to a pass).
  - Does NOT protect against: anything neither the read tier nor the index
    can see. Secret equality needs a value, so `env_distinct` is reported
    MANUAL, never pass, unless --secrets-compare is given: then the host
    compares and only a token comes back (vpsexec._gate_token, withheld
    output on anything else). Live and cached state can both change between
    preflight and the run. The "cannot fail" rule is a conservative heuristic
    over known always-zero commands; a STOP step it does not flag is not
    proven sound. Lint is a floor, not a review.
"""
import datetime
import hashlib
import itertools
import json
import os
import re
import shlex
import subprocess
from pathlib import Path

from . import actions, indexstore, journal, secretmask, vpsexec, vpsexecpolicy
from .gates import Refused, deny_scan
from .preflight import EXIT_CODES, GO, GO_WARN, NO_GO

POLICY_MAX_BYTES = 1024 * 1024
EXPIRY_WARN_HOURS = 48
EVIDENCE_MAX = 600
HEX64_RE = re.compile(r"\b[0-9a-f]{64}\b")
STOP_RE = re.compile(r"\bSTOP\b|\b[Ss]top (?:if|unless|when|on|here)\b")
# A step whose `why` claims to be a probe/precheck/check (the weekend's "a
# probe wrote text into an integer column" halt) or a STOP must itself be
# unable to write: its `cmd` must classify as a read.
PROBE_WHY_RE = re.compile(r"\bprobes?\b|\bprechecks?\b|\bchecks?\b", re.I)
OPTIONAL_RE = re.compile(r"\boptional\b|\bonly if\b", re.I)
TIMEOUT_FLAG_RE = re.compile(r"^--timeout=(\d+)$")
# vpsrun's play-step condition grammar (its STEP_ID_RE / WHEN_RE), kept
# identical so lint and the runner agree on what a play means.
STEP_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
WHEN_RE = re.compile(r"^([A-Za-z0-9_-]{1,32}) reports (.+)$")
PLAY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Commands whose exit status is 0 whatever they find. A STOP step built on one
# of these never stops anything.
_ALWAYS_ZERO = {"echo", "printf", "true", ":"}
# Filters reading a pipe: exit 0 on any input (no pipefail in a plain ssh).
_PIPE_FILTERS = {"head", "tail", "sort", "uniq", "wc", "cut", "tr", "column",
                 "tee", "nl", "cat", "fmt", "rev"}


# ---- shared ----------------------------------------------------------------

def _result(name, status, evidence, data=None):
    out = {"name": name, "status": status, "evidence": str(evidence)[:EVIDENCE_MAX]}
    if data is not None:
        out["data"] = data
    return out


def verdict(checks):
    statuses = set(c["status"] for c in checks)
    if not checks or statuses & {"fail", "error"}:
        return NO_GO
    if statuses & {"warn", "manual"}:
        return GO_WARN
    return GO


def report(kind, path, checks):
    v = verdict(checks)
    counts = {}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    return {"kind": kind, "policy": str(path), "verdict": v,
            "exit_code": EXIT_CODES[v], "counts": counts, "checks": checks}


def render(rep):
    lines = ["RUNBOOK %s %s" % (rep["kind"].upper(), rep["policy"])]
    for c in rep["checks"]:
        lines.append("  [%-6s] %-34s %s" % (c["status"].upper() if c["status"] == "manual"
                                            else c["status"], c["name"],
                                            c["evidence"].replace("\n", " ")))
    lines.append("  counts: %s" % ", ".join("%s=%d" % kv for kv in sorted(rep["counts"].items())))
    lines.append("VERDICT: %s (exit %d)" % (rep["verdict"], rep["exit_code"]))
    if rep["kind"] == "preflight":
        lines.append("  MANUAL is not a pass: run the named step (or check by hand) "
                     "before the release.")
    return "\n".join(lines)


def _in_actions_dir(path):
    """True when `path` sits in a policies/actions/ directory (docs/ACTIONS.md,
    "Where action policies live") rather than directly under policies/."""
    return Path(path).resolve().parent.name == vpsexecpolicy.ACTIONS_SUBDIR


def _estate_root(path):
    """The estate root for a single policy file: one level up from
    policies/<file>.yaml, or one level further for policies/actions/<file>.yaml
    — an action policy lives one directory deeper, so its estate is one
    directory further up."""
    parent = Path(path).resolve().parent
    return parent.parent.parent if parent.name == vpsexecpolicy.ACTIONS_SUBDIR else parent.parent


def load_file(path, deny, today, governor_hosts=None):
    """Validate ONE policy file with the door's own rules. Returns
    (doc, raw, runbooks, assumes). Raises Refused exactly where load() would."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as e:
        raise Refused("cannot read %s: %s" % (path, e))
    if size > POLICY_MAX_BYTES:
        raise Refused("%s is %d bytes, over the %d-byte cap" % (path, size, POLICY_MAX_BYTES))
    doc, raw = vpsexecpolicy._read(path)
    unknown = sorted(set(doc) - vpsexecpolicy.KNOWN_KEYS)
    if unknown:
        raise Refused("policy %s has unknown top-level key(s) %r" % (path.name, unknown))
    if doc.get("version") != 1:
        raise Refused("policy %s: version must be 1" % path.name)
    if not str(doc.get("reason", "")).strip():
        raise Refused("policy %s has no top-level 'reason'" % path.name)
    vpsexecpolicy.check_placement(path, doc, in_actions_dir=_in_actions_dir(path))
    expires = vpsexecpolicy._check_expiry(path, doc, today)
    host_re = vpsexec.probe.HOST_RE
    vpsexecpolicy._check_shape(path, doc, host_re)
    runbooks = [vpsexecpolicy._check_runbook(path, n, entry, deny, governor_hosts,
                                             host_re, expires)
                for n, entry in enumerate(doc.get("runbooks") or [], 1)]
    assumes = vpsexecpolicy.check_assumes(path, doc, host_re, governor_hosts)
    return doc, raw, runbooks, assumes


def _push_of(cmd):
    words = (cmd or "").split()
    if len(words) == 3 and words[0] == vpsexec.PUSH_CANONICAL:
        return words[1], words[2]
    return None


def _first_line(text, n=90):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n - 1] + "…"


# ---- lint: the "cannot fail" heuristic -----------------------------------

def _tokens(command):
    # `2>&1` and `&>` are redirections, not the `&` operator.
    command = re.sub(r"\d*>&\d+|&>>?", " ", command)
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _simple_never_fails(words, piped):
    if not words:
        return False
    head = os.path.basename(words[0])
    if head in _ALWAYS_ZERO:
        return True
    if head == "exit":
        return words[1:] in ([], ["0"])
    if piped and head in _PIPE_FILTERS:
        return True
    if piped and head in ("awk", "sed"):
        program = " ".join(words[1:])
        return not re.search(r"\bexit\b|\bq\b|\bQ\b", program)
    if head == "docker":
        rest = [w for w in words[1:] if not w.startswith("-")]
        return rest[:1] in (["ps"], ["images"]) or rest[:2] in (["compose", "ps"],
                                                                 ["compose", "ls"])
    return False


def _pipeline_can_fail(words_list):
    # Without pipefail a pipeline's status is its last command's.
    return not _simple_never_fails(words_list[-1], len(words_list) > 1)


def can_fail(command):
    """False only when the command provably exits 0 (a known always-zero form,
    or `|| true`). Unknown or unparseable means True: never a false alarm."""
    try:
        tokens = _tokens(command)
    except ValueError:
        return True
    statements, current = [], []
    for t in tokens:
        if t in (";", "&", "\n"):
            statements.append(current)
            current = []
        else:
            current.append(t)
    statements.append(current)
    statements = [s for s in statements if s]
    if not statements:
        return True
    last = statements[-1]
    # Split the last statement into pipelines joined by && / ||, then fold
    # left: `a && b` fails if either can; `a || b` fails only if both can.
    pipelines, ops, words, pipe = [], [], [], []
    for t in last + ["&&"]:
        if t in ("&&", "||"):
            pipe.append(words)
            pipelines.append(pipe)
            ops.append(t)
            words, pipe = [], []
        elif t == "|":
            pipe.append(words)
            words = []
        elif set(t) <= set("|&;"):
            return True  # an operator this fold does not model
        else:
            words.append(t)
    ops = ops[:-1]
    fails = _pipeline_can_fail(pipelines[0])
    for op, pipe in zip(ops, pipelines[1:]):
        right = _pipeline_can_fail(pipe)
        fails = (fails or right) if op == "&&" else (fails and right)
    return fails


# ---- lint ------------------------------------------------------------------

def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _artifact_index(dirs, wanted_names):
    """{basename: [path, ...]} for regular, non-symlink files under `dirs`."""
    found = {}
    for d in dirs:
        for root, subdirs, files in os.walk(str(d)):
            subdirs.sort()
            for name in sorted(files):
                if name not in wanted_names:
                    continue
                p = os.path.join(root, name)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                found.setdefault(name, []).append(p)
    return found


def _lint_pushes(runbooks, artifact_dirs):
    pushes = [(n, _push_of(r["cmd"])) for n, r in enumerate(runbooks, 1)]
    pushes = [(n, p) for n, p in pushes if p]
    if not pushes:
        return [_result("pushes", "skip", "no vpscfg-push steps")]
    dirs = [d for d in artifact_dirs if Path(d).is_dir()]
    if not dirs:
        return [_result("pushes", "fail", "%d push step(s) but no artifact directory "
                        "(looked in: %s) — pass --artifacts DIR"
                        % (len(pushes), ", ".join(str(d) for d in artifact_dirs) or "none"))]
    index = _artifact_index(dirs, set(name for _, (_, name) in pushes))
    out = []
    for n, (sha, name) in pushes:
        paths = index.get(name, [])
        if not paths:
            out.append(_result("push step %d" % n, "fail",
                               "%s: local source missing under %s" % (name, ", ".join(map(str, dirs)))))
            continue
        hashes = {}
        for p in paths:
            try:
                if os.path.getsize(p) > vpsexec.PUSH_MAX_BYTES:
                    hashes[p] = "over the push size cap"
                    continue
                hashes[p] = _hash_file(p)
            except OSError as e:
                hashes[p] = "unreadable (%s)" % e.strerror
        match = [p for p, h in hashes.items() if h == sha]
        if match:
            out.append(_result("push step %d" % n, "pass", "%s sha256 %s… at %s"
                               % (name, sha[:12], match[0])))
        else:
            out.append(_result("push step %d" % n, "fail", "%s: sha256 mismatch — the "
                               "runbook names %s…, local has %s" % (
                                   name, sha[:12], "; ".join("%s at %s" % (h[:12] + "…" if
                                       len(h) == 64 else h, p) for p, h in hashes.items()))))
    return out


def _lint_timeouts(runbooks):
    missing = [n for n, r in enumerate(runbooks, 1) if not r.get("timeout")]
    if not missing:
        return _result("timeouts", "pass", "every step names a timeout")
    return _result("timeouts", "warn", "step(s) %s have no timeout: the door predicts one "
                   "(read 60s, mutations up to 300s) and a play cannot carry what the "
                   "runbook never said" % ", ".join(map(str, missing)), data=missing)


def _lint_stops(runbooks):
    out = []
    for n, r in enumerate(runbooks, 1):
        if STOP_RE.search(str(r["why"])) and not can_fail(r["cmd"]):
            out.append(_result("stop step %d" % n, "fail",
                               "why says STOP, but `%s` exits 0 whatever it finds — the "
                               "halt can never fire. Make the check fail (grep -q, test, "
                               "curl -f) or drop the STOP" % _first_line(r["cmd"], 120)))
    return out or [_result("stop steps", "pass", "every STOP step can exit non-zero")]


def _lint_expiry(doc, now):
    expires = doc.get("expires")
    if not expires:
        return _result("expires", "skip", "no expires (the file grants nothing)")
    expires = str(expires)
    end = datetime.datetime.combine(datetime.date.fromisoformat(expires)
                                    + datetime.timedelta(days=1), datetime.time())
    left = end - now
    if left.total_seconds() <= 0:
        return _result("expires", "fail", "expired %s — its runbooks are DISARMED" % expires)
    hours = left.total_seconds() / 3600
    if hours <= EXPIRY_WARN_HOURS:
        return _result("expires", "warn", "expires %s: its runbooks disarm in %.0fh"
                       % (expires, hours))
    return _result("expires", "pass", "expires %s (%.0f days left)" % (expires, hours / 24))


def _lint_shape(doc, runbooks):
    if not runbooks:
        return _result("shape", "skip", "no runbooks")
    if "shape" not in doc:
        return _result("shape", "fail", "no shape declared — the file is DISARMED. Add "
                       "shape: %s" % _shape_yaml(vpsexecpolicy.runbook_shape(runbooks)))
    declared = {"steps": doc["shape"]["steps"], "hosts": sorted(doc["shape"]["hosts"]),
                "break_glass": doc["shape"]["break_glass"]}
    mismatch = vpsexecpolicy._shape_mismatch(declared, runbooks)
    if mismatch:
        return _result("shape", "fail", "%s — the file is DISARMED until the shape matches"
                       % mismatch)
    return _result("shape", "pass", "%d steps, hosts %s" % (declared["steps"],
                                                            ", ".join(declared["hosts"])))


def _shape_yaml(shape):
    bg = shape["break_glass"]
    return "{steps: %d, hosts: [%s], break_glass: %s}" % (
        shape["steps"], ", ".join(shape["hosts"]),
        bg if isinstance(bg, str) else ("true" if bg else "false"))


def _load_plays(plays_dir):
    """[(path, steps)] for every readable plays/*.yaml; unreadable ones are
    returned with steps=None so lint can say so."""
    import yaml
    out = []
    d = Path(plays_dir)
    if not d.is_dir():
        return out
    for p in sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml"))):
        try:
            doc = yaml.safe_load(p.read_bytes())
            steps = doc.get("steps") if isinstance(doc, dict) else None
            if not isinstance(steps, list):
                raise ValueError("no steps list")
            parsed = []
            for s in steps:
                if not isinstance(s, dict):
                    raise ValueError("a step is not a mapping")
                flags = [str(f) for f in (s.get("flags") or [])]
                timeout = None
                for f in flags:
                    m = TIMEOUT_FLAG_RE.match(f)
                    if m:
                        timeout = int(m.group(1))
                canonical, action_error = None, None
                if "action" in s or "with" in s:
                    # V4: an action step is matched by the canonical string the
                    # door would build from it — the same spelling a runbook's
                    # action entry is authorised by.
                    try:
                        action = actions.get(s.get("action"), "play step")
                        canonical = actions.canonical(action, actions.validate(
                            action, s.get("with"), "play step"))
                    except Refused as e:
                        action_error = str(e)
                parsed.append({"cmd": canonical if canonical is not None
                               else vpsexec.normalize(str(s.get("cmd") or "")),
                               "push_sha": str(s["sha256"]) if "push" in s else None,
                               "action": s.get("action") if ("action" in s or "with" in s)
                               else None, "action_error": action_error,
                               "timeout": timeout, "text": json.dumps(s, sort_keys=True),
                               "id": s.get("id"), "when": s.get("when")})
            out.append((p, parsed))
        except (OSError, ValueError, AttributeError, yaml.YAMLError) as e:
            out.append((p, "%s" % e))
    return out


def _condition_problems(steps):
    """vpsrun's `id:` / `when:` rules at authoring time: an id is 1-32 of
    [A-Za-z0-9_-] and unique; `when` reads '<earlier id> reports <regex>' and
    the regex compiles."""
    problems, ids = [], []
    for i, s in enumerate(steps, 1):
        if s["when"] is not None:
            m = WHEN_RE.match(str(s["when"]).strip())
            if not m:
                problems.append("step %d when must read '<earlier step id> reports "
                                "<regex>'" % i)
            elif m.group(1) not in ids:
                problems.append("step %d when names %r, which is not the id of an "
                                "EARLIER step in this play" % (i, m.group(1)))
            else:
                try:
                    re.compile(m.group(2))
                except re.error as e:
                    problems.append("step %d when regex does not compile (%s)" % (i, e))
        if s["id"] is not None:
            sid = str(s["id"])
            if not STEP_ID_RE.match(sid):
                problems.append("step %d id %r must be 1-32 of [A-Za-z0-9_-]" % (i, sid))
            elif sid in ids:
                problems.append("step %d id %r is already used by an earlier step"
                                % (i, sid))
            ids.append(sid)
    return problems


def _step_index(play_step, runbooks):
    """The runbook step numbers a play step is (same push sha, or same command)."""
    hits = []
    for n, r in enumerate(runbooks, 1):
        push = _push_of(r["cmd"])
        if play_step["push_sha"]:
            if push and push[0] == play_step["push_sha"]:
                hits.append(n)
        elif play_step.get("action") is not None:
            if r.get("action") and play_step["cmd"] == r["cmd"]:
                hits.append(n)
        elif play_step["cmd"] and not r.get("action") and play_step["cmd"] == r["cmd"]:
            hits.append(n)
    return hits


def _unmatched_problem(i, s, deny, risky_extra, others):
    """None when a play step that matches no step of THIS policy is still
    sound: a plain read (reads need no runbook), or a step of another
    committed policy file. Otherwise the reason it makes the play NO-GO (V3:
    a play left stale by a policy edit runs a step nothing authorises)."""
    if s.get("action_error"):
        return "step %d action cannot be expanded by this door (%s)" % (i, s["action_error"])
    if s["action"] is None and not s["push_sha"]:
        try:
            tier, _ = vpsexec.classify(s["cmd"], deny, risky_extra)
        except Refused as e:
            return "step %d `%s` is refused outright (%s)" % (i, _first_line(s["cmd"], 80), e)
        if tier == "read":
            return None
    if _step_index(s, others):
        return None
    what = ("push %s…" % s["push_sha"][:12] if s["push_sha"]
            else "`%s`" % _first_line(s["cmd"], 100))
    return ("step %d %s matches no runbook step in this policy or any other committed "
            "policy — the play is stale (the policy was edited after it was generated) "
            "or the step was never authorised; regenerate it (`vpsrun release new ... "
            "--replace`) or fix the step" % (i, what))


def _plays_claimed(policy_path, releases_dir):
    """Play file names run by a release that lists this policy in its
    `policies:` — those plays are this policy's even when a policy edit has
    left not one of their steps matching (V3: a fully stale play)."""
    import yaml
    d, me, out = Path(releases_dir), Path(policy_path).name, set()
    if not d.is_dir():
        return out
    for p in sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml"))):
        try:
            doc = yaml.safe_load(p.read_bytes())
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict) or me not in [
                str(x) for x in (doc.get("policies") or []) if isinstance(doc.get("policies"), list)]:
            continue
        for e in doc.get("plays") if isinstance(doc.get("plays"), list) else []:
            e = e.get("play") if isinstance(e, dict) else e
            if isinstance(e, str):
                out.add(e if e.endswith((".yaml", ".yml")) else e + ".yaml")
    return out


def _lint_plays(runbooks, raw_text, plays_dir, deny=(), risky_extra=(), others=(),
                claimed=frozenset()):
    """(results, covered step numbers, number of plays that are for this policy).
    `others` are the committed runbook steps of every OTHER policy file (a
    play may legitimately run them); a mutation step matching nothing in
    either is a failure, never silently ignored."""
    from . import releasenew
    plays = _load_plays(plays_dir)
    out, covered, mine, names = [], set(), 0, []
    for path, steps in plays:
        if isinstance(steps, str):
            continue  # not ours to judge: vpsrun refuses an unreadable play itself
        matched = [(s, _step_index(s, runbooks)) for s in steps]
        if not any(hits for _, hits in matched) and path.name not in claimed:
            continue
        mine += 1
        names.append(path.name)
        problems, warnings = _condition_problems(steps), []
        for i, s in enumerate(steps, 1):
            m = WHEN_RE.match(str(s["when"] or "").strip())
            if m and m.group(2) == releasenew.STUB_REGEX:
                problems.append("step %d still carries `release new`'s placeholder when: "
                                "(%s) — write the real condition or delete the when:"
                                % (i, releasenew.STUB_REGEX))
        for i, (s, hits) in enumerate(matched, 1):
            if hits or not _step_index(s, others):
                stray = sorted(set(HEX64_RE.findall(s["text"]))
                               - set(HEX64_RE.findall(raw_text)))
                if stray:
                    problems.append("step %d names hash(es) not in the policy: %s"
                                    % (i, ", ".join(h[:12] + "…" for h in stray)))
            if not hits:
                problem = _unmatched_problem(i, s, deny, risky_extra, others)
                if problem:
                    problems.append(problem)
                continue
            optional = [n for n in hits if OPTIONAL_RE.search(str(runbooks[n - 1]["why"]))
                        and not runbooks[n - 1].get("rollback")]
            if optional and s["when"] is None:
                warnings.append("step %d runs runbook step %s, which says optional / only "
                                "if, unconditionally — give it a `when:` on the step that "
                                "decides, or confirm production always needs it"
                                % (i, "/".join(map(str, optional))))
            covered.update(hits)
            wanted = max([runbooks[n - 1].get("timeout") or 0 for n in hits] or [0])
            if wanted and s["timeout"] is None:
                warnings.append("step %d has no --timeout= (runbook step %s says %ds)"
                                % (i, "/".join(map(str, hits)), wanted))
            elif wanted and s["timeout"] < wanted:
                problems.append("step %d --timeout=%d is shorter than runbook step %s's "
                                "%ds — an explicit timeout wins and cuts it off"
                                % (i, s["timeout"], "/".join(map(str, hits)), wanted))
        name = "play %s" % path.name
        if problems:
            out.append(_result(name, "fail", "; ".join(problems + warnings)))
        elif warnings:
            out.append(_result(name, "warn", "; ".join(warnings)))
        else:
            out.append(_result(name, "pass", "%d step(s); hashes and timeouts carried"
                               % len(steps)))
    if not mine:
        out.append(_result("plays", "skip", "no play under %s runs this policy's steps"
                           % plays_dir))
    return out, covered, mine, names


def _lint_releases(policy_path, runbooks, my_plays, plays_dir, releases_dir):
    """releases/*.yaml (vpsrun release) that run this policy's plays, list it
    in `policies:` or name it in `on_fail`. Each must name plays that exist,
    list this policy for its one reusable grant when it runs this policy's
    break-glass steps, and offer only entries that are rollback steps here."""
    import yaml
    d = Path(releases_dir)
    if not d.is_dir():
        return [_result("releases", "skip", "no releases directory at %s" % d)]
    me = Path(policy_path).name
    any_bg = any(r.get("break_glass") for r in runbooks)
    out = []
    for p in sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml"))):
        try:
            doc = yaml.safe_load(p.read_bytes())
        except (OSError, yaml.YAMLError):
            continue  # vpsrun refuses an unreadable release itself
        if not isinstance(doc, dict):
            continue
        names = []
        for e in doc.get("plays") if isinstance(doc.get("plays"), list) else []:
            e = e.get("play") if isinstance(e, dict) else e
            if isinstance(e, str):
                names.append(e if e.endswith((".yaml", ".yml")) else e + ".yaml")
        policies = ([str(x) for x in doc["policies"]]
                    if isinstance(doc.get("policies"), list) else [])
        on_fail = ([o for o in doc["on_fail"] if isinstance(o, dict)]
                   if isinstance(doc.get("on_fail"), list) else [])
        runs_mine = [n for n in names if n in my_plays]
        mine_fail = [o for o in on_fail if str(o.get("runbook")) in (me, Path(me).stem)]
        if not runs_mine and me not in policies and not mine_fail:
            continue
        problems, warnings = [], []
        for n in names:
            if not PLAY_NAME_RE.match(n) or not (Path(plays_dir) / n).is_file():
                problems.append("play %s is not a file under %s" % (n, plays_dir))
        if runs_mine and any_bg and me not in policies:
            warnings.append("runs %s (this policy's steps) but does not list %s in "
                            "policies: — the one reusable grant it mints will not cover "
                            "them" % (", ".join(runs_mine), me))
        for o in mine_fail:
            step = o.get("step")
            if isinstance(step, bool) or not isinstance(step, int) or not (
                    1 <= step <= len(runbooks)):
                problems.append("on_fail names %s step %r, which does not exist" % (me, step))
            elif not runbooks[step - 1].get("rollback"):
                problems.append("on_fail names %s step %d, which is not a rollback step "
                                "(rollback: true)" % (me, step))
        name = "release %s" % p.name
        if problems:
            out.append(_result(name, "fail", "; ".join(problems + warnings)))
        elif warnings:
            out.append(_result(name, "warn", "; ".join(warnings)))
        else:
            out.append(_result(name, "pass", "%d play(s); names and rollbacks agree"
                               % len(names)))
    return out or [_result("releases", "skip", "no release under %s runs or names this "
                           "policy" % d)]


def _lint_optional(runbooks, covered, mine):
    flagged = [n for n, r in enumerate(runbooks, 1)
               if OPTIONAL_RE.search(str(r["why"])) and not r.get("rollback")]
    if not flagged:
        return _result("optional steps", "pass", "no optional / only-if steps")
    if not mine:
        return _result("optional steps", "skip", "step(s) %s are optional; no play to "
                       "compare" % ", ".join(map(str, flagged)))
    left = [n for n in flagged if n not in covered]
    if left:
        return _result("optional steps", "warn",
                       "step(s) %s say optional / only if, and no play includes them. "
                       "Decide now whether production needs them (this weekend it did)"
                       % ", ".join(map(str, left)), data=left)
    return _result("optional steps", "pass", "every optional step is in a play")


def _lint_assumes(assumes, action_assumes, runbooks):
    """`assumes` is the hand-written list; `action_assumes` is
    `actions.step_assumes(runbooks)` — `[(step, item)]` for every fact an
    action step assumes (docs/ACTIONS.md). Both are checked the same way;
    an action-derived one is labelled "(from action step N)"."""
    total = len(assumes) + len(action_assumes)
    if not total:
        return [_result("assumes", "warn" if runbooks else "skip",
                        "no assumes: block — preflight has nothing to compare against "
                        "the hosts")]
    out = []
    for n, item in enumerate(assumes, 1):
        manual = [k for k in vpsexecpolicy.ASSUME_MANUAL_KEYS if k in item]
        if manual and not item.get("verified_by"):
            out.append(_result("assumes[%d]" % n, "warn",
                               "%s cannot be read from the read tier and no step is named "
                               "to verify it — add verified_by: <step>" % ", ".join(manual)))
    for step, item in action_assumes:
        manual = [k for k in vpsexecpolicy.ASSUME_MANUAL_KEYS if k in item]
        if manual and not item.get("verified_by"):
            out.append(_result("assumes[action step %d]" % step, "warn",
                               "%s cannot be read from the read tier and no step is named "
                               "to verify it — add verified_by: <step> (from action step %d)"
                               % (", ".join(manual), step)))
    return out or [_result("assumes", "pass", "%d item(s) declared; run `vpsexec runbook "
                           "preflight` to check them" % total)]


def _lint_probe_steps(runbooks, deny, risky_extra):
    """A step whose `why` says probe/precheck/check (or STOP) must itself
    classify as a read — the weekend's "a probe wrote text into an integer
    column" halt, caught before it is armed. An action step's own check and
    verify are already gated at plan time (vpsexec._gate_action); this rule
    is for hand-written `cmd:` steps only."""
    out = []
    for n, r in enumerate(runbooks, 1):
        if r.get("action") or not (PROBE_WHY_RE.search(str(r["why"]))
                                   or STOP_RE.search(str(r["why"]))):
            continue
        try:
            tier, detail = vpsexec.classify(r["cmd"], deny, risky_extra)
        except Refused as e:
            out.append(_result("probe step %d" % n, "fail",
                               "why says probe/precheck/check/STOP, but `%s` is refused "
                               "outright (%s)" % (_first_line(r["cmd"], 100), e)))
            continue
        if tier != "read":
            out.append(_result("probe step %d" % n, "fail",
                               "why says probe/precheck/check/STOP, but `%s` classifies as "
                               "%s%s, not a read — a probe that can write is not a probe. "
                               "Use assumes.privileges or an action's done-check instead of "
                               "a write used as a check"
                               % (_first_line(r["cmd"], 100), tier,
                                  " (%s)" % detail if detail else "")))
    return out or [_result("probe steps", "pass", "every probe/precheck/check/STOP step "
                           "classifies as a read")]


def _lint_expands(doc, runbooks):
    r = actions.lint_expands(doc, runbooks)
    return _result(r["name"], r["status"], r["evidence"])


def lint(path, guard, policy=None, plays_dir=None, artifact_dirs=None, today=None,
         now=None, releases_dir=None):
    path = Path(path)
    now = now or datetime.datetime.now()
    today = today or now.date().isoformat()
    estate = _estate_root(path)
    plays_dir = Path(plays_dir) if plays_dir else estate / "plays"
    releases_dir = Path(releases_dir) if releases_dir else estate / "releases"
    artifact_dirs = [Path(d) for d in (artifact_dirs or [estate / "artifacts"])]
    deny = list(guard.deny_patterns()) + list((policy or {}).get("deny_extra", []))
    risky_extra = list((policy or {}).get("risky_extra", []))
    try:
        doc, raw, runbooks, assumes = load_file(path, deny, today,
                                                set(guard.policy.get("hosts", {})))
    except Refused as r:
        return report("lint", path, [_result("policy", "fail", r)])
    checks = [_result("policy", "pass", "loads under the door's rules (%d step(s))"
                      % len(runbooks)),
              _lint_shape(doc, runbooks), _lint_expiry(doc, now), _lint_timeouts(runbooks)]
    checks.append(_lint_expands(doc, runbooks))
    checks += _lint_pushes(runbooks, artifact_dirs)
    checks += _lint_stops(runbooks)
    checks += _lint_probe_steps(runbooks, deny, risky_extra)
    others = [r for r in (policy or {}).get("runbooks") or []
              if r.get("source") != path.name]
    play_results, covered, mine, names = _lint_plays(
        runbooks, raw.decode("utf-8", "replace"), plays_dir, deny, risky_extra, others,
        _plays_claimed(path, releases_dir))
    checks += play_results
    checks += _lint_releases(path, runbooks, names, plays_dir, releases_dir)
    checks.append(_lint_optional(runbooks, covered, mine))
    checks += _lint_assumes(assumes, actions.step_assumes(runbooks), runbooks)
    return report("lint", path, checks)


# ---- preflight -------------------------------------------------------------

class _NotRead(Exception):
    pass


def _probe(ctx, host, command):
    """One fixed read through the door's own gates. Output is masked before
    it is returned; nothing unmasked leaves this function."""
    tier, detail = vpsexec.classify(command, ctx["deny"], ctx["risky"])
    if tier != "read":
        raise _NotRead("%s%s" % (tier, " (%s)" % detail if detail else ""))
    deny_scan(command, ctx["deny"])
    journal.append("vpsexec", {"event": "read", "hosts": [host], "command": command,
                               "via": "runbook preflight"})
    rc, out, err = ctx["ssh"](host, command, timeout=vpsexec.READ_TIMEOUT)
    return rc, secretmask.mask(out) or "", secretmask.mask(err) or ""


def _manual_note(item, runbooks, what):
    step = item.get("verified_by")
    if step:
        return "%s Verify with runbook step %d: %s" % (
            what, step, _first_line(runbooks[step - 1]["why"]))
    return "%s No runbook step verifies this — add one and name it with verified_by:." % what


def _inspect(ctx, host, container, template):
    return _probe(ctx, host, "docker inspect --format %s %s"
                  % (shlex.quote(template), shlex.quote(container)))


def _container_checks(ctx, label, item, host):
    name = item["container"]
    tag = "assumes[%s] %s" % (label, name)
    rc, out, err = _inspect(ctx, host, name, "{{.Image}} {{.State.Status}}")
    if rc != 0:
        if "no such" in (err + out).lower():
            return [_result(tag, "fail", "container %s not found on %s" % (name, host))]
        return [_result(tag, "error", "docker inspect rc=%d: %s" % (rc, _first_line(err or out)))]
    parts = out.split()
    image, state = (parts + ["", ""])[:2]
    results = [_result(tag, "pass" if state == "running" else "fail",
                       "%s on %s is %s, image %s" % (name, host, state or "unknown", image),
                       data={"image": image, "state": state})]
    if "image" in item:
        ok = image == item["image"]
        results.append(_result(tag + " image", "pass" if ok else "fail",
                               "image %s%s" % (image, "" if ok else ", the runbook assumes %s"
                                               % item["image"])))
    if "env_names_any_of" in item:
        rc, out, err = _inspect(ctx, host, name,
                                '{{range .Config.Env}}{{index (split . "=") 0}} {{end}}')
        if rc != 0:
            results.append(_result(tag + " env names", "error", "rc=%d: %s"
                                   % (rc, _first_line(err or out))))
        else:
            # Names only. Anything after `=` is dropped, should a host ever
            # hand a value back.
            names = sorted(set(w.split("=", 1)[0] for w in out.split()
                               if vpsexecpolicy.ENV_NAME_RE.fullmatch(w.split("=", 1)[0])))
            sets = item["env_names_any_of"]
            hit = next((s for s in sets if set(s) <= set(names)), None)
            if hit:
                results.append(_result(tag + " env names", "pass", "has %s"
                                       % ", ".join(hit), data={"names": names}))
            else:
                results.append(_result(tag + " env names", "fail", "none of the assumed "
                                       "sets is complete: %s. Present: %s" % (
                                           "; ".join("[%s] lacks %s" % (", ".join(s), ", ".join(
                                               sorted(set(s) - set(names)))) for s in sets),
                                           ", ".join(names) or "(none)"),
                                       data={"names": names}))
    if "compose_labels" in item or "compose_files" in item:
        rc, out, err = _inspect(ctx, host, name, "{{json .Config.Labels}}")
        try:
            if rc != 0:
                raise ValueError("rc=%d: %s" % (rc, _first_line(err or out)))
            labels = json.loads(out or "null") or {}
            if not isinstance(labels, dict):
                raise ValueError("labels are not a mapping")
        except ValueError as e:
            return results + [_result(tag + " labels", "error", "cannot read labels: %s" % e)]
        for key, want in sorted((item.get("compose_labels") or {}).items()):
            have = labels.get(key)
            results.append(_result("%s label %s" % (tag, key), "pass" if have == want else "fail",
                                   "%s=%s%s" % (key, have if have is not None else "(absent)",
                                                "" if have == want else ", assumed %s" % want)))
        if "compose_files" in item:
            have = set(f.strip() for f in str(labels.get(
                "com.docker.compose.project.config_files") or "").split(",") if f.strip())
            missing = [f for f in item["compose_files"] if f not in have]
            results.append(_result(tag + " compose files", "fail" if missing else "pass",
                                   "not in the container's compose config_files (%s): %s"
                                   % (", ".join(sorted(have)) or "none", ", ".join(missing))
                                   if missing else "started from %s" % ", ".join(item["compose_files"])))
    return results


def _absent_check(ctx, label, item, host):
    paths = item["absent"]
    tag = "assumes[%s] absent" % label
    rc, out, err = _probe(ctx, host, "ls -d -- %s" % " ".join(shlex.quote(p) for p in paths))
    present = set(line.strip() for line in out.splitlines())
    gone, exists, unknown = [], [], []
    for p in paths:
        if p in present:
            exists.append(p)
        elif any(p in line and "No such file" in line for line in err.splitlines()):
            gone.append(p)
        else:
            unknown.append(p)
    if exists:
        return _result(tag, "fail", "already exist on %s: %s — the runbook creates them"
                       % (host, ", ".join(exists)))
    if unknown:
        return _result(tag, "error", "could not tell for %s (rc=%d: %s)"
                       % (", ".join(unknown), rc, _first_line(err or out)))
    return _result(tag, "pass", "absent on %s: %s" % (host, ", ".join(gone)))


def _free_check(ctx, label, item, host):
    wants = item["min_free_gb"]
    paths = list(wants)
    tag = "assumes[%s] free disk" % label
    rc, out, err = _probe(ctx, host, "df -P -k -- %s" % " ".join(shlex.quote(p) for p in paths))
    rows = [line.split() for line in out.splitlines()[1:] if line.strip()]
    if rc != 0 or len(rows) != len(paths):
        return _result(tag, "error", "df rc=%d, %d row(s) for %d path(s): %s"
                       % (rc, len(rows), len(paths), _first_line(err or out)))
    low, seen = [], []
    for p, row in zip(paths, rows):
        try:
            gb = int(row[3]) / (1024.0 * 1024.0)
        except (IndexError, ValueError):
            return _result(tag, "error", "cannot parse df for %s" % p)
        seen.append("%s %.1fG" % (p, gb))
        if gb < wants[p]:
            low.append("%s has %.1fG free, needs %sG" % (p, gb, wants[p]))
    if low:
        return _result(tag, "fail", "; ".join(low))
    return _result(tag, "pass", ", ".join(seen))


def _age_text(age):
    hours = age / 3600.0
    if hours < 1:
        return "%dm" % max(1, round(age / 60.0))
    return "%.0fh" % hours


def _index_doc(ctx, host):
    """The cached index document for `host`, fetched (and journalled as
    `preflight_source`) at most once per preflight run.
    -> (doc_or_None, age_seconds_or_None, reason_or_None)."""
    if host in ctx["index_cache"]:
        return ctx["index_cache"][host]
    if ctx["live"]:
        doc, age, reason = None, None, "forced live (--live)"
    else:
        doc, age, reason = indexstore.cache_status(host, ctx["index_dir"], ctx["max_age"],
                                                   now=ctx["now"])
    ctx["index_cache"][host] = (doc, age, reason)
    journal.append("vpsexec", {"event": "preflight_source", "host": host,
                               "index_usable": doc is not None,
                               "age_seconds": age, "reason": reason,
                               "via": "runbook preflight (index)"})
    return doc, age, reason


def _with_source(results, source, suffix=""):
    out = []
    for r in results:
        r = dict(r)
        r["evidence"] = ("%s %s%s" % (r["evidence"], source, suffix))[:EVIDENCE_MAX]
        out.append(r)
    return out


# Compose labels the index records (hostindex._parse_inspect), by label name.
_INDEX_LABELS = {
    "com.docker.compose.project": lambda c: (c.get("compose") or {}).get("project"),
    "com.docker.compose.service": lambda c: (c.get("compose") or {}).get("service"),
    "com.docker.compose.project.working_dir":
        lambda c: (c.get("compose") or {}).get("working_dir"),
    # recorded split on ","; the label is the files joined with "," again
    "com.docker.compose.project.config_files":
        lambda c: ",".join((c.get("compose") or {}).get("config_files") or []) or None,
}


def _container_from_index(doc, label, item, host):
    """(results, None) when a fresh index answers EVERY fact the item assumes
    about its container (state, image id, env NAMES, the compose labels and
    files it records), else (None, why) and the caller falls back to live.
    The index holds env names only, never values (hostindex)."""
    name = item["container"]
    tag = "assumes[%s] %s" % (label, name)
    sec = ((doc or {}).get("sections") or {}).get("containers")
    if not isinstance(sec, dict) or "error" in sec or "unavailable" in sec:
        return None, "the index's containers section has an error"
    if not sec.get("docker"):
        return None, "the index recorded no docker daemon"
    if name in (sec.get("skipped") or []):
        return None, "the index skipped container %s" % name
    unknown = sorted(k for k in item.get("compose_labels") or {} if k not in _INDEX_LABELS)
    if unknown:
        return None, "the index does not record label(s) %s" % ", ".join(unknown)
    c = next((x for x in sec.get("containers") or [] if x.get("name") == name), None)
    if c is None:
        return [_result(tag, "fail", "container %s is not in the index's container list for "
                        "%s" % (name, host))], None
    state, image = c.get("state") or "", c.get("image_id") or ""
    if "image" in item and not image:
        return None, "the index recorded no image id for %s" % name
    names = c.get("env_names")
    if "env_names_any_of" in item and not isinstance(names, list):
        return None, "the index recorded no env names for %s" % name
    results = [_result(tag, "pass" if state == "running" else "fail",
                       "%s on %s is %s, image %s" % (name, host, state or "unknown", image),
                       data={"image": image, "state": state})]
    if "image" in item:
        ok = image == item["image"]
        results.append(_result(tag + " image", "pass" if ok else "fail",
                               "image %s%s" % (image, "" if ok else ", the runbook assumes %s"
                                               % item["image"])))
    if "env_names_any_of" in item:
        present = sorted(set(n for n in names if isinstance(n, str)
                             and vpsexecpolicy.ENV_NAME_RE.fullmatch(n)))
        sets = item["env_names_any_of"]
        hit = next((s for s in sets if set(s) <= set(present)), None)
        if hit:
            results.append(_result(tag + " env names", "pass", "has %s" % ", ".join(hit),
                                   data={"names": present}))
        else:
            results.append(_result(tag + " env names", "fail", "none of the assumed sets is "
                                   "complete: %s. Present: %s" % (
                                       "; ".join("[%s] lacks %s" % (", ".join(s), ", ".join(
                                           sorted(set(s) - set(present)))) for s in sets),
                                       ", ".join(present) or "(none)"),
                                   data={"names": present}))
    for key, want in sorted((item.get("compose_labels") or {}).items()):
        have = _INDEX_LABELS[key](c)
        results.append(_result("%s label %s" % (tag, key), "pass" if have == want else "fail",
                               "%s=%s%s" % (key, have if have is not None else "(absent)",
                                            "" if have == want else ", assumed %s" % want)))
    if "compose_files" in item:
        have = set((c.get("compose") or {}).get("config_files") or [])
        missing = [f for f in item["compose_files"] if f not in have]
        results.append(_result(tag + " compose files", "fail" if missing else "pass",
                               "not in the container's compose config_files (%s): %s"
                               % (", ".join(sorted(have)) or "none", ", ".join(missing))
                               if missing else "started from %s" % ", ".join(item["compose_files"])))
    return results, None


def _container_step(ctx, label, item, host, suffix):
    """The container facts: from a fresh index when it answers all of them
    (citing its age), else a live read (journaled with the reason the index
    could not answer), else under --index-only a skip."""
    doc, age, reason = _index_doc(ctx, host)
    if doc is not None:
        results, reason = _container_from_index(doc, label, item, host)
        if results is not None:
            return _with_source(results, "(index, %s old)" % _age_text(age), suffix)
    if ctx["index_only"]:
        return [_result("assumes[%s] container" % label, "skip",
                        "cannot answer from the index (%s) — --index-only never dials%s"
                        % (reason, suffix))]
    journal.append("vpsexec", {"event": "preflight_live_fallback", "host": host,
                               "fact": "container", "container": item["container"],
                               "reason": reason, "via": "runbook preflight (index fallback)"})
    return _with_source(_container_checks(ctx, label, item, host),
                        "(live; index: %s)" % reason, suffix)


def _sql_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def _privileges_check(ctx, label, item, host):
    priv = item["privileges"]
    tag = "assumes[%s] privileges" % label
    schema = priv.get("schema") or "public"
    # Schema-qualified, each part quoted as an identifier server-side: an
    # unqualified name would resolve through the session's search_path.
    qualified = "format('%%I.%%I', %s, %s)" % (_sql_literal(schema), _sql_literal(priv["table"]))
    conds = " AND ".join(
        "has_table_privilege(%s, %s, %s)" % (_sql_literal(priv["role"]), qualified,
                                             _sql_literal(p))
        for p in sorted(priv["privs"]))
    sql = "SELECT CASE WHEN %s THEN 'VPSCFG-DONE' ELSE 'VPSCFG-NEEDED' END" % conds
    try:
        check = actions.SqlCheck(priv["container"], priv["db"], sql)
    except actions.ParamError as e:
        return [_result(tag, "error", "cannot build the privilege check: %s" % e)]
    command, script = check.command(), check.script()
    deny_scan(command, ctx["deny"])
    deny_scan(script, ctx["deny"])
    journal.append("vpsexec", {"event": "read", "hosts": [host], "command": command,
                               "via": "runbook preflight (privileges)"})
    # The real transport is binary-mode: stdin goes as bytes, output may come
    # back as bytes (L1: a str here was a TypeError in production).
    rc, out, err = ctx["ssh"](host, command, timeout=vpsexec.READ_TIMEOUT,
                              data=script.encode("utf-8"))
    out = secretmask.mask(vpsexec._decode(out)) or ""
    err = secretmask.mask(vpsexec._decode(err)) or ""
    token = check.token(out)
    privs_text = ", ".join(sorted(priv["privs"]))
    where = "%s.%s.%s" % (priv["db"], schema, priv["table"])
    if rc != 0 or token is None:
        return [_result(tag, "error", "privilege check rc=%d: %s" % (rc, _first_line(err or out)))]
    if token == actions.DONE:
        return [_result(tag, "pass", "%s holds %s on %s" % (priv["role"], privs_text, where))]
    return [_result(tag, "fail", "%s is missing at least one of %s on %s"
                   % (priv["role"], privs_text, where))]


def _owner_from_index(doc, owner):
    """`(not_owned_list, truncated_bool)` when the index can answer
    owner_of_tables for this item, or `(None, reason)` when it cannot."""
    sections = (doc or {}).get("sections") or {}
    pg = sections.get("postgres")
    if not isinstance(pg, dict) or "error" in pg or "unavailable" in pg:
        return None, "the index's postgres section has an error"
    inst = next((i for i in pg.get("instances") or []
                if i.get("container") == owner["container"]), None)
    if inst is None:
        return None, "container %s is not in the index's postgres instances" % owner["container"]
    if "error" in inst or "unavailable" in inst:
        return None, "the index's postgres instance for %s has an error" % owner["container"]
    database = owner.get("database")
    if not database:
        return None, "owner_of_tables has no database: — the index cannot choose one"
    db = next((d for d in inst.get("databases") or [] if d.get("name") == database), None)
    if db is None:
        return None, "database %s is not in the index" % database
    if "error" in db or "schemas_unavailable" in db:
        return None, "database %s's schemas are unavailable in the index" % database
    schemas = db.get("schemas") or []
    if owner.get("schema"):
        schemas = [s for s in schemas if s.get("name") == owner["schema"]]
        if not schemas:
            return None, "schema %s is not in the index" % owner["schema"]
    not_owned, truncated, recorded = [], False, 0
    for s in schemas:
        truncated = truncated or bool(s.get("tables_truncated"))
        for t in s.get("tables") or []:
            recorded += 1
            if t.get("owner") != owner["role"]:
                not_owned.append("%s.%s" % (s["name"], t["name"]))
    if not_owned:
        # A named unowned table is a real answer, truncated list or not.
        return sorted(not_owned), truncated
    # Nothing unowned among what was recorded proves "owns everything" only
    # when the list is complete and non-empty (M2): a truncated list may hide
    # an unowned table, and zero recorded tables proves nothing at all.
    if truncated:
        return None, ("the index's table list for %s was truncated, so it cannot prove "
                      "every table is owned" % database)
    if not recorded:
        return None, "the index recorded no tables in %s%s" % (
            database, (" schema %s" % owner["schema"]) if owner.get("schema") else "")
    return [], False


def _owner_of_tables_check(ctx, label, item, owner, host, runbooks):
    tag = "assumes[%s] owner_of_tables" % label
    scope = "%s%s" % (owner.get("database") or "the app database",
                      (" schema %s" % owner["schema"]) if owner.get("schema") else "")
    doc, age, cache_reason = _index_doc(ctx, host)
    unusable = cache_reason
    if doc is not None:
        not_owned, extra = _owner_from_index(doc, owner)
        if not_owned is not None:
            source = "(index, %s old)" % _age_text(age)
            if not_owned:
                shown = ", ".join(not_owned[:20])
                more = " (+%d more)" % (len(not_owned) - 20) if len(not_owned) > 20 else ""
                trunc = "; the index's table list was truncated — more may be unowned" \
                        if extra else ""
                return _result(tag, "fail", "role %s does not own: %s%s%s %s"
                              % (owner["role"], shown, more, trunc, source))
            return _result(tag, "pass", "role %s owns every table the index recorded in "
                          "%s %s" % (owner["role"], scope, source))
        unusable = extra
    if ctx["index_only"]:
        return _result(tag, "skip", "cannot answer owner_of_tables from the index (%s) — "
                       "--index-only never dials, and table ownership has no live check"
                       % unusable)
    note = _manual_note(item, runbooks, "Role %s must own every table, sequence and view "
                        "in %s (reached via %s). Ownership needs a database credential, "
                        "which the read tier does not hold." % (owner["role"], scope,
                                                                 owner["container"]))
    return _result(tag, "manual", "%s (%s)" % (note, unusable))


def _preflight_item(ctx, label, item, aliases, runbooks, suffix):
    host = aliases.get(item["host"], item["host"])
    checks = []
    live_steps = []
    if item.get("container"):
        # Index first (state, image, env NAMES, recorded compose labels), the
        # live read only when the index cannot answer: V7b.
        try:
            checks += _container_step(ctx, label, item, host, suffix)
        except _NotRead as e:
            checks.append(_result("assumes[%s]" % label, "manual",
                                  "this check needs a command the read tier does not "
                                  "allow (%s) — verify it by hand%s" % (e, suffix)))
        except Refused as r:
            checks.append(_result("assumes[%s]" % label, "error",
                                  "refused: %s%s" % (r, suffix)))
        except (OSError, subprocess.TimeoutExpired) as e:
            checks.append(_result("assumes[%s]" % label, "error",
                                  secretmask.mask("transport: %s" % e) + suffix))
    if item.get("absent"):
        live_steps.append(("absent", lambda: [_absent_check(ctx, label, item, host)]))
    if item.get("min_free_gb"):
        live_steps.append(("free disk", lambda: [_free_check(ctx, label, item, host)]))
    if item.get("privileges"):
        live_steps.append(("privileges", lambda: _privileges_check(ctx, label, item, host)))
    for kind, fn in live_steps:
        if ctx["index_only"]:
            checks.append(_result("assumes[%s] %s" % (label, kind), "skip",
                                  "no index data for %s — --index-only never dials%s"
                                  % (kind, suffix)))
            continue
        try:
            checks += _with_source(fn(), "(live)", suffix)
        except _NotRead as e:
            checks.append(_result("assumes[%s]" % label, "manual",
                                  "this check needs a command the read tier does not "
                                  "allow (%s) — verify it by hand%s" % (e, suffix)))
        except Refused as r:
            checks.append(_result("assumes[%s]" % label, "error",
                                  "refused: %s%s" % (r, suffix)))
        except (OSError, subprocess.TimeoutExpired) as e:
            # str(TimeoutExpired) carries the argv; mask it like the door does.
            checks.append(_result("assumes[%s]" % label, "error",
                                  secretmask.mask("transport: %s" % e) + suffix))
    owner = item.get("owner_of_tables")
    if owner:
        r = _owner_of_tables_check(ctx, label, item, owner, host, runbooks)
        r["evidence"] = (r["evidence"] + suffix)[:EVIDENCE_MAX]
        checks.append(r)
    for names in item.get("env_distinct") or []:
        tag = "assumes[%s] env_distinct" % label
        if ctx.get("secrets_compare") and ctx["index_only"]:
            r = _result(tag, "skip", "%s: --secrets-compare reads the host and "
                        "--index-only never dials" % ", ".join(names))
        elif ctx.get("secrets_compare"):
            r = _secrets_compare(ctx, tag, item, names, host, aliases, runbooks)
        else:
            r = _result(tag, "manual", _manual_note(
                item, runbooks, "%s must hold different values. Comparing values means "
                "reading them, which this tool never does (--secrets-compare runs the "
                "policy's ensure_secret token-only check instead)." % ", ".join(names)))
        r["evidence"] = (r["evidence"] + suffix)[:EVIDENCE_MAX]
        checks.append(r)
    return checks


def _secrets_compare(ctx, tag, item, names, host, aliases, runbooks):
    """D4 (opt-in): answer env_distinct with the token-only check of the
    policy's own ensure_secret steps on this host — the same pinned script,
    the same gate (_gate_token) and the same fail-closed parsing as the door.
    Every pair of `names` must be compared by some step (key vs one of its
    distinct_from). No value is ever read back: the result is a token, and
    on anything else the output is withheld."""
    covering = []
    for a, b in itertools.combinations(names, 2):
        found = None
        for n, r in enumerate(runbooks, 1):
            act = r.get("action")
            if not act or act["name"] != "ensure_secret":
                continue
            for h in r["hosts"]:
                exp = act["expansions"][h]
                p = exp.params
                if aliases.get(h, h) == host and (
                        (p["key"] == a and b in p["distinct_from"])
                        or (p["key"] == b and a in p["distinct_from"])):
                    found = (n, h, exp)
                    break
            if found:
                break
        if found is None:
            return _result(tag, "manual", _manual_note(
                item, runbooks, "%s must hold different values; --secrets-compare found "
                "no ensure_secret step on %s comparing %s with %s" % (", ".join(names),
                                                                      host, a, b)))
        if found not in covering:
            covering.append(found)
    steps = []
    for n, h, exp in covering:
        probe = exp.check or exp.verify
        where = "step %d (%s on %s)" % (n, exp.params["key"], exp.params["file"])
        steps.append(where)
        try:
            if not isinstance(probe, actions.TokenCheck):
                raise Refused("its check is not a token-only check")
            vpsexec._gate_probe(probe, "secrets-compare check", ctx["deny"], ctx["risky"],
                                exp)
            journal.append("vpsexec", {"event": "read", "hosts": [host],
                                       "command": "token-only check %s, %s" % (probe.key,
                                                                               where),
                                       "via": "runbook preflight (secrets-compare)"})
            rc, out, _err = vpsexec._run_probe(host, probe, ctx["ssh"], vpsexec.READ_TIMEOUT,
                                               ctx["deny"])
        except Refused as r:
            return _result(tag, "error", "secrets-compare %s refused: %s" % (where, r))
        except (OSError, subprocess.TimeoutExpired):
            journal.append("vpsexec", {"event": "secrets_compare", "host": host,
                                       "step": n, "token": None, "error": "transport"})
            return _result(tag, "error", "secrets-compare %s: transport lost" % where)
        token = vpsexec._probe_token(probe, rc, out)
        journal.append("vpsexec", dict({"event": "secrets_compare", "host": host, "step": n,
                                        "token": token, "rc": rc},
                                       **({"error": "not-a-token"} if token is None else {})))
        if token is None:
            return _result(tag, "error", "secrets-compare %s did not print exactly %s or %s "
                           "(rc=%s); its output is withheld" % (where, actions.DONE,
                                                                actions.NEEDED, rc))
        if token == actions.NEEDED:
            return _result(tag, "fail", "%s: the token-only check of %s says NEEDED — a key "
                           "is missing, short or shares its value (no value was read back) "
                           "(live)" % (", ".join(names), where))
    return _result(tag, "pass", "%s hold different values: token-only check of %s, no "
                   "value read back (live)" % (", ".join(names), "; ".join(steps)))


def preflight(path, guard, policy=None, ssh=None, today=None, live=False,
             index_only=False, index_dir=None, now=None, secrets_compare=False):
    path = Path(path)
    today = today or datetime.date.today().isoformat()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    hosts_cfg = guard.policy.get("hosts", {})
    deny = list(guard.deny_patterns()) + list((policy or {}).get("deny_extra", []))
    ctx = {"deny": deny, "risky": list((policy or {}).get("risky_extra", [])),
           "ssh": ssh or vpsexec._default_ssh, "live": bool(live),
           "index_only": bool(index_only), "secrets_compare": bool(secrets_compare),
           "index_dir": Path(index_dir) if index_dir
                        else _estate_root(path) / indexstore.CACHE_DIRNAME,
           "max_age": indexstore.max_age_seconds(guard.policy.get("limits") or {}),
           "now": now, "index_cache": {}}
    try:
        _, _, runbooks, assumes = load_file(path, deny, today, set(hosts_cfg))
    except Refused as r:
        return report("preflight", path, [_result("policy", "fail", r)])
    action_assumes = actions.step_assumes(runbooks)
    if not assumes and not action_assumes:
        return report("preflight", path, [_result(
            "assumes", "warn", "no assumes: block — nothing about the hosts was "
            "checked. Declare what the steps take for granted (docs/VPSEXEC.md)")])
    aliases = vpsexec.governor_aliases(hosts_cfg)
    checks = []
    for n, item in enumerate(assumes, 1):
        checks += _preflight_item(ctx, str(n), item, aliases, runbooks, "")
    for step, item in action_assumes:
        checks += _preflight_item(ctx, "action step %d" % step, item, aliases, runbooks,
                                  " (from action step %d)" % step)
    return report("preflight", path, checks)


# ---- CLI -------------------------------------------------------------------

USAGE = """vpsexec runbook — check a runbook policy before it is armed or run.

  vpsexec runbook lint <policy.yaml> [--plays DIR] [--releases DIR]
                                     [--artifacts DIR]... [--json]
      static and local: shape, expiry, timeouts, push artifacts, STOP steps,
      plays generated from it (with their id:/when:), releases that run or
      name it (plays, policies:, on_fail), optional steps no play includes
  vpsexec runbook preflight <policy.yaml> [--live | --index-only] [--json]
      read tier only, against the hosts: compares the policy's assumes: block
      (container, image, env NAMES, compose labels/files, absent paths, free
      disk, table privileges), using the cached `vpscfg index` document for a
      host when it is fresh enough, else a live read. Facts neither can see
      are MANUAL, never pass. --live always dials, ignoring the index.
      --index-only never dials a host; anything the index cannot answer is
      SKIP, never pass. --secrets-compare (opt-in) answers env_distinct with
      the policy's own ensure_secret token-only check (prints a token, never
      a value); without it env_distinct is MANUAL, under --index-only SKIP.

Verdict: GO (0), GO-WITH-WARNINGS (1), NO-GO (2) — as docs/PREFLIGHT.md.
"""


def cli(argv, guard, policy, ssh=None, today=None, now=None):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    verb, rest = argv[0], argv[1:]
    if verb not in ("lint", "preflight"):
        raise Refused("unknown `vpsexec runbook` verb %r — lint or preflight" % verb)
    if "--run" in rest:
        raise Refused("`vpsexec runbook %s` only reads — --run is meaningless here" % verb)
    opts = {"json": False, "plays": None, "artifacts": [], "releases": None,
            "live": False, "index_only": False, "secrets_compare": False}
    target = None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--json":
            opts["json"] = True
        elif verb == "preflight" and a == "--live":
            opts["live"] = True
        elif verb == "preflight" and a == "--index-only":
            opts["index_only"] = True
        elif verb == "preflight" and a == "--secrets-compare":
            opts["secrets_compare"] = True
        elif verb == "lint" and a in ("--plays", "--artifacts", "--releases"):
            value = vpsexec._value(rest, i, a)
            i += 1
            if a == "--artifacts":
                opts["artifacts"].append(value)
            else:
                opts[a[2:]] = value
        elif verb == "lint" and a.startswith(("--plays=", "--artifacts=", "--releases=")):
            key, value = a[2:].split("=", 1)
            if key == "artifacts":
                opts["artifacts"].append(value)
            else:
                opts[key] = value
        elif a.startswith("-"):
            raise Refused("unknown flag %r for `vpsexec runbook %s`" % (a, verb))
        elif target is None:
            target = a
        else:
            raise Refused("`vpsexec runbook %s` takes one policy file" % verb)
        i += 1
    if not target:
        raise Refused("usage: vpsexec runbook %s <policy.yaml>" % verb)
    if opts["live"] and opts["index_only"]:
        raise Refused("`vpsexec runbook preflight` takes --live or --index-only, not both")
    if verb == "lint":
        rep = lint(target, guard, policy, plays_dir=opts["plays"],
                   artifact_dirs=opts["artifacts"] or None, today=today, now=now,
                   releases_dir=opts["releases"])
    else:
        rep = preflight(target, guard, policy, ssh=ssh, today=today, live=opts["live"],
                        index_only=opts["index_only"], now=now,
                        secrets_compare=opts["secrets_compare"])
    print(json.dumps(rep, indent=2, sort_keys=True) if opts["json"] else render(rep))
    return rep["exit_code"]
