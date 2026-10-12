"""IaC gate — badfarm's static IaC scan as preflight evidence and a fleet read.

`badfarm iac scan` (a separate, separately installed tool) reads Ansible,
Terraform/HCL, Kubernetes manifests and compose files and reports outage,
admin lockout, exposure, secret and degradation risk. This module runs it
against a LOCAL directory only, validates its v1 JSON report, and maps the
report to a preflight status. It never passes --repo/--ref (no clone, no
network fetch from here) and writes nothing.

  vpscfg fleet iac PATH [--fail-on LEVEL] [--format text|json]

Exit codes mirror badfarm's: 0 pass, 1 findings at/above --fail-on or an
incomplete scan, 2 refused (bad input, bad report, badfarm missing).

Threats:
  - Protects against: a deploy carrying IaC that would lock out admins,
    expose a service or drop a dependency, when the contract says
    preflight.iac: required; a scanner that could not answer being read as
    a pass (exit 2, a timeout, non-JSON, a schema mismatch, an exit code
    that disagrees with the verdict, or output over OUTPUT_CAP all refuse);
    an unbounded report filling memory (output is read through a cap);
    secrets from the scanned tree leaking through the report (everything
    shown is masked, and a refusal echoes only a clipped, masked excerpt);
    a relative or non-executable VPSCFG_BADFARM being run from the cwd; a
    PATH lookup landing on a relative path (PATH containing "." or an empty
    entry) or on anything that is not, once resolved, an executable regular
    file; a report whose claimed verdict disagrees with one recomputed here
    from its own findings/coverage at the fail-on level actually requested
    (never the fail_on the report claims for itself), including an
    in-source suppression badfarm itself marks untrustworthy
    (suppressed[i]["trusted"] is False, for critical/high severities) being
    used to quietly drop a real finding; an in-source suppression being
    read as an unqualified pass (surfaced as warn instead).
  - Does NOT protect against: a malicious badfarm on PATH or named by
    VPSCFG_BADFARM that reports "pass" with findings/coverage data that is
    itself fabricated to agree with that pass — whoever controls the
    operator's environment controls the scanner; risk badfarm has no rule
    for. A pass is evidence that the known rules found nothing, not that
    the IaC is safe.
"""

import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from . import secretmask
from .gates import Refused

ENV_VAR = "VPSCFG_BADFARM"
SCHEMA_VERSION = 1
KIND = "iac-scan-report"
VERDICTS = ("block", "warn", "incomplete", "pass")
MODES = ("off", "advisory", "required")
FAIL_ON_LEVELS = ("critical", "high", "medium", "low")
SEVERITIES = ("critical", "high", "medium", "low", "info")
FINDING_STR_FIELDS = ("rule", "category", "severity", "file", "title", "evidence", "remediation")
OUTPUT_CAP = 8 * 1024 * 1024
EXCERPT_MAX = 200
TOP_MAX = 5


def locate():
    """The badfarm executable, or None when it is not installed. A set
    VPSCFG_BADFARM must name an absolute path to an executable regular file;
    anything else refuses rather than falling back to PATH. A PATH lookup is
    held to the same bar: shutil.which() can hand back a relative path when
    PATH contains "." or an empty entry (e.g. "./badfarm" picked up from the
    scanned repo itself) — that is refused, not silently treated as absent,
    so required mode fails closed and advisory mode still warns rather than
    skipping. The result is resolved (symlinks followed) and re-checked as a
    regular, executable file."""
    raw = os.environ.get(ENV_VAR)
    if raw is not None:
        if not os.path.isabs(raw):
            raise Refused("%s must be an absolute path" % ENV_VAR)
        try:
            st = os.stat(raw)
        except OSError:
            raise Refused("%s names a path that does not exist" % ENV_VAR) from None
        if not stat.S_ISREG(st.st_mode) or not os.access(raw, os.X_OK):
            raise Refused("%s must name an executable regular file" % ENV_VAR)
        return raw
    found = shutil.which("badfarm")
    if found is None:
        return None
    if not os.path.isabs(found):
        raise Refused("badfarm resolved via PATH to a non-absolute path %r "
                      "(PATH likely contains '.' or an empty entry)" % found)
    resolved = os.path.realpath(found)
    try:
        st = os.stat(resolved)
    except OSError:
        raise Refused("badfarm on PATH (%r) could not be stat'd" % found) from None
    if not stat.S_ISREG(st.st_mode) or not os.access(resolved, os.X_OK):
        raise Refused("badfarm on PATH (%r) is not an executable regular file" % found)
    return resolved


def scan_argv(exe, directory, fail_on="high"):
    return [exe, "iac", "scan", "--format", "json", "--fail-on", fail_on, "--", str(directory)]


def run_capped(argv, timeout=300):
    """Run argv with stdout and stderr spooled to temp files, reading back at
    most OUTPUT_CAP + 1 bytes of stdout, so an oversized report is detected
    without being held in memory."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise
        out.seek(0)
        err.seek(0)
        return (rc, out.read(OUTPUT_CAP + 1).decode("utf-8", "replace"),
                err.read(64 * 1024).decode("utf-8", "replace"))


def _excerpt(text):
    text = " ".join(str(text or "").split())
    return secretmask.mask(text[:EXCERPT_MAX]) or "(no output)"


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


_SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


def _recomputed_verdict(doc, fail_on):
    """Defence in depth: recompute the verdict from findings, coverage and
    the REQUESTED fail_on (never doc["fail_on"] — that is the report's own
    claim, and a report that lies about its verdict could lie about that
    too) instead of trusting the reported verdict.

    block  if any finding (or untrusted suppressed critical/high entry) has
           severity >= fail_on (critical > high > medium > low).
           An untrusted suppression (suppressed[i]["trusted"] is False) is
           counted the same as an unsuppressed finding of that severity: an
           in-source `# badfarm:ignore` is author-controlled, and badfarm may
           mark one untrustworthy (e.g. the suppressed line was edited after
           the ignore comment). A suppressed entry with no "trusted" key
           predates the field and is treated as trusted, for backwards
           compatibility with older badfarm output.
    incomplete  if not block and any coverage entry has "blocking": true.
    warn   if not block/incomplete and any (unsuppressed) finding exists.
    pass   otherwise.
    """
    limit = _SEVERITY_RANK[fail_on]
    untrusted = [f for f in doc["suppressed"]
                 if f.get("trusted", True) is False and f.get("severity") in ("critical", "high")]
    blocking_pool = doc["findings"] + untrusted
    if any(_SEVERITY_RANK.get(f.get("severity"), -1) <= limit for f in blocking_pool):
        return "block"
    if any(c.get("blocking") for c in doc["coverage"]):
        return "incomplete"
    return "warn" if doc["findings"] else "pass"


def validate_report(doc, fail_on):
    """Refuse anything that is not a badfarm v1 iac-scan-report."""
    if not isinstance(doc, dict):
        raise Refused("badfarm report is not a JSON object")
    if not _is_int(doc.get("schema_version")) or doc["schema_version"] != SCHEMA_VERSION:
        raise Refused("badfarm report schema_version %r is not %d"
                      % (doc.get("schema_version"), SCHEMA_VERSION))
    if doc.get("kind") != KIND:
        raise Refused("badfarm report kind is not %r" % KIND)
    if doc.get("verdict") not in VERDICTS:
        raise Refused("badfarm report verdict is not one of %s" % ", ".join(VERDICTS))
    tool = doc.get("tool")
    if not isinstance(tool, dict) or tool.get("name") != "badfarm" \
            or not isinstance(tool.get("version"), str):
        raise Refused("badfarm report tool block is malformed")
    files = doc.get("files")
    if not isinstance(files, dict) or not _is_int(files.get("scanned")) \
            or not _is_int(files.get("skipped")):
        raise Refused("badfarm report files block is malformed")
    for key, kind in (("source", dict), ("summary", dict), ("suppressed", list),
                      ("coverage", list), ("findings", list)):
        if not isinstance(doc.get(key), kind):
            raise Refused("badfarm report %s is missing or not a %s" % (key, kind.__name__))
    for i, f in enumerate(doc["findings"]):
        if not isinstance(f, dict):
            raise Refused("badfarm finding %d is not an object" % i)
        for field in FINDING_STR_FIELDS:
            if not isinstance(f.get(field), str):
                raise Refused("badfarm finding %d field %s is not a string" % (i, field))
        if not _is_int(f.get("line")) or f["line"] < 0:
            raise Refused("badfarm finding %d line is not a non-negative integer" % i)
        if f["severity"] not in SEVERITIES:
            raise Refused("badfarm finding %d severity is not one of %s" % (i, ", ".join(SEVERITIES)))
    for i, f in enumerate(doc["suppressed"]):
        if not isinstance(f, dict) or f.get("severity") not in SEVERITIES:
            raise Refused("badfarm suppressed finding %d is missing a valid severity" % i)
        if "trusted" in f and not isinstance(f["trusted"], bool):
            raise Refused("badfarm suppressed finding %d trusted flag is not a boolean" % i)
    recomputed = _recomputed_verdict(doc, fail_on)
    if recomputed != doc["verdict"]:
        raise Refused("badfarm report verdict %r disagrees with the verdict recomputed from "
                      "its findings/coverage at --fail-on %s (%r)"
                      % (doc["verdict"], fail_on, recomputed))
    return doc


def run_scan(path, runner=None, timeout=300, fail_on="high"):
    """Scan one local directory. Returns (badfarm exit code, report).
    Raises Refused for anything that is not a valid answer."""
    if fail_on not in FAIL_ON_LEVELS:
        raise Refused("--fail-on must be one of %s" % ", ".join(FAIL_ON_LEVELS))
    directory = Path(path).expanduser().resolve()
    if not directory.is_dir():
        raise Refused("IaC scan path %s is not a directory" % directory)
    exe = locate()
    if exe is None:
        raise Refused("badfarm not installed (not on PATH and %s unset)" % ENV_VAR)
    try:
        rc, out, err = (runner or run_capped)(scan_argv(exe, directory, fail_on), timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Refused("badfarm timed out after %ss" % timeout) from None
    except OSError as e:
        raise Refused("badfarm could not run: %s" % type(e).__name__) from None
    if len(out or "") > OUTPUT_CAP:
        raise Refused("badfarm output exceeds %d bytes" % OUTPUT_CAP)
    if rc == 2:
        raise Refused("badfarm refused the input (exit 2): %s" % _excerpt(err or out))
    if rc not in (0, 1):
        raise Refused("badfarm exited %s: %s" % (rc, _excerpt(err or out)))
    try:
        doc = json.loads(out)
    except ValueError:
        raise Refused("badfarm output is not JSON: %s" % _excerpt(out)) from None
    validate_report(doc, fail_on)
    if rc == 0 and doc["verdict"] in ("block", "incomplete"):
        raise Refused("badfarm exit 0 disagrees with verdict %r" % doc["verdict"])
    if rc == 1 and doc["verdict"] == "pass":
        raise Refused("badfarm exit 1 disagrees with verdict 'pass'")
    return rc, doc


def scan(path, runner=None, timeout=300, fail_on="high"):
    return run_scan(path, runner=runner, timeout=timeout, fail_on=fail_on)[1]


def _counts(report):
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in report["findings"]:
        counts[f["severity"]] += 1
    return counts


def _ranked(report):
    return sorted(report["findings"], key=lambda f: SEVERITIES.index(f["severity"]))


def classify(report, mode):
    """(status, evidence, data) for preflight. A block blocks only when the
    contract makes the gate required; incomplete is never a pass. A `pass`
    verdict with one or more in-source suppressions is surfaced as `warn`:
    an author-controlled `# badfarm:ignore` is not the same as a scan that
    found nothing, and it should not read as a silent, unqualified pass."""
    if mode not in MODES:
        raise Refused("preflight.iac must be one of %s" % ", ".join(MODES))
    v = report["verdict"]
    suppressed_count = len(report["suppressed"])
    if v == "block":
        status = "fail" if mode == "required" else "warn"
    elif v in ("warn", "incomplete"):
        status = "warn"
    elif suppressed_count > 0:
        status = "warn"
    else:
        status = "pass"
    counts = _counts(report)
    top = [secretmask.mask("%s %s:%d" % (f["rule"], f["file"], f["line"]))
           for f in _ranked(report)[:TOP_MAX]]
    evidence = "verdict %s; %s" % (v, " ".join("%s=%d" % (s, n) for s, n in counts.items()))
    if top:
        evidence += "; top: " + ", ".join(top)
    if suppressed_count:
        evidence += "; suppressed: %d" % suppressed_count
    data = {"verdict": v, "counts": counts, "top": top, "suppressed": suppressed_count,
            "tool_version": report["tool"]["version"]}
    return status, evidence, data


def _masked(value):
    if isinstance(value, str):
        return secretmask.mask(value)
    if isinstance(value, list):
        return [_masked(v) for v in value]
    if isinstance(value, dict):
        return {k: _masked(v) for k, v in value.items()}
    return value


def render(path, report, fail_on):
    counts = _counts(report)
    lines = ["IAC SCAN %s: verdict %s (badfarm %s, fail-on %s)"
             % (path, report["verdict"].upper(), report["tool"]["version"], fail_on),
             "  files: %d scanned, %d skipped; coverage entries: %d; suppressed: %d"
             % (report["files"]["scanned"], report["files"]["skipped"],
                len(report["coverage"]), len(report["suppressed"])),
             "  findings: " + " ".join("%s=%d" % (s, n) for s, n in counts.items())]
    ranked = _ranked(report)
    for f in ranked[:20]:
        lines.append("  [%-8s] %s %s:%d  %s" % (f["severity"], f["rule"], f["file"],
                                                f["line"], f["title"]))
    if len(ranked) > 20:
        lines.append("  … %d more (use --format json)" % (len(ranked) - 20))
    return secretmask.mask("\n".join(lines))


def cli(argv, runner=None):
    """`vpscfg fleet iac PATH [--fail-on LEVEL] [--format text|json]`."""
    argv = list(argv)
    for item in argv:
        head = item.split("=", 1)[0]
        if head in ("--repo", "--ref", "--run", "--output"):
            raise Refused("fleet iac scans a local path only: %s is not accepted" % head)
    if not argv or argv[0].startswith("-"):
        raise Refused("usage: vpscfg fleet iac PATH [--fail-on LEVEL] [--format text|json]")
    path, rest = argv[0], argv[1:]
    opts = {"--fail-on": "high", "--format": "text"}
    seen = set()
    while rest:
        flag = rest.pop(0)
        if flag not in opts or flag in seen or not rest:
            raise Refused("unsupported fleet iac argument %r" % flag)
        seen.add(flag)
        opts[flag] = rest.pop(0)
    if opts["--format"] not in ("text", "json"):
        raise Refused("--format must be text or json")
    rc, report = run_scan(path, runner=runner, fail_on=opts["--fail-on"])
    if opts["--format"] == "json":
        print(json.dumps(_masked(report), sort_keys=True))
    else:
        print(render(Path(path).expanduser().resolve(), report, opts["--fail-on"]))
    return rc
