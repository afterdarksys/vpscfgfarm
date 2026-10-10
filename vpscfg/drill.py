"""Scratch restore drill. Issues the receipt repair.check_request already requires.

Threats:
  - Protects against: a restore that was never proven (a receipt is journaled
    only when the canary and the teardown both succeed); `compose down -v`
    or a volume prune (refused before any step runs); extracting an archive
    onto `/` or any path that is not this run's scratch directory; a canary
    aimed at a production URL (http://127.0.0.1, port >= 20000); a postgres
    canary that is not a single SELECT, or that `docker exec`s a production
    container by name (compose exec -T inside the drill project).
  - Does NOT protect against: a host that lies about the canary, or an
    archive whose members are path-safe and whose contents are wrong. The
    scratch directory is left in place. This door does not rm -rf it, and it
    does not widen scopes.unlocked. A local test is not a fleet drill.
"""
import json
import re
import secrets
import shlex
import subprocess
import sys
from datetime import datetime, timezone

from . import contracts, journal, sqlread
from .gates import DENY_ALWAYS_FLOOR, Refused, deny_scan
from .probe import HOST_RE
from .secretscensus import PATH_RE

VERIFIER = "vpscfg drill"
PROJECT_RE = re.compile(r"^vpscfg-drill-[a-f0-9]{16}\Z")
SCRATCH_RE = re.compile(r"^/tmp/vpscfg-drill-[A-Za-z0-9]+\Z")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
REL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
URL_RE = re.compile(r"^http://127\.0\.0\.1:(\d{1,5})(/[A-Za-z0-9._~/-]*)?\Z")
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}\Z")
MKTEMP = "mktemp -d /tmp/vpscfg-drill-XXXXXXXX"
_PLACEHOLDER_SCRATCH = "<scratch>"
_PLACEHOLDER_PROJECT = "<project>"


def _check_url(url):
    if not isinstance(url, str):
        raise Refused("drill.http must be http://127.0.0.1 with port >= 20000")
    match = URL_RE.fullmatch(url)
    if not match:
        raise Refused("drill.http must be http://127.0.0.1 with port >= 20000")
    port = int(match.group(1))
    if port < 20000 or port > 65535:
        raise Refused("drill.http port must be >= 20000")
    return url


def validate_block(block):
    if not isinstance(block, dict):
        raise Refused("drill block must be a mapping")
    archive = block.get("archive")
    compose = block.get("compose")
    service = block.get("service")
    http = block.get("http")
    postgres = block.get("postgres")
    if not isinstance(archive, str) or ".." in archive or not PATH_RE.match(archive):
        raise Refused("drill.archive must be an absolute path with no ..")
    if (not isinstance(compose, str) or compose.startswith("/") or ".." in compose
            or not REL_RE.fullmatch(compose)):
        raise Refused("drill.compose must be a relative path inside the archive")
    if not isinstance(service, str) or not NAME_RE.fullmatch(service):
        raise Refused("drill.service must be a compose service name")
    has_http = http is not None
    has_pg = postgres is not None
    if has_http == has_pg:
        raise Refused("drill needs exactly one canary: http or postgres")
    spec = {"archive": archive, "compose": compose, "service": service}
    if has_http:
        spec["http"] = _check_url(http)
    else:
        if not isinstance(postgres, str):
            raise Refused("drill.postgres must be a single SELECT")
        spec["postgres"] = sqlread.classify(postgres, select_only=True)
    return spec


def _phrase_unsafe(command):
    lowered = " ".join(command.split()).lower()
    if ("down -v" in lowered or "--volumes" in lowered or "volume rm" in lowered):
        return True
    if "prune" in lowered.split():
        return True
    if re.search(r"(?:^|\s)-c\s+/(?:\s|$)", lowered) or "-c/" in lowered:
        return True
    return False


def _tar_dests(command):
    try:
        words = shlex.split(command)
    except ValueError:
        raise Refused("drill step is not a single command")
    dests = []
    index = 0
    while index < len(words):
        word = words[index]
        if word == "-C" and index + 1 < len(words):
            dests.append(words[index + 1])
            index += 2
            continue
        if word.startswith("-C") and len(word) > 2:
            dests.append(word[2:])
        index += 1
    return dests


def assert_plan_safe(commands, scratch=None):
    """Phrase-check every step. When `scratch` is set, tar -C must be that
    directory and nothing else — a placeholder plan skips this half."""
    for command in commands:
        if not isinstance(command, str) or command.strip() == "":
            raise Refused("drill step refused")
        if _phrase_unsafe(command):
            raise Refused("drill step refused")
        if scratch is None:
            continue
        for dest in _tar_dests(command):
            if dest != scratch or not SCRATCH_RE.fullmatch(dest):
                raise Refused("drill refuses tar -C outside the scratch directory")


def _member_command(archive):
    return (
        "tar -tf %s | while IFS= read -r member; do "
        "case \"$member\" in /*|../*|*/../*|*/..|..) exit 1;; esac; done"
        % shlex.quote(archive)
    )


def _commands(project, scratch, spec):
    archive = spec["archive"]
    compose_file = "%s/%s" % (scratch, spec["compose"])
    quoted_project = shlex.quote(project)
    quoted_file = shlex.quote(compose_file)
    steps = [
        ("sha", "sha256sum -- %s" % shlex.quote(archive), None),
        ("members", _member_command(archive), None),
        ("extract", "tar -xf %s -C %s" % (shlex.quote(archive), shlex.quote(scratch)), None),
        ("up", "docker compose -p %s -f %s up -d" % (quoted_project, quoted_file), None),
    ]
    if "http" in spec:
        canary = "curl -fsS --max-time 5 --proto =http --url %s" % shlex.quote(spec["http"])
        steps.append(("canary", canary, None))
    else:
        # compose exec requires a command. The fixed client is psql; the SQL
        # stays on stdin and names the drill service, not a container.
        canary = ("docker compose -p %s -f %s exec -T %s "
                  "psql -v ON_ERROR_STOP=1 --no-password -f -"
                  % (quoted_project, quoted_file, shlex.quote(spec["service"])))
        steps.append(("canary", canary, spec["postgres"].encode("utf-8")))
    steps.append(("down", "docker compose -p %s -f %s down" % (quoted_project, quoted_file), None))
    return steps


def _plan_lines(spec):
    steps = _commands(_PLACEHOLDER_PROJECT, _PLACEHOLDER_SCRATCH, spec)
    return [MKTEMP] + [command for _kind, command, _stdin in steps]


def _bind(host, contract, names):
    if not isinstance(contract, dict):
        raise Refused("contract refused")
    if not isinstance(names, (set, frozenset, list, tuple)) or host not in names:
        raise Refused("contract is bound to a different host")
    if contract.get("host") not in names:
        raise Refused("contract %r is bound to host %r, not %r"
                      % (contract.get("service"), contract.get("host"), host))


def _parse(argv):
    if len(argv) < 3 or argv[1] != "drill" or argv[2].startswith("-"):
        raise Refused("usage: vpscfg <host> drill <service>")
    service = argv[2]
    if not NAME_RE.fullmatch(service):
        raise Refused("invalid service name")
    run = False
    reason = None
    index = 3
    while index < len(argv):
        token = argv[index]
        if token == "--run":
            run = True
            index += 1
            continue
        if token == "--reason":
            if reason is not None or index + 1 >= len(argv):
                raise Refused("drill --reason text")
            reason = argv[index + 1]
            index += 2
            continue
        raise Refused("unknown drill flag %r" % token)
    return service, run, reason


def _scratch_ok(out, rc):
    if rc != 0 or not isinstance(out, str):
        return None
    if out.count("\n") > 1 or "\r" in out:
        return None
    text = out[:-1] if out.endswith("\n") else out
    if text in ("/", "/tmp", "/tmp/") or "\n" in text or ".." in text:
        return None
    if not SCRATCH_RE.fullmatch(text):
        return None
    return text


def _parse_digest(out):
    if not isinstance(out, str) or out.strip() == "":
        return None
    parts = out.splitlines()[0].split()
    if not parts or not _DIGEST_RE.fullmatch(parts[0]):
        return None
    return parts[0]


def _call(runner, host, command, stdin):
    result = runner(host, command, stdin)
    if not isinstance(result, tuple) or len(result) != 3:
        raise Refused("drill runner returned an unexpected result")
    rc, out, err = result
    if type(rc) is not int or not isinstance(out, str) or not isinstance(err, str):
        raise Refused("drill runner returned an unexpected result")
    return rc, out, err


def _print_plan(host, contract, spec):
    lines = _plan_lines(spec)
    assert_plan_safe(lines, scratch=None)
    print("DRILL PLAN for %s on %s" % (contract.get("service"), host))
    print("  scratch project; this door does not remove the scratch directory")
    for line in lines:
        print("  %s" % line)
    return 0


def execute(guard, host, contract, spec, reason, runner=None, project_name=None):
    if not isinstance(reason, str) or reason.strip() == "":
        raise Refused("drill --run requires --reason")
    scope = "service:%s/%s" % (host, contract.get("service"))
    guard.assert_verb("drill")
    guard.assert_mutation_allowed("drill", host, scope)
    project = project_name if project_name is not None else ("vpscfg-drill-" + secrets.token_hex(8))
    if not isinstance(project, str) or not PROJECT_RE.fullmatch(project):
        raise Refused("drill project name refused")
    runner = runner or default_runner
    rc, out, err = _call(runner, host, MKTEMP, None)
    scratch = _scratch_ok(out, rc)
    if scratch is None:
        print("DRILL FAILED: scratch directory refused", file=sys.stderr)
        return 1
    steps = _commands(project, scratch, spec)
    assert_plan_safe([command for _kind, command, _stdin in steps], scratch=scratch)
    for _kind, command, _stdin in steps:
        deny_scan(command, DENY_ALWAYS_FLOOR)
    digest = None
    canary_ok = False
    failed = False
    for kind, command, stdin in steps[:-1]:
        try:
            step_rc, step_out, _step_err = _call(runner, host, command, stdin)
        except Exception:
            failed = True
            break
        if kind == "sha":
            digest = _parse_digest(step_out) if step_rc == 0 else None
            if digest is None:
                failed = True
                break
        elif step_rc != 0:
            failed = True
            break
        elif kind == "canary":
            canary_ok = True
    down_kind, down_command, down_stdin = steps[-1]
    if down_kind != "down":
        raise Refused("drill teardown missing")
    try:
        down_rc, _down_out, _down_err = _call(runner, host, down_command, down_stdin)
    except Exception:
        down_rc = 1
    verified = (not failed) and digest is not None and canary_ok and down_rc == 0
    if not verified:
        print("DRILL FAILED: canary or teardown did not succeed — no receipt",
              file=sys.stderr)
        return 1
    proof = {
        "kind": "restore-drill",
        "verified": True,
        "host": contract["host"],
        "service": contract["service"],
        "reference": "sha256:" + digest,
        "verifier": VERIFIER,
        "tested_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        journal.append("drill", {"event": "restore-drill", "reason": reason, **proof})
    except Exception:
        print("DRILL FAILED: receipt was not journaled", file=sys.stderr)
        return 1
    print(json.dumps(proof, sort_keys=True))
    return 0


def default_runner(host, command, stdin=None):
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    payload = None
    if isinstance(stdin, bytes):
        payload = stdin
    elif isinstance(stdin, str):
        payload = stdin.encode("utf-8")
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, command],
        input=payload, capture_output=True, timeout=120)
    if result.returncode == 255:
        raise OSError("SSH connection lost; remote completion is unknown")
    return (result.returncode,
            result.stdout.decode("utf-8", "replace"),
            result.stderr.decode("utf-8", "replace"))


def cli(guard, host, argv, names, runner=None, project_name=None):
    service, run, reason = _parse(argv)
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    contract = contracts.load(service)
    if contract.get("service") != service:
        raise Refused("contract service mismatch")
    _bind(host, contract, names)
    block = contract.get("drill")
    if block is None:
        print("BLOCKED: contract %s has no drill block" % service, file=sys.stderr)
        return 1
    spec = validate_block(block)
    if not run:
        return _print_plan(host, contract, spec)
    return execute(guard, host, contract, spec, reason,
                   runner=runner, project_name=project_name)
