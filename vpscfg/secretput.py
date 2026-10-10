"""Install a secret from a keystore pipe onto an allowlisted path.

`secret-put --from-pipe NAME PATH` reads the secret from the stdout of the
command the governor names (integrations.secret_source.command, an argv list;
NAME is appended as the last argument; no shell). With none named,
--from-pipe refuses: no environment variable or flag can supply one.

Threats:
  - Protects against: cron, CI, or an agent writing a secret (a controlling
    TTY is required on --run); an environment variable or flag choosing the
    program the secret is read from (only the reviewed governor names it,
    validated as plain words and run without a shell); a path that is not an
    exact secrets.sinks entry on exactly one contract; the secret bytes
    reaching the journal (name and sha256 only).
  - Does NOT protect against: a human at the keyboard installing the wrong
    value (the journal records the hash), or a governor naming a command that
    does something else. Plan mode does not touch the TTY, the pipe, or the
    host.
"""
import hashlib
import re
import shlex
import subprocess
import sys

from . import integrations, journal, secretmask
from .gates import DENY_ALWAYS_FLOOR, Refused, deny_scan
from .probe import HOST_RE
from .secretscensus import PATH_RE

MAX_SECRET = 1024 * 1024
NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
    r"/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
    r"(@[A-Za-z0-9][A-Za-z0-9_.-]{0,31})?\Z"
)
USAGE = "usage: vpscfg <host> secret-put --from-pipe NAME PATH"


def source_command(source=None):
    """The governor's secret-source argv. Refuses when none is named."""
    argv = integrations.secret_source() if source is None else source
    if not argv:
        raise Refused(
            "secret-put --from-pipe: no secret source is configured. Name the "
            "command that prints one secret in the governor "
            "(integrations.secret_source.command, an argv list; NAME is appended)")
    return list(argv)


def default_pipe(argv, name):
    try:
        result = subprocess.run(argv + [name], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Refused("secret source %s did not run (%s)" % (argv[0], type(e).__name__))
    if result.returncode != 0:
        raise Refused("secret source %s failed (rc=%d)" % (argv[0], result.returncode))
    return result.stdout


def _path_ok(path):
    return isinstance(path, str) and ".." not in path and bool(PATH_RE.match(path))


def find_sink(contracts_on_host, path):
    """The path must be an exact member of exactly one contract's sinks.
    A listed path that contains '..' refuses the whole contract."""
    if not _path_ok(path):
        raise Refused("secret path refused")
    matches = []
    for name in sorted(contracts_on_host):
        contract = contracts_on_host[name]
        if not isinstance(contract, dict):
            raise Refused("contract %s is malformed" % name)
        secrets = contract.get("secrets")
        if secrets is None:
            continue
        if not isinstance(secrets, dict):
            raise Refused("secrets block on %s is malformed" % name)
        listed = secrets.get("sinks")
        if listed is None:
            continue
        if not isinstance(listed, list):
            raise Refused("secrets.sinks on %s is malformed" % name)
        for item in listed:
            if not _path_ok(item):
                raise Refused("secrets.sinks entry on %s refused" % name)
        if path in listed:
            matches.append((name, contract))
    if len(matches) != 1:
        raise Refused("path must be an allowlisted sink on exactly one contract")
    return matches[0]


def install_command(path):
    return "install -m 600 /dev/stdin -- %s" % shlex.quote(path)


def default_runner(host, command, stdin=None):
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    payload = stdin if isinstance(stdin, bytes) else b""
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, command],
        input=payload, capture_output=True, timeout=60)
    if result.returncode == 255:
        raise OSError("SSH connection lost; remote completion is unknown")
    return (result.returncode,
            result.stdout.decode("utf-8", "replace"),
            result.stderr.decode("utf-8", "replace"))


def _parse(argv):
    if len(argv) < 2 or argv[1] != "secret-put":
        raise Refused(USAGE)
    run = False
    name = None
    reason = None
    path = None
    index = 2
    while index < len(argv):
        token = argv[index]
        if token == "--run":
            run = True
            index += 1
            continue
        if token == "--from-pipe":
            if name is not None or index + 1 >= len(argv):
                raise Refused("secret-put --from-pipe NAME")
            name = argv[index + 1]
            index += 2
            continue
        if token == "--reason":
            if reason is not None or index + 1 >= len(argv):
                raise Refused("secret-put --reason text")
            reason = argv[index + 1]
            index += 2
            continue
        if token.startswith("-"):
            raise Refused("unknown secret-put flag %r" % token)
        if path is not None:
            raise Refused("secret-put takes one path")
        path = token
        index += 1
    if not name or not path:
        raise Refused(USAGE)
    return name, path, run, reason


def _call(runner, host, command, stdin):
    result = runner(host, command, stdin)
    if not isinstance(result, tuple) or len(result) != 3:
        raise Refused("secret-put runner returned an unexpected result")
    rc, out, err = result
    if type(rc) is not int or not isinstance(out, str) or not isinstance(err, str):
        raise Refused("secret-put runner returned an unexpected result")
    return rc, out, err


def put(guard, host, name, path, run, reason, contracts_on_host,
        runner=None, pipe=None, source=None, tty_check=None):
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise Refused("secret name refused")
    argv = source_command(source)
    _contract_name, contract = find_sink(contracts_on_host, path)
    command = install_command(path)
    if not run:
        print("SECRET-PUT PLAN %s -> %s" % (name, path))
        print("  source: %s" % " ".join(shlex.quote(a) for a in argv + [name]))
        print("  %s" % command)
        print("  plan only — the secret is not read and the host is not touched")
        return 0
    if not isinstance(reason, str) or reason.strip() == "":
        raise Refused("secret-put --run requires --reason")
    scope = "service:%s/%s" % (host, contract.get("service"))
    guard.assert_verb("secret-put")
    guard.assert_mutation_allowed("secret-put", host, scope)
    if tty_check is None:
        from .vpsexecgrant import _require_tty
        _require_tty(sys.stdin, "secret-put")
    else:
        tty_check(sys.stdin, "secret-put")
    blob = default_pipe(argv, name) if pipe is None else pipe(name)
    if not isinstance(blob, (bytes, bytearray)) or len(blob) == 0:
        raise Refused("empty secret refused")
    blob = bytes(blob)
    if len(blob) > MAX_SECRET:
        raise Refused("secret exceeds 1 MiB")
    deny_scan(command, DENY_ALWAYS_FLOOR)
    digest = hashlib.sha256(blob).hexdigest()
    rc, out, err = _call(runner or default_runner, host, command, blob)
    journal.append("secret-put", {
        "event": "secret-put",
        "reason": reason,
        "host": host,
        "service": contract.get("service"),
        "name": name,
        "sha256": digest,
        "rc": rc,
    })
    if rc != 0:
        shown = secretmask.mask(err or out or "")
        if shown:
            print(shown, file=sys.stderr)
        return 1
    print("secret-put %s sha256:%s" % (name, digest))
    return 0


def cli(guard, host, argv, contracts_on_host, runner=None, pipe=None,
        source=None, tty_check=None):
    name, path, run, reason = _parse(argv)
    return put(guard, host, name, path, run, reason, contracts_on_host,
               runner=runner, pipe=pipe, source=source, tty_check=tty_check)
