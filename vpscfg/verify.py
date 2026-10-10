"""Verify runner — a deploy's post-conditions, and the fleet-watch primitive.

All checks are read-only and safe to run at ANY time (verify against prod is
how a backend crash-looping unnoticed for weeks would be caught on day 0).

Threats:
  - Protects against: "deployed and walked away" — verify failure is loud and
    journaled; URL allowlist-by-shape (https/http only, no file:// etc.);
    container names validated before reaching the fixed ssh command; the
    mail perimeter silently becoming an open relay (smtp_relay_refused
    FAILS if a foreign RCPT is accepted — and never, ever sends DATA);
    cert expiry surprises (tls_expiry, min_days); "we have DR" as a feeling
    (pg_replication fails unless the standby IS in recovery AND lag is
    bounded); a copied file that no longer matches its source
    (replica_of: sha256 or certificate end date, never the file).
  - Does NOT protect against: a check list that is too weak — verify proves
    what the contract ASKS it to prove, nothing more. tls_expiry's fallback
    inspects certs WITHOUT chain verification when normal verification
    fails (self-signed perimeter): that path reads the presented cert and
    sends nothing — it is an observer, not a client, and must never be
    copied into code that transmits data (SECURITY-RULES rule 5 applies to
    real channels).
"""
import re
import math
import shlex
import subprocess
import time
import urllib.request

from .gates import Refused

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$")

CHECK_TYPES = frozenset(('http', 'container', 'smtp_banner', 'smtp_relay_refused',
                        'tls_expiry', 'pg_replication', 'replica_of'))


def deadline_seconds(value):
    """Bound contract health polling; absent deadlines retain one-shot checks."""
    if value is None:
        return 0
    match = re.fullmatch(r'([0-9]+)(s|m)?', str(value))
    if not match:
        raise Refused('within must be a positive duration such as 90s or 2m')
    seconds = int(match[1]) * (60 if match[2] == 'm' else 1)
    if not 1 <= seconds <= 3600:
        raise Refused('within must be between 1s and 1h')
    return seconds


def validate_checks(contract):
    checks = contract.get('verify')
    if not isinstance(checks, list) or not checks:
        raise Refused('verify must contain at least one supported health check')
    for check in checks:
        if not isinstance(check, dict) or len(check) != 1:
            raise Refused('each verify entry must contain exactly one check')
        kind, spec = next(iter(check.items()))
        if kind not in CHECK_TYPES or not isinstance(spec, dict) or not spec:
            raise Refused('unrecognized check or invalid check parameters: %r' % kind)
        for field, low, high in (('timeout', 0.01, 300), ('port', 1, 65535)):
            if field not in spec:
                continue
            try:
                value = float(spec[field])
            except (ValueError, TypeError):
                raise Refused('invalid %s in verification' % field)
            if isinstance(spec[field], bool) or not math.isfinite(value) or not low <= value <= high or (field == 'port' and not value.is_integer()):
                raise Refused('invalid %s in verification' % field)
        if kind == 'container':
            deadline_seconds(spec.get('within'))
            if not isinstance(spec.get('name'), str) or not NAME_RE.fullmatch(spec['name']):
                raise Refused('invalid container check name')
            if spec.get('state', 'running') not in ('running', 'healthy', 'unhealthy', 'exited', 'paused', 'created', 'restarting', 'dead'):
                raise Refused('invalid container check state')
        if kind == 'http' and not str(spec.get('url', '')).startswith(('http://', 'https://')):
            raise Refused('verify http URL must be http(s)')
        if kind == 'http' and (type(spec.get('expect', 200)) is not int or not 100 <= spec.get('expect', 200) <= 599):
            raise Refused('HTTP verification requires a valid integer status code')
        if kind == 'replica_of':
            from .replicaof import validate as validate_replica
            validate_replica(spec)

def _check_http(spec, fetch=None):
    url = spec.get("url", "")
    if not url.startswith(("https://", "http://")):
        raise Refused("verify http url %r must be http(s)" % url)
    expect = int(spec.get("expect", 200))
    timeout = float(spec.get("timeout", 10))
    if fetch is None:
        def fetch(u, t):
            try:
                with urllib.request.urlopen(u, timeout=t) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code
    try:
        status = fetch(url, timeout)
    except Exception as e:
        return {"check": "http", "url": url, "ok": False, "detail": "unreachable: %s" % e}
    return {"check": "http", "url": url, "ok": status == expect,
            "detail": "got %s want %s" % (status, expect)}

def _check_container(spec, host, runner=None, clock=None, sleep=None):
    clock, sleep = clock or time.monotonic, sleep or time.sleep
    deadline = clock() + deadline_seconds(spec.get('within'))
    name = spec.get("name", "")
    if not NAME_RE.match(name):
        raise Refused("verify container name %r fails validation" % name)
    if not HOST_RE.match(host or ""):
        raise Refused("invalid host %r" % host)
    if runner is None:
        def runner(h, n):
            # ssh joins argv into ONE remote shell string, so every remote arg
            # must be shell-quoted or the {{...}} format template word-splits
            # server-side. Found live on first production verify.
            remote = " ".join(shlex.quote(a) for a in [
                "docker", "inspect", "--format",
                "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                n])
            r = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", h, remote],
                capture_output=True, text=True, timeout=min(30, max(0.01, deadline - clock()))
                if spec.get('within') is not None else 30)
            return r.returncode, r.stdout.strip()
    want = spec.get("state", "running")
    while True:
        try:
            rc, out = runner(host, name)
        except (OSError, subprocess.TimeoutExpired) as exc:
            rc, out = 1, 'inspect unavailable: %s' % exc
        ok = rc == 0 and want in out.split()
        remaining = deadline - clock()
        if ok or remaining <= 0:
            break
        sleep(min(2, remaining))
    return {"check": "container", "name": name, "ok": ok,
            "detail": out if rc == 0 else "inspect failed rc=%d: %s" % (rc, out)}

def _read_smtp_reply(rfile):
    """Read one (possibly multi-line) SMTP reply; return the 3-digit code.
    A malformed reply returns 0 — which never satisfies any expectation."""
    code = 0
    for _ in range(50):  # bounded: a chatty server cannot hold us forever
        line = rfile.readline()
        if not line:
            break
        line = line.decode("utf-8", "replace") if isinstance(line, bytes) else line
        if len(line) >= 4 and line[:3].isdigit():
            code = int(line[:3])
            if line[3:4] != "-":
                break
        else:
            break
    return code


def _default_connector(host, port, timeout):
    import socket
    return socket.create_connection((host, port), timeout=timeout)


def _check_smtp_banner(spec, connector=None):
    """The server's first line, matched. Sends only QUIT."""
    host, port = spec.get("host", ""), int(spec.get("port", 25))
    expect = str(spec.get("expect", ""))
    timeout = float(spec.get("timeout", 10))
    if not HOST_RE.match(host):
        raise Refused("smtp_banner host %r fails validation" % host)
    connector = connector or _default_connector
    try:
        conn = connector(host, port, timeout)
        rfile = conn.makefile("rb")
        banner = rfile.readline()
        banner = banner.decode("utf-8", "replace").strip() if isinstance(banner, bytes) else banner.strip()
        conn.sendall(b"QUIT\r\n")
        conn.close()
    except Exception as e:
        return {"check": "smtp_banner", "name": "%s:%d" % (host, port),
                "ok": False, "detail": "unreachable: %s" % e}
    return {"check": "smtp_banner", "name": "%s:%d" % (host, port),
            "ok": expect in banner,
            "detail": "banner %r want %r" % (banner[:60], expect)}


# Fixed remote relay probe. Runs on the `via` host (which has a vantage the
# ops machine lacks — e.g. relay1 can reach web1:25, the laptop's ISP cannot).
# Self-contained, no imports beyond the stdlib, argv = [host, port, rcpt].
# Prints exactly one line: RELAY|<ok|open>|<code>|<text>. Safety identical to
# the local path: null sender, RFC-2606 reserved recipient, judged post-DATA.
_REMOTE_RELAY_PROBE = r"""
import socket, sys
host, port, rcpt = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def rd(f):
    code = 0
    for _ in range(50):
        line = f.readline()
        if not line: break
        line = line.decode("utf-8", "replace")
        if len(line) >= 4 and line[:3].isdigit():
            code = int(line[:3])
            if line[3:4] != "-": break
        else: break
    return code
def out(verdict, code, text):
    print("RELAY|%s|%d|%s" % (verdict, code, text)); sys.exit(0)
try:
    s = socket.create_connection((host, port), timeout=20); f = s.makefile("rb")
    if rd(f) != 220: out("ok", 0, "no 220 greeting; failing closed as refusal")
    s.sendall(b"EHLO vpscfg-verify\r\n")
    if rd(f) != 250: out("ok", 0, "EHLO refused; failing closed as refusal")
    s.sendall(b"MAIL FROM:<>\r\n"); c = rd(f)
    if not (200 <= c < 300): out("ok", c, "refused at MAIL FROM")
    s.sendall(("RCPT TO:<%s>\r\n" % rcpt).encode()); c = rd(f)
    if not (200 <= c < 300): out("ok", c, "refused foreign recipient at RCPT")
    s.sendall(b"DATA\r\n"); c = rd(f)
    if not (300 <= c < 400): out("ok", c, "DATA refused; not relayed")
    s.sendall(("From: <>\r\nTo: <%s>\r\nSubject: vpscfg relay probe\r\n\r\nrelay test\r\n.\r\n" % rcpt).encode())
    c = rd(f)
    try:
        s.sendall(b"QUIT\r\n")
    except Exception: pass
    s.close()
    if 200 <= c < 300: out("open", c, "message ACCEPTED for delivery")
    out("ok", c, "message rejected at delivery; not an open relay")
except Exception as e:
    out("ok", -1, "unreachable from via host: %s" % e)
"""


def _check_smtp_relay_refused(spec, connector=None, runner=None):
    """Prove the perimeter will not relay a stranger's mail off the estate.

    A correct relay test must survive a STORE-AND-FORWARD proxy: the
    mail perimeter proxy accepts MAIL/RCPT optimistically at the edge (250)
    and only learns the real answer when it forwards to the primary mail
    server, which rejects foreign recipients with 554. An RCPT-only probe
    therefore gives a FALSE 'open relay' on such a proxy. So this
    check completes the transaction and judges on the FINAL, post-DATA
    response — the point at which a deferred rejection surfaces.

    Safety: the sender is the null sender <> (no backscatter) and the
    recipient is an RFC 2606 reserved domain (example.com) that routes
    nowhere — so even against a TRUE open relay this probe delivers nothing
    to any third party. PASS on refusal at ANY stage; OPEN RELAY only if the
    message is ACCEPTED for delivery after end-of-DATA.
    """
    host, port = spec.get("host", ""), int(spec.get("port", 25))
    timeout = float(spec.get("timeout", 20))
    mail_from = spec.get("mail_from", "")            # null sender by default
    rcpt_to = spec.get("rcpt_to", "relay-probe@example.com")  # reserved, routes nowhere
    if not HOST_RE.match(host):
        raise Refused("smtp_relay_refused host %r fails validation" % host)
    if mail_from and not re.match(r"^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$", mail_from):
        raise Refused("smtp_relay_refused mail_from %r fails validation" % mail_from)
    if not re.match(r"^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$", rcpt_to):
        raise Refused("smtp_relay_refused rcpt_to %r fails validation" % rcpt_to)
    via = spec.get("via")
    if via:
        return _relay_refused_via(host, port, via, rcpt_to, runner=runner)

    connector = connector or _default_connector
    name = "%s:%d" % (host, port)

    def _fail(detail):
        return {"check": "smtp_relay_refused", "name": name, "ok": False,
                "detail": detail}

    try:
        conn = connector(host, port, timeout)
        rfile = conn.makefile("rb")
        if _read_smtp_reply(rfile) != 220:
            conn.close()
            return _fail("no 220 greeting — cannot prove refusal, failing closed")
        conn.sendall(b"EHLO vpscfg-verify\r\n")
        if _read_smtp_reply(rfile) != 250:
            conn.close()
            return _fail("EHLO not accepted — cannot prove refusal, failing closed")
        conn.sendall(("MAIL FROM:<%s>\r\n" % mail_from).encode())
        mail_code = _read_smtp_reply(rfile)
        if not (200 <= mail_code < 300):
            _quit(conn, rfile)
            return {"check": "smtp_relay_refused", "name": name, "ok": True,
                    "detail": "refused at MAIL FROM (%d) — will not begin a "
                              "foreign transaction" % mail_code}
        conn.sendall(("RCPT TO:<%s>\r\n" % rcpt_to).encode())
        rcpt_code = _read_smtp_reply(rfile)
        if not (200 <= rcpt_code < 300):
            _quit(conn, rfile)
            return {"check": "smtp_relay_refused", "name": name, "ok": True,
                    "detail": "refused foreign recipient at RCPT (%d) — "
                              "perimeter holds at the edge" % rcpt_code}
        # RCPT accepted. On a plain MX that already means open relay, but on a
        # forwarding proxy the decision is still ahead — send DATA to a sink
        # and read the FINAL word.
        conn.sendall(b"DATA\r\n")
        data_code = _read_smtp_reply(rfile)
        if not (300 <= data_code < 400):
            _quit(conn, rfile)
            return {"check": "smtp_relay_refused", "name": name, "ok": True,
                    "detail": "RCPT accepted at edge but DATA refused (%d) — "
                              "not relayed" % data_code}
        conn.sendall(b"From: <>\r\nTo: <%s>\r\nSubject: vpscfg relay probe\r\n"
                     b"\r\nAutomated relay test. If you received this, the MX "
                     b"relayed a stranger's mail.\r\n.\r\n"
                     % rcpt_to.encode())
        final_code = _read_smtp_reply(rfile)
        _quit(conn, rfile)
    except Exception as e:
        return _fail("unreachable: %s" % e)
    if 200 <= final_code < 300:
        return _fail("OPEN RELAY: a stranger's message was ACCEPTED for "
                     "delivery (%d after end-of-DATA) — the estate is relaying "
                     "foreign mail" % final_code)
    return {"check": "smtp_relay_refused", "name": name, "ok": True,
            "detail": "foreign message rejected at delivery (%d) — the "
                      "forwarding upstream refuses to relay; not an open relay"
                      % final_code}


def _quit(conn, rfile):
    """Best-effort RSET+QUIT. A probe must not leave a transaction dangling,
    but cleanup failure never changes the verdict."""
    try:
        conn.sendall(b"RSET\r\n")
        _read_smtp_reply(rfile)
        conn.sendall(b"QUIT\r\n")
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass


def _relay_refused_via(host, port, via, rcpt_to, runner=None):
    """Run the relay probe FROM `via` — a fleet host with a vantage the ops
    machine lacks (relay1 reaches web1:25; the laptop's ISP blocks 25). The
    remote command is a FIXED, reviewed python probe; only the validated
    host/port/recipient vary, and all three are shell-quoted. Same pattern as
    _check_pg_replication running a fixed psql over ssh."""
    if not HOST_RE.match(via):
        raise Refused("smtp_relay_refused via %r fails validation" % via)
    name = "%s:%d via %s" % (host, port, via)
    if runner is None:
        def runner(via_host, remote):
            r = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                 via_host, remote],
                capture_output=True, text=True, timeout=60)
            return r.returncode, r.stdout
    remote = "python3 -c %s %s %d %s" % (
        shlex.quote(_REMOTE_RELAY_PROBE), shlex.quote(host), port,
        shlex.quote(rcpt_to))
    try:
        rc, stdout = runner(via, remote)
    except Exception as e:
        return {"check": "smtp_relay_refused", "name": name, "ok": False,
                "detail": "probe could not run on %s: %s — failing closed"
                          % (via, e)}
    line = ""
    for ln in stdout.splitlines():
        if ln.startswith("RELAY|"):
            line = ln.strip()
            break
    if not line:
        return {"check": "smtp_relay_refused", "name": name, "ok": False,
                "detail": "no verdict from probe on %s (rc=%d) — failing closed"
                          % (via, rc)}
    parts = line.split("|", 3)
    verdict = parts[1] if len(parts) > 1 else ""
    code = parts[2] if len(parts) > 2 else "?"
    text = parts[3] if len(parts) > 3 else ""
    if verdict == "open":
        return {"check": "smtp_relay_refused", "name": name, "ok": False,
                "detail": "OPEN RELAY on the inbound MX: %s (%s) — from %s's "
                          "external vantage" % (text, code, via)}
    return {"check": "smtp_relay_refused", "name": name, "ok": True,
            "detail": "%s (%s) — perimeter holds from %s's vantage"
                      % (text, code, via)}


def _tls_not_after(host, port, timeout, starttls):
    """The presented certificate's notAfter, as epoch seconds.

    Verified handshake first (real trust). If verification fails (the
    perimeter may be self-signed), fall back to an INSPECTION-ONLY
    unverified read of the DER cert — no application data is ever sent on
    that connection, and the date still gets checked. Requires the
    `cryptography` package only on the fallback path.
    """
    import socket
    import ssl
    import time as _time

    def _handshake(ctx):
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            if starttls == "smtp":
                rfile = raw.makefile("rb")
                if _read_smtp_reply(rfile) != 220:
                    raise OSError("no SMTP greeting before STARTTLS")
                raw.sendall(b"EHLO vpscfg-verify\r\n")
                if _read_smtp_reply(rfile) != 250:
                    raise OSError("EHLO refused before STARTTLS")
                raw.sendall(b"STARTTLS\r\n")
                if _read_smtp_reply(rfile) != 220:
                    raise OSError("STARTTLS refused")
            return ctx.wrap_socket(raw, server_hostname=host)
        except Exception:
            raw.close()
            raise

    try:
        tls = _handshake(ssl.create_default_context())
        cert = tls.getpeercert()
        tls.close()
        not_after = cert.get("notAfter")
        return _time.mktime(_time.strptime(not_after, "%b %d %H:%M:%S %Y %Z"))
    except ssl.SSLError:
        pass  # verification failed — self-signed is expected on the perimeter
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspection only; nothing is transmitted
    tls = _handshake(ctx)
    der = tls.getpeercert(binary_form=True)
    tls.close()
    try:
        from cryptography import x509
    except ImportError:
        raise OSError("cert is not publicly verifiable and `cryptography` is "
                      "unavailable to parse it — cannot inspect, failing closed")
    parsed = x509.load_der_x509_certificate(der)
    return parsed.not_valid_after.timestamp()


def _check_tls_expiry(spec, fetcher=None):
    """The presented cert must outlive min_days (default 14)."""
    import time as _time
    host, port = spec.get("host", ""), int(spec.get("port", 443))
    min_days = float(spec.get("min_days", 14))
    timeout = float(spec.get("timeout", 15))
    starttls = spec.get("starttls")
    if not HOST_RE.match(host):
        raise Refused("tls_expiry host %r fails validation" % host)
    if starttls not in (None, "smtp"):
        raise Refused("tls_expiry starttls %r not supported (smtp or omit)" % starttls)
    fetcher = fetcher or _tls_not_after
    name = "%s:%d" % (host, port)
    try:
        not_after = fetcher(host, port, timeout, starttls)
    except Exception as e:
        return {"check": "tls_expiry", "name": name, "ok": False,
                "detail": "cannot inspect cert: %s — failing closed" % e}
    days_left = (not_after - _time.time()) / 86400.0
    return {"check": "tls_expiry", "name": name, "ok": days_left >= min_days,
            "detail": "%.1f days left (min %g)" % (days_left, min_days)}


# Fixed read-only SQL, no interpolation (SECURITY-RULES rule 7). One query
# answers both questions: is this actually a standby, and how far behind.
_PG_REPLICATION_SQL = ("SELECT pg_is_in_recovery(), COALESCE(EXTRACT(EPOCH FROM "
                       "now() - pg_last_xact_replay_timestamp()), -1)")


def _check_pg_replication(spec, runner=None):
    """DR as a checked invariant: the standby must BE a standby, and its
    replay lag must be bounded. Anything else — not in recovery, lag over
    the limit, unparseable answer — fails."""
    host = spec.get("host", "")
    container = spec.get("name", "")
    lag_max = float(spec.get("lag_max_s", 300))
    user = spec.get("user", "postgres")
    if not HOST_RE.match(host):
        raise Refused("pg_replication host %r fails validation" % host)
    if not NAME_RE.match(container):
        raise Refused("pg_replication container %r fails validation" % container)
    if not re.match(r"^[A-Za-z0-9_-]{1,63}$", user):
        raise Refused("pg_replication user %r fails validation" % user)
    if runner is None:
        def runner(h, n):
            remote = " ".join(shlex.quote(a) for a in [
                "docker", "exec", n, "psql", "-U", user, "-tA",
                "-c", _PG_REPLICATION_SQL])
            r = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", h, remote],
                capture_output=True, text=True, timeout=30)
            return r.returncode, r.stdout.strip()
    name = "%s/%s" % (host, container)
    rc, out = runner(host, container)
    if rc != 0:
        return {"check": "pg_replication", "name": name, "ok": False,
                "detail": "query failed rc=%d — cannot prove replication" % rc}
    parts = out.strip().split("|")
    if len(parts) != 2:
        return {"check": "pg_replication", "name": name, "ok": False,
                "detail": "unparseable answer %r — cannot prove replication" % out[:60]}
    in_recovery, lag_raw = parts[0].strip(), parts[1].strip()
    if in_recovery != "t":
        return {"check": "pg_replication", "name": name, "ok": False,
                "detail": "NOT in recovery — this is not a standby; 'dr' is "
                          "aspiration, not fact"}
    try:
        lag = float(lag_raw)
    except ValueError:
        return {"check": "pg_replication", "name": name, "ok": False,
                "detail": "unparseable lag %r" % lag_raw[:30]}
    if lag < 0:
        return {"check": "pg_replication", "name": name, "ok": False,
                "detail": "no replayed transaction yet — replication has never "
                          "caught up"}
    return {"check": "pg_replication", "name": name, "ok": lag <= lag_max,
            "detail": "replay lag %.1fs (max %gs)" % (lag, lag_max)}


def run_checks(contract, host, fetch=None, runner=None, replica_runner=None):
    """Run every check in the contract's verify block. Returns (all_ok, results)."""
    checks = contract.get('verify')
    if not isinstance(checks, list) or not checks:
        return False, [{'check': 'invalid', 'ok': False, 'detail': 'verify must contain health checks'}]
    results = []
    for spec in checks:
        if not isinstance(spec, dict) or len(spec) != 1 or not isinstance(next(iter(spec.values())), dict):
            return False, [{'check': 'invalid', 'ok': False, 'detail': 'malformed verify entry'}]
        if "http" in spec:
            results.append(_check_http(spec["http"], fetch=fetch))
        elif "container" in spec:
            results.append(_check_container(spec["container"], host, runner=runner))
        elif "smtp_banner" in spec:
            results.append(_check_smtp_banner(spec["smtp_banner"]))
        elif "smtp_relay_refused" in spec:
            results.append(_check_smtp_relay_refused(spec["smtp_relay_refused"]))
        elif "tls_expiry" in spec:
            results.append(_check_tls_expiry(spec["tls_expiry"]))
        elif "pg_replication" in spec:
            results.append(_check_pg_replication(spec["pg_replication"]))
        elif "replica_of" in spec:
            # Own runner: (host, remote command), not the container runner.
            from .replicaof import check as check_replica
            results.append(check_replica(spec["replica_of"], host, runner=replica_runner))
        else:
            results.append({"check": "unknown", "ok": False,
                            "detail": "unrecognized check %r" % list(spec)})
    return all(r["ok"] for r in results), results

def render(service, ok, results):
    lines = ["VERIFY %s: %s" % (service, "PASS" if ok else "FAIL")]
    for r in results:
        lines.append("  [%s] %-9s %s — %s" % ("ok" if r["ok"] else "!!",
                     r["check"], r.get("url") or r.get("name", ""), r["detail"]))
    return "\n".join(lines)
