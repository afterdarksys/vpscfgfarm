"""Best-effort journal push to a control plane (<url>/telemetry/events).

The local JSONL journal is the record; this is the antenna. A telemetry outage
must never block or fail a mutation, so every failure here is swallowed after
the local journal write has already happened.

OFF unless the governor names an endpoint (integrations.telemetry.url, see
vpscfg/integrations.py). No environment variable can set or change the URL.
The API key is the operator's: $VPSCFG_TELEMETRY_KEY or
~/.config/vpscfgfarm/telemetry-key (never the governor: a secret does not
belong in a committed file, and the key alone cannot choose where events go).

Threats:
  - Protects against: the push path breaking mutations (strictly best-effort,
    called AFTER journal.append persists locally; all exceptions swallowed);
    key leakage into argv/logs (key travels only in the request header);
    an environment variable sending journal events (and the key) somewhere
    else (the endpoint comes from the governor only, https only; the opener
    ignores HTTP(S)_PROXY / no_proxy, so no proxy sees the request); a
    redirect carrying the key elsewhere, or down to plain http (3xx is a
    failed push, never followed).
  - Does NOT protect against: the API lying or dropping events — the journal
    is authoritative, the API copy is convenience. Accepted residual: the
    TLS trust store is the interpreter's, which SSL_CERT_FILE / SSL_CERT_DIR
    can change; whoever can set those can already run the doors as you.
"""
import json
import os
import urllib.request
from pathlib import Path

from . import integrations

KEY_ENV = "VPSCFG_TELEMETRY_KEY"
KEY_FILE = Path.home() / ".config" / "vpscfgfarm" / "telemetry-key"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is a failed push: following it would resend X-API-Key to a
    location the governor never named (possibly over plain http)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    """No proxies from the environment, no redirects."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _key():
    k = os.environ.get(KEY_ENV)
    if k:
        return k.strip()
    try:
        return KEY_FILE.read_text().strip() or None
    except OSError:
        return None


def _url():
    """(url or None, reason). Never raises: a bad governor entry turns the
    antenna off and says why; it must not fail the journal write."""
    try:
        url = integrations.telemetry_url()
    except Exception as e:
        return None, "telemetry endpoint misconfigured (%s)" % e
    if url is None:
        return None, "no telemetry endpoint in the governor (integrations.telemetry.url)"
    return url, None


def enabled():
    return _url()[0] is not None and _key() is not None


def status():
    """(state, detail). The journal's second home, or the reason there isn't one.

    push_event swallows everything by design — a telemetry outage must never
    fail a mutation. The cost is that "no API key configured" and "the control
    plane is fine" look identical from the outside, so every mutation can be
    recorded to a single local file that is gitignored and unbacked, and nothing
    ever says so. This makes the difference visible.
    """
    url, why = _url()
    if url is None:
        return "off", (
            "%s — journal entries are LOCAL ONLY. "
            "journal/ is gitignored, so nothing off this machine has a copy." % why)
    if _key() is None:
        return "no-key", (
            "no %s and no %s — journal entries are LOCAL ONLY. "
            "journal/ is gitignored, so nothing off this machine has a copy."
            % (KEY_ENV, KEY_FILE))
    return "configured", "pushing to %s" % url


def push_event(record, timeout=5):
    """POST one journal record. Returns True on 2xx, False otherwise. Never raises."""
    base, _ = _url()
    if base is None:
        return False
    key = _key()
    if not key:
        return False
    url = base + "/telemetry/events"
    # The local journal keeps the operator's command verbatim (it is the
    # record); the control-plane copy does not — PGPASSWORD=x stays home.
    from . import secretmask
    record = dict(record)
    # Local paths (where the estate lives, which interpreter ran) stay in the
    # local journal; the control plane gets the governor's hash, not its path.
    for field in ("estate_root", "estate_pointer", "governor", "interpreter"):
        record.pop(field, None)
    for field in ("command", "remote", "detail", "stdout", "stderr", "verify_detail"):
        if isinstance(record.get(field), str):
            record[field] = secretmask.mask(record[field])
    body = json.dumps({
        "source": "vpscfg",
        "event": str(record.get("event") or record.get("verb") or "journal"),
        "host": record.get("host"),
        "service": record.get("service"),
        "operator": record.get("operator"),
        "payload": record,
    }).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": key})
    try:
        with _opener().open(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False
