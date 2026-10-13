"""vpsexec incident override — a loud, time-boxed, human-opened emergency mode.

Why it exists: on a frozen host, fixing anything needs a committed, reviewed
break_glass runbook naming the exact command. During a customer outage that is
hours too slow, and an outage the door cannot reach is an outage the operator
fixes with raw ssh, outside every gate. An incident is the sanctioned middle:
the human at the keyboard opens it for named hosts and a short window, and for
that window break-glass mutations on those hosts no longer need a committed
runbook entry. Everything else is unchanged.

  vpsexec incident open --hosts web1,web2 --ttl 1h --reason "OUTAGE-123 ..."
      TTY only; pending input is flushed; type INCIDENT:<hosts>:<ttl>.
      Mints ic_<128-bit hex> (HMAC-SHA256 with the grant key, 0600) in the
      grants dir and journals `incident_opened`.
  vpsexec <hosts> '<cmd>' --break-glass --incident ic_<id> --run --reason "why"
      Every gate still runs (floor, deny_extra and secrets.yaml, the map,
      master switch and lockdown mode, target resolution, journal-or-refuse,
      the per-host lock, verify, secret masking). Only the runbook lookup is
      lifted, for the incident's hosts. Approval is a typed `GO` at the
      controlling TTY — never --approve, never an approval contract.
      Journals `incident_command`.
  vpsexec incident close <id>
      TTY only; type CLOSE:<id>. Ends it early (or, after expiry, records the
      end), prints every command run under it from the journal, and writes
      that report — with a backfill of draft runbook entries — to
      journal/incidents/<id>.md, so the reviewed policy catches up.
  vpsexec incident status
      Open incidents, and expired ones nobody has closed yet.

Extending means opening a new incident: there is no extend verb.

Notification: every state change is a journal event (`incident_opened`,
`incident_command`, `incident_closed`), and journal.append already hands every
record to telemetry.push_event — the existing control-plane path. Nothing here
makes a network call of its own.

Threats:
  - Protects against: an agent, cron job or CI opening, closing or using an
    incident (open and close need this process's controlling terminal in the
    foreground plus an exact typed phrase; each command needs a typed GO at
    that terminal; --approve and --approval-contract are refused alongside
    --incident; there is no flag that skips the prompt); a tampered or forged
    incident file (HMAC-SHA256 over canonical JSON that includes a fixed
    `kind`, so a grant can never pass as an incident; compared in constant
    time; exact key set; duplicate JSON keys refused; 64 KiB cap; must be a
    private regular file, not a symlink, owned by the operator, in a private
    directory); scope creep (every host in the plan must be listed in the
    incident by its canonical name — a plan touching one unlisted host
    refuses whole; hosts are named explicitly at open, never `@group`, `@all`,
    `all` or a glob); stale use (expiry checked when the plan is built and
    again after GO is typed; issued_at in the future refused; the TTL is one
    of 15m/30m/1h/2h/4h and must equal expires_at - issued_at; a closed
    incident is permanently closed via a closed list that, if present but
    unreadable, fails closed); the deny-always floor, deny_extra (secrets.yaml)
    and map constraints (they run before the incident is consulted, and a map
    with forbid_break_glass refuses --incident too); untraceable use (open,
    every command and close are journaled, journal-or-refuse).
  - Does NOT protect against: a process running as the operator — it can read
    grant.key and forge an incident, and it can allocate a pty, so the TTY
    check is the same barrier the typed phrase already is; root on the
    workstation; a same-user process deleting the closed list; a bad command
    typed by the human during the incident — the incident removes the review
    step on purpose, which is why it is loud, short, host-scoped, and ends in
    a backfill that puts every mutation in front of a reviewer.
"""

import datetime
import hmac
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path

from . import journal, secretmask, vpsexecgrant
from .gates import Refused
from .probe import HOST_RE

VERSION = 1
KIND = "incident"
TTLS = {"15m": 900, "30m": 1800, "1h": 3600, "2h": 7200, "4h": 14400}
MAX_BYTES = 64 * 1024
REASON_MAX = 500
ID_RE = re.compile(r"^ic_[0-9a-f]{32}$")
CLOSED = "incidents-closed.jsonl"
APPROVAL_PHRASE = "GO"
TOP_KEYS = frozenset(["version", "kind", "incident_id", "operator", "issued_at",
                      "expires_at", "ttl", "hosts", "reason", "mac"])
GLOB_CHARS = set("*?[]{}")


def _grant_dir(grant_dir=None):
    # Looked up at call time, so the grant module's directory is the one place
    # both kinds of file live (and tests redirect it once).
    return Path(grant_dir or vpsexecgrant.GRANT_DIR)


# ---------------------------------------------------------------------------
# hosts and reason
# ---------------------------------------------------------------------------

def parse_hosts(spec, hosts_cfg):
    """'web1,web2' -> canonical governed host names, in the order named.
    No groups, no `all`, no globs: an incident names every machine it reaches."""
    aliases = dict((n, c["alias_of"]) for n, c in (hosts_cfg or {}).items()
                   if isinstance(c, dict) and c.get("alias_of"))
    out = []
    for token in (t.strip() for t in (spec or "").split(",")):
        if not token:
            continue
        if (token.startswith("@") or token.lower() in ("all", "@all")
                or GLOB_CHARS & set(token)):
            raise Refused("--hosts %r: an incident names each host explicitly — no "
                          "groups, no `all`, no wildcards" % token)
        if not HOST_RE.match(token):
            raise Refused("--hosts: invalid host name %r" % token)
        canonical = aliases.get(token, token)
        if canonical not in (hosts_cfg or {}):
            raise Refused("--hosts: %r is not a governed host — an incident covers "
                          "machines the governor already knows" % token)
        if canonical not in out:
            out.append(canonical)
    if not out:
        raise Refused("--hosts names no host")
    return out


def _check_reason(reason):
    reason = (reason or "").strip()
    if not reason:
        raise Refused('incident open needs --reason "what is broken, ticket"')
    if len(reason) > REASON_MAX:
        raise Refused("--reason is longer than %d characters" % REASON_MAX)
    if any(ord(c) < 32 or ord(c) == 127 for c in reason):
        raise Refused("--reason must be one line of printable text")
    return reason


# ---------------------------------------------------------------------------
# minting
# ---------------------------------------------------------------------------

def fields_for(hosts, ttl, reason, now=None):
    if ttl not in TTLS:
        raise Refused("--ttl %r is not allowed — one of: %s (capped at 4h; extend "
                      "by opening a new incident)" % (ttl, ", ".join(TTLS)))
    issued = vpsexecgrant._now(now).replace(microsecond=0)
    expires = issued + datetime.timedelta(seconds=TTLS[ttl])
    return {"version": VERSION, "kind": KIND, "operator": vpsexecgrant.operator(),
            "issued_at": vpsexecgrant._fmt(issued),
            "expires_at": vpsexecgrant._fmt(expires), "ttl": ttl,
            "hosts": list(hosts), "reason": _check_reason(reason)}


def mint(fields, key_path=None, grant_dir=None):
    """Seal and write. Journal-or-refuse: an incident nobody can trace must
    not exist, so the journal entry is written before the file."""
    grant_dir = _grant_dir(grant_dir)
    vpsexecgrant._private_dir(grant_dir, create=True)
    key = vpsexecgrant.load_key(key_path, create=True)
    inc = dict(fields)
    inc["incident_id"] = "ic_" + secrets.token_hex(16)
    inc["mac"] = vpsexecgrant._mac(key, inc)
    journal.append("vpsexec", {
        "event": "incident_opened", "incident": inc["incident_id"],
        "hosts": inc["hosts"], "ttl": inc["ttl"], "issued_at": inc["issued_at"],
        "expires_at": inc["expires_at"], "reason": secretmask.mask(inc["reason"])})
    path = grant_dir / inc["incident_id"]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(inc, f, indent=2, sort_keys=True)
        f.write("\n")
    return path, inc


# ---------------------------------------------------------------------------
# closed list
# ---------------------------------------------------------------------------

def closed_ids(grant_dir=None):
    """Incident ids closed so far. Present but untrustworthy => refuse."""
    path = _grant_dir(grant_dir) / CLOSED
    if not os.path.lexists(path):
        return set()
    fd, st = vpsexecgrant._open_regular(path, os.O_RDONLY, "incident closed list")
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise Refused("incident closed list %s is not a private regular file "
                          "owned by you — failing closed" % path)
        try:
            lines = f.read().splitlines()
        except ValueError:
            raise Refused("incident closed list %s is not UTF-8 — failing closed" % path)
    ids = set()
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            iid = json.loads(line)["incident"]
        except (ValueError, KeyError, TypeError):
            raise Refused("incident closed list %s line %d is invalid — failing "
                          "closed" % (path, n))
        if not isinstance(iid, str) or not ID_RE.match(iid):
            raise Refused("incident closed list %s line %d has a bad id" % (path, n))
        ids.add(iid)
    return ids


def _record_closed(iid, grant_dir, now, early):
    grant_dir = _grant_dir(grant_dir)
    closed_ids(grant_dir)  # an untrusted existing file refuses before we append
    fd, _ = vpsexecgrant._open_regular(grant_dir / CLOSED,
                                       os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                                       "incident closed list")
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps({"incident": iid, "closed_at": vpsexecgrant._fmt(
            vpsexecgrant._now(now)), "early": early,
            "operator": vpsexecgrant.operator()}, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _read(path):
    fd, st = vpsexecgrant._open_regular(path, os.O_RDONLY, "incident file")
    with os.fdopen(fd, "rb") as f:
        if st.st_uid != os.getuid():
            raise Refused("incident file %s is not owned by you" % path)
        if st.st_mode & 0o077:
            raise Refused("incident file %s has mode %o — it must be 600"
                          % (path, stat.S_IMODE(st.st_mode)))
        raw = f.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise Refused("incident file %s exceeds %d bytes" % (path, MAX_BYTES))
    vpsexecgrant._private_dir(path.parent)
    try:
        doc = json.loads(raw.decode("utf-8"),
                         object_pairs_hook=vpsexecgrant._no_duplicates)
    except (UnicodeDecodeError, ValueError) as e:
        raise Refused("incident file %s is not valid JSON (%s)" % (path, e))
    if not isinstance(doc, dict):
        raise Refused("incident file %s is not a JSON object" % path)
    return doc


def check(incident_id, now=None, key_path=None, grant_dir=None, allow_expired=False):
    """The incident, or Refused. allow_expired is for `close` only: it still
    authenticates the file but lets a lapsed incident be closed and reported."""
    try:
        return _check(incident_id, now, key_path, grant_dir, allow_expired)
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        raise Refused("incident %s is malformed (%s)" % (incident_id, type(e).__name__))


def _check(incident_id, now, key_path, grant_dir, allow_expired):
    iid = str(incident_id or "").strip()
    if not ID_RE.match(iid):
        raise Refused("incident id must be ic_ followed by 32 hex characters")
    path = _grant_dir(grant_dir) / iid
    inc = _read(path)
    vpsexecgrant._exact_keys(inc, TOP_KEYS, "incident")
    key = vpsexecgrant.load_key(key_path)
    if not isinstance(inc["mac"], str) or not hmac.compare_digest(
            inc["mac"].encode("utf-8"), vpsexecgrant._mac(key, inc).encode("utf-8")):
        raise Refused("incident file %s failed its MAC — edited, forged, or sealed "
                      "with another key" % path)
    if inc["version"] != VERSION or isinstance(inc["version"], bool) or inc["kind"] != KIND:
        raise Refused("incident file %s has the wrong version or kind" % path)
    if not hmac.compare_digest(str(inc["incident_id"]), iid):
        raise Refused("incident file %s does not carry its own id" % path)
    for k in ("operator", "issued_at", "expires_at", "ttl", "reason"):
        if not isinstance(inc[k], str):
            raise Refused("incident %s must be a string" % k)
    if (not isinstance(inc["hosts"], list) or not inc["hosts"]
            or not all(isinstance(h, str) and HOST_RE.match(h) for h in inc["hosts"])):
        raise Refused("incident hosts must be a non-empty list of host names")
    now = vpsexecgrant._now(now)
    issued = vpsexecgrant._parse_time(inc["issued_at"], "issued_at")
    expires = vpsexecgrant._parse_time(inc["expires_at"], "expires_at")
    if inc["ttl"] not in TTLS or (expires - issued).total_seconds() != TTLS[inc["ttl"]]:
        raise Refused("incident ttl %r is not allowed or does not match its window"
                      % inc["ttl"])
    if (issued - now).total_seconds() > vpsexecgrant.FUTURE_SKEW_SECONDS:
        raise Refused("incident issued_at %s is in the future" % inc["issued_at"])
    if iid in closed_ids(grant_dir):
        raise Refused("incident %s is closed (permanently) — open a new one" % iid)
    if now >= expires and not allow_expired:
        raise Refused("incident %s expired at %s — open a new one to keep working"
                      % (iid, inc["expires_at"]))
    return inc


def minutes_left(inc, now=None):
    expires = vpsexecgrant._parse_time(inc["expires_at"], "expires_at")
    return max(0, int((expires - vpsexecgrant._now(now)).total_seconds() // 60))


def banner(inc, now=None):
    return ("INCIDENT %s OPEN — expires in %d min (%s) — hosts: %s"
            % (inc["incident_id"], minutes_left(inc, now), inc["expires_at"],
               ", ".join(inc["hosts"])))


def authorize(inc, hosts, aliases=None):
    """Every plan host must be one the incident lists (canonical names)."""
    aliases = aliases or {}
    listed = set(aliases.get(h, h) for h in inc["hosts"])
    outside = [h for h in hosts if aliases.get(h, h) not in listed]
    if outside:
        raise Refused("incident %s does not cover %s (it covers %s) — open a new "
                      "incident naming them; nothing ran"
                      % (inc["incident_id"], ", ".join(outside), ", ".join(inc["hosts"])))


def go_phrase(hosts, digest):
    """What a human types to run ONE command under an incident (M8): bound to
    the command's target, so a reflexive `GO` cannot approve the wrong thing.
    One host: GO:<host>. Several: GO:<first 6 of the plan-hash>."""
    hosts = list(hosts or [])
    if len(hosts) == 1:
        return "%s:%s" % (APPROVAL_PHRASE, hosts[0])
    return "%s:%s" % (APPROVAL_PHRASE, str(digest or "")[:6])


def short_id(iid):
    """ic_ plus the first 8 hex: what a human reads and types (L5)."""
    return str(iid)[:11]


def approve(inc, stream, prompt=None, now=None, grant_dir=None, key_path=None,
            hosts=None, digest=None):
    """Typed GO:<host> (or GO:<plan[:6]>) at the controlling terminal, then
    the incident is checked again — it may have expired or been closed while
    the prompt waited."""
    vpsexecgrant._require_tty(stream if stream is not None else sys.stdin,
                              "an incident command")
    vpsexecgrant.flush_input(stream)
    prompt = prompt or (lambda msg: input(msg))
    print(banner(inc, now))
    want = go_phrase(hosts, digest)
    typed = prompt("Type %s to run this under incident %s, anything else aborts: "
                   % (want, inc["incident_id"]))
    if typed.strip() != want:
        raise Refused("approval text did not match %r — aborted" % want)
    check(inc["incident_id"], now=now, grant_dir=grant_dir, key_path=key_path)
    return "incident:%s" % inc["incident_id"]


# ---------------------------------------------------------------------------
# report + backfill
# ---------------------------------------------------------------------------

def _events(iid):
    out = []
    for line in journal.read_stream("vpsexec").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("incident") == iid:
            out.append(rec)
    return out


def _q(text):
    """A YAML double-quoted scalar (JSON strings are valid YAML)."""
    return json.dumps(str(text), ensure_ascii=False)


def report(inc, closed_at, early):
    iid = inc["incident_id"]
    events = _events(iid)
    commands, results, pending = [], [], []
    for e in events:
        if e.get("event") == "incident_command":
            commands.append(e)
            results.append(None)
            pending.append(len(commands) - 1)
        elif e.get("event") == "mutation_complete":
            # The completion belongs to the earliest unanswered command of the
            # same plan: a command refused at its lock never completes.
            for n in pending:
                if commands[n].get("plan_hash") == e.get("plan_hash"):
                    results[n] = e.get("results")
                    pending.remove(n)
                    break
    lines = ["# Incident %s" % iid, "",
             "- hosts: %s" % ", ".join(inc["hosts"]),
             "- reason: %s" % secretmask.mask(inc["reason"]),
             "- opened: %s by %s (ttl %s, expires %s)"
             % (inc["issued_at"], inc["operator"], inc["ttl"], inc["expires_at"]),
             "- closed: %s (%s)" % (closed_at, "early" if early else "after expiry"),
             "- commands run: %d" % len(commands), "",
             "## Commands", ""]
    if not commands:
        lines.append("(none — no mutation ran under this incident)")
    for n, c in enumerate(commands, 1):
        res = results[n - 1]
        lines.append("%d. %s  hosts=%s  where=%s%s" % (
            n, c.get("ts", "?"), ",".join(c.get("hosts") or []), c.get("placement"),
            "  containers=%s" % json.dumps(c.get("targets")) if any(
                (c.get("targets") or {}).values()) else ""))
        lines.append("   cmd: `%s`" % secretmask.mask(c.get("command") or ""))
        lines.append("   reason: %s" % secretmask.mask(c.get("reason") or ""))
        lines.append("   plan-hash: %s  results: %s"
                     % (c.get("plan_hash"), json.dumps(res) if res is not None
                        else "(no completion record)"))
    lines += ["", "## Backfill (draft runbook entries — REVIEW before committing)", "",
              "Every mutation above, as a break_glass runbook entry, so the next",
              "outage of this shape is a lookup. Commands are secret-masked: a",
              "`<masked>` value must be rewritten before this can match anything.",
              "Delete entries that were one-offs; set `expires`, the `shape`, and",
              "a `verify` for the ones you keep.", "", "```yaml",
              "version: 1",
              "reason: %s" % _q("backfill from incident %s: %s"
                                % (iid, secretmask.mask(inc["reason"]))),
              'expires: "YYYY-MM-DD"',
              "runbooks:"]
    seen = set()
    entries = 0
    for c in commands:
        targets = c.get("targets") or {}
        names = sorted(set(n for v in targets.values() for n in (v or [])))
        key = (c.get("command"), c.get("placement"), tuple(c.get("hosts") or []),
               tuple(names))
        if key in seen:
            continue
        seen.add(key)
        entries += 1
        lines.append("  - hosts: [%s]" % ", ".join(c.get("hosts") or []))
        lines.append("    cmd: %s" % _q(secretmask.mask(c.get("command") or "")))
        lines.append("    where: %s" % c.get("placement"))
        if c.get("placement") == "container" and len(names) == 1:
            lines.append("    container: %s" % names[0])
        lines.append("    break_glass: true")
        lines.append("    why: %s" % _q("incident %s: %s"
                                         % (iid, secretmask.mask(c.get("reason") or ""))))
    if not entries:
        lines.append("  []  # nothing to backfill")
    lines += ["```", ""]
    return "\n".join(lines)


def write_report(iid, text):
    d = Path(journal.JOURNAL_DIR) / "incidents"
    if not d.exists():
        d.mkdir(parents=True, mode=0o700)
    path = d / ("%s.md" % iid)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def close(iid, now=None, grant_dir=None, key_path=None):
    inc = check(iid, now=now, grant_dir=grant_dir, key_path=key_path,
                allow_expired=True)
    early = vpsexecgrant._now(now) < vpsexecgrant._parse_time(inc["expires_at"],
                                                               "expires_at")
    closed_at = vpsexecgrant._fmt(vpsexecgrant._now(now))
    journal.append("vpsexec", {"event": "incident_closed", "incident": iid,
                               "hosts": inc["hosts"], "early": early,
                               "closed_at": closed_at})
    _record_closed(iid, grant_dir, now, early)
    text = report(inc, closed_at, early)
    return write_report(iid, text), text


# ---------------------------------------------------------------------------
# CLI: vpsexec incident open|close|status
# ---------------------------------------------------------------------------

USAGE = """vpsexec incident — emergency override for a customer outage

  vpsexec incident open --hosts h1,h2 --ttl <15m|30m|1h|2h|4h> --reason "why"
                        TTY only; type INCIDENT:<hosts>:<ttl>. Hosts by name only.
  vpsexec incident status
  vpsexec incident close <ic_id>   TTY only; type CLOSE:<ic_ + 8 hex>. Writes the
                                   report and backfill to journal/incidents/<ic_id>.md.

  use: vpsexec <hosts> '<cmd>' --break-glass --incident <ic_id> --run --reason "why"
       then type GO:<host> (several hosts: GO:<first 6 of the plan-hash>).
       Every gate except the runbook lookup still applies.
"""


def _flag(rest, i, name):
    a = rest[i]
    if "=" in a:
        return a.split("=", 1)[1], i
    if i + 1 >= len(rest):
        raise Refused("%s needs a value" % name)
    return rest[i + 1], i + 1


def cli(argv, hosts_cfg, stream=None, prompt=None, now=None, key_path=None,
        grant_dir=None):
    stream = stream if stream is not None else sys.stdin
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    verb, rest = argv[0], argv[1:]

    if verb == "open":
        opts, i = {"hosts": None, "ttl": None, "reason": None}, 0
        while i < len(rest):
            name = rest[i].split("=", 1)[0]
            if name not in ("--hosts", "--ttl", "--reason"):
                raise Refused("unknown argument %r for `vpsexec incident open`" % rest[i])
            opts[name[2:]], i = _flag(rest, i, name)
            i += 1
        if not (opts["hosts"] and opts["ttl"]):
            raise Refused('usage: vpsexec incident open --hosts h1,h2 --ttl 1h '
                          '--reason "why"')
        hosts = parse_hosts(opts["hosts"], hosts_cfg)
        fields = fields_for(hosts, opts["ttl"], opts["reason"], now=now)
        print("INCIDENT OPEN — break-glass mutations on these hosts will NOT need "
              "a committed runbook until it expires or is closed:")
        print("  hosts : %s" % ", ".join(hosts))
        print("  ttl   : %s (until %s)" % (opts["ttl"], fields["expires_at"]))
        print("  reason: %s" % secretmask.mask(fields["reason"]))
        print("  every command still needs --run, --reason and a typed GO; the "
              "floor, deny_extra, the map and the journal still apply.")
        vpsexecgrant._confirm(stream, prompt, "INCIDENT:%s:%s"
                              % (",".join(hosts), opts["ttl"]), "open this incident")
        # Re-stamp after the prompt: the window starts when it is minted.
        fields = fields_for(hosts, opts["ttl"], opts["reason"], now=now)
        path, inc = mint(fields, key_path=key_path, grant_dir=grant_dir)
        print("")
        print("OPENED %s" % path)
        print(banner(inc, now))
        print("  close it when the outage is over: vpsexec incident close %s"
              % inc["incident_id"])
        return 0

    if verb == "status":
        if rest:
            raise Refused("`vpsexec incident status` takes no arguments")
        d = _grant_dir(grant_dir)
        if not d.is_dir():
            print("no open incidents")
            return 0
        vpsexecgrant._private_dir(d)
        shown = 0
        for p in sorted(d.iterdir()):
            if not ID_RE.match(p.name):
                continue
            try:
                inc = check(p.name, now=now, key_path=key_path, grant_dir=grant_dir)
                print("  " + banner(inc, now) + "  reason: %s"
                      % secretmask.mask(inc["reason"]))
                shown += 1
            except Refused as r:
                if "expired at" in str(r):
                    print("  EXPIRED %s — not closed yet; `vpsexec incident close %s` "
                          "writes its report" % (p.name, p.name))
                    shown += 1
                elif "is closed" not in str(r):
                    print("  INVALID %s — %s" % (p.name, r))
                    shown += 1
        if not shown:
            print("no open incidents")
        return 0

    if verb == "close":
        if len(rest) != 1:
            raise Refused("usage: vpsexec incident close <ic_id>")
        iid = rest[0].strip()
        inc = check(iid, now=now, key_path=key_path, grant_dir=grant_dir,
                    allow_expired=True)
        print("CLOSE incident %s (hosts %s) — permanent." % (iid, ", ".join(inc["hosts"])))
        vpsexecgrant._confirm(stream, prompt, "CLOSE:%s" % short_id(iid), "close it")
        path, text = close(iid, now=now, grant_dir=grant_dir, key_path=key_path)
        print("")
        print(text)
        print("CLOSED %s — report written to %s" % (iid, path))
        return 0

    raise Refused("unknown incident verb %r — open, status, close" % verb)
