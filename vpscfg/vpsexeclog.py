"""Reading the vpsexec journal — post-incident review, and the repeat guard.

journal/vpsexec.jsonl is append-only and write-heavy; this is the read side.
"What did we run during INC-4471, on what, and did it work?" should be one
command six months later, not an afternoon with grep.

Threats:
  - Protects against: a mis-fired automation re-running an identical mutation
    (recent_plan finds a byte-identical plan-hash inside a time window, so an
    unattended repeat can be refused); an unreadable or partially-written
    journal silently reading as "nothing happened" (a corrupt line raises
    rather than being skipped when strict, and the reader reports how many
    records it actually saw).
  - Does NOT protect against: a journal someone edited. It is an operational
    record, not a tamper-evident log — the control-plane copy pushed by
    telemetry.py is the second witness.
"""

import json
import re
import time

from . import secretmask
from pathlib import Path

from .gates import Refused

TS_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def path(stream="vpsexec"):
    from . import journal
    return Path(journal.JOURNAL_DIR) / ("%s.jsonl" % stream)


def read(stream="vpsexec", limit=None):
    """Newest-last list of records. A missing journal is empty, not an error."""
    p = path(stream)
    if not p.exists():
        return []
    records, bad = [], 0
    try:
        lines = p.read_text().splitlines()
    except OSError as e:
        raise Refused("journal unreadable (%s)" % e)
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            bad += 1
    if bad:
        records.append({"event": "_unparseable", "count": bad,
                        "ts": time.strftime(TS_FORMAT)})
    return records[-limit:] if limit else records


def _epoch(record):
    try:
        return time.mktime(time.strptime(record.get("ts", ""), TS_FORMAT))
    except (ValueError, TypeError, OverflowError):
        return None


def age_seconds(record):
    """Seconds since a record was written, or None if its timestamp is junk."""
    ts = _epoch(record)
    return None if ts is None else max(0.0, time.time() - ts)


def query(records, reason=None, host=None, event=None, plan_hash=None,
          since_seconds=None):
    """Filter. `reason` and `host` are substring/membership matches, because at
    2am you remember 'INC-4471' but not how you capitalised the rest."""
    now = time.time()
    out = []
    for r in records:
        if event and r.get("event") != event:
            continue
        if plan_hash and r.get("plan_hash") != plan_hash:
            continue
        if reason and reason.lower() not in str(r.get("reason") or "").lower():
            continue
        if host:
            hosts = r.get("hosts") or ([r["host"]] if r.get("host") else [])
            judged = r.get("judgment") or {}
            hosts = list(hosts) + list(judged.get("hosts") or [])
            if host not in hosts:
                continue
        if since_seconds is not None:
            ts = _epoch(r)
            if ts is None or (now - ts) > since_seconds:
                continue
        out.append(r)
    return out


def recent_plan(digest, within_seconds=300, stream="vpsexec"):
    """The most recent completed run of this byte-identical plan, or None.

    Used to catch an automation re-firing the same mutation. Only
    mutation_attempt records carry a plan_hash, so this cannot match a read.
    """
    hits = query(read(stream), plan_hash=digest, event="mutation_attempt",
                 since_seconds=within_seconds)
    return hits[-1] if hits else None


def _hosts_of(record):
    hosts = record.get("hosts") or ([record["host"]] if record.get("host") else [])
    if not hosts:
        hosts = (record.get("judgment") or {}).get("hosts") or []
    return list(hosts)


# Fields carrying remote command OUTPUT. Redacted on export: the journal caps
# them at 500 chars, but 500 chars of a config dump is still 500 chars of
# whatever was on that host.
OUTPUT_FIELDS = ("detail", "stdout", "stderr", "verify_detail")
COMMAND_FIELDS = ("command", "remote")


def export(records, redact=True):
    """A digest safe to archive or commit.

    The local journal is the record and it is gitignored, correctly — it holds
    command output. This strips that output and keeps the audit skeleton: who,
    when, where, what command, which plan-hash, what reason, what result. That
    is what answers "what changed on web1 this week?" six months later, and it
    is safe to put somewhere that outlives the laptop.

    redact=False is available for local inspection; it is not what you commit.
    """
    out = []
    for r in records:
        if r.get("event") == "_unparseable":
            out.append(dict(r))
            continue
        rec = dict(r)
        # An operator-typed command can carry a secret too (PGPASSWORD=...).
        # The journal keeps it verbatim (it is the record); an export does not.
        for field in COMMAND_FIELDS:
            if isinstance(rec.get(field), str):
                rec[field] = secretmask.mask(rec[field])
        for field in OUTPUT_FIELDS:
            if field in rec:
                rec[field] = ("<redacted: %d chars>" % len(str(rec[field])) if redact
                              else secretmask.mask(str(rec[field])))
        out.append(rec)
    return out


def durability(record_count=0):
    """One line on whether the journal has a second home. Fails loud, not silent."""
    from . import telemetry
    state, detail = telemetry.status()
    if state == "configured":
        return "journal: local + control plane (%s)" % detail
    fix = ("set VPSCFG_TELEMETRY_KEY or write %s" % telemetry.KEY_FILE
           if state == "no-key" else
           "name an endpoint in the governor (integrations.telemetry.url)")
    return ("journal: LOCAL ONLY — %d record(s) exist nowhere else.\n"
            "  %s\n"
            "  Fix: %s, or archive `vpsexec log --export`."
            % (record_count, detail, fix))


def render(records, limit=40):
    """One line per record, newest last — the shape you want when scrolling
    back through an incident."""
    if not records:
        return "no matching journal records"
    shown = records[-limit:]
    lines = []
    if len(records) > len(shown):
        lines.append("(%d older records not shown)" % (len(records) - len(shown)))
    for r in shown:
        ts = (r.get("ts") or "")[:19].replace("T", " ")
        event = r.get("event", "?")
        hosts = ",".join(_hosts_of(r)) or "-"
        detail = (r.get("command") or r.get("remote") or r.get("target") or "")
        rc = r.get("rc")
        bits = ["%-19s" % ts, "%-18s" % event, "%-22s" % hosts[:22]]
        if rc is not None:
            bits.append("rc=%-3s" % rc)
        if detail:
            bits.append(secretmask.mask(str(detail))[:52])
        reason = r.get("reason")
        if reason:
            # The reason is what you searched for; a line that hides it is a
            # line you cannot confirm you matched.
            bits.append("(%s)" % str(reason)[:40])
        lines.append("  " + " ".join(bits).rstrip())
    return "\n".join(lines)


def runs(records, host=None):
    """Group the journal into mutation runs, oldest first.

    A run opens at `mutation_attempt` and collects every `step`, `verify` and
    `canary_failed` after it until `mutation_complete`. Runs are serial per
    invocation (the host lock sees to that), so adjacency is the grouping. A
    run with no `mutation_complete` is still returned: an interrupted run is
    exactly the one somebody needs to read.
    """
    out, current = [], None
    for r in records:
        event = r.get("event")
        if event == "mutation_attempt":
            current = {"attempt": r, "steps": [], "complete": None}
            out.append(current)
        elif current is not None and event in ("step", "verify", "canary_failed"):
            current["steps"].append(r)
        elif current is not None and event == "mutation_complete":
            current["complete"] = r
            current = None
    if host:
        out = [run for run in out if host in _hosts_of(run["attempt"])]
    return out


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _indent(text, prefix="      | "):
    # Remote output can carry terminal escapes; never replay them raw.
    text = _CONTROL.sub(lambda m: "\\x%02x" % ord(m.group(0)), str(text).rstrip("\n"))
    return "\n".join(prefix + line for line in text.splitlines()) if text else ""


def render_runs(selected):
    """What happened, in full: the answer to "I ran it, look" without a paste."""
    if not selected:
        return "no mutation runs in the journal"
    blocks = []
    for run in selected:
        a = run["attempt"]
        lines = ["%s  %s" % ((a.get("ts") or "")[:19].replace("T", " "),
                             ",".join(_hosts_of(a)) or "-"),
                 "  command : %s" % secretmask.mask(str(a.get("command"))),
                 "  reason  : %s" % a.get("reason"),
                 "  approved: %s by %s%s" % (a.get("approval"), a.get("operator", "?"),
                                             "  [BREAK-GLASS]" if a.get("break_glass") else ""),
                 "  plan    : %s" % a.get("plan_hash")]
        for s in run["steps"]:
            if s.get("event") == "canary_failed":
                lines.append("  CANARY FAILED — not run: %s" % ", ".join(s.get("not_run") or []))
                continue
            label = "verify" if s.get("event") == "verify" else "step"
            if s.get("attempt"):
                label += " %s/%s" % (s.get("attempt"), s.get("tries"))
            lines.append("  [%s] %s rc=%s  %s" % (label, s.get("target") or s.get("host"),
                                                  s.get("rc"), secretmask.mask(str(s.get("remote")))))
            has_full = "stdout" in s or "stderr" in s
            body = (s.get("stdout", "") + s.get("stderr", "")) if has_full else s.get("detail", "")
            # Records journaled before masking existed still hold raw output;
            # mask on the way out too. Idempotent on already-masked text.
            body = secretmask.mask(body)
            if body:
                lines.append(_indent(body))
            if not has_full and body:
                lines.append("      (older record: only the first 500 chars were journaled)")
        c = run["complete"]
        if c is None:
            lines.append("  RESULT  : INCOMPLETE — no mutation_complete record (interrupted?)")
        else:
            lines.append("  RESULT  : %s" % ("ok" if not c.get("failed") and not c.get("not_run")
                                             else "failed=%s not_run=%s"
                                             % (c.get("failed"), c.get("not_run"))))
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)
