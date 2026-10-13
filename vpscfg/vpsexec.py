"""vpsexec — gated ad-hoc command execution across a fleet, or inside its
containers.

Built for the two things `vpscfg deploy` cannot do: restart a wedged process
across several machines during an outage, and read five machines' logs at once.
Reads fan out in parallel; mutations run serially in the order you named the
hosts and continue past a failure, reporting per host.

This is a SECOND door, deliberately separate from vpscfg/executor.py. The
executor's contract — "free-form remote shell through the executor" is listed
under Never in docs/STABILITY.md — stays literally true: no operator string
ever reaches it. vpsexec carries its own, stricter gate stack instead, because
it is the one place operator text becomes a remote command.

Gate order (all of it runs before anything executes):

   1. floor deny-scan     DENY_ALWAYS_FLOOR over the whole line. Never overridable.
   2. unanalyzable-scan   $( ) / backticks / <( ) refused outright — a deny-scan
                          cannot see through substitution, so it fails closed.
   3. tier classification read | mutating | risky.  Unknown => mutating.
   4. authorisation       a risky command runs ONLY if a committed runbook in
                          policies/*.yaml, or an --override file, names it
                          exactly — this command, these hosts, this placement,
                          unexpired.
   5. governor            mode / master switch / per-host posture (reads exempt).
                          A frozen or lockdown host is reachable only via
                          --break-glass AND a runbook marked break_glass: true.
   6. target resolution   container names checked against LIVE docker ps on
                          every host, in parallel, with the edit-distance-1
                          near-miss gate. One unprobeable host refuses the run.
   7. plan + plan-hash    always printed; --run alone still refuses.
   8. approval            TTY: type the host name. No TTY: --approve=<plan-hash>.
                          A step an approval contract lists may use
                          --approval-contract instead of typing (break-glass or
                          not; vpsexecgrant.py); TTY still required. A grant
                          is spent only when asked: --grant FILE, or --grant
                          auto (never one minted --for-release). With no flag
                          a break-glass plan LISTS valid grants (for vpsrun)
                          and asks for the typed phrase; --no-grant lists none.
                          Under --incident (vpsexecincident.py) gates 4-5 skip
                          only the runbook lookup for the incident's hosts, and
                          approval is a typed GO:<host> (GO:<plan[:6]> for
                          several) at the controlling TTY (no grant, no list).
   9. journal-or-refuse   an unauditable mutation must not happen.
  10. per-host lock       one mutation in flight per host; unknown completion retains it.
                          A locked or unreachable host fails that host only —
                          it cannot abort a fleet already in motion.

Threats:
  - Protects against: destructive command classes reaching any host (floor scan
    over the whole line, case-insensitive and whitespace-collapsed, repeated per
    segment so `ls && systemctl stop x` cannot hide behind a benign head);
    substitution bypasses (`$(echo pr)une` — the gap gates.py documents — is
    refused rather than scanned); a stale approval authorizing a different
    command (the plan-hash covers host, command, resolved container set,
    placement and override digest, so any drift invalidates it); standing
    blanket permission (--approve authorizes exactly one byte-identical plan,
    never a session or a host); typo'd container names (the volume near-miss
    rule, applied to containers); overrides that rot (expiry required); an
    override file quietly widening the floor (an entry naming a floor pattern
    rejects the WHOLE file as tampered); unjournaled mutations (journal-or-
    refuse); concurrent mutations (operation-owned lock, retained on disconnect).
    `push` ships bytes under the same gates, bound to their sha256 (see the
    push section below for its own Threats note).
  - Does NOT protect against: a semantically disastrous command that is
    syntactically ordinary — `systemctl stop postgres`, on a posture-test host,
    with a real override and a real human approving it, is indistinguishable
    from intent (that is what postures and blast_radius are for); a compromised
    host lying about what it ran; an operator who already holds SSH and skips
    this door entirely (which is why this door must be the only sanctioned one).
"""

import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import (actions, blackout, detach, journal, lock, mapfile, probe, secretmask,
               sshconfig, vpsexeclog, vpsexecgrant, vpsexecincident, vpsexecpolicy)
from .control import Guard
from .gates import DENY_ALWAYS_FLOOR, Refused, deny_scan, edit_distance
from .commandtext import normalize, literal_words, has_expansion
from . import readpolicy

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False

PLAN_HASH_VERSION = 2

# ---------------------------------------------------------------------------
# Tier 2 — risky. Refusable-but-overridable. Tier 1 is DENY_ALWAYS_FLOOR, which
# lives in gates.py, is compiled into all three doors, and NOTHING here can lift.
#
# Substring match over the whitespace-collapsed, lowercased command line. These
# are deliberately blunt: a false positive costs an override entry (cheap, and
# git-visible), a false negative costs a host.
#
# Note: bare "passwd" is absent on purpose — it would match `cat /etc/passwd`
# and burn the signal on a read. The mutating forms are covered by chpasswd /
# useradd / usermod / userdel.
# ---------------------------------------------------------------------------
VPSEXEC_RISKY = [
    # service + machine lifecycle
    "systemctl stop", "systemctl disable", "systemctl mask", "systemctl restart",
    "systemctl reload", "systemctl daemon-reload", "systemctl set-default",
    "service stop", "service restart", "invoke-rc.d",
    "shutdown", "reboot", "halt", "poweroff", "init 0", "init 6", "telinit",
    # container + orchestrator lifecycle
    "docker stop", "docker kill", "docker rm", "docker rmi", "docker restart",
    "docker compose down", "docker-compose down", "docker compose stop",
    "docker compose up", "docker-compose up", "docker compose restart",
    "docker-compose restart", "docker start", "docker create", "docker run",
    # hand-rolled `docker exec` sidesteps --in's live-container and near-miss
    # gates, so it costs an override entry. Use --in / --in-match instead.
    "docker exec",
    "docker network rm", "docker image rm", "docker container rm",
    "docker update", "docker load", "docker import", "docker commit",
    "kubectl delete", "kubectl drain", "kubectl cordon", "kubectl scale",
    "kubectl apply", "kubectl replace", "kubectl patch", "kubectl rollout",
    # exec/cp/port-forward are NOT reads: exec runs arbitrary code in a pod,
    # cp writes into one, port-forward opens a tunnel. Same class as
    # `docker exec` — risky, so they cost a runbook/override. Substring-matched,
    # so `k3s kubectl exec` is caught too.
    "kubectl exec", "kubectl cp", "kubectl port-forward",
    "helm uninstall", "helm delete", "helm rollback", "helm upgrade",
    # filesystem destruction / permission change
    "rm -r", "rm -f", "rm --recursive", "rm --force",
    "chown -r", "chmod -r", "chmod 777", "chattr", "setfacl",
    "mv /", "ln -sf /", "tee /etc", "tee /opt",
    # users, keys, auth
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "chpasswd",
    "visudo", "ssh-keygen", "authorized_keys",
    # network + firewall
    "iptables", "ip6tables", "nft ", "ufw ", "firewall-cmd",
    "ip link set", "ip addr add", "ip addr del", "ip route add", "ip route del",
    # packages + kernel
    "apt-get remove", "apt-get purge", "apt-get upgrade", "apt-get dist-upgrade",
    "apt remove", "apt purge", "apt upgrade", "dpkg -r", "dpkg --purge",
    "modprobe", "rmmod", "insmod", "sysctl -w",
    # data stores
    "pg_ctl", "pg_dropcluster", "pg_resetwal", "mysqladmin",
    "redis-cli flushall", "redis-cli flushdb", "redis-cli shutdown",
    # processes + scheduling
    "kill -9", "kill -kill", "killall", "pkill", "crontab -r", "at -r",
    # git history rewrites on a host
    "git reset --hard", "git clean -", "git checkout --force", "git push --force",
]

# Compatibility/introspection only; readpolicy.is_read validates full argv.
READ_ONLY_HEADS = frozenset(readpolicy.OPTIONS) | readpolicy.BARE

# Constructs a deny-scan provably cannot see through. Not overridable — an
# override names a literal command, and these have no literal to name.
UNANALYZABLE = ("$(", "`", "<(", ">(")

# The only redirections a read may carry. Discarding output cannot write to a
# real path, and `2>/dev/null` is in half the read commands anyone types — but
# ANY other `>` makes the command a mutation, because it can create a file.
SAFE_REDIRECT_RE = re.compile(r"(?:\d?>\s*/dev/null|&>\s*/dev/null|\d?>&\d)(?=\s|$|[;|&])")

CONTAINER_RE = probe.HOST_RE  # same shape: alnum start, then alnum . - (no _)
SEGMENT_SPLITS = (";", "&&", "||", "|", "\n")


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------

def split_segments(command):
    """Split on shell control operators, respecting quotes.

    A splitter bug can only ever UNDER-split, and every scan that matters
    (floor, risky) also runs over the whole line — so under-splitting cannot
    turn a risky command into a read.
    """
    segments, buf, quote, i = [], [], None, 0
    while i < len(command):
        c = command[i]
        if c == '\\' and quote != "'" and i + 1 < len(command):
            buf.extend(command[i:i + 2])
            i += 2
            continue
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        two = command[i:i + 2]
        if two in ("&&", "||"):
            segments.append("".join(buf)); buf = []; i += 2; continue
        if c == "&" and (command[i - 1:i] == ">" or command[i + 1:i + 2] == ">"):
            # `2>&1` / `&>` — part of a redirection, not a control operator.
            buf.append(c); i += 1; continue
        if c in (";", "|", "\n", "&"):
            segments.append("".join(buf)); buf = []; i += 1; continue
        buf.append(c)
        i += 1
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


def risky_hit(text, extra=()):
    """First risky pattern found in `text`, or None.

    `extra` comes from the YAML policy framework's `risky_extra:` and can only
    ADD patterns — there is no path from a policy file to removing one.
    """
    lowered = normalize(text).lower()
    for pattern in list(VPSEXEC_RISKY) + list(extra or ()):
        if pattern in lowered:
            return pattern
    return None


def _segment_is_read(segment):
    if has_expansion(segment):
        return False
    segment = SAFE_REDIRECT_RE.sub('', segment)
    segment = re.sub(r'<\s*/dev/null(?=\s|$)', '', segment)
    if any(c in segment for c in '<>'):
        return False
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return False  # unbalanced quotes: unparseable => not a read
    if not tokens:
        return False
    return readpolicy.is_read(tokens)


def _expand_short_flags(tokens):
    """Normalise flag spellings so a disqualifier cannot hide inside one.

    Two evasions, both found in commands people actually type:
      bundled shorts   `curl -sfo /tmp/x`, `nc -le /bin/sh host 4444`
      long with value  `journalctl --vacuum-size=200M`

    Either would otherwise classify as an ordinary read — and a read needs no
    --run, no approval, and works on a frozen host. A reverse shell must not be
    a read, and neither must a command that deletes the logs.
    """
    out = list(tokens)
    for token in tokens:
        if token.startswith("--"):
            # `--vacuum-size=200M` must also count as `--vacuum-size`.
            if "=" in token:
                out.append(token.split("=", 1)[0])
        elif len(token) > 2 and token.startswith("-"):
            out.extend("-" + ch for ch in token[1:])
    return out


def tree_reads(command, deny_patterns, depth=0, grep_options=False):
    """Apply readpolicy.tree_read_verdict and readpolicy.path_read_verdict
    (raw devices, process memory, credential files) to every segment of
    `command`.

    Raises Refused for a refusal; returns the first demotion reason or None.
    Whitespace-bearing arguments of heads that do not take patterns are
    re-scanned as shell text (`sh -c '...'`, `ssh h '...'`), best effort: text
    that does not parse as shell there is data, not a command."""
    grep_options = grep_options or "GREP_OPTIONS" in command
    demote = None
    for segment in split_segments(command):
        segment = re.sub(r'<\s*/dev/null(?=\s|$)', '', SAFE_REDIRECT_RE.sub('', segment))
        try:
            tokens = shlex.split(segment)
        except ValueError:
            if depth:
                continue
            raise Refused("unparseable segment %r — refusing rather than guessing "
                          "what it reads" % segment)
        for verdict in (readpolicy.tree_read_verdict(tokens, deny_patterns, grep_options),
                        readpolicy.path_read_verdict(tokens, deny_patterns)):
            if verdict and verdict[0] == "refuse":
                raise Refused(verdict[1])
            demote = demote or (verdict and verdict[1])
        head = tokens[0].rsplit("/", 1)[-1] if tokens else ""
        if depth < 3 and head not in readpolicy.PATTERN_HEADS:
            for token in tokens[1:]:
                if any(c in token for c in " \t\n;|&"):
                    demote = demote or tree_reads(token, deny_patterns, depth + 1,
                                                          grep_options)
    return demote


def classify(command, deny_patterns, risky_extra=()):
    """Return (tier, detail). Tier is 'read', 'mutating', or 'risky'.

    Raises Refused for tier-1 floor matches and for unanalyzable constructs —
    neither is a tier, because neither has a path to running.
    """
    norm = normalize(command)
    if not norm:
        raise Refused("empty command")
    if len(norm) > 65536:
        raise Refused('command exceeds 64 KiB limit')
    try:
        literal_words(norm)
    except ValueError as exc:
        raise Refused('invalid shell quoting: %s' % exc)

    # 1. Tier 1. Whole line, then every segment. Never overridable.
    deny_scan(norm, deny_patterns)
    for segment in split_segments(norm):
        deny_scan(segment, deny_patterns)

    # 2. Constructs that defeat scanning entirely.
    for bad in UNANALYZABLE + ('$',):
        if bad in norm:
            raise Refused(
                "command contains %r — command substitution cannot be scanned, "
                "so it is refused outright (not overridable). Write the literal "
                "command you mean." % bad
            )
    if has_expansion(norm):
        raise Refused('unquoted shell expansion cannot be inspected; use literal arguments or a quoted find pattern')

    # 2b. Tree reads (readpolicy.tree_read_verdict): a recursive content read
    # rooted at a broad or unknown directory is refused on every tier; one
    # rooted outside the log trees is never a read. Path reads
    # (readpolicy.path_read_verdict): a content read of a raw device, process
    # memory or a credential file is refused on every tier; /sys and
    # /proc/<pid>/root are never reads.
    tree_demote = tree_reads(norm, deny_patterns)

    # 3. Tier 2. Whole line and per segment, so a benign head cannot shelter it.
    hit = risky_hit(norm, risky_extra) or risky_hit(' '.join(literal_words(norm)), risky_extra)
    if hit is None:
        for segment in split_segments(norm):
            hit = risky_hit(segment, risky_extra)
            if hit:
                break
    if hit:
        return "risky", hit

    # 4. Read only if EVERY segment is a read and nothing writes or expands.
    if ">" in SAFE_REDIRECT_RE.sub("", norm):
        return "mutating", "redirection"
    if "$" in norm:
        raise Refused('variable expansion cannot be authorized as a literal command')
    segments = split_segments(norm)
    if tree_demote:
        return "mutating", tree_demote
    if segments and all(_segment_is_read(s) for s in segments):
        return "read", None
    hint = _read_form_hint(segments)
    return "mutating", "not on the read-only allowlist%s" % (
        "; hint: " + hint if hint else "")


def _read_form_hint(segments):
    """Message only, computed AFTER the tier is decided: for the first
    non-read segment whose head is a known read tool refused for its flags or
    form, say what form is accepted. Nothing here feeds back into classify."""
    for segment in segments:
        if _segment_is_read(segment):
            continue
        segment = re.sub(r'<\s*/dev/null(?=\s|$)', '', SAFE_REDIRECT_RE.sub('', segment))
        if has_expansion(segment) or any(c in segment for c in '<>'):
            return None
        try:
            return readpolicy.read_form_hint(shlex.split(segment))
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# host sets
# ---------------------------------------------------------------------------

def governor_aliases(hosts_cfg):
    """{alias: canonical} from the governor's hosts[*].alias_of declarations."""
    return dict((name, cfg["alias_of"])
                for name, cfg in (hosts_cfg or {}).items()
                if isinstance(cfg, dict) and cfg.get("alias_of"))


def resolve_hosts(spec, groups, hosts_cfg, machines=None):
    """Turn 'web1,web2', '@dns', '@all', or '@dns,web1' into a host list.

    Two names for one machine would otherwise run the command TWICE on one box,
    or fail because only one of the names is an ssh alias. Both are handled:

      alias_of   the governor declares `web1` IS `web1.example.internal`, so
                 `web1` is rewritten to the reachable name and the rewrite is
                 shown in the plan. Postures are read from the CANONICAL host,
                 validated equal at load, so an alias cannot launder a posture.
      machines   two ssh aliases resolving to one HostName collapse to the
                 first named, and the drop is shown.

    Returns {"hosts", "aliased", "dropped", "excluded"} — an operator who typed
    something that turned into something else deserves to read that in the plan.
    """
    spec = (spec or "").strip()
    if not spec:
        raise Refused("no host named — usage: vpsexec <host[,host]|@group> '<command>'")

    aliases = governor_aliases(hosts_cfg)
    governed = set(hosts_cfg or ())
    known = sshconfig.load()
    groups = groups or {}
    names, excluded = [], []

    for token in (t.strip() for t in spec.split(",")):
        if not token:
            continue
        if not token.startswith("@"):
            names.append(token)
            continue
        group = token[1:]
        if group == "all":
            # Every governed machine, once. Alias entries are skipped (their
            # canonical target is already in the list). A governed host with no
            # ssh alias at all is excluded and said so in the plan — never
            # silently, or "I ran it everywhere" quietly means "almost".
            for host in sorted(governed):
                if host in aliases:
                    continue
                if known and host not in known:
                    excluded.append((host, "no ~/.ssh/config alias"))
                else:
                    names.append(host)
        elif group in groups:
            names.extend(groups[group])
        else:
            raise Refused(
                "no host group %r in the governor — defined groups: %s (plus @all)"
                % (group, ", ".join(sorted(groups)) or "none"))
    if not names:
        raise Refused("host spec %r resolved to no hosts" % spec)

    canonical, aliased = [], []
    for name in names:
        if not probe.HOST_RE.match(name or ""):
            raise Refused("invalid host name %r" % name)
        target = aliases.get(name, name)
        if target != name and (name, target) not in aliased:
            aliased.append((name, target))
        if known and target not in known:
            raise Refused(
                "host %r is not reachable: %s is not an alias in ~/.ssh/config "
                "— known: %s"
                % (name, "it" if target == name else "its canonical name %r" % target,
                   ", ".join(sorted(known))))
        canonical.append(target)

    # Collapse ssh aliases that point at one machine, keeping the first named.
    machines = sshconfig.machines() if machines is None else machines
    alias_to_machine = {}
    for target, rec in (machines or {}).items():
        for alias in rec.get("aliases", []):
            alias_to_machine[alias] = target

    ordered, seen_machines, dropped = [], {}, []
    for name in canonical:
        key = alias_to_machine.get(name, name)
        if key in seen_machines:
            if name != seen_machines[key]:
                dropped.append((name, seen_machines[key]))
            continue
        seen_machines[key] = name
        ordered.append(name)
    if not ordered:
        raise Refused("host spec %r resolved to no reachable host%s"
                      % (spec, " (excluded: %s)"
                         % ", ".join("%s (%s)" % e for e in excluded)
                         if excluded else ""))
    return {"hosts": ordered, "aliased": aliased, "dropped": dropped,
            "excluded": excluded}


# ---------------------------------------------------------------------------
# override files
# ---------------------------------------------------------------------------

def load_override(path, deny_patterns, today=None):
    """Parse + validate an override file. Fails closed on everything.

    An entry naming a tier-1 floor pattern does not merely get dropped — the
    whole file is rejected as tampered, because a file that tries to lift the
    floor has told you what it is.

    `break_glass: true` marks an entry as a pre-authorised outage runbook: it
    lets --break-glass reach a frozen or lockdown host for THAT exact command
    and host set. Written and reviewed during calm, used under fire.
    """
    if not _HAVE_YAML:
        raise Refused("--override needs PyYAML and it is unavailable — failing closed")
    p = Path(path)
    try:
        raw = p.read_bytes()
        doc = yaml.safe_load(raw)
    except (OSError, yaml.YAMLError) as e:
        raise Refused("override file unreadable/invalid (%s) — failing closed" % e)

    if not isinstance(doc, dict):
        raise Refused("override file %s is not a mapping" % path)
    if doc.get("version") != 1:
        raise Refused("override file %s: version must be 1" % path)

    expires = doc.get("expires")
    if not expires:
        raise Refused(
            "override file %s has no 'expires' — an override without an expiry "
            "is a permanent hole; date it (YYYY-MM-DD)" % path)
    expires = str(expires)
    today = today or time.strftime("%Y-%m-%d")
    if not vpsexecpolicy.iso_date(expires):
        raise Refused("override file %s: expires %r is not YYYY-MM-DD" % (path, expires))
    if expires < today:
        raise Refused(
            "override file %s expired on %s (today is %s) — re-approve it "
            "deliberately, in git" % (path, expires, today))

    if not str(doc.get("reason", "")).strip():
        raise Refused("override file %s has no top-level 'reason'" % path)

    allow = doc.get("allow")
    if not isinstance(allow, list) or not allow:
        raise Refused("override file %s: 'allow' must be a non-empty list" % path)

    entries = []
    for n, entry in enumerate(allow, 1):
        if not isinstance(entry, dict):
            raise Refused("override file %s entry %d is not a mapping" % (path, n))
        unknown = sorted(set(entry) - vpsexecpolicy.RUNBOOK_KEYS)
        if unknown:
            raise Refused("override file %s entry %d has unknown key(s) %r — "
                          "refusing rather than ignoring them" % (path, n, unknown))
        for key in ("container", "verify_retry"):
            # Refused, not ignored: an override that named a container and was
            # then read without it would authorise every container.
            if key in entry:
                raise Refused("override file %s entry %d sets %r — that key is "
                              "for committed runbooks in policies/, not an "
                              "ad-hoc --override file" % (path, n, key))

        hosts = entry.get("hosts", entry.get("host"))
        if isinstance(hosts, str):
            hosts = [hosts]
        if (not isinstance(hosts, list) or not hosts
                or not all(isinstance(h, str) and h.strip() for h in hosts)):
            raise Refused("override file %s entry %d needs host: <name> or "
                          "hosts: [<name>, ...]" % (path, n))
        for h in hosts:
            if not probe.HOST_RE.match(h):
                raise Refused("override file %s entry %d: invalid host %r"
                              % (path, n, h))

        if "action" in entry or "with" in entry:
            # A typed action (docs/ACTIONS.md) for non-break-glass hosts only.
            where_n = "override file %s entry %d" % (path, n)
            if entry.get("break_glass", False) is not False:
                raise Refused("%s sets break_glass on an action — an ad-hoc --override "
                              "file cannot elevate past a host's posture" % where_n)
            if not str(entry.get("why", "")).strip():
                raise Refused("%s missing 'why'" % where_n)
            cmd, record = vpsexecpolicy.action_call(entry, deny_patterns, hosts, where_n)
            entries.append({"hosts": list(hosts), "cmd": cmd, "where": "host",
                            "why": entry["why"], "break_glass": False,
                            "source": str(path), "verify": None, "action": record})
            continue

        for key in ("cmd", "why"):
            if not str(entry.get(key, "")).strip():
                raise Refused("override file %s entry %d missing %r" % (path, n, key))

        where = entry.get("where", "host")
        if where not in ("host", "container"):
            raise Refused(
                "override file %s entry %d: where must be 'host' or 'container', "
                "not %r — an override for the host must not silently authorise "
                "40 containers" % (path, n, where))

        break_glass = entry.get("break_glass", False)
        if not isinstance(break_glass, bool):
            raise Refused("override file %s entry %d: break_glass must be true "
                          "or false, not %r" % (path, n, break_glass))
        if break_glass:
            raise Refused(
                "override file %s entry %d sets break_glass: true — an ad-hoc "
                "--override file cannot elevate past a host's posture. "
                "Reaching a frozen host is precisely the decision that must not "
                "be improvised during an incident, so it comes only from a "
                "runbook committed to policies/ and reviewed beforehand."
                % (path, n))

        cmd = normalize(entry["cmd"])
        try:
            deny_scan(cmd, deny_patterns)
            tree_reads(cmd, deny_patterns)
        except Refused as r:
            raise Refused(
                "override file %s entry %d names a deny-always pattern (%s) — "
                "the floor is not overridable by any file, so this whole file is "
                "rejected as tampered" % (path, n, r))
        for bad in UNANALYZABLE:
            if bad in cmd:
                raise Refused(
                    "override file %s entry %d contains %r — substitution is not "
                    "overridable" % (path, n, bad))
        if actions.is_reserved(cmd):
            raise actions.reserved_refusal("override file %s entry %d" % (path, n))

        verify = entry.get("verify")
        if verify is not None:
            if not isinstance(verify, str) or not verify.strip():
                raise Refused("override file %s entry %d: verify must be a "
                              "non-empty string" % (path, n))
            verify = normalize(verify)
            deny_scan(verify, deny_patterns)
        entries.append({"hosts": list(hosts), "cmd": cmd, "where": where,
                        "why": entry["why"], "break_glass": False,
                        "source": str(path), "verify": verify})

    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
            "expires": expires, "reason": doc["reason"], "allow": entries}


def authorizations(policy, override):
    """Every authorisation in force: committed runbooks from policies/*.yaml,
    plus any ad-hoc --override file. Same schema, same rules; the only
    difference is that one was reviewed in advance and the other was not."""
    entries = list((policy or {}).get("runbooks", []))
    if override:
        entries += override["allow"]
    return entries


def permits(entries, host, command, where, aliases=None, containers=None):
    """Exact match only — no globs, no prefixes, no regex. An authorisation
    that can be interpreted is one that can be misinterpreted.

    `aliases` is the governor's {alias: canonical} map. Target resolution
    rewrites `web1` to `web1.example.internal`, so a runbook naming either
    spelling must match either spelling: both sides are compared by their
    canonical name. Only a governor-declared alias_of (one hop, chains refused
    at load) joins two names; an entry for host X never matches host Y.

    `containers` is the invocation's --in names, or None for --in-match /
    --in-all / the host itself. An entry that names a `container` matches only
    an invocation of exactly `--in <that container>`: it never authorises a
    glob, every container, or a different one."""
    aliases = aliases or {}
    norm = normalize(command)
    want = aliases.get(host, host)
    for entry in entries or ():
        if (entry["cmd"] == norm and entry["where"] == where
                and any(aliases.get(h, h) == want for h in entry["hosts"])
                and _container_ok(entry, containers)):
            return entry
    return None


def _container_ok(entry, containers):
    named = entry.get("container")
    if named is None:
        return True
    return bool(containers) and set(containers) == {named}


def lookup(entries, hosts, command, where, aliases=None, containers=None):
    """{host: entry-or-None} across a whole fleet target."""
    return dict((h, permits(entries, h, command, where, aliases=aliases,
                            containers=containers))
                for h in hosts)


def _spellings(host, aliases):
    """'web1.example.internal (alias: web1)' — every name a runbook may use."""
    others = sorted(a for a, c in (aliases or {}).items() if c == host)
    return "%s (alias: %s)" % (host, ", ".join(others)) if others else host


# ---------------------------------------------------------------------------
# target resolution (per host)
# ---------------------------------------------------------------------------

def live_containers(host, prober=None):
    prober = prober or probe.run
    result = prober(host, "containers")
    if result["rc"] != 0:
        raise Refused("cannot list containers on %s: %s"
                      % (host, secretmask.mask((result["stderr"] or result["stdout"]).strip())[:200]))
    names = []
    for line in (result["stdout"] or "").splitlines():
        name = line.split("\t")[0].strip()
        if name and name != "NO_DOCKER" and CONTAINER_RE.match(name):
            names.append(name)
    return sorted(set(names))


def _near_miss_check(requested, live):
    """The one-character volume-twin rule (gates.volume_name_check), applied
    to container names."""
    for name in live:
        if edit_distance(requested, name) == 1:
            raise Refused(
                "container %r is one character away from LIVE container %r — "
                "refusing; name the exact container you mean" % (requested, name))


def resolve_targets(host, names, match, all_flag, prober=None):
    """Return the ordered target list for ONE host. [] means the host itself."""
    if not (names or match or all_flag):
        return []
    live = live_containers(host, prober=prober)
    if not live:
        raise Refused("no live containers on %s to target" % host)

    selected = []
    if all_flag:
        selected = list(live)
    if match:
        hit = fnmatch.filter(live, match)
        if not hit:
            raise Refused(
                "--in-match %r matched no live container on %s (live: %s) — a "
                "glob that matches nothing is a typo, not an empty set"
                % (match, host, ", ".join(live)))
        selected += hit
    for name in names:
        if not CONTAINER_RE.match(name or ""):
            raise Refused("invalid container name %r" % name)
        if name not in live:
            _near_miss_check(name, live)
            raise Refused("no live container %r on %s (live: %s)"
                          % (name, host, ", ".join(live)))
        selected.append(name)
    return sorted(set(selected))


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

def build_remote_command(command, container):
    if container is None:
        return normalize(command)
    return "docker exec %s sh -lc %s" % (shlex.quote(container),
                                         shlex.quote(normalize(command)))


def build_plan(hosts, command, per_host_targets, tier, detail, override=None,
               entries=None, all_flag=False, dropped=None, postures=None,
               break_glass=False, excluded=None, aliased=None, verify=None,
               canary=0, compare=False, windows=None, blackout_status=None,
               verify_retry=None):
    """per_host_targets: {host: [container, ...]}  ([] => the host itself).
    verify: {host: post-condition command}. Runs on the host, after the steps.
    verify_retry: {host: (tries, interval)}; absent => one try."""
    per_host, verify, verify_retry = {}, verify or {}, verify_retry or {}
    for host in hosts:
        targets = list(per_host_targets.get(host, []))
        per_host[host] = {
            "targets": targets,
            "verify": verify.get(host),
            "verify_retry": verify_retry.get(host),
            "steps": [{"container": c, "remote": build_remote_command(command, c)}
                      for c in (targets or [None])],
        }
    entries = entries or {}
    return {
        "hosts": list(hosts),
        "command": normalize(command),
        "placement": "container" if any(per_host[h]["targets"] for h in hosts) else "host",
        "per_host": per_host,
        "all_flag": bool(all_flag),
        "dropped": list(dropped or []),
        "excluded": list(excluded or []),
        "aliased": list(aliased or []),
        "postures": dict(postures or {}),
        "tier": tier,
        "tier_detail": detail,
        "break_glass": bool(break_glass),
        "canary": int(canary or 0),
        "compare": bool(compare),
        "windows": dict(windows or {}),
        "blackout_status": blackout_status,
        "override_path": override["path"] if override else None,
        "override_sha256": override["sha256"] if override else None,
        "override_why": sorted(set(e["why"] for e in entries.values() if e)) or None,
    }


def plan_hash(plan):
    """Covers everything that changes what actually runs, across the whole
    fleet. Deliberately NOT the --run flag, so the dry run's hash is the one you
    approve with. A container appearing on ANY host invalidates it.

    A push adds its own key, so a push plan and an ordinary command whose
    text happens to equal the canonical push string can never share a hash."""
    fields = {
        "v": PLAN_HASH_VERSION,
        "hosts": list(plan["hosts"]),
        "command": plan["command"],
        "placement": plan["placement"],
        "targets": dict((h, sorted(plan["per_host"][h]["targets"]))
                        for h in plan["hosts"]),
        "tier": plan["tier"],
        "break_glass": plan["break_glass"],
        "canary": plan.get("canary", 0),
        "verify": dict((h, plan["per_host"][h].get("verify")) for h in plan["hosts"]),
        "override_sha256": plan["override_sha256"],
    }
    if plan.get("push"):
        fields["push"] = dict((k, plan["push"][k])
                              for k in ("sha256", "basename", "size", "path"))
    # Only when present, so every plan without a retry keeps its old hash.
    retries = dict((h, list(plan["per_host"][h]["verify_retry"])) for h in plan["hosts"]
                   if plan["per_host"][h].get("verify_retry"))
    if retries:
        fields["verify_retry"] = retries
    # Only when present, so every plan outside an incident keeps its old hash.
    if plan.get("incident"):
        fields["incident"] = plan["incident"]
    # A typed action: the bytes that run, per host (S3). Only when present.
    if plan.get("action"):
        fields["action"] = dict((k, plan["action"][k]) for k in ACTION_HASH_KEYS)
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# typed actions (vpscfg/actions, docs/ACTIONS.md)
#
# `vpsexec <hosts> --action NAME --with JSON` reaches a typed action. Its
# canonical string `vpscfg-action <name>@<v> '<json>'` is the plan's command:
# the floor, deny_extra, risky_extra, runbook matching, grants and the
# plan-hash all see it. The door, not the operator, builds the body from a
# fixed template; the plan prints the body in full and the plan-hash binds its
# sha256, the check's and the verify. Typing the canonical string is refused.
#
# Threats:
#   - Protects against: an action running anywhere a committed runbook (or a
#     non-break-glass override) does not name it (a mutation action is tier
#     risky, so gate 4 applies; break-glass still needs a committed
#     break_glass entry); bytes running that were not shown (body, check and
#     verify are printed and hashed per host; REPLAN on any change); a
#     template reaching the floor or a deny list (every byte is deny-scanned
#     with the governor's and the policies' patterns before approval and again
#     per host); a done-check that writes or lies (a shell check must classify
#     as a read under classify(), a SQL check goes through the sqlread gate in
#     a read-only session, a token-only check must be the pinned reviewed
#     script of this very action (_gate_token; its output is never shown or
#     journaled, only the token); its output must be exactly one token, anything else
#     — extra lines, another case, nothing, rc != 0, a transport failure —
#     fails the host closed with the body NOT run); a check releasing someone
#     else's lock (it runs only after this operation took the lock, and never
#     replaces reconcile); a read action that writes (its body must classify
#     as a read too); actions under an incident (refused, D9).
#   - Does NOT protect against: a reviewed template that is wrong (golden
#     files and `expands:` make every change visible; they do not prove it
#     right); a host that lies about the check (the host is trusted, as for
#     every verify).
# ---------------------------------------------------------------------------

ACTION_HASH_KEYS = ("name", "version", "params", "tier", "per_host")
ACTION_CHECK_TIMEOUT = 60  # a done-check is a read: the read timeout


def _action_tier(action, tier, detail):
    """The tier is fixed in code: read for a read action, otherwise risky (a
    runbook or override must name it). A risky_extra hit on the canonical
    string makes even a read action risky — policies only tighten."""
    if tier == "risky":
        return tier, detail
    if action.tier == "read":
        return "read", None
    return "risky", ("typed action %s@%d — runs only where a runbook or override names it"
                     % (action.name, action.version))


TOKEN_FILE_KINDS = (None, "an environment file")


def _gate_token(probe, what, deny, risky_extra, exp):
    """A token-only check (actions.TokenCheck): the ONLY exemption from the
    credential-file rule, and only for the registered script of `exp`'s own
    action and version, with `exp`'s own parameters, for the registry's named
    file parameter. That file may be an environment file; never a device,
    /proc, /sys, an ssh host key, a key/.private file or registries.yaml.
    The floor and deny lists scan the command and the whole stdin (S1)."""
    if exp is None:
        raise Refused("action %s: a token-only check runs only bound to its own action "
                      "— refused" % what)
    path = probe.bind(exp)  # Refused: other action, unregistered, swapped bytes
    kind = readpolicy._credential_file(path)
    if kind not in TOKEN_FILE_KINDS:
        raise Refused("action %s reads %s, which is %s: a token-only check is exempt "
                      "for an environment file only — refused" % (what, path, kind))
    verdict = readpolicy._path_class(path)
    if verdict:
        raise Refused("action %s reads %s: %s — refused" % (what, path, verdict[1]))
    for t in (probe.command(), probe.script()):
        deny_scan(t, deny)
    hit = next((p for p in (risky_extra or ()) if p in normalize(probe.text()).lower()), None)
    if hit:
        raise Refused("action %s matches the policy's risky_extra %r — refused at plan "
                      "time" % (what, hit))


def _gate_probe(probe, what, deny, risky_extra, exp=None):
    """A check or verify: a shell text must classify as a read; a SqlCheck
    passes the sqlread gate (one SELECT/SHOW, read-only session) and the
    policies' risky_extra over its whole text; a TokenCheck passes
    _gate_token."""
    if isinstance(probe, actions.TokenCheck):
        _gate_token(probe, what, deny, risky_extra, exp)
        return
    if isinstance(probe, actions.SqlCheck):
        text = probe.text()  # pg_script() runs sqlread.classify, or refuses
        for t in (probe.command(), probe.script()):
            deny_scan(t, deny)
        hit = next((p for p in (risky_extra or ()) if p in normalize(text).lower()), None)
        if hit:
            raise Refused("action %s matches the policy's risky_extra %r — refused at plan "
                          "time" % (what, hit))
        return
    tier, detail = classify(probe, deny, risky_extra)
    if tier != "read":
        raise Refused("action %s %r classifies as %r%s, not a read — it runs with no "
                      "approval of its own, so it must be unable to change anything"
                      % (what, probe, tier, " (%s)" % detail if detail else ""))


def _gate_action(expansions, deny, risky_extra):
    for exp in expansions.values():
        actions.deny_check(exp, deny, "--action")
        if exp.tier == "read":
            _gate_probe(exp.body, "body (a read action)", deny, risky_extra)
        if exp.check is not None:
            _gate_probe(exp.check, "done-check", deny, risky_extra, exp)
        if exp.verify is not None:
            _gate_probe(exp.verify, "verify", deny, risky_extra, exp)


def _attach_action(plan, expansions):
    """Steps, verify and the hashed action record, per host."""
    per = {}
    for host in plan["hosts"]:
        exp = expansions[host]
        ph = plan["per_host"][host]
        ph["steps"] = [{"container": None, "remote": exp.body, "check": exp.check,
                        "retry": exp.verify_retry if exp.tier == "read" else None}]
        ph["verify"] = exp.verify_text()
        ph["verify_probe"] = exp.verify
        ph["verify_retry"] = exp.verify_retry if exp.verify is not None else None
        per[host] = {"body_sha256": exp.body_sha256(), "check_sha256": exp.check_sha256(),
                     "verify": exp.verify_text(),
                     "retry": list(exp.verify_retry) if exp.verify_retry else None}
    first = expansions[plan["hosts"][0]]
    plan["action"] = {"name": first.name, "version": first.version, "params": first.params,
                      "tier": first.tier, "idempotent": first.idempotent, "per_host": per,
                      "canonical": first.canonical}


def _action_fields(plan, per_host=True):
    """Journal keys for an action plan (params masked); {} otherwise."""
    act = plan.get("action")
    if not act:
        return {}
    out = {"action": act["name"], "action_version": act["version"],
           "params": secretmask.mask(actions.base.canonical_json(act["params"]))}
    if per_host:
        out["body_sha256"] = dict((h, v["body_sha256"]) for h, v in act["per_host"].items())
    return out


def _render_action_header(plan):
    act = plan["action"]
    hosts = plan["hosts"]
    lines = ["  action  : %s@%d (%s%s)" % (
        act["name"], act["version"], act["tier"],
        ", idempotent" if act["idempotent"] else
        "" if act["tier"] == "read" else ", NOT idempotent: no done-check")]
    if act["tier"] != "read":
        lines.append("  check   : %s" % ("skips a host whose check prints VPSCFG-DONE ([done], "
                                         "body not run)" if act["idempotent"] else "none"))
    retries = sorted(set(tuple(plan["per_host"][h]["steps"][0]["retry"])
                         for h in hosts if plan["per_host"][h]["steps"][0].get("retry")))
    for tries, interval in retries:
        lines.append("  retry   : the probe, up to %d tries, %ds apart" % (tries, interval))
    return lines


def _render_action_step(label, step):
    """The body IN FULL, then the check: what is approved is what runs."""
    lines = ["  %s" % label, "    body:"]
    lines += ["      %s" % l for l in step["remote"].splitlines()]
    if step.get("check") is not None:
        lines.append("    check:")
        lines += ["      %s" % l for l in actions.probe_text(step["check"]).splitlines()]
    return lines


def _run_probe(host, probe, ssh, timeout, deny):
    """One check or verify on a host: a shell text, or a SqlCheck with its
    script on stdin (the password stays inside the container), or a
    TokenCheck whose reviewed bytes are re-checked before they are sent."""
    if isinstance(probe, actions.TokenCheck):
        probe.pinned()
    if isinstance(probe, (actions.SqlCheck, actions.TokenCheck)):
        command, script = probe.command(), probe.script()
        deny_scan(command, deny)
        deny_scan(script, deny)
        return ssh(host, command, timeout=timeout, data=script.encode("utf-8"))
    deny_scan(probe, deny)
    return ssh(host, probe, timeout=timeout)


def _probe_token(probe, rc, out):
    if rc != 0:
        return None
    if isinstance(probe, (actions.SqlCheck, actions.TokenCheck)):
        return probe.token(_decode(out))
    return actions.plain_token(_decode(out))


def _action_already_done(host, plan, step, ssh, timeout, deny, lock_token):
    """Run the done-check (lock held by THIS operation). True: DONE, skip the
    body. False: NEEDED, run it. Anything else raises Refused: the host fails
    closed and nothing ran (S6) — never "assume done", never "assume not"."""
    probe = step["check"]
    # A token-only check may read a secret file: nothing it printed, and no
    # transport text, is ever shown or journaled — only the token or a fixed
    # error class, rc and duration.
    withheld = isinstance(probe, actions.TokenCheck)
    started = time.monotonic()
    fields = dict({"event": "action_check", "host": host, "operation_id": lock_token},
                  **_action_fields(plan, per_host=False))
    try:
        rc, out, err = _run_probe(host, probe, ssh, min(timeout, ACTION_CHECK_TIMEOUT), deny)
    except (OSError, subprocess.TimeoutExpired) as e:
        journal.append("vpsexec", dict(fields, token=None, rc=None, detail=(
            "transport" if withheld else secretmask.mask("transport: %s" % e)[:200])))
        raise Refused("done-check on %s failing closed, the step did not run: the check "
                      "could not run (%s)" % (host, "transport lost" if withheld
                                              else secretmask.mask(str(e))[:120]))
    token = _probe_token(probe, rc, out)
    extra = {"error": "not-a-token"} if withheld and token is None else {}
    journal.append("vpsexec", dict(fields, token=token, rc=rc,
                                   duration=round(time.monotonic() - started, 3), **extra))
    if token is None and withheld:
        raise Refused("done-check on %s failing closed, the step did not run: the "
                      "token-only check did not print exactly %s or %s (rc=%s); its "
                      "output is withheld, never shown" % (host, actions.DONE,
                                                            actions.NEEDED, rc))
    if token is None:
        shown = secretmask.mask(_decode(out) or _decode(err) or "")[:80]
        raise Refused("done-check on %s failing closed, the step did not run: it printed "
                      "%r (rc=%s), not exactly %s or %s" % (host, shown, rc, actions.DONE,
                                                            actions.NEEDED))
    if token == actions.DONE:
        journal.append("vpsexec", dict(fields, event="action_already_done",
                                       plan_hash=plan_hash(plan)))
        return True
    return False


def _run_read_retry(host, step, ssh, timeout):
    """A read action's probe, retried inside the verify_retry bounds: up to
    `tries` attempts, `interval` apart, all of it ending by a monotonic
    deadline of VERIFY_RETRY_TOTAL_MAX. Passes on the first rc 0."""
    tries, interval = step["retry"]
    deadline = _verify_clock() + vpsexecpolicy.VERIFY_RETRY_TOTAL_MAX
    attempt, rc, out, err = 0, 1, "", ""
    for attempt in range(1, tries + 1):
        left = deadline - _verify_clock()
        rc, out, err = ssh(host, step["remote"], timeout=max(1, int(min(
            timeout, VERIFY_ATTEMPT_TIMEOUT_MAX, left))))
        if rc == 0 or attempt == tries or _verify_clock() + interval >= deadline:
            break
        _verify_sleep(interval)
    return rc, out, err, attempt


def render_plan(plan, digest):
    hosts = plan["hosts"]
    lines = ["PLAN — %d host%s: %s"
             % (len(hosts), "" if len(hosts) == 1 else "s", ", ".join(hosts))]
    lines.append("  command : %s" % plan["command"])
    lines.append("  tier    : %s%s" % (plan["tier"],
                 " (%s)" % plan["tier_detail"] if plan["tier_detail"] else ""))
    order = ("parallel (read)" if plan["tier"] == "read"
             else "serial, continue on error")
    if plan.get("canary"):
        order += "  |  CANARY: first %d host(s) must pass first" % plan["canary"]
    lines.append("  order   : %s" % order)
    verifies = sorted(set(
        v + (" (up to %d tries, %ds apart)" % tuple(r) if r else "")
        for v, r in ((plan["per_host"][h].get("verify"),
                      plan["per_host"][h].get("verify_retry")) for h in hosts) if v))
    push = plan.get("push")
    if push:
        lines.append("  push    : %s (%d bytes)" % (push["local"], push["size"]))
        lines.append("  sha256  : %s" % push["sha256"])
        lines.append("  to      : %s  (dir 0700, file 0600, root)" % push["path"])
    for v in verifies:
        lines.append("  verify  : %s" % v)
    if push and not verifies:
        lines.append("  verify  : built in — remote sha256sum must equal the "
                     "sha256 above before the rename")
    elif not verifies and plan["tier"] != "read":
        lines.append("  verify  : NONE — rc=0 is the only evidence this worked")
    if plan.get("windows"):
        status = plan.get("blackout_status")
        if status == "ok":
            outside = [h for h in hosts if not plan["windows"].get(h)]
            lines.append("  blackout: %s"
                         % ("all hosts in a maintenance window" if not outside
                            else "NOT in a window: %s" % ", ".join(outside)))
        else:
            lines.append("  blackout: unknown (tool %s) — advisory only" % status)
    if plan["break_glass"]:
        elevated = [h for h in hosts
                    if plan["postures"].get(h) not in ("test", "released")]
        lines.append("  BREAK-GLASS: %d of %d host(s) elevated past posture — %s"
                     % (len(elevated), len(hosts),
                        ", ".join("%s(%s)" % (h, plan["postures"].get(h, "?"))
                                  for h in elevated)))
    for name, canonical in plan.get("aliased", []):
        lines.append("  note    : %s is %s (alias) — running as %s"
                     % (name, canonical, canonical))
    for alias, kept in plan["dropped"]:
        lines.append("  note    : %s is the same machine as %s — dropped" % (alias, kept))
    for host, why in plan.get("excluded", []):
        lines.append("  EXCLUDED: %s — %s (this plan does NOT reach it)" % (host, why))
    if plan.get("incident"):
        lines.append("  INCIDENT: %s — runbook lookup lifted for these hosts; "
                     "approval is a typed GO" % plan["incident"])
    if plan["override_path"]:
        lines.append("  override: %s  sha256=%s"
                     % (plan["override_path"], plan["override_sha256"][:12]))
        for why in (plan["override_why"] or []):
            lines.append("  why     : %s" % why)
    act = plan.get("action")
    if act:
        lines += _render_action_header(plan)
    lines.append("")
    lines.append("WILL RUN:")
    for host in hosts:
        for step in plan["per_host"][host]["steps"]:
            label = "%s / %s" % (host, step["container"]) if step["container"] else host
            if act:
                lines += _render_action_step(label, step)
                continue
            lines.append("  %-28s %s" % (label, step["remote"]))
    total = sum(len(plan["per_host"][h]["steps"]) for h in hosts)
    lines.append("")
    lines.append("  %d command(s) across %d host(s)" % (total, len(hosts)))
    lines.append("plan-hash: %s" % digest)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# approval
# ---------------------------------------------------------------------------

def approval_phrase(plan):
    """What the operator must type. Scales with what is at stake."""
    if plan["break_glass"]:
        return "BREAK-GLASS:%d" % len(plan["hosts"])
    if plan["all_flag"]:
        return "ALL:%s" % ",".join(plan["hosts"])
    if len(plan["hosts"]) > 1:
        return "FLEET:%d" % len(plan["hosts"])
    return plan["hosts"][0]


BREAK_GLASS_APPROVE_REFUSAL = (
    "break-glass plans need your typed BREAK-GLASS phrase or an approval "
    "contract; --approve alone no longer approves break-glass (add "
    "--approval-contract=FILE)")


# `--approval-contract=auto` / `--grant auto`: pick a valid covering grant.
AUTO_GRANT = "auto"


def check_plan_hash(approve_flag, digest):
    if not hmac.compare_digest(str(approve_flag), digest):
        raise Refused(
            "--approve does not match this plan.\n"
            "    supplied : %s\n"
            "    this plan: %s\n"
            "  The plan changed since you were shown it (hosts, command, "
            "container set, or override file). Re-run without --run, read "
            "the new plan, and approve that." % (approve_flag, digest))


def approve(plan, digest, approve_flag, stream=None, prompt=None):
    """Explicit approval, or Refused. Never returns False.

    A plan-hash alone never approves break-glass: any process can pass
    --approve. Break-glass takes the typed phrase, or --approve together with
    an approval contract (handled in dispatch, through vpsexecgrant.use)."""
    if approve_flag:
        if plan["break_glass"]:
            journal.append("vpsexec", {"event": "refused",
                                       "reason": BREAK_GLASS_APPROVE_REFUSAL,
                                       "plan_hash": digest})
            raise Refused(BREAK_GLASS_APPROVE_REFUSAL)
        check_plan_hash(approve_flag, digest)
        return "plan-hash"

    stream = stream if stream is not None else sys.stdin
    if not (hasattr(stream, "isatty") and stream.isatty()):
        raise Refused(
            "no TTY and no --approve — vpsexec will not mutate unattended.\n"
            "  Run without --run to see the plan, then pass --approve=%s" % digest)

    want = approval_phrase(plan)
    # Keystrokes typed before the prompt (a mistyped or mashed key) must not
    # become its answer. Discarded, never matched: the exact check stands.
    vpsexecgrant.flush_input(stream)
    prompt = prompt or (lambda msg: input(msg))
    typed = prompt("Type %s to approve, anything else aborts: " % want)
    if typed.strip() != want:
        raise Refused("approval text did not match %r — aborted" % want)
    return "interactive"


# ---------------------------------------------------------------------------
# push — one local file to a content-addressed staging path
#
# `vpsexec <hosts> push <file> --sha256 <hex>` ships bytes, not commands. It is
# represented inside the gate stack as the canonical command
# `vpscfg-push <sha256> <basename>`, so tier, posture, runbooks, break-glass,
# the plan-hash and the journal all bind the exact content hash. The remote
# path is derived, never chosen: /var/tmp/vpscfg-push/<sha256>/<basename>,
# directory 0700 root, file 0600 root. Anything that consumes it later (an
# `install ... /var/tmp/vpscfg-push/<sha>/diskwatch /usr/local/bin/diskwatch`) names the
# hash in its own command text, so ITS approval binds the bytes too.
#
# Threats:
#   - Protects against: an approval for one file installing another (the hash
#     is in the canonical command and the plan-hash; the local file is hashed
#     and must equal --sha256 before anything else happens); local TOCTOU (the
#     file is read ONCE into memory, hashed, and those same bytes are sent);
#     symlinks, directories, devices, FIFOs and oversize input (lstat + fstat
#     on an O_NOFOLLOW descriptor, 256 MiB cap, read bounded by the cap); an
#     operator-chosen or traversing remote path (strict basename regex, derived
#     path); a partially written or corrupted upload being installed (temp
#     name, remote sha256sum must match, then atomic rename; mismatch removes
#     the temp and fails); a pre-planted staging dir under world-writable
#     /var/tmp (both levels must be real directories owned by uid 0, mode 0700,
#     or the push refuses); shell injection (argv lists locally; the remote
#     string holds only the validated hash and basename, shlex-quoted).
#   - Does NOT protect against: a malicious or compromised host (it can lie
#     about sha256sum; content-addressing assumes root on the target is
#     honest); a malicious binary whose hash the operator approved; staging
#     directories accumulating (no garbage collection yet — see VPSEXEC.md);
#     a transport drop mid-push (the per-host lock is retained, as for any
#     mutation with unknown completion, and a temp file may remain in the 0700
#     staging dir — it is never renamed into place without a matching hash).
# ---------------------------------------------------------------------------

PUSH_VERB = "push"
PUSH_CANONICAL = "vpscfg-push"
PUSH_ROOT = "/var/tmp/vpscfg-push"
PUSH_MAX_BYTES = 256 * 1024 * 1024
PUSH_UPLOAD_TIMEOUT_CAP = 1800

# Per-host timeout when neither --timeout nor a runbook names one: predicted
# from what the command does, never above PREDICTED_TIMEOUT_CAP. A fixed 120 s
# was too long for a read and too short for a rollout; it can cut a break-glass
# rotation off mid-run.
PREDICTED_TIMEOUT_CAP = 300
READ_TIMEOUT = 60
_TIMEOUT_CLASSES = (
    # (seconds, label, pattern) — first match wins; patterns see the whole command.
    (300, "script or package install", re.compile(
        r"(^|[;&|]\s*)(bash|sh|python3?)\s+\S+\.(sh|py)\b|\b(apt|apt-get)\s+(install|upgrade|dist-upgrade|full-upgrade)\b"
        r"|\bpip3?\s+install\b|\bnpm\s+(ci|install)\b|\bdocker\s+(compose\s+)?build\b")),
    (240, "rollout, image pull or compose up", re.compile(
        r"\bkubectl\s+(rollout|set\s+(env|image)|apply|patch|scale|delete)\b"
        r"|\bdocker\s+(pull|run)\b|\bdocker\s+compose\b.*\b(up|pull)\b|\bhelm\s+(upgrade|install)\b")),
    (180, "database or migration", re.compile(r"\b(psql|pg_dump|pg_restore|mysql|migrate)\b")),
    (90, "service restart", re.compile(r"\bsystemctl\s+(restart|reload|start|stop)\b|\bdocker\s+(restart|stop|start)\b")),
)


def predict_timeout(command, tier, base=120):
    """(seconds, why) for one host. Reads get READ_TIMEOUT; mutations get the
    first matching class, else `base`; every prediction is capped."""
    if tier == "read":
        return min(READ_TIMEOUT, PREDICTED_TIMEOUT_CAP), "read"
    for seconds, label, pattern in _TIMEOUT_CLASSES:
        if pattern.search(command or ""):
            return min(seconds, PREDICTED_TIMEOUT_CAP), "predicted: " + label
    return min(base, PREDICTED_TIMEOUT_CAP), "predicted: default mutation"


def choose_timeout(explicit, runbook_timeouts, command, tier, base=120):
    """--timeout wins, then the longest runbook timeout among the hosts, then
    the prediction."""
    if explicit:
        return explicit, "--timeout"
    named = [t for t in runbook_timeouts if t]
    if named:
        return max(named), "runbook"
    return predict_timeout(command, tier, base)
# Always .fullmatch(): with .match, `$` also matches before a trailing "\n",
# and normalize() would then strip that newline back into an authorised name.
PUSH_BASENAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def push_command(sha256, basename):
    """The canonical gate-stack spelling of a push. Runbooks name exactly this."""
    return "%s %s %s" % (PUSH_CANONICAL, sha256, basename)


def load_push_file(path, expected_sha, max_bytes=None):
    """Validate and read the local file ONCE. Returns the push record,
    including `data`, the exact bytes that were hashed and will be sent.

    Every refusal here happens before a host is resolved, probed or dialled.
    """
    max_bytes = PUSH_MAX_BYTES if max_bytes is None else max_bytes
    expected = str(expected_sha or "").lower()
    if not SHA256_RE.fullmatch(expected):
        raise Refused("push needs --sha256 <64 hex characters> — the approval "
                      "binds that hash, so it must be stated, not inferred")
    path = str(path or "")
    name = os.path.basename(path)
    if (name in (".", "..") or name.startswith("-")
            or not PUSH_BASENAME_RE.fullmatch(name)):
        raise Refused("push: basename %r must match [A-Za-z0-9._-]{1,64}, not "
                      "start with '-', and not be . or .." % name)
    try:
        st = os.lstat(path)
    except OSError as e:
        raise Refused("push: cannot stat %r: %s" % (path, e))
    if not stat.S_ISREG(st.st_mode):
        kind = ("a symlink" if stat.S_ISLNK(st.st_mode) else
                "a directory" if stat.S_ISDIR(st.st_mode) else
                "a device" if (stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode))
                else "not a regular file")
        raise Refused("push: %r is %s — only regular files are pushed" % (path, kind))
    if st.st_size > max_bytes:
        raise Refused("push: %r is %d bytes, over the %d-byte cap"
                      % (path, st.st_size, max_bytes))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        raise Refused("push: cannot open %r: %s" % (path, e))
    chunks, total = [], 0
    try:
        fst = os.fstat(fd)
        if (not stat.S_ISREG(fst.st_mode)
                or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino)):
            raise Refused("push: %r changed between lstat and open — refusing" % path)
        while True:
            chunk = os.read(fd, min(1 << 20, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise Refused("push: %r grew past the %d-byte cap while reading"
                              % (path, max_bytes))
    except OSError as e:
        raise Refused("push: cannot read %r: %s" % (path, e))
    finally:
        os.close(fd)
    data = b"".join(chunks)
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise Refused(
            "push: %r has sha256 %s, not the --sha256 given (%s). The approval "
            "binds the hash you state; refusing to ship different bytes."
            % (path, actual, expected))
    directory = "%s/%s" % (PUSH_ROOT, actual)
    return {"local": os.path.abspath(path), "basename": name, "sha256": actual,
            "size": len(data), "dir": directory,
            "path": "%s/%s" % (directory, name),
            "command": push_command(actual, name), "data": data}


def upload_timeout(size, timeout):
    """The per-host timeout, plus ~1s per MiB, capped. Still a hard limit: an
    expiry is a transport failure (lock retained, push journaled)."""
    extra = (size + (1 << 20) - 1) >> 20
    return max(timeout, min(timeout + extra, PUSH_UPLOAD_TIMEOUT_CAP))


def push_remote_commands(push, tmp, root=None, owner_uid=0):
    """The fixed remote steps. Only the validated hash and basename (and a
    CSPRNG temp suffix) vary, and each is shlex-quoted. `root`/`owner_uid`
    exist so tests can run the real script locally; production uses the
    defaults (PUSH_ROOT, uid 0)."""
    q = shlex.quote
    root, d, final, t = (q(root or PUSH_ROOT), q(push["dir"]), q(push["path"]),
                         q(tmp))
    owner = "%d:700" % int(owner_uid)
    return {
        "prepare": ("umask 077; mkdir -p -m 0700 %s %s && for d in %s %s; do "
                    "test -d \"$d\" && test ! -L \"$d\" && "
                    "test \"$(stat -c %%u:%%a \"$d\")\" = %s || "
                    "{ echo \"unsafe staging dir: $d\" >&2; exit 1; }; done"
                    % (root, d, root, d, owner)),
        "present": "test -f %s && test ! -L %s && sha256sum %s" % (final, final, final),
        "upload": "umask 077; set -C; cat > %s" % t,
        "check": "sha256sum %s" % t,
        "commit": "chmod 0600 %s && mv -fT %s %s" % (t, t, final),
        "discard": "rm -f %s" % t,
    }


def _sha_matches(output, expected):
    words = (output or "").split()
    got = words[0].lower() if words else ""
    return bool(SHA256_RE.fullmatch(got)) and hmac.compare_digest(got, expected)


def _push_steps(host, push, data, cmds, ssh, timeout):
    """-> (outcome, detail). Temp, verify, rename; a mismatch never renames."""
    def first(out, err):
        lines = secretmask.mask((err or out or "").strip()).splitlines()
        return lines[0][:120] if lines else ""

    rc, out, err = ssh(host, cmds["prepare"], timeout=timeout)
    if rc != 0:
        return "staging_refused", "staging dir refused: %s" % first(out, err)
    rc, out, _ = ssh(host, cmds["present"], timeout=timeout)
    if rc == 0 and _sha_matches(out, push["sha256"]):
        return "already_present", "already present: %s" % push["path"]
    rc, out, err = ssh(host, cmds["upload"], data=data,
                       timeout=upload_timeout(push["size"], timeout))
    if rc != 0:
        drc = ssh(host, cmds["discard"], timeout=timeout)[0]
        return "upload_failed", ("upload failed: %s (temp removal rc=%s)"
                                 % (first(out, err), drc))
    rc, out, err = ssh(host, cmds["check"], timeout=timeout)
    if rc != 0 or not _sha_matches(out, push["sha256"]):
        drc = ssh(host, cmds["discard"], timeout=timeout)[0]
        return "hash_mismatch", ("remote sha256 does not match %s — temp removed "
                                 "(rc=%s), nothing renamed into place"
                                 % (push["sha256"], drc))
    rc, out, err = ssh(host, cmds["commit"], timeout=timeout)
    if rc != 0:
        drc = ssh(host, cmds["discard"], timeout=timeout)[0]
        return "rename_failed", ("rename failed: %s (temp removal rc=%s)"
                                 % (first(out, err), drc))
    return "pushed", "pushed %s (%d bytes)" % (push["path"], push["size"])


def _push_one_host(host, plan, deny, ssh, timeout, result):
    """One host's push. Journals the outcome whatever it is, including a
    transport failure (which then propagates, so the lock is retained)."""
    push, data = plan["push"], plan["push_data"]
    tmp = "%s/.%s.part-%s" % (push["dir"], push["basename"], secrets.token_hex(8))
    outcome, detail = "transport_error", "transport failed mid-push"
    try:
        cmds = push_remote_commands(push, tmp)
        for text in cmds.values():
            try:
                deny_scan(text, deny)
            except Refused as r:
                outcome, detail = "refused", str(r)
                raise
        outcome, detail = _push_steps(host, push, data, cmds, ssh, timeout)
    finally:
        journal.append("vpsexec", {
            "event": "push", "host": host, "sha256": push["sha256"],
            "basename": push["basename"], "size": push["size"],
            "path": push["path"], "outcome": outcome, "detail": detail})
    ok = outcome in ("pushed", "already_present")
    result["outputs"].append({"container": None, "rc": 0 if ok else 1,
                              "stdout": detail, "stderr": ""})
    if not ok:
        result["rc"] = 1
        result["error"] = detail


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------

def _default_ssh(host, remote_cmd, connect_timeout=8, timeout=120, data=None):
    """`data` (bytes) is fed to the remote command's stdin — push only. The
    argv is a list; the remote string is built by this module from validated
    values, never from operator text beyond the (already gated) command."""
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % connect_timeout,
            host, remote_cmd]
    if data is None:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out, err = r.stdout, r.stderr
    else:
        r = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
        out = r.stdout.decode("utf-8", "replace")
        err = r.stderr.decode("utf-8", "replace")
    if r.returncode == 255:
        raise OSError('SSH connection lost; remote completion is unknown')
    return r.returncode, out, err


# The real transport runs mutation steps detached (vpscfg/detach.py), so a
# dropped session re-attaches instead of costing the deploy. An injected
# transport opts in the same way; one that does not keeps the attached path.
_default_ssh.detached = True


def _decode(data):
    return data.decode("utf-8", "replace") if isinstance(data, bytes) else (data or "")


def _live_printer(host):
    """Masked live log lines for a human watching a terminal. The WHOLE text so
    far is re-masked on every update (the masker reads context: a Secret's
    `data:` block, an unterminated PEM), and only complete lines are shown.
    Captured runs (vpsrun, tests) see the output once, in the final render."""
    if not sys.stderr.isatty():
        return None
    shown = {"out": 0, "err": 0}

    def show(out, err):
        for name, data in (("out", out), ("err", err)):
            text = _decode(data[:256 * 1024])
            text = text[:text.rfind("\n") + 1]
            lines = secretmask.mask(text).splitlines()
            for line in lines[shown[name]:]:
                print("  %s %s| %s" % (host, "!" if name == "err" else " ", line),
                      file=sys.stderr)
            shown[name] = max(shown[name], len(lines))
    return show


def _run_step(host, step, idx, ssh, timeout, is_read, lock_token, unmanaged_ok=False):
    """(rc, stdout, stderr) for one step. A mutation step on a detach-capable
    transport is launched detached under the lock's operation id — on a host
    without systemd only if the governor's allow_unmanaged_steps names it."""
    if is_read or not lock_token or not getattr(ssh, "detached", False):
        return ssh(host, step["remote"], timeout=timeout)
    rc, out, err = detach.run(
        host, lock_token, idx, step["remote"], lock_token, ssh, timeout,
        progress=lambda msg: print("  [%s] %s" % (host, msg), file=sys.stderr),
        on_output=_live_printer(host), unmanaged_ok=unmanaged_ok)
    return rc, _decode(out), _decode(err)


def _step_detail(out, err):
    """The legacy summary field: stderr wins, 500 cap. Both full streams are
    journaled beside it (`stdout`, `stderr`), on the uncertain path too."""
    return (err or out or "")[:500]


# Full step output kept in the journal (stdout and stderr, each capped), so a
# human who ran a break-glass step in their own terminal can say "done" and
# `vpsexec last` shows the result — nobody pastes output back by hand. The
# journal is gitignored and local; `log --export` still strips these fields.
STEP_OUTPUT_CAP = 16384

# Between verify_retry attempts. A module attribute so tests never really sleep.
_verify_sleep = time.sleep
_verify_clock = time.monotonic
# A retried verify is bounded as a whole, not just its sleeps: each attempt
# times out after at most this long, and every attempt and sleep together end
# by a monotonic deadline of vpsexecpolicy.VERIFY_RETRY_TOTAL_MAX seconds.
VERIFY_ATTEMPT_TIMEOUT_MAX = 60


def _run_one_host(host, plan, guard, reason, ssh, timeout, is_read):
    """Everything that happens on ONE machine. Never raises: a failure here is
    that host's result, so a locked or unreachable box cannot abort the fleet.

    The post-condition runs last, on the host, and its failure fails the host —
    `systemctl restart nginx` returning 0 is not evidence that nginx serves.
    """
    result = {"host": host, "rc": 0, "error": None, "outputs": [],
              "verify_rc": None, "verify_detail": ""}
    locked = False
    lock_token = None
    uncertain = False
    still_running = False
    unmanaged_ok = _allows_unmanaged(guard, host)
    try:
        if not is_read:
            lock_token = lock.acquire(host, _operator(), reason,
                                      runner=lambda h, c: ssh(h, c))
            locked = True
        if plan.get("push"):
            _push_one_host(host, plan, guard.deny_patterns(), ssh, timeout, result)
        steps = [] if plan.get("push") else plan["per_host"][host]["steps"]
        act_fields = _action_fields(plan, per_host=False)
        if act_fields:
            act_fields["body_sha256"] = plan["action"]["per_host"][host]["body_sha256"]
        for idx, step in enumerate(steps, 1):
            deny_scan(step["remote"], guard.deny_patterns())
            # A typed action's done-check: after THIS operation took the lock,
            # before the body. DONE skips the body and the verify; anything
            # but NEEDED fails the host closed (Refused, nothing ran).
            if (step.get("check") is not None and not is_read
                    and _action_already_done(host, plan, step, ssh, timeout,
                                             guard.deny_patterns(), lock_token)):
                result["already_done"] = True
                result["outputs"].append({
                    "container": None, "rc": 0, "stderr": "", "compare_key": "",
                    "stdout": "[done] already done: the check printed %s — body not run"
                              % actions.DONE})
                break
            try:
                if step.get("retry") and is_read:
                    rc, out, err, attempts = _run_read_retry(host, step, ssh, timeout)
                    result["attempts"] = attempts
                else:
                    rc, out, err = _run_step(host, step, idx, ssh, timeout, is_read,
                                             lock_token, unmanaged_ok=unmanaged_ok)
            except detach.DetachUnknown as e:
                still_running = isinstance(e, detach.DetachStillRunning)
                # Whatever the step printed before contact was lost is evidence.
                pout, perr = secretmask.mask(_decode(e.out)), secretmask.mask(_decode(e.err))
                result["outputs"].append({"container": step["container"], "rc": None,
                                          "stdout": pout, "stderr": perr,
                                          "compare_key": pout})
                journal.append("vpsexec", dict({
                    "event": "step", "host": host, "target": step["container"] or host,
                    "remote": step["remote"], "rc": None, "uncertain": True,
                    "operation_id": lock_token, "detail": _step_detail(pout, perr),
                    "stdout": pout[:STEP_OUTPUT_CAP], "stderr": perr[:STEP_OUTPUT_CAP]},
                    **act_fields))
                raise
            # Masked HERE, before the output reaches the result, the journal,
            # --compare or the terminal: one choke point, nothing to forget.
            tagged = secretmask.mask(out, tags=True)
            out, err = secretmask.untag(tagged), secretmask.mask(err)
            # compare_key keeps per-run HMAC tags so --compare still splits
            # hosts whose secrets differ; it is never printed or journaled.
            result["outputs"].append({"container": step["container"], "rc": rc,
                                      "stdout": out or "", "stderr": err or "",
                                      "compare_key": tagged or ""})
            if rc != 0 and result["rc"] == 0:
                result["rc"] = rc
                first = (err or out or "").strip().splitlines()[:1]
                result["error"] = first[0][:120] if first else ""
            if not is_read:
                journal.append("vpsexec", dict({
                    "event": "step", "host": host, "target": step["container"] or host,
                    "remote": step["remote"], "rc": rc, "operation_id": lock_token,
                    "detail": _step_detail(out, err),
                    "stdout": (out or "")[:STEP_OUTPUT_CAP],
                    "stderr": (err or "")[:STEP_OUTPUT_CAP]}, **act_fields))

        verify = plan["per_host"][host].get("verify")
        probe = plan["per_host"][host].get("verify_probe")
        if verify and result["rc"] == 0 and not result.get("already_done"):
            tries, interval = plan["per_host"][host].get("verify_retry") or (1, 0)
            deadline = (_verify_clock() + vpsexecpolicy.VERIFY_RETRY_TOTAL_MAX
                        if tries > 1 else None)
            spent = False
            for attempt in range(1, tries + 1):
                attempt_timeout = timeout
                if deadline is not None:
                    left = deadline - _verify_clock()
                    attempt_timeout = max(1, int(min(timeout, VERIFY_ATTEMPT_TIMEOUT_MAX,
                                                     left)))
                if probe is not None:
                    # A typed action's verify: shell text or a SqlCheck. A
                    # SqlCheck passes only on the exact VPSCFG-DONE row.
                    try:
                        vrc, vout, verr = _run_probe(host, probe, ssh, attempt_timeout,
                                                     guard.deny_patterns())
                    except (OSError, subprocess.TimeoutExpired):
                        if isinstance(probe, actions.TokenCheck):
                            raise OSError("token-only verify: transport lost") from None
                        raise
                    if isinstance(probe, (actions.SqlCheck, actions.TokenCheck)):
                        vtok = _probe_token(probe, vrc, vout)
                        vrc = 0 if vtok == actions.DONE else (vrc or 1)
                    vout, verr = _decode(vout), _decode(verr)
                    if isinstance(probe, actions.TokenCheck):
                        # Withheld like the done-check: the token or a fixed
                        # error class, never the output.
                        vout, verr = (vtok or ""), ("" if vtok else
                                                    "token-only verify: output withheld")
                else:
                    vrc, vout, verr = ssh(host, verify, timeout=attempt_timeout)
                vout, verr = secretmask.mask(vout), secretmask.mask(verr)
                result["verify_rc"] = vrc
                result["verify_detail"] = (verr or vout or "").strip()[:200]
                if not is_read:
                    record = {
                        "event": "verify", "host": host, "remote": verify, "rc": vrc,
                        "detail": result["verify_detail"],
                        "stdout": (vout or "")[:STEP_OUTPUT_CAP],
                        "stderr": (verr or "")[:STEP_OUTPUT_CAP]}
                    if tries > 1:
                        record.update(attempt=attempt, tries=tries)
                    journal.append("vpsexec", record)
                if vrc == 0 or attempt == tries:
                    break
                if deadline is not None and _verify_clock() + interval >= deadline:
                    spent = True  # no room for another sleep and attempt
                    break
                _verify_sleep(interval)
            if tries > 1:
                result["verify_attempts"] = attempt
            if vrc != 0:
                result["rc"] = vrc or 1
                result["error"] = ("verify FAILED%s: %s"
                                   % (" (retry budget of %ds spent after %d of %d tries)"
                                      % (vpsexecpolicy.VERIFY_RETRY_TOTAL_MAX, attempt, tries)
                                      if spent else "",
                                      result["verify_detail"][:100] or verify))
    except Refused as r:
        result["rc"] = result["rc"] or 1
        result["error"] = str(r).splitlines()[0][:160]
    except (subprocess.TimeoutExpired, OSError) as e:
        uncertain = True
        result["rc"] = result["rc"] or 1
        # str(TimeoutExpired) carries the argv, i.e. the operator's command.
        result["error"] = secretmask.mask("transport: %s" % e)[:160]
    except BaseException:
        uncertain = True
        raise
    finally:
        if locked:
            if uncertain:
                result["lock_retained"] = lock_token  # mutation_complete names it
                result['error'] = ((result['error'] or '') + ' [BLOCKED: lock retained; reconcile '
                                   'operation %s — next: vpsexec reconcile %s%s]'
                                   % (lock_token, host, " --stop" if still_running else ""))
                print(result['error'], file=sys.stderr)
            else:
                try:
                    # The op dir (step logs, exit codes) goes with the lock,
                    # in the same remote command (only a detached step made one).
                    released = lock.release(
                        host, runner=lambda h, c: ssh(h, c), token=lock_token,
                        op_dir=(detach.op_dir(lock_token)
                                if getattr(ssh, "detached", False) else None))
                except (OSError, subprocess.TimeoutExpired):
                    released = False
                if not released:
                    result['rc'] = result['rc'] or 1
                    result['error'] = ((result['error'] or '') + ' [BLOCKED: lock not released]').strip()
                else:
                    # Written ONLY now — every step, the verify and the lock
                    # release are behind it — so vpsrun --resume may treat this
                    # host as finished. A per-step record is not enough: a door
                    # that died between steps or during the verify wrote those.
                    # It names its attempt (run-scoped reason + plan-hash), so
                    # resume can never take another operation's host_done.
                    journal.append("vpsexec", dict({
                        "event": "host_done", "host": host, "operation_id": lock_token,
                        "rc": result["rc"], "verify_rc": result["verify_rc"],
                        "reason": reason, "plan_hash": plan_hash(plan)},
                        **({"already_done": bool(result.get("already_done"))}
                           if plan.get("action") else {})))
    return result


def _allows_unmanaged(guard, host):
    """The governor's explicit acceptance of the escape risk on a host without
    systemd: `"allow_unmanaged_steps": ["<canonical host>", ...]`. An alias
    name in the list counts for nothing (it would launder the canonical
    host's risk decision); the canonical name of `host` must be listed."""
    policy = getattr(guard, "policy", None) or {}
    listed = policy.get("allow_unmanaged_steps") or []
    if not isinstance(listed, list):
        return False
    cfg = (policy.get("hosts") or {}).get(host) or {}
    canonical = cfg.get("alias_of") or host if isinstance(cfg, dict) else host
    return canonical in listed and not ((policy.get("hosts") or {}).get(canonical) or {}
                                        ).get("alias_of")


def _host_stdout(result):
    """All of a host's stdout, joined — the unit --compare groups on."""
    return "\n".join((o.get("compare_key", o["stdout"]) or "").rstrip("\n")
                     for o in result["outputs"]).strip()


def _render_output(result):
    lines = ["───── %s ─────" % result["host"]]
    for out in result["outputs"]:
        if out["container"]:
            lines.append("  [%s]" % out["container"])
        body = (out["stdout"] or "").rstrip("\n")
        if body:
            lines.append(body)
        err = (out["stderr"] or "").rstrip("\n")
        if err:
            lines.append(err)
    if result["error"] and not result["outputs"]:
        lines.append("  %s" % result["error"])
    return "\n".join(lines)


def _render_compare(results):
    """Group hosts by identical output. Reading five machines is rarely about
    five outputs — it is about which one is different."""
    groups = {}
    for r in results:
        groups.setdefault(_host_stdout(r), []).append(r["host"])
    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[1][0]))
    biggest = len(ordered[0][1]) if ordered else 0
    lines = ["COMPARE — %d host(s), %d distinct result(s)"
             % (len(results), len(ordered))]
    for body, hosts in ordered:
        divergent = len(hosts) < biggest
        lines.append("")
        lines.append("  %d host%s  %s%s"
                     % (len(hosts), "" if len(hosts) == 1 else "s",
                        ", ".join(hosts), "   ← divergent" if divergent else ""))
        # body is the grouping key and may carry <masked:tag>; the tag did
        # its job (splitting the groups) and is not shown.
        for line in (secretmask.untag(body).splitlines() or ["(no output)"]):
            lines.append("      %s" % line)
    lines.append("")
    if len(ordered) == 1:
        lines.append("  all hosts agree")
    elif biggest == 1:
        # Every host differs, or an even split: there is no majority, so
        # nothing is "the odd one out" and saying otherwise would be a guess.
        lines.append("  no majority — every host differs")
    return "\n".join(lines)


def _render_summary(results):
    failed = [r for r in results if r["rc"] != 0]
    lines = ["SUMMARY — %d host(s)" % len(results)]
    for r in results:
        note = r["error"] or ""
        if not note and r.get("already_done"):
            note = "already done (check), body not run"
        if not note and r["verify_rc"] == 0:
            note = "verify ok"
        lines.append("  [%-4s] %-24s rc=%-3s %s"
                     % (_status_label(r), r["host"], r["rc"], note))
    lines.append("  %d ok, %d failed of %d"
                 % (len(results) - len(failed), len(failed), len(results)))
    return "\n".join(lines)


def _status_label(r):
    if r["rc"] != 0:
        return "FAIL"
    return "done" if r.get("already_done") else "ok"


def _run_serial(hosts, plan, guard, reason, ssh, timeout, is_read, announce=True):
    results = []
    for host in hosts:
        r = _run_one_host(host, plan, guard, reason, ssh, timeout, is_read)
        results.append(r)
        if announce:
            note = r["error"] or ("verify ok" if r["verify_rc"] == 0 else "")
            print("  [%s] %s rc=%s%s" % (_status_label(r), host,
                                         r["rc"], "  " + note if note else ""))
    return results


def _run_parallel(hosts, plan, guard, reason, ssh, timeout, is_read, max_parallel):
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(max_parallel, len(hosts))) as pool:
        futures = dict((pool.submit(_run_one_host, h, plan, guard, reason, ssh,
                                    timeout, is_read), h) for h in hosts)
        done = dict((futures[f], f.result())
                    for f in concurrent.futures.as_completed(futures))
    return [done[h] for h in hosts]


def execute(plan, guard, reason, approval, ssh=None, timeout=120, max_parallel=5,
            stream=None, prompt=None):
    """Run the plan across the fleet. Every gate already ran in dispatch().

    Reads fan out in parallel — when you are reading five machines' logs during
    an outage, latency is the product. Mutations run serially in the order you
    named the hosts and continue past a failure, then report per host.

    With --canary the first N hosts run alone and must PASS, post-condition
    included, before the rest are touched. Continue-on-error finishes the job;
    the canary is what stops a bad command from reaching all eight machines.
    """
    ssh = ssh or _default_ssh
    hosts = plan["hosts"]
    is_read = plan["tier"] == "read"
    canary = plan.get("canary") or 0

    if not is_read:
        journal.append("vpsexec", {
            "event": "mutation_attempt", "hosts": hosts,
            "command": plan["command"], "placement": plan["placement"],
            "targets": dict((h, plan["per_host"][h]["targets"]) for h in hosts),
            "verify": dict((h, plan["per_host"][h].get("verify")) for h in hosts),
            "tier": plan["tier"], "break_glass": plan["break_glass"],
            "canary": canary, "postures": plan["postures"],
            "override": plan["override_path"],
            "override_sha256": plan["override_sha256"],
            "plan_hash": plan_hash(plan), "approval": approval, "reason": reason,
            "push": plan.get("push"), **_incident_fields(plan), **_action_fields(plan)})

    halted = []
    if is_read and len(hosts) > 1:
        results = _run_parallel(hosts, plan, guard, reason, ssh, timeout,
                                is_read, max_parallel)
    elif canary and len(hosts) > 1:
        head, tail = hosts[:canary], hosts[canary:]
        print("  CANARY — %d of %d host(s) first: %s"
              % (len(head), len(hosts), ", ".join(head)))
        results = _run_serial(head, plan, guard, reason, ssh, timeout, is_read)
        if any(r["rc"] != 0 for r in results):
            halted = tail
            print("")
            print("  CANARY FAILED — halting. %d host(s) NOT touched: %s"
                  % (len(tail), ", ".join(tail)))
            journal.append("vpsexec", {
                "event": "canary_failed", "hosts": head, "not_run": tail,
                "command": plan["command"], "reason": reason})
        else:
            print("  CANARY PASSED")
            _confirm_continue(tail, stream, prompt)
            results += _run_serial(tail, plan, guard, reason, ssh, timeout, is_read)
    else:
        results = _run_serial(hosts, plan, guard, reason, ssh, timeout, is_read)

    if plan.get("compare"):
        print("")
        print(_render_compare(results))
    else:
        for r in results:
            body = _render_output(r)
            if body.strip():
                print("")
                print(body)

    print("")
    print(_render_summary(results))
    if halted:
        print("  %d host(s) not run: %s" % (len(halted), ", ".join(halted)))

    failed = [r for r in results if r["rc"] != 0]
    if not is_read:
        # Hosts whose outcome is unknown and whose lock stays held, by
        # operation id: vpsrun --resume refuses a step listed here until a
        # `reconciled` record names that operation. Absent when there are none.
        retained = dict((r["host"], r["lock_retained"]) for r in results
                        if r.get("lock_retained"))
        journal.append("vpsexec", {
            "event": "mutation_complete", "hosts": hosts,
            "command": plan["command"],
            "results": dict((r["host"], r["rc"]) for r in results),
            "failed": [r["host"] for r in failed], "not_run": halted,
            **({"lock_retained": retained} if retained else {}),
            **({"action_body_sha256": _action_fields(plan)["body_sha256"],
                "already_done": [r["host"] for r in results if r.get("already_done")]}
               if plan.get("action") else {}),
            **_incident_fields(plan)})
    if plan.get("incident_record"):
        print(vpsexecincident.banner(plan["incident_record"]))
    return 1 if (failed or halted) else 0


def _incident_fields(plan):
    """Journal keys tying a mutation to its incident, so `incident close` can
    report it. Absent outside an incident: those records are unchanged."""
    if not plan.get("incident"):
        return {}
    return {"incident": plan["incident"], "plan_hash": plan_hash(plan)}


def _confirm_continue(remaining, stream, prompt):
    """After a passing canary. With a TTY a human says go; unattended, the
    plan-hash already authorised the whole fleet and the canary was the gate."""
    if not remaining:
        return
    stream = stream if stream is not None else sys.stdin
    if not (hasattr(stream, "isatty") and stream.isatty()):
        print("  (no TTY — canary passed, continuing to %d more host(s))"
              % len(remaining))
        return
    vpsexecgrant.flush_input(stream)
    prompt = prompt or (lambda msg: input(msg))
    typed = prompt("  Canary passed. Type CONTINUE for the remaining %d host(s): "
                   % len(remaining))
    if typed.strip() != "CONTINUE":
        raise Refused("canary passed but continuation was not confirmed — "
                      "%d host(s) left untouched: %s"
                      % (len(remaining), ", ".join(remaining)))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# Reserved: these can never be host names. Validated against the governor so a
# host called "log" fails loudly instead of shadowing a verb.
RESERVED_VERBS = frozenset(["hosts", "groups", "runbooks", "checks", "check",
                            "locks", "log", "last", "help", "grant", "reconcile",
                            "incident", "runbook"])
REPEAT_WINDOW_SECONDS = 300

USAGE = """vpsexec — run a command across a fleet, or inside its containers.

  vpsexec <hosts> '<command>' [flags]       # the command must be ONE argument

Hosts
  web1                 one host (aliases resolve: web1 IS web1.example.internal)
  web1,web2,web3       an explicit list, run in the order named
  @web                 a group from policies/*.yaml
  @all                 every governed machine, once
  @dns,web1            groups and hosts mix freely

Placement (default: the host itself)
  --in NAME            run inside this live container (repeatable)
  --in-match GLOB      run inside every live container matching GLOB
  --in-all             run inside every live container on each host

Execution
  --run                actually execute. Without it you get the plan, and stop.
  --reason "why"       required for anything that is not a read. Journaled forever.
  --verify 'CMD'       post-condition, run per host after the command. Must be a
                       read. Its failure fails that host.
  --canary [N]         run the first N hosts (default 1) alone; they must PASS,
                       post-condition included, before the rest are touched.
  --compare            reads only: group hosts by identical output, flag the
                       odd one out.
  --override=FILE      an ad-hoc YAML authorisation file
  --break-glass        reach frozen/lockdown hosts, backed by a committed runbook
  --incident=ID        an open incident (`vpsexec incident open`) stands in for
                       the committed runbook on the hosts it lists. Typed
                       GO:<host> (GO:<plan[:6]> for several) at the TTY; never
                       --approve, --approval-contract or --grant.
  --require-blackout   refuse hosts not inside an active maintenance window
  --approve=HASH       non-interactive approval of one exact plan-hash
  --approval-contract=FILE | --grant FILE
                       a grant from `vpsexec grant new` replaces the typed
                       BREAK-GLASS phrase for a step it lists (or, when no host
                       needs elevation, that step's ordinary phrase). TTY still
                       required. Invalid for this plan => refused, no prompt.
                       Omitted: valid grants are LISTED, never used; the typed
                       phrase follows.
  --approval-contract=auto | --grant auto
                       auto-pick a VALID covering grant (short before reusable,
                       soonest-expiring first; never one minted --for-release);
                       refuses if none covers it.
  --no-grant           never list or use a grant: the typed phrase only.
  --timeout N          per-host timeout in seconds. Default: a runbook's timeout:,
                       else predicted from the command (read 60s, rollout/pull
                       240s, script/install 300s), capped at 300s

Push a file (a mutation: --run, --reason, posture, approval all apply)
  vpsexec <hosts> push <local-file> --sha256 <hex> [--run --reason "why"]
                       copies ONE regular file to the content-addressed path
                       /var/tmp/vpscfg-push/<sha256>/<basename>. The file must
                       hash to --sha256; the gates see `vpscfg-push <sha> <name>`.

Typed actions (docs/ACTIONS.md)
  vpsexec <hosts> --action NAME --with '{"param": value, ...}' [--run --reason "why"]
                       a closed vocabulary of declarative steps. The door builds
                       the body from reviewed code, prints it in full with its
                       done-check, and the plan-hash binds those bytes. A
                       mutation action runs only where a runbook (`action:` +
                       `with:`) or a non-break-glass override names it. The
                       gates see `vpscfg-action <name>@<v> '<json>'`; typing
                       that string yourself is refused.

Named read plays (policies/checks.yaml)
  vpsexec check                 list the checks available
  vpsexec check disk [hosts]    run one; its default host set is in the policy
  vpsexec check container-logs edge1 name=shop-caddy since=2h
                                typed params: each value is regex-checked, then
                                the whole command must STILL classify as a read
  A check's command must be a read, so a check can never be a way to mutate.

Runbook checks (see `vpsexec runbook --help`)
  vpsexec runbook lint <policy.yaml>       static: shape, expiry, timeouts,
                                           push artifacts, STOP steps, plays
  vpsexec runbook preflight <policy.yaml>  read tier only: the policy's
                                           assumes: block against the hosts

Approval contracts (see `vpsexec grant --help`)
  vpsexec grant new <runbook> --ttl 1h [--steps 1-20,23] [--hosts h] [--run]
  vpsexec grant new <policy> --kind reusable --ttl 12h [--max-uses N]
                    [--for-release NAME] [--run]   (committed, clean files only)
  vpsexec grant list | show <file> | revoke <session_id>

Incident override (see `vpsexec incident --help`) — customer outage only
  vpsexec incident open --hosts h1,h2 --ttl <15m|30m|1h|2h|4h> --reason "why"
  vpsexec incident status | close <ic_id>

Introspection (read-only, no host needed)
  vpsexec hosts        governed hosts: posture, alias, reachability, window
  vpsexec groups       host groups from policies/*.yaml
  vpsexec runbooks     authorisations in force, with expiry
  vpsexec locks <hosts>  who holds the per-host mutation lock

Release valve (a human, in a terminal)
  vpsexec reconcile <host>
                 a lock RETAINED after a dropped session or a timeout: shows the
                 owner, the step's exit code and log tail, whether it still runs,
                 and the runbook's verify; then, unless it still runs (any
                 process of the step's group or unit), its controller is alive
                 here, or it has no op dir and is younger than twice the
                 longest step (7200s), asks for RECONCILE:<host>:<op8> and
                 releases THAT operation's lock (and its op dir) only.
  vpsexec reconcile <host> --stop
                 TERM a STILL RUNNING operation's step(s) and their whole
                 process group: STOP:<host>:<op8>, journaled; releases
                 nothing — reconcile afterwards.
  vpsexec last [HOST] [-n N]
                 the last N mutation runs IN FULL: command, approval, every
                 step's output, verify, result. Run it yourself, then say "done".
  vpsexec log [--reason X] [--host X] [--event X] [--since 2h] [-n N]
                 --export   JSON digest, command output redacted, safe to archive
                 --raw      with --export: keep output. Not what you commit.

Reads fan out in parallel. Mutations run serially, in the order you named the
hosts, and continue past a failure — then report per host and exit non-zero.

Tiers
  read       on the read-only allowlist — runs anywhere, no --run, no approval
  mutating   anything else — needs --run, --reason, posture, approval
  risky      needs, additionally, a runbook or override naming it exactly
  (floor)    DENY_ALWAYS_FLOOR — refused by every door, always, no exceptions

Unknown commands are mutations, not reads. That is the direction it fails.
"""


def _value(argv, i, name):
    if i + 1 >= len(argv):
        raise Refused("%s needs a value" % name)
    return argv[i + 1]


def parse_args(argv, push=False):
    """push=True parses `<hosts> push <local-file> --sha256 <hex> [flags]`;
    --sha256 is an unknown flag everywhere else."""
    opts = {"host": None, "command": None, "in": [], "match": None, "all": False,
            "override": None, "run": False, "reason": None, "approve": None,
            "timeout": None, "break_glass": False, "verify": None, "canary": 0,
            "compare": False, "require_blackout": False, "sha256": None,
            "push_file": None, "approval_contract": None, "incident": None,
            "grant_flag": "--approval-contract", "no_grant": False,
            "action": None, "with": None}
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--run":
            opts["run"] = True
        elif a == "--in-all":
            opts["all"] = True
        elif a == "--break-glass":
            opts["break_glass"] = True
        elif a == "--compare":
            opts["compare"] = True
        elif a == "--require-blackout":
            opts["require_blackout"] = True
        elif a == "--canary":
            opts["canary"] = 1
        elif a.startswith("--canary="):
            opts["canary"] = a.split("=", 1)[1]
        elif a.startswith("--verify="):
            opts["verify"] = a.split("=", 1)[1]
        elif a == "--verify":
            opts["verify"] = _value(argv, i, "--verify"); i += 1
        elif a.startswith("--in-match="):
            opts["match"] = a.split("=", 1)[1]
        elif a == "--in-match":
            opts["match"] = _value(argv, i, "--in-match"); i += 1
        elif a.startswith("--in="):
            opts["in"].append(a.split("=", 1)[1])
        elif a == "--in":
            opts["in"].append(_value(argv, i, "--in")); i += 1
        elif a.startswith("--override="):
            opts["override"] = a.split("=", 1)[1]
        elif a == "--override":
            opts["override"] = _value(argv, i, "--override"); i += 1
        elif a.startswith("--reason="):
            opts["reason"] = a.split("=", 1)[1]
        elif a == "--reason":
            opts["reason"] = _value(argv, i, "--reason"); i += 1
        elif a.startswith("--approve="):
            opts["approve"] = a.split("=", 1)[1]
        elif a == "--approve":
            opts["approve"] = _value(argv, i, "--approve"); i += 1
        elif a.startswith("--approval-contract="):
            opts["approval_contract"] = a.split("=", 1)[1]
            opts["grant_flag"] = "--approval-contract"
        elif a == "--approval-contract":
            opts["approval_contract"] = _value(argv, i, "--approval-contract"); i += 1
            opts["grant_flag"] = "--approval-contract"
        elif a.startswith("--grant="):  # `--grant auto` / `--grant FILE`: same flag
            opts["approval_contract"] = a.split("=", 1)[1]
            opts["grant_flag"] = "--grant"
        elif a == "--grant":
            opts["approval_contract"] = _value(argv, i, "--grant"); i += 1
            opts["grant_flag"] = "--grant"
        elif a == "--no-grant":
            opts["no_grant"] = True
        elif a.startswith("--incident="):
            opts["incident"] = a.split("=", 1)[1]
        elif a == "--incident":
            opts["incident"] = _value(argv, i, "--incident"); i += 1
        elif a.startswith("--timeout="):
            opts["timeout"] = a.split("=", 1)[1]
        elif a == "--timeout":
            opts["timeout"] = _value(argv, i, "--timeout"); i += 1
        elif not push and a.startswith("--action="):
            opts["action"] = a.split("=", 1)[1]
        elif not push and a == "--action":
            opts["action"] = _value(argv, i, "--action"); i += 1
        elif not push and a.startswith("--with="):
            opts["with"] = a.split("=", 1)[1]
        elif not push and a == "--with":
            opts["with"] = _value(argv, i, "--with"); i += 1
        elif push and a.startswith("--sha256="):
            opts["sha256"] = a.split("=", 1)[1]
        elif push and a == "--sha256":
            opts["sha256"] = _value(argv, i, "--sha256"); i += 1
        elif a.startswith("-"):
            raise Refused("unknown flag %r" % a)
        else:
            positional.append(a)
        i += 1

    if opts["approval_contract"] is not None and not opts["approval_contract"].strip():
        raise Refused("--approval-contract needs a file path (or auto)")
    if opts["approval_contract"] is not None and opts["approval_contract"].strip() == "auto":
        opts["approval_contract"] = AUTO_GRANT  # a file named auto is ./auto
    if opts.get("no_grant") and opts["approval_contract"] is not None:
        raise Refused("--no-grant and %s contradict each other — pass one"
                      % opts["grant_flag"])
    if opts["incident"] is not None:
        if not opts["incident"].strip():
            raise Refused("--incident needs an incident id (ic_...)")
        if opts["approve"] or opts["approval_contract"] is not None:
            raise Refused("--incident is approved by a typed GO at your terminal "
                          "only — not with --approve, --approval-contract or --grant")
    if push:
        if len(positional) != 3 or positional[1] != PUSH_VERB:
            raise Refused("usage: vpsexec <hosts> push <local-file> --sha256 <hex> "
                          "[--run --reason \"why\"]")
        opts["host"], opts["push_file"] = positional[0], positional[2]
    elif opts["action"] is not None:
        # `<hosts> --action NAME --with JSON`: the door builds the command.
        if len(positional) != 1:
            raise Refused("usage: vpsexec <hosts> --action NAME --with JSON [flags] — a "
                          "typed action takes no command text (got %d positional "
                          "argument(s))" % len(positional))
        opts["host"] = positional[0]
    elif opts["with"] is not None:
        raise Refused("--with gives a typed action its parameters; it needs --action NAME")
    elif len(positional) < 2:
        raise Refused("usage: vpsexec <hosts> '<command>' [flags]  (see --help)")
    elif len(positional) > 2:
        raise Refused(
            "the command must be ONE quoted argument — got %d bare words (%s). "
            "An unquoted command is a command whose shape this door cannot see; "
            "wrap it: vpsexec %s '%s'"
            % (len(positional) - 1, " ".join(positional[1:]),
               positional[0], " ".join(positional[1:])))
    else:
        opts["host"], opts["command"] = positional
    for key in ("timeout", "canary"):
        if opts[key] not in (None, 0):
            try:
                opts[key] = int(opts[key])
            except (TypeError, ValueError):
                raise Refused("--%s must be an integer" % key.replace("_", "-"))
    return opts


def _resolve_all_targets(hosts, opts, prober, max_parallel=5):
    """Container sets for every host. Probed in parallel — an outage is not the
    moment to discover things one ssh round-trip at a time.

    A host that cannot be probed refuses the WHOLE run: you cannot approve a
    plan that could not be computed.
    """
    if not (opts["in"] or opts["match"] or opts["all"]):
        return dict((h, []) for h in hosts)
    if len(hosts) == 1:
        return {hosts[0]: resolve_targets(hosts[0], opts["in"], opts["match"],
                                          opts["all"], prober=prober)}
    import concurrent.futures
    out, errors = {}, []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(max_parallel, len(hosts))) as pool:
        futures = dict((pool.submit(resolve_targets, h, opts["in"], opts["match"],
                                    opts["all"], prober), h) for h in hosts)
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            try:
                out[host] = fut.result()
            except Refused as r:
                errors.append("%s: %s" % (host, r))
            except (subprocess.TimeoutExpired, OSError) as e:
                errors.append("%s: transport: %s" % (host, e))
    if errors:
        raise Refused("could not resolve containers on every host, so there is "
                      "no plan to approve:\n    " + "\n    ".join(sorted(errors)))
    return out


def _resolve_verify_retry(opts, hosts, auth, verify):
    """{host: (tries, interval)} for hosts whose verify came from a runbook
    entry carrying verify_retry. An explicit --verify is a different check:
    it runs once, as before."""
    if opts["verify"]:
        return {}
    out = {}
    for host in hosts:
        retry = (auth.get(host) or {}).get("verify_retry")
        if retry and verify.get(host):
            out[host] = (retry["tries"], retry["interval"])
    return out


def _resolve_verify(opts, hosts, auth, deny, risky_extra):
    """{host: post-condition}. Explicit --verify wins; otherwise each host uses
    the verify from the runbook that authorised it, so different runbooks can
    check different things in one fleet command.

    A post-condition MUST be a read. It runs unapproved, immediately after a
    mutation — if it could change anything it would be a second command
    smuggled past every gate, not a check.
    """
    verify = {}
    if opts["verify"]:
        for host in hosts:
            verify[host] = normalize(opts["verify"])
    else:
        for host in hosts:
            entry = auth.get(host)
            if entry and entry.get("verify"):
                verify[host] = normalize(entry["verify"])
    for command in sorted(set(verify.values())):
        tier, detail = classify(command, deny, risky_extra)
        if tier != "read":
            raise Refused(
                "post-condition %r classifies as %r%s, not a read — a verify runs "
                "with no approval right after a mutation, so it must be unable "
                "to change anything" % (command, tier, " (%s)" % detail if detail else ""))
    return verify


# ---- introspection -------------------------------------------------------

def _render_hosts(guard, policy, windows, status):
    hosts_cfg = guard.policy.get("hosts", {})
    aliases = governor_aliases(hosts_cfg)
    known = set(sshconfig.load())
    lines = ["%-26s %-10s %-9s %-24s %s"
             % ("HOST", "POSTURE", "MUTABLE", "ALIAS OF", "REACHABLE")]
    for name in sorted(hosts_cfg):
        cfg = hosts_cfg[name] or {}
        posture = cfg.get("posture", "frozen")
        target = aliases.get(name)
        reach = (target or name) in known if known else True
        lines.append("%-26s %-10s %-9s %-24s %s"
                     % (name, posture,
                        "yes" if posture in ("test", "released") else "no",
                        target or "-", "yes" if reach else "NO ssh alias"))
    lines.append("")
    lines.append("mutable hosts are the only ones vpsexec will change without "
                 "--break-glass + a runbook")
    if status and status != "ok":
        lines.append("maintenance windows: unknown (blackout tool %s)" % status)
    elif windows:
        inside = sorted(h for h, v in windows.items() if v)
        lines.append("in a maintenance window: %s" % (", ".join(inside) or "none"))
    return "\n".join(lines)


def _render_groups(policy):
    groups = policy.get("groups", {})
    if not groups:
        return "no host groups defined in policies/*.yaml"
    lines = ["%-12s %s" % ("GROUP", "MEMBERS")]
    for name in sorted(groups):
        lines.append("%-12s %s" % ("@" + name, ", ".join(groups[name])))
    lines.append("")
    lines.append("@all is built in: every governed machine, once")
    return "\n".join(lines)


def _render_checks(policy):
    checks = policy.get("checks", {})
    if not checks:
        return ("no checks defined in policies/*.yaml\n"
                "  A check is a named read play: `vpsexec check disk`.")
    lines = ["%d check(s) available" % len(checks), ""]
    for name in sorted(checks):
        c = checks[name]
        lines.append("  %-14s %s" % (name, c["cmd"]))
        lines.append("  %-14s hosts: %-14s %s"
                     % ("", c["hosts"], "(--compare)" if c["compare"] else ""))
        for pname, p in sorted((c.get("params") or {}).items()):
            lines.append("  %-14s %s=%s%s" % ("", pname, p["re"].pattern,
                                              "  (default %s)" % p["default"]
                                              if p["default"] is not None else ""))
        lines.append("  %-14s %s" % ("", c["why"]))
        lines.append("")
    return "\n".join(lines).rstrip()


def _render_runbooks(policy):
    books = policy.get("runbooks", [])
    disarmed = ["  DISARMED (expired %s): %s, %d runbook(s)"
                % (e["expires"], Path(e["path"]).name, e["runbooks"])
                for e in policy.get("expired", [])]
    disarmed += ["  DISARMED (misshapen: %s): %s, %d runbook(s)"
                 % (m["reason"], Path(m["path"]).name, m["runbooks"])
                 for m in policy.get("misshapen", [])]
    if disarmed:
        return (_render_runbooks({**policy, "expired": [], "misshapen": []})
                + "\n\n" + "\n".join(disarmed))
    if not books:
        return ("no runbooks in force.\n"
                "  --break-glass reaches nothing until a runbook in policies/ "
                "authorises a command.\n"
                "  See policies/examples/ for the shape.")
    lines = ["%d authorisation(s) in force" % len(books), ""]
    for b in books:
        lines.append("  %s%s%s" % (b["cmd"], "   [BREAK-GLASS]" if b["break_glass"] else "",
                                   "   [ROLLBACK]" if b.get("rollback") else ""))
        lines.append("      hosts   : %s" % ", ".join(b["hosts"]))
        lines.append("      where   : %s%s" % (b["where"], "  (container: %s)"
                                                % b["container"] if b.get("container") else ""))
        if b.get("verify"):
            retry = b.get("verify_retry")
            lines.append("      verify  : %s%s" % (b["verify"], "  (up to %d tries, %ds apart)"
                                                    % (retry["tries"], retry["interval"])
                                                    if retry else ""))
        lines.append("      why     : %s" % b["why"])
        lines.append("      source  : %s (expires %s)"
                     % (b.get("source", "?"), b.get("expires") or "-"))
        lines.append("")
    return "\n".join(lines).rstrip()


def _render_locks(hosts, ssh, timeout=30):
    """Who holds the per-host mutation lock. A read, and a fleet-wide one."""
    ssh = ssh or _default_ssh
    lines = ["%-26s %s" % ("HOST", "LOCK")]
    for host in hosts:
        directory = shlex.quote(lock.LOCK_DIR)
        cmd = ("if test -d %s; then cat %s/owner 2>/dev/null || echo 'LOCKED (owner unavailable)'; else echo FREE; fi"
               % (directory, directory))
        try:
            rc, out, err = ssh(host, cmd, timeout=timeout)
            body = secretmask.mask((out or "").strip() or (err or "").strip() or "?")
        except (subprocess.TimeoutExpired, OSError) as e:
            body = "unreachable: %s" % e
        lines.append("%-26s %s" % (host, body[:90]))
    return "\n".join(lines)


# ---- reconcile: the release valve for a retained lock ---------------------
#
# Threats:
#   - Protects against: a retained lock needing hand-ssh and hand-rmdir on a
#     frozen host (2026-10-12); releasing a lock whose operation is still
#     running (refused outright — a running unit, a live runner pid, or any
#     process naming the op dir is STILL RUNNING, checked again after the
#     phrase); releasing a different operation's lock (owner and token are
#     read, must agree with each other, and are compared byte-for-byte in the
#     same remote command that removes them); an agent or script releasing
#     locks (controlling-TTY check before any host is contacted, pending
#     keystrokes flushed, a phrase naming the host and the op); an unaudited
#     release (journal-or-refuse: the evidence is journaled before the lock is
#     touched, and `reconciled` after it is released).
#   - Does NOT protect against: a human typing the phrase over evidence that
#     says UNKNOWN without reading it (UNKNOWN is a judgment call by design);
#     a lock with no op dir (taken by `vpscfg deploy`, a push, or a door from
#     before detached steps), whose running state this tool cannot prove; a
#     command that left work running outside its own process (a backgrounded
#     daemon) — the runbook verify is the check for that.

RECONCILE_VERIFY_TIMEOUT = 60


def _journal_context(host, op):
    """The mutation_attempt that preceded this op's steps, and the steps."""
    records = vpsexeclog.read()
    steps = [r for r in records if r.get("event") == "step" and r.get("host") == host
             and r.get("operation_id") == op]
    attempt = None
    if steps:
        first = records.index(steps[0])
        for r in reversed(records[:first]):
            if r.get("event") == "mutation_attempt" and host in (r.get("hosts") or []):
                attempt = r
                break
    return attempt, steps


def _reexpand_action(command, host):
    """The Expansion an op's journaled canonical string (`vpscfg-action
    name@N '<json>'`) stands for, rebuilt by THIS door's code; Refused when it
    does not parse, names a version this door cannot expand, or re-expands to
    a different canonical string."""
    try:
        words = shlex.split(command)
    except ValueError as e:
        raise Refused("the journaled canonical does not parse (%s)" % e)
    if len(words) != 3 or words[0] != actions.ACTION_CANONICAL:
        raise Refused("the journaled command is not one canonical action string")
    params = actions.parse_with_json(words[2], "the journaled canonical's JSON")
    exp = actions.expand(words[1], params, host, "reconcile")
    if exp.canonical != command:
        raise Refused("the journaled canonical re-expands to a different string")
    return exp


def _reconcile_verify(host, attempt, policy, aliases):
    """(command, source, expansion): for a typed action, its verify re-expanded
    from the journaled canonical by this door (never the plan's text, which
    for a SqlCheck or TokenCheck is a heredoc no classifier rates a read);
    otherwise the verify of the runbook entry that authorised the op's
    command, else the verify its plan carried. (None, None, None) if none;
    (None, why, None) when an action cannot be re-expanded."""
    if not attempt:
        return None, None, None
    if actions.is_reserved(attempt.get("command") or ""):
        try:
            exp = _reexpand_action(attempt.get("command") or "", host)
        except (Refused, ValueError) as e:
            return None, "cannot re-expand the action (%s)" % secretmask.mask(str(e))[:160], None
        if exp.verify is None:
            return None, None, exp
        return exp.verify_text(), "action %s@%d, re-expanded" % (exp.name, exp.version), exp
    targets = (attempt.get("targets") or {}).get(host) or []
    containers = list(targets) if attempt.get("placement") == "container" else None
    try:
        entry = lookup(authorizations(policy, None), [host], attempt.get("command") or "",
                       attempt.get("placement") or "host", aliases=aliases,
                       containers=containers).get(host)
    except Refused:
        entry = None
    if entry and entry.get("verify"):
        return normalize(entry["verify"]), entry.get("source") or "runbook", None
    planned = (attempt.get("verify") or {}).get(host)
    if planned:
        return normalize(planned), "the op's plan", None
    return None, None, None


def _reconcile_run_action_verify(host, exp, ssh, deny, risky_extra):
    """(label, rc, detail) for an action's re-expanded verify, through the
    same gate and runner as a run: a shell text must classify as a read, a
    SqlCheck runs in its read-only session, a TokenCheck is bound to its own
    action and its output is withheld (only the token or a fixed error
    class). rc is None when it did not run."""
    probe = exp.verify
    withheld = isinstance(probe, actions.TokenCheck)
    if isinstance(probe, actions.TokenCheck):
        label = "token-only check %s" % probe.key
    elif isinstance(probe, actions.SqlCheck):
        label = "SQL check in %s/%s" % (probe.container, probe.database)
    else:
        label = probe
    try:
        _gate_probe(probe, "verify", deny, risky_extra, exp)
    except Refused as e:
        return label, None, "refused by the gate, not run (%s)" % secretmask.mask(str(e))[:160]
    try:
        rc, out, err = _run_probe(host, probe, ssh, RECONCILE_VERIFY_TIMEOUT, deny)
    except Refused as e:
        return label, None, "refused, not run (%s)" % secretmask.mask(str(e))[:160]
    except (OSError, subprocess.TimeoutExpired) as e:
        return label, None, ("transport lost" if withheld
                             else "transport: %s" % secretmask.mask(str(e))[:120])
    if isinstance(probe, (actions.SqlCheck, actions.TokenCheck)):
        token = _probe_token(probe, rc, out)
        if withheld:
            detail = token or "token-only verify: output withheld"
        else:
            detail = token or secretmask.mask(_decode(err) or _decode(out) or "").strip()[:200]
        return label, 0 if token == actions.DONE else (rc or 1), detail
    return label, rc, secretmask.mask(_decode(err) or _decode(out) or "").strip()[:200]


def _operator():
    return vpsexecgrant.operator()  # the password database, never $USER


def longest_step_seconds():
    """The longest any single step holding a host lock may run, from the real
    caps: a runbook `timeout:` (vpsexecpolicy.RUNBOOK_TIMEOUT_MAX), an
    executor step (executor.MAX_STEP_SECONDS), a k3s rollout wait
    (k3sapply.MAX_TIMEOUT, waited with 60 s of slack)."""
    from . import executor, k3sapply
    return max(vpsexecpolicy.RUNBOOK_TIMEOUT_MAX, executor.MAX_STEP_SECONDS,
               k3sapply.MAX_TIMEOUT + 60)


# A lock with no op dir (vpscfg deploy, push, an older door) proves nothing
# about whether its work still runs; it may be released only once it is older
# than twice the longest step any lock holder may run.
UNPROVEN_LOCK_MIN_AGE = None  # computed on first use: unproven_lock_min_age()


def unproven_lock_min_age():
    return UNPROVEN_LOCK_MIN_AGE or 2 * longest_step_seconds()


def _pid_alive(pid):
    """Only a real, positive pid can be alive: 0 or -1 would make kill()
    address a process group, and a non-integer is not a pid."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, OverflowError):
        return False
    return True


def _live_controller(meta):
    """The controller that took this lock, if it is THIS machine and its pid
    is alive — whatever the journal says (`vpscfg deploy` journals no vpsexec
    attempt): that process may still be working, so the lock is not anyone's
    to release. "Alive" means that pid exists AND its process started when
    the controller recorded (`started`, its own start time): a pid number now
    held by a later or earlier process is a recycled pid, i.e. a dead
    controller. A controller field that is present but malformed (including
    a `started` that is not a positive integer: null, 0, negative), or a live
    pid whose start time cannot be read, counts as live (fail closed); a lock
    without one (an older door) is judged by the other rules."""
    ctl = meta.get("controller")
    if ctl is None:
        return None
    if not isinstance(ctl, dict) or not isinstance(ctl.get("host"), str):
        return {"host": "?", "pid": "?", "started": "malformed controller field"}
    if ctl.get("host") != socket.gethostname():
        return None
    pid = ctl.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return {"host": ctl.get("host"), "pid": pid, "started": "malformed pid"}
    if not _pid_alive(pid):
        return None
    started = ctl.get("started")
    actual = lock.process_start(pid)
    if (actual is None or isinstance(started, bool) or not isinstance(started, int)
            or started <= 0):
        return ctl  # alive, and its identity cannot be checked: fail closed
    if abs(actual - started) > lock.START_TOLERANCE:
        return None  # a recycled pid: the controller itself is gone
    return ctl


def reconcile(argv, guard, policy, ssh=None, stream=None, prompt=None):
    """`vpsexec reconcile <host> [--stop]`: evidence first, then one typed
    phrase. With --stop it stops the op's unit or processes (STOP:<host>:<op8>)
    and releases nothing; a normal reconcile then applies."""
    stop = argv[1:] == ["--stop"]
    if stop:
        argv = argv[:1]
    if len(argv) != 1 or argv[0].startswith("-"):
        raise Refused("usage: vpsexec reconcile <host> [--stop]   (one host)")
    stream = stream if stream is not None else sys.stdin
    # Before any host is contacted: this is a human's release valve.
    vpsexecgrant._require_tty(stream, "vpsexec reconcile")
    hosts_cfg = guard.policy.get("hosts", {})
    resolved = resolve_hosts(argv[0], policy.get("groups", {}), hosts_cfg)
    if len(resolved["hosts"]) != 1:
        raise Refused("reconcile takes exactly one host; %r resolves to %d"
                      % (argv[0], len(resolved["hosts"])))
    host = resolved["hosts"][0]
    # Lock bookkeeping, not a change to the service: the token, master switch
    # and mode apply; posture does not (break-glass is what took the lock).
    guard.assert_exec_elevated(host)
    ssh = ssh or _default_ssh
    runner = lambda h, c: ssh(h, c, timeout=detach.POLL_TIMEOUT)  # noqa: E731

    held = lock.read_owner(host, runner=runner)
    print("RECONCILE — %s" % host)
    if held is None:
        print("  lock      : free — nothing to reconcile")
        # Evidence for vpsrun --resume: a step whose outcome was never recorded
        # holds no lock here, so it settles as "lock free" (and runs again).
        journal.append("vpsexec", {"event": "reconcile_free", "host": host,
                                   "reconciled_by": _operator()})
        return 0
    meta = held["meta"] or {}
    op = held["token"]
    print("  lock      : HELD (%s)" % lock.LOCK_DIR)
    print("  operator  : %s" % secretmask.mask(str(meta.get("operator", "?"))))
    print("  reason    : %s" % secretmask.mask(str(meta.get("reason", "?")))[:200])
    print("  operation : %s" % (meta.get("operation_id") or "(owner unreadable)"))
    if not lock.consistent(held) or not detach.OP_RE.match(op):
        journal.append("vpsexec", {"event": "reconcile_refused", "host": host,
                                   "why": "owner/token mismatch"})
        raise Refused("the lock on %s has an owner and token that do not agree (or are "
                      "unreadable) — not a lock this door wrote as one operation. "
                      "Nothing was released; inspect %s by hand." % (host, lock.LOCK_DIR))
    live = _live_controller(meta)
    if live:
        journal.append("vpsexec", {"event": "reconcile_refused", "host": host,
                                   "operation_id": op, "why": "controller alive",
                                   "controller": live})
        raise Refused("the process that took this lock is still alive on THIS machine "
                      "(pid %s, started %s) — it may still be working (a vpscfg deploy, a "
                      "vpsexec door or a vpsrun play it ran). Find it: `ps -o pid,lstart,"
                      "args -p %s`. If it is that door, let it finish; if it is stuck, end "
                      "it (kill %s) — then reconcile. Nothing was released."
                      % (live.get("pid"), live.get("started"), live.get("pid"),
                         live.get("pid")))

    def gather():
        try:
            return detach.inspect(host, op, ssh)
        except (OSError, subprocess.TimeoutExpired, detach.PollError) as e:
            raise Refused("cannot read the op dir on %s (%s) — no evidence, no release"
                          % (host, e))

    evidence = gather()
    print("  op dir    : %s  (%d step(s))" % (detach.op_dir(op), len(evidence["steps"])))
    if not evidence["steps"]:
        print("  WARNING   : NO OP DIR. This lock was taken by `vpscfg deploy`, a push, or "
              "a door from before detached steps. Whether its work still runs is NOT "
              "provable here — check the host before you type the phrase.")
    for st in evidence["steps"]:
        print("  step %-4d : %s, %s, %s, via %s"
              % (st["idx"], "exit rc=%d" % st["rc"] if st["rc"] is not None else "NO exit file",
                 "RUNNING" if st["running"] else "not running", st["state"], st["how"]))
        for name, label in (("out", "stdout"), ("err", "stderr")):
            tail = secretmask.mask(_decode(st[name])).strip()
            if tail:
                print("     %s tail:" % label)
                for line in tail.splitlines()[-15:]:
                    print("       %s" % line)
    print("  processes : %s" % (secretmask.mask(evidence["procs"])[:300]
                                if evidence["procs"] else "none name the op dir"))

    attempt, jsteps = _journal_context(host, op)
    if attempt:
        print("  journal   : %s  (reason: %s)"
              % (secretmask.mask(attempt.get("command") or "?"),
                 secretmask.mask(str(attempt.get("reason") or "?"))[:120]))
    else:
        print("  journal   : no record of this op on this controller")
    verify, source, vexp = _reconcile_verify(host, attempt, policy,
                                             governor_aliases(hosts_cfg))
    vrc, vdetail = None, ""
    deny = list(guard.deny_patterns()) + list(policy.get("deny_extra", []))
    if vexp is not None and vexp.verify is not None:
        # A typed action: its own verify, re-expanded, through the run's gate
        # and runner. Evidence only — the verdict and the phrase still decide.
        verify, vrc, vdetail = _reconcile_run_action_verify(
            host, vexp, ssh, deny, policy.get("risky_extra", []))
        print("  verify    : %s (%s) -> %s %s"
              % (verify, source, "not run:" if vrc is None else "ok" if vrc == 0
                 else "FAILED rc=%s" % vrc, vdetail))
    elif verify:
        try:
            tier, _ = classify(verify, deny, policy.get("risky_extra", []))
        except Refused as e:
            # Unclassifiable is "not a plain read": never run, never fatal —
            # the evidence and the RECONCILE phrase still decide.
            tier = "refused (%s)" % secretmask.mask(str(e))[:120]
        if tier != "read":
            print("  verify    : %s (%s) is not a plain read [%s] — not run"
                  % (secretmask.mask(verify)[:200], source, tier))
        else:
            try:
                vrc, vout, verr = ssh(host, verify, timeout=RECONCILE_VERIFY_TIMEOUT)
                vdetail = secretmask.mask(verr or vout or "").strip()[:200]
            except (OSError, subprocess.TimeoutExpired) as e:
                vdetail = "transport: %s" % secretmask.mask(str(e))[:120]
            print("  verify    : %s (%s) -> %s %s"
                  % (verify, source, "ok" if vrc == 0 else "FAILED rc=%s" % vrc, vdetail))
    else:
        print("  verify    : %s" % ("%s — not run" % source if source else "none declared"))

    state, rc = detach.verdict(evidence)
    print("")
    print("VERDICT: %s" % ("COMPLETED rc=%d" % rc if state == "COMPLETED" else state))
    record = {"host": host, "operation_id": op, "owner": meta, "verdict": state, "rc": rc,
              "steps": [{"idx": s["idx"], "rc": s["rc"], "running": s["running"],
                         "state": s["state"], "how": s["how"],
                         "stdout_tail": secretmask.mask(_decode(s["out"]))[-1000:],
                         "stderr_tail": secretmask.mask(_decode(s["err"]))[-1000:]}
                        for s in evidence["steps"]],
              "procs": secretmask.mask(evidence["procs"])[:500],
              "verify": verify, "verify_rc": vrc, "verify_detail": vdetail,
              "journal_steps": len(jsteps), "lock_age": held.get("age"),
              "reconciled_by": _operator()}
    if stop:
        return _reconcile_stop(host, op, state, record, ssh, stream, prompt)
    if state == "STILL RUNNING":
        raise Refused("operation %s on %s is STILL RUNNING — nothing to reconcile; the lock "
                      "stays. Re-run `vpsexec reconcile %s` once it has finished, or stop "
                      "it first: vpsexec reconcile %s --stop" % (op[:8], host, host, host))
    if not evidence["steps"]:
        age, need = held.get("age"), unproven_lock_min_age()
        if age is None or age < need:
            raise Refused(
                "the lock on %s has NO op dir, so whether its work still runs cannot be "
                "proven, and it is %s old; it may be released only once it is at least "
                "%ds old (twice the longest step a lock holder may run). Nothing was "
                "released; re-run later, after the manual checks in docs/RECOVERY.md."
                % (host, "an unknown time" if age is None else "%ds" % age, need))

    want = "RECONCILE:%s:%s" % (host, op[:8])
    vpsexecgrant.flush_input(stream)
    prompt = prompt or (lambda msg: input(msg))
    if prompt("Type %s to release this operation's lock, anything else aborts: "
              % want).strip() != want:
        raise Refused("reconcile phrase did not match %r — the lock stays" % want)

    # Again, after the human read and typed: nothing may have started since.
    if detach.verdict(gather())[0] == "STILL RUNNING":
        raise Refused("operation %s on %s started running again while you read — the "
                      "lock stays" % (op[:8], host))
    journal.append("vpsexec", dict(record, event="reconcile_attempt"))  # or refuse
    if not lock.release_matching(host, held, runner=runner, op_dir=detach.op_dir(op)):
        journal.append("vpsexec", {"event": "reconcile_failed", "host": host,
                                   "operation_id": op})
        raise Refused("the lock on %s no longer matches operation %s (owner or token "
                      "changed) — another operation holds it now; nothing was released"
                      % (host, op[:8]))
    journal.append("vpsexec", dict(record, event="reconciled"))
    print("  [ok] lock released for operation %s on %s, op dir removed (journaled: "
          "reconciled)" % (op[:8], host))
    return 0


def _reconcile_stop(host, op, state, record, ssh, stream, prompt):
    """`reconcile <host> --stop`: TTY (already checked) and STOP:<host>:<op8>;
    journal-or-refuse before anything is signalled. Releases nothing."""
    if state != "STILL RUNNING":
        print("  nothing is running for operation %s — nothing to stop. Reconcile it: "
              "vpsexec reconcile %s" % (op[:8], host))
        return 0
    want = "STOP:%s:%s" % (host, op[:8])
    vpsexecgrant.flush_input(stream)
    prompt = prompt or (lambda msg: input(msg))
    if prompt("Type %s to stop this operation's step(s), anything else aborts: "
              % want).strip() != want:
        raise Refused("stop phrase did not match %r — nothing was stopped" % want)
    journal.append("vpsexec", dict(record, event="reconcile_stop_attempt"))  # or refuse
    try:
        rc, out, err = ssh(host, detach.stop_cmd(op), timeout=detach.POLL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        journal.append("vpsexec", {"event": "reconcile_stop_failed", "host": host,
                                   "operation_id": op, "why": secretmask.mask(str(e))[:200]})
        raise Refused("could not reach %s to stop operation %s (%s) — the lock stays"
                      % (host, op[:8], e))
    refused = [l for l in (out or "").splitlines() if l.startswith(detach.STOP_REFUSED)]
    if refused:
        parts = refused[0].split()
        why, step, pgid = (parts + ["?", "?", "?"])[1:4]
        journal.append("vpsexec", {"event": "reconcile_stop_refused", "host": host,
                                   "operation_id": op, "why": why, "step": step,
                                   "pgid": pgid, "stopped_by": _operator()})
        raise Refused(
            "nothing was signalled: step %s's process group %s on %s is %s — %s, so "
            "the group's identity cannot be proven and --stop will not signal it. "
            "Act by hand on the host: `ps -o pid,pgid,lstart,args -g %s`, end what "
            "belongs to this operation, then run `vpsexec reconcile %s`."
            % (step, pgid, host, why.upper(),
               "its leader pid now belongs to a process started at another time"
               if why == "reused" else "its leader is gone and its remaining members "
               "could not all be proven the step's (Linux /proc: same session, started "
               "no earlier than the leader, and the step's VPSCFG_OP tag in its "
               "environment; other systems cannot prove it)",
               pgid, host))
    stopped = detach.STOPPED in (out or "")
    journal.append("vpsexec", {"event": "reconcile_stopped" if stopped
                               else "reconcile_stop_failed", "host": host,
                               "operation_id": op, "rc": rc,
                               "detail": secretmask.mask((err or out or "").strip())[:200],
                               "stopped_by": _operator()})
    if not stopped:
        raise Refused("stopping operation %s on %s did not confirm (rc=%s) — the lock stays"
                      % (op[:8], host, rc))
    print("  [ok] stop sent to operation %s on %s (journaled). The lock stays: next, "
          "reconcile it with the evidence:\n  vpsexec reconcile %s" % (op[:8], host, host))
    return 0


def _parse_since(text):
    """'90s' '30m' '2h' '7d' -> seconds."""
    if text is None:
        return None
    text = str(text).strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text and text[-1] in units:
        try:
            return float(text[:-1]) * units[text[-1]]
        except ValueError:
            pass
    try:
        return float(text)
    except ValueError:
        raise Refused("--since %r: use 90s, 30m, 2h or 7d" % text)


def _introspect(verb, argv, guard, policy, ssh, blackout_runner):
    if verb == "groups":
        print(_render_groups(policy))
        return 0
    if verb == "runbooks":
        print(_render_runbooks(policy))
        return 0
    if verb == "checks":
        print(_render_checks(policy))
        return 0
    if verb == "hosts":
        hosts_cfg = guard.policy.get("hosts", {})
        windows, status = blackout.assess(sorted(hosts_cfg), runner=blackout_runner)
        print(_render_hosts(guard, policy, windows, status))
        return 0
    if verb == "locks":
        spec = argv[0] if argv and not argv[0].startswith("-") else "@all"
        resolved = resolve_hosts(spec, policy.get("groups", {}),
                                 guard.policy.get("hosts", {}))
        print(_render_locks(resolved["hosts"], ssh))
        return 0
    if verb == "log":
        opts = {"reason": None, "host": None, "event": None, "since": None,
                "n": 40, "export": False, "raw": False}
        i = 0
        while i < len(argv):
            a = argv[i]
            if a == "--export":
                opts["export"] = True
            elif a == "--raw":
                opts["raw"] = True
            elif a in ("-n", "--limit"):
                opts["n"] = int(_value(argv, i, a)); i += 1
            else:
                for flag in ("reason", "host", "event", "since"):
                    if a == "--" + flag:
                        opts[flag] = _value(argv, i, a); i += 1
                        break
                    if a.startswith("--%s=" % flag):
                        opts[flag] = a.split("=", 1)[1]
                        break
                else:
                    if a.startswith("-"):
                        raise Refused("unknown flag %r for `vpsexec log`" % a)
            i += 1

        all_records = vpsexeclog.read()
        records = vpsexeclog.query(
            all_records, reason=opts["reason"], host=opts["host"],
            event=opts["event"], since_seconds=_parse_since(opts["since"]))

        if opts["export"]:
            # Machine-readable and safe to archive. Command OUTPUT is stripped
            # unless --raw, because the journal caps it at 500 chars and 500
            # chars of a config dump is still 500 chars off that host.
            print(json.dumps(vpsexeclog.export(records, redact=not opts["raw"]),
                             indent=2, sort_keys=True))
            return 0

        # The journal is gitignored by design. Say plainly whether anything
        # else has a copy, rather than letting a silent no-op look like health.
        print(vpsexeclog.durability(len(all_records)))
        print("")
        print(vpsexeclog.render(records, limit=opts["n"]))
        return 0
    if verb == "last":
        opts = {"host": None, "n": 1}
        i = 0
        while i < len(argv):
            a = argv[i]
            if a in ("-n", "--limit"):
                value = _value(argv, i, a); i += 1
                if not value.isdigit():
                    raise Refused("-n takes a whole number, got %r" % value)
                opts["n"] = int(value)
            elif a == "--host":
                opts["host"] = _value(argv, i, a); i += 1
            elif a.startswith("--host="):
                opts["host"] = a.split("=", 1)[1]
            elif a.startswith("-"):
                raise Refused("unknown flag %r for `vpsexec last`" % a)
            else:
                opts["host"] = a
            i += 1
        if opts["n"] < 1:
            raise Refused("-n must be at least 1")
        if opts["host"]:
            # The journal records the canonical name; `last web1` must find it.
            opts["host"] = governor_aliases(guard.policy.get("hosts", {})).get(
                opts["host"], opts["host"])
        selected = vpsexeclog.runs(vpsexeclog.read(), host=opts["host"])[-opts["n"]:]
        print(vpsexeclog.render_runs(selected))
        return 0
    raise Refused("unknown introspection verb %r" % verb)


def _run_check(args, guard, policy, **kw):
    """`vpsexec check disk [hosts] [flags]`.

    Resolves the name, then re-enters dispatch with the command spelled out, so
    a check gets the identical gate stack — including the floor, the secret
    paths, and the read classification. It is a shortcut for typing, never a
    shortcut past a gate.
    """
    checks = policy.get("checks", {})
    if not args or args[0].startswith("-"):
        print(_render_checks(policy))
        return 0
    name = args[0]
    if name not in checks:
        raise Refused("no check named %r — available: %s (see `vpsexec checks`)"
                      % (name, ", ".join(sorted(checks)) or "none"))
    check = checks[name]

    rest = list(args[1:])
    spec = check["hosts"]
    if rest and not rest[0].startswith("-") and "=" not in rest[0]:
        spec = rest.pop(0)
    supplied = [a for a in rest if not a.startswith("-") and "=" in a]
    rest = [a for a in rest if a not in supplied]
    cmd = vpsexecpolicy.bind_params(check, supplied)

    deny = list(guard.deny_patterns()) + list(policy.get("deny_extra", []))
    tier, detail = classify(cmd, deny, policy.get("risky_extra", []))
    if tier != "read":
        raise Refused(
            "check %r (%s) classifies as %r%s, not a read — a check runs with no "
            "--run and no approval, so a mutating one would be a hole, not a "
            "convenience. Fix %s."
            % (name, cmd, tier, " (%s)" % detail if detail else "",
               check.get("source", "the policy")))

    argv = [spec, cmd]
    if check["compare"] and "--compare" not in rest:
        argv.append("--compare")
    return dispatch(argv + rest, guard=guard, policy=policy, **kw)


# ---- dispatch ------------------------------------------------------------

def dispatch(argv, guard=None, policy=None, prober=None, ssh=None, stream=None,
             prompt=None, today=None, machines=None, blackout_runner=None,
             mapdoc=None):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0

    guard = guard or Guard.load()
    guard.assert_verb("exec")
    hosts_cfg = guard.policy.get("hosts", {})

    # "auto" is passed only by main() — the real CLI resolves the directory
    # map; programmatic callers (tests included) opt in explicitly, so the
    # suite can never depend on a stray map above the repo.
    if mapdoc == "auto":
        mapdoc = mapfile.resolve()

    shadowed = sorted(set(hosts_cfg) & RESERVED_VERBS)
    if shadowed:
        raise Refused(
            "governed host(s) %r use a reserved vpsexec verb name (%s) — rename "
            "them, or `vpsexec %s ...` is ambiguous"
            % (shadowed, ", ".join(sorted(RESERVED_VERBS)), shadowed[0]))

    if policy is None:
        # A group member is reachable if IT is an ssh alias, or if the governor
        # declares it an alias of one — so `web1` is a legal group member.
        reachable = set(sshconfig.load())
        reachable |= set(a for a, t in governor_aliases(hosts_cfg).items()
                         if t in reachable)
        today = today or time.strftime("%Y-%m-%d")
        policy = vpsexecpolicy.load(
            deny_patterns=guard.deny_patterns(), today=today,
            governor_hosts=set(hosts_cfg), host_re=probe.HOST_RE,
            known_aliases=reachable)
        # Only where the policy was loaded: `check` re-enters dispatch with it.
        for note in vpsexecpolicy.expiry_notes(policy, today=today):
            print(note, file=sys.stderr)

    # The governor names the remote branch reusable grants are bound to
    # (validated with the governor; default origin/main).
    policy = dict(policy, policy_remote=guard.policy.get("policy_remote")
                  or dict(vpsexecgrant.DEFAULT_POLICY_REMOTE))

    if argv[0] == "check":
        return _run_check(argv[1:], guard, policy, prober=prober, ssh=ssh,
                          stream=stream, prompt=prompt, today=today,
                          machines=machines, blackout_runner=blackout_runner,
                          mapdoc=mapdoc)

    if argv[0] == "grant":
        # The door's own classifier, so `grant new` can say which steps are
        # reads (they run without a grant) instead of skipping them silently.
        grant_deny = list(guard.deny_patterns()) + list(policy.get("deny_extra", []))
        return vpsexecgrant.cli(
            argv[1:], policy, aliases=governor_aliases(hosts_cfg),
            stream=stream, prompt=prompt,
            classify=lambda cmd: classify(cmd, grant_deny,
                                          policy.get("risky_extra", []))[0])

    if argv[0] == "reconcile":
        return reconcile(argv[1:], guard, policy, ssh=ssh, stream=stream, prompt=prompt)

    if argv[0] == "incident":
        return vpsexecincident.cli(argv[1:], hosts_cfg, stream=stream, prompt=prompt)

    if argv[0] == "runbook":
        # Lint is local; preflight sends only fixed reads, each classified by
        # classify() above and refused unless it comes back `read`.
        from . import runbookcheck
        return runbookcheck.cli(argv[1:], guard, policy, ssh=ssh, today=today)

    if argv[0] in RESERVED_VERBS:
        return _introspect(argv[0], argv[1:], guard, policy, ssh, blackout_runner)

    # `<hosts> push <file>`: the local checks and the one read of the file run
    # first, before any host is resolved or dialled. From here on the push is
    # the canonical command `vpscfg-push <sha256> <basename>` and takes the
    # same gates as any other mutation.
    push = None
    if len(argv) >= 2 and argv[1] == PUSH_VERB:
        opts = parse_args(argv, push=True)
        if opts["in"] or opts["match"] or opts["all"] or opts["compare"]:
            raise Refused("push places a file on the host; --in/--in-match/"
                          "--in-all/--compare do not apply")
        push = load_push_file(opts["push_file"], opts["sha256"])
        opts["command"] = push["command"]
    else:
        opts = parse_args(argv)
    action, action_params = None, None
    if not push and opts["action"] is not None:
        # `<hosts> --action NAME --with JSON`: typed literals in, the canonical
        # string out. The door builds the body; nothing here is operator text.
        for flag, set_ in (("--in/--in-match/--in-all", opts["in"] or opts["match"]
                            or opts["all"]), ("--verify", opts["verify"]),
                           ("--incident", opts["incident"])):
            if set_:
                raise Refused("%s does not apply to a typed action — it owns its "
                              "placement and verify, and incidents take no actions (D9)"
                              % flag)
        action = actions.get(opts["action"], "--action")
        action_params = actions.validate(action, actions.parse_with_json(opts["with"]),
                                         "--action %s" % action.name)
        opts["command"] = actions.canonical(action, action_params)
    elif not push:
        if normalize(opts["command"]).split()[:1] == [PUSH_CANONICAL]:
            raise Refused("%r is the reserved spelling of `vpsexec <hosts> push` "
                          "— use the push verb" % PUSH_CANONICAL)
        if actions.is_reserved(opts["command"]):
            raise actions.reserved_refusal("this command")
    # The YAML layer may only tighten: patterns are added, never removed.
    deny = list(guard.deny_patterns()) + list(policy.get("deny_extra", []))
    risky_extra = policy.get("risky_extra", [])
    if push:
        deny_scan(push["local"], deny)

    # Gate 0: the directory's leash. A .vpscfgfarm.map found walking up from
    # CWD is UNTRUSTED input that may only TIGHTEN — its extras merge into
    # deny/risky, its caps refuse, and nothing in it can grant (the loader
    # refuses grant-shaped keys outright). A map that exists but fails
    # validation refuses the run — a broken leash is not no leash.
    if mapdoc:
        deny += mapdoc["constraints"]["deny_extra"]
        risky_extra = list(risky_extra) + mapdoc["constraints"]["risky_extra"]
        if mapdoc["constraints"]["forbid_break_glass"] and (
                opts["break_glass"] or opts["incident"]):
            raise Refused("%s forbids --break-glass from this directory — "
                          "elevation does not launch from here" % mapdoc["path"])
        if mapdoc["constraints"]["require_blackout"]:
            opts["require_blackout"] = True
        mapfile.enforce_forbid_flags(mapdoc, opts["command"],
                                     flag_expander=_expand_short_flags)
        print("map: %s (directory constraints in force)" % mapdoc["path"])

    resolved = resolve_hosts(opts["host"], policy.get("groups", {}), hosts_cfg,
                             machines=machines)
    hosts = resolved["hosts"]
    if mapdoc:
        mapfile.enforce_hosts_allow(mapdoc, hosts,
                                    aliases_of=governor_aliases(hosts_cfg))

    # Gates 1-3: floor, unanalyzable, tier.
    tier, detail = classify(opts["command"], deny, risky_extra)
    expansions = None
    if action:
        tier, detail = _action_tier(action, tier, detail)
        expansions = dict((h, actions.expand(action.name, action_params, h, "--action"))
                          for h in hosts)
        _gate_action(expansions, deny, risky_extra)
    if push and tier == "read":
        raise Refused("a push classified as a read — refusing; a push is "
                      "always a mutation")
    if mapdoc:
        mapfile.enforce_tier_cap(mapdoc, tier)
    placement = "container" if (opts["in"] or opts["match"] or opts["all"]) else "host"

    if opts["compare"] and tier != "read":
        raise Refused("--compare is for reads — a mutation already reports per "
                      "host, and grouping mutations by output would hide failures")
    if opts["canary"]:
        if tier == "read":
            raise Refused("--canary applies to fleet mutations, not reads")
        if len(hosts) < 2:
            raise Refused("--canary needs more than one host (this plan has %d)"
                          % len(hosts))
        if opts["canary"] >= len(hosts):
            raise Refused("--canary %d leaves no hosts behind it (%d in the plan)"
                          % (opts["canary"], len(hosts)))

    # The incident override. Consulted only after the floor, deny_extra, the
    # map and the tier have run, and only for mutations: it can lift the
    # runbook lookup below for the hosts it lists, nothing else.
    incident = None
    if opts["incident"]:
        if tier == "read":
            raise Refused("--incident applies to mutations; a read needs no "
                          "incident and runs as it always does")
        incident = vpsexecincident.check(opts["incident"])
        vpsexecincident.authorize(incident, hosts, governor_aliases(hosts_cfg))
        print(vpsexecincident.banner(incident))

    # Gate 4: authorisation — committed runbooks plus any ad-hoc override file.
    override = load_override(opts["override"], deny, today=today) if opts["override"] else None
    entries = authorizations(policy, override)
    aliases = governor_aliases(hosts_cfg)
    # Exact --in names only; a glob or --in-all is never "the" container.
    containers = (list(opts["in"]) if placement == "container"
                  and not (opts["match"] or opts["all"]) else None)
    auth = lookup(entries, hosts, opts["command"], placement, aliases=aliases,
                  containers=containers)
    postures = dict((h, hosts_cfg.get(h, {}).get("posture", "frozen")) for h in hosts)
    elevated = set()

    if tier != "read":
        if not opts["reason"] or not opts["reason"].strip():
            raise Refused('every vpsexec mutation requires --reason "why" — the '
                          "2am question is always 'why was this run'")

        if tier == "risky" and not incident:
            unauthorised = [h for h in hosts if auth[h] is None]
            if unauthorised:
                raise Refused(
                    "command matches risky pattern %r and is not authorised for "
                    "%d of %d host(s): %s\n"
                    "  Add to a runbook in policies/ (reviewed, committed) or an "
                    "--override file:\n"
                    "    - hosts: [%s]\n"
                    "      cmd: \"%s\"\n"
                    "      where: %s\n"
                    "      why: \"<why this, why now>\"\n"
                    "  A runbook cannot name a deny-always pattern — that floor "
                    "is not liftable by any file."
                    % (detail, len(unauthorised), len(hosts),
                       ", ".join(unauthorised), ", ".join(unauthorised),
                       normalize(opts["command"]), placement))

        # Gate 5: posture, per host, with break-glass as the only elevation.
        blocked = [h for h in hosts if postures[h] not in ("test", "released")]
        if blocked:
            if not opts["break_glass"]:
                how = ("  This command names incident %s, which stands in for the "
                       "runbook on these hosts — but elevation past posture is "
                       "still explicit: add --break-glass." % incident["incident_id"]
                       if incident else
                       "  A committed break_glass runbook plus --break-glass reaches "
                       "them; in a customer outage with no such runbook, open an "
                       "incident (vpsexec incident open) and add --incident <id> "
                       "--break-glass. Otherwise change posture in "
                       "vpscfg-control.json — deliberately, in git.")
                raise Refused(
                    "%d of %d host(s) refuse mutations by posture: %s\n%s%s"
                    % (len(blocked), len(hosts),
                       ", ".join("%s(%s)" % (h, postures[h]) for h in blocked), how,
                       "\n  This command is a mutation, not a read: %s" % detail
                       if tier == "mutating" and detail else ""))
            unbacked = [h for h in blocked
                        if not incident
                        and not (auth[h] and auth[h].get("break_glass"))]
            if unbacked:
                raise Refused(
                    "--break-glass needs a committed break_glass runbook naming "
                    "this exact command for each elevated host. Missing for: %s\n"
                    "  Break-glass is a lookup, not an improvisation — the "
                    "runbook is written and reviewed BEFORE the outage."
                    % ", ".join(_spellings(h, aliases) for h in unbacked))
            elevated = set(blocked)

        for host in hosts:
            if host in elevated:
                guard.assert_exec_elevated(host)
            else:
                guard.assert_exec_allowed(host)

    # Gate 5b: maintenance windows. Advisory unless --require-blackout.
    windows, blackout_status = {}, None
    if tier != "read":
        windows, blackout_status = blackout.assess(hosts, runner=blackout_runner)
        if opts["require_blackout"]:
            blackout.require(windows, blackout_status)
    elif opts["require_blackout"]:
        raise Refused("--require-blackout applies to mutations; a read does not "
                      "need a maintenance window")

    # Gate 6: targets, checked against live state on every host.
    limits = guard.policy.get("limits", {})
    max_parallel = int(limits.get("max_parallel_hosts", 5))
    per_host_targets = _resolve_all_targets(hosts, opts, prober, max_parallel)
    # Belt and braces: an entry naming a container must have resolved to
    # exactly that container on its host.
    for host in hosts:
        named = (auth.get(host) or {}).get("container")
        if named is not None and per_host_targets.get(host) != [named]:
            raise Refused("runbook entry for %s names container %r, but this plan "
                          "targets %s — refusing" % (host, named,
                                                     per_host_targets.get(host) or "the host"))

    if expansions:
        # The action's own verify (gated in _gate_action), never the entry's.
        verify = dict((h, e.verify_text()) for h, e in expansions.items() if e.verify)
        verify_retry = dict((h, e.verify_retry) for h, e in expansions.items()
                            if e.verify and e.verify_retry)
    else:
        verify = _resolve_verify(opts, hosts, auth, deny, risky_extra)
        verify_retry = _resolve_verify_retry(opts, hosts, auth, verify)

    # Gate 7: the plan. Always shown, before anything can happen.
    plan = build_plan(hosts, opts["command"], per_host_targets, tier, detail,
                      override=override, entries=auth, all_flag=opts["all"],
                      dropped=resolved["dropped"], postures=postures,
                      break_glass=bool(elevated), excluded=resolved["excluded"],
                      aliased=resolved["aliased"], verify=verify,
                      canary=opts["canary"], compare=opts["compare"],
                      windows=windows, blackout_status=blackout_status,
                      verify_retry=verify_retry)
    if policy.get("files"):
        plan["policy_files"] = [f["path"] for f in policy["files"]]
    if push:
        plan["push"] = dict((k, v) for k, v in push.items() if k != "data")
        plan["push_data"] = push["data"]
    if incident:
        plan["incident"] = incident["incident_id"]
        plan["incident_record"] = incident
    if expansions:
        _attach_action(plan, expansions)
    digest = plan_hash(plan)

    # Pre-flight: scan every constructed command on every host BEFORE approval,
    # so a floor match aborts the fleet rather than the fourth host of five.
    for host in hosts:
        for step in plan["per_host"][host]["steps"]:
            deny_scan(step["remote"], deny)
        if plan["per_host"][host].get("verify"):
            deny_scan(plan["per_host"][host]["verify"], deny)

    print(render_plan(plan, digest))
    if incident:
        print(vpsexecincident.banner(incident))
    if expansions:
        # Journal-or-refuse: an action plan nobody can trace must not run.
        journal.append("vpsexec", dict({
            "event": "action_planned", "hosts": hosts, "command": plan["command"],
            "tier": tier, "plan_hash": digest,
            "check_sha256": dict((h, v["check_sha256"])
                                 for h, v in plan["action"]["per_host"].items())},
            **_action_fields(plan)))

    # Gate 7b: the repeat guard. People mash commands during an incident; an
    # automation that re-fires is more likely a bug than intent.
    if tier != "read":
        prior = vpsexeclog.recent_plan(digest, within_seconds=REPEAT_WINDOW_SECONDS)
        if prior:
            age = vpsexeclog.age_seconds(prior)
            note = ("this IDENTICAL plan ran %s ago (reason: %r)"
                    % ("%ds" % age if age is not None else "recently",
                       prior.get("reason")))
            if opts["approve"]:
                until = time.strftime("%H:%M", time.localtime(
                    time.time() + max(0, REPEAT_WINDOW_SECONDS - (age or 0)) + 60))
                raise Refused(
                    "%s.\n  Refusing an unattended repeat inside %ds — a script "
                    "re-firing the same mutation is more likely a bug than "
                    "intent. Re-run interactively if you mean it, or wait until "
                    "%s. A vpsrun step: `vpsrun ... --resume` waits the window out "
                    "for its own failed step."
                    % (note, REPEAT_WINDOW_SECONDS, until))
            print("")
            print("  ⚠ WARNING: %s" % note)

    named = [(auth.get(h) or {}).get("timeout") for h in hosts]
    if expansions and not any(named):
        named = [e.timeout for e in expansions.values()]  # the action's own default
    timeout, basis = choose_timeout(
        opts["timeout"], named, plan["command"], tier,
        int(limits.get("command_timeout_sec", 120)))
    print("  timeout : %ds per host (%s)" % (timeout, basis))

    # Grants: with no contract flag on a break-glass plan, or with --grant
    # auto on any mutation, list every VALID grant that covers this exact plan
    # (vpsrun reads these lines when planning a play or release). Only an
    # explicit `--grant auto` (or --approval-contract=auto) ever USES one
    # without naming it (H4c), and never one minted --for-release (M6). An
    # incident and --no-grant never list or pick one. Nothing is counted or
    # journaled here; use() re-checks the chosen grant in full.
    explicit_auto = opts["approval_contract"] == AUTO_GRANT
    auto = (tier != "read" and not incident and not opts["no_grant"]
            and (explicit_auto
                 or (opts["approval_contract"] is None and plan["break_glass"])))
    found = (vpsexecgrant.candidates(plan, policy, aliases=aliases)
             if auto else [])
    if auto:
        print(vpsexecgrant.render_candidates(found))

    if tier == "read":
        journal.append("vpsexec", {"event": "read", "hosts": hosts,
                                   "command": plan["command"]})
        return execute(plan, guard, None, "read", ssh=ssh, timeout=timeout,
                       max_parallel=max_parallel, stream=stream, prompt=prompt)

    if not opts["run"]:
        print("")
        print("Plan only. Nothing has run. To execute, re-run with:")
        print("  --run --reason \"why\"                       and approve at the prompt")
        print("  --run --reason \"why\" --approve=%s   if unattended" % digest)
        return 0

    # Gates 8-10: approval, journal-or-refuse, per-host locks. An approval
    # contract replaces ONLY the typed break-glass phrase; every gate above has
    # already run unchanged. Invalid for this plan => refused, never prompted.
    contract = opts["approval_contract"]
    grant_flag = opts["grant_flag"]
    if explicit_auto:
        grant_flag = "%s auto" % opts["grant_flag"]
        usable = vpsexecgrant.unbound(found)
        if not usable:
            raise Refused("%s: no valid grant in %s covers this plan%s — mint one "
                          "(vpsexec grant new ...), or drop the flag to type the phrase"
                          % (grant_flag, vpsexecgrant.GRANT_DIR,
                             " (grants minted --for-release are spent only by their "
                             "release)" if found else ""))
        contract = vpsexecgrant.announce(usable, digest)
    elif contract is None and found:
        print("  grant   : not used — this door auto-picks only with --grant auto "
              "(or name one: --grant FILE); the typed phrase follows")
    if incident:
        approval = vpsexecincident.approve(incident, stream, prompt=prompt,
                                           hosts=hosts, digest=digest)
        journal.append("vpsexec", {
            "event": "incident_command", "incident": incident["incident_id"],
            "hosts": hosts, "command": plan["command"],
            "placement": plan["placement"],
            "targets": dict((h, plan["per_host"][h]["targets"]) for h in hosts),
            "tier": plan["tier"], "postures": plan["postures"],
            "elevated": sorted(elevated), "reason": opts["reason"],
            "plan_hash": digest, "expires_at": incident["expires_at"]})
    elif contract is not None:
        if opts["approve"] and not plan["break_glass"]:
            raise Refused("--approve and %s are two approvals "
                          "for one plan — pass one (a contract only replaces the "
                          "break-glass phrase)" % opts["grant_flag"])
        if opts["approve"]:
            check_plan_hash(opts["approve"], digest)
        approval = vpsexecgrant.use(contract, plan, digest, policy,
                                    stream, aliases=aliases, flag=grant_flag)
        if opts["approve"]:
            approval = "plan-hash+" + approval
    else:
        approval = approve(plan, digest, opts["approve"], stream=stream, prompt=prompt)
    print("  [ok] approved via %s" % approval)
    if elevated:
        journal.append("vpsexec", {
            "event": "break_glass", "hosts": sorted(elevated),
            "command": plan["command"], "reason": opts["reason"],
            "runbooks": sorted(set(auth[h].get("source") or "--override"
                                   for h in elevated if auth[h])),
            **({"incident": incident["incident_id"]} if incident else {})})
    return execute(plan, guard, opts["reason"], approval, ssh=ssh,
                   timeout=timeout, max_parallel=max_parallel,
                   stream=stream, prompt=prompt)


def main(argv):
    try:
        return dispatch(argv, mapdoc="auto")
    except Refused as r:
        try:
            journal.append("vpsexec", {"event": "refused", "reason": str(r),
                                       "argv": list(argv)})
        except OSError:
            pass
        print("REFUSED: %s" % r, file=sys.stderr)
        print("(every vpsexec invocation is journaled; see journal/vpsexec.jsonl)",
              file=sys.stderr)
        return 2
    except (ValueError, subprocess.TimeoutExpired) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
