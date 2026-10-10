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
                          not; vpsexecgrant.py); TTY still required.
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
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import (blackout, journal, lock, mapfile, probe, secretmask, sshconfig, vpsexeclog,
               vpsexecgrant, vpsexecpolicy)
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
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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
    if plan["override_path"]:
        lines.append("  override: %s  sha256=%s"
                     % (plan["override_path"], plan["override_sha256"][:12]))
        for why in (plan["override_why"] or []):
            lines.append("  why     : %s" % why)
    lines.append("")
    lines.append("WILL RUN:")
    for host in hosts:
        for step in plan["per_host"][host]["steps"]:
            label = "%s / %s" % (host, step["container"]) if step["container"] else host
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
    try:
        if not is_read:
            lock_token = lock.acquire(host, os.environ.get("USER", "unknown"), reason,
                                      runner=lambda h, c: ssh(h, c))
            locked = True
        if plan.get("push"):
            _push_one_host(host, plan, guard.deny_patterns(), ssh, timeout, result)
        for step in ([] if plan.get("push") else plan["per_host"][host]["steps"]):
            deny_scan(step["remote"], guard.deny_patterns())
            rc, out, err = ssh(host, step["remote"], timeout=timeout)
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
                journal.append("vpsexec", {
                    "event": "step", "host": host, "target": step["container"] or host,
                    "remote": step["remote"], "rc": rc, "detail": (err or out)[:500],
                    "stdout": (out or "")[:STEP_OUTPUT_CAP],
                    "stderr": (err or "")[:STEP_OUTPUT_CAP]})

        verify = plan["per_host"][host].get("verify")
        if verify and result["rc"] == 0:
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
                result['error'] = ((result['error'] or '') + ' [BLOCKED: lock retained; reconcile operation %s]' % lock_token)
                print(result['error'], file=sys.stderr)
            else:
                try:
                    released = lock.release(host, runner=lambda h, c: ssh(h, c), token=lock_token)
                except (OSError, subprocess.TimeoutExpired):
                    released = False
                if not released:
                    result['rc'] = result['rc'] or 1
                    result['error'] = ((result['error'] or '') + ' [BLOCKED: lock not released]').strip()
    return result


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
        if not note and r["verify_rc"] == 0:
            note = "verify ok"
        lines.append("  [%-4s] %-24s rc=%-3s %s"
                     % ("ok" if r["rc"] == 0 else "FAIL", r["host"], r["rc"], note))
    lines.append("  %d ok, %d failed of %d"
                 % (len(results) - len(failed), len(failed), len(results)))
    return "\n".join(lines)


def _run_serial(hosts, plan, guard, reason, ssh, timeout, is_read, announce=True):
    results = []
    for host in hosts:
        r = _run_one_host(host, plan, guard, reason, ssh, timeout, is_read)
        results.append(r)
        if announce:
            note = r["error"] or ("verify ok" if r["verify_rc"] == 0 else "")
            print("  [%s] %s rc=%s%s" % ("ok" if r["rc"] == 0 else "FAIL", host,
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
            "push": plan.get("push")})

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
        journal.append("vpsexec", {
            "event": "mutation_complete", "hosts": hosts,
            "command": plan["command"],
            "results": dict((r["host"], r["rc"]) for r in results),
            "failed": [r["host"] for r in failed], "not_run": halted})
    return 1 if (failed or halted) else 0


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
                            "locks", "log", "last", "help", "grant"])
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
  --require-blackout   refuse hosts not inside an active maintenance window
  --approve=HASH       non-interactive approval of one exact plan-hash
  --approval-contract=FILE
                       a grant from `vpsexec grant new` replaces the typed
                       BREAK-GLASS phrase for a step it lists (or, when no host
                       needs elevation, that step's ordinary phrase). TTY still
                       required. Invalid for this plan => refused, no prompt.
  --timeout N          per-host timeout in seconds. Default: a runbook's timeout:,
                       else predicted from the command (read 60s, rollout/pull
                       240s, script/install 300s), capped at 300s

Push a file (a mutation: --run, --reason, posture, approval all apply)
  vpsexec <hosts> push <local-file> --sha256 <hex> [--run --reason "why"]
                       copies ONE regular file to the content-addressed path
                       /var/tmp/vpscfg-push/<sha256>/<basename>. The file must
                       hash to --sha256; the gates see `vpscfg-push <sha> <name>`.

Named read plays (policies/checks.yaml)
  vpsexec check                 list the checks available
  vpsexec check disk [hosts]    run one; its default host set is in the policy
  vpsexec check container-logs edge1 name=shop-caddy since=2h
                                typed params: each value is regex-checked, then
                                the whole command must STILL classify as a read
  A check's command must be a read, so a check can never be a way to mutate.

Approval contracts (see `vpsexec grant --help`)
  vpsexec grant new <runbook> --ttl 1h [--steps 1-20,23] [--hosts h] [--run]
  vpsexec grant list | show <file> | revoke <session_id>

Introspection (read-only, no host needed)
  vpsexec hosts        governed hosts: posture, alias, reachability, window
  vpsexec groups       host groups from policies/*.yaml
  vpsexec runbooks     authorisations in force, with expiry
  vpsexec locks <hosts>  who holds the per-host mutation lock
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
            "push_file": None, "approval_contract": None}
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
        elif a == "--approval-contract":
            opts["approval_contract"] = _value(argv, i, "--approval-contract"); i += 1
        elif a.startswith("--timeout="):
            opts["timeout"] = a.split("=", 1)[1]
        elif a == "--timeout":
            opts["timeout"] = _value(argv, i, "--timeout"); i += 1
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
        raise Refused("--approval-contract needs a file path")
    if push:
        if len(positional) != 3 or positional[1] != PUSH_VERB:
            raise Refused("usage: vpsexec <hosts> push <local-file> --sha256 <hex> "
                          "[--run --reason \"why\"]")
        opts["host"], opts["push_file"] = positional[0], positional[2]
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
        if normalize(opts["command"]).split()[:1] == [PUSH_CANONICAL]:
            raise Refused("%r is the reserved spelling of `vpsexec <hosts> push` "
                          "— use the push verb" % PUSH_CANONICAL)
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
        if mapdoc["constraints"]["forbid_break_glass"] and opts["break_glass"]:
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

        if tier == "risky":
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
                raise Refused(
                    "%d of %d host(s) refuse mutations by posture: %s\n"
                    "  During an incident, a committed break_glass runbook plus "
                    "--break-glass reaches them. Without one, change posture in "
                    "vpscfg-control.json — deliberately, in git.%s"
                    % (len(blocked), len(hosts),
                       ", ".join("%s(%s)" % (h, postures[h]) for h in blocked),
                       "\n  This command is a mutation, not a read: %s" % detail
                       if tier == "mutating" and detail else ""))
            unbacked = [h for h in blocked
                        if not (auth[h] and auth[h].get("break_glass"))]
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
    digest = plan_hash(plan)

    # Pre-flight: scan every constructed command on every host BEFORE approval,
    # so a floor match aborts the fleet rather than the fourth host of five.
    for host in hosts:
        for step in plan["per_host"][host]["steps"]:
            deny_scan(step["remote"], deny)
        if plan["per_host"][host].get("verify"):
            deny_scan(plan["per_host"][host]["verify"], deny)

    print(render_plan(plan, digest))

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
                raise Refused(
                    "%s.\n  Refusing an unattended repeat inside %ds — a script "
                    "re-firing the same mutation is more likely a bug than "
                    "intent. Re-run interactively if you mean it."
                    % (note, REPEAT_WINDOW_SECONDS))
            print("")
            print("  ⚠ WARNING: %s" % note)

    timeout, basis = choose_timeout(
        opts["timeout"], [(auth.get(h) or {}).get("timeout") for h in hosts],
        plan["command"], tier, int(limits.get("command_timeout_sec", 120)))
    print("  timeout : %ds per host (%s)" % (timeout, basis))

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
    if opts["approval_contract"] is not None:
        if opts["approve"] and not plan["break_glass"]:
            raise Refused("--approve and --approval-contract are two approvals "
                          "for one plan — pass one (a contract only replaces the "
                          "break-glass phrase)")
        if opts["approve"]:
            check_plan_hash(opts["approve"], digest)
        approval = vpsexecgrant.use(opts["approval_contract"], plan, digest, policy,
                                    stream, aliases=aliases)
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
                                   for h in elevated if auth[h]))})
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
