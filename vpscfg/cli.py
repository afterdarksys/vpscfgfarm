"""CLI — the operator's command grammar, wired to the pipeline.

  vpscfg status                         governor state
  vpscfg fleet hosts                    machines from ~/.ssh/config (no network)
  vpscfg <host> show|details|containers|services|overlays
  vpscfg <host> drift <service>         git <-> contract <-> live (read-only)
  vpscfg <host> ports                   declared ports vs what the kernel has bound (read-only)
  vpscfg <host> logs <unit> [--in C] [--file P] --search PAT [--regex] --since 2h
                                        read + search a unit's journal, a container's logs, or a
                                        config file, time-windowed (read-only; secret paths refused)
  vpscfg <host> backup-verify <service> stream the newest pre-backup and prove it restores-shaped
  vpscfg <host> verify <service>        run the contract's post-conditions (read-only)
  vpscfg <host> deploy <service>        plan + gates + outage-check (no --run: read-only)
  vpscfg <host> deploy <service> --preflight [--json] [--allow-unhealthy-baseline --reason "why"]
                                        go/no-go report (read-only): GO=0, WARNINGS=1, NO-GO=2
  vpscfg <host> deploy <service> --run  needs a GO preflight for the same plan within 30 min
  vpscfg <host> ansible <playbook>      --show only in v0
  vpscfg <host> rollback <service>      plan the restore (needs --run + --reason to execute)
  vpscfg <host> drill <service>         plan a scratch restore drill (read-only)
  vpscfg <host> drill <service> --run --reason "why"
                                        mutation: canary, then compose down with no volume flag;
                                        a receipt is journaled only when both succeed
  vpscfg <host> sql <db> 'SELECT …'     read-only; the credential stays on the host
  vpscfg <host> secret-put --from-pipe NAME PATH
                                        plan an allowlisted secret install (read-only)
  vpscfg <host> secret-put ... --run --reason "why"
                                        mutation: a controlling terminal and the governor's secret source
  vpscfg fleet watch                    run every contract's verify block, then the host-OS nag (read-only)
  vpscfg journal verify [--against DIR] [stream]
                                        check the journal's hash chain (read-only)
  vpscfg map                            show + validate this directory's .vpscfgfarm.map
  vpscfg deploy|verify|drift|... [svc]  verb-first: host and service inferred from the map
  vpscfg fleet baseline [host ...]      fingerprint container state per host (read-only)
  vpscfg fleet changes  [host ...]      diff live state vs baseline; flag UNJOURNALED changes
  vpscfg fleet keys                     dial every ssh alias; flag key rot and name traps
  vpscfg fleet secrets                  fingerprint declared credential files (hashes only)
  vpscfg fleet never                    hash and mode of every sync.never path (read-only)
  vpscfg fleet dns                      zone hash and named-checkzone; UNPINNED until a sha256 is pinned
  vpscfg fleet authkeys                 authorized_keys and sudoers line hashes; UNPINNED until pinned
  vpscfg fleet escrow <svc> --reason    age-encrypt declared credentials to committed recipients
  vpscfg fleet k3s [host ...]           k3s + iptables backend health and REBOOT-SAFE verdict (read-only);
                                        run before rebooting or disabling netfilter-persistent on a k3s host
  vpscfg fleet firewall [host ...]      firewall audit (read-only): lockdown present, ordered and persisted;
                                        stale/orphan NAT; the netfilter-persistent landmine
  vpscfg fleet coverage [host ...]      running workloads vs contracts and skeletons (read-only)
  vpscfg fleet health [host ...]        unhealthy or restarting duration, host-wide (read-only)
  vpscfg fleet twins [host ...]         a second live copy of a service; reports, does not stop it
  vpscfg fleet images [host ...]        contracted image pins vs live refs (read-only)
  vpscfg fleet postgres                 declared replication shape; UNPINNED until contracts name it
  vpscfg fleet os                       declared host OS; eol is a failure, and this is not a CVE scan
  vpscfg lint                           contract quality floor (read-only)
  vpscfg module ...                     locked in v0; edit contracts/ in git

Mutations (--run) additionally require --reason "why" — journaled forever.

Flag-sensitivity is judged in BOTH doors: deploy/ansible/rollback/drill/secret-put
WITHOUT --run are reads; WITH --run they are mutations and hit the full gate
stack + executor (which has no firing pin in v0). sql is always a read.
"""

import difflib
import subprocess
import sys
from pathlib import Path

from . import __version__, backupverify, k3sapply, contracts, drift, executor, fingerprint, fleetkeys, journal, lint, logsearch, mapfile, outage, playbook, ports as ports_mod, preflight, probe, secretscensus, sshconfig, syncplan, verify
from .contracts import CONTRACT_DIR
from .control import Guard
from .gates import Refused, READ_ONLY_VERBS


def main(argv):
    try:
        return _dispatch(argv)
    except Refused as r:
        print("REFUSED: %s" % r, file=sys.stderr)
        return 2
    except (ValueError, subprocess.TimeoutExpired) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1


def _dispatch(argv):
    guard = Guard.load()

    if not argv or argv[0] in ("help", "-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "status":
        return _status(guard)
    if argv[0] == "fleet":
        return _fleet(argv[1:])
    if argv[0] == "lint":
        return lint.run()
    if argv[0] == "journal":
        return _journal_verify(argv[1:])
    if argv[0] == "map":
        return _map_show()

    # Verb-first grammar: from a directory whose .vpscfgfarm.map names a
    # service, the host and service are inferred — the map routes, the
    # contract still decides everything that matters, and every gate below
    # runs exactly as if both had been typed.
    if argv[0] in MAP_INFERABLE_VERBS:
        argv = _map_infer(argv)
    if argv[0] == "module":
        raise Refused("module verbs are locked in v0 — edit contracts/ in git "
                      "(git-visible, which is the point)")

    host = argv[0]
    verb = argv[1] if len(argv) > 1 else "show"
    if verb in ("deploy", "rollback"):
        _check_flags(verb, argv)
    mutating = verb in ("deploy", "ansible", "rollback", "drill", "secret-put") and "--run" in argv
    guard.assert_verb(verb)
    if mutating:
        guard.assert_read_only_or_verified(verb)

    if verb in ("containers", "services", "overlays", "details"):
        result = probe.run(host, verb)
        sys.stdout.write(result["stdout"] or result["stderr"])
        return 0 if result["rc"] == 0 else 1

    if verb == "show":
        for what in ("details", "containers", "overlays"):
            print("== %s ==" % what)
            result = probe.run(host, what)
            sys.stdout.write(result["stdout"] or result["stderr"])
        return 0

    if verb == "drift":
        return _drift(host, argv)

    if verb == "ports":
        return _ports(host)

    if verb == "logs":
        return _logs(host, argv)

    if verb == "backup-verify":
        service = _svc_arg(argv, "backup-verify")
        contracts.load(service)  # a backup without a contract is not ours to bless
        result = backupverify.verify_backup(host, service)
        print(backupverify.render(service, host, result))
        return 0 if result["ok"] else 1

    if verb == "verify":
        service = _svc_arg(argv, "verify")
        contract = contracts.load(service)
        ok, results = verify.run_checks(contract, host)
        print(verify.render(service, ok, results))
        return 0 if ok else 1

    if verb == "deploy":
        return _deploy(guard, host, argv)

    if verb == "rollback":
        return _rollback(guard, host, argv)

    if verb == "ansible":
        if "--run" in argv:
            raise Refused("ansible --run is not released in v0 — --show only")
        name = argv[2] if len(argv) > 2 and not argv[2].startswith("--") else None
        return playbook.show(host, name)

    if verb == "drill":
        from . import drill as drill_mod
        return drill_mod.cli(guard, host, argv, names=_host_names(host))

    if verb == "sql":
        from . import sqlread
        return sqlread.cli(host, argv, contracts_on_host=_contracts_on_host(host))

    if verb == "secret-put":
        from . import secretput
        return secretput.cli(guard, host, argv, contracts_on_host=_contracts_on_host(host))

    raise Refused("verb %r not understood" % verb)


MAP_INFERABLE_VERBS = frozenset(
    ["deploy", "verify", "drift", "rollback", "backup-verify", "ports",
     "show", "containers", "services", "overlays", "details"])


def _map_infer(argv):
    """Rewrite verb-first argv to the canonical <host> <verb> [svc] shape
    using the directory's map. Refuses when there is no map to infer from —
    a bare verb is never guessed into a host."""
    doc = mapfile.resolve()
    if doc is None:
        raise Refused(
            "%r reads as a verb, not a host, and no .vpscfgfarm.map exists "
            "in or above this directory — run `vpscfg <host> %s ...`, or add "
            "a map that names this directory's service" % (argv[0], argv[0]))
    contract = mapfile.bind(doc)
    verb, rest = argv[0], list(argv[1:])
    needs_svc = verb in ("deploy", "verify", "drift", "rollback", "backup-verify")
    if needs_svc and (not rest or rest[0].startswith("--")):
        rest = [doc["service"]] + rest
    print("map: %s -> %s on %s" % (doc["path"], doc["service"], contract["host"]))
    return [contract["host"], verb] + rest


def _map_show():
    """Resolve, validate, and display this directory's map (read-only)."""
    path = mapfile.find()
    if path is None:
        print("no .vpscfgfarm.map in or above %s" % Path.cwd())
        return 1
    doc = mapfile.load(path)
    print("map: %s" % doc["path"])
    if doc["service"]:
        contract = mapfile.bind(doc)
        print("  routes: service %s -> host %s (contract binding verified "
              "both ways)" % (doc["service"], contract["host"]))
        entry = (doc.get("deploy") or {}).get("entry")
        if entry:
            print("  legacy entry: %s (superseded by `vpscfg deploy` from here)" % entry)
    else:
        print("  routes: nothing (no service declared — constraints only)")
    cons = doc["constraints"]
    any_cons = False
    for key in ("deny_extra", "risky_extra", "hosts_allow", "forbid_flags"):
        if cons[key]:
            print("  constraint %s: %s" % (key, cons[key]))
            any_cons = True
    for key in ("require_blackout", "forbid_break_glass"):
        if cons[key]:
            print("  constraint %s: true" % key)
            any_cons = True
    if cons["max_tier"]:
        print("  constraint max_tier: %s" % cons["max_tier"])
        any_cons = True
    if not any_cons:
        print("  constraints: none")
    return 0


# Flags each verb understands, and which of them take the next argv token as
# their value. The verbs test flags by membership, so an unknown spelling
# (`--rnu`, `--preflighta`) would otherwise be silently ignored — a mistyped
# --run quietly becoming a dry run, a mistyped safety flag quietly dropped.
_FLAGS = {
    "deploy": ({"--preflight", "--run", "--json", "--allow-unhealthy-baseline",
                "--reason", "--repair-action"}, {"--reason"}),
    # Parsed by repair.cli's argparse, which accepts --flag=value.
    "repair": ({"--repair-action", "--request", "--approve-digest", "--approval-file",
                "--operation-id", "--run"},
               {"--repair-action", "--request", "--approve-digest", "--approval-file",
                "--operation-id"}),
    "rollback": ({"--run", "--reason"}, {"--reason"}),
}


def _check_flags(verb, argv):
    """Refuse any flag the verb does not understand, before anything is
    loaded or probed. A value-taking flag's value is skipped, never judged,
    even when it starts with '-' (the verbs read it as the value too)."""
    kind = "repair" if verb == "deploy" and "--repair-action" in argv else verb
    accepted, takes_value = _FLAGS[kind]
    equals_ok = kind == "repair"
    i = 2
    while i < len(argv):
        tok = argv[i]
        i += 1
        if not tok.startswith("-"):
            continue
        name = tok.split("=", 1)[0] if equals_ok else tok
        if name in accepted:
            if name in takes_value and "=" not in tok:
                i += 1
            continue
        label = "%s --repair-action" % verb if kind == "repair" else verb
        head = tok.split("=", 1)[0]
        if "=" in tok and head in accepted:
            hint = " — write it as two arguments: %s <value>" % head
        else:
            close = difflib.get_close_matches(head, sorted(accepted), n=1, cutoff=0.6)
            hint = " — did you mean %s?" % close[0] if close else ""
        raise Refused("unknown flag %r for %s%s; accepted: %s"
                      % (tok, label, hint, " ".join(sorted(accepted))))


def _svc_arg(argv, verb):
    svc = argv[2] if len(argv) > 2 and not argv[2].startswith("--") else None
    if not svc:
        raise Refused("%s requires a service name (its contract)" % verb)
    return svc


def _drift(host, argv):
    service = _svc_arg(argv, "drift")
    contract = contracts.load(service)
    if contract["host"] != host:
        raise Refused("contract %r is bound to host %r, not %r"
                      % (service, contract["host"], host))
    repo = contract.get("repo")
    if not repo:
        raise Refused("contract %r has no 'repo' field — drift needs the git side" % service)
    local = drift.local_hashes(repo, contract["sync"]["include"])
    remote, truncated = drift.remote_hashes(host, contract["deploy_dir"], list(local))
    report = drift.compare(local, remote, contract["sync"]["never"])
    print(drift.render(service, host, report, truncated))
    return 0 if not (report["drifted"] or report["missing_on_host"]) else 1


def _logs(host, argv):
    """Read + search logs or a config file on one host. Read-only; the built
    command is scanned by the floor + secrets deny stack before it runs."""
    from . import vpsexecpolicy
    rest = argv[2:]
    spec = {"target": None, "in_container": None, "file": None,
            "searches": [], "regex": False, "since": "current", "max": None}
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--in":
            i += 1; spec["in_container"] = rest[i] if i < len(rest) else None
        elif a == "--file":
            i += 1; spec["file"] = rest[i] if i < len(rest) else None
        elif a == "--search":
            i += 1
            if i < len(rest):
                spec["searches"].append(rest[i])
        elif a == "--regex":
            spec["regex"] = True
        elif a == "--fixed":
            spec["regex"] = False
        elif a == "--since":
            i += 1; spec["since"] = rest[i] if i < len(rest) else "current"
        elif a == "--max":
            i += 1
            try:
                spec["max"] = int(rest[i]) if i < len(rest) else None
            except ValueError:
                raise Refused("--max needs an integer")
        elif not a.startswith("--") and spec["target"] is None:
            spec["target"] = a
        else:
            raise Refused("unknown logs argument %r" % a)
        i += 1

    guard = Guard.load()
    deny = list(guard.deny_patterns())
    try:
        pol = vpsexecpolicy.load(deny_patterns=deny)
        deny += list(pol.get("deny_extra", []))
        secrets_loaded = True
    except Exception:
        secrets_loaded = False
    # A --file read without the secrets deny list loaded would be an ungated
    # path read — fail closed. Log reads (no arbitrary path) proceed.
    if spec["file"] and not secrets_loaded:
        raise Refused("cannot load the secrets deny list — refusing a --file "
                      "read rather than reading an ungated path")
    result = logsearch.run(host, spec, deny)
    print(logsearch.render(host, spec, result))
    # A completed read is a success; "no matches" is an answer, not an error.
    # Only a transport/command failure (ssh down, rc>=2) is non-zero.
    return 0 if result["rc"] in (0, 1) else 1


def _host_names(host):
    """Every governed name for the machine `host` names (aliases collapsed)."""
    names = {host}
    for canonical, aliases in _governed_docker_hosts().items():
        if host == canonical or host in aliases:
            names |= aliases | {canonical}
    return names


def _contracts_on_host(host):
    names = _host_names(host)
    on_host = {}
    for name in sorted(p.stem for p in CONTRACT_DIR.glob("*.y*ml")):
        try:
            contract = contracts.load(name)
        except Refused:
            continue
        if contract["host"] in names:
            on_host[name] = contract
    return on_host


def _ports(host):
    """Kernel bind state vs contract declarations for one host."""
    on_host = _contracts_on_host(host)
    res = probe.run(host, "listening")
    if res["rc"] != 0 and not res["stdout"].strip():
        raise Refused("listening probe failed on %s: %s"
                      % (host, (res["stderr"] or "no output")[:200]))
    listening = ports_mod.parse_listening(res["stdout"])
    owners = ports_mod.parse_process_owners(res["stdout"])
    report = ports_mod.audit(listening, on_host, owners)
    text, failures = ports_mod.render(host, report)
    print(text)
    return 0 if failures == 0 else 1


def _deploy(guard, host, argv):
    service = _svc_arg(argv, "deploy")
    if "--repair-action" in argv:
        from . import repair
        return repair.cli(argv, host, service, guard)
    contract = contracts.load(service)
    if contract.get("monitor_only"):
        raise Refused("contract %r is monitor_only (verify-only) — it has no apply "
                      "path. Run its checks with `vpscfg %s verify %s`."
                      % (service, host, service))
    if contract["host"] != host:
        raise Refused("contract %r is bound to host %r, not %r"
                      % (service, contract["host"], host))

    if k3sapply.is_k3s(contract):
        # A dirty tree still SHOWS a plan (the tag then names HEAD only);
        # preflight and --run refuse it, because that tag would not name
        # what gets built.
        planned = k3sapply.planned(contract, k3sapply.image_ref(
            contract, preflight._source_manifest(contract), require_clean=False))
    else:
        planned = []
        for step in contract.get("pre", []):
            if "backup" in step:
                planned.append(step["backup"])
        for argv_t in syncplan.rsync_argvs(contract, dry_run=True):
            planned.append(" ".join(argv_t))
        planned.append(contract.get("build", "(no build command declared)"))

    mapdoc = mapfile.resolve()
    if mapdoc:
        # The directory's leash covers this door too: every planned command
        # is scanned against the map's extra deny patterns before anything
        # is shown as runnable, and a hit refuses the whole plan.
        for cmd in planned:
            if mapdoc["constraints"]["deny_extra"]:
                from .gates import deny_scan
                deny_scan(cmd, mapdoc["constraints"]["deny_extra"])

    if "--preflight" in argv:
        if "--run" in argv:
            raise Refused("--preflight is read-only and cannot be combined with --run — "
                          "run the preflight, then deploy --run while it is fresh")
        return _preflight(guard, host, service, contract, planned, argv)

    print("PLAN for %s on %s:" % (service, host))
    for cmd in planned:
        print("  would: %s" % cmd)

    if "--run" not in argv:
        # Read-only gate rehearsal: outage-check from live observation.
        cres = probe.run(host, "containers")
        live = [{"name": l.split("\t")[0], "image": l.split("\t")[1] if "\t" in l else ""}
                for l in cres["stdout"].splitlines() if l and l != "NO_DOCKER"]
        assessment = outage.assess(contract, live, [],
                                   host_meta={"failover": False if guard.no_failover(host) else None})
        print(outage.render(service, host, assessment))
        print("(no --run: nothing was executed; this was plan + gates only)")
        return 0

    scope = "%s:%s/%s" % (contract.get("scope_kind", "service"), host, service)
    # The go/no-go gate: a GO/GO-WITH-WARNINGS preflight for THIS plan within
    # the freshness window, consumed now (fail fast, journaled, single-use)
    # and re-checked by the executor under the host lock with the same token
    # (closes the check-then-lock gap).
    import uuid
    token = uuid.uuid4().hex
    preflight.require_fresh(contract, host, token=token, consume=True)
    executor.apply(guard, contract, "deploy", host, scope, planned,
                   reason=_reason_arg(argv),
                   preflight=lambda: preflight.require_fresh(contract, host, token=token))
    return 0


def _preflight(guard, host, service, contract, planned, argv):
    """Read-only go/no-go report. Exit 0 GO, 1 GO-WITH-WARNINGS, 2 NO-GO.
    The result is journaled; deploy --run looks it up by plan hash."""
    allow = "--allow-unhealthy-baseline" in argv
    reason = _reason_arg(argv)
    if allow and not (reason and reason.strip()):
        raise Refused("--allow-unhealthy-baseline requires --reason \"why\" — deploying onto "
                      "a failing service is a decision, and decisions are journaled")
    path = next((CONTRACT_DIR / (service + ext) for ext in (".yaml", ".yml", ".json")
                 if (CONTRACT_DIR / (service + ext)).exists()), None)
    raw = path.read_text() if path else ""
    report = preflight.run(contract, host, guard, raw, planned,
                           host_contracts=_contracts_on_host(host),
                           allow_unhealthy=allow, aliases=_host_names(host))
    try:
        preflight.record(report, reason=reason)
        report["recorded"] = True
    except Exception as exc:  # noqa: BLE001 — unrecorded means deploy --run cannot use it
        report["recorded"] = False
        report["record_error"] = str(exc)
        report["verdict"], report["exit_code"] = preflight.NO_GO, 2
    if "--json" in argv:
        import json as _json
        print(_json.dumps(report, indent=1, sort_keys=True, default=str))
    else:
        print(preflight.render(report))
        if report["recorded"]:
            print("  recorded in journal/preflight.jsonl — deploy --run accepts a GO for "
                  "this exact plan for %d min" % (preflight.FRESHNESS_SECONDS // 60))
        else:
            print("  NOT RECORDED (%s) — deploy --run will refuse; verdict forced to NO-GO"
                  % report["record_error"])
    return report["exit_code"]


def _reason_arg(argv):
    if "--reason" in argv:
        i = argv.index("--reason")
        if i + 1 < len(argv):
            return argv[i + 1]
    return None


def _rollback(guard, host, argv):
    service = _svc_arg(argv, "rollback")
    contract = contracts.load(service)
    if contract["host"] != host:
        raise Refused("contract %r is bound to host %r, not %r"
                      % (service, contract["host"], host))
    if k3sapply.is_k3s(contract):
        ap = contract["apply"]
        planned = [k3sapply.set_image_cmd(contract, "<previous image, resolved under the lock "
                                                    "from the last journaled door deploy>"),
                   k3sapply.rollout_status_cmd(contract)]
        print("ROLLBACK PLAN for %s on %s (k3s: set the image the last deploy replaced):"
              % (service, host))
        for cmd in planned:
            print("  would: %s" % cmd)
        if "--run" not in argv:
            print("(no --run: nothing was executed)")
            return 0
        executor.apply(guard, contract, "rollback", host, "pod:%s/%s" % (host, service),
                       planned, reason=_reason_arg(argv))
        return 0
    backup = probe.latest_backup(host, service)
    if not backup:
        raise Refused("no /root/%s-pre-*.tar.gz backup exists on %s — nothing "
                      "to roll back TO. Backups are created by deploy's pre step."
                      % (service, host))
    planned = [
        "tar xzf %s -C /" % backup,
        contract.get("build", "(no build command declared)"),
    ]
    print("ROLLBACK PLAN for %s on %s:" % (service, host))
    print("  restore from: %s" % backup)
    for cmd in planned:
        print("  would: %s" % cmd)
    if "--run" not in argv:
        print("(no --run: nothing was executed)")
        return 0
    scope = "%s:%s/%s" % (contract.get("scope_kind", "service"), host, service)
    executor.apply(guard, contract, "rollback", host, scope, planned,
                   reason=_reason_arg(argv))
    return 0


def _fleet(rest):
    what = rest[0] if rest else "hosts"
    if what == "watch":
        return _fleet_watch()
    if what == "baseline":
        return _fleet_baseline(rest[1:])
    if what == "changes":
        return _fleet_changes(rest[1:])
    if what == "secrets":
        return _fleet_secrets()
    if what == "escrow":
        return _fleet_escrow(rest[1:])
    if what == "keys":
        governed = Guard.load().policy.get("hosts", {})
        text, problems = fleetkeys.run(governed_hosts=governed)
        print(text)
        return 0 if problems == 0 else 1
    if what == "firewall":
        return _fleet_firewall(rest[1:])
    if what == "k3s":
        return _fleet_k3s(rest[1:])
    if what == "never":
        return _fleet_never()
    if what == "dns":
        return _fleet_dns()
    if what == "authkeys":
        return _fleet_authkeys()
    if what == "coverage":
        return _fleet_coverage(rest[1:])
    if what == "health":
        return _fleet_health(rest[1:])
    if what == "twins":
        return _fleet_twins(rest[1:])
    if what == "images":
        return _fleet_images(rest[1:])
    if what == "postgres":
        return _fleet_postgres()
    if what == "os":
        return _fleet_os()
    if what != "hosts":
        raise Refused("fleet %r not released in v0 (hosts, watch, baseline, changes, keys, secrets, escrow, firewall, k3s, never, dns, authkeys, coverage, health, twins, images, postgres, os)" % what)
    machines = sshconfig.machines()
    print("fleet machines (from ~/.ssh/config):")
    for target, rec in sorted(machines.items()):
        print("  %-28s user=%-9s aliases: %s"
              % (target, rec["user"] or "-", ", ".join(sorted(rec["aliases"]))))
    print("(%d machines)" % len(machines))
    return 0


def _fleet_firewall(names):
    """The firewall manager's audit as a read: lockdown present+ordered+persisted, stale NAT,
    and the netfilter-persistent landmine. Exit 1 on any CRITICAL/HIGH."""
    from . import firewall
    canonical = _governed_docker_hosts()
    alias_to = dict((a, c) for c, names_ in canonical.items() for a in names_)
    unknown = [n for n in names if n not in alias_to]
    if unknown:
        raise Refused("not a governed host: %s" % ", ".join(unknown))
    targets = [alias_to[n] for n in names] or _default_audit_targets(canonical)
    estate = firewall.load_estate()
    print("desired state: %s (sha256 %s)  ports %s"
          % (estate["path"], estate["sha256"][:12], ",".join(map(str, estate["ports"]))))
    failing, facts_by_host = 0, {}
    for host in targets:
        res = probe.run(host, "firewall", command_timeout=90)
        if res["rc"] != 0 and not res["stdout"].strip():
            print("── %s ──\n   UNVERIFIED  probe failed: %s" % (host, res["stderr"].strip()[:160]))
            failing += 1
            continue
        findings, facts = firewall.audit(
            res["stdout"], firewall.for_host(estate, sorted(canonical.get(host, {host}))))
        facts_by_host[host] = facts
        print(firewall.render(host, findings, facts))
        failing += any(f["severity"] in firewall.FAILING for f in findings)
    fleet = firewall.fleet_findings(facts_by_host, estate)
    if fleet:
        print(firewall.render("fleet", fleet, {}))
    journal.append("watch", {"event": "fleet_firewall", "hosts": targets,
                             "failing": failing, "estate_sha256": estate["sha256"]})
    print("fleet firewall: %d host(s), %d with CRITICAL/HIGH findings" % (len(targets), failing))
    return 0 if failing == 0 else 1


def _fleet_k3s(names):
    """k3s liveness + iptables backend safety, and a REBOOT-SAFE verdict per
    host. Exit 1 on any CRITICAL/HIGH. Run it before rebooting a Docker/k3s
    host or disabling netfilter-persistent there (a reboot that left k3s
    crash-looping, with nothing alerting, is the lesson)."""
    from . import k3s as k3s_mod
    canonical = _governed_docker_hosts()
    alias_to = dict((a, c) for c, names_ in canonical.items() for a in names_)
    unknown = [n for n in names if n not in alias_to]
    if unknown:
        raise Refused("not a governed host: %s" % ", ".join(unknown))
    targets = [alias_to[n] for n in names] or _default_audit_targets(canonical)
    failing, unsafe = 0, []
    for host in targets:
        res = probe.run(host, "k3s", command_timeout=90)
        if res["rc"] != 0 and not res["stdout"].strip():
            print("── %s ──\n   UNVERIFIED  probe failed: %s" % (host, res["stderr"].strip()[:160]))
            failing += 1
            unsafe.append(host)
            continue
        findings, facts = k3s_mod.audit(res["stdout"])
        print(k3s_mod.render(host, findings, facts))
        failing += any(f["severity"] in k3s_mod.FAILING for f in findings)
        if not k3s_mod.reboot_safe(findings):
            unsafe.append(host)
    journal.append("watch", {"event": "fleet_k3s", "hosts": targets, "failing": failing,
                             "reboot_unsafe": unsafe})
    print("fleet k3s: %d host(s), %d with CRITICAL/HIGH findings; NOT reboot-safe: %s"
          % (len(targets), failing, ", ".join(unsafe) or "none"))
    return 0 if failing == 0 else 1


def _fleet_never():
    """Hash and mode of every sync.never path. Does not read or rewrite the file."""
    from . import neverprint
    names = sorted(p.stem for p in CONTRACT_DIR.glob("*.y*ml"))
    problems = 0
    checked = 0
    for name in names:
        try:
            contract = contracts.load(name)
            paths = neverprint.never_paths(contract)
        except Refused as r:
            print("SKIP %s: %s" % (name, r))
            problems += 1
            continue
        if not paths:
            continue
        checked += 1
        files, drifts = neverprint.report(contract)
        print(neverprint.render(name, files, drifts))
        problems += len(drifts)
    print("fleet never: %d contract(s) with sync.never, %d problem(s)" % (checked, problems))
    return 0 if problems == 0 else 1


def _fleet_dns():
    """Zone-file pin. Empty or unhashed pins are UNPINNED and do not SSH."""
    from . import dnspins
    result = dnspins.run(dnspins.load())
    print(dnspins.render(result))
    journal.append("watch", {"event": "fleet_dns", "state": result["state"],
                             "probed": result["probed"], "ok": result["ok"]})
    return 0 if result["ok"] else 1


def _fleet_authkeys():
    """Line-hash census. An empty allowlist is UNPINNED and does not SSH."""
    from . import authkeys
    governed = sorted(_governed_docker_hosts())
    result = authkeys.run(authkeys.load(), governed)
    print(authkeys.render(result))
    journal.append("watch", {"event": "fleet_authkeys", "state": result["state"],
                             "probed": result["probed"], "ok": result["ok"]})
    return 0 if result["ok"] else 1


def _fleet_host_targets(names):
    """Canonical hosts for a fleet read. Named aliases collapse to canonical.
    DNS hosts stay in the default list: an empty host is a clean observation."""
    canonical = _governed_docker_hosts()
    alias_to = dict((a, c) for c, names_ in canonical.items() for a in names_)
    unknown = [n for n in names if n not in alias_to]
    if unknown:
        raise Refused("not a governed host: %s" % ", ".join(unknown))
    targets = []
    if names:
        for name in names:
            canon = alias_to[name]
            if canon not in targets:
                targets.append(canon)
    else:
        targets = sorted(canonical)
    return canonical, targets


def _probe_sections(host, what):
    """Run one fixed probe. Empty failure is UNVERIFIED, not a clean host."""
    from .probesplit import sections
    res = probe.run(host, what, command_timeout=90)
    if res["rc"] != 0 and not (res["stdout"] or "").strip():
        return None, "probe failed: %s" % (res["stderr"] or "").strip()[:160]
    parts = sections(res["stdout"])
    return parts, None


def _promoted_contracts():
    loaded, skipped = [], 0
    for path in sorted(CONTRACT_DIR.glob("*.y*ml")):
        try:
            loaded.append(contracts.load(path.stem))
        except Refused as refused:
            print("SKIP %s: %s" % (path.stem, refused))
            skipped += 1
    return loaded, skipped


def _fleet_coverage(names):
    """Running containers and pods against contracts and skeletons. Exit 1
    when anything running is uncovered, a host is bare, or a probe is unread."""
    from . import coverage
    canonical, targets = _fleet_host_targets(names)
    decls = coverage.load_index(CONTRACT_DIR)
    failing = 0
    for host in targets:
        parts, err = _probe_sections(host, "workloads")
        if err or parts is None or "containers" not in parts or "pods" not in parts:
            print("coverage %s: UNVERIFIED %s" % (host, err or "probe sections missing"))
            failing += 1
            continue
        try:
            containers = coverage.parse_containers(parts.get("containers", ""))
            pods, pod_error = coverage.parse_pods(parts.get("pods", ""))
        except Refused as refused:
            print("coverage %s: UNVERIFIED %s" % (host, refused))
            failing += 1
            continue
        report = coverage.judge(
            host, canonical.get(host, {host}), containers, pods, decls, pod_error=pod_error)
        print(coverage.render(report))
        if not report["ok"]:
            failing += 1
    journal.append("watch", {"event": "fleet_coverage", "hosts": targets, "failing": failing})
    print("fleet coverage: %d host(s), %d failing" % (len(targets), failing))
    return 0 if failing == 0 else 1


def _fleet_health(names):
    """Host-wide unhealthy duration. A contract may tighten the ceiling."""
    from . import coverage, healthdur
    from datetime import datetime, timezone
    _canonical, targets = _fleet_host_targets(names)
    loaded, _skipped = _promoted_contracts()
    watches = healthdur.watches_from(loaded, coverage.names_of)
    now = datetime.now(timezone.utc)
    failing = 0
    for host in targets:
        parts, err = _probe_sections(host, "health")
        if err or parts is None or "docker" not in parts or "pods" not in parts:
            print("health %s: UNVERIFIED %s" % (host, err or "probe sections missing"))
            failing += 1
            continue
        try:
            docker_rows = healthdur.parse_docker(parts.get("docker", ""))
            pod_rows, pod_error = healthdur.parse_pods(parts.get("pods", ""))
        except Refused as refused:
            print("health %s: UNVERIFIED %s" % (host, refused))
            failing += 1
            continue
        report = healthdur.judge(docker_rows, pod_rows, now, watches=watches, pod_error=pod_error)
        print(healthdur.render(host, report))
        if not report["ok"]:
            failing += 1
    journal.append("watch", {"event": "fleet_health", "hosts": targets, "failing": failing})
    print("fleet health: %d host(s), %d failing" % (len(targets), failing))
    return 0 if failing == 0 else 1


def _fleet_twins(names):
    """Declared authority plus the same running container name on two hosts.
    This reports the twin. It does not stop either copy."""
    from . import authority, coverage
    _canonical, targets = _fleet_host_targets(names)
    loaded, skipped = _promoted_contracts()
    by_host = {}
    failing = skipped
    for host in targets:
        parts, err = _probe_sections(host, "workloads")
        if err or parts is None or "containers" not in parts:
            print("twins %s: UNVERIFIED %s" % (host, err or "probe sections missing"))
            failing += 1
            continue
        try:
            containers = coverage.parse_containers(parts.get("containers", ""))
        except Refused as refused:
            print("twins %s: UNVERIFIED %s" % (host, refused))
            failing += 1
            continue
        by_host[host] = [row["name"] for row in containers if row["running"]]
    report = authority.judge(loaded, by_host)
    print(authority.render(report))
    if not report["ok"]:
        failing += 1
    journal.append("watch", {"event": "fleet_twins", "hosts": targets,
                             "findings": len(report["findings"]), "failing": failing})
    return 0 if failing == 0 else 1


def _fleet_images(names):
    """Contracted workloads only. A floating ref with no policy is UNPINNED.
    updates: watch notes :latest and does not fail for that alone."""
    from . import coverage, imagepin
    _canonical, targets = _fleet_host_targets(names)
    loaded, skipped = _promoted_contracts()
    policies = imagepin.policies_from(loaded, coverage.names_of)
    rows = []
    failing = skipped
    seen = set()
    for host in targets:
        parts, err = _probe_sections(host, "workloads")
        if err or parts is None or "containers" not in parts or "pods" not in parts:
            print("images %s: UNVERIFIED %s" % (host, err or "probe sections missing"))
            failing += 1
            continue
        try:
            containers = coverage.parse_containers(parts.get("containers", ""))
            pods, pod_error = coverage.parse_pods(parts.get("pods", ""))
        except Refused as refused:
            print("images %s: UNVERIFIED %s" % (host, refused))
            failing += 1
            continue
        if pod_error:
            print("images %s: UNVERIFIED %s" % (host, pod_error))
            failing += 1
            continue
        for row in containers:
            if row["running"]:
                key = (row["name"], row["image"])
                if key not in seen:
                    seen.add(key)
                    rows.append({"name": row["name"], "image": row["image"]})
        for pod in pods:
            if not pod["running"] or pod["namespace"] in coverage.SKIP_NAMESPACES:
                continue
            key = (pod["owner"], pod["image"])
            if key not in seen:
                seen.add(key)
                rows.append({"name": pod["owner"], "image": pod["image"]})
    report = imagepin.judge(rows, policies)
    print(imagepin.render(report))
    if not report["ok"]:
        failing += 1
    journal.append("watch", {"event": "fleet_images", "hosts": targets,
                             "findings": len(report["findings"]), "failing": failing})
    return 0 if failing == 0 else 1


def _fleet_postgres():
    """Shape lint only. Fewer than two declared copies is UNPINNED. No SSH,
    no guessed container names, no SQL."""
    from . import pgtopology
    loaded, skipped = _promoted_contracts()
    report = pgtopology.judge(loaded)
    print(pgtopology.render(report))
    journal.append("watch", {"event": "fleet_postgres", "state": report["state"],
                             "ok": report["ok"], "skipped": skipped})
    if skipped:
        return 1
    return 0 if report["ok"] else 1


def _fleet_os():
    """Declared OS nag. No package scan and no SSH unless a caller injects
    a PRETTY_NAME, which this verb does not."""
    from . import hostos
    canonical, _targets = _fleet_host_targets([])
    findings = hostos.nag(canonical)
    print(hostos.render(findings))
    bad = hostos.failing(findings)
    journal.append("watch", {"event": "fleet_os", "hosts": sorted(canonical), "failing": bad})
    return 0 if bad == 0 else 1


def _governed_docker_hosts():
    """Canonical governed hosts (aliases collapsed) plus each host's alias set,
    from the same governor file both doors read."""
    policy = Guard.load().policy
    hosts = policy.get("hosts", {})
    canonical = {}
    for name, cfg in hosts.items():
        if cfg.get("alias_of"):
            continue
        canonical[name] = {name}
    for name, cfg in hosts.items():
        target = cfg.get("alias_of")
        if target and target in canonical:
            canonical[target].add(name)
    return canonical


def _default_audit_targets(canonical):
    """Hosts a fleet audit covers when none are named: every governed host
    except those the governor marks `audit_by_default: false` (e.g. a busy
    authoritative DNS server, where even a listing can load nat/conntrack
    modules). Name such a host to include it."""
    hosts = Guard.load().policy.get("hosts", {})
    return sorted(h for h in canonical
                  if (hosts.get(h) or {}).get("audit_by_default") is not False)


def _fleet_baseline(names):
    """Snapshot container state per host into inventory/fingerprints/."""
    canonical = _governed_docker_hosts()
    targets = names or sorted(canonical)
    failures = 0
    for host in targets:
        if host not in canonical:
            raise Refused("host %r is not a canonical governed host (aliases "
                          "baseline under their canonical name)" % host)
        try:
            snap = fingerprint.snapshot(host)
            pods = fingerprint.snapshot_pods(host)
        except Exception as e:
            print("SKIP %-24s %s" % (host, str(e)[:120]))
            failures += 1
            continue
        fingerprint.save_baseline(host, snap, pods=pods)
        print("BASELINE %-24s %d container(s), %d pod(s)"
              % (host, len(snap), len(pods)))
    return 0 if failures == 0 else 1


def _fleet_changes(names):
    """Diff live container state against each baseline. A change with zero
    journaled mutations on that host since the baseline is the alarm this
    platform exists to raise: something bypassed the doors."""
    canonical = _governed_docker_hosts()
    targets = names or fingerprint.baselined_hosts()
    if not targets:
        raise Refused("no baselines yet — run `vpscfg fleet baseline` first")
    alarms = 0
    for host in targets:
        aliases = canonical.get(host, {host})
        try:
            current = fingerprint.snapshot(host)
            current_pods = fingerprint.snapshot_pods(host)
        except Exception as e:
            # An unprobeable host is an UNVERIFIED host, not a clean one —
            # a bypasser who breaks the probe must not silence the alarm.
            print("SKIP %-24s cannot verify: %s" % (host, str(e)[:120]))
            alarms += 1
            continue
        rep = fingerprint.report(host, current, aliases=aliases,
                                 current_pods=current_pods)
        print(fingerprint.render(rep))
        if rep["uncovered"]:
            alarms += 1
            journal.append("watch", {"event": "unjournaled_change", "host": host,
                                     "changes": [c[0] for c in rep["uncovered"]]})
    print("fleet changes: %d host(s), %d with UNJOURNALED changes"
          % (len(targets), alarms))
    return 0 if alarms == 0 else 1


def _fleet_secrets():
    """Census every contract's declared credential files. Hashes only —
    contents never leave the host through this path."""
    names = sorted(p.stem for p in CONTRACT_DIR.glob("*.y*ml"))
    problems = 0
    for name in names:
        try:
            contract = contracts.load(name)
        except Refused as r:
            print("SKIP %s: %s" % (name, r))
            continue
        try:
            files, drift_notes = secretscensus.census_report(contract)
        except Refused as r:
            print("SKIP %s: %s" % (name, r))
            continue
        if not files:
            print("--   %-24s no credential files declared" % name)
            continue
        for f in files:
            if f["exists"]:
                print("ok   %-24s %s  sha256=%s…  %db" % (
                    name, f["path"], f["sha256"][:16], f["size"]))
            else:
                print("!!   %-24s %s  MISSING" % (name, f["path"]))
        for path, why in drift_notes:
            print("!!   %-24s %s — %s" % (name, path, why))
            problems += 1
        problems += sum(1 for f in files if not f["exists"])
    print("fleet secrets: %d contract(s), %d problem(s)" % (len(names), problems))
    return 0 if problems == 0 else 1


def _fleet_escrow(rest):
    """Encrypted credential escrow for one contract. Requires --reason."""
    svc = rest[0] if rest and not rest[0].startswith("--") else None
    if not svc:
        raise Refused("escrow requires a service name (its contract)")
    contract = contracts.load(svc)
    res = secretscensus.escrow(contract, _reason_arg(rest))
    print("ESCROW %s: %d file(s), %d bytes -> %s" % (
        svc, len(res["files"]), res["bytes"], res["output"]))
    print("  ciphertext sha256: %s" % res["ciphertext_sha256"])
    print("  decrypt: age -d -i <private key> %s | tar tzf -" % res["output"])
    return 0


def _fleet_watch():
    """Run every non-skeleton contract's verify block. A backend can
    crash-loop unnoticed for weeks: a fleet needs watching, not only
    deploying."""
    from . import journal as _journal
    names = sorted(p.stem for p in CONTRACT_DIR.glob("*.y*ml"))
    if not names:
        raise Refused("no contracts to watch")
    failures = 0
    for name in names:
        try:
            contract = contracts.load(name)
        except Refused as r:
            print("SKIP %s: %s" % (name, r))
            continue
        ok, results = verify.run_checks(contract, contract["host"])
        print(verify.render(name, ok, results))
        if not ok:
            failures += 1
    from . import hostos
    try:
        os_findings = hostos.nag(_governed_docker_hosts())
    except Refused as r:
        # The nag failing must not skip the chain check below.
        print("HOST OS: UNVERIFIED %s" % r)
        eol_bad = None
        failures += 1
    else:
        print(hostos.render(os_findings))
        eol_bad = hostos.failing(os_findings)
        failures += eol_bad
    chain_bad = sum(len(journal.chain_verify(s)["problems"]) for s in journal.streams())
    if chain_bad:
        print("JOURNAL CHAIN: %d broken link(s) — run `vpscfg journal verify`" % chain_bad)
        failures += 1
    _journal.append("watch", {"event": "fleet_watch", "contracts": len(names),
                              "failures": failures, "chain_problems": chain_bad,
                              "eol": eol_bad})
    print("fleet watch: %d contract(s), %d failing" % (len(names), failures))
    return 0 if failures == 0 else 1


def _journal_verify(rest):
    """Verify every journal stream's hash chain (read-only, no network).

    `--against DIR` compares a mirror copy of `<stream>.jsonl`. A longer
    mirror, or a shared prefix that disagrees, is truncation. A longer local
    file is lag. A missing mirror is unverified. The chain alone cannot see
    a shortened tail — see journal.py's Threats note.
    """
    if rest and rest[0] != "verify":
        raise Refused("journal supports one verb: verify [--against DIR] [stream]")
    mirror = None
    names = []
    tokens = rest[1:] if rest else []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--against":
            if mirror is not None or index + 1 >= len(tokens):
                raise Refused("journal verify --against DIR")
            mirror = tokens[index + 1]
            if mirror.startswith("-") or mirror == "":
                raise Refused("journal verify --against DIR")
            index += 2
            continue
        if token.startswith("-"):
            raise Refused("unknown journal flag %r" % token)
        if not journal.STREAM_RE.fullmatch(token):
            raise Refused("invalid journal stream")
        names.append(token)
        index += 1
    if not names:
        names = journal.streams()
        if not names:
            if mirror is not None:
                print("UNVERIFIED")
                return 1
            print("journal verify: no streams yet")
            return 0
    bad = 0
    for name in names:
        res = journal.chain_verify(name)
        print("%s %-12s %d entries, %d chained" % (
            "OK  " if res["ok"] else "FAIL", name, res["entries"], res["chained"]))
        for lineno, why in res["problems"]:
            print("      line %d: %s" % (lineno, why))
            bad += 1
        if mirror is None:
            continue
        try:
            local_text = journal.read_stream(name)
            mirror_text = journal.read_mirror(mirror, name)
        except FileNotFoundError:
            print("UNVERIFIED %s" % name)
            return 1
        except (OSError, ValueError) as exc:
            print("FAIL %-12s %s" % (name, exc))
            bad += 1
            continue
        ok, problems, _local_count, _mirror_count = journal.compare_witness(
            local_text, mirror_text)
        if ok and any(reason == "lag" for _lineno, reason in problems):
            if res["ok"]:
                print("LAG")
            continue
        if not ok:
            for lineno, why in problems:
                print("      line %d: %s" % (lineno, why))
                bad += 1
    return 0 if bad == 0 else 1


def _status(guard):
    p = guard.policy
    print("vpscfg %s — control status" % __version__)
    print("  policy verified via wrapper token: %s" % guard.verified)
    print("  mode: %s   mutation_enabled: %s" % (p["mode"], p["mutation_enabled"]))
    print("  unlocked scopes: %s" % (p["scopes"]["unlocked"] or "NONE"))
    print("  read-only verbs always available: %s" % ", ".join(sorted(READ_ONLY_VERBS)))
    print("  host postures:")
    for h, cfg in sorted(p.get("hosts", {}).items()):
        print("    %-6s %-9s %s" % (h, cfg.get("posture"), cfg.get("reason", "")))
    print("  deny_always entries: %d (floor-checked)" % len(p["deny_always"]))
    return 0
