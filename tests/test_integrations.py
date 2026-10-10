"""Governor-named integrations: telemetry, the Traefik file provider, the
firewall manager, the maintenance-window export and the secret source are
OFF unless the governor names them, and nothing but the governor can name
them (no env var, no $HOME).

Threats: an environment variable redirecting journal events (with the API
key) or choosing the desired state a firewall audit judges against; a
governor value reaching a remote shell unchecked; a desired-state path that
escapes the estate root; an environment variable choosing the maintenance-
window file a gate reads; a secret-source command reaching a shell.
"""
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import (blackout, cli, estate, firewall, integrations, probe, secretput,  # noqa: E402
                    telemetry, vpsexeclog)
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

ENV_ATTEMPTS = {
    "VPSCFG_TELEMETRY_URL": "https://attacker.example.net/v1",
    "FIREWALL_DESIRED_STATE": "/tmp/forged-estate.json",
    "VPSCFG_FIREWALL": "/tmp/forged-estate.json",
    "TRAEFIK_FILE": "/etc/shadow",
    "VPSCFG_TRAEFIK_FILE": "/etc/shadow",
    "VPSCFG_CONTROL_PATH": "/tmp/forged-governor.json",
    "HOME": "/tmp/forged-home",
    "VPSCFG_BLACKOUT_FILE": "/tmp/forged-blackouts.json",
    "VPSCFG_BLACKOUT_MAX_AGE": "999999999",
    "VPSCFG_KEYSTORE": "/tmp/forged-keystore",
}

DESIRED = {"servers": ["192.0.2.10"], "admin": ["198.51.100.7"],
           "private": ["10.0.0.0/8"], "ports": [6379, 5432]}

def fw(desired_state):
    return {"desired_state": desired_state, "script": "/usr/local/sbin/lockdown.sh",
            "unit": "lockdown.service", "installer": "lockdown-install <host>"}


CONFIGURED = {
    "telemetry": {"url": "https://telemetry.example.com/v1/"},
    "traefik": {"host": "web1", "file": "/srv/traefik/dynamic/services.yml"},
    "firewall": fw("estate/firewall.json"),
    "blackout": {"file": "/srv/maintenance/active.json"},
    "secret_source": {"command": ["keystore", "pipe", "--"]},
}


class _Estate(unittest.TestCase):
    """A temp estate root with its own governor; estate.current() points at
    it for the duration of each test."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        self.governor = os.path.join(self.root, "vpscfg-control.json")
        os.mkdir(os.path.join(self.root, "estate"))
        with open(os.path.join(self.root, "estate", "firewall.json"), "w") as f:
            json.dump(DESIRED, f)
        self.write_governor(None)
        patcher = mock.patch.object(integrations.estate, "current",
                                    lambda: estate.Estate(self.root, "default"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def write_governor(self, integ):
        doc = {"version": 1, "mode": "test", "mutation_enabled": False,
               "deny_always": ["x"], "scopes": {"unlocked": []}}
        if integ is not None:
            doc["integrations"] = integ
        with open(self.governor, "w") as f:
            json.dump(doc, f)

    def env(self):
        return mock.patch.dict(os.environ, ENV_ATTEMPTS)


def _no_network(*a, **k):
    raise AssertionError("telemetry dialled out while it should be off")


class DefaultOff(_Estate):
    def test_nothing_named_means_every_integration_is_off(self):
        self.assertIsNone(integrations.telemetry_url())
        self.assertIsNone(integrations.traefik())
        self.assertIsNone(integrations.firewall_desired_state())
        self.assertIsNone(integrations.blackout_file())
        self.assertIsNone(integrations.secret_source())

    def test_missing_governor_is_off_not_a_crash(self):
        os.unlink(self.governor)
        self.assertIsNone(integrations.telemetry_url())

    def test_telemetry_off_pushes_nothing_even_with_a_key(self):
        with mock.patch.object(telemetry, "_key", lambda: "k"), \
                mock.patch.object(telemetry, "_opener", lambda: types.SimpleNamespace(open=_no_network)):
            self.assertFalse(telemetry.enabled())
            self.assertFalse(telemetry.push_event({"event": "x"}))
            state, detail = telemetry.status()
        self.assertEqual(state, "off")
        self.assertIn("LOCAL ONLY", detail)
        self.assertIn("integrations.telemetry.url", detail)

    def test_durability_names_the_governor_fix_when_off(self):
        line = vpsexeclog.durability(3)
        self.assertIn("LOCAL ONLY", line)
        self.assertIn("integrations.telemetry.url", line)

    def test_traefik_probe_refuses_before_dialling(self):
        with mock.patch("vpscfg.sshconfig.load", lambda: {}), \
                mock.patch.object(probe.subprocess, "run", _no_network):
            with self.assertRaises(Refused) as cm:
                probe.run("web1", "traefik")
        self.assertIn("traefik mapping skipped", str(cm.exception))
        self.assertNotIn("traefik", probe.COMMANDS)

    def test_firewall_audit_refuses_with_no_desired_state(self):
        with self.assertRaises(Refused) as cm:
            firewall.load_estate()
        self.assertIn("no desired-state file configured", str(cm.exception))

    def test_no_blackout_file_means_no_window_is_known(self):
        """Unset is the same answer as a missing export file: unknown for
        every host, never inside, and --require-blackout refuses."""
        self.assertEqual(blackout.assess(["web1", "db1"]),
                         ({"web1": None, "db1": None}, "unconfigured"))
        windows, status = blackout.assess(["web1"])
        with self.assertRaises(Refused) as cm:
            blackout.require(windows, status)
        self.assertIn("integrations.blackout.file", str(cm.exception))

    def test_secret_put_from_pipe_refuses_with_no_source(self):
        contracts = {"web": {"service": "web", "secrets": {"sinks": ["/srv/web/.env"]}}}
        with self.assertRaises(Refused) as cm:
            secretput.put(Guard({"hosts": {}}, True), "web1", "shop/db", "/srv/web/.env",
                          False, None, contracts, runner=_no_network, pipe=_no_network)
        self.assertIn("integrations.secret_source.command", str(cm.exception))


class Configured(_Estate):
    def setUp(self):
        super().setUp()
        self.write_governor(CONFIGURED)

    def test_values_come_from_the_governor(self):
        self.assertEqual(integrations.telemetry_url(), "https://telemetry.example.com/v1")
        self.assertEqual(integrations.traefik(),
                         {"host": "web1", "file": "/srv/traefik/dynamic/services.yml"})
        self.assertEqual(integrations.firewall_desired_state(),
                         os.path.join(self.root, "estate", "firewall.json"))
        self.assertEqual(integrations.blackout_file(), "/srv/maintenance/active.json")
        self.assertEqual(integrations.secret_source(), ["keystore", "pipe", "--"])

    def test_blackout_reads_the_named_export_file(self):
        path = os.path.join(self.root, "active.json")
        with open(path, "w") as f:
            json.dump([{"host": "web1"}], f)
        self.write_governor({"blackout": {"file": path}})
        self.assertEqual(blackout.assess(["web1", "db1"]),
                         ({"web1": True, "db1": False}, "ok"))
        os.unlink(path)
        self.assertEqual(blackout.assess(["web1"]), ({"web1": None}, "unavailable"))

    def test_telemetry_posts_to_the_governor_url(self):
        sent = []

        class Resp(object):
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def urlopen(req, timeout=None):
            sent.append(req.full_url)
            return Resp()
        with mock.patch.object(telemetry, "_key", lambda: "k"), \
                mock.patch.object(telemetry, "_opener", lambda: types.SimpleNamespace(open=urlopen)):
            self.assertTrue(telemetry.push_event({"event": "x"}))
            self.assertEqual(telemetry.status(),
                             ("configured", "pushing to https://telemetry.example.com/v1"))
        self.assertEqual(sent, ["https://telemetry.example.com/v1/telemetry/events"])

    def test_traefik_command_cats_the_named_file(self):
        self.assertEqual(probe.traefik_command(),
                         "cat /srv/traefik/dynamic/services.yml 2>/dev/null || echo NO_TRAEFIK_FILE")

    def test_firewall_loads_the_named_desired_state(self):
        loaded = firewall.load_estate()
        self.assertEqual(loaded["servers"], ["192.0.2.10"])
        self.assertEqual(loaded["path"], os.path.join(self.root, "estate", "firewall.json"))


class NoEnvironmentVariable(_Estate):
    def test_env_cannot_turn_an_integration_on(self):
        with self.env():
            self.assertIsNone(integrations.telemetry_url())
            self.assertIsNone(integrations.traefik())
            self.assertIsNone(integrations.firewall_desired_state())
            with mock.patch.object(telemetry, "_key", lambda: "k"), \
                    mock.patch.object(telemetry, "_opener", lambda: types.SimpleNamespace(open=_no_network)):
                self.assertFalse(telemetry.push_event({"event": "x"}))
            with self.assertRaises(Refused):
                firewall.load_estate()
            self.assertIsNone(integrations.blackout_file())
            self.assertIsNone(integrations.secret_source())
            self.assertEqual(blackout.assess(["web1"]), ({"web1": None}, "unconfigured"))

    def test_env_cannot_point_the_blackout_gate_at_a_forged_file(self):
        """VPSCFG_BLACKOUT_FILE used to choose the file; a forged export that
        puts every host in a window must change nothing, configured or not."""
        forged = os.path.join(self.root, "forged.json")
        with open(forged, "w") as f:
            json.dump([{"host": "web1"}], f)
        real = os.path.join(self.root, "real.json")
        with open(real, "w") as f:
            json.dump([], f)
        env = dict(ENV_ATTEMPTS, VPSCFG_BLACKOUT_FILE=forged)
        with mock.patch.dict(os.environ, env):
            self.assertEqual(blackout.assess(["web1"]), ({"web1": None}, "unconfigured"))
            self.write_governor({"blackout": {"file": real}})
            self.assertEqual(blackout.assess(["web1"]), ({"web1": False}, "ok"))
            # A stale named file stays stale whatever VPSCFG_BLACKOUT_MAX_AGE says.
            old = os.stat(real).st_mtime - blackout.EXPORT_MAX_AGE_SECONDS - 60
            os.utime(real, (old, old))
            self.assertEqual(blackout.assess(["web1"]), ({"web1": None}, "unavailable"))

    def test_env_cannot_change_a_configured_value(self):
        self.write_governor(CONFIGURED)
        with self.env():
            self.assertEqual(integrations.telemetry_url(), "https://telemetry.example.com/v1")
            self.assertEqual(integrations.traefik()["file"], "/srv/traefik/dynamic/services.yml")
            self.assertEqual(integrations.firewall_desired_state(),
                             os.path.join(self.root, "estate", "firewall.json"))
            self.assertEqual(integrations.blackout_file(), "/srv/maintenance/active.json")
            self.assertEqual(integrations.secret_source(), ["keystore", "pipe", "--"])

    def test_modules_read_no_environment_for_these(self):
        src = (REPO / "vpscfg" / "integrations.py").read_text()
        for banned in ("os.environ", "getenv", "expanduser", "Path.home", "sys.argv"):
            self.assertNotIn(banned, src)
        self.assertNotIn("VPSCFG_TELEMETRY_URL", (REPO / "vpscfg" / "telemetry.py").read_text())
        fw = (REPO / "vpscfg" / "firewall.py").read_text()
        for banned in ("os.environ", "getenv", "Path.home", "FIREWALL_DESIRED_STATE"):
            self.assertNotIn(banned, fw)
        for mod in ("blackout.py", "secretput.py"):
            src = (REPO / "vpscfg" / mod).read_text()
            for banned in ("os.environ", "getenv", "expanduser", "Path.home"):
                self.assertNotIn(banned, src, mod)


class _Recorder(object):
    """A local HTTP server (127.0.0.1, ephemeral port) that records each
    request's path and X-API-Key and answers with `status` (+ Location)."""

    def __init__(self, status=201, location=None):
        import http.server
        import threading
        seen = self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                seen.append((self.path, self.headers.get("X-API-Key")))
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = _answer

            def log_message(self, *a):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TelemetryTransport(_Estate):
    """The push never follows a redirect and never uses an environment proxy:
    either would hand X-API-Key to something the governor did not name.
    Local servers only; the governor URL is patched to plain http so no TLS
    is needed (the https-only rule is tested in Malformed)."""

    def push_to(self, base, env=None):
        with mock.patch.object(telemetry, "_key", lambda: "sekrit-key"), \
                mock.patch.object(integrations, "telemetry_url", lambda governor=None: base), \
                mock.patch.dict(os.environ, env or {}):
            return telemetry.push_event({"event": "x"}, timeout=5)

    def test_a_redirect_is_a_failure_and_the_key_is_not_resent(self):
        elsewhere = _Recorder(201)
        first = _Recorder(302, location=elsewhere.url + "/stolen")
        self.addCleanup(elsewhere.close)
        self.addCleanup(first.close)
        self.assertFalse(self.push_to(first.url))
        self.assertEqual(first.seen, [("/telemetry/events", "sekrit-key")])
        self.assertEqual(elsewhere.seen, [])

    def test_environment_proxies_are_ignored(self):
        proxy = _Recorder(201)
        target = _Recorder(201)
        self.addCleanup(proxy.close)
        self.addCleanup(target.close)
        env = {"HTTP_PROXY": proxy.url, "http_proxy": proxy.url,
               "HTTPS_PROXY": proxy.url, "https_proxy": proxy.url,
               "ALL_PROXY": proxy.url, "NO_PROXY": "", "no_proxy": ""}
        self.assertTrue(self.push_to(target.url, env))
        self.assertEqual(target.seen, [("/telemetry/events", "sekrit-key")])
        self.assertEqual(proxy.seen, [])
        with mock.patch.dict(os.environ, env):
            handlers = telemetry._opener().handlers
        # An empty ProxyHandler registers no *_open method, so the opener has
        # no proxy handler at all (the default one, which reads the
        # environment, is the one an empty handler replaces).
        self.assertFalse([h for h in handlers
                          if isinstance(h, telemetry.urllib.request.ProxyHandler) and h.proxies])

    def test_key_comes_from_the_vpscfg_name_only(self):
        with mock.patch.dict(os.environ, {"VPSCFG_TELEMETRY_KEY": " k1 \n"}):
            self.assertEqual(telemetry._key(), "k1")
        self.assertEqual(telemetry.KEY_FILE.parts[-3:], (".config", "vpscfgfarm", "telemetry-key"))


class Malformed(_Estate):
    def refuses(self, integ, fn, needle):
        self.write_governor(integ)
        with self.assertRaises(Refused) as cm:
            fn()
        self.assertIn(needle, str(cm.exception))

    def test_telemetry_must_be_https(self):
        for url in ("http://telemetry.example.com/v1", "ftp://x.example.com",
                    "https://x.example.com/v1?k=1", "https://x.example.com/../v1",
                    "https://user@x.example.com/", 7):
            self.refuses({"telemetry": {"url": url}}, integrations.telemetry_url, "https://")

    def test_bad_telemetry_entry_turns_the_antenna_off_without_raising(self):
        self.write_governor({"telemetry": {"url": "http://telemetry.example.com"}})
        with mock.patch.object(telemetry, "_key", lambda: "k"), \
                mock.patch.object(telemetry, "_opener", lambda: types.SimpleNamespace(open=_no_network)):
            self.assertFalse(telemetry.push_event({"event": "x"}))
            state, detail = telemetry.status()
        self.assertEqual(state, "off")
        self.assertIn("misconfigured", detail)

    def test_unknown_or_incomplete_entries_refuse(self):
        self.refuses({"slack": {}}, integrations.telemetry_url, "unknown integration")
        self.refuses({"telemetry": {"url": "https://a.example.com", "key": "s"}},
                     integrations.telemetry_url, "exactly")
        self.refuses({"traefik": {"file": "/a.yml"}}, integrations.traefik, "missing")
        self.refuses([], integrations.telemetry_url, "mapping")
        self.refuses({"firewall": "estate/firewall.json"}, integrations.firewall_desired_state, "mapping")

    def test_traefik_values_cannot_reach_the_shell(self):
        for path in ("relative/x.yml", "/a/../etc/shadow", "/a/./b.yml", "/a//b.yml",
                     "/a/b.yml; rm -rf /", "/a/$(id).yml", "/a/b c.yml", "/"):
            self.refuses({"traefik": {"host": "web1", "file": path}},
                         integrations.traefik, "absolute, normalised")
        for host in ("-oProxyCommand=x", "web1;id", ""):
            self.refuses({"traefik": {"host": host, "file": "/a.yml"}},
                         integrations.traefik, "host")

    def test_desired_state_stays_inside_the_estate(self):
        for rel in ("/etc/firewall.json", "../firewall.json", "estate/../../x.json",
                    "estate//firewall.json", "./estate/firewall.json", ""):
            self.refuses({"firewall": fw(rel)},
                         integrations.firewall_desired_state, "relative")

    def test_desired_state_symlink_directory_or_missing_refuses(self):
        os.symlink(os.path.join(self.root, "estate", "firewall.json"),
                   os.path.join(self.root, "link.json"))
        self.refuses({"firewall": fw("link.json")},
                     integrations.firewall_desired_state, "symlink")
        os.symlink(os.path.join(self.root, "estate"), os.path.join(self.root, "dirlink"))
        self.refuses({"firewall": fw("dirlink/firewall.json")},
                     integrations.firewall_desired_state, "symlink")
        self.refuses({"firewall": fw("estate")},
                     integrations.firewall_desired_state, "not a regular file")
        self.refuses({"firewall": fw("estate/absent.json")},
                     integrations.firewall_desired_state, "firewall desired state")

    def test_blackout_file_is_an_absolute_normalised_path(self):
        for path in ("relative.json", "/a/../etc/x.json", "/a//b.json", "/a/b c.json",
                     "/", "", 7, ["/a.json"]):
            self.refuses({"blackout": {"file": path}}, integrations.blackout_file,
                         "absolute, normalised")

    def test_malformed_blackout_entry_is_an_error_never_a_window(self):
        self.write_governor({"blackout": {"file": "relative.json"}})
        self.assertEqual(blackout.assess(["web1"]), ({"web1": None}, "error"))

    def test_secret_source_is_an_argv_list_of_plain_words(self):
        for argv in ("keystore pipe --", [], ["keystore", "pipe; id"], ["keystore", "$(id)"],
                     ["keystore", "a b"], ["-oProxyCommand=x"], ["../bin/keystore"],
                     ["keystore", 7], ["keystore", ""], ["x"] * 17):
            self.refuses({"secret_source": {"command": argv}}, integrations.secret_source,
                         "argv list")
        self.write_governor({"secret_source": {"command": ["/usr/local/bin/keystore",
                                                           "pipe", "--vault=prod", "--"]}})
        self.assertEqual(integrations.secret_source()[0], "/usr/local/bin/keystore")

    def test_firewall_manager_names_are_checked(self):
        good = fw("estate/firewall.json")
        for key, bad in (("script", "relative/lockdown.sh"), ("script", "/a/../b.sh"),
                         ("script", "/a/b.sh\n"), ("script", "/a/$(id).sh"),
                         ("unit", "-lockdown.service"), ("unit", "lock down.service"),
                         ("unit", "x.service\n"), ("unit", "x;id"), ("unit", ""),
                         ("installer", "a\nb"), ("installer", "run `id`"),
                         ("installer", "$(id)"), ("installer", ""), ("installer", 7)):
            self.refuses({"firewall": dict(good, **{key: bad})},
                         integrations.firewall_manager, "firewall.%s" % key)
        self.refuses({"firewall": {"desired_state": "estate/firewall.json"}},
                     integrations.firewall_manager, "missing")

    def test_firewall_probe_quotes_the_governor_names_and_refuses_when_off(self):
        self.write_governor(None)
        with self.assertRaises(Refused) as cm:
            probe.firewall_command()
        self.assertIn("integrations.firewall", str(cm.exception))
        self.write_governor({"firewall": fw("estate/firewall.json")})
        cmd = probe.firewall_command()
        self.assertIn("for u in lockdown.service netfilter-persistent", cmd)
        self.assertIn("sha256sum /usr/local/sbin/lockdown.sh", cmd)
        self.assertNotIn("@@UNIT@@", cmd)
        self.assertNotIn("@@SCRIPT@@", cmd)
        odd = probe.firewall_command({"unit": "lock.x-1.service", "script": "/opt/x/lock.sh"})
        self.assertIn("for u in lock.x-1.service ", odd)

    def test_a_trailing_newline_never_passes_a_pattern(self):
        self.refuses({"telemetry": {"url": "https://telemetry.example.com/v1\n"}},
                     integrations.telemetry_url, "https://")
        self.refuses({"traefik": {"host": "web1\n", "file": "/a.yml"}},
                     integrations.traefik, "host")
        self.refuses({"traefik": {"host": "web1", "file": "/a.yml\n"}},
                     integrations.traefik, "absolute, normalised")
        self.refuses({"firewall": fw("estate/firewall.json\n")},
                     integrations.firewall_desired_state, "relative")
        self.refuses({"blackout": {"file": "/srv/x.json\n"}},
                     integrations.blackout_file, "absolute, normalised")
        self.refuses({"secret_source": {"command": ["keystore\n", "pipe"]}},
                     integrations.secret_source, "argv list")
        self.refuses({"secret_source": {"command": ["keystore", "pipe\n"]}},
                     integrations.secret_source, "argv list")
        self.assertIsNone(probe.HOST_RE.match("web1\n"))
        self.assertIsNotNone(probe.HOST_RE.match("web1"))

    def test_desired_state_is_read_from_the_descriptor_it_checked(self):
        """The bytes the audit judges and hashes come from the one O_NOFOLLOW
        descriptor; a symlink (file or directory) refuses wherever it is, a
        FIFO refuses without blocking."""
        self.write_governor({"firewall": fw("estate/firewall.json")})
        path, raw = integrations.firewall_desired_state_read()
        self.assertEqual(json.loads(raw), DESIRED)
        loaded = firewall.load_estate()
        import hashlib
        self.assertEqual(loaded["sha256"], hashlib.sha256(raw).hexdigest())
        # swap the real file for a symlink to a forged one: refused, not followed
        forged = os.path.join(self.root, "forged.json")
        with open(forged, "w") as f:
            json.dump(dict(DESIRED, ports=[1]), f)
        real = os.path.join(self.root, "estate", "firewall.json")
        os.rename(real, real + ".bak")
        os.symlink(forged, real)
        with self.assertRaises(Refused) as cm:
            integrations.firewall_desired_state_read()
        self.assertIn("symlink", str(cm.exception))
        with self.assertRaises(Refused):
            firewall.load_estate()
        os.unlink(real)
        os.mkfifo(real)
        with self.assertRaises(Refused) as cm:
            integrations.firewall_desired_state_read()
        self.assertIn("not a regular file", str(cm.exception))

    def test_unparseable_governor_refuses(self):
        with open(self.governor, "w") as f:
            f.write("{not json")
        with self.assertRaises(Refused):
            integrations.traefik()


class HostFacts(unittest.TestCase):
    """Per-host facts that used to be estate host names in tool code: "no
    failover" and "leave out of a default fleet audit" are governor fields."""

    POLICY = {"hosts": {"web1": {"posture": "frozen", "failover": False},
                        "web1.example.internal": {"posture": "frozen", "alias_of": "web1"},
                        "dns1": {"posture": "frozen", "audit_by_default": False},
                        "db1": {"posture": "lockdown"}}}

    def test_failover_comes_from_the_governor(self):
        g = Guard(self.POLICY, True)
        self.assertTrue(g.no_failover("web1"))
        self.assertFalse(g.no_failover("db1"))
        self.assertFalse(g.no_failover("unlisted"))
        self.assertFalse(Guard({"hosts": {"x": "not-a-mapping"}}, True).no_failover("x"))

    def test_default_audit_skips_only_marked_hosts(self):
        with mock.patch.object(cli.Guard, "load", lambda: Guard(self.POLICY, True)):
            canonical = cli._governed_docker_hosts()
            self.assertEqual(cli._default_audit_targets(canonical), ["db1", "web1"])
        with mock.patch.object(cli.Guard, "load", lambda: Guard({"hosts": {
                "dns1": {"posture": "frozen"}, "web1": {"posture": "frozen"}}}, True)):
            self.assertEqual(cli._default_audit_targets(cli._governed_docker_hosts()),
                             ["dns1", "web1"])


if __name__ == "__main__":
    unittest.main()
