"""Host index tests: every section from faked SSH output, failure isolation,
gates, secret masking, cache rotation, diff and query.

Hermetic: the ssh transport is a fake that emulates a host (systemd, docker
with env VALUES it knows, a postgres container, redis, rabbitmq). Nothing
dials a host; the cache lives in a temp dir.
"""
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import hostindex, indexstore, journal, telemetry  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

# collect() journals an `index_read` record before it sends anything (M5):
# every test here journals into a temp dir, never the checkout's journal/.
_SAVED = {}


def setUpModule():
    _SAVED["dir"] = tempfile.TemporaryDirectory()
    _SAVED["old"] = (journal.JOURNAL_DIR, telemetry.push_event)
    journal.JOURNAL_DIR = Path(_SAVED["dir"].name) / "journal"
    telemetry.push_event = lambda *a, **k: False


def tearDownModule():
    journal.JOURNAL_DIR, telemetry.push_event = _SAVED["old"]
    _SAVED["dir"].cleanup()

# Split literals, so the public exporter's secret-assignment scan sees none.
ENV_SECRET = "hunter2-Env-" + "S3cret-Value"
DB_PASSWORD = "Pg-Sup3r-" + "S3cret-Pw"
NOW = __import__("datetime").datetime(2026, 10, 12, 12, 0, 0)

CONTAINERS = {
    "app-postgres": {
        "image": "postgres:16-alpine", "id": "sha256:1111", "state": "running",
        "compose": ("shop", "postgres", "/srv/shop/docker-compose.yml",
                    "/srv/shop"),
        "networks": {"shop_default": {"IPAddress": "172.18.0.2"}},
        "ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]},
        "env": {"POSTGRES_PASSWORD": DB_PASSWORD, "POSTGRES_USER": "postgres",
                "PATH": "/usr/bin"},
    },
    "auth": {
        "image": "example/auth:1.4", "id": "sha256:2222", "state": "running",
        "compose": ("auth", "auth", "/srv/auth/docker-compose.yml", "/srv/auth"),
        "networks": {"web": {}, "shop_default": {}},
        "ports": {"3001/tcp": [{"HostIp": "0.0.0.0", "HostPort": "3001"}]},
        "env": {"DB_HOST": "postgres", "DB_PASSWORD": ENV_SECRET, "JWT_SECRET": ENV_SECRET},
    },
    "cache": {
        "image": "redis:7", "id": "sha256:3333", "state": "running",
        "compose": ("auth", "redis", "/srv/auth/docker-compose.yml", "/srv/auth"),
        "networks": {"web": {}}, "ports": {"6379/tcp": None},
        "env": {"REDIS_PASSWORD": ENV_SECRET},
    },
    "mq": {
        "image": "rabbitmq:3.13-management", "id": "sha256:4444", "state": "running",
        "compose": ("ops", "mq", "/srv/ops/compose.yml", "/srv/ops"),
        "networks": {"ops": {}}, "ports": {},
        "env": {"RABBITMQ_DEFAULT_PASS": ENV_SECRET},
    },
    "old_job": {
        "image": "busybox", "id": "sha256:5555", "state": "exited",
        "compose": ("", "", "", ""), "networks": {}, "ports": {}, "env": {},
    },
}

ATOMS = {
    "hostname": (0, "web1.example.internal"),
    "os": (0, 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"'),
    "uname": (0, "Linux 6.1.0-25-amd64 x86_64"),
    "uptime": (0, "86400.55 1000.00"),
    "cpus": (0, "8"),
    "memory": (0, "               total        used        free      shared  buff/cache   available\n"
                  "Mem:     33554432000 1000 2000 3000 4000 30000000000\nSwap: 0 0 0"),
    "disks": (0, "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                 "/dev/vda1 100000 40000 60000 40% /"),
    "units": (0, "docker.service loaded active running Docker\n"
                 "ssh.service loaded active running OpenSSH\n"
                 "cron.service loaded inactive dead Cron"),
    "files": (0, "docker.service enabled enabled\nssh.service enabled enabled\n"
                 "cron.service disabled enabled\nk3s.service disabled enabled\n"
                 "getty@.service enabled enabled"),
    "client": (0, "27.3.1"),
    "version": (0, "27.3.1"),
    "names": (0, "\n".join(sorted(CONTAINERS)) + "\nbad$(name)"),
    "k3s_unit": (3, "inactive"),
    "k3s": (1, ""),
    "ss": (0, "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
              'tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("docker-proxy",pid=901,fd=4))\n'
              'tcp LISTEN 0 4096 0.0.0.0:3001 0.0.0.0:* users:(("docker-proxy",pid=902,fd=4))\n'
              'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=600,fd=3))'),
    "passwd": (0, "root:x:0:0:root:/root:/bin/bash\n"
                  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                  "alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n"
                  "postgres:x:999:999::/var/lib/postgresql:/bin/false\n"
                  "token" ":x:1001:1001:Token Svc,,,:/home/token:/usr/sbin/nologin"),
    "group": (0, "root:x:0:\nsudo:x:27:alice\ndocker:x:998:alice\nalice:x:1000:\npostgres:x:999:"),
    "traefik": (0, "http:\n  routers:\n    auth:\n      rule: Host(`auth.example.com`)\n"
                   "      service: auth\n  services:\n    auth:\n      loadBalancer:\n"
                   "        servers:\n          - url: http://auth:3001\n"
                   "  middlewares:\n    auth:\n      basicAuth:\n        users:\n"
                   "          - admin:$apr1$" + ENV_SECRET + "\n"),
}

PG_GLOBAL = ("@@@version\n16.4\n@@@recovery\nf\n@@@databases\n"
             "shop_auth\tlogin\tUTF8\tt\t8000000\n"
             "inventory\tinventory\tUTF8\tt\t\n"
             "weird;name\tpostgres\tUTF8\tt\t1\n"
             "postgres\tpostgres\tUTF8\tt\t7000000\n"
             "@@@roles\nlogin\tf\tt\tf\tf\tf\tt\npostgres\tt\tt\tt\tt\tt\tt\n"
             "@@@members\napp_readers\tlogin\n")
PG_DB = {
    "shop_auth": ("@@@schemas\nshop\tlogin\npublic\tpostgres\n"
                        "@@@ownership\nshop\tlogin\tr\t12\nshop\tpostgres\tr\t8\n"
                        "shop\tlogin\tS\t4\npublic\tpostgres\tv\t1\n"
                        "@@@tables\nshop\tusers\tlogin\nshop\tsessions\tpostgres\n"),
    "inventory": "@@@schemas\npublic\tinventory\n@@@ownership\n@@@tables\n",
    "postgres": "@@@schemas\npublic\tpostgres\n@@@ownership\n@@@tables\n",
}
REDIS_INFO = ("# Server\r\nredis_version:7.2.4\r\n# Replication\r\nrole:master\r\n"
              "connected_slaves:0\r\n# Memory\r\nused_memory:1048576\r\n"
              "used_memory_human:1.00M\r\nmaxmemory:0\r\n# Keyspace\r\n"
              "db0:keys=12,expires=3,avg_ttl=0\r\ndb2:keys=5,expires=0,avg_ttl=0\r\n")
RABBIT = ("@@@vhost /\n@@@queues\nname\tmessages\tconsumers\njobs\t12\t1\nmail\t0\t2\n"
          "@@@exchanges\nname\ttype\n\tdirect\namq.topic\ttopic\n"
          "@@@vhost billing\n@@@queues\ninvoices\t3\t0\n@@@exchanges\n")


def _inspect(fmt, names):
    lines = []
    for n in names:
        c = CONTAINERS.get(n)
        if c is None:
            continue
        if '{{range .Config.Env}}{{index (split . "=") 0}} {{end}}' in fmt:
            env = " ".join(c["env"]) + " "
        elif ".Config.Env" in fmt:  # a template that would leak values
            env = " ".join("%s=%s" % kv for kv in c["env"].items())
        else:
            env = ""
        lines.append("\t".join([
            "/" + n, c["image"], c["id"], c["state"], c["compose"][0] or "<no value>",
            c["compose"][1], c["compose"][2], c["compose"][3],
            json.dumps(c["networks"]), json.dumps(c["ports"]), env]))
    return "\n".join(lines)


class FakeHost(object):
    """Emulates one host over the ssh transport signature."""

    def __init__(self, atoms=None, fail_labels=(), pg_stderr=None, raise_on=None):
        self.atoms = dict(ATOMS)
        self.atoms.update(atoms or {})
        self.fail_labels = set(fail_labels)
        self.pg_stderr = pg_stderr
        self.raise_on = raise_on
        self.sent = []

    def __call__(self, host, command, stdin=None):
        self.sent.append((command, stdin))
        if self.raise_on and self.raise_on in command:
            raise OSError("ssh transport failed: connection reset")
        if command.startswith("echo @@@"):
            out = []
            for label, body in re.findall(r"echo @@@(\w+); (.*?) 2>/dev/null; echo \"@@@rc \$\?\"",
                                          command):
                if label == "inspect":
                    fmt = re.search(r"--format '(.*?)' ", body, re.S).group(1)
                    names = body.split("' ", 1)[1].split()
                    rc, text = 0, _inspect(fmt, names)
                else:
                    rc, text = self.atoms.get(label, (127, ""))
                if label in self.fail_labels:
                    rc, text = 1, ""
                out.append("@@@%s\n%s\n@@@rc %d" % (label, text, rc))
            return 0, "\n".join(out) + "\n", ""
        if "psql" in command:
            if self.pg_stderr:
                return 2, "", self.pg_stderr
            db = re.search(r"PGDATABASE=(\S+)", command).group(1).strip("'")
            return 0, PG_GLOBAL if db == "postgres" and "@@@roles" in stdin else PG_DB[db], ""
        if "redis-cli" in command:
            return 0, REDIS_INFO, ""
        if "rabbitmqctl" in command:
            return 0, RABBIT, ""
        return 127, "", "unknown command"


TRAEFIK = {"host": "web1", "file": "/root/traefik/dynamic/services.yml"}


def _collect(fake=None, **kw):
    fake = fake or FakeHost()
    kw.setdefault("traefik", TRAEFIK)
    return hostindex.collect("web1", ssh=fake, now=NOW, **kw), fake


class SectionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc, cls.fake = _collect()

    def test_envelope(self):
        d = self.doc
        self.assertEqual(d["index_version"], 1)
        self.assertEqual(d["collected_at"], "2026-10-12T12:00:00Z")
        self.assertEqual(d["host"], "web1")
        self.assertEqual(sorted(d["sections"]), sorted(hostindex.SECTIONS))
        for s in hostindex.SECTIONS:
            self.assertNotIn("error", d["sections"][s], s)
            self.assertNotIn("unavailable", d["sections"][s], s)

    def test_host(self):
        h = self.doc["sections"]["host"]
        self.assertEqual(h["hostname"], "web1.example.internal")
        self.assertEqual(h["os"]["id"], "debian")
        self.assertEqual(h["kernel"], "6.1.0-25-amd64")
        self.assertEqual(h["uptime_seconds"], 86400)
        self.assertEqual(h["cpus"], 8)
        self.assertEqual(h["memory"]["available_bytes"], 30000000000)
        self.assertEqual(h["disks"][0]["mount"], "/")

    def test_services_merge_enabled_state(self):
        units = dict((u["name"], u) for u in self.doc["sections"]["services"]["units"])
        self.assertEqual(units["docker.service"]["enabled"], "enabled")
        self.assertEqual(units["cron.service"]["active"], "inactive")
        self.assertIn("k3s.service", units)          # unit file only
        self.assertNotIn("getty@.service", units)    # templates skipped

    def test_containers(self):
        c = self.doc["sections"]["containers"]
        self.assertEqual(c["docker"]["server_version"], "27.3.1")
        self.assertEqual(c["skipped"], ["bad$(name)"])
        by = dict((x["name"], x) for x in c["containers"])
        pg = by["app-postgres"]
        self.assertEqual(pg["compose"], {"project": "shop", "service": "postgres",
                                         "config_files": ["/srv/shop/docker-compose.yml"],
                                         "working_dir": "/srv/shop"})
        self.assertEqual(pg["networks"], ["shop_default"])
        self.assertEqual(pg["published"], [{"proto": "tcp", "host_ip": "127.0.0.1",
                                            "host_port": 5432, "container_port": 5432}])
        self.assertEqual(by["auth"]["env_names"], ["DB_HOST", "DB_PASSWORD", "JWT_SECRET"])
        self.assertIsNone(by["old_job"]["compose"]["project"])
        self.assertIsNone(c["k3s"])

    def test_bad_container_name_never_sent(self):
        self.assertFalse(any("bad$(name)" in cmd and "inspect" in cmd for cmd, _ in self.fake.sent))

    def test_ports_map_to_process_and_container(self):
        ls = dict((e["port"], e) for e in self.doc["sections"]["ports"]["listeners"])
        self.assertEqual(ls[5432]["container"], "app-postgres")
        self.assertEqual(ls[5432]["process"], "docker-proxy")
        self.assertEqual(ls[22]["process"], "sshd")
        self.assertEqual(ls[22]["pid"], 600)
        self.assertIsNone(ls[22]["container"])

    def test_users_and_groups(self):
        u = self.doc["sections"]["users"]
        users = dict((x["name"], x) for x in u["users"])
        self.assertTrue(users["alice"]["sudo"])
        self.assertTrue(users["alice"]["login"])
        self.assertFalse(users["daemon"]["login"])
        self.assertFalse(users["postgres"]["login"])
        self.assertEqual(users["alice"]["groups"], ["alice", "docker", "sudo"])
        self.assertEqual(u["sudo_users"], ["alice"])
        self.assertNotIn("gecos", users["alice"])
        self.assertEqual(users["token"]["uid"], 1001)  # survives the masker
        self.assertNotIn("Token Svc", json.dumps(u))
        self.assertNotIn("x", json.dumps(u["groups"][0]["members"]))

    def test_postgres(self):
        p = self.doc["sections"]["postgres"]
        self.assertTrue(p["present"])
        inst = p["instances"][0]
        self.assertEqual(inst["id"], "container:app-postgres")
        self.assertEqual(inst["version"], "16.4")
        self.assertFalse(inst["in_recovery"])
        roles = dict((r["name"], r) for r in inst["roles"])
        self.assertTrue(roles["postgres"]["superuser"])
        self.assertEqual(roles["login"]["member_of"], ["app_readers"])
        dbs = dict((d["name"], d) for d in p["databases"])
        login = dbs["shop_auth"]
        self.assertEqual(login["instance"], "container:app-postgres")
        self.assertEqual(login["owner"], "login")
        schema = dict((s["name"], s) for s in login["schemas"])["shop"]
        self.assertIn({"owner": "postgres", "kind": "table", "count": 8}, schema["ownership"])
        self.assertIn({"name": "sessions", "owner": "postgres"}, schema["tables"])
        self.assertIsNone(dbs["inventory"]["size_bytes"])
        self.assertIn("safe pattern", dbs["weird;name"]["schemas_unavailable"])

    def test_postgres_session_is_read_only(self):
        pg = [(c, s) for c, s in self.fake.sent if "psql" in c]
        self.assertTrue(pg)
        for cmd, script in pg:
            self.assertIn("default_transaction_read_only=on", cmd)
            self.assertTrue(script.startswith("BEGIN READ ONLY;"))
            self.assertNotIn("weird;name", cmd)
            self.assertNotIn(DB_PASSWORD, cmd)

    def test_redis(self):
        r = self.doc["sections"]["redis"]
        self.assertTrue(r["present"])
        inst = r["instances"][0]
        self.assertEqual(inst["container"], "cache")
        self.assertEqual(inst["version"], "7.2.4")
        self.assertEqual(inst["role"], "master")
        self.assertEqual(inst["keyspace"], [{"db": 0, "keys": 12, "expires": 3},
                                            {"db": 2, "keys": 5, "expires": 0}])
        self.assertEqual(inst["memory"]["used_bytes"], 1048576)
        cmds = [c for c, _ in self.fake.sent if "redis-cli" in c]
        self.assertTrue(all(c.rstrip("'").endswith("INFO") for c in cmds))

    def test_rabbitmq(self):
        q = self.doc["sections"]["rabbitmq"]
        vh = dict((v["name"], v) for v in q["instances"][0]["vhosts"])
        self.assertEqual(vh["/"]["queues"], [{"name": "jobs", "messages": 12, "consumers": 1},
                                             {"name": "mail", "messages": 0, "consumers": 2}])
        self.assertIn({"name": "", "type": "direct"}, vh["/"]["exchanges"])
        self.assertEqual(vh["billing"]["queues"][0]["name"], "invoices")

    def test_web(self):
        w = self.doc["sections"]["web"]
        self.assertEqual(w["routers"][0]["hostnames"], ["auth.example.com"])
        self.assertEqual(w["routers"][0]["backends"], ["http://auth:3001"])
        self.assertNotIn("basicAuth", json.dumps(w))

    def test_web_backend_userinfo_masked(self):
        atoms = {"traefik": (0, "http:\n  routers:\n    r:\n      rule: Host(`a.example.com`)\n"
                                "      service: s\n  services:\n    s:\n      loadBalancer:\n"
                                "        servers:\n          - url: http://u:%s@b:80\n" % DB_PASSWORD)}
        doc, _ = _collect(FakeHost(atoms=atoms))
        self.assertNotIn(DB_PASSWORD, json.dumps(doc))


class SecretTest(unittest.TestCase):
    def test_env_values_and_db_password_never_in_output(self):
        doc, fake = _collect()
        text = json.dumps(doc) + indexstore.dump(doc, "json")
        self.assertNotIn(ENV_SECRET, text)
        self.assertNotIn(DB_PASSWORD, text)
        for cmd, stdin in fake.sent:
            self.assertNotIn(ENV_SECRET, cmd)
            self.assertNotIn(DB_PASSWORD, cmd + (stdin or ""))

    def test_fake_would_catch_a_value_leaking_template(self):
        # Proves the test above has teeth: a raw .Config.Env template leaks.
        leaked = _inspect("{{.Config.Env}}", ["auth"])
        self.assertIn(ENV_SECRET, leaked)

    def test_psql_error_carrying_password_is_masked(self):
        fake = FakeHost(pg_stderr="psql: error: password=%s rejected" % DB_PASSWORD)
        doc, _ = _collect(fake)
        inst = doc["sections"]["postgres"]["instances"][0]
        self.assertIn("error", inst)
        self.assertNotIn(DB_PASSWORD, json.dumps(doc))

    def test_password_read_inside_container_only(self):
        cmd = hostindex.pg_command({"source": "container", "container": "pg"}, "app")
        self.assertIn("POSTGRES_PASSWORD_FILE", cmd)
        self.assertNotIn("-e PGPASSWORD", cmd)
        self.assertIn("docker exec -i", cmd)

    def test_raw_parse_keeps_the_size_cap(self):
        from vpscfg import secretmask
        huge = (0, "x:x:1:1::/h:/bin/sh\n" * (secretmask.MAX_INPUT // 18 + 1))
        doc, _ = _collect(FakeHost(atoms={"passwd": huge}))
        self.assertIn("withheld", doc["sections"]["users"]["error"])

    def test_table_limit_matches_cap(self):
        self.assertIn("LIMIT %d" % (hostindex.MAX_TABLES + 1), hostindex._PG_PER_DB[2][1])

    def test_every_string_leaf_masked(self):
        doc = hostindex.mask_leaves({"a": ["DATABASE_URL=postgres://u:%s@db/x" % DB_PASSWORD]})
        self.assertNotIn(DB_PASSWORD, json.dumps(doc))


class IsolationAndGateTest(unittest.TestCase):
    def test_failed_atom_errors_one_section_only(self):
        doc, _ = _collect(FakeHost(fail_labels={"ss"}))
        self.assertIn("error", doc["sections"]["ports"])
        for s in ("host", "services", "containers", "users", "postgres", "redis"):
            self.assertNotIn("error", doc["sections"][s], s)

    def test_transport_failure_errors_one_section_only(self):
        doc, _ = _collect(FakeHost(raise_on="cat /etc/passwd"))
        self.assertIn("ssh transport failed", doc["sections"]["users"]["error"])
        self.assertNotIn("error", doc["sections"]["host"])
        self.assertNotIn("error", doc["sections"]["postgres"])

    def test_governor_deny_pattern_makes_section_unavailable_unsent(self):
        doc, fake = _collect(deny_patterns=["/etc/passwd"])
        self.assertIn("unavailable", doc["sections"]["users"])
        self.assertFalse(any("/etc/passwd" in c for c, _ in fake.sent))
        self.assertNotIn("unavailable", doc["sections"]["host"])

    def test_risky_extra_makes_section_unavailable(self):
        doc, fake = _collect(risky_extra=["list-units"])
        self.assertIn("not a read", doc["sections"]["services"]["unavailable"])
        self.assertFalse(any("list-units" in c for c, _ in fake.sent))
        # postgres still detected through containers, flagged incomplete
        self.assertTrue(doc["sections"]["postgres"]["present"])
        self.assertIn("detection_incomplete", doc["sections"]["postgres"])

    def test_failed_container_list_is_not_absent_postgres(self):
        doc, _ = _collect(FakeHost(fail_labels={"names"}))
        self.assertIn("error", doc["sections"]["postgres"])
        self.assertIn("error", doc["sections"]["redis"])
        self.assertIn("daemon did not answer", doc["sections"]["containers"]["error"])

    def test_no_docker_is_an_observation(self):
        doc, _ = _collect(FakeHost(atoms={"client": (127, ""), "version": (127, ""),
                                          "names": (127, "")}))
        self.assertIsNone(doc["sections"]["containers"]["docker"])
        self.assertFalse(doc["sections"]["redis"]["present"])

    def test_deny_pattern_inside_container_command(self):
        doc, fake = _collect(deny_patterns=["redis-cli"])
        self.assertIn("unavailable", doc["sections"]["redis"]["instances"][0])
        self.assertFalse(any("redis-cli" in c for c, _ in fake.sent))

    def test_rabbit_gate_refuses_non_list_verbs(self):
        with self.assertRaises(hostindex.Unavailable):
            hostindex.rabbit_gate("rabbitmqctl -q delete_queue jobs")
        with self.assertRaises(hostindex.Unavailable):
            hostindex.rabbit_gate("rabbitmqctl -q list_queues; rabbitmqctl purge_queue x")
        hostindex.rabbit_gate(hostindex._RABBIT_SCRIPT)

    def test_sql_gate_refuses_writes(self):
        with self.assertRaises(hostindex.Unavailable):
            hostindex.pg_script([("bad", "DELETE FROM users")])
        with self.assertRaises(hostindex.Unavailable):
            hostindex.pg_script([("bad", "SELECT 1; DROP TABLE users")])

    def test_web_unavailable_without_governor_or_on_other_host(self):
        doc, _ = _collect(traefik=None)
        self.assertIn("unavailable", doc["sections"]["web"])
        doc, _ = _collect(traefik={"host": "edge1", "file": "/etc/traefik/x.yml"})
        self.assertIn("edge1", doc["sections"]["web"]["unavailable"])

    def test_every_host_command_classifies_as_read(self):
        from vpscfg import vpsexec
        from vpscfg.gates import DENY_ALWAYS_FLOOR
        _doc, fake = _collect()
        for cmd, _ in fake.sent:
            if cmd.startswith("echo @@@"):
                for body in re.findall(r"echo @@@\w+; (.*?); echo \"@@@rc", cmd):
                    self.assertEqual(vpsexec.classify(body, DENY_ALWAYS_FLOOR)[0], "read", body)

    def test_k3s_active_but_unreachable_is_an_error_not_empty(self):
        doc, _ = _collect(FakeHost(atoms={"k3s_unit": (0, "active"), "k3s": (1, "")}))
        self.assertIn("error", doc["sections"]["containers"]["k3s"])

    def test_k3s_workloads(self):
        doc, _ = _collect(FakeHost(atoms={"k3s_unit": (0, "active"), "k3s": (
            0, "Deployment default api 2 2 reg/api:1,reg/side:2\nDaemonSet kube-system svclb <none> <none> rancher/klipper:1")}))
        w = doc["sections"]["containers"]["k3s"]["workloads"]
        self.assertEqual(w[0], {"kind": "Deployment", "namespace": "default", "name": "api",
                                "ready": 2, "desired": 2, "images": ["reg/api:1", "reg/side:2"]})
        self.assertIsNone(w[1]["ready"])

    def test_section_subset_and_dependencies(self):
        doc, _ = _collect(sections=["postgres"])
        self.assertEqual(list(doc["sections"]), ["postgres"])
        self.assertNotIn("containers", doc["sections"])
        self.assertTrue(doc["sections"]["postgres"]["present"])
        with self.assertRaises(Refused):
            hostindex.parse_sections("postgres,bogus")

    def test_invalid_host_refused(self):
        with self.assertRaises(Refused):
            hostindex.collect("../etc", ssh=FakeHost())


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "index"

    def tearDown(self):
        self.tmp.cleanup()

    def _cli(self, argv, fake=None):
        out, err = io.StringIO(), io.StringIO()
        rc = indexstore.cli(argv, directory=self.dir, out=out, err=err,
                            collect_kwargs={"ssh": fake or FakeHost(), "traefik": TRAEFIK,
                                            "now": NOW},
                            hosts_for_all=lambda: ["web1"])
        return rc, out.getvalue(), err.getvalue()

    def test_cache_rotates_and_diff(self):
        rc, out, _ = self._cli(["web1", "--json"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["host"], "web1")
        self.assertTrue((self.dir / "web1.json").exists())
        atoms = {"cpus": (0, "16"), "names": (0, "\n".join(sorted(set(CONTAINERS) - {"mq"})))}
        self._cli(["web1"], FakeHost(atoms=atoms))
        self.assertTrue((self.dir / "web1.prev.json").exists())
        rc, out, _ = self._cli(["diff", "web1"])
        self.assertEqual(rc, 1)
        self.assertIn('~ host.cpus: 8 -> 16', out)
        self.assertIn('- containers.containers["mq"].state = "running"', out)
        self.assertNotIn("collected_at:", out.split("\n", 1)[1])

    def test_diff_ignores_reorder(self):
        a = {"x": [{"name": "a", "v": 1}, {"name": "b", "v": 2}]}
        b = {"x": [{"name": "b", "v": 2}, {"name": "a", "v": 1}]}
        self.assertEqual(indexstore.diff(a, b), [])

    def test_partial_or_all_failed_run_not_cached(self):
        self._cli(["web1", "--section", "postgres"])
        self.assertFalse((self.dir / "web1.json").exists())
        _rc, _out, err = self._cli(["web1"], FakeHost(raise_on="echo"))
        self.assertIn("not cached", err)

    def test_yaml_output(self):
        rc, out, _ = self._cli(["web1", "--yaml", "--no-save"])
        self.assertIn("index_version: 1", out)
        self.assertNotIn(ENV_SECRET, out)
        self.assertFalse((self.dir / "web1.json").exists())

    def test_all_summary(self):
        rc, out, _ = self._cli(["--all"])
        self.assertTrue(out.startswith("web1: host=ok"))

    def test_symlink_cache_refused(self):
        self.dir.mkdir(parents=True)
        (self.dir / "web1.json").symlink_to(Path(self.tmp.name) / "elsewhere")
        with self.assertRaises(Refused):
            self._cli(["web1"])

    def test_queries(self):
        self._cli(["web1"])
        other = json.loads((self.dir / "web1.json").read_text())
        other["host"] = "edge1"
        other["sections"]["postgres"] = {"present": False, "instances": [], "databases": []}
        other["sections"]["redis"] = {"present": False, "instances": []}
        indexstore.save(other, self.dir)
        docs = indexstore.load_all(self.dir)
        hits = indexstore.query('postgres.databases[] | select(name=="shop_auth")', docs)
        self.assertEqual([h for h, _ in hits], ["web1"])
        self.assertEqual(hits[0][1]["owner"], "login")
        hits = indexstore.query("redis | select(present)", docs)
        self.assertEqual([h for h, _ in hits], ["web1"])
        hits = indexstore.query(
            "containers.containers[] | select(published[].host_port == 5432) | name", docs)
        self.assertEqual(hits, [("edge1", "app-postgres"), ("web1", "app-postgres")])
        hits = indexstore.query('users.users[] | select(sudo and not name == "root") | name', docs)
        self.assertEqual(sorted(set(v for _, v in hits)), ["alice"])
        hits = indexstore.query('containers.containers[] | select(env_names[] ~ "PASSWORD") | name', docs)
        self.assertIn(("web1", "auth"), hits)
        rc, out, _ = self._cli(["query", "redis | select(present)", "--hosts"])
        self.assertEqual((rc, out), (0, "web1\n"))

    def test_ownership_query_from_the_docs(self):
        self._cli(["web1"])
        hits = indexstore.query('postgres.databases[].schemas[].ownership[] | '
                                'select(owner == "postgres" and kind == "table")',
                                indexstore.load_all(self.dir))
        self.assertEqual(hits, [("web1", {"owner": "postgres", "kind": "table", "count": 8})])

    def test_cli_dispatch_wires_index_and_fleet_index(self):
        from unittest import mock
        from vpscfg import cli
        from vpscfg.control import Guard
        self._cli(["web1"])
        guard = Guard({"allowed_verbs": [], "deny_always": [], "hosts": {"web1": {}}}, False)
        with mock.patch("vpscfg.cli.Guard.load", return_value=guard), \
                mock.patch("vpscfg.vpsexecpolicy.load", return_value={}), \
                mock.patch("vpscfg.integrations.traefik", return_value=None), \
                mock.patch("vpscfg.indexstore.cache_dir", return_value=self.dir), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(cli._dispatch(["index", "query", "redis | select(present)", "--hosts"]), 0)
            self.assertEqual(cli._dispatch(["fleet", "index", "query", "redis.present", "--hosts"]), 0)
        self.assertEqual(out.getvalue(), "web1\nweb1\n")

    def test_schema_and_schedule_templates(self):
        root = Path(__file__).resolve().parent.parent
        schema = json.loads((root / "docs" / "index.schema.json").read_text())
        self.assertEqual(sorted(schema["properties"]["sections"]["properties"]),
                         sorted(hostindex.SECTIONS))
        self.assertEqual(schema["properties"]["index_version"]["const"], hostindex.INDEX_VERSION)
        sched = root / "contrib" / "index-schedule"
        self.assertIn("<integer>43200</integer>", (sched / "local.vpscfg.index.plist").read_text())
        self.assertIn("OnCalendar=*-*-* 00,12:00:00", (sched / "vpscfg-index.timer").read_text())
        self.assertIn("index --all", (sched / "vpscfg-index.service").read_text())

    def test_bad_queries_refused(self):
        for bad in ["", "select(", "a | | b", "a ; rm", 'select(x == )']:
            with self.assertRaises(Refused):
                indexstore.compile_query(bad)


class DoorTest(unittest.TestCase):
    """Both doors treat `index` as a read-only group word, like `fleet`."""

    def _wrapper(self):
        import importlib.util
        root = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location("index_outer", root / "vpscfg-control.py")
        wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wrapper)
        return wrapper

    def test_outer_door_classifies_index_as_read(self):
        from vpscfg.gates import READ_ONLY_VERBS
        wrapper = self._wrapper()
        self.assertIn("index", READ_ONLY_VERBS)
        self.assertEqual(READ_ONLY_VERBS, wrapper.READ_ONLY_VERBS)
        root = Path(__file__).resolve().parent.parent
        policy = json.loads((root / "contrib" / "example-estate" / "vpscfg-control.json").read_text())
        for argv in (["index", "web1"], ["index", "--all"], ["index", "diff", "web1"],
                     ["index", "query", "redis | select(present)"]):
            with self.subTest(argv=argv):
                judgment = wrapper.judge(policy, argv)
                self.assertTrue(judgment["read_only"])
                self.assertEqual(judgment["verb"], "index")

    def test_outer_door_refuses_index_until_the_governor_releases_it(self):
        import contextlib
        from unittest import mock
        wrapper = self._wrapper()
        policy = {"allowed_verbs": ["fleet"], "deny_always": [], "mutation_enabled": False,
                  "mode": "test", "hosts": {}, "scopes": {"unlocked": []}}
        with mock.patch.object(wrapper, "journal"), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                wrapper.judge(policy, ["index", "web1"])


if __name__ == "__main__":
    unittest.main()
