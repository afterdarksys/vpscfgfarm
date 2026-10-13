"""P1b: recreate and tag_image (vpscfg/actions/container.py) and install_pushed
(vpscfg/actions/file.py). docs/ACTIONS.md is the contract.

Hermetic: the door talks to a scripted fake host that keeps state (so a
second run can be a no-op), or a body runs under local bash with a fake
`docker` first on PATH. The journal is redirected. Nothing dials a host.

What is proven here:
  S1  no body, check or verify hits the floor; every value is a quoted word
  S5  parameters are typed literals (accept/refuse, injection corpus, YAML
      type confusion through the real loader)
  S6  checks and verifies are reads; a check that prints anything but one
      token, exits non-zero or loses the transport fails the host closed
  S11 recreate's compose fields come only from typed parameters, are emitted
      as assumes for preflight, and are re-checked by the body on the host
  idempotency: tag_image and install_pushed run twice on the fake host; the
      second run is [done] and sends no body. recreate is not idempotent.
"""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_actions_core as core  # noqa: E402
import test_vpsexec as tv  # noqa: E402
from vpscfg import actions, vpsexec  # noqa: E402
from vpscfg.actions import base  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused, deny_scan  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "tests" / "golden" / "actions"
DENY = list(DENY_ALWAYS_FLOOR)
SHA = "3f1c" + "0" * 56 + "a1e9"
NAMES = ("recreate", "tag_image", "install_pushed")

RECREATE = {"container": "shop-web-1", "project": "shopstack", "service": "frontend",
            "working_dir": "/opt/shop", "config_files": ["/srv/compose/shop.yml"]}
TAG = {"image_ref": "shop/web:1.5", "new_tag": "shop/web:rollback"}
INSTALL = {"sha256": SHA, "basename": "diskwatch-0.8.0", "dest": "/usr/local/bin/diskwatch",
           "mode": "0755", "owner": "root"}
VALID = {"recreate": RECREATE, "tag_image": TAG, "install_pushed": INSTALL}

# A wider valid corpus for the floor and quoting sweep and the read checks.
CORPUS = [
    ("recreate", RECREATE),
    ("recreate", dict(RECREATE, healthy=True, tries=30, interval=20)),
    ("recreate", {"container": "shop-db", "project": "shop_2", "service": "db.primary",
                  "working_dir": "/srv/stack", "config_files": [
                      "/etc/compose/a.yml", "/etc/compose/b.yml", "/etc/compose/c.yml",
                      "/etc/compose/d.yml"]}),
    ("tag_image", TAG),
    ("tag_image", {"image_ref": "postgres:16", "new_tag": "shop/db-base:pinned"}),
    ("tag_image", {"image_ref": "registry.example.com:5000/shop/web@sha256:" + "c" * 64,
                   "new_tag": "registry.example.com:5000/shop/web:stable"}),
    ("install_pushed", INSTALL),
    ("install_pushed", {"sha256": "d" * 64, "basename": "shop.conf",
                        "dest": "/etc/shop/app.conf", "mode": "0600", "owner": "root"}),
    ("install_pushed", {"sha256": "e" * 64, "basename": "motd.txt", "dest": "/etc/motd",
                        "mode": "0644", "owner": "root"}),
]


def entry(name, params, hosts=("edge1",), break_glass=False):
    """A loaded runbook entry naming one action call, as the loader builds it."""
    exps = dict((h, actions.expand(name, params, h)) for h in hosts)
    first = exps[hosts[0]]
    return {"hosts": list(hosts), "cmd": first.canonical, "where": "host", "why": "test",
            "break_glass": break_glass, "source": "p1b.yaml", "expires": "2999-01-01",
            "verify": first.verify_text(), "timeout": first.timeout, "rollback": False,
            "verify_retry": first.verify_retry, "container": None,
            "action": {"name": name, "version": first.version, "params": first.params,
                       "tier": first.tier, "expansions": exps}}


# ---------------------------------------------------------------------------
# S5: parameters
# ---------------------------------------------------------------------------

class ParamTest(unittest.TestCase):
    def refuses(self, name, word, **over):
        with self.assertRaises(Refused, msg="%s %r" % (name, over)) as cm:
            actions.expand(name, dict(VALID[name], **over), "web1")
        self.assertIn(word, str(cm.exception))

    def test_valid_corpus_expands(self):
        for name, params in CORPUS:
            exp = actions.expand(name, params, "web1")
            self.assertEqual(exp.tier, "mutation")
        self.assertFalse(actions.expand("recreate", RECREATE, "web1").idempotent)
        self.assertTrue(actions.expand("tag_image", TAG, "web1").idempotent)
        self.assertTrue(actions.expand("install_pushed", INSTALL, "web1").idempotent)

    def test_recreate_refusals(self):
        self.refuses("recreate", "with.config_files", config_files=[])
        self.refuses("recreate", "with.config_files", config_files="/srv/compose/shop.yml")
        self.refuses("recreate", "with.config_files",
                     config_files=["/a.yml", "/b.yml", "/c.yml", "/d.yml", "/e.yml"])
        self.refuses("recreate", "with.config_files", config_files=["compose.yml"])
        self.refuses("recreate", "with.config_files", config_files=["/a.yml", "/a.yml"])
        self.refuses("recreate", "with.working_dir", working_dir="/opt/shop/")
        self.refuses("recreate", "with.project", project="-p")
        self.refuses("recreate", "with.service", service="web front")
        self.refuses("recreate", "with.healthy", healthy="yes")
        self.refuses("recreate", "600s", tries=30, interval=21)
        with self.assertRaises(Refused) as cm:
            actions.expand("recreate", {k: v for k, v in RECREATE.items() if k != "project"},
                           "web1")
        self.assertIn("with.project is missing", str(cm.exception))

    def test_tag_image_refusals(self):
        self.refuses("tag_image", "new_tag must be a full reference", new_tag="shop/web")
        self.refuses("tag_image", "new_tag must be a full reference",
                     new_tag="shop/web@sha256:" + "a" * 64)
        self.refuses("tag_image", "new_tag must be a full reference",
                     new_tag="registry.example.com:5000/shop/web")
        self.refuses("tag_image", "bare repository", image_ref="shop/web")
        self.refuses("tag_image", "same reference", new_tag="shop/web:1.5")
        self.refuses("tag_image", "with.image_ref", image_ref="Shop/Web:1.5")

    def test_install_pushed_refusals(self):
        self.refuses("install_pushed", "with.mode", mode=420)         # YAML 0644
        self.refuses("install_pushed", "with.mode", mode="0777")
        self.refuses("install_pushed", "with.mode", mode="644")
        self.refuses("install_pushed", "with.owner", owner="alice")
        self.refuses("install_pushed", "with.sha256", sha256=SHA.upper())
        self.refuses("install_pushed", "with.sha256", sha256=SHA[:-1])
        self.refuses("install_pushed", "with.basename", basename=".hidden")
        self.refuses("install_pushed", "with.basename", basename="a/b")
        self.refuses("install_pushed", "with.dest", dest="/usr/local/bin/")
        self.refuses("install_pushed", "with.dest", dest="/usr/local/../bin/x")

    def test_injection_corpus_is_refused_for_every_string_param(self):
        for name in NAMES:
            action = base.REGISTRY[name]
            for pname, spec in sorted(action.params.items()):
                if spec.type.name.startswith(("int_range", "flag")):
                    continue
                for value in core.ParamTypeTest.INJECTIONS:
                    v = [value] if spec.type.name.startswith("list_of") else value
                    with self.assertRaises(Refused, msg="%s.%s=%r" % (name, pname, value)):
                        actions.expand(name, dict(VALID[name], **{pname: v}), "web1")


class YamlTypeConfusionTest(core._PolicyDir):
    def policy(self, action, with_):
        return textwrap.dedent("""\
            version: 1
            expires: "2026-12-31"
            reason: p1b loader test
            shape: {steps: 1, hosts: [edge1], break_glass: false}
            runbooks:
              - hosts: [edge1]
                action: %s
                with: %s
                why: "S1: test"
            """ % (action, with_))

    def test_type_confusion_refuses_the_load(self):
        inst = "sha256: %s, basename: diskwatch-0.8.0, dest: /usr/local/bin/diskwatch" % SHA
        rec = ("container: shop-web-1, project: shopstack, service: frontend, "
               "working_dir: /opt/shop")
        for action, with_, word in (
                ("install_pushed", "{%s, mode: 0644, owner: root}" % inst, "with.mode"),
                ("install_pushed", "{%s, mode: '0644', owner: yes}" % inst, "with.owner"),
                ("recreate", "{%s, config_files: /srv/compose/shop.yml}" % rec,
                 "with.config_files"),
                ("recreate", "{%s, config_files: [/srv/compose/shop.yml], healthy: on}" % rec,
                 "with.healthy"),
                ("recreate", "{%s, config_files: [/srv/compose/shop.yml], tries: '20'}" % rec,
                 "with.tries"),
                ("tag_image", "{image_ref: shop/web:1.5, new_tag: [shop/web:rollback]}",
                 "with.new_tag"),
                ("tag_image", "[shop/web:1.5, shop/web:rollback]", "mapping")):
            self.write(self.policy(action, with_))
            with self.assertRaises(Refused, msg=with_) as cm:
                self.load()
            self.assertIn(word, str(cm.exception), with_)

    def test_quoted_mode_and_recreate_load_with_their_assumes(self):
        inst = "sha256: %s, basename: diskwatch-0.8.0, dest: /usr/local/bin/diskwatch" % SHA
        path = self.armed(self.policy("install_pushed", "{%s, mode: '0644', owner: root}"
                                      % inst))
        self.assertEqual(self.load()["misshapen"], [])
        path.unlink()
        self.armed(self.policy("recreate", "{container: shop-web-1, project: shopstack, "
                                           "service: frontend, working_dir: /opt/shop, "
                                           "config_files: [/srv/compose/shop.yml]}"))
        pol = self.load()
        self.assertEqual(pol["misshapen"], [])
        (rb,) = pol["runbooks"]
        self.assertEqual(rb["action"]["name"], "recreate")


# ---------------------------------------------------------------------------
# golden files, S1 floor sweep, S6 read classification
# ---------------------------------------------------------------------------

class GoldenTest(unittest.TestCase):
    def test_golden_files_match(self):
        for name in NAMES:
            action = base.REGISTRY[name]
            want = json.loads((GOLDEN / ("%s@%d.json" % (name, action.version))).read_text())
            self.assertEqual(core._golden_doc(action), want, name)

    def test_one_byte_drift_is_caught(self):
        for name in NAMES:
            action = base.REGISTRY[name]
            want = json.loads((GOLDEN / ("%s@%d.json" % (name, action.version))).read_text())
            real = type(action).build

            def drifted(self, p, host, real=real):
                out = real(self, p, host)
                return dict(out, body=out["body"] + " ")
            type(action).build = drifted
            try:
                self.assertNotEqual(core._golden_doc(action), want, name)
            finally:
                type(action).build = real

    def test_wait_healthy_is_unchanged(self):
        self.assertEqual(base.REGISTRY["wait_healthy"].version, 1)


class FloorSweepTest(unittest.TestCase):
    def test_no_text_hits_the_floor_and_values_are_quoted(self):
        for name, params in CORPUS:
            exp = actions.expand(name, params, "web1")
            for text in [exp.canonical] + exp.texts():
                deny_scan(text, DENY)
            values = []
            for v in exp.params.values():
                values += v if isinstance(v, list) else [v]
            texts = [exp.body] + [p for p in (exp.check, exp.verify) if isinstance(p, str)]
            for value in (v for v in values if isinstance(v, str)):
                for text in texts:
                    start = text.find(value)
                    while start != -1:
                        end = start + len(value)
                        self.assertTrue(
                            text[start - 1:start] == "'" and text[end:end + 1] == "'",
                            "%s: %r appears outside single quotes in %r" % (name, value, text))
                        start = text.find(value, end)

    def test_checks_and_verifies_are_reads(self):
        for name, params in CORPUS:
            exp = actions.expand(name, params, "web1")
            for probe_text in (exp.check, exp.verify):
                if probe_text is not None:
                    self.assertEqual(vpsexec.classify(probe_text, DENY)[0], "read",
                                     "%s: %r" % (name, probe_text))

    def test_recreate_assumes_pin_the_compose_fields(self):
        exp = actions.expand("recreate", CORPUS[2][1], "web1")
        (item,) = exp.assumes
        self.assertEqual(item["host"], "web1")
        self.assertEqual(item["container"], "shop-db")
        self.assertEqual(item["compose_files"], CORPUS[2][1]["config_files"])
        self.assertEqual(item["compose_labels"], {
            "com.docker.compose.project": "shop_2",
            "com.docker.compose.service": "db.primary",
            "com.docker.compose.project.working_dir": "/srv/stack",
            "com.docker.compose.project.config_files":
                "/etc/compose/a.yml,/etc/compose/b.yml,/etc/compose/c.yml,/etc/compose/d.yml"})


# ---------------------------------------------------------------------------
# recreate's body on local bash with a fake docker: the label guard
# ---------------------------------------------------------------------------

FAKE_DOCKER = """#!/bin/sh
if [ "$1" = inspect ]; then printf '%s\\n' "$FAKE_LABELS"; exit 0; fi
if [ "$1" = compose ]; then shift; printf '%s\\n' "$@" > "$FAKE_LOG"; exit 0; fi
exit 9
"""


class RecreateBodyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        (root / "bin").mkdir()
        docker = root / "bin" / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o755)
        self.log = root / "compose.log"
        self.path = "%s:%s" % (root / "bin", os.environ.get("PATH", "/usr/bin:/bin"))

    def run_body(self, params, labels):
        exp = actions.expand("recreate", params, "web1")
        env = dict(os.environ, PATH=self.path, FAKE_LABELS=labels, FAKE_LOG=str(self.log))
        r = subprocess.run(["bash", "-c", exp.body], capture_output=True, text=True,
                           timeout=30, env=env)
        return r.returncode, r.stdout, r.stderr

    def test_matching_labels_recreate_with_the_pinned_argv(self):
        rc, out, err = self.run_body(dict(RECREATE, config_files=["/srv/compose/base.yml",
                                                                  "/srv/compose/prod.yml"]),
                                     "shopstack|frontend|/opt/shop|"
                                     "/srv/compose/base.yml,/srv/compose/prod.yml")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.log.read_text().splitlines(), [
            "-p", "shopstack", "--project-directory", "/opt/shop", "-f",
            "/srv/compose/base.yml", "-f", "/srv/compose/prod.yml", "up", "-d", "--no-deps",
            "--force-recreate", "--pull", "never", "frontend"])

    def test_any_label_difference_refuses_before_compose(self):
        for labels in ("shopstack|frontend|/opt/shop|/srv/compose/other.yml",
                       "other|frontend|/opt/shop|/srv/compose/shop.yml",
                       "shopstack|backend|/opt/shop|/srv/compose/shop.yml",
                       "shopstack|frontend|/opt/elsewhere|/srv/compose/shop.yml",
                       "", "shopstack|frontend|/opt/shop|/srv/compose/shop.yml|x"):
            rc, out, err = self.run_body(RECREATE, labels)
            self.assertEqual(rc, 3, labels)
            self.assertIn("not recreated", err)
            self.assertFalse(self.log.exists(), labels)
        rc, _, err = self.run_body(RECREATE, "shopstack|frontend|/opt/shop|/srv/compose/shop.yml")
        self.assertEqual(rc, 0, err)


# ---------------------------------------------------------------------------
# the door, with a stateful fake host
# ---------------------------------------------------------------------------

class FakeHost(object):
    """Answers the action texts by what is currently true on the 'host'.
    `done` flips when the body runs; `check_out` overrides the check's answer."""

    def __init__(self, name):
        exp = actions.expand(name, VALID[name], "edge1")
        self.exp, self.done, self.sent, self.check_out = exp, False, [], None

    def __call__(self, host, cmd, timeout=None, connect_timeout=None, data=None):
        self.sent.append(cmd)
        if "vpscfg.lock" in cmd:
            return 0, "", ""
        if cmd == self.exp.check:
            if self.check_out is not None:
                ans = self.check_out
                if callable(ans):
                    return ans()
                return ans
            return 0, ("VPSCFG-DONE\n" if self.done else "VPSCFG-NEEDED\n"), ""
        if cmd == self.exp.verify:
            return (0 if self.done else 1), "", ""
        if cmd == self.exp.body:
            self.done = True
            return 0, "", ""
        return 1, "", "unexpected command"

    def bodies(self):
        return [c for c in self.sent if c == self.exp.body]


class DoorTest(core._Door):
    def setUp(self):
        super().setUp()
        self._sleep = vpsexec._verify_sleep
        vpsexec._verify_sleep = lambda s: None

    def tearDown(self):
        vpsexec._verify_sleep = self._sleep
        super().tearDown()

    def run_action(self, name, host_fake):
        return self.door(["edge1", "--action", name, "--with", json.dumps(VALID[name]),
                          "--run", "--reason", "p1b"],
                         policy=tv._yaml_policy(runbooks=[entry(name, VALID[name])]),
                         ssh=host_fake)

    def test_idempotent_actions_twice_run_is_a_no_op(self):
        for name in ("tag_image", "install_pushed"):
            fake = FakeHost(name)
            rc, out = self.run_action(name, fake)
            self.assertEqual(rc, 0, out)
            self.assertEqual(len(fake.bodies()), 1, name)
            self.assertIn(fake.exp.body.splitlines()[0], out, "the body is shown")
            rc, out = self.run_action(name, fake)
            self.assertEqual(rc, 0, out)
            self.assertIn("[done] edge1", out)
            self.assertEqual(len(fake.bodies()), 1, "%s: the second run sent no body" % name)
            self.assertIs(self.ev("host_done")[-1]["already_done"], True)

    def test_unauthorised_refuses(self):
        fake = FakeHost("tag_image")
        r, _ = self.door(["edge1", "--action", "tag_image", "--with", json.dumps(TAG),
                          "--run", "--reason", "x"], ssh=fake)
        self.assertIsInstance(r, Refused)
        self.assertEqual(fake.bodies(), [])

    def test_check_abuse_fails_closed(self):
        def lost():
            raise OSError("SSH connection lost")

        def slow():
            raise subprocess.TimeoutExpired("ssh", 60)
        for name in ("tag_image", "install_pushed"):
            for answer in ((0, "VPSCFG-DONE\nextra\n", ""), (0, "vpscfg-done\n", ""),
                           (0, "", ""), (1, "VPSCFG-DONE\n", ""), (0, "VPSCFG-DONE ", ""),
                           (0, "VPSCFG-NEEDED\nVPSCFG-DONE\n", ""), lost, slow):
                fake = FakeHost(name)
                fake.check_out = answer
                rc, out = self.run_action(name, fake)
                self.assertEqual(rc, 1, (name, answer, out))
                self.assertIn("failing closed", out)
                self.assertEqual(fake.bodies(), [], (name, answer))

    def test_a_check_made_non_read_by_risky_extra_refuses_at_plan_time(self):
        pol = tv._yaml_policy(runbooks=[entry("tag_image", TAG)])
        pol["risky_extra"] = ["grep -qxf"]
        r, _ = self.door(["edge1", "--action", "tag_image", "--with", json.dumps(TAG)],
                         policy=pol, ssh=FakeHost("tag_image"))
        self.assertIsInstance(r, Refused)
        self.assertIn("done-check", str(r))

    def test_recreate_is_not_idempotent_and_runs_body_then_verify(self):
        fake = FakeHost("recreate")
        rc, out = self.run_action("recreate", fake)
        self.assertEqual(rc, 0, out)
        self.assertIn("NOT idempotent", out)
        self.assertIn("--force-recreate --pull never", out)
        cmds = [c for c in fake.sent if "vpscfg.lock" not in c]
        self.assertEqual(cmds, [fake.exp.body, fake.exp.verify])
        self.assertEqual(self.ev("action_check"), [])
        rc, out = self.run_action("recreate", fake)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(fake.bodies()), 2, "a recreate always runs")

    def test_recreate_verify_failure_fails_the_host(self):
        fake = FakeHost("recreate")
        real = fake.__call__

        def never_up(host, cmd, **kw):
            rc, out, err = real(host, cmd, **kw)
            if cmd == fake.exp.verify:
                return 1, "", ""
            return rc, out, err
        rc, out = self.run_action("recreate", never_up)
        self.assertEqual(rc, 1, out)
        self.assertEqual(len([c for c in fake.sent if c == fake.exp.verify]), 20)


class PublicHygieneTest(unittest.TestCase):
    def test_exporter_scan_finds_nothing(self):
        spec = importlib.util.spec_from_file_location("export_public",
                                                      REPO / "tools" / "export-public.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        files = [REPO / "vpscfg" / "actions" / "container.py",
                 REPO / "vpscfg" / "actions" / "file.py", REPO / "docs" / "ACTIONS.md",
                 Path(__file__)] + [GOLDEN / ("%s@%d.json" % (n, base.REGISTRY[n].version))
                                    for n in NAMES]
        for path in files:
            self.assertEqual(mod.scan_text(str(path.relative_to(REPO)), path.read_text(), []),
                             [], path)


if __name__ == "__main__":
    unittest.main()
