"""`vpsexec runbook lint|preflight` — the weekend's deploy-time halts, found at
authoring time instead.

Hermetic: policies, plays and artifacts live in a temp estate; ssh is a fake
that answers fixed read commands; the journal is redirected by the vpsexec
harness. Nothing here dials a host or reads ~/.vpscfg or a real estate.

Each lint rule and each `assumes` fact has a pass case and a fail case; the
facts the read tier cannot see are MANUAL, and MANUAL is never a pass. One
test plants an env VALUE in the fake host's answer and proves it appears in
no output, no JSON and no journal record.
"""
import contextlib
import datetime
import hashlib
import io
import json
import sys
import textwrap
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
from vpscfg import runbookcheck, vpsexec, vpsexecpolicy  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
NOW = datetime.datetime(2026, 10, 12, 12, 0, 0)
TODAY = "2026-10-12"
ARTIFACT = b"shop release bytes\n"
SHA = hashlib.sha256(ARTIFACT).hexdigest()
IMAGE = "sha256:" + "a" * 64
SECRET = "hunter2-do-not-" + "print-7f3a9c"  # split: no literal for the exporter scan


def _policy_text(steps=None, shape=None, expires="2026-12-31", assumes=None,
                 extra=""):
    steps = steps if steps is not None else [
        {"cmd": "docker ps --filter name=shop-api --format '{{.Names}}' | grep -qx shop-api",
         "why": "P1: READ. Stop if shop-api is not running.", "timeout": 30},
        {"cmd": "vpscfg-push %s shop.tar.gz" % SHA, "why": "S1: stage the build",
         "timeout": 120},
        {"cmd": "docker compose --project-directory /srv/shop up -d --no-build app",
         "why": "C1: recreate", "timeout": 240},
    ]
    body = ["version: 1", 'expires: "%s"' % expires,
            "reason: shop release (test)"]
    if shape != "omit":
        body.append("shape: %s" % (shape or "{steps: %d, hosts: [edge1], break_glass: false}"
                                   % len(steps)))
    body.append("runbooks:")
    for s in steps:
        body.append("  - hosts: [%s]" % s.get("host", "edge1"))
        body.append("    cmd: %s" % json.dumps(s["cmd"]))
        body.append("    where: host")
        body.append("    why: %s" % json.dumps(s["why"]))
        if s.get("timeout"):
            body.append("    timeout: %d" % s["timeout"])
        if s.get("rollback"):
            body.append("    rollback: true")
    if assumes:
        body.append(textwrap.dedent(assumes).strip("\n"))
    return "\n".join(body) + "\n" + extra


ASSUMES_OK = """
assumes:
  - host: edge1
    container: shop-api
    image: %s
    env_names_any_of: [[DATABASE_URL], [DB_HOST, DB_NAME, DB_USER, DB_PASS]]
""" % IMAGE


class _Estate(tv._Harness):

    def setUp(self):
        super().setUp()
        root = Path(self.tmp.name) / "estate"
        for d in ("policies", "plays", "artifacts"):
            (root / d).mkdir(parents=True)
        self.root = root
        (root / "artifacts" / "shop.tar.gz").write_bytes(ARTIFACT)
        self.guard = tv._guard()

    def write_policy(self, text, name="shop-release.yaml"):
        path = self.root / "policies" / name
        path.write_text(text)
        return path

    def write_play(self, steps, name="shop.yaml"):
        doc = {"version": 1, "reason": "shop release", "steps": steps}
        (self.root / "plays" / name).write_text(json.dumps(doc))

    def lint(self, text=None, path=None, **kw):
        path = path or self.write_policy(text if text is not None else
                                         _policy_text(assumes=ASSUMES_OK))
        return runbookcheck.lint(path, self.guard, tv._yaml_policy(), now=NOW,
                                 today=TODAY, **kw)

    @staticmethod
    def status(rep, name):
        hits = [c for c in rep["checks"] if c["name"] == name]
        assert hits, "no check %r in %r" % (name, [c["name"] for c in rep["checks"]])
        return hits[0]["status"]

    @staticmethod
    def evidence(rep, name):
        return next(c["evidence"] for c in rep["checks"] if c["name"] == name)


# ===========================================================================
# lint
# ===========================================================================

class LintTest(_Estate):

    def test_clean_policy_is_go(self):
        rep = self.lint()
        self.assertEqual(rep["verdict"], "GO", runbookcheck.render(rep))
        self.assertEqual(rep["exit_code"], 0)

    def test_unloadable_policy_is_no_go(self):
        rep = self.lint(_policy_text(extra="allow_floor: true\n"))
        self.assertEqual(self.status(rep, "policy"), "fail")
        self.assertEqual(rep["verdict"], "NO-GO")

    # --- push sources ---
    def test_push_source_present_and_matching_passes(self):
        self.assertEqual(self.status(self.lint(), "push step 2"), "pass")

    def test_push_source_missing_fails(self):
        (self.root / "artifacts" / "shop.tar.gz").unlink()
        rep = self.lint()
        self.assertEqual(self.status(rep, "push step 2"), "fail")
        self.assertIn("missing", self.evidence(rep, "push step 2"))
        self.assertEqual(rep["verdict"], "NO-GO")

    def test_push_source_rebuilt_fails_on_sha_mismatch(self):
        (self.root / "artifacts" / "shop.tar.gz").write_bytes(b"rebuilt\n")
        rep = self.lint()
        self.assertEqual(self.status(rep, "push step 2"), "fail")
        self.assertIn("mismatch", self.evidence(rep, "push step 2"))

    def test_push_with_no_artifact_directory_fails(self):
        rep = self.lint(artifact_dirs=[str(self.root / "nowhere")])
        self.assertEqual(self.status(rep, "pushes"), "fail")

    def test_push_symlink_is_not_a_source(self):
        real = Path(self.tmp.name) / "elsewhere.tar.gz"
        real.write_bytes(ARTIFACT)
        link = self.root / "artifacts" / "shop.tar.gz"
        link.unlink()
        link.symlink_to(real)
        self.assertEqual(self.status(self.lint(), "push step 2"), "fail")

    # --- timeouts ---
    def test_step_without_timeout_warns(self):
        steps = [{"cmd": "systemctl restart nginx", "why": "restart"},
                 {"cmd": "systemctl reload nginx", "why": "reload", "timeout": 30}]
        rep = self.lint(_policy_text(steps=steps, assumes=ASSUMES_OK))
        self.assertEqual(self.status(rep, "timeouts"), "warn")
        self.assertEqual(next(c for c in rep["checks"] if c["name"] == "timeouts")["data"], [1])
        self.assertEqual(rep["verdict"], "GO-WITH-WARNINGS")

    # --- shape ---
    def test_wrong_shape_step_count_fails(self):
        rep = self.lint(_policy_text(shape="{steps: 4, hosts: [edge1], break_glass: false}",
                                     assumes=ASSUMES_OK))
        self.assertEqual(self.status(rep, "shape"), "fail")
        self.assertIn("steps: declared 4, loaded 3", self.evidence(rep, "shape"))
        self.assertEqual(rep["verdict"], "NO-GO")

    def test_missing_shape_fails_and_suggests_one(self):
        rep = self.lint(_policy_text(shape="omit", assumes=ASSUMES_OK))
        self.assertEqual(self.status(rep, "shape"), "fail")
        self.assertIn("shape: {steps: 3, hosts: [edge1], break_glass: false}",
                      self.evidence(rep, "shape"))

    # --- expiry ---
    def test_expiry_within_48h_warns(self):
        rep = self.lint(_policy_text(expires="2026-10-13", assumes=ASSUMES_OK))
        self.assertEqual(self.status(rep, "expires"), "warn")

    def test_expiry_three_days_out_passes(self):
        rep = self.lint(_policy_text(expires="2026-10-15", assumes=ASSUMES_OK))
        self.assertEqual(self.status(rep, "expires"), "pass")

    def test_expired_policy_fails(self):
        rep = self.lint(_policy_text(expires="2026-10-11", assumes=ASSUMES_OK))
        self.assertEqual(self.status(rep, "expires"), "fail")

    # --- STOP steps ---
    def test_stop_step_that_cannot_fail_fails(self):
        steps = [{"cmd": "docker ps --filter name=shop-web --format '{{.Names}}'",
                  "why": "P1: READ. Stop if shop-web is missing.", "timeout": 30}]
        rep = self.lint(_policy_text(steps=steps, assumes=ASSUMES_OK))
        self.assertEqual(self.status(rep, "stop step 1"), "fail")

    def test_stop_step_that_can_fail_passes(self):
        self.assertEqual(self.status(self.lint(), "stop steps"), "pass")

    def test_can_fail_heuristic(self):
        never = ["docker ps --filter name=x --format '{{.Names}}'",
                 "echo ok", "systemctl is-active nginx || true",
                 "grep -q x /etc/hosts || :", "docker ps | head -1",
                 "cat /etc/hostname | wc -l", "curl -fsS http://x/ ; echo done",
                 "docker images 2>&1 | sort"]
        can = ["grep -qx shop-web /tmp/x", "docker ps | grep -qx shop-web",
               "test -e /opt/x", "curl -qfsS --max-time 10 http://127.0.0.1/healthz",
               "echo ok && false", "cat /etc/hostname", "docker inspect x",
               "echo 'unbalanced", "systemctl is-active nginx || grep -q x y",
               "docker ps | awk '{exit 1}'"]
        for cmd in never:
            self.assertFalse(runbookcheck.can_fail(cmd), cmd)
        for cmd in can:
            self.assertTrue(runbookcheck.can_fail(cmd), cmd)

    # --- plays ---
    def _play_steps(self, timeout_flag=True, sha=SHA, include_optional=False):
        flags = ["--timeout=240"] if timeout_flag else []
        steps = [{"hosts": "edge1", "push": "artifacts/shop.tar.gz", "sha256": sha,
                  "why": "stage", "flags": ["--timeout=120"]},
                 {"hosts": "edge1",
                  "cmd": "docker compose --project-directory /srv/shop up -d --no-build app",
                  "why": "recreate", "flags": flags}]
        if include_optional:
            steps.append({"hosts": "edge1", "cmd": "systemctl restart shop-worker",
                          "why": "optional", "flags": ["--timeout=90"]})
        return steps

    def test_play_carrying_hashes_and_timeouts_passes(self):
        self.write_play(self._play_steps())
        self.assertEqual(self.status(self.lint(), "play shop.yaml"), "pass")

    def test_play_missing_a_steps_timeout_warns(self):
        self.write_play(self._play_steps(timeout_flag=False))
        rep = self.lint()
        self.assertEqual(self.status(rep, "play shop.yaml"), "warn")
        self.assertIn("no --timeout=", self.evidence(rep, "play shop.yaml"))

    def test_play_with_shorter_timeout_fails(self):
        steps = self._play_steps()
        steps[1]["flags"] = ["--timeout=60"]
        self.write_play(steps)
        rep = self.lint()
        self.assertEqual(self.status(rep, "play shop.yaml"), "fail")

    def test_play_naming_a_hash_not_in_the_policy_fails(self):
        steps = self._play_steps()
        steps.append({"hosts": "edge1", "push": "artifacts/other.tar.gz",
                      "sha256": "b" * 64, "why": "stale", "flags": []})
        self.write_play(steps)
        rep = self.lint()
        self.assertEqual(self.status(rep, "play shop.yaml"), "fail")
        self.assertIn("not in the policy", self.evidence(rep, "play shop.yaml"))

    def test_unrelated_play_is_ignored(self):
        self.write_play([{"hosts": "web3", "cmd": "systemctl restart caddy", "why": "x"}])
        self.assertEqual(self.status(self.lint(), "plays"), "skip")

    # --- optional / only-if ---
    def _optional_policy(self):
        steps = [
            {"cmd": "vpscfg-push %s shop.tar.gz" % SHA, "why": "stage", "timeout": 120},
            {"cmd": "docker compose --project-directory /srv/shop up -d --no-build app",
             "why": "recreate", "timeout": 240},
            {"cmd": "systemctl restart shop-worker",
             "why": "RH 17: optional — only if the worker holds the old schema", "timeout": 90},
        ]
        return _policy_text(steps=steps, assumes=ASSUMES_OK)

    def test_optional_step_no_play_includes_warns(self):
        self.write_play(self._play_steps())
        rep = self.lint(self._optional_policy())
        self.assertEqual(self.status(rep, "optional steps"), "warn")
        self.assertEqual(next(c for c in rep["checks"]
                              if c["name"] == "optional steps")["data"], [3])

    def test_optional_step_in_a_play_passes(self):
        self.write_play(self._play_steps(include_optional=True))
        rep = self.lint(self._optional_policy())
        self.assertEqual(self.status(rep, "optional steps"), "pass")

    def test_optional_step_with_no_plays_is_skipped(self):
        rep = self.lint(self._optional_policy())
        self.assertEqual(self.status(rep, "optional steps"), "skip")

    # --- assumes, statically ---
    def test_no_assumes_warns(self):
        rep = self.lint(_policy_text())
        self.assertEqual(self.status(rep, "assumes"), "warn")

    def test_manual_assumption_with_no_verifying_step_warns(self):
        assumes = """
        assumes:
          - host: edge1
            owner_of_tables: {container: shop-db, role: shop_app}
        """
        rep = self.lint(_policy_text(assumes=assumes))
        self.assertEqual(self.status(rep, "assumes[1]"), "warn")

    # --- through the door ---
    def test_dispatch_lint_returns_the_verdict_exit_code(self):
        path = self.write_policy(_policy_text(shape="omit", assumes=ASSUMES_OK))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexec.dispatch(["runbook", "lint", str(path), "--json"],
                                  guard=self.guard, policy=tv._yaml_policy())
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out.getvalue())["verdict"], "NO-GO")

    def test_dispatch_refuses_run(self):
        path = self.write_policy(_policy_text(assumes=ASSUMES_OK))
        with self.assertRaises(Refused):
            vpsexec.dispatch(["runbook", "preflight", str(path), "--run"],
                             guard=self.guard, policy=tv._yaml_policy())

    def test_lint_never_dials_a_host(self):
        self.write_play(self._play_steps())
        with mock.patch.object(vpsexec, "_default_ssh",
                               side_effect=AssertionError("lint dialled a host")):
            self.lint()
        self.assertEqual(self.ssh_calls, [])


# ===========================================================================
# the assumes: block in the policy format
# ===========================================================================

class AssumesFormatTest(_Estate):

    def load(self, assumes):
        self.write_policy(_policy_text(assumes=assumes))
        return vpsexecpolicy.load(policy_dir=self.root / "policies", deny_patterns=list(DENY_ALWAYS_FLOOR),
                                  today=TODAY, governor_hosts=set(tv._policy()["hosts"]),
                                  host_re=vpsexec.probe.HOST_RE)

    def test_door_loads_a_policy_with_assumes(self):
        merged = self.load("""
        assumes:
          - host: edge1
            container: shop-api
            image: %s
            env_names_any_of: [[DATABASE_URL], [DB_HOST, DB_NAME, DB_USER, DB_PASS]]
            compose_labels: {com.docker.compose.project: shop}
            compose_files: [/srv/shop/docker-compose.yml]
          - host: edge1
            absent: [/srv/releases/shop-1.5.0]
            min_free_gb: {/opt: 5}
          - host: edge1
            owner_of_tables: {container: shop-db, role: shop_app, database: shop}
            env_distinct: [[SESSION_SECRET, JWT_SECRET]]
            verified_by: 1
        """ % IMAGE)
        self.assertEqual(len(merged["runbooks"]), 3)

    def test_malformed_assumes_refuse_the_load(self):
        bad = {
            "unknown key": "  - {host: edge1, container: x, shell: 'id'}",
            "no host": "  - {container: x}",
            "ungoverned host": "  - {host: nosuch, container: x}",
            "no fact": "  - {host: edge1}",
            "image without container": "  - {host: edge1, image: '%s'}" % IMAGE,
            "short image": "  - {host: edge1, container: x, image: 'sha256:abc'}",
            "env value not name": "  - {host: edge1, container: x, env_names_any_of: [['DB_PASS=x']]}",
            "env flat list": "  - {host: edge1, container: x, env_names_any_of: [DB_HOST]}",
            "relative path": "  - {host: edge1, absent: [opt/x]}",
            "dotdot path": "  - {host: edge1, absent: [/opt/../etc]}",
            "glob path": "  - {host: edge1, absent: ['/opt/*']}",
            "shell in path": "  - {host: edge1, absent: ['/opt/x;id']}",
            "free not number": "  - {host: edge1, min_free_gb: {/opt: lots}}",
            "owner no role": "  - {host: edge1, owner_of_tables: {container: pg}}",
            "owner bad role": "  - {host: edge1, owner_of_tables: {container: pg, role: 'x; drop'}}",
            "verified_by out of range": "  - {host: edge1, owner_of_tables: {container: pg, role: r}, verified_by: 9}",
            "verified_by on readable fact": "  - {host: edge1, absent: [/opt/x], verified_by: 1}",
            "distinct needs two": "  - {host: edge1, env_distinct: [[JWT_SECRET]]}",
            "container injection": "  - {host: edge1, container: 'x;id'}",
        }
        for label, item in bad.items():
            with self.subTest(label):
                with self.assertRaises(Refused):
                    self.load("assumes:\n" + item)


# ===========================================================================
# preflight
# ===========================================================================

class FakeHost:
    """Answers the fixed reads preflight sends. Records every command."""

    def __init__(self, image=IMAGE, state="running",
                 env="PATH=/usr/bin DB_HOST=db.internal DB_NAME=inv DB_USER=inv DB_PASS=%s" % SECRET,
                 labels=None, existing=(), free_kb=None, missing_container=False,
                 broken=False):
        self.image, self.state, self.env = image, state, env
        self.labels = labels if labels is not None else {
            "com.docker.compose.project": "shop",
            "com.docker.compose.project.config_files": "/srv/shop/docker-compose.yml",
            "traefik.http.middlewares.auth.basicauth.users": "admin:" + SECRET}
        self.existing, self.free_kb = set(existing), free_kb or {}
        self.missing_container, self.broken = missing_container, broken
        self.calls = []

    def __call__(self, host, cmd, timeout=None, connect_timeout=None):
        self.calls.append((host, cmd))
        if self.broken:
            raise OSError("ssh: connect to host edge1: Connection refused")
        if cmd.startswith("docker inspect"):
            if self.missing_container:
                return 1, "", "Error: No such object: shop-api\n"
            if ".Config.Env" in cmd:
                # A host that answers with VALUES (it should only send names):
                # preflight must still never show them.
                return 0, self.env + "\n", ""
            if ".Config.Labels" in cmd:
                return 0, json.dumps(self.labels) + "\n", ""
            return 0, "%s %s\n" % (self.image, self.state), ""
        if cmd.startswith("ls -d -- "):
            paths = [p.strip("'") for p in cmd[len("ls -d -- "):].split()]
            out = "".join(p + "\n" for p in paths if p in self.existing)
            err = "".join("ls: cannot access '%s': No such file or directory\n" % p
                          for p in paths if p not in self.existing and p != "/denied")
            err += "ls: cannot access '/denied': Permission denied\n" if "/denied" in paths else ""
            return (0 if not err else 2), out, err
        if cmd.startswith("df -P -k -- "):
            paths = cmd[len("df -P -k -- "):].split()
            rows = ["Filesystem 1024-blocks Used Available Capacity Mounted on"]
            for p in paths:
                rows.append("/dev/vda1 100000000 1 %d 1%% %s" % (self.free_kb.get(p, 50 * 1024 * 1024), p))
            return 0, "\n".join(rows) + "\n", ""
        raise AssertionError("preflight sent an unexpected command: %r" % cmd)


class PreflightTest(_Estate):

    def preflight(self, assumes, host=None, steps=None):
        host = host or FakeHost()
        path = self.write_policy(_policy_text(steps=steps, assumes=assumes))
        rep = runbookcheck.preflight(path, self.guard, tv._yaml_policy(), ssh=host,
                                     today=TODAY)
        return rep, host

    def test_matching_container_is_go_and_every_command_is_a_read(self):
        rep, host = self.preflight(ASSUMES_OK)
        self.assertEqual(rep["verdict"], "GO", runbookcheck.render(rep))
        self.assertTrue(host.calls)
        for h, cmd in host.calls:
            self.assertEqual(h, "edge1")
            self.assertEqual(vpsexec.classify(cmd, list(DENY_ALWAYS_FLOOR))[0], "read", cmd)
            self.assertNotIn("--run", cmd)
        self.assertEqual(self.status(rep, "assumes[1] shop-api env names"), "pass")

    def test_env_shape_mismatch_fails(self):
        # The stage A halt: the precheck assumed DATABASE_URL, prod has DB_*.
        assumes = ASSUMES_OK.replace("[[DATABASE_URL], [DB_HOST, DB_NAME, DB_USER, DB_PASS]]",
                                     "[[DATABASE_URL]]")
        rep, _ = self.preflight(assumes)
        name = "assumes[1] shop-api env names"
        self.assertEqual(self.status(rep, name), "fail")
        self.assertIn("lacks DATABASE_URL", self.evidence(rep, name))
        self.assertEqual(rep["verdict"], "NO-GO")

    def test_env_values_never_appear_anywhere(self):
        assumes = ASSUMES_OK.replace("[[DATABASE_URL], [DB_HOST, DB_NAME, DB_USER, DB_PASS]]",
                                     "[[DATABASE_URL]]") + \
            "    compose_labels: {com.docker.compose.project: shop}\n"
        for answer in (FakeHost(), FakeHost(env="DB_PASS=%s DB_HOST=x" % SECRET)):
            rep, _ = self.preflight(assumes, host=answer)
            text = runbookcheck.render(rep)
            blob = json.dumps(rep)
            self.assertNotIn(SECRET, text)
            self.assertNotIn(SECRET, blob)
            self.assertIn("DB_PASS", text)  # the NAME is reported
        journal_text = (Path(self.tmp.name) / "vpsexec.jsonl").read_text()
        self.assertNotIn(SECRET, journal_text)

    def test_env_names_are_read_by_a_names_only_template(self):
        _, host = self.preflight(ASSUMES_OK)
        env_cmd = next(c for _, c in host.calls if ".Config.Env" in c)
        self.assertIn('split . "="', env_cmd)

    def test_image_mismatch_fails(self):
        rep, _ = self.preflight(ASSUMES_OK, host=FakeHost(image="sha256:" + "c" * 64))
        self.assertEqual(self.status(rep, "assumes[1] shop-api image"), "fail")

    def test_missing_container_fails(self):
        rep, _ = self.preflight(ASSUMES_OK, host=FakeHost(missing_container=True))
        self.assertEqual(self.status(rep, "assumes[1] shop-api"), "fail")
        self.assertEqual(rep["verdict"], "NO-GO")

    def test_stopped_container_fails(self):
        rep, _ = self.preflight(ASSUMES_OK, host=FakeHost(state="exited"))
        self.assertEqual(self.status(rep, "assumes[1] shop-api"), "fail")

    def test_compose_labels_and_files(self):
        assumes = """
        assumes:
          - host: edge1
            container: shop-api
            compose_labels: {com.docker.compose.project: shop}
            compose_files: [/srv/shop/docker-compose.yml]
        """
        rep, _ = self.preflight(assumes)
        self.assertEqual(rep["verdict"], "GO", runbookcheck.render(rep))
        rep, _ = self.preflight(assumes, host=FakeHost(labels={
            "com.docker.compose.project": "shop-old",
            "com.docker.compose.project.config_files": "/srv/old-shop/compose.yml"}))
        self.assertEqual(self.status(
            rep, "assumes[1] shop-api label com.docker.compose.project"), "fail")
        self.assertEqual(self.status(rep, "assumes[1] shop-api compose files"), "fail")

    def test_absent_paths(self):
        assumes = """
        assumes:
          - host: edge1
            absent: [/srv/releases/shop-1.5.0]
        """
        rep, _ = self.preflight(assumes)
        self.assertEqual(self.status(rep, "assumes[1] absent"), "pass")
        rep, _ = self.preflight(assumes, host=FakeHost(
            existing=["/srv/releases/shop-1.5.0"]))
        self.assertEqual(self.status(rep, "assumes[1] absent"), "fail")

    def test_absent_path_that_cannot_be_read_is_an_error_not_a_pass(self):
        rep, _ = self.preflight("""
        assumes:
          - host: edge1
            absent: [/denied]
        """)
        self.assertEqual(self.status(rep, "assumes[1] absent"), "error")
        self.assertEqual(rep["verdict"], "NO-GO")

    def test_free_disk(self):
        assumes = """
        assumes:
          - host: edge1
            min_free_gb: {/opt: 5}
        """
        rep, _ = self.preflight(assumes)
        self.assertEqual(self.status(rep, "assumes[1] free disk"), "pass")
        rep, _ = self.preflight(assumes, host=FakeHost(free_kb={"/opt": 1024 * 1024}))
        self.assertEqual(self.status(rep, "assumes[1] free disk"), "fail")

    def test_owner_of_tables_is_manual_with_its_step_never_pass(self):
        # The re-key and wave6 halts: ownership needs a DB credential.
        rep, host = self.preflight("""
        assumes:
          - host: edge1
            owner_of_tables: {container: shop-db, role: shop_app, database: shop}
            env_distinct: [[SESSION_SECRET, JWT_SECRET]]
            verified_by: 1
        """)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "manual")
        self.assertEqual(self.status(rep, "assumes[1] env_distinct"), "manual")
        self.assertIn("runbook step 1: P1", self.evidence(rep, "assumes[1] owner_of_tables"))
        self.assertEqual(rep["verdict"], "GO-WITH-WARNINGS")
        self.assertEqual(rep["exit_code"], 1)
        self.assertEqual(host.calls, [])  # nothing was even attempted
        self.assertIn("MANUAL", runbookcheck.render(rep))

    def test_manual_without_a_step_says_so(self):
        rep, _ = self.preflight("""
        assumes:
          - host: edge1
            owner_of_tables: {container: shop-db, role: auth_svc}
        """)
        self.assertIn("No runbook step verifies this",
                      self.evidence(rep, "assumes[1] owner_of_tables"))

    def test_a_check_the_read_tier_refuses_is_manual(self):
        with mock.patch.object(runbookcheck.vpsexec, "classify",
                               return_value=("mutating", "pretend")):
            rep, host = self.preflight(ASSUMES_OK)
        self.assertEqual(self.status(rep, "assumes[1]"), "manual")
        self.assertEqual(host.calls, [])
        self.assertNotEqual(rep["verdict"], "GO")

    def test_transport_failure_is_an_error(self):
        rep, _ = self.preflight(ASSUMES_OK, host=FakeHost(broken=True))
        self.assertEqual(self.status(rep, "assumes[1]"), "error")
        self.assertEqual(rep["verdict"], "NO-GO")

    def test_no_assumes_block_warns(self):
        rep, host = self.preflight(None)
        self.assertEqual(self.status(rep, "assumes"), "warn")
        self.assertEqual(host.calls, [])

    def test_reads_are_journaled_as_reads(self):
        self.preflight(ASSUMES_OK)
        reads = [e for e in self.events() if e.get("via") == "runbook preflight"]
        self.assertTrue(reads)
        self.assertTrue(all(e["event"] == "read" for e in reads))

    def test_preflight_through_dispatch(self):
        path = self.write_policy(_policy_text(assumes=ASSUMES_OK))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vpsexec.dispatch(["runbook", "preflight", str(path)], guard=self.guard,
                                  policy=tv._yaml_policy(), ssh=FakeHost(), today=TODAY)
        self.assertEqual(rc, 0, out.getvalue())
        self.assertIn("VERDICT: GO", out.getvalue())


# ===========================================================================
# the doors
# ===========================================================================

class DoorTest(unittest.TestCase):

    def test_runbook_is_a_reserved_verb(self):
        self.assertIn("runbook", vpsexec.RESERVED_VERBS)

    def test_outer_door_judges_runbook_as_a_read_and_refuses_run(self):
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader("vpsexec_door_rb", str(REPO / "vpsexec"))
        spec = importlib.util.spec_from_loader("vpsexec_door_rb", loader)
        door = importlib.util.module_from_spec(spec)
        loader.exec_module(door)
        door.journal = lambda entry: None  # refuse() must not write the checkout's journal
        gov = tv._policy()
        judged = door.judge(gov, ["runbook", "preflight", "policies/x.yaml"])
        self.assertEqual((judged["hosts"], judged["read_only"], judged["introspect"]),
                         ([], True, "runbook"))
        for argv in (["runbook", "lint", "x.yaml", "--run"],
                     ["runbook", "lint", "volume prune"]):
            with self.assertRaises(SystemExit):
                with contextlib.redirect_stderr(io.StringIO()):
                    door.judge(gov, argv)


if __name__ == "__main__":
    unittest.main()
