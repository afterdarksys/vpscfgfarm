"""Draft-only compose and Deployment translation. Nothing here applies."""

import ast
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from vpscfg import cli, translate


COMPOSE = """
services:
  web:
    image: registry.example.com/team/web:1.2
"""

DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: apps
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: web
          image: registry.example.com/team/web:1.2
          ports:
            - containerPort: 8080
"""


class TranslateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_cli(self, argv, text=None, name="compose.yml"):
        if text is not None:
            path = self.root / name
            path.write_text(text)
            argv = [argv[0], str(path), *argv[1:]]
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = translate.cli(argv)
        return code, buf.getvalue(), json.loads(buf.getvalue())

    def test_registry_image_drops_the_tag_and_stays_a_draft(self):
        code, out, draft = self.run_cli(["compose-to-k3s", "--service", "web"], COMPOSE)
        self.assertEqual(code, 0)
        self.assertFalse(draft["executable"])
        self.assertFalse(draft["applied"])
        self.assertFalse(draft["blocked"])
        self.assertEqual(draft["workload"]["image_repository"], "registry.example.com/team/web")
        self.assertEqual(draft["workload"]["name"], "web")
        self.assertIn("tag stripped; k3s apply derives the tag", draft["unmapped"])
        self.assertNotIn(":1.2", out)
        self.assertIsNone(draft["limits"]["nodes_observed"])
        self.assertEqual(draft["not_a_contract"], ["host", "repo", "verify", "scope_kind"])

    def test_short_image_volumes_secrets_privilege_and_host_networking_refuse(self):
        code, out, draft = self.run_cli(["compose-to-k3s", "--service", "web"], "services:\n  web:\n    image: nginx:latest\n")
        self.assertEqual(code, 1)
        self.assertIn("image repository is not a registry path without a tag", draft["refused"])
        self.assertNotIn("latest", out)
        code, out, draft = self.run_cli(
            ["compose-to-k3s", "--service", "web"],
            COMPOSE + "volumes:\n  data: {}\n", name="volumes.yml")
        self.assertEqual(code, 1)
        self.assertIn("volumes are a separate reviewed step", draft["refused"])
        code, out, draft = self.run_cli(
            ["compose-to-k3s", "--service", "web"],
            COMPOSE + "secrets:\n  db:\n    file: ./super-secret-file\n", name="secrets.yml")
        self.assertEqual(code, 1)
        self.assertIn("secrets are not copied", draft["refused"])
        self.assertNotIn("super-secret-file", out)
        code, out, draft = self.run_cli(
            ["compose-to-k3s", "--service", "web"],
            "services:\n  web:\n    image: registry.example.com/team/web:1.2\n    privileged: true\n    network_mode: host\n")
        self.assertEqual(code, 1)
        self.assertIn("privileged mode is not copied", draft["refused"])
        self.assertIn("host networking is not copied", draft["refused"])

    def test_environment_values_and_sibling_services_are_not_copied(self):
        text = """
services:
  web:
    image: registry.example.com/team/web:1.2
    environment:
      DATABASE_PASSWORD: super-secret-value
  other:
    image: registry.example.com/team/other:9.9.9
    environment:
      TOKEN: sibling-secret-value
"""
        code, out, draft = self.run_cli(["compose-to-k3s", "--service", "web"], text)
        self.assertEqual(code, 1)
        self.assertIn("secret-like environment name", draft["refused"])
        self.assertIn("environment not copied", draft["unmapped"])
        self.assertNotIn("super-secret-value", out)
        self.assertNotIn("DATABASE_PASSWORD", out)
        self.assertNotIn("sibling-secret-value", out)
        clean = text.replace("DATABASE_PASSWORD: super-secret-value", "COLOR: blue")
        code, out, draft = self.run_cli(["compose-to-k3s", "--service", "web"], clean, name="clean.yml")
        self.assertEqual(code, 0)
        self.assertEqual(draft["workload"]["name"], "web")
        self.assertNotIn("sibling-secret-value", out)
        self.assertNotIn("9.9.9", out)

    def test_underscore_service_name_is_not_rewritten(self):
        code, out, draft = self.run_cli(
            ["compose-to-k3s", "--service", "web_app"],
            "services:\n  web_app:\n    image: registry.example.com/team/web:1.2\n")
        self.assertEqual(code, 1)
        self.assertIsNone(draft["workload"]["name"])
        self.assertIn("service name is not a Kubernetes name", draft["refused"])
        self.assertNotIn("web-app", out)

    def test_run_output_symlink_size_and_documents_fail_before_a_draft_is_applied(self):
        code, out, draft = self.run_cli(["compose-to-k3s", "missing.yml", "--service", "web", "--run"])
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["run and output are not accepted"])
        self.assertNotIn("workload", draft)
        code, _out, draft = self.run_cli(["compose-to-k3s", "missing.yml", "--output", "out.yml", "--service", "web"])
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["run and output are not accepted"])
        target = self.root / "compose.yml"
        target.write_text(COMPOSE)
        link = self.root / "link.yml"
        link.symlink_to(target)
        code, _out, draft = self.run_cli(["compose-to-k3s", str(link), "--service", "web"])
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["input must be a regular file"])
        huge = self.root / "huge.yml"
        huge.write_bytes(b"x" * (translate.MAX_BYTES + 1))
        code, _out, draft = self.run_cli(["compose-to-k3s", str(huge), "--service", "web"])
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["input exceeds 1 MiB"])
        code, out, draft = self.run_cli(
            ["compose-to-k3s", "--service", "web"], COMPOSE + "---\n" + COMPOSE, name="two.yml")
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["expected one document"])
        code, out, draft = self.run_cli(
            ["compose-to-k3s", "--service", "web"], "services: [zzparser-token\n", name="broken.yml")
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["yaml document refused"])
        self.assertNotIn("zzparser-token", out)

    def test_deployment_draft_drops_replicas_ports_and_the_tag(self):
        code, out, draft = self.run_cli(["k3s-to-compose", "--container", "web"], DEPLOYMENT, name="web.yml")
        self.assertEqual(code, 0)
        self.assertFalse(draft["executable"])
        self.assertEqual(draft["workload"]["compose_service"], "web")
        self.assertEqual(draft["workload"]["image_repository"], "registry.example.com/team/web")
        self.assertEqual(draft["workload"]["namespace"], "apps")
        self.assertIn("replicas not copied", draft["unmapped"])
        self.assertIn("ports not copied", draft["unmapped"])
        self.assertIn("namespace is not represented in compose", draft["unmapped"])
        self.assertNotIn(":1.2", out)
        self.assertIsNone(draft["limits"]["nodes_observed"])

    def test_frozen_namespace_pull_policy_scheduling_secrets_and_commands(self):
        frozen = DEPLOYMENT.replace("namespace: apps", "namespace: kube-system")
        code, out, draft = self.run_cli(["k3s-to-compose", "--container", "web"], frozen, name="frozen.yml")
        self.assertEqual(code, 1)
        self.assertIn("namespace is frozen", draft["refused"])
        self.assertIsNone(draft["workload"]["namespace"])
        self.assertNotIn("kube-system", out)
        always = DEPLOYMENT.replace(
            "image: registry.example.com/team/web:1.2",
            "image: registry.example.com/team/web:1.2\n          imagePullPolicy: Always")
        code, _out, draft = self.run_cli(["k3s-to-compose", "--container", "web"], always, name="always.yml")
        self.assertEqual(code, 1)
        self.assertIn("imagePullPolicy Always is refused", draft["refused"])
        spread = DEPLOYMENT.replace(
            "containers:",
            "affinity:\n        podAntiAffinity: {}\n      containers:")
        code, _out, draft = self.run_cli(["k3s-to-compose", "--container", "web"], spread, name="spread.yml")
        self.assertEqual(code, 1)
        self.assertIn("multi-node scheduling is not drafted", draft["refused"])
        secret = DEPLOYMENT.replace(
            "image: registry.example.com/team/web:1.2",
            "image: registry.example.com/team/web:1.2\n          env:\n            - name: DB\n              valueFrom:\n                secretKeyRef:\n                  name: db-password\n                  key: password")
        code, out, draft = self.run_cli(["k3s-to-compose", "--container", "web"], secret, name="secret.yml")
        self.assertEqual(code, 1)
        self.assertIn("secrets are not copied", draft["refused"])
        self.assertNotIn("db-password", out)
        command = DEPLOYMENT.replace(
            "image: registry.example.com/team/web:1.2",
            "image: registry.example.com/team/web:1.2\n          command: [\"rm\", \"-rf\", \"/\"]")
        code, out, draft = self.run_cli(["k3s-to-compose", "--container", "web"], command, name="command.yml")
        self.assertEqual(code, 0)
        self.assertIn("command not copied", draft["unmapped"])
        self.assertNotIn("-rf", out)

    def test_json_compose_and_fleet_dispatch_and_closed_inputs(self):
        code, _out, draft = self.run_cli(
            ["compose-to-k3s", "--service", "web"],
            json.dumps({"services": {"web": {"image": "registry.example.com/team/web:1.2"}}}),
            name="compose.json")
        self.assertEqual(code, 0)
        self.assertEqual(draft["workload"]["image_repository"], "registry.example.com/team/web")
        path = self.root / "compose.yml"
        path.write_text(COMPOSE)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli._fleet(["translate", "compose-to-k3s", str(path), "--service", "web"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(buf.getvalue())["executable"])
        code, _out, draft = self.run_cli(["compose-to-k3s", "missing.yml"])
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["name the service or container"])
        code, out, draft = self.run_cli(["compose-to-k3s", "missing.yml", "--service", "web;id"])
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["invalid workload name"])
        self.assertNotIn("web;id", out)
        code, _out, draft = self.run_cli(["compose-to-k3s", "missing.yml", "--service", "web", "--apply"])
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["unsupported translate argument"])
        tree = ast.parse(Path(translate.__file__).read_text())
        imported = [alias.name for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
                    for alias in node.names]
        imported += [node.module for node in tree.body if isinstance(node, ast.ImportFrom) and node.module]
        self.assertFalse(any(name in ("subprocess", "socket", "executor") or (name or "").endswith("executor")
                             for name in imported))



    def test_deeply_nested_json_is_refused_cleanly(self):
        text = '{"services": {"web": {"image": "x/y", "labels": ' + "[" * 50000 + "]" * 50000 + "}}}"
        code, _, draft = self.run_cli(["compose-to-k3s", "--service", "web"], text, name="deep.json")
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["input is nested too deeply"])

    def test_moderately_nested_json_hits_the_depth_limit(self):
        text = '{"services": {"web": {"image": "x/y", "labels": ' + "[" * 80 + "]" * 80 + "}}}"
        code, _, draft = self.run_cli(["compose-to-k3s", "--service", "web"], text, name="deep.json")
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["input is nested too deeply"])

    def test_yaml_alias_fan_out_is_refused_before_it_is_walked(self):
        lines = ['a: &a ["x","x","x","x","x","x","x","x","x"]']
        prev = "a"
        for name in "bcdefg":
            lines.append("%s: &%s [%s]" % (name, name, ",".join(["*" + prev] * 9)))
            prev = name
        lines.append("services: {web: {image: x/y, labels: *%s}}" % prev)
        code, _, draft = self.run_cli(["compose-to-k3s", "--service", "web"], "\n".join(lines))
        self.assertEqual(code, 2)
        self.assertEqual(draft["refused"], ["input has too many nodes"])

    def test_ordinary_compose_anchors_still_draft(self):
        text = """
x-common: &common
  image: registry.example.com/team/web:1.2
services:
  web:
    <<: *common
"""
        code, _, draft = self.run_cli(["compose-to-k3s", "--service", "web"], text)
        self.assertEqual(code, 0)
        self.assertEqual(draft["workload"]["image_repository"], "registry.example.com/team/web")

if __name__ == "__main__":
    unittest.main()
