"""contrib/ tests — the example estate and the runbook walker.

Hermetic: the policy loader gets explicit governor_hosts, known_aliases and
today=, so neither ~/.ssh/config nor the clock matters. The walker runs in
--list mode and, in run mode, only against a stub vpsexec that records its
argv. Nothing here reaches a host.

What this pins:
  - the example loads with the real loader, and its governor passes the real
    governor validation;
  - every verify (and every check) in the example classifies as a read;
  - every vpscfg-push sha256 in the example matches bytes in artifacts/;
  - rollback steps load as rollback, by `rollback: true` and by the older
    "(rollback only" text, and the walker skips both;
  - --list never calls vpsexec.
An estate's own check that none of its names leaks into contrib/ lives with
the estate (tests/estate/test_contrib_strings.py).
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import probe, sshconfig, vpsexec, vpsexecpolicy  # noqa: E402
from vpscfg.control import _validate  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR  # noqa: E402

CONTRIB = REPO / "contrib"
ESTATE = CONTRIB / "example-estate"
POLICIES = ESTATE / "policies"
ARTIFACTS = ESTATE / "artifacts"
WALK = CONTRIB / "runbook-walker" / "walk.sh"
DEPLOY = CONTRIB / "runbook-walker" / "deploy.sh"
TODAY = "2026-10-08"  # before the example's expiry
RUNBOOK = "web-release-example"

DENY = list(DENY_ALWAYS_FLOOR)


def _governor():
    return json.loads((ESTATE / "vpscfg-control.json").read_text())


def _load(policy_dir=POLICIES, today=TODAY):
    gov = _governor()
    hosts = gov["hosts"]
    reachable = set(sshconfig.load(ESTATE / "ssh_config.example"))
    reachable |= set(a for a, t in vpsexec.governor_aliases(hosts).items()
                     if t in reachable)
    return vpsexecpolicy.load(policy_dir, deny_patterns=gov["deny_always"],
                              today=today, governor_hosts=set(hosts),
                              host_re=probe.HOST_RE, known_aliases=reachable)


def _runbooks(policy):
    return [r for r in policy["runbooks"] if r["source"] == RUNBOOK + ".yaml"]


def _stub_vpsexec(directory):
    """A vpsexec stand-in that appends its argv (one JSON list per call)."""
    log = Path(directory) / "calls.jsonl"
    stub = Path(directory) / "vpsexec"
    stub.write_text("#!%s\nimport json, sys\nopen(%r, 'a').write(json.dumps("
                    "sys.argv[1:]) + '\\n')\n" % (sys.executable, str(log)))
    stub.chmod(0o755)
    return stub, log


def _walk(*args, env_extra=None, stdin=""):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(["bash", str(WALK)] + list(args), input=stdin,
                          capture_output=True, text=True, env=env, timeout=60)


class ExampleEstateTest(unittest.TestCase):

    def test_governor_passes_validation(self):
        gov = _governor()
        _validate(gov)  # raises Refused on any problem
        self.assertIn("exec", gov["allowed_verbs"])
        for entry in DENY_ALWAYS_FLOOR:
            self.assertIn(entry, gov["deny_always"])
        postures = dict((h, c["posture"]) for h, c in gov["hosts"].items())
        self.assertEqual(postures["web1"], "frozen")
        self.assertEqual(postures["edge1"], "test")

    def test_policies_load(self):
        pol = _load()
        self.assertEqual(pol["expired"], [])
        self.assertEqual(set(pol["groups"]),
                         {"web", "db", "edge", "docker", "shop", "test"})
        self.assertEqual(len(_runbooks(pol)), 11)
        self.assertIn("shop-health", pol["checks"])

    def test_runbook_disarms_after_expiry(self):
        pol = _load(today="2027-01-01")
        self.assertEqual(_runbooks(pol), [])
        self.assertEqual(len(pol["expired"]), 1)
        self.assertEqual(len(pol["groups"]), 6)  # groups still apply

    def test_every_verify_is_a_read(self):
        verifies = [r["verify"] for r in _runbooks(_load()) if r["verify"]]
        self.assertGreaterEqual(len(verifies), 7)
        for verify in verifies:
            self.assertEqual(vpsexec.classify(verify, DENY)[0], "read", verify)

    def test_every_check_is_a_read(self):
        for name, check in _load()["checks"].items():
            cmd = vpsexecpolicy.bind_params(check, [])
            self.assertEqual(vpsexec.classify(cmd, DENY)[0], "read", name)

    def test_precheck_and_verify_steps_are_reads(self):
        steps = _runbooks(_load())
        for index in (1, 8, 9):
            self.assertEqual(vpsexec.classify(steps[index - 1]["cmd"], DENY)[0],
                             "read", steps[index - 1]["why"])
            self.assertFalse(steps[index - 1]["break_glass"])

    def test_pushes_match_artifacts(self):
        on_disk = dict((hashlib.sha256(p.read_bytes()).hexdigest(), p.name)
                       for p in ARTIFACTS.rglob("*") if p.is_file())
        pushes = [r["cmd"].split() for r in _runbooks(_load())
                  if r["cmd"].startswith("vpscfg-push ")]
        self.assertTrue(pushes)
        for _, sha, name in pushes:
            self.assertEqual(on_disk.get(sha), name, "no artifact %s with sha %s"
                             % (name, sha))
        # Every 64-hex string the runbook names is either a pushed artifact or
        # the hash of a file inside it, so a rebuilt artifact cannot leave a
        # stale hash behind.
        text = (POLICIES / (RUNBOOK + ".yaml")).read_text()
        named = set(re.findall(r"\b[0-9a-f]{64}\b", text))
        import tarfile
        inner = set()
        for path in ARTIFACTS.glob("*.tar.gz"):
            with tarfile.open(path) as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        inner.add(hashlib.sha256(tar.extractfile(member).read())
                                  .hexdigest())
        self.assertEqual(named - set(on_disk) - inner, set())

    def test_rollback_steps_load_as_rollback(self):
        steps = _runbooks(_load())
        self.assertEqual([i for i, r in enumerate(steps, 1) if r["rollback"]],
                         [10, 11])
        for r in steps[9:]:
            self.assertTrue(r["why"].startswith("R"))
            self.assertTrue(r["break_glass"])

    def test_example_addresses_are_documentation_ranges(self):
        for path in sorted(CONTRIB.rglob("*")):
            if path.is_file() and path.suffix in ("", ".md", ".json", ".yaml",
                                                   ".example", ".sh"):
                for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                                     path.read_text(errors="replace")):
                    if ip == "127.0.0.1":
                        continue
                    self.assertTrue(ip.startswith(("192.0.2.", "198.51.100.",
                                                   "203.0.113.")),
                                    "%s: %s" % (path.name, ip))


class WalkerTest(unittest.TestCase):

    def test_scripts_parse(self):
        for script in (WALK, DEPLOY):
            r = subprocess.run(["bash", "-n", str(script)], capture_output=True,
                               text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_list_never_calls_vpsexec(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub, log = _stub_vpsexec(tmp)
            r = _walk("--policies", str(POLICIES), "--runbook", RUNBOOK, "--list",
                      env_extra={"VPSEXEC": str(stub)})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(log.exists(), "--list called vpsexec")
        lines = [l for l in r.stdout.splitlines() if re.match(r"^\s*\d+\s", l)]
        self.assertEqual(len(lines), 11)
        self.assertIn("ROLLBACK", lines[9])
        self.assertIn("ROLLBACK", lines[10])
        self.assertNotIn("ROLLBACK", lines[6])
        self.assertIn("push", lines[3])
        self.assertIn("stop-if", lines[0])

    def test_list_honours_old_rollback_text(self):
        body = textwrap.dedent("""\
            version: 1
            expires: "2026-12-31"
            shape: {steps: 2, hosts: [web1], break_glass: true}
            reason: "old-style rollback marker"
            runbooks:
              - hosts: [web1]
                cmd: "docker restart shop-web"
                break_glass: true
                why: "A1: restart"
              - hosts: [web1]
                cmd: "docker start shop-web"
                break_glass: true
                why: "A-R (rollback only): start it again"
            """)
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "old-style.yaml").write_text(body)
            steps = [r for r in _load(Path(tmp))["runbooks"]]
            self.assertEqual([r["rollback"] for r in steps], [False, True])
            r = _walk("--policies", tmp, "--runbook", "old-style", "--list",
                      env_extra={"VPSEXEC": "/nonexistent/vpsexec"})
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [l for l in r.stdout.splitlines() if re.match(r"^\s*\d+\s", l)]
        self.assertNotIn("ROLLBACK", lines[0])
        self.assertIn("ROLLBACK", lines[1])

    def test_run_builds_the_right_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub, log = _stub_vpsexec(tmp)
            grant = Path(tmp) / "grant.json"
            grant.write_text("{}")
            state = Path(tmp) / "state"
            args = ("--policies", str(POLICIES), "--runbook", RUNBOOK,
                    "--vpsexec", str(stub), "--artifacts", str(ARTIFACTS),
                    "--state-dir", str(state), "--reason", "example walk",
                    "--grant", str(grant))
            r = _walk(*args, stdin="y\ny\ny\n")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            calls = [json.loads(l) for l in log.read_text().splitlines()]
            progress = (state / (RUNBOOK + ".progress")).read_text().splitlines()

            # A second walk without --from refuses rather than re-running.
            again = _walk(*args)
            self.assertEqual(again.returncode, 2)
            self.assertEqual(len(log.read_text().splitlines()), 9)

        steps = _runbooks(_load())
        self.assertEqual(len(calls), 9)  # 11 steps, 2 rollback skipped
        self.assertEqual([p.split("\t")[0] for p in progress],
                         [str(i) for i in range(1, 10)])
        contract = "--approval-contract=%s" % grant
        for argv, step in zip(calls, steps):
            self.assertEqual(argv[0], ",".join(step["hosts"]))
            self.assertIn("--run", argv)
            self.assertEqual(argv[argv.index("--reason") + 1], "example walk")
            self.assertEqual("--break-glass" in argv, step["break_glass"], step["why"])
            self.assertEqual(contract in argv, step["break_glass"], step["why"])
            if step["cmd"].startswith("vpscfg-push "):
                _, sha, name = step["cmd"].split()
                self.assertEqual(argv[1], "push")
                self.assertEqual(Path(argv[2]).name, name)
                self.assertEqual(argv[argv.index("--sha256") + 1], sha)
            else:
                self.assertEqual(argv[1], step["cmd"])

    def test_stop_if_halts_without_yes(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub, log = _stub_vpsexec(tmp)
            r = _walk("--policies", str(POLICIES), "--runbook", RUNBOOK,
                      "--vpsexec", str(stub), "--artifacts", str(ARTIFACTS),
                      "--state-dir", str(Path(tmp) / "state"), "--reason", "x",
                      stdin="")
            self.assertEqual(r.returncode, 1)
            self.assertIn("Resume with --from 2", r.stdout)
            self.assertEqual(len(log.read_text().splitlines()), 1)

    def test_missing_artifact_stops_before_any_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub, log = _stub_vpsexec(tmp)
            empty = Path(tmp) / "empty"
            empty.mkdir()
            r = _walk("--policies", str(POLICIES), "--runbook", RUNBOOK,
                      "--vpsexec", str(stub), "--artifacts", str(empty),
                      "--state-dir", str(Path(tmp) / "state"), "--reason", "x")
            self.assertEqual(r.returncode, 1)
            self.assertIn("MISSING ARTIFACT", r.stderr)
            self.assertFalse(log.exists())

    def test_only_runs_a_rollback_step_deliberately(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub, log = _stub_vpsexec(tmp)
            state = Path(tmp) / "state"
            r = _walk("--policies", str(POLICIES), "--runbook", RUNBOOK,
                      "--vpsexec", str(stub), "--artifacts", str(ARTIFACTS),
                      "--state-dir", str(state), "--reason", "rollback", "--only", "10")
            self.assertEqual(r.returncode, 0, r.stderr)
            calls = [json.loads(l) for l in log.read_text().splitlines()]
            self.assertFalse((state / (RUNBOOK + ".progress")).exists())
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], _runbooks(_load())[9]["cmd"])

    def test_run_requires_reason(self):
        r = _walk("--policies", str(POLICIES), "--runbook", RUNBOOK,
                  "--vpsexec", "/nonexistent/vpsexec")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--reason", r.stderr)


if __name__ == "__main__":
    unittest.main()
