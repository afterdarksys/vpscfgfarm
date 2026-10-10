"""Drill receipt, journal witness, read-only sql, and secret-put.

Runners are injected. Nothing here opens an SSH session or writes the
real journal/ directory.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import cli, drill, journal, repair, secretput, sqlread  # noqa: E402
from vpscfg.control import Guard  # noqa: E402
from vpscfg.gates import DENY_ALWAYS_FLOOR, READ_ONLY_VERBS, Refused  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
DIGEST = "ab" * 32
SCRATCH = "/tmp/vpscfg-drill-abc"
PROJECT = "vpscfg-drill-" + ("ab" * 8)
PG_SQL = "SELECT 42 AS drillmarker"
HTTP_BLOCK = {
    "archive": "/var/backups/web.tar",
    "compose": "compose.yml",
    "service": "web",
    "http": "http://127.0.0.1:20000/health",
}
PG_BLOCK = {
    "archive": "/var/backups/web.tar",
    "compose": "compose.yml",
    "service": "web",
    "postgres": PG_SQL,
}
SINK = "/opt/web/.env.production"


def _append(stream, entry):
    with mock.patch("vpscfg.telemetry.push_event"):
        return journal.append(stream, entry)


def _io(fn):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn()
    return rc, out.getvalue(), err.getvalue()


class Scripted(object):
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, host, command, stdin=None):
        self.calls.append((host, command, stdin))
        if not self.replies:
            raise AssertionError("runner called too often: %s" % command)
        return self.replies.pop(0)


def _guard(host, verbs, posture="test", unlocked=None, verified=True):
    if unlocked is None:
        unlocked = ["service:%s/web" % host]
    hosts = {host: {"posture": posture}}
    return Guard({
        "allowed_verbs": list(verbs),
        "mutation_enabled": True,
        "mode": "test",
        "hosts": hosts,
        "scopes": {"unlocked": list(unlocked)},
        "deny_always": list(DENY_ALWAYS_FLOOR),
    }, verified)


def _drill_contract(block, host="edge1", service="web"):
    return {"service": service, "host": host, "drill": dict(block)}


def _happy_replies(sha_line, canary_rc=0):
    return [
        (0, SCRATCH + "\n", ""),
        (0, sha_line, ""),
        (0, "", ""),
        (0, "", ""),
        (0, "", ""),
        (canary_rc, "", ""),
        (0, "", ""),
    ]


def _down_tokens(command):
    return shlex.split(command)


class WitnessTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._orig = journal.JOURNAL_DIR
        journal.JOURNAL_DIR = Path(self._tmp.name)
        self.addCleanup(setattr, journal, "JOURNAL_DIR", self._orig)

    def _verify(self, rest):
        return _io(lambda: cli._journal_verify(rest))

    def _seed(self, n=3):
        for i in range(n):
            _append("witness", {"event": "e%d" % i})
        return journal.JOURNAL_DIR / "witness.jsonl"

    def test_empty_journal_still_means_verify_all(self):
        for rest in ([], ["verify"]):
            rc, out, _err = self._verify(rest)
            self.assertEqual(rc, 0)
            self.assertIn("journal verify: no streams yet", out)

    def test_empty_with_mirror_is_unverified(self):
        mirror = Path(self._tmp.name) / "mirror"
        mirror.mkdir()
        rc, out, _err = self._verify(["verify", "--against", str(mirror)])
        self.assertEqual(rc, 1)
        self.assertIn("UNVERIFIED", out)
        self.assertNotIn("FAIL", out)

    def test_shortened_local_tail_is_truncation(self):
        path = self._seed(3)
        mirror = Path(self._tmp.name) / "mirror"
        mirror.mkdir()
        (mirror / "witness.jsonl").write_text(path.read_text())
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:-1]) + "\n")
        self.assertTrue(journal.chain_verify("witness")["ok"])
        rc, out, _err = self._verify(["verify", "--against", str(mirror), "witness"])
        self.assertEqual(rc, 1)
        self.assertIn("truncation", out)

    def test_longer_local_is_lag(self):
        path = self._seed(3)
        mirror = Path(self._tmp.name) / "mirror"
        mirror.mkdir()
        (mirror / "witness.jsonl").write_text(path.read_text())
        _append("witness", {"event": "extra"})
        rc, out, _err = self._verify(["verify", "witness", "--against", str(mirror)])
        self.assertEqual(rc, 0)
        self.assertIn("LAG", out)
        self.assertNotIn("truncation", out)

    def test_equal_copies_pass(self):
        path = self._seed(3)
        mirror = Path(self._tmp.name) / "mirror"
        mirror.mkdir()
        (mirror / "witness.jsonl").write_text(path.read_text())
        rc, out, _err = self._verify(["verify", "--against", str(mirror), "witness"])
        self.assertEqual(rc, 0)
        self.assertNotIn("LAG", out)
        self.assertNotIn("UNVERIFIED", out)
        self.assertNotIn("truncation", out)

    def test_edited_mirror_prefix_disagrees(self):
        path = self._seed(3)
        mirror = Path(self._tmp.name) / "mirror"
        mirror.mkdir()
        lines = path.read_text().splitlines()
        lines[0] = lines[0] + "x"
        (mirror / "witness.jsonl").write_text("\n".join(lines) + "\n")
        rc, out, _err = self._verify(["verify", "--against", str(mirror), "witness"])
        self.assertEqual(rc, 1)
        self.assertIn("shared prefix disagrees", out)

    def test_bad_chain_hides_neither_the_break_nor_a_lag_banner(self):
        path = self._seed(2)
        mirror = Path(self._tmp.name) / "mirror"
        mirror.mkdir()
        (mirror / "witness.jsonl").write_text(path.read_text())
        _append("witness", {"event": "extra"})
        lines = path.read_text().splitlines()
        rec = json.loads(lines[-1])
        rec["prev"] = "nope"
        lines[-1] = json.dumps(rec)
        path.write_text("\n".join(lines) + "\n")
        rc, out, _err = self._verify(["verify", "--against", str(mirror), "witness"])
        self.assertEqual(rc, 1)
        self.assertIn("prev hash mismatch", out)
        self.assertNotIn("LAG", out)

    def test_missing_mirror_is_unverified_not_fail(self):
        self._seed(1)
        mirror = Path(self._tmp.name) / "mirror"
        mirror.mkdir()
        rc, out, _err = self._verify(["verify", "--against", str(mirror), "witness"])
        self.assertEqual(rc, 1)
        self.assertIn("UNVERIFIED witness", out)
        self.assertNotIn("FAIL", out)

    def test_symlink_mirror_fails_closed_without_following(self):
        path = self._seed(1)
        mirror = Path(self._tmp.name) / "mirror"
        mirror.mkdir()
        real = Path(self._tmp.name) / "elsewhere.jsonl"
        real.write_text(path.read_text())
        (mirror / "witness.jsonl").symlink_to(real)
        rc, out, _err = self._verify(["verify", "--against", str(mirror), "witness"])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL", out)
        self.assertNotIn("UNVERIFIED", out)
        self.assertIn("non-regular", out)

    def test_bad_stream_and_flags_refuse(self):
        mirror = Path(self._tmp.name) / "mirror"
        mirror.mkdir()
        cases = [
            ["verify", "../x"],
            ["verify", "--against", str(mirror), "../x"],
            ["verify", "--against", str(mirror), "--against", str(mirror)],
            ["verify", "--against"],
            ["verify", "--against", "--stream"],
            ["verify", "--nope"],
            ["status"],
        ]
        for rest in cases:
            with self.subTest(rest=rest):
                with self.assertRaises(Refused):
                    cli._journal_verify(rest)

    def test_compare_witness_rejects_non_text_and_names_lag(self):
        ok, problems, _local, _mirror = journal.compare_witness(None, "x")
        self.assertFalse(ok)
        self.assertIn("not text", problems[0][1])
        ok, problems, local_n, mirror_n = journal.compare_witness("a\nb\n", "a\n")
        self.assertTrue(ok)
        self.assertEqual(problems, [(2, "lag")])
        self.assertEqual((local_n, mirror_n), (2, 1))
        ok, _problems, _a, _b = journal.compare_witness("", "")
        self.assertTrue(ok)


class DrillTest(unittest.TestCase):
    def _guard(self, host="edge1", posture="test", unlocked=None):
        return _guard(host, ["drill"], posture=posture, unlocked=unlocked)

    def test_plan_does_not_touch_token_runner_or_host(self):
        runner = mock.Mock(side_effect=AssertionError("runner"))
        contract = _drill_contract(HTTP_BLOCK)
        with mock.patch("vpscfg.drill.contracts.load", return_value=contract), \
                mock.patch("vpscfg.drill.secrets.token_hex",
                           side_effect=AssertionError("token")):
            rc, out, err = _io(lambda: drill.cli(
                self._guard(), "edge1", ["edge1", "drill", "web"], {"edge1"}, runner=runner))
        self.assertEqual(rc, 0, err)
        runner.assert_not_called()
        self.assertIn("DRILL PLAN", out)
        self.assertIn("<scratch>", out)
        self.assertIn("<project>", out)
        self.assertIn("does not remove the scratch directory", out)
        self.assertNotIn(SCRATCH, out)

    def test_missing_block_is_blocked_before_any_call(self):
        runner = mock.Mock(side_effect=AssertionError("runner"))
        contract = {"service": "web", "host": "edge1"}
        with mock.patch("vpscfg.drill.contracts.load", return_value=contract), \
                mock.patch("vpscfg.drill.secrets.token_hex",
                           side_effect=AssertionError("token")):
            rc, _out, err = _io(lambda: drill.cli(
                self._guard(), "edge1", ["edge1", "drill", "web", "--run", "--reason", "why"],
                {"edge1"}, runner=runner))
        self.assertEqual(rc, 1)
        self.assertIn("BLOCKED: contract web has no drill block", err)
        runner.assert_not_called()

    def test_invalid_block_refuses_before_ssh(self):
        runner = mock.Mock(side_effect=AssertionError("runner"))
        bad = [
            dict(HTTP_BLOCK, postgres=PG_SQL),
            {k: v for k, v in HTTP_BLOCK.items() if k != "http"},
            dict(HTTP_BLOCK, http="http://localhost:20000/health"),
            dict(HTTP_BLOCK, http="https://127.0.0.1:20000/health"),
            dict(HTTP_BLOCK, http="http://127.0.0.1:80/health"),
            dict(HTTP_BLOCK, http="http://user:pw@127.0.0.1:20000/health"),
            dict(HTTP_BLOCK, archive="/var/backups/../web.tar"),
            dict(PG_BLOCK, postgres="WITH x AS (SELECT 1) INSERT INTO t SELECT 1"),
        ]
        for block in bad:
            with self.subTest(block=block):
                contract = _drill_contract(block)
                with mock.patch("vpscfg.drill.contracts.load", return_value=contract):
                    with self.assertRaises(Refused):
                        drill.cli(self._guard(), "edge1",
                                  ["edge1", "drill", "web", "--run", "--reason", "why"],
                                  {"edge1"}, runner=runner)
                runner.assert_not_called()

    def test_phrase_and_tar_dest_refuse(self):
        refused = [
            "docker compose -p p -f f.yml down -v",
            "docker compose -p p -f f.yml down --volumes",
            "docker volume rm web",
            "docker system prune -f",
            "tar -xf /var/backups/web.tar -C /",
            "tar -xf /var/backups/web.tar -C/",
        ]
        for command in refused:
            with self.subTest(command=command):
                with self.assertRaises(Refused):
                    drill.assert_plan_safe([command], scratch=SCRATCH)
        spec = drill.validate_block(HTTP_BLOCK)
        lines = drill._plan_lines(spec)
        drill.assert_plan_safe(lines, scratch=None)
        with self.assertRaises(Refused):
            drill.assert_plan_safe(lines, scratch=SCRATCH)

    def test_happy_path_receipt_and_clean_teardown(self):
        sha = "%s  SECRETLEAK\n" % DIGEST
        script = Scripted(_happy_replies(sha))
        spec = drill.validate_block(HTTP_BLOCK)
        captured = {}

        def grab(stream, entry):
            captured["stream"] = stream
            captured["entry"] = entry
            return entry

        with mock.patch("vpscfg.drill.journal.append", side_effect=grab):
            rc, out, err = _io(lambda: drill.execute(
                self._guard(), "edge1", _drill_contract(HTTP_BLOCK), spec, "why",
                runner=script, project_name=PROJECT))
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(script.calls), 7)
        self.assertEqual(script.calls[0][1], drill.MKTEMP)
        self.assertIsNone(script.calls[5][2])
        self.assertIn("curl", script.calls[5][1])
        down = script.calls[-1][1]
        tokens = _down_tokens(down)
        self.assertIn("down", tokens)
        self.assertNotIn("-v", tokens)
        self.assertNotIn("--volumes", tokens)
        proof = json.loads(out)
        self.assertEqual(out.strip(), json.dumps(proof, sort_keys=True))
        self.assertEqual(set(proof), {
            "host", "kind", "reference", "service", "tested_at", "verified", "verifier",
        })
        self.assertEqual(proof["kind"], "restore-drill")
        self.assertIs(proof["verified"], True)
        self.assertEqual(proof["host"], "edge1")
        self.assertEqual(proof["service"], "web")
        self.assertEqual(proof["reference"], "sha256:" + DIGEST)
        self.assertEqual(proof["verifier"], "vpscfg drill")
        self.assertIsNotNone(datetime.fromisoformat(proof["tested_at"]).tzinfo)
        self.assertEqual(captured["stream"], "drill")
        blob = json.dumps(captured["entry"])
        self.assertNotIn("SECRETLEAK", blob)
        self.assertNotIn("SECRETLEAK", out)
        self.assertEqual(captured["entry"]["reason"], "why")

    def test_postgres_sql_stays_on_stdin(self):
        sha = "%s  /var/backups/web.tar\n" % DIGEST
        script = Scripted(_happy_replies(sha))
        spec = drill.validate_block(PG_BLOCK)
        with mock.patch("vpscfg.drill.journal.append", return_value={}):
            rc, _out, err = _io(lambda: drill.execute(
                self._guard(), "edge1", _drill_contract(PG_BLOCK), spec, "why",
                runner=script, project_name=PROJECT))
        self.assertEqual(rc, 0, err)
        canary = script.calls[5]
        self.assertNotIn(PG_SQL, canary[1])
        self.assertNotIn("drillmarker", canary[1])
        self.assertIn("exec -T", canary[1])
        self.assertIn("psql", canary[1])
        self.assertIn(PG_SQL, canary[2].decode("utf-8"))

    def test_canary_failure_still_tears_down_without_a_receipt(self):
        script = Scripted(_happy_replies("%s  x\n" % DIGEST, canary_rc=1))
        spec = drill.validate_block(HTTP_BLOCK)
        with mock.patch("vpscfg.drill.journal.append", side_effect=AssertionError("journal")):
            rc, out, err = _io(lambda: drill.execute(
                self._guard(), "edge1", _drill_contract(HTTP_BLOCK), spec, "why",
                runner=script, project_name=PROJECT))
        self.assertEqual(rc, 1)
        self.assertIn("no receipt", err)
        self.assertNotIn("restore-drill", out)
        self.assertEqual(len(script.calls), 7)
        tokens = _down_tokens(script.calls[-1][1])
        self.assertIn("down", tokens)
        self.assertNotIn("-v", tokens)
        self.assertNotIn("--volumes", tokens)

    def test_bad_scratch_does_not_extract_or_tear_down(self):
        spec = drill.validate_block(HTTP_BLOCK)
        samples = [
            (0, "/\n", ""),
            (0, "/tmp\n", ""),
            (0, SCRATCH + "\nextra\n", ""),
            (0, "/tmp/vpscfg-drill-abc/../x\n", ""),
            (1, SCRATCH + "\n", ""),
        ]
        for reply in samples:
            script = Scripted([reply])
            with self.subTest(reply=reply):
                rc, _out, err = _io(lambda: drill.execute(
                    self._guard(), "edge1", _drill_contract(HTTP_BLOCK), spec, "why",
                    runner=script, project_name=PROJECT))
                self.assertEqual(rc, 1)
                self.assertIn("scratch directory refused", err)
                self.assertEqual(len(script.calls), 1)
                self.assertNotIn("tar", script.calls[0][1])

    def test_uppercase_digest_tears_down_without_a_receipt(self):
        script = Scripted([
            (0, SCRATCH + "\n", ""),
            (0, ("AB" * 32) + "  file\n", ""),
            (0, "", ""),
        ])
        spec = drill.validate_block(HTTP_BLOCK)
        with mock.patch("vpscfg.drill.journal.append", side_effect=AssertionError("journal")):
            rc, out, err = _io(lambda: drill.execute(
                self._guard(), "edge1", _drill_contract(HTTP_BLOCK), spec, "why",
                runner=script, project_name=PROJECT))
        self.assertEqual(rc, 1)
        self.assertIn("no receipt", err)
        self.assertNotIn("sha256:", out)
        self.assertEqual(len(script.calls), 3)
        self.assertIn("sha256sum", script.calls[1][1])
        self.assertIn("down", _down_tokens(script.calls[2][1]))

    def test_unjournaled_receipt_is_not_printed(self):
        script = Scripted(_happy_replies("%s  x\n" % DIGEST))
        spec = drill.validate_block(HTTP_BLOCK)
        with mock.patch("vpscfg.drill.journal.append", side_effect=OSError("full")):
            rc, out, err = _io(lambda: drill.execute(
                self._guard(), "edge1", _drill_contract(HTTP_BLOCK), spec, "why",
                runner=script, project_name=PROJECT))
        self.assertEqual(rc, 1)
        self.assertIn("receipt was not journaled", err)
        self.assertNotIn(DIGEST, out)
        self.assertEqual(len(script.calls), 7)

    def test_frozen_host_stops_before_token_and_runner(self):
        runner = mock.Mock(side_effect=AssertionError("runner"))
        spec = drill.validate_block(HTTP_BLOCK)
        with mock.patch("vpscfg.drill.secrets.token_hex",
                        side_effect=AssertionError("token")):
            with self.assertRaises(Refused) as caught:
                drill.execute(self._guard(posture="frozen"), "edge1",
                              _drill_contract(HTTP_BLOCK), spec, "why", runner=runner)
        self.assertIn("posture", str(caught.exception))
        runner.assert_not_called()

    def test_token_hex_runs_only_after_the_gate(self):
        script = Scripted(_happy_replies("%s  x\n" % DIGEST))
        spec = drill.validate_block(HTTP_BLOCK)
        with mock.patch("vpscfg.drill.journal.append", return_value={}), \
                mock.patch("vpscfg.drill.secrets.token_hex", return_value="ab" * 8) as hexed:
            rc, _out, err = _io(lambda: drill.execute(
                self._guard(), "edge1", _drill_contract(HTTP_BLOCK), spec, "why",
                runner=script))
        self.assertEqual(rc, 0, err)
        hexed.assert_called_once_with(8)
        # mktemp, sha, members, extract, then compose -p PROJECT
        self.assertEqual(script.calls[4][1].split()[3], PROJECT)

    def test_alias_scope_uses_the_cli_host_and_the_proof_uses_the_contract(self):
        script = Scripted(_happy_replies("%s  x\n" % DIGEST))
        spec = drill.validate_block(HTTP_BLOCK)
        guard = self._guard(host="alias", unlocked=["service:alias/web"])
        guard.policy["hosts"]["edge1"] = {"posture": "test"}
        seen = []
        real = guard.assert_mutation_allowed

        def wrapped(verb, host, scope):
            seen.append((verb, host, scope))
            return real(verb, host, scope)

        guard.assert_mutation_allowed = wrapped
        with mock.patch("vpscfg.drill.journal.append", return_value={}):
            rc, out, err = _io(lambda: drill.execute(
                guard, "alias", _drill_contract(HTTP_BLOCK, host="edge1"), spec, "why",
                runner=script, project_name=PROJECT))
        self.assertEqual(rc, 0, err)
        self.assertEqual(seen, [("drill", "alias", "service:alias/web")])
        self.assertEqual(json.loads(out)["host"], "edge1")
        self.assertEqual(script.calls[0][0], "alias")

    def test_bad_project_name_does_not_call_the_runner(self):
        runner = mock.Mock(side_effect=AssertionError("runner"))
        spec = drill.validate_block(HTTP_BLOCK)
        with self.assertRaises(Refused):
            drill.execute(self._guard(), "edge1", _drill_contract(HTTP_BLOCK), spec, "why",
                          runner=runner, project_name="vpscfg-drill-" + ("AB" * 8))
        runner.assert_not_called()

    def test_issued_proof_satisfies_check_request(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "vpscfg").mkdir()
        (root / "vpscfg" / "executor.py").write_text("# test executor\n")
        (root / "vpscfg-control.py").write_text("# test wrapper\n")
        (root / "vpscfg-control.json").write_text("{}\n")
        source = root / "source"
        source.mkdir()
        (source / "app").write_text("release-one")
        for args in (
            ("init", "-q"),
            ("add", "app"),
            ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
             "commit", "-qm", "fixture"),
        ):
            subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True)
        contract = {
            "service": "web", "host": "edge1", "repo": str(source), "deploy_dir": "/opt/web",
            "sync": {"include": ["app"], "never": [".env"]},
            "build": "docker restart web",
            "verify": [{"container": {"name": "web", "state": "healthy"}}],
            "pre": [{"backup": "tar czf /root/web-pre.tar.gz /opt/web"}],
            "blast_radius": {"volumes": ["web-data"], "max_other_containers": 0},
            "drill": dict(HTTP_BLOCK),
        }
        script = Scripted(_happy_replies("%s  x\n" % DIGEST))
        spec = drill.validate_block(HTTP_BLOCK)
        with mock.patch("vpscfg.drill.journal.append", return_value={}):
            rc, out, err = _io(lambda: drill.execute(
                self._guard(), "edge1", contract, spec, "why",
                runner=script, project_name=PROJECT))
        self.assertEqual(rc, 0, err)
        proof = json.loads(out)
        request = {
            "schema_version": 1, "kind": "repair-request", "operation_id": "gf-fixture",
            "recipe": repair.RECIPE, "host": "edge1", "service": "web",
            "plan_checksum": "sha256:" + ("a" * 64),
            "generated_at": repair.now(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "binding": repair.describe(contract, root),
            "ownership_digest": "sha256:" + ("b" * 64),
            "affected_services": ["web"],
            "rollback_proof": proof,
        }
        self.assertIs(repair.check_request(request, contract, root), request)
        request["rollback_proof"] = dict(proof, verified=False)
        with self.assertRaises(Refused):
            repair.check_request(request, contract, root)
        request["rollback_proof"] = dict(proof, host="web1")
        with self.assertRaises(Refused):
            repair.check_request(request, contract, root)


class SqlReadTest(unittest.TestCase):
    def block(self):
        return {
            "engine": "postgres", "container": "db", "database": "app",
            "role": "reader", "password_file": "/run/secrets/db",
        }

    def redis_block(self):
        return {
            "engine": "redis", "container": "cache", "database": "cache",
            "password_file": "/run/secrets/redis", "db": 2,
        }

    def test_classifier_rejects_writes_and_keeps_literals(self):
        refused = [
            "INSERT INTO t VALUES (1)",
            "COPY t TO PROGRAM 'id'",
            "SELECT 1; SELECT 2",
            "SELECT 1 -- hide",
            "SELECT 1 /* hide */",
            "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x",
            "EXPLAIN ANALYZE SELECT 1",
            "SELECT insert",
            "SELECT 'unterminated",
            "SELECT $$hidden$$",
            "",
            "SELECT 1\x00",
            "SELECT '\\x'",
            "SELECT 1 INTO scratch",
            "BEGIN",
            "SET ROLE postgres",
            "SELECT 'DROP TABLE users'",
        ]
        for query in refused:
            with self.subTest(query=query):
                with self.assertRaises(Refused):
                    sqlread.classify(query)
        self.assertEqual(sqlread.classify("SELECT 'insert'"), "SELECT 'insert'")
        self.assertEqual(sqlread.classify("SELECT ';'"), "SELECT ';'")
        self.assertEqual(sqlread.classify("SELECT 1;"), "SELECT 1")
        with self.assertRaises(Refused):
            sqlread.classify("SHOW ALL", select_only=True)

    def test_bad_query_never_reaches_the_runner(self):
        runner = mock.Mock(side_effect=AssertionError("runner"))
        with self.assertRaises(Refused):
            sqlread.execute("edge1", self.block(), "INSERT INTO t VALUES (1)", runner)
        runner.assert_not_called()

    def test_postgres_precheck_then_user_script(self):
        query = "SELECT 42 AS markerq"
        calls = []

        def runner(host, command, stdin):
            calls.append((host, command, stdin))
            if len(calls) == 1:
                return (0, "f\n", "")
            return (0, "ok\npassword=hunter2\n", "")

        captured = {}

        def grab(stream, entry):
            captured["entry"] = entry
            return entry

        with mock.patch("vpscfg.sqlread.journal.append", side_effect=grab):
            rc, out, err = _io(lambda: sqlread.execute("edge1", self.block(), query, runner))
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(calls), 2)
        pre_cmd, pre_in = calls[0][1], calls[0][2]
        user_cmd, user_in = calls[1][1], calls[1][2]
        self.assertEqual(pre_in, sqlread._PRECHECK.encode("utf-8"))
        self.assertNotIn(b"BEGIN", pre_in)
        self.assertTrue(user_in.decode("utf-8").startswith(sqlread._USER_PREFIX))
        self.assertIn("statement_timeout", user_in.decode("utf-8"))
        self.assertIn(query, user_in.decode("utf-8"))
        self.assertNotIn(query, pre_cmd)
        self.assertNotIn(query, user_cmd)
        self.assertNotIn("SELECT", pre_cmd)
        self.assertNotIn("SELECT", user_cmd)
        self.assertIn("-tA", pre_cmd)
        self.assertNotIn("-tA", user_cmd)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("markerq", json.dumps(captured["entry"]))
        self.assertEqual(captured["entry"]["event"], "sql-read")
        self.assertEqual(captured["entry"]["db"], "app")
        self.assertEqual(
            captured["entry"]["sha256"],
            hashlib.sha256(query.encode("utf-8")).hexdigest())

    def test_superuser_and_unreadable_precheck_stop(self):
        leaks = [
            (0, "t\nLEAKED-SUPERUSER-ROW\n", ""),
            (0, "", ""),
            (1, "f\nLEAKED-SUPERUSER-ROW\n", "boom"),
            (0, "f" + ("x" * 40), ""),
        ]
        for reply in leaks:
            calls = []

            def runner(host, command, stdin, reply=reply):
                calls.append(command)
                return reply

            with mock.patch("vpscfg.sqlread.journal.append",
                            side_effect=AssertionError("journal")):
                with self.assertRaises(Refused) as caught:
                    sqlread.execute("edge1", self.block(), "SELECT 1", runner)
            self.assertIn("superuser", str(caught.exception))
            self.assertNotIn("LEAKED-SUPERUSER-ROW", str(caught.exception))
            self.assertEqual(len(calls), 1)

    def test_output_cap_drops_the_201st_line(self):
        lines = ["row-%d" % i for i in range(201)]

        def runner(host, command, stdin):
            if stdin == sqlread._PRECHECK.encode("utf-8"):
                return (0, "f\n", "")
            return (0, "\n".join(lines) + "\n", "")

        with mock.patch("vpscfg.sqlread.journal.append", return_value={}):
            rc, out, _err = _io(lambda: sqlread.execute(
                "edge1", self.block(), "SELECT 1", runner))
        self.assertEqual(rc, 0)
        self.assertIn("row-199", out)
        self.assertNotIn("row-200", out)
        self.assertIn("[output capped]", out)

    def test_journal_failure_does_not_print_rows(self):
        def runner(host, command, stdin):
            if stdin == sqlread._PRECHECK.encode("utf-8"):
                return (0, "f\n", "")
            return (0, "secret-row\n", "")

        with mock.patch("vpscfg.sqlread.journal.append", side_effect=OSError("full")):
            with self.assertRaises(OSError):
                _io(lambda: sqlread.execute("edge1", self.block(), "SELECT 1", runner))

    def test_redis_is_one_fixed_call(self):
        seen = []

        def runner(host, command, stdin):
            seen.append((command, stdin))
            return (0, "PONG\n", "")

        with mock.patch("vpscfg.sqlread.journal.append", return_value={}) as append:
            rc, out, err = _io(lambda: sqlread.execute(
                "edge1", self.redis_block(), "PING", runner))
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(seen), 1)
        command, stdin = seen[0]
        tokens = shlex.split(command)
        self.assertIn("REDISCLI_AUTH", command)
        self.assertIn("redis-cli", tokens)
        self.assertIn("-n", tokens)
        self.assertIn("2", tokens)
        self.assertNotIn("-a", tokens)
        self.assertEqual(stdin, b"PING\n")
        self.assertIn("PONG", out)
        self.assertEqual(append.call_args[0][1]["db"], "cache")
        for command_text in ("CONFIG GET dir", "KEYS *", "MONITOR", "PING; INFO", "GET secret"):
            with self.subTest(command_text=command_text):
                with self.assertRaises(Refused):
                    sqlread.classify_redis(command_text)

    def test_malformed_block_fails_closed_and_cli_is_one_query(self):
        good = {"service": "web", "host": "edge1", "sql": self.block()}
        bad = {"service": "other", "host": "edge1", "sql": {"engine": "postgres"}}
        with self.assertRaises(Refused):
            sqlread.find_sql({"good": good, "bad": bad}, "app")
        twin = {"service": "other", "host": "edge1", "sql": dict(self.block())}
        with self.assertRaises(Refused):
            sqlread.find_sql({"a": good, "b": twin}, "app")
        dotted = dict(self.block(), password_file="/run/../secrets/db")
        with self.assertRaises(Refused):
            sqlread.validate_block(dotted, "dotted")
        flagged = dict(self.redis_block(), db=True)
        with self.assertRaises(Refused):
            sqlread.validate_block(flagged, "flag")
        runner = mock.Mock(side_effect=AssertionError("runner"))
        with self.assertRaises(Refused):
            sqlread.cli("edge1", ["edge1", "sql", "app", "SELECT 1", "extra"],
                        {"web": good}, runner=runner)
        runner.assert_not_called()


SOURCE = ["keystore", "pipe", "--"]


class SecretPutTest(unittest.TestCase):
    def contracts(self, path=SINK):
        return {"web": {"service": "web", "host": "edge1", "secrets": {"sinks": [path]}}}

    def _guard(self, host="edge1", posture="test", unlocked=None):
        return _guard(host, ["secret-put"], posture=posture, unlocked=unlocked)

    def test_plan_does_not_read_or_write(self):
        runner = mock.Mock(side_effect=AssertionError("runner"))
        pipe = mock.Mock(side_effect=AssertionError("pipe"))
        tty = mock.Mock(side_effect=AssertionError("tty"))
        rc, out, err = _io(lambda: secretput.put(
            self._guard(), "edge1", "estate/db", SINK, False, None, self.contracts(),
            runner=runner, pipe=pipe, source=SOURCE, tty_check=tty))
        self.assertEqual(rc, 0, err)
        self.assertIn("SECRET-PUT PLAN estate/db -> %s" % SINK, out)
        self.assertIn("source: keystore pipe -- estate/db", out)
        self.assertIn("install -m 600", out)
        self.assertIn("plan only", out)
        runner.assert_not_called()
        pipe.assert_not_called()
        tty.assert_not_called()

    def test_order_is_verb_mutation_tty_pipe_then_run(self):
        order = []
        guard = self._guard()
        real_verb = guard.assert_verb
        real_mut = guard.assert_mutation_allowed

        def verb(name):
            order.append("verb")
            return real_verb(name)

        def mutation(*args):
            order.append("mutation")
            return real_mut(*args)

        guard.assert_verb = verb
        guard.assert_mutation_allowed = mutation

        def tty(*_args):
            order.append("tty")

        def pipe(_name):
            order.append("pipe")
            return b"sekrit-value"

        def runner(_host, _command, _stdin):
            order.append("run")
            return (0, "", "")

        with mock.patch("vpscfg.secretput.journal.append", return_value={}):
            rc, out, err = _io(lambda: secretput.put(
                guard, "edge1", "estate/db", SINK, True, "why", self.contracts(),
                runner=runner, pipe=pipe, source=SOURCE, tty_check=tty))
        self.assertEqual(rc, 0, err)
        self.assertEqual(order, ["verb", "mutation", "tty", "pipe", "run"])
        self.assertIn("sha256:", out)
        self.assertNotIn("sekrit-value", out)

    def test_mutation_refusal_stops_before_tty(self):
        order = []
        guard = self._guard(posture="frozen")
        real_verb = guard.assert_verb

        def verb(name):
            order.append("verb")
            return real_verb(name)

        def mutation(*_args):
            order.append("mutation")
            raise Refused("host posture is frozen")

        guard.assert_verb = verb
        guard.assert_mutation_allowed = mutation
        tty = mock.Mock(side_effect=AssertionError("tty"))
        with self.assertRaises(Refused):
            secretput.put(guard, "edge1", "estate/db", SINK, True, "why", self.contracts(),
                          runner=mock.Mock(), pipe=mock.Mock(), source=SOURCE, tty_check=tty)
        self.assertEqual(order, ["verb", "mutation"])
        tty.assert_not_called()

    def test_missing_or_bad_sink_never_reaches_the_gate(self):
        guard = self._guard()
        guard.assert_verb = mock.Mock(side_effect=AssertionError("verb"))
        with self.assertRaises(Refused):
            secretput.put(guard, "edge1", "estate/db", "/opt/other/.env", False, None,
                          self.contracts(), runner=mock.Mock(), source=SOURCE)
        bad = {"web": {"service": "web", "secrets": {"sinks": ["/tmp/../x", SINK]}}}
        with self.assertRaises(Refused) as caught:
            secretput.put(guard, "edge1", "estate/db", SINK, False, None, bad, source=SOURCE)
        self.assertIn("secrets.sinks entry", str(caught.exception))
        twin = {
            "a": {"service": "a", "secrets": {"sinks": [SINK]}},
            "b": {"service": "b", "secrets": {"sinks": [SINK]}},
        }
        with self.assertRaises(Refused):
            secretput.put(guard, "edge1", "estate/db", SINK, False, None, twin, source=SOURCE)
        guard.assert_verb.assert_not_called()

    def test_stringio_is_not_a_controlling_tty(self):
        pipe = mock.Mock(side_effect=AssertionError("pipe"))
        with mock.patch("sys.stdin", io.StringIO("")):
            with self.assertRaises(Refused) as caught:
                secretput.put(self._guard(), "edge1", "estate/db", SINK, True, "why",
                              self.contracts(), runner=mock.Mock(), pipe=pipe,
                              source=SOURCE)
        self.assertIn("human at a keyboard", str(caught.exception))
        pipe.assert_not_called()

    def test_no_source_refuses_before_anything_runs(self):
        pipe = mock.Mock(side_effect=AssertionError("pipe"))
        tty = mock.Mock(side_effect=AssertionError("tty"))
        for run in (False, True):
            with mock.patch.object(secretput.integrations, "secret_source", lambda: None):
                with self.assertRaises(Refused) as caught:
                    secretput.put(self._guard(), "edge1", "estate/db", SINK, run, "why",
                                  self.contracts(), runner=mock.Mock(), pipe=pipe,
                                  tty_check=tty)
            self.assertIn("integrations.secret_source.command", str(caught.exception))
        pipe.assert_not_called()
        tty.assert_not_called()

    def test_source_argv_runs_without_a_shell_name_last(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, b"sekrit-value", b"")
        with mock.patch.object(secretput.subprocess, "run", run):
            self.assertEqual(secretput.default_pipe(SOURCE, "estate/db"), b"sekrit-value")
        self.assertEqual(calls[0][0], ["keystore", "pipe", "--", "estate/db"])
        self.assertNotIn("shell", calls[0][1])
        with mock.patch.object(secretput.subprocess, "run",
                               lambda argv, **_k: subprocess.CompletedProcess(argv, 3, b"", b"")):
            with self.assertRaises(Refused) as caught:
                secretput.default_pipe(SOURCE, "estate/db")
        self.assertIn("rc=3", str(caught.exception))

    def test_journal_records_name_and_hash_only(self):
        blob = b"sekrit-value"
        captured = {}

        def grab(stream, entry):
            captured["stream"] = stream
            captured["entry"] = dict(entry)
            return entry

        def runner(host, command, stdin):
            self.assertEqual(stdin, blob)
            tokens = shlex.split(command)
            self.assertEqual(tokens[:4], ["install", "-m", "600", "/dev/stdin"])
            self.assertIn(SINK, tokens)
            return (0, "", "")

        with mock.patch("vpscfg.secretput.journal.append", side_effect=grab):
            rc, out, err = _io(lambda: secretput.put(
                self._guard(), "edge1", "estate/db@prod", SINK, True, "why", self.contracts(),
                runner=runner, pipe=lambda _name: blob, source=SOURCE,
                tty_check=lambda *_a: None))
        self.assertEqual(rc, 0, err)
        entry = captured["entry"]
        self.assertEqual(captured["stream"], "secret-put")
        self.assertNotIn("path", entry)
        encoded = json.dumps(entry)
        self.assertNotIn("sekrit-value", encoded)
        self.assertNotIn(SINK, encoded)
        digest = hashlib.sha256(blob).hexdigest()
        self.assertEqual(entry["sha256"], digest)
        self.assertEqual(entry["name"], "estate/db@prod")
        self.assertIn("secret-put estate/db@prod sha256:%s" % digest, out)
        self.assertNotIn("sekrit-value", out)

    def test_empty_and_huge_secrets_do_not_run(self):
        runner = mock.Mock(side_effect=AssertionError("runner"))
        for blob in (b"", b"x" * (secretput.MAX_SECRET + 1)):
            with self.subTest(size=len(blob)):
                with self.assertRaises(Refused):
                    secretput.put(self._guard(), "edge1", "estate/db", SINK, True, "why",
                                  self.contracts(), runner=runner, pipe=lambda _n, blob=blob: blob,
                                  source=SOURCE, tty_check=lambda *_a: None)
        runner.assert_not_called()


def _load_wrapper():
    spec = importlib.util.spec_from_file_location(
        "drill_witness_outer", ROOT / "vpscfg-control.py")
    wrapper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wrapper)
    return wrapper


class DoorAgreementTest(unittest.TestCase):
    """Against the example estate's governor (web1 frozen, edge1 test) with
    one container scope unlocked on the test host, as a stage-2 governor has;
    tests/estate/ reruns these against the estate's own governor."""

    GOVERNOR = ROOT / "contrib" / "example-estate" / "vpscfg-control.json"
    FROZEN = "web1"
    TEST = "edge1"

    def _policy(self):
        policy = json.loads(self.GOVERNOR.read_text())
        policy["scopes"]["unlocked"] = ["container:edge1/shop-web"]
        return policy

    def test_read_only_sets_and_scopes_match(self):
        wrapper = _load_wrapper()
        self.assertEqual(READ_ONLY_VERBS, wrapper.READ_ONLY_VERBS)
        self.assertIn("sql", READ_ONLY_VERBS)
        self.assertNotIn("drill", READ_ONLY_VERBS)
        self.assertNotIn("secret-put", READ_ONLY_VERBS)
        policy = self._policy()
        example = json.loads((ROOT / "contrib" / "example-estate" / "vpscfg-control.json").read_text())
        self.assertEqual(example["scopes"]["unlocked"], [])
        for verb in ("sql", "secret-put", "drill"):
            self.assertIn(verb, policy["allowed_verbs"])
            self.assertIn(verb, example["allowed_verbs"])

    def test_outer_door_classifies_plan_and_sql_as_reads(self):
        wrapper = _load_wrapper()
        policy = self._policy()
        frozen = self.FROZEN
        reads = [
            [frozen, "sql", "app", "SELECT 1"],
            [frozen, "sql", "app", "SELECT 'insert'"],
            [frozen, "drill", "web"],
            [frozen, "secret-put", "--from-pipe", "estate/db", SINK],
        ]
        for argv in reads:
            with self.subTest(argv=argv):
                self.assertTrue(wrapper.judge(policy, argv)["read_only"])
        with mock.patch.object(wrapper, "journal"), \
                contextlib.redirect_stderr(io.StringIO()):
            for argv in (
                [frozen, "drill", "web", "--run", "--reason", "why"],
                [frozen, "secret-put", "--from-pipe", "estate/db", SINK, "--run", "--reason", "why"],
                [frozen, "sql", "app", "SELECT 'DROP TABLE users'"],
            ):
                with self.subTest(argv=argv):
                    with self.assertRaises(SystemExit):
                        wrapper.judge(policy, argv)
        judgment = wrapper.judge(policy, [self.TEST, "drill", "web", "--run", "--reason", "why"])
        self.assertFalse(judgment["read_only"])

    def test_inner_door_refuses_unverified_run_before_the_module(self):
        policy = self._policy()
        guard = Guard(policy, False)
        test, frozen = self.TEST, self.FROZEN
        with mock.patch("vpscfg.cli.Guard.load", return_value=guard):
            with mock.patch("vpscfg.drill.cli", return_value=0) as drilled:
                with self.assertRaises(Refused) as caught:
                    cli._dispatch([test, "drill", "web", "--run", "--reason", "why"])
                self.assertIn("control token", str(caught.exception))
                drilled.assert_not_called()
            with mock.patch("vpscfg.drill.cli", return_value=0) as drilled:
                self.assertEqual(cli._dispatch([test, "drill", "web"]), 0)
                drilled.assert_called_once()
            with mock.patch("vpscfg.secretput.cli", return_value=0) as put:
                with self.assertRaises(Refused) as caught:
                    cli._dispatch([test, "secret-put", "--from-pipe", "estate/db",
                                   SINK, "--run", "--reason", "why"])
                self.assertIn("control token", str(caught.exception))
                put.assert_not_called()
            with mock.patch("vpscfg.secretput.cli", return_value=0) as put:
                self.assertEqual(
                    cli._dispatch([test, "secret-put", "--from-pipe", "estate/db", SINK]),
                    0)
                put.assert_called_once()
            with mock.patch("vpscfg.sqlread.cli", return_value=0) as sql_cli:
                self.assertEqual(
                    cli._dispatch([frozen, "sql", "app", "SELECT 1"]), 0)
                sql_cli.assert_called_once()


if __name__ == "__main__":
    unittest.main()
