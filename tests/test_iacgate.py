"""badfarm IaC gate: locate, scan, report validation, classify, fleet iac.
Hermetic: runners are injected; the one stub-executable test runs a local
script, never badfarm. One integration test runs a real badfarm if present."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import cli, iacgate  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

EXE = "/opt/badfarm/bin/badfarm"
FINDING = {"rule": "iac.tf.open_ingress", "category": "exposure", "severity": "high",
           "file": "k8s/svc.yaml", "line": 7, "title": "NodePort on 0.0.0.0",
           "evidence": "type: NodePort", "remediation": "use ClusterIP"}


def report(verdict="pass", findings=(), suppressed=(), coverage=None):
    if coverage is None:
        coverage = [{"file": "a.tf", "status": "partial", "reason": "module", "blocking": False}]
    return {"schema_version": 1, "kind": "iac-scan-report",
            "tool": {"name": "badfarm", "version": "0.9.0"}, "source": {"path": "/x"},
            "files": {"scanned": 4, "skipped": 1}, "findings": list(findings),
            "suppressed": list(suppressed), "coverage": coverage,
            "summary": {"total": len(findings)}, "verdict": verdict}


class Runner(object):
    def __init__(self, rc=0, out=None, err=""):
        self.rc, self.err = rc, err
        self.out = json.dumps(report()) if out is None else out
        self.calls = []

    def __call__(self, argv, timeout=300):
        self.calls.append((list(argv), timeout))
        return self.rc, self.out, self.err


class TmpBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.src = self.tmp / "src"
        self.src.mkdir()
        self._env = mock.patch.dict(os.environ, {}, clear=False)
        self._env.start()
        os.environ.pop(iacgate.ENV_VAR, None)

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def exe(self, name="badfarm", mode=0o755, body="#!/bin/sh\nexit 0\n"):
        path = self.tmp / name
        path.write_text(body)
        path.chmod(mode)
        return path


class LocateTest(TmpBase):
    def test_env_absolute_executable_is_used(self):
        path = self.exe()
        os.environ[iacgate.ENV_VAR] = str(path)
        self.assertEqual(iacgate.locate(), str(path))

    def test_env_relative_refused_even_if_it_exists(self):
        self.exe()
        os.environ[iacgate.ENV_VAR] = "badfarm"
        cwd = os.getcwd()
        os.chdir(str(self.tmp))
        try:
            with self.assertRaises(Refused):
                iacgate.locate()
        finally:
            os.chdir(cwd)
        os.environ[iacgate.ENV_VAR] = ""
        with self.assertRaises(Refused):
            iacgate.locate()

    def test_env_non_executable_missing_or_directory_refused(self):
        for value in (str(self.exe(mode=0o644)), str(self.tmp / "nope"), str(self.src)):
            os.environ[iacgate.ENV_VAR] = value
            with self.assertRaises(Refused, msg=value):
                iacgate.locate()

    def test_env_set_never_falls_back_to_path(self):
        os.environ[iacgate.ENV_VAR] = "relative/badfarm"
        with mock.patch("shutil.which", return_value=EXE), self.assertRaises(Refused):
            iacgate.locate()

    def test_unset_uses_path_or_none(self):
        path = self.exe()
        with mock.patch("shutil.which", return_value=str(path)):
            self.assertEqual(iacgate.locate(), str(path.resolve()))
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(iacgate.locate())

    def test_path_hit_that_is_not_absolute_is_refused(self):
        # shutil.which() can hand back a relative path when PATH contains
        # "." or an empty entry — e.g. "./badfarm" found inside the scanned
        # repo. That must refuse, not be treated as absent (None), so
        # required mode fails closed and advisory mode warns.
        for relative in ("./badfarm", "badfarm", "sub/badfarm"):
            with mock.patch("shutil.which", return_value=relative):
                with self.assertRaises(Refused, msg=relative):
                    iacgate.locate()

    def test_path_hit_that_does_not_exist_or_is_not_executable_is_refused(self):
        missing = str(self.tmp / "nope-badfarm")
        not_exec = str(self.exe(name="not-exec", mode=0o644))
        directory = str(self.src)
        for bad in (missing, not_exec, directory):
            with mock.patch("shutil.which", return_value=bad):
                with self.assertRaises(Refused, msg=bad):
                    iacgate.locate()

    def test_path_hit_is_resolved_through_a_symlink(self):
        real = self.exe(name="real-badfarm")
        link = self.tmp / "badfarm-link"
        link.symlink_to(real)
        with mock.patch("shutil.which", return_value=str(link)):
            self.assertEqual(iacgate.locate(), str(real.resolve()))


class ScanTest(TmpBase):
    def setUp(self):
        super(ScanTest, self).setUp()
        self._loc = mock.patch("vpscfg.iacgate.locate", return_value=EXE)
        self._loc.start()

    def tearDown(self):
        self._loc.stop()
        super(ScanTest, self).tearDown()

    def test_argv_exact(self):
        r = Runner()
        self.assertEqual(iacgate.scan(str(self.src), runner=r, timeout=42)["verdict"], "pass")
        self.assertEqual(r.calls, [([EXE, "iac", "scan", "--format", "json", "--fail-on", "high",
                                     "--", str(self.src.resolve())], 42)])

    def test_path_is_resolved_and_must_be_a_directory(self):
        r = Runner()
        link = self.tmp / "link"
        link.symlink_to(self.src)
        iacgate.scan(str(link), runner=r)
        self.assertEqual(r.calls[0][0][-1], str(self.src.resolve()))
        f = self.tmp / "file.tf"
        f.write_text("x")
        for bad in (f, self.tmp / "missing"):
            with self.assertRaises(Refused):
                iacgate.scan(str(bad), runner=Runner())

    def test_badfarm_absent_refused(self):
        with mock.patch("vpscfg.iacgate.locate", return_value=None), self.assertRaises(Refused):
            iacgate.scan(str(self.src), runner=Runner())

    def test_bad_fail_on_refused_before_running(self):
        r = Runner()
        with self.assertRaises(Refused):
            iacgate.run_scan(str(self.src), runner=r, fail_on="none")
        self.assertEqual(r.calls, [])

    def test_exit_2_refused_with_masked_clipped_excerpt(self):
        secret = "password=" + "hunter2-super-secret"
        out = json.dumps({"refused": secret + " " + "x" * 5000})
        with self.assertRaises(Refused) as cm:
            iacgate.scan(str(self.src), runner=Runner(rc=2, out=out))
        msg = str(cm.exception)
        self.assertIn("exit 2", msg)
        self.assertNotIn("hunter2", msg)
        self.assertLess(len(msg), 400)
        with self.assertRaises(Refused):
            iacgate.scan(str(self.src), runner=Runner(rc=2, out=""))

    def test_unexpected_exit_codes_refused(self):
        for rc in (3, 127, -9):
            with self.assertRaises(Refused, msg=rc):
                iacgate.scan(str(self.src), runner=Runner(rc=rc))

    def test_timeout_and_exec_failure_refused(self):
        def slow(argv, timeout=300):
            raise subprocess.TimeoutExpired(argv, timeout)

        def missing(argv, timeout=300):
            raise FileNotFoundError(argv[0])
        for runner in (slow, missing):
            with self.assertRaises(Refused):
                iacgate.scan(str(self.src), runner=runner)

    def test_output_cap(self):
        big = " " * (iacgate.OUTPUT_CAP + 1)
        with self.assertRaises(Refused) as cm:
            iacgate.scan(str(self.src), runner=Runner(out=big))
        self.assertIn("exceeds", str(cm.exception))
        ok = json.dumps(report())
        padded = ok + " " * (iacgate.OUTPUT_CAP - len(ok))
        self.assertEqual(iacgate.scan(str(self.src), runner=Runner(out=padded))["verdict"], "pass")

    def test_non_json_refused_without_echo(self):
        with self.assertRaises(Refused) as cm:
            iacgate.scan(str(self.src), runner=Runner(out="token: ghp_" + "a" * 36 + "\nnot json"))
        self.assertNotIn("a" * 36, str(cm.exception))

    def test_schema_mismatches_refused(self):
        def mutate(fn):
            doc = report("block", [dict(FINDING)])
            fn(doc)
            return json.dumps(doc)
        bad = {
            "not an object": json.dumps([report()]),
            "schema 2": mutate(lambda d: d.update(schema_version=2)),
            "schema str": mutate(lambda d: d.update(schema_version="1")),
            "schema bool": mutate(lambda d: d.update(schema_version=True)),
            "kind": mutate(lambda d: d.update(kind="workload-draft")),
            "verdict": mutate(lambda d: d.update(verdict="ok")),
            "no verdict": mutate(lambda d: d.pop("verdict")),
            "tool name": mutate(lambda d: d["tool"].update(name="other")),
            "tool version": mutate(lambda d: d["tool"].update(version=9)),
            "files": mutate(lambda d: d["files"].update(scanned="4")),
            "findings dict": mutate(lambda d: d.update(findings={})),
            "finding str": mutate(lambda d: d.update(findings=["x"])),
            "suppressed": mutate(lambda d: d.pop("suppressed")),
            "coverage": mutate(lambda d: d.update(coverage={})),
            "summary": mutate(lambda d: d.update(summary=[])),
            "source": mutate(lambda d: d.pop("source")),
            "line str": mutate(lambda d: d["findings"][0].update(line="7")),
            "line bool": mutate(lambda d: d["findings"][0].update(line=True)),
            "line neg": mutate(lambda d: d["findings"][0].update(line=-1)),
            "severity": mutate(lambda d: d["findings"][0].update(severity="severe")),
        }
        for field in iacgate.FINDING_STR_FIELDS:
            bad["missing " + field] = mutate(lambda d, f=field: d["findings"][0].pop(f))
            bad["int " + field] = mutate(lambda d, f=field: d["findings"][0].update({f: 1}))
        for name, out in bad.items():
            with self.assertRaises(Refused, msg=name):
                iacgate.scan(str(self.src), runner=Runner(rc=1, out=out))

    def test_exit_code_must_agree_with_verdict(self):
        # Each doc here is internally consistent (findings/coverage agree with
        # its claimed verdict at fail-on high) so only the rc-vs-verdict check
        # under test can fire, never the verdict-recomputation check.
        crit = dict(FINDING, severity="critical")
        incomplete_cov = [{"file": "a.tf", "status": "parse-error", "reason": "bad yaml",
                           "blocking": True}]
        docs = {"block": report("block", [crit]), "incomplete": report("incomplete", [], coverage=incomplete_cov),
                "pass": report("pass")}
        for rc, verdict in ((0, "block"), (0, "incomplete"), (1, "pass")):
            with self.assertRaises(Refused, msg=(rc, verdict)):
                iacgate.scan(str(self.src), runner=Runner(rc=rc, out=json.dumps(docs[verdict])))
        low = dict(FINDING, severity="low")
        docs = {"pass": report("pass"), "warn": report("warn", [low]),
                "block": report("block", [crit]), "incomplete": report("incomplete", [], coverage=incomplete_cov)}
        for rc, verdict in ((0, "pass"), (0, "warn"), (1, "warn"), (1, "block"), (1, "incomplete")):
            out = json.dumps(docs[verdict])
            self.assertEqual(iacgate.scan(str(self.src), runner=Runner(rc=rc, out=out))["verdict"],
                             verdict)


class ClassifyTest(unittest.TestCase):
    def test_mapping_per_mode(self):
        expected = {
            "advisory": {"block": "warn", "warn": "warn", "incomplete": "warn", "pass": "pass"},
            "required": {"block": "fail", "warn": "warn", "incomplete": "warn", "pass": "pass"},
            "off": {"block": "warn", "warn": "warn", "incomplete": "warn", "pass": "pass"},
        }
        for mode, table in expected.items():
            for verdict, status in table.items():
                self.assertEqual(iacgate.classify(report(verdict), mode)[0], status, (mode, verdict))
        with self.assertRaises(Refused):
            iacgate.classify(report(), "strict")

    def test_evidence_and_data(self):
        findings = [dict(FINDING, severity=s, rule="iac.tf.r%d" % i, line=i)
                    for i, s in enumerate(["low", "critical", "high", "medium", "low", "info", "high"])]
        status, evidence, data = iacgate.classify(report("block", findings), "required")
        self.assertEqual(status, "fail")
        self.assertIn("verdict block", evidence)
        self.assertIn("critical=1 high=2 medium=1 low=2 info=1", evidence)
        self.assertEqual(data["top"], ["iac.tf.r1 k8s/svc.yaml:1", "iac.tf.r2 k8s/svc.yaml:2",
                                       "iac.tf.r6 k8s/svc.yaml:6", "iac.tf.r3 k8s/svc.yaml:3",
                                       "iac.tf.r0 k8s/svc.yaml:0"])
        self.assertEqual(data["verdict"], "block")
        self.assertEqual(data["tool_version"], "0.9.0")
        self.assertEqual(data["counts"]["high"], 2)

    def test_suppressed_visibility_bumps_pass_to_warn(self):
        suppressed = [dict(FINDING, suppression_reason="reviewed")]
        status, evidence, data = iacgate.classify(report("pass", suppressed=suppressed), "required")
        self.assertEqual(status, "warn")
        self.assertEqual(data["suppressed"], 1)
        self.assertIn("suppressed: 1", evidence)
        # A clean report with nothing suppressed stays pass.
        status, _, data = iacgate.classify(report("pass"), "required")
        self.assertEqual(status, "pass")
        self.assertEqual(data["suppressed"], 0)
        # Suppressions never downgrade an already-worse verdict's status.
        for verdict, mode, expect in (("block", "required", "fail"), ("warn", "advisory", "warn"),
                                      ("incomplete", "required", "warn")):
            status, _, _ = iacgate.classify(report(verdict, suppressed=suppressed), mode)
            self.assertEqual(status, expect, (verdict, mode))


class RecomputedVerdictTest(ScanTest):
    """Defence in depth: validate_report recomputes the verdict from
    findings/coverage/suppressed at the REQUESTED --fail-on rather than
    trusting what badfarm reports, and refuses on any mismatch."""

    def test_reported_pass_with_a_blocking_finding_is_refused(self):
        crit = dict(FINDING, severity="critical")
        with self.assertRaises(Refused) as cm:
            iacgate.scan(str(self.src), runner=Runner(rc=0, out=json.dumps(report("pass", [crit]))))
        self.assertIn("recomputed", str(cm.exception))

    def test_reported_pass_with_blocking_coverage_gap_is_refused(self):
        gap = [{"file": "a.tf", "status": "parse-error", "reason": "bad", "blocking": True}]
        with self.assertRaises(Refused):
            iacgate.scan(str(self.src), runner=Runner(rc=0, out=json.dumps(report("pass", coverage=gap))))

    def test_untrusted_suppressed_critical_or_high_counts_toward_block(self):
        untrusted_high = dict(FINDING, severity="high", trusted=False)
        with self.assertRaises(Refused):
            iacgate.scan(str(self.src),
                        runner=Runner(rc=0, out=json.dumps(report("pass", suppressed=[untrusted_high]))))
        # A matching reported verdict of block is accepted.
        doc = iacgate.scan(str(self.src),
                           runner=Runner(rc=1, out=json.dumps(report("block", suppressed=[untrusted_high]))))
        self.assertEqual(doc["verdict"], "block")

    def test_trusted_or_low_severity_suppressed_entries_do_not_force_block(self):
        trusted_high = dict(FINDING, severity="high", trusted=True)
        untrusted_low = dict(FINDING, severity="low", trusted=False)
        no_trusted_key = dict(FINDING, severity="high")  # older badfarm output: missing key => trusted
        for suppressed in ([trusted_high], [untrusted_low], [no_trusted_key]):
            doc = iacgate.scan(str(self.src),
                               runner=Runner(rc=0, out=json.dumps(report("pass", suppressed=suppressed))))
            self.assertEqual(doc["verdict"], "pass", suppressed)

    def test_suppressed_entry_with_invalid_trusted_type_refused(self):
        bad = dict(FINDING, severity="high", trusted="no")
        with self.assertRaises(Refused):
            iacgate.scan(str(self.src), runner=Runner(rc=0, out=json.dumps(report("pass", suppressed=[bad]))))

    def test_fail_on_shifts_the_block_threshold(self):
        medium = dict(FINDING, severity="medium")
        # At fail-on high, a medium finding does not block: warn is correct.
        doc = iacgate.scan(str(self.src), runner=Runner(rc=1, out=json.dumps(report("warn", [medium]))),
                          fail_on="high")
        self.assertEqual(doc["verdict"], "warn")
        # At fail-on medium, the same finding must block.
        with self.assertRaises(Refused):
            iacgate.scan(str(self.src), runner=Runner(rc=1, out=json.dumps(report("warn", [medium]))),
                        fail_on="medium")
        doc = iacgate.scan(str(self.src), runner=Runner(rc=1, out=json.dumps(report("block", [medium]))),
                          fail_on="medium")
        self.assertEqual(doc["verdict"], "block")


class FleetIacCliTest(TmpBase):
    def _fleet(self, argv, runner):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("vpscfg.iacgate.locate", return_value=EXE), \
                mock.patch("vpscfg.iacgate.run_capped", side_effect=runner), \
                mock.patch.object(cli.Guard, "load", return_value=mock.Mock()), \
                redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(["fleet", "iac"] + argv)
        return rc, out.getvalue(), err.getvalue()

    def test_exit_codes_mirror_badfarm(self):
        rc, out, _ = self._fleet([str(self.src)], Runner())
        self.assertEqual(rc, 0)
        self.assertIn("verdict PASS", out)
        block = Runner(rc=1, out=json.dumps(report("block", [FINDING])))
        rc, out, _ = self._fleet([str(self.src), "--fail-on", "medium"], block)
        self.assertEqual(rc, 1)
        self.assertIn("iac.tf.open_ingress k8s/svc.yaml:7", out)
        self.assertEqual(block.calls[0][0][5:7], ["--fail-on", "medium"])
        rc, _, err = self._fleet([str(self.src)], Runner(rc=2, out=""))
        self.assertEqual(rc, 2)
        self.assertIn("REFUSED", err)

    def test_json_format_prints_the_validated_report_masked(self):
        finding = dict(FINDING, evidence="password: hunter2-" + "very-secret")
        rc, out, _ = self._fleet([str(self.src), "--format", "json"],
                                 Runner(rc=1, out=json.dumps(report("block", [finding]))))
        self.assertEqual(rc, 1)
        doc = json.loads(out)
        self.assertEqual(doc["kind"], "iac-scan-report")
        self.assertNotIn("hunter2", out)

    def test_remote_and_write_flags_refused_before_running(self):
        runner = Runner()
        for argv in (["--repo", "https://example.com/x.git", "--ref", "main"],
                     [str(self.src), "--repo=https://example.com/x.git"],
                     [str(self.src), "--ref", "main"], [str(self.src), "--run"],
                     [str(self.src), "--output", "/tmp/x.json"],
                     [str(self.src), "--format", "sarif"], [str(self.src), "--fail-on"],
                     [str(self.src), "--fail-on", "high", "--fail-on", "low"],
                     [str(self.src), "--fail-on", "everything"],
                     [str(self.src), "extra"], []):
            rc, _, err = self._fleet(argv, runner)
            self.assertEqual(rc, 2, argv)
            self.assertIn("REFUSED", err)
        self.assertEqual(runner.calls, [])

    def test_unknown_fleet_subcommand_lists_iac(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli.Guard, "load", return_value=mock.Mock()), \
                redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(cli.main(["fleet", "nope"]), 2)
        self.assertIn("iac)", err.getvalue())


class StubExecutableTest(TmpBase):
    """The real subprocess path (env locate + capped reader) against a local
    stub script that prints a fixed report. Runs everywhere; no badfarm."""

    def test_env_stub_end_to_end(self):
        body = ("#!%s\nimport json, sys\nassert sys.argv[1:8] == ['iac', 'scan', '--format', "
                "'json', '--fail-on', 'high', '--'], sys.argv\nprint(json.dumps(%r))\nsys.exit(1)\n"
                % (sys.executable, report("block", [FINDING])))
        os.environ[iacgate.ENV_VAR] = str(self.exe(name="bf-stub", body=body))
        doc = iacgate.scan(str(self.src), timeout=60)
        self.assertEqual(doc["verdict"], "block")
        self.assertEqual(iacgate.classify(doc, "required")[0], "fail")

    def test_capped_reader_refuses_oversized_output(self):
        body = ("#!%s\nimport sys\nsys.stdout.write(' ' * %d)\n"
                % (sys.executable, iacgate.OUTPUT_CAP + 10))
        os.environ[iacgate.ENV_VAR] = str(self.exe(name="bf-big", body=body))
        with self.assertRaises(Refused):
            iacgate.scan(str(self.src), timeout=60)


if __name__ == "__main__":
    unittest.main()
