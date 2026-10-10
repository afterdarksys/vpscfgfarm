"""`vpsexec <hosts> push <file> --sha256 <hex>` — gated, content-addressed file push.

Hermetic: ssh, docker ps, ~/.ssh/config, the journal and telemetry are all
injected or redirected (the harness is test_vpsexec's), so nothing here can
reach a fleet host or write the real journal.

Most of these prove a REFUSAL, and that it happened before any transport:
a push whose bytes differ from the approved hash must never reach a host.
"""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402  (module, not names: no re-collection)
from vpscfg import vpsexec, vpsexecpolicy  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

CONTENT = b"\x7fELF fake diskwatch binary\n" * 50
OTHER = b"\x7fELF a different build\n" * 50


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class _PushHarness(tv._Harness):

    def setUp(self):
        super().setUp()
        self.work = tempfile.TemporaryDirectory()
        self.uploads = []
        self.probed = []

    def tearDown(self):
        self.work.cleanup()
        super().tearDown()

    def file(self, name="diskwatch", data=CONTENT, mode=0o755):
        path = os.path.join(self.work.name, name)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, mode)
        return path

    def push_ssh(self, present_hash=None, remote_hash=None, prepare_rc=0):
        """A fake host. `present_hash`: the final file already exists with
        that hash. `remote_hash`: what sha256sum of the temp reports (default:
        the true hash of what was uploaded)."""
        def _ssh(host, cmd, timeout=None, connect_timeout=None, data=None):
            self.ssh_calls.append((host, cmd))
            if data is not None:
                self.uploads.append((host, cmd, data))
            if "vpscfg.lock" in cmd:
                return 0, "", ""
            if cmd.startswith("umask 077; mkdir"):
                return prepare_rc, "", "unsafe staging dir: /var/tmp/vpscfg-push" if prepare_rc else ""
            if cmd.startswith("test -f"):
                if present_hash:
                    return 0, "%s  /var/tmp/x\n" % present_hash, ""
                return 1, "", ""
            if cmd.startswith("sha256sum"):
                got = remote_hash or _sha(self.uploads[-1][2])
                return 0, "%s  /var/tmp/x\n" % got, ""
            return 0, "", ""
        return _ssh

    def recording_prober(self):
        def _probe(host, what):
            self.probed.append(host)
            return {"host": host, "probe": what, "rc": 0, "stdout": "", "stderr": ""}
        return _probe

    def dispatch(self, argv, runbooks=None, policy=None, prompt=None, ssh=None,
                 gov=None):
        return vpsexec.dispatch(
            argv, guard=tv._guard(gov),
            policy=policy or tv._yaml_policy(runbooks=runbooks or []),
            prober=self.recording_prober(), ssh=ssh or self.push_ssh(),
            stream=tv.ApprovalTest._TTY() if prompt else tv.ApprovalTest._NoTTY(),
            prompt=prompt, today="2026-08-27",
            blackout_runner=self.blackout_runner(unavailable=True))

    def capture(self, argv, **kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.dispatch(argv, **kw)
        return rc, buf.getvalue()

    def plan_hash_of(self, argv, **kw):
        _, out = self.capture(argv, **kw)
        return [l.split()[-1] for l in out.splitlines() if l.startswith("plan-hash:")][0]

    def push_events(self):
        return [e for e in self.events() if e.get("event") == "push"]

    def remote(self):
        return [c for _, c in self.ssh_calls if "vpscfg.lock" not in c]


# ===========================================================================
# happy path
# ===========================================================================

class PushHappyPathTest(_PushHarness):

    def test_push_to_a_test_host_is_temp_then_verify_then_rename(self):
        path = self.file()
        sha = _sha(CONTENT)
        rc = self.dispatch(["edge1", "push", path, "--sha256", sha, "--run",
                            "--reason", "diskwatch canary"], prompt=lambda m: "edge1")
        self.assertEqual(rc, 0)
        final = "/var/tmp/vpscfg-push/%s/diskwatch" % sha
        cmds = self.remote()
        self.assertEqual(len(cmds), 5, cmds)
        prepare, present, upload, check, commit = cmds
        self.assertIn("mkdir -p -m 0700 /var/tmp/vpscfg-push /var/tmp/vpscfg-push/%s" % sha, prepare)
        self.assertIn("0:700", prepare)
        self.assertEqual(present, "test -f %s && test ! -L %s && sha256sum %s"
                         % (final, final, final))
        self.assertTrue(upload.startswith("umask 077; set -C; cat > /var/tmp/vpscfg-push/%s/.diskwatch.part-" % sha))
        tmp = upload.split("cat > ", 1)[1]
        self.assertEqual(check, "sha256sum %s" % tmp)
        self.assertEqual(commit, "chmod 0600 %s && mv -fT %s %s" % (tmp, tmp, final))
        # The exact bytes that were hashed are the bytes that were sent.
        self.assertEqual([(h, d) for h, _, d in self.uploads], [("edge1", CONTENT)])
        ev = self.push_events()
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["host"], ev[0]["sha256"], ev[0]["basename"],
                          ev[0]["size"], ev[0]["path"], ev[0]["outcome"]),
                         ("edge1", sha, "diskwatch", len(CONTENT), final, "pushed"))
        attempt = [e for e in self.events() if e["event"] == "mutation_attempt"][0]
        self.assertEqual(attempt["command"], "vpscfg-push %s diskwatch" % sha)
        self.assertEqual(attempt["push"]["sha256"], sha)
        self.assertNotIn("data", attempt["push"])
        done = [e for e in self.events() if e["event"] == "mutation_complete"][0]
        self.assertEqual(done["results"], {"edge1": 0})

    def test_plan_names_the_canonical_command_hash_and_path(self):
        path = self.file()
        sha = _sha(CONTENT)
        rc, out = self.capture(["edge1", "push", path, "--sha256", sha,
                                "--reason", "x"])
        self.assertEqual(rc, 0)
        self.assertIn("command : vpscfg-push %s diskwatch" % sha, out)
        self.assertIn("tier    : mutating", out)
        self.assertIn("/var/tmp/vpscfg-push/%s/diskwatch" % sha, out)
        self.assertIn("Plan only. Nothing has run.", out)

    def test_already_present_is_idempotent_and_uploads_nothing(self):
        path = self.file()
        sha = _sha(CONTENT)
        rc = self.dispatch(["edge1", "push", path, "--sha256", sha, "--run",
                            "--reason", "again"], prompt=lambda m: "edge1",
                           ssh=self.push_ssh(present_hash=sha))
        self.assertEqual(rc, 0)
        self.assertEqual(self.uploads, [])
        self.assertFalse(any("mv -fT" in c for c in self.remote()))
        self.assertEqual(self.push_events()[0]["outcome"], "already_present")

    def test_local_file_changing_after_plan_does_not_change_what_is_sent(self):
        """TOCTOU: the file is read once. Rewriting it while the operator reads
        the plan must not change the bytes that reach the host."""
        path = self.file()
        sha = _sha(CONTENT)

        def approve_after_swap(msg):
            with open(path, "wb") as f:
                f.write(OTHER)
            return "edge1"
        rc = self.dispatch(["edge1", "push", path, "--sha256", sha, "--run",
                            "--reason", "x"], prompt=approve_after_swap)
        self.assertEqual(rc, 0)
        self.assertEqual(self.uploads[0][2], CONTENT)

    def test_approve_with_matching_plan_hash_runs_unattended(self):
        path = self.file()
        sha = _sha(CONTENT)
        args = ["edge1", "push", path, "--sha256", sha, "--reason", "x"]
        digest = self.plan_hash_of(args)
        rc = self.dispatch(args + ["--run", "--approve=" + digest])
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.uploads), 1)


# ===========================================================================
# local refusals — all before any transport
# ===========================================================================

class PushLocalRefusalTest(_PushHarness):

    def assertRefusedBeforeTransport(self, argv, fragment):
        with self.assertRaises(Refused) as cm:
            self.dispatch(argv, prompt=lambda m: "edge1")
        self.assertIn(fragment, str(cm.exception))
        self.assertEqual(self.ssh_calls, [])
        self.assertEqual(self.probed, [])
        self.assertEqual(self.uploads, [])

    def test_wrong_sha256_is_refused(self):
        path = self.file()
        self.assertRefusedBeforeTransport(
            ["edge1", "push", path, "--sha256", _sha(OTHER), "--run", "--reason", "x"],
            "not the --sha256 given")

    def test_missing_or_malformed_sha256_is_refused(self):
        path = self.file()
        for extra in ([], ["--sha256", "abc"], ["--sha256", "g" * 64]):
            self.assertRefusedBeforeTransport(
                ["edge1", "push", path] + extra + ["--run", "--reason", "x"],
                "--sha256")

    def test_symlink_is_refused(self):
        target = self.file()
        link = os.path.join(self.work.name, "diskwatch-link")
        os.symlink(target, link)
        self.assertRefusedBeforeTransport(
            ["edge1", "push", link, "--sha256", _sha(CONTENT), "--run", "--reason", "x"],
            "symlink")

    def test_directory_is_refused(self):
        d = os.path.join(self.work.name, "adir")
        os.mkdir(d)
        self.assertRefusedBeforeTransport(
            ["edge1", "push", d, "--sha256", _sha(b""), "--run", "--reason", "x"],
            "directory")

    def test_device_is_refused(self):
        self.assertRefusedBeforeTransport(
            ["edge1", "push", "/dev/null", "--sha256", _sha(b""), "--run", "--reason", "x"],
            "device")

    def test_oversize_is_refused(self):
        path = self.file()
        real = vpsexec.PUSH_MAX_BYTES
        vpsexec.PUSH_MAX_BYTES = len(CONTENT) - 1
        try:
            self.assertRefusedBeforeTransport(
                ["edge1", "push", path, "--sha256", _sha(CONTENT), "--run", "--reason", "x"],
                "cap")
        finally:
            vpsexec.PUSH_MAX_BYTES = real

    def test_bad_basenames_are_refused(self):
        for name in ("has space", "-rf", "x" * 65, "semi;colon", "dollar$x"):
            path = self.file(name=name)
            self.assertRefusedBeforeTransport(
                ["edge1", "push", path, "--sha256", _sha(CONTENT), "--run", "--reason", "x"],
                "basename")
        self.assertRefusedBeforeTransport(
            ["edge1", "push", self.work.name + "/..", "--sha256", _sha(CONTENT),
             "--run", "--reason", "x"], "basename")

    def test_trailing_newline_or_cr_in_basename_or_sha_is_refused(self):
        """`$` in a .match regex accepts a trailing newline, and normalize()
        strips it — so "diskwatch\n" would have matched a runbook for "diskwatch"."""
        for name in ("diskwatch\n", "diskwatch\r", "diskwatch\r\n"):
            self.assertRefusedBeforeTransport(
                ["edge1", "push", self.file(name=name), "--sha256",
                 _sha(CONTENT), "--run", "--reason", "x"], "basename")
        path = self.file()
        for sha in (_sha(CONTENT) + "\n", _sha(CONTENT) + "\r", " " + _sha(CONTENT)):
            self.assertRefusedBeforeTransport(
                ["edge1", "push", path, "--sha256", sha, "--run", "--reason", "x"],
                "--sha256")

    def test_newline_basename_cannot_ride_a_frozen_host_runbook(self):
        sha = _sha(CONTENT)
        rb = [tv._runbook(["web1"], "vpscfg-push %s diskwatch" % sha, break_glass=True)]
        with self.assertRaises(Refused):
            self.dispatch(["web1", "push", self.file(name="diskwatch\n"),
                           "--sha256", sha, "--break-glass", "--run", "--reason", "x"],
                          runbooks=rb, prompt=lambda m: "BREAK-GLASS:1")
        self.assertEqual(self.ssh_calls, [])

    def test_placement_flags_are_refused(self):
        path = self.file()
        for flag in (["--in", "shop-api"], ["--in-all"], ["--compare"]):
            self.assertRefusedBeforeTransport(
                ["edge1", "push", path, "--sha256", _sha(CONTENT)] + flag
                + ["--run", "--reason", "x"], "do not apply")

    def test_sha256_flag_is_unknown_outside_push(self):
        with self.assertRaises(Refused):
            self.dispatch(["edge1", "df -h", "--sha256", _sha(CONTENT)])

    def test_canonical_spelling_cannot_be_run_as_a_command(self):
        with self.assertRaises(Refused) as cm:
            self.dispatch(["edge1", "vpscfg-push %s diskwatch" % _sha(CONTENT), "--run",
                           "--reason", "x"], prompt=lambda m: "edge1")
        self.assertIn("reserved", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])


# ===========================================================================
# the mutation gates, applied to a push
# ===========================================================================

class PushGateTest(_PushHarness):

    def test_no_run_is_plan_only(self):
        path = self.file()
        rc = self.dispatch(["edge1", "push", path, "--sha256", _sha(CONTENT),
                            "--reason", "x"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.ssh_calls, [])
        self.assertEqual(self.uploads, [])

    def test_no_reason_is_refused(self):
        path = self.file()
        with self.assertRaises(Refused) as cm:
            self.dispatch(["edge1", "push", path, "--sha256", _sha(CONTENT), "--run"],
                          prompt=lambda m: "edge1")
        self.assertIn("--reason", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_no_tty_and_no_approve_is_refused(self):
        path = self.file()
        with self.assertRaises(Refused) as cm:
            self.dispatch(["edge1", "push", path, "--sha256", _sha(CONTENT),
                           "--run", "--reason", "x"])
        self.assertIn("no TTY", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_plan_hash_binds_the_content_hash(self):
        a = self.file("diskwatch", CONTENT)
        b = os.path.join(self.work.name, "b")
        os.mkdir(b)
        b = os.path.join(b, "diskwatch")
        with open(b, "wb") as f:
            f.write(OTHER)
        ha = self.plan_hash_of(["edge1", "push", a, "--sha256", _sha(CONTENT), "--reason", "x"])
        hb = self.plan_hash_of(["edge1", "push", b, "--sha256", _sha(OTHER), "--reason", "x"])
        self.assertNotEqual(ha, hb)
        # An approval for one content cannot push another.
        with self.assertRaises(Refused) as cm:
            self.dispatch(["edge1", "push", b, "--sha256", _sha(OTHER), "--run",
                           "--reason", "x", "--approve=" + ha])
        self.assertIn("does not match", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_push_plan_hash_differs_from_the_same_text_as_a_command(self):
        plan = vpsexec.build_plan(["edge1"], "vpscfg-push %s diskwatch" % _sha(CONTENT),
                                  {"edge1": []}, "mutating", None)
        plain = vpsexec.plan_hash(plan)
        plan["push"] = {"sha256": _sha(CONTENT), "basename": "diskwatch",
                        "size": len(CONTENT), "path": "/p"}
        self.assertNotEqual(plain, vpsexec.plan_hash(plan))

    def test_frozen_host_without_break_glass_is_refused(self):
        path = self.file()
        sha = _sha(CONTENT)
        rb = [tv._runbook(["web1"], "vpscfg-push %s diskwatch" % sha, break_glass=True)]
        with self.assertRaises(Refused) as cm:
            self.dispatch(["web1", "push", path, "--sha256", sha, "--run",
                           "--reason", "x"], runbooks=rb, prompt=lambda m: "web1")
        self.assertIn("web1(frozen)", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_break_glass_without_a_matching_runbook_is_refused(self):
        path = self.file()
        sha = _sha(CONTENT)
        for rb in ([],
                   [tv._runbook(["web1"], "vpscfg-push %s diskwatch" % _sha(OTHER), break_glass=True)],
                   [tv._runbook(["web1"], "vpscfg-push %s other" % sha, break_glass=True)],
                   [tv._runbook(["web1"], "vpscfg-push %s diskwatch" % sha, break_glass=False)]):
            self.ssh_calls = []
            with self.assertRaises(Refused) as cm:
                self.dispatch(["web1", "push", path, "--sha256", sha, "--break-glass",
                               "--run", "--reason", "x"], runbooks=rb,
                              prompt=lambda m: "BREAK-GLASS:1")
            self.assertIn("break_glass runbook", str(cm.exception))
            self.assertEqual(self.ssh_calls, [])

    def test_break_glass_with_the_exact_runbook_pushes_to_a_frozen_host(self):
        path = self.file()
        sha = _sha(CONTENT)
        rb = [tv._runbook(["web1"], "vpscfg-push %s diskwatch" % sha, break_glass=True)]
        rc = self.dispatch(["web1", "push", path, "--sha256", sha, "--break-glass",
                            "--run", "--reason", "diskwatch upgrade"], runbooks=rb,
                           prompt=lambda m: "BREAK-GLASS:1")
        self.assertEqual(rc, 0)
        self.assertEqual([(h, d) for h, _, d in self.uploads], [("web1", CONTENT)])
        bg = [e for e in self.events() if e["event"] == "break_glass"]
        self.assertEqual(bg[0]["hosts"], ["web1"])
        self.assertEqual(bg[0]["command"], "vpscfg-push %s diskwatch" % sha)

    def test_mode_and_master_switch_still_apply(self):
        path = self.file()
        for gov in (tv._policy(mutation=False), tv._policy(mode="lockdown")):
            self.ssh_calls = []
            with self.assertRaises(Refused):
                self.dispatch(["edge1", "push", path, "--sha256", _sha(CONTENT),
                               "--run", "--reason", "x"], gov=gov,
                              prompt=lambda m: "edge1")
            self.assertEqual(self.ssh_calls, [])


# ===========================================================================
# transport failures
# ===========================================================================

class PushTransportTest(_PushHarness):

    def test_remote_hash_mismatch_removes_the_temp_and_fails(self):
        path = self.file()
        sha = _sha(CONTENT)
        rc = self.dispatch(["edge1", "push", path, "--sha256", sha, "--run",
                            "--reason", "x"], prompt=lambda m: "edge1",
                           ssh=self.push_ssh(remote_hash=_sha(OTHER)))
        self.assertEqual(rc, 1)
        cmds = self.remote()
        tmp = cmds[2].split("cat > ", 1)[1]
        self.assertEqual(cmds[-1], "rm -f %s" % tmp)
        self.assertFalse(any("mv -fT" in c for c in cmds))
        ev = self.push_events()
        self.assertEqual(ev[0]["outcome"], "hash_mismatch")
        done = [e for e in self.events() if e["event"] == "mutation_complete"][0]
        self.assertEqual(done["failed"], ["edge1"])

    def test_unsafe_staging_dir_refuses_before_upload(self):
        path = self.file()
        rc = self.dispatch(["edge1", "push", path, "--sha256", _sha(CONTENT), "--run",
                            "--reason", "x"], prompt=lambda m: "edge1",
                           ssh=self.push_ssh(prepare_rc=1))
        self.assertEqual(rc, 1)
        self.assertEqual(self.uploads, [])
        self.assertEqual(self.push_events()[0]["outcome"], "staging_refused")

    def test_refusal_inside_the_host_run_is_journaled_as_a_push_event(self):
        path = self.file()
        push = vpsexec.load_push_file(path, _sha(CONTENT))
        plan = {"push": dict((k, v) for k, v in push.items() if k != "data"),
                "push_data": push["data"]}
        result = {"outputs": [], "rc": 0, "error": None}
        with self.assertRaises(Refused):
            vpsexec._push_one_host("edge1", plan, ["cat >"], self.push_ssh(), 60, result)
        self.assertEqual(self.ssh_calls, [])
        ev = self.push_events()
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["outcome"], "refused")
        self.assertIn("cat >", ev[0]["detail"])

    def test_upload_timeout_scales_with_size_and_is_capped(self):
        mib = 1 << 20
        self.assertEqual(vpsexec.upload_timeout(0, 120), 120)
        self.assertEqual(vpsexec.upload_timeout(1, 120), 121)
        self.assertEqual(vpsexec.upload_timeout(256 * mib, 120), 376)
        self.assertEqual(vpsexec.upload_timeout(10 ** 12, 120),
                         vpsexec.PUSH_UPLOAD_TIMEOUT_CAP)
        self.assertEqual(vpsexec.upload_timeout(0, 5000), 5000)  # never lowers
        seen = {}
        inner = self.push_ssh()

        def timing(host, cmd, timeout=None, connect_timeout=None, data=None):
            seen.setdefault("upload" if data is not None else cmd, timeout)
            return inner(host, cmd, timeout=timeout, data=data)
        path = self.file()
        self.dispatch(["edge1", "push", path, "--sha256", _sha(CONTENT), "--run",
                       "--reason", "x", "--timeout", "30"], prompt=lambda m: "edge1",
                      ssh=timing)
        self.assertEqual(seen["upload"], 31)

    def test_transport_drop_is_journaled_and_retains_the_lock(self):
        path = self.file()
        inner = self.push_ssh()

        def dropping(host, cmd, timeout=None, connect_timeout=None, data=None):
            if data is not None:
                self.ssh_calls.append((host, cmd))
                raise OSError("SSH connection lost; remote completion is unknown")
            return inner(host, cmd, timeout=timeout, data=data)
        rc = self.dispatch(["edge1", "push", path, "--sha256", _sha(CONTENT), "--run",
                            "--reason", "x"], prompt=lambda m: "edge1", ssh=dropping)
        self.assertEqual(rc, 1)
        self.assertEqual(self.push_events()[0]["outcome"], "transport_error")
        self.assertFalse(any("rmdir /run/vpscfg.lock" in c for _, c in self.ssh_calls))


# ===========================================================================
# deny floor / deny_extra sweep
# ===========================================================================

class PushDenySweepTest(_PushHarness):

    def test_floor_pattern_in_basename_is_refused(self):
        path = self.file(name="mkfs.helper")
        with self.assertRaises(Refused) as cm:
            self.dispatch(["edge1", "push", path, "--sha256", _sha(CONTENT), "--run",
                           "--reason", "x"], prompt=lambda m: "edge1")
        self.assertIn("mkfs", str(cm.exception))
        self.assertEqual(self.ssh_calls, [])

    def test_deny_extra_in_basename_or_local_path_is_refused(self):
        pol = tv._yaml_policy(deny_extra=["id_rsa"])
        key = self.file(name="id_rsa")
        d = os.path.join(self.work.name, "id_rsa.d")
        os.mkdir(d)
        inside = os.path.join(d, "blob")
        with open(inside, "wb") as f:
            f.write(CONTENT)
        for path in (key, inside):
            self.ssh_calls = []
            with self.assertRaises(Refused) as cm:
                self.dispatch(["edge1", "push", path, "--sha256", _sha(CONTENT),
                               "--run", "--reason", "x"], policy=pol,
                              prompt=lambda m: "edge1")
            self.assertIn("id_rsa", str(cm.exception))
            self.assertEqual(self.ssh_calls, [])

    def _wrapper(self):
        root = Path(tv.REPO)
        loader = importlib.machinery.SourceFileLoader("vpsexec_wrapper_push_test",
                                                      str(root / "vpsexec"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod

    @tv.unittest.skipUnless(vpsexecpolicy._HAVE_YAML, "PyYAML unavailable")
    def test_outer_door_sweeps_reason_and_basename_like_any_command(self):
        wrapper = self._wrapper()
        gov = {"allowed_verbs": ["exec"], "deny_always": list(tv.DENY),
               "mutation_enabled": True, "mode": "test",
               "hosts": {"edge1": {"posture": "test"}}}
        sha = _sha(CONTENT)
        for argv in (["edge1", "push", "/tmp/diskwatch", "--sha256", sha, "--run",
                      "--reason", "then TRUNCATE the table"],
                     ["edge1", "push", "/tmp/mkfs.helper", "--sha256", sha, "--run",
                      "--reason", "x"]):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    wrapper.judge(gov, argv)
        # A clean push is a mutation to the outer door, judged by posture.
        j = wrapper.judge(gov, ["edge1", "push", "/tmp/diskwatch", "--sha256", sha,
                                "--run", "--reason", "x"])
        self.assertFalse(j["read_only"])
        self.assertEqual(j["hosts"], ["edge1"])
        gov["hosts"]["edge1"]["posture"] = "frozen"
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                wrapper.judge(gov, ["edge1", "push", "/tmp/diskwatch", "--sha256", sha,
                                    "--run", "--reason", "x"])


class ContentCheckClassificationTest(tv.unittest.TestCase):
    """The documented install and verify forms, with a real hash."""
    SHA = _sha(CONTENT)

    def test_hash_check_verify_is_a_read_and_install_is_a_mutation(self):
        verify = "echo '%s  /usr/local/bin/diskwatch' | sha256sum --check --status" % self.SHA
        self.assertEqual(vpsexec.classify(verify, list(tv.DENY))[0], "read")
        staged = "/var/tmp/vpscfg-push/%s/diskwatch" % self.SHA
        install = ("echo '%s  %s' | sha256sum --check --status && install -m 0755 "
                   "-o root -g root %s /usr/local/bin/diskwatch" % (self.SHA, staged, staged))
        self.assertEqual(vpsexec.classify(install, list(tv.DENY))[0], "mutating")

    @tv.unittest.skipUnless(__import__("shutil").which("sha256sum"), "no sha256sum")
    def test_hash_check_verify_fails_on_the_wrong_bytes(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "diskwatch")
            with open(f, "wb") as fh:
                fh.write(CONTENT)
            cmd = "echo '%s  %s' | sha256sum --check --status"
            ok = subprocess.run(["sh", "-c", cmd % (self.SHA, f)])
            bad = subprocess.run(["sh", "-c", cmd % (_sha(OTHER), f)])
            missing = subprocess.run(["sh", "-c", cmd % (self.SHA, f + ".x")],
                                     stderr=subprocess.DEVNULL)
        self.assertEqual(ok.returncode, 0)
        self.assertNotEqual(bad.returncode, 0)
        self.assertNotEqual(missing.returncode, 0)


def _gnu_shim():
    """A PATH dir whose stat/mv/sha256sum are GNU coreutils (the fleet's), or
    None. On Linux these are the system tools; on macOS, Homebrew's g*."""
    import shutil
    import subprocess
    if not shutil.which("bash"):
        return None
    import atexit
    shim = tempfile.mkdtemp()
    atexit.register(shutil.rmtree, shim, True)
    for tool in ("stat", "mv", "sha256sum"):
        for alt in (tool, "g" + tool):
            found = shutil.which(alt)
            if not found:
                continue
            try:
                out = subprocess.run([found, "--version"], capture_output=True,
                                     text=True, timeout=10).stdout
            except OSError:
                continue
            if "GNU" in out:
                os.symlink(found, os.path.join(shim, tool))
                break
        else:
            return None
    return shim


_SHIM = _gnu_shim()


@tv.unittest.skipUnless(_SHIM, "bash + GNU stat/mv/sha256sum unavailable")
class RealRemoteScriptTest(tv._Harness):
    """Runs the REAL strings from push_remote_commands() under local bash, with
    a temporary PUSH_ROOT and no ssh — the fake-ssh tests only prove which
    strings are sent, not what they do."""

    def setUp(self):
        super().setUp()
        self.work = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.work.name, "vpscfg-push")
        self._real_root = vpsexec.PUSH_ROOT
        vpsexec.PUSH_ROOT = self.root
        src = os.path.join(self.work.name, "diskwatch")
        with open(src, "wb") as f:
            f.write(CONTENT)
        self.push = vpsexec.load_push_file(src, _sha(CONTENT))
        self.uid = os.getuid()

    def tearDown(self):
        vpsexec.PUSH_ROOT = self._real_root
        self.work.cleanup()
        super().tearDown()

    def local_ssh(self, host, cmd, timeout=None, connect_timeout=None, data=None):
        import subprocess
        r = subprocess.run(["bash", "-c", cmd], input=data or b"",
                           capture_output=True, timeout=60,
                           env={"PATH": _SHIM + os.pathsep + os.environ["PATH"]})
        return r.returncode, r.stdout.decode(), r.stderr.decode()

    def run_push(self, data=None, owner_uid=None, tmp_suffix="t1"):
        tmp = "%s/.diskwatch.part-%s" % (self.push["dir"], tmp_suffix)
        cmds = vpsexec.push_remote_commands(
            self.push, tmp, owner_uid=self.uid if owner_uid is None else owner_uid)
        return vpsexec._push_steps("local", self.push,
                                   CONTENT if data is None else data,
                                   cmds, self.local_ssh, 60), tmp

    def mode(self, p):
        return oct(os.lstat(p).st_mode & 0o777)

    def leftovers(self):
        d = self.push["dir"]
        return [n for n in os.listdir(d) if ".part-" in n] if os.path.isdir(d) else []

    def test_clean_run_then_already_present(self):
        (outcome, detail), _ = self.run_push()
        self.assertEqual(outcome, "pushed", detail)
        self.assertEqual(self.mode(self.root), "0o700")
        self.assertEqual(self.mode(self.push["dir"]), "0o700")
        self.assertEqual(self.mode(self.push["path"]), "0o600")
        with open(self.push["path"], "rb") as f:
            self.assertEqual(f.read(), CONTENT)
        self.assertEqual(self.leftovers(), [])
        (outcome, _), _ = self.run_push(tmp_suffix="t2")
        self.assertEqual(outcome, "already_present")

    def test_pre_existing_temp_is_refused_and_nothing_renamed(self):
        os.makedirs(self.push["dir"], mode=0o700)
        os.chmod(self.root, 0o700)
        tmp = "%s/.diskwatch.part-t1" % self.push["dir"]
        with open(tmp, "wb") as f:
            f.write(OTHER)
        (outcome, _), _ = self.run_push()
        self.assertEqual(outcome, "upload_failed")
        self.assertFalse(os.path.exists(self.push["path"]))

    def test_hash_mismatch_removes_the_temp(self):
        (outcome, _), tmp = self.run_push(data=OTHER)
        self.assertEqual(outcome, "hash_mismatch")
        self.assertFalse(os.path.exists(tmp))
        self.assertFalse(os.path.exists(self.push["path"]))
        self.assertEqual(self.leftovers(), [])

    def test_symlinked_staging_root_is_refused(self):
        real = os.path.join(self.work.name, "elsewhere")
        os.mkdir(real, 0o700)
        os.symlink(real, self.root)
        (outcome, _), _ = self.run_push()
        self.assertEqual(outcome, "staging_refused")
        self.assertEqual(os.listdir(os.path.join(real, _sha(CONTENT))), [])

    def test_wrong_mode_staging_root_is_refused(self):
        os.mkdir(self.root)
        os.chmod(self.root, 0o755)
        (outcome, _), _ = self.run_push()
        self.assertEqual(outcome, "staging_refused")
        self.assertFalse(os.path.exists(self.push["path"]))

    def test_staging_dir_not_owned_by_the_required_uid_is_refused(self):
        if self.uid == 0:
            os.mkdir(self.root, 0o700)
            os.chown(self.root, 65534, 65534)
            owner = 0
        else:
            owner = 0  # as a normal user the dirs are ours, not root's
        (outcome, _), _ = self.run_push(owner_uid=owner)
        self.assertEqual(outcome, "staging_refused")
        self.assertFalse(os.path.exists(self.push["path"]))


if __name__ == "__main__":
    import unittest
    unittest.main()
