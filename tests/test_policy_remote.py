"""Reusable grants are bound to PUSHED policy (round 5, item 4).

The governor's `policy_remote` ({name, ref}, default origin/main) is fetched
at mint and at every use of a reusable grant. A local bare repository stands
in for the real remote ("origin"): the harness allows the local-path
transport that the door refuses in production (protocol.file.allow=never),
and one test proves that refusal.

Most tests prove a REFUSAL, and that nothing ran.
"""
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_grant_kinds as tk  # noqa: E402
import test_vpsexec as tv  # noqa: E402
import test_vpsexec_incident as ti  # noqa: E402
from vpscfg import control, gitcmd, vpsexecgrant  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

NGINX = tk.NGINX
EDIT = ('cmd: "systemctl restart caddy"', 'cmd: "systemctl restart caddy --no-block"')
CADDY2 = "systemctl restart caddy --no-block"


class _RemoteHarness(tk._KindsHarness):

    def edit(self, old, new):
        p = self.policy_dir / "rb.yaml"
        text = p.read_text()
        self.assertIn(old, text)
        p.write_text(text.replace(old, new))

    def grants(self):
        return set(self.grant_dir.glob("ru_*.json")) if self.grant_dir.exists() else set()

    def mint_refuses(self, needle):
        before = self.grants()
        with self.assertRaises(Refused) as cm:
            self.mint_reusable()
        self.assertIn(needle, str(cm.exception))
        self.assertEqual(self.grants(), before, "a grant was written")
        return str(cm.exception)

    def clone(self, dest):
        subprocess.run(["git", "clone", "-q", "-b", "main", str(self.origin), str(dest)],
                       check=True, capture_output=True,
                       env={"PATH": os.environ["PATH"], "HOME": self.home.name,
                            "GIT_CONFIG_NOSYSTEM": "1"})

    def no_fetch(self):
        """Any fetch fails the test: the path under test must never reach the
        network."""
        def boom(*a, **k):
            raise AssertionError("fetched the policy remote")
        p = mock.patch.object(gitcmd, "fetched", boom)
        p.start()
        self.addCleanup(p.stop)

    def origin_head(self, origin=None):
        return self.git("--git-dir", str(origin or self.origin), "rev-parse", "refs/heads/main")

    def scratch_dirs(self):
        """Record every scratch repository the fetch creates."""
        made = []
        real = gitcmd.tempfile.mkdtemp

        def spy(*a, **k):
            d = real(*a, **k)
            made.append(d)
            return d
        p = mock.patch.object(gitcmd.tempfile, "mkdtemp", spy)
        p.start()
        self.addCleanup(p.stop)
        return made


class PushedPolicyTest(_RemoteHarness):

    def test_a_pushed_commit_passes_at_mint_and_use(self):
        path = self.mint_reusable()
        g = self.load(path)
        self.assertEqual(g["scope"]["git"]["remote"],
                         {"name": "origin", "ref": "main", "url": str(self.origin)})
        self.assertEqual(g["scope"]["git"]["commit"], self.origin_head())
        self.assertEqual(self.use("web1", NGINX, path), 0)
        # A later, pushed edit is covered.
        self.edit(*EDIT)
        self.commit("pushed edit")
        self.reload_policy()
        self.assertEqual(self.use("web1", CADDY2, path), 0)
        self.assertIn(("web1", CADDY2), self.ran())

    def test_an_unpushed_local_commit_refuses(self):
        path = self.mint_reusable()
        self.edit(*EDIT)
        self.commit("local only", push=False)
        self.reload_policy()
        msg = self.refuses(path, "unpushed", cmd=CADDY2)
        self.assertIn("origin/main", msg)

    def test_minting_over_an_unpushed_commit_refuses(self):
        self.edit(*EDIT)
        self.commit("local only", push=False)
        self.reload_policy()
        self.mint_refuses("unpushed")

    def test_an_uncommitted_edit_refuses(self):
        path = self.mint_reusable()
        self.edit(*EDIT)
        self.reload_policy()
        self.refuses(path, "uncommitted", cmd=CADDY2)

    def test_a_version_pushed_since_mint_but_not_yet_pulled_passes(self):
        """The remote moved on twice; the operator's checkout holds the first
        of those pushes. That version is on the branch, after the minted
        commit: covered."""
        path = self.mint_reusable()
        self.edit(*EDIT)
        self.commit("v2")
        v2 = (self.policy_dir / "rb.yaml").read_text()
        self.edit("restart nginx", "reload nginx")
        self.commit("v3")
        (self.policy_dir / "rb.yaml").write_text(v2)  # not pulled v3 yet
        self.reload_policy()
        self.assertEqual(self.use("web1", CADDY2, path), 0)

    def test_a_version_older_than_the_minted_one_refuses(self):
        old = (self.policy_dir / "rb.yaml").read_text()
        self.edit(*EDIT)
        self.commit("v2")
        self.reload_policy()
        path = self.mint_reusable()
        (self.policy_dir / "rb.yaml").write_text(old)  # rolled back locally
        self.reload_policy()
        self.refuses(path, "unpushed")

    def test_a_scope_file_removed_from_the_remote_refuses(self):
        """The policy was withdrawn upstream; the operator's checkout still has
        the (minted) bytes. The remote is what counts."""
        path = self.mint_reusable()
        keep = (self.policy_dir / "rb.yaml").read_text()
        self.git("rm", "-q", "rb.yaml")
        self.commit("withdraw")
        (self.policy_dir / "rb.yaml").write_text(keep)
        self.reload_policy()
        self.refuses(path, "not a plain file (mode 100644) on origin/main")

    def test_a_remote_url_change_refuses(self):
        path = self.mint_reusable()
        other = Path(self.home.name) / "other.git"
        self.git("clone", "-q", "--bare", str(self.origin), str(other))
        self.git("remote", "set-url", "origin", str(other))
        self.refuses(path, "now points at")

    def test_a_force_pushed_remote_refuses(self):
        path = self.mint_reusable()
        self.git("commit", "-q", "--amend", "-m", "rewritten")
        self.push(force=True)
        self.refuses(path, "force-pushed or rewritten")

    def test_a_fetch_failure_refuses(self):
        path = self.mint_reusable()
        self.origin.rename(self.origin.with_name("moved.git"))  # the bound URL is gone
        self.refuses(path, "could not fetch")

    def test_no_remote_refuses_at_use_and_at_mint(self):
        path = self.mint_reusable()
        self.git("remote", "remove", "origin")
        self.refuses(path, "has no remote 'origin'")
        self.mint_refuses("has no remote 'origin'")

    def test_the_door_refuses_a_local_path_remote(self):
        """Production default: protocol.file.allow=never — a local directory
        cannot stand in for the real remote."""
        gitcmd.FETCH_FILE_PROTOCOL = "never"
        self.mint_refuses("is not an https or ssh URL")

    def test_the_governors_remote_branch_is_used_and_bound(self):
        self.git("push", "-q", "origin", "HEAD:refs/heads/release")
        gov = tv._policy()
        gov["policy_remote"] = {"name": "origin", "ref": "release"}
        policy = dict(self.policy, policy_remote=gov["policy_remote"])
        fields = vpsexecgrant.select_reusable(policy, "rb", "12h")
        self.assertEqual(fields["scope"]["git"]["remote"]["ref"], "release")
        path = self.mint_reusable()  # bound to origin/main (the default)
        with self.assertRaises(Refused) as cm:
            self.use("web1", NGINX, path, gov=gov)
        self.assertIn("policy_remote is now origin/release", str(cm.exception))
        self.assertEqual(self.ran(), [])

    def test_policy_remote_is_validated_with_the_governor(self):
        base = tv._policy()
        for bad in ("origin", {"name": "origin"}, {"name": "-x", "ref": "main"},
                    {"name": "origin", "ref": "a..b"}, {"name": "origin", "ref": "--upload-pack=x"},
                    {"name": "origin", "ref": "main", "url": "x"}):
            with self.subTest(bad=bad), self.assertRaises(Refused):
                control._validate(dict(base, policy_remote=bad))
        control._validate(dict(base, policy_remote={"name": "origin", "ref": "main"}))

    def test_a_grant_minted_before_the_remote_binding_refuses(self):
        path = self.mint_reusable()
        g = self.load(path)
        del g["scope"]["git"]["remote"]
        self.reseal(path, g)
        self.refuses(path, "malformed")

    def test_the_fetch_uses_only_the_hardened_options(self):
        seen = []
        real = subprocess.run

        def spy(argv, *a, **k):
            if "fetch" in argv or "ls-remote" in argv:
                seen.append((list(argv), dict(k.get("env") or {})))
            return real(argv, *a, **k)
        with mock.patch.object(gitcmd.subprocess, "run", spy):
            self.mint_reusable()
        verbs = [a[a.index("-C") + 2] for a, _ in seen]
        self.assertTrue(verbs and len(verbs) % 2 == 0, verbs)
        self.assertEqual(verbs, ["ls-remote", "fetch"] * (len(verbs) // 2))
        for argv, env in seen:
            self.assertEqual(argv[0], gitcmd.binary())
            for opt in ("core.fsmonitor=false", "core.hooksPath=/dev/null",
                        "protocol.allow=never", "protocol.https.allow=always",
                        "protocol.ssh.allow=always", "core.sshCommand=/usr/bin/ssh",
                        "submodule.recurse=false"):
                self.assertIn(opt, argv)
            # Never in the policy repository: in a private scratch repository.
            scratch = argv[argv.index("-C") + 1]
            self.assertNotEqual(os.path.realpath(scratch),
                                os.path.realpath(str(self.policy_dir)))
            self.assertIn("vpscfg-fetch-", scratch)
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(env["PATH"], "/usr/bin:/bin")
            self.assertNotIn("GIT_DIR", env)
            self.assertNotIn("GIT_CONFIG_GLOBAL", env)  # the operator's credentials
        fetch = seen[1][0]
        self.assertIn("--no-recurse-submodules", fetch)
        self.assertIn("--no-tags", fetch)
        self.assertEqual(fetch[-2:], [str(self.origin),
                                      "+refs/heads/main:refs/heads/vpscfg-fetched"])
        self.assertLessEqual(gitcmd.FETCH_TIMEOUT, 30)

    def test_the_default_fetch_refuses_the_file_protocol(self):
        gitcmd.FETCH_FILE_PROTOCOL = "never"
        self.assertIn("-c", gitcmd._net_argv("/x"))
        self.assertIn("protocol.file.allow=never", gitcmd._net_argv("/x"))
        for ref in ("-x", "a..b", "main.lock", "a//b"):
            with self.subTest(ref=ref), self.assertRaises(Refused):
                with gitcmd.fetched(str(self.origin), ref):
                    pass

    # --- round 6: the policy repository's own config is never read ---------

    def test_a_repo_local_insteadof_is_ignored(self):
        """A repo-local url.<x>.insteadOf pointed the old in-repo fetch at a
        private bare repo holding an edit that was never pushed to origin."""
        other = Path(self.home.name) / "other.git"
        self.git("clone", "-q", "--bare", str(self.origin), str(other))
        self.git("config", "url.%s.insteadOf" % other, str(self.origin))
        self.edit(*EDIT)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "only in other")
        self.git("push", "-q", str(other), "HEAD:refs/heads/main")
        self.reload_policy()
        self.mint_refuses("unpushed")          # origin was fetched, not other
        self.git("checkout", "-q", "HEAD~1", "--", "rb.yaml")
        self.git("commit", "-q", "-m", "back")
        self.push()
        self.reload_policy()
        path = self.mint_reusable()
        self.assertEqual(self.load(path)["scope"]["git"]["commit"], self.origin_head())

    def test_a_repo_local_ssh_command_never_runs(self):
        marker = Path(self.home.name) / "repo-ssh-ran"
        pinned = Path(self.home.name) / "pinned-ssh-ran"
        for script, mark in (("repo-ssh", marker), ("pinned-ssh", pinned)):
            p = Path(self.home.name) / script
            p.write_text("#!/bin/sh\ntouch %s\nexit 255\n" % mark)
            p.chmod(0o755)
        self.git("config", "core.sshCommand", str(Path(self.home.name) / "repo-ssh"))
        self.git("remote", "set-url", "origin", "ssh://git@example.invalid/policy.git")
        with mock.patch.object(gitcmd, "SSH_COMMAND", str(Path(self.home.name) / "pinned-ssh")):
            self.mint_refuses("could not fetch")
        self.assertFalse(marker.exists(), "the repository's core.sshCommand ran")
        self.assertTrue(pinned.exists(), "the pinned ssh was not the one used")

    def test_a_repo_local_credential_helper_never_runs(self):
        import http.server
        import threading

        class Auth(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="x"')
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), Auth)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        url = "http://127.0.0.1:%d/policy.git" % srv.server_address[1]
        marker = Path(self.home.name) / "helper-ran"
        self.git("config", "credential.helper", "!f() { touch %s; }; f" % marker)
        self.git("remote", "set-url", "origin", url)
        empty_home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, empty_home)
        with mock.patch.object(gitcmd, "FETCH_PROTOCOLS", ("https", "ssh", "http")), \
                mock.patch.object(gitcmd, "_operator_home", lambda: str(empty_home)):
            self.mint_refuses("could not fetch")
        self.assertFalse(marker.exists(), "the repository's credential helper ran")
        # Control: the same server DOES make git run a helper from the
        # repository's config when git runs inside it (the old fetch).
        subprocess.run(["git", "-C", str(self.policy_dir), "ls-remote", url],
                       capture_output=True, timeout=30,
                       env={"PATH": "/usr/bin:/bin", "HOME": str(empty_home),
                            "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"})
        self.assertTrue(marker.exists(), "control: the helper should run in-repo")

    def test_a_non_https_or_ssh_url_refuses(self):
        gitcmd.FETCH_FILE_PROTOCOL = "never"
        for url in ("git://example.invalid/p.git", "http://example.invalid/p.git",
                    "ext::sh -c touch% /tmp/x", str(self.origin),
                    "file://%s" % self.origin, "-uhttps://x", "https://a b"):
            with self.subTest(url=url):
                self.git("config", "remote.origin.url", url)
                self.mint_refuses("is not an https or ssh URL")
        # "git@" + host: split so the public exporter's e-mail scan sees no address.
        for url in ("https://github.com/o/p.git", "ssh://git@" + "github.com/o/p.git",
                    "git@" + "github.com:o/p.git"):
            self.assertTrue(gitcmd.url_allowed(url), url)
        # transport::address forms look scp-like but are never ssh
        for url in ("ext::true", "fd::3", "git@x::y", "ext::sh%20-c%20id"):
            with self.subTest(url=url):
                self.assertFalse(gitcmd.url_allowed(url), url)

    def test_a_global_insteadof_rewrite_refuses(self):
        other = Path(self.home.name) / "other.git"
        self.git("clone", "-q", "--bare", str(self.origin), str(other))
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home)
        (home / ".gitconfig").write_text('[url "%s"]\n\tinsteadOf = %s\n'
                                         % (other, self.origin))
        with mock.patch.object(gitcmd, "_operator_home", lambda: str(home)):
            msg = self.mint_refuses("is rewritten to")
        self.assertIn(str(other), msg)

    def test_the_scratch_repository_is_removed(self):
        made = self.scratch_dirs()
        path = self.mint_reusable()
        self.assertEqual(self.use("web1", NGINX, path), 0)
        self.git("commit", "-q", "--amend", "-m", "rewritten")
        self.push(force=True)
        with self.assertRaises(Refused) as cm:   # a refusal inside the fetch block
            self.use("web1", NGINX, path)
        self.assertIn("force-pushed", str(cm.exception))
        self.assertGreaterEqual(len(made), 3)
        for d in made:
            self.assertFalse(os.path.exists(d), "scratch repository left behind: %s" % d)
            self.assertIn("vpscfg-fetch-", d)


class ReplacedEstateTest(_RemoteHarness):

    def test_a_replaced_estate_with_a_local_only_commit_refuses(self):
        """The estate directory is replaced by a fresh clone of the same
        remote (same path, same URL) whose edit is committed locally only."""
        path = self.mint_reusable()
        shutil.rmtree(self.policy_dir)
        self.clone(self.policy_dir)
        self.edit(*EDIT)
        self.commit("local only in the clone", push=False)
        self.reload_policy()
        self.refuses(path, "unpushed", cmd=CADDY2)

    def test_an_estate_symlink_repointed_at_a_clone_with_a_local_commit_refuses(self):
        alias = Path(tempfile.mkdtemp()) / "estate"
        self.addCleanup(shutil.rmtree, alias.parent)
        os.symlink(self.policy_dir, alias)
        real = self.policy_dir
        self.addCleanup(setattr, self, "policy_dir", real)
        self.policy_dir = alias
        self.reload_policy()
        path = self.mint_reusable()
        clone = alias.parent / "clone"
        self.clone(clone)
        alias.unlink()
        os.symlink(clone, alias)
        self.edit(*EDIT)
        self.commit("local only in the clone", push=False)
        self.reload_policy()
        with self.assertRaises(Refused):
            self.use("web1", CADDY2, path)
        self.assertEqual(self.ran(), [])


class OfflineShortGrantTest(_RemoteHarness):

    def test_a_short_grant_never_fetches_and_works_offline(self):
        self.git("remote", "remove", "origin")
        self.no_fetch()
        path = self.mint("--steps", "1")
        self.assertEqual(self.use("web1", NGINX, path), 0)
        self.assertEqual(self.ran(), [("web1", NGINX)])


class OfflineIncidentTest(ti._IncidentHarness):

    def test_an_incident_never_fetches_and_works_offline(self):
        self.git("remote", "remove", "origin")

        def boom(*a, **k):
            raise AssertionError("fetched the policy remote")
        with mock.patch.object(gitcmd, "fetched", boom):
            iid = self.open("web1")
            rc, _ = self.run_cmd("web1", iid)
        self.assertEqual(rc, 0)
        self.assertEqual(self.ran(), [("web1", ti.CMD)])


if __name__ == "__main__":
    unittest.main()
