"""tools/export-public.py — fresh-history export from an allowlist, behind a
fail-closed leak scan.

Hermetic: every test builds its own throwaway git repository and exports into
its own temp directory, with HOME and the git identity set by the test. Nothing
is pushed and no remote exists anywhere.
"""
import gzip
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools" / "export-public.py"
_spec = importlib.util.spec_from_file_location("export_public", str(TOOL))
xp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(xp)

TERMS = ["corpnet", "198.18.", "acme-internal"]

# Leak shapes are assembled at run time, so this file's own text stays clean
# under the public-export scan it tests; the scanner sees exactly the strings
# the tests feed it.
RESOLVER = "8.8." "4.4"        # routable: a public resolver
RESOLVER2 = "8.8." "8.8"
ROUTABLE = "9.9." "9.9"        # routable, for the boundary cases
ROUTABLE0 = "9.9." "9.009"     # the same address with a leading zero
MAIL = "ops" "@corp.io"        # outside the reserved example domains
FAKE = "q7Lm2pXv9RtK4wZs"      # a 16-character literal, not a credential


class ScannerUnit(unittest.TestCase):
    def kinds(self, text, path="f.txt"):
        return [(n, k) for n, k, _, _ in xp.scan_text(path, text, TERMS)]

    def test_routable_ip_is_a_hit_and_documentation_ranges_are_not(self):
        self.assertEqual(self.kinds("ssh %s now" % RESOLVER), [(1, "ipv4")])
        for quiet in ("192.0.2.10", "198.51.100.5", "203.0.113.9", "10.1.2.3",
                      "172.16.0.1", "192.168.1.1", "127.0.0.1", "0.0.0.0",
                      "version 1.2.3", "999.1.1.1", "1.2.3.4567"):
            with self.subTest(quiet=quiet):
                self.assertEqual(self.kinds(quiet), [])

    def test_ip_boundaries_the_review_found(self):
        """W4 M2: every one of these is a routable address and was missed."""
        for text in ("peer_" + ROUTABLE, "x" + ROUTABLE, ROUTABLE + "v2",
                     ROUTABLE0, "host=%s:22" % ROUTABLE, "[%s]" % ROUTABLE):
            with self.subTest(text=text):
                self.assertEqual(self.kinds(text), [(1, "ipv4")])
        self.assertEqual([e for _, _, e, _ in xp.scan_text("f", ROUTABLE0, [])],
                         [ROUTABLE0])

    def test_denylist_terms_hit_lines_and_paths(self):
        self.assertEqual(self.kinds("host db.CorpNet.lan"), [(1, "denylist")])
        self.assertIn((0, "denylist"), self.kinds("clean", path="inventory/corpnet-db.txt"))
        self.assertIn((1, "denylist"), self.kinds("addr 198.18.0.4"))

    def test_email_outside_reserved_domains_is_a_hit(self):
        self.assertEqual(self.kinds("mail " + MAIL), [(1, "email")])
        for quiet in ("ops@example.com", "a@mail.example.org", "x@host.test",
                      "y@foo.invalid", "pkg==1.0 @decorator"):
            with self.subTest(quiet=quiet):
                self.assertEqual(self.kinds(quiet), [])

    def test_private_key_header_is_a_hit(self):
        for header in ("-----BEGIN " "OPENSSH PRIVATE KEY-----",
                       "-----BEGIN " "RSA PRIVATE KEY-----",
                       "-----BEGIN " "PRIVATE KEY-----",
                       "-----BEGIN " "PGP PRIVATE KEY BLOCK-----"):
            with self.subTest(header=header):
                self.assertIn((1, "private-key"), self.kinds(header))
        self.assertEqual(self.kinds("-----BEGIN PUBLIC KEY-----"), [])

    def test_token_shapes_are_hits(self):
        cases = {
            "ghp_" + "a1B2" * 9: "github-token",
            "AKIA" + "ABCDEFGHIJKLMNOP": "aws-access-key",
            "xoxb-" "1234567890-abcdefghij": "slack-token",
            "sk_live_" + "Z9" * 10: "stripe-key",
            "eyJhbGciOiJIUzI1NiJ9." "eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2": "jwt",
            'db_password = "%s"' % FAKE: "secret-assignment",
            'API_KEY: "' 'Zx81LqPv03NmRt55"': "secret-assignment",
            "PGPASSWORD=" "s3cr3tvaluehunter2xx": "secret-assignment",  # unquoted (M2)
            'token = "' 'latest-real-secret-9f8e7d6c"': "secret-assignment",  # "test" inside (M2)
            "export DB_PASSWORD='%s'" % FAKE: "secret-assignment",
            "DB_PASS=%s" % FAKE: "secret-assignment",
            'pw: "%s"' % FAKE: "secret-assignment",
            "passwd = '%s'" % FAKE: "secret-assignment",
            "ADMIN-PW: %s" % FAKE: "secret-assignment",
        }
        for text, kind in cases.items():
            with self.subTest(kind=kind):
                self.assertIn(kind, [k for _, k in self.kinds(text)])

    def test_secret_placeholders_are_not_hits(self):
        for quiet in ('password = "<your-password-here>"', 'api_key: "${API_KEY_FROM_ENV}"',
                      'secret = "changeme-changeme-123"', 'token: "example-token-value"',
                      "password = read_password_from_file(path2)",
                      "client_secret: xxxxxxxxxxxxxxxxxxxx",
                      "auth_token=os.environ.get",
                      "bypass = 'q7Lm2pXv9RtK4wZs'", "compass: q7Lm2pXv9RtK4wZs",
                      "upward = q7Lm2pXv9RtK4wZs"):
            with self.subTest(quiet=quiet):
                self.assertEqual(self.kinds(quiet), [])

    def test_evidence_for_tokens_is_masked(self):
        token = "ghp_" + "a1B2" * 9
        (_, _, evidence, _), = xp.scan_text("f", token, [])
        self.assertNotIn(token, evidence)

    def test_denylist_sees_through_zero_width_and_nfkc(self):
        """W4 M1: a term split by zero-width characters, or spelled in
        full-width letters, still matches."""
        for text in ("corp\u200bnet", "corp\u2060net", "c\u00adorpnet",
                     "\uff43\uff4f\uff52\uff50\uff4e\uff45\uff54", "CORP\ufeffNET"):
            with self.subTest(text=ascii(text)):
                self.assertIn((1, "denylist"), self.kinds(text))
        self.assertIn((0, "denylist"), self.kinds("x", path="docs/corp\u200dnet.md"))

    def test_allowlist_rules(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# c\nsrc/\ndocs/*.md\n**/keep.txt\n!src/private/\nREADME\n")
        self.addCleanup(os.unlink, f.name)
        rules = xp.load_allowlist(f.name)
        for path, want in (("src/a.py", True), ("src/x/y.py", True), ("src/private/k", False),
                           ("docs/a.md", True), ("docs/sub/a.md", False), ("README", True),
                           ("a/b/keep.txt", True), ("keep.txt", True), ("READMEx", False),
                           ("estate/x", False)):
            with self.subTest(path=path):
                self.assertIs(xp.allowed(path, rules), want)

    def test_allowlist_refuses_escapes_and_emptiness(self):
        for body in ("../etc/passwd\n", "/abs\n", "# nothing\n", "!src/\n"):
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
                f.write(body)
            self.addCleanup(os.unlink, f.name)
            with self.subTest(body=body), self.assertRaises(xp.Refused):
                xp.load_allowlist(f.name)


class ExportEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(os.path.realpath(self.tmp.name))
        self.home = base / "home"
        self.home.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(HOME=str(self.home), GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="Export Test", GIT_AUTHOR_EMAIL="t@example.com",
                        GIT_COMMITTER_NAME="Export Test", GIT_COMMITTER_EMAIL="t@example.com")
        self.src = base / "src"
        self.out = base / "out"
        self.lists = base / "lists"
        self.lists.mkdir()
        self.git(self.src.parent, "init", "-q", str(self.src))
        # History carries a secret that the export must never contain.
        self.write("tool/core.py", "API = 'old'\n")
        self.write("estate/hosts.txt", "db %s corpnet\n" % RESOLVER2)
        self.commit("first, with the estate")
        self.write("tool/core.py", "def main():\n    return 0\n")
        self.write("tool/run.sh", "#!/bin/sh\nexit 0\n", mode=0o755)
        self.write("docs/guide.md", "Talk to 192.0.2.10 (an example).\n")
        self.commit("second")
        self.allow = self.listfile("allow.txt", "tool/\ndocs/\n")
        self.deny = self.listfile("deny.txt", "\n".join(TERMS) + "\n")
        self.exc = self.lists / "exceptions.txt"
        self.bins = self.lists / "binaries.txt"

    def git(self, cwd, *args):
        r = subprocess.run(["git"] + list(args), cwd=str(cwd), env=self.env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def write(self, rel, text, mode=0o644):
        p = self.src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        os.chmod(str(p), mode)

    def commit(self, msg):
        self.git(self.src, "add", "-A")
        self.git(self.src, "commit", "-q", "--no-verify", "-m", msg)

    def listfile(self, name, text):
        p = self.lists / name
        p.write_text(text)
        return p

    def export(self, *extra, commit="HEAD"):
        argv = [sys.executable, str(TOOL), "--repo", str(self.src), "--commit", commit,
                "--out", str(self.out), "--allowlist", str(self.allow),
                "--denylist", str(self.deny), "--exceptions", str(self.exc),
                "--binary-allowlist", str(self.bins)] + list(extra)
        return subprocess.run(argv, capture_output=True, text=True, timeout=120, env=self.env)

    def test_clean_tree_exports_with_one_fresh_commit(self):
        # Uncommitted and untracked changes must not be exported.
        self.write("tool/core.py", "LEAK = '%s'\n" % MAIL)
        self.write("tool/untracked.py", "x = '%s'\n" % RESOLVER2)
        r = self.export()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        files = sorted(str(p.relative_to(self.out)) for p in self.out.rglob("*")
                       if p.is_file() and ".git" not in p.parts)
        self.assertEqual(files, ["docs/guide.md", "tool/core.py", "tool/run.sh"])
        self.assertEqual((self.out / "tool/core.py").read_text(), "def main():\n    return 0\n")
        self.assertTrue(os.access(str(self.out / "tool/run.sh"), os.X_OK))
        self.assertEqual(self.git(self.out, "rev-list", "--all", "--count").strip(), "1")
        self.assertEqual(self.git(self.out, "log", "--format=%P").strip(), "")  # a root commit
        self.assertEqual(self.git(self.out, "remote").strip(), "")
        everything = self.git(self.out, "log", "-p", "--all")
        self.assertNotIn(RESOLVER2, everything)
        self.assertNotIn("corpnet", everything)
        self.assertNotIn("API = 'old'", everything)

    def test_seeded_leak_blocks_the_export(self):
        self.write("tool/core.py", "def main():\n    return '%s'\n" % RESOLVER)
        self.write("docs/guide.md", "ask %s about corpnet\n" % MAIL)
        self.commit("leak")
        r = self.export()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("tool/core.py:2:ipv4:", r.stdout)
        self.assertIn(RESOLVER, r.stdout)
        self.assertIn("docs/guide.md:1:email:", r.stdout)
        self.assertIn("docs/guide.md:1:denylist:", r.stdout)
        self.assertIn("NOT COMMITTED", r.stderr)
        self.assertFalse((self.out / ".git").exists())

    def test_leak_outside_the_allowlist_is_never_exported(self):
        self.allow.write_text("tool/\n")
        r = self.export()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse((self.out / "estate").exists())

    def test_leak_in_a_path_name_blocks(self):
        self.write("tool/corpnet-hosts.py", "x = 1\n")
        self.commit("path leak")
        r = self.export()
        self.assertEqual(r.returncode, 1)
        self.assertIn("tool/corpnet-hosts.py:0:denylist:", r.stdout)

    @staticmethod
    def key(path, n, kind, line):
        return "%s:%d:%s:%s" % (path, n, kind, hashlib.sha256(line.encode()).hexdigest()[:16])

    def test_exact_exception_lets_it_through(self):
        self.write("tool/core.py", "def main():\n    return '%s'\n" % RESOLVER)
        self.commit("reviewed")
        self.exc.write_text(self.key("tool/core.py", 2, "ipv4", "    return '%s'" % RESOLVER)
                            + "  # public resolver, reviewed\n")
        r = self.export()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("1 excepted", r.stderr)

    def test_excepted_line_changed_in_place_blocks(self):
        """W4 H2: the exception pins the reviewed line's content."""
        self.write("tool/core.py", "def main():\n    return '%s'  # now with more\n" % RESOLVER)
        self.commit("edited in place")
        self.exc.write_text(self.key("tool/core.py", 2, "ipv4", "    return '%s'" % RESOLVER) + "\n")
        r = self.export()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("tool/core.py:2:ipv4:", r.stdout)
        self.assertIn("stale-exception", r.stdout)

    def test_excepted_line_gaining_a_second_hit_blocks(self):
        """W4 H2: the same line, same position, a new kind of leak."""
        line = "    return '%s'  # ask %s" % (RESOLVER, MAIL)
        self.write("tool/core.py", "def main():\n%s\n" % line)
        self.commit("second hit on an excepted line")
        self.exc.write_text(self.key("tool/core.py", 2, "ipv4", line) + "\n")
        r = self.export()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("tool/core.py:2:email:", r.stdout)
        self.assertNotIn("tool/core.py:2:ipv4:", r.stdout)

    def test_bare_path_line_exception_is_refused(self):
        self.exc.write_text("tool/core.py:2\n")
        r = self.export()
        self.assertEqual(r.returncode, 2)
        self.assertIn("path:line:kind:digest16", r.stderr)

    def test_stale_exception_blocks(self):
        self.write("tool/core.py", "\ndef main():\n    return '%s'\n" % RESOLVER)
        self.commit("line moved")
        self.exc.write_text(self.key("tool/core.py", 2, "ipv4", "    return '%s'" % RESOLVER) + "\n")
        r = self.export()
        self.assertEqual(r.returncode, 1)
        self.assertIn("tool/core.py:3:ipv4:", r.stdout)
        self.assertIn("stale-exception", r.stdout)

    def test_stale_only_exception_blocks_a_clean_tree(self):
        """W4 L4: no hits at all, one leftover exception: still refuses."""
        self.exc.write_text(self.key("tool/core.py", 1, "ipv4", "gone") + "\n")
        r = self.export()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("stale-exception", r.stdout)
        self.assertIn("0 scan hit(s)", r.stderr)
        self.assertFalse((self.out / ".git").exists())

    # --- W4 M1: strict UTF-8 ------------------------------------------------

    def test_utf16_file_refuses_unless_binary_allowlisted(self):
        p = self.src / "tool" / "notes.txt"
        p.write_bytes(("corpnet %s\n" % RESOLVER2).encode("utf-16"))
        self.commit("utf-16")
        r = self.export()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("tool/notes.txt:0:binary:", r.stdout)

    def test_binary_hits_cannot_be_excepted(self):
        (self.src / "tool" / "blob.bin").write_bytes(b"\x00\x01\x02")
        self.commit("blob")
        key = self.key("tool/blob.bin", 0, "binary", "tool/blob.bin")
        self.exc.write_text(key + "\n")
        r = self.export()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(key, r.stdout)

    def test_gzip_fixture(self):
        clean = gzip.compress(b"nothing to see here\n")
        leaky = gzip.compress(b"db host corpnet-db\n")
        (self.src / "tool" / "clean.tar.gz").write_bytes(clean)
        (self.src / "tool" / "leaky.tar.gz").write_bytes(leaky)
        self.commit("archives")
        r = self.export("--no-commit")
        self.assertEqual(r.returncode, 1)
        self.assertIn("tool/clean.tar.gz:0:binary:", r.stdout)  # not listed: refused
        # Listed: allowed through, but its gunzipped bytes are still searched.
        self.bins.write_text("tool/clean.tar.gz\ntool/leaky.tar.gz  # reviewed\n")
        shutil.rmtree(str(self.out))
        r = self.export("--no-commit")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn("tool/clean.tar.gz", r.stdout)
        self.assertIn("tool/leaky.tar.gz:0:binary-denylist:", r.stdout)

    def test_gzip_past_the_cap_refuses(self):
        (self.src / "tool" / "big.gz").write_bytes(gzip.compress(b"\0" * 4096))
        self.commit("bomb")
        self.bins.write_text("tool/big.gz\n")
        real = xp.GUNZIP_CAP
        try:
            xp.GUNZIP_CAP = 1024
            with self.assertRaises(xp.Refused) as cm:
                xp.scan_binary("tool/big.gz", (self.src / "tool" / "big.gz").read_bytes(), TERMS)
            self.assertIn("inflates past", str(cm.exception))
            hits = xp.scan_binary("tool/small.gz", gzip.compress(b"x" * 1024), TERMS)
            self.assertEqual(hits, [])  # exactly at the cap is fine
        finally:
            xp.GUNZIP_CAP = real

    # --- W4 M3: estate pointers never ship ----------------------------------

    def test_any_estate_pointer_path_refuses_the_export(self):
        for name in ("estate.path", "tool/Estate.Path", "docs/ESTATE.PATH"):
            with self.subTest(name=name):
                p = self.src / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("/srv/estate\n")
                self.commit("pointer " + name)
                self.allow.write_text("tool/\ndocs/\nestate.path\n")
                if self.out.exists():
                    shutil.rmtree(str(self.out))
                r = self.export()
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("estate pointer", r.stderr)
                self.git(self.src, "rm", "-q", name)
                self.commit("drop " + name)

    def test_out_through_a_symlink_into_the_repo_refuses(self):
        link = self.src.parent / "sneaky"
        os.symlink(str(self.src), str(link))
        self.out = link / "public"
        r = self.export()
        self.assertEqual(r.returncode, 2)
        self.assertIn("outside the source", r.stderr)

    def test_non_empty_out_refuses_and_is_untouched(self):
        self.out.mkdir()
        (self.out / "precious").write_text("keep")
        r = self.export()
        self.assertEqual(r.returncode, 2)
        self.assertIn("not empty", r.stderr)
        self.assertEqual(os.listdir(str(self.out)), ["precious"])

    def test_out_inside_the_source_repo_refuses(self):
        self.out = self.src / "public"
        r = self.export()
        self.assertEqual(r.returncode, 2)
        self.assertIn("outside the source", r.stderr)

    def test_symlink_in_the_allowlist_refuses(self):
        os.symlink("core.py", str(self.src / "tool" / "link.py"))
        self.commit("symlink")
        r = self.export()
        self.assertEqual(r.returncode, 2)
        self.assertIn("only regular files", r.stderr)

    def test_empty_denylist_refuses(self):
        self.deny.write_text("# nothing\n")
        r = self.export()
        self.assertEqual(r.returncode, 2)
        self.assertIn("denylist", r.stderr)

    def test_older_commit_exports_that_commit(self):
        first = self.git(self.src, "rev-list", "--max-parents=0", "HEAD").strip()
        self.allow.write_text("estate/\n")
        r = self.export(commit=first)
        self.assertEqual(r.returncode, 1)  # the first commit's estate file leaks
        self.assertIn("estate/hosts.txt:1:ipv4:", r.stdout)

    def test_no_commit_mode_never_inits(self):
        r = self.export("--no-commit")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.out / ".git").exists())


if __name__ == "__main__":
    unittest.main()
