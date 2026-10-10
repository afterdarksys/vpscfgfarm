"""sshconfig follows `Include` the way OpenSSH does — hermetically, in temp dirs.

Negative tests are the point: loops, runaway depth and unreadable includes
must refuse with a clear error, never shrink or guess the host registry.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import sshconfig  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402


class IncludeTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name) / ".ssh"
        self.dir.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, text):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def load(self, main):
        return sshconfig.load(self.write("config", main), ssh_dir=self.dir)

    # --- what works -------------------------------------------------------

    def test_relative_include_resolves_against_ssh_dir_not_cwd(self):
        self.write("fleet.conf", "Host web1\n  HostName 192.0.2.10\n")
        with tempfile.TemporaryDirectory() as elsewhere:
            old = os.getcwd()
            os.chdir(elsewhere)
            try:
                hosts = self.load("Include fleet.conf\n")
            finally:
                os.chdir(old)
        self.assertEqual(hosts["web1"]["hostname"], "192.0.2.10")

    def test_glob_includes_in_sorted_order(self):
        self.write("config.d/20-b", "Host b\n  HostName 2\n")
        self.write("config.d/10-a", "Host a\n  HostName 1\n")
        hosts = self.load("Include config.d/*\nHost c\n  HostName 3\n")
        self.assertEqual(list(hosts), ["a", "b", "c"])

    def test_includes_nest(self):
        self.write("one", "Include two\nHost one\n  HostName 1\n")
        self.write("two", "Include three\nHost two\n  HostName 2\n")
        self.write("three", "Host three\n  HostName 3\n  User deploy\n")
        hosts = self.load("Include one\n")
        self.assertEqual(sorted(hosts), ["one", "three", "two"])
        self.assertEqual(hosts["three"]["user"], "deploy")

    def test_missing_include_is_ignored(self):
        hosts = self.load("Include nope.conf config.d/*\nHost a\n  HostName 1\n")
        self.assertEqual(hosts, {"a": {"hostname": "1", "user": None}})

    def test_absolute_tilde_and_quoted_paths(self):
        abs_file = self.write("abs dir/x.conf", "Host x\n  HostName 9\n")
        self.write("tilde.conf", "Host t\n  HostName 8\n")
        home = self.dir.parent
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            hosts = self.load('Include "%s"\nInclude ~/.ssh/tilde.conf\n' % abs_file)
        self.assertEqual(hosts["x"]["hostname"], "9")
        self.assertEqual(hosts["t"]["hostname"], "8")

    def test_include_inside_host_block_applies_to_that_block(self):
        self.write("addr", "HostName 192.0.2.20\nUser ops\n")
        hosts = self.load("Host db1\n  Include addr\nHost other\n  HostName 5\n")
        self.assertEqual(hosts["db1"], {"hostname": "192.0.2.20", "user": "ops"})
        self.assertEqual(hosts["other"]["hostname"], "5")

    def test_outer_block_resumes_after_the_include(self):
        self.write("inner", "HostName 7\nHost db1-replica\n  User inner\n")
        hosts = self.load("Host db1 db1-*\n  Include inner\n  User after\n")
        # After the include, `User after` belongs to the outer db1 block again,
        # not to the Host line that appeared inside the included file.
        self.assertEqual(hosts["db1"], {"hostname": "7", "user": "after"})
        self.assertEqual(hosts["db1-replica"]["user"], "inner")

    def test_scoped_include_registers_only_names_the_block_matches(self):
        self.write("inner", "Host db1 web1\n  HostName 7\n")
        hosts = self.load("Host db*\n  Include inner\n")
        self.assertIn("db1", hosts)
        self.assertNotIn("web1", hosts)  # ssh would never apply it to web1

    def test_negated_outer_pattern_vetoes(self):
        self.write("inner", "Host db1 db2\n  HostName 7\n")
        hosts = self.load("Host db* !db2\n  Include inner\n")
        self.assertIn("db1", hosts)
        self.assertNotIn("db2", hosts)

    def test_include_under_match_registers_nothing(self):
        self.write("inner", "Host sneaky\n  HostName 6\n")
        hosts = self.load("Match host foo exec true\n  Include inner\n")
        self.assertEqual(hosts, {})

    def test_match_block_does_not_leak_into_the_host_before_it(self):
        hosts = self.load("Host a\n  HostName 1\nMatch all\n  HostName 2\n")
        self.assertEqual(hosts["a"]["hostname"], "1")

    def test_sibling_includes_of_one_file_are_not_a_loop(self):
        self.write("shared", "Host s\n  HostName 1\n")
        hosts = self.load("Include shared\nInclude shared\n")
        self.assertIn("s", hosts)

    def test_machines_follows_includes(self):
        self.write("fleet", "Host a a.example\n  HostName 192.0.2.1\n")
        cfg = self.write("config", "Include fleet\n")
        m = sshconfig.machines(cfg, ssh_dir=self.dir)
        self.assertEqual(sorted(m["192.0.2.1"]["aliases"]), ["a", "a.example"])

    def test_depth_sixteen_is_allowed(self):
        for i in range(1, 16):
            self.write("d%d" % i, "Include d%d\n" % (i + 1))
        self.write("d16", "Host deep\n  HostName 1\n")
        self.assertIn("deep", self.load("Include d1\n"))

    # --- what refuses -----------------------------------------------------

    def test_self_include_loop_refuses(self):
        with self.assertRaises(sshconfig.SshConfigError) as cm:
            self.load("Host a\n  HostName 1\nInclude config\n")
        self.assertIn("loop", str(cm.exception))

    def test_two_file_loop_refuses_and_names_the_chain(self):
        self.write("a", "Include b\n")
        self.write("b", "Include a\n")
        with self.assertRaises(Refused) as cm:  # a Refused, so every door reports it
            self.load("Include a\n")
        self.assertIn("loop", str(cm.exception))
        self.assertIn("->", str(cm.exception))

    def test_loop_through_a_symlink_refuses(self):
        self.write("a", "Include link\n")
        os.symlink(str(self.dir / "a"), str(self.dir / "link"))
        with self.assertRaises(sshconfig.SshConfigError):
            self.load("Include a\n")

    def test_depth_seventeen_refuses(self):
        for i in range(1, 17):
            self.write("d%d" % i, "Include d%d\n" % (i + 1))
        self.write("d17", "Host deep\n  HostName 1\n")
        with self.assertRaises(sshconfig.SshConfigError) as cm:
            self.load("Include d1\n")
        self.assertIn("deeper than 16", str(cm.exception))

    def test_directories_matched_by_an_include_are_skipped(self):
        """As ssh does: a glob (or literal) that names a directory is skipped."""
        (self.dir / "config.d" / "sub").mkdir(parents=True)
        self.write("config.d/a", "Host a\n  HostName 1\n")
        hosts = self.load("Include config.d/*\nInclude config.d/sub\n")
        self.assertEqual(hosts, {"a": {"hostname": "1", "user": None}})

    @unittest.skipIf(os.getuid() == 0, "root reads mode-000 files")
    def test_unreadable_include_refuses_rather_than_shrinking(self):
        p = self.write("locked", "Host a\n  HostName 1\n")
        os.chmod(str(p), 0)
        try:
            with self.assertRaises(sshconfig.SshConfigError):
                self.load("Include locked\nHost b\n  HostName 2\n")
        finally:
            os.chmod(str(p), 0o600)

    def test_group_or_world_writable_include_refuses(self):
        for mode in (0o664, 0o646, 0o666):
            p = self.write("shared", "Host a\n  HostName 1\n")
            os.chmod(str(p), mode)
            with self.assertRaises(sshconfig.SshConfigError, msg=oct(mode)) as cm:
                self.load("Include shared\n")
            self.assertIn("bad owner or permissions", str(cm.exception))

    def test_include_owned_by_someone_else_refuses(self):
        p = self.write("theirs", "Host a\n  HostName 1\n")
        real_fstat = os.fstat

        def fstat(fd):
            st = real_fstat(fd)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                                   os.getuid() + 4242, st.st_gid, st.st_size,
                                   st.st_atime, st.st_mtime, st.st_ctime))
        with mock.patch.object(sshconfig.os, "fstat", fstat):
            with self.assertRaises(sshconfig.SshConfigError) as cm:
                self.load("Include theirs\n")
        self.assertIn("bad owner", str(cm.exception))
        self.assertTrue(p.exists())

    def test_private_and_read_only_includes_are_fine(self):
        for mode in (0o600, 0o644, 0o400, 0o444):
            p = self.write("ok", "Host a\n  HostName 1\n")
            os.chmod(str(p), mode)
            self.assertIn("a", self.load("Include ok\n"), oct(mode))
            os.chmod(str(p), 0o600)

    def test_first_hostname_and_user_win_as_in_ssh(self):
        hosts = self.load("Host a\n  HostName 1\n  User first\n"
                          "Host a b\n  HostName 2\n  User second\n")
        self.assertEqual(hosts["a"], {"hostname": "1", "user": "first"})
        self.assertEqual(hosts["b"], {"hostname": "2", "user": "second"})

    def test_first_value_wins_across_an_include(self):
        self.write("late", "Host a\n  HostName 9\n")
        hosts = self.load("Host a\n  HostName 1\nInclude late\n")
        self.assertEqual(hosts["a"]["hostname"], "1")

    def test_host_patterns_stop_at_a_comment(self):
        hosts = self.load("Host a b # c d\n  HostName 1\nHost e #f\n  HostName 2\n")
        self.assertEqual(sorted(hosts), ["a", "b", "e"])

    def test_a_name_the_block_negates_is_not_registered(self):
        hosts = self.load("Host db1 !db1 db2\n  HostName 1\n")
        self.assertEqual(sorted(hosts), ["db2"])

    def test_undecodable_include_refuses(self):
        (self.dir / "bin").write_bytes(b"Host \xff\xfe\n")
        with self.assertRaises(sshconfig.SshConfigError):
            self.load("Include bin\n")

    def test_unbalanced_quote_refuses(self):
        with self.assertRaises(sshconfig.SshConfigError):
            self.load('Include "fleet.conf\n')

    def test_missing_top_level_file_is_still_empty(self):
        self.assertEqual(sshconfig.load(self.dir / "absent", ssh_dir=self.dir), {})


if __name__ == "__main__":
    unittest.main()
