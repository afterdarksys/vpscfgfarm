"""The estate root (vpscfg/estate.py): where the governor and policies live.

What this pins:
  - with no pointer file the estate root IS the tool checkout, and every module
    path that used to be built from the repo root is unchanged;
  - the ONLY override is <tool root>/estate.path, and every doubt about it or
    its target refuses: group/world-writable pointer, pointer owned by another
    uid, a symlinked pointer, relative / non-normalised / garbage / multi-line /
    oversized contents, a missing target, a target writable by others or owned
    by another uid, a symlinked target or a target under a symlink, an ancestor
    another user could rename it through, and a pointed governor or policy
    file that is a symlink or writable by others;
  - no environment variable changes the answer, with or without a pointer
    (the VPSCFG_CONTROL_PATH hole must stay closed);
  - all three doors (vpscfg-control.py, vpsexec, the package) resolve the SAME
    root: the inner door verifies the outer door's token against the pointed
    governor, and refuses the tool checkout's governor once the estate moved;
  - both outer doors journal the resolved root and the governor's sha256.

Hermetic: unit tests resolve against temp directories; door tests run copies
of the doors in a temp checkout with HOME pointed into it. Nothing reaches a host.
"""
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import estate  # noqa: E402

EXAMPLE = REPO / "contrib" / "example-estate"
ENV_ATTEMPTS = {
    "VPSCFG_ESTATE": None, "VPSCFG_ESTATE_ROOT": None, "VPSCFG_ESTATE_PATH": None,
    "VPSCFG_CONTROL_PATH": None, "VPSCFG_POLICY_DIR": None, "ESTATE_ROOT": None,
    # Interpreter variables (W4 H1). The doors run under `python3 -I`, so none
    # of these reaches them. PYTHONHOME (and PYTHONEXECUTABLE/PYTHONPLATLIBDIR)
    # are left out here only because a bogus value stops the interpreter
    # before any code runs; tests/test_interpreter_isolation.py covers
    # PYTHONHOME, and a forging sitecustomize/usercustomize for the others.
    "PYTHONPATH": None, "PYTHONUSERBASE": None, "PYTHONSTARTUP": None,
    "PYTHONNOUSERSITE": None, "PYTHONSAFEPATH": None,
}


def _real_tmpdir(case):
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    path = Path(os.path.realpath(tmp.name))
    os.chmod(str(path), 0o700)
    return path


def _with_uid(st, uid):
    fields = list(st)
    fields[stat.ST_UID] = uid
    return os.stat_result(fields)


class ResolveUnit(unittest.TestCase):
    def setUp(self):
        base = _real_tmpdir(self)
        self.tool = base / "tool"
        self.tool.mkdir(mode=0o700)
        self.target = base / "estate"
        self.target.mkdir(mode=0o700)
        (self.target / "vpscfg-control.json").write_text("{}")
        os.chmod(str(self.target / "vpscfg-control.json"), 0o644)
        (self.target / "policies").mkdir(mode=0o755)
        self.pointer = self.tool / "estate.path"

    def point(self, text, mode=0o600):
        if self.pointer.exists() or self.pointer.is_symlink():
            self.pointer.unlink()
        self.pointer.write_bytes(text if isinstance(text, bytes) else text.encode())
        os.chmod(str(self.pointer), mode)

    def refuses(self, needle, **kw):
        with self.assertRaises(estate.EstateRefused) as cm:
            estate.resolve(str(self.tool), **kw)
        self.assertIn(needle, str(cm.exception))
        return cm.exception

    # --- the default --------------------------------------------------------

    def test_no_pointer_is_the_tool_root(self):
        est = estate.resolve(str(self.tool))
        self.assertEqual(est.source, "default")
        self.assertEqual(est.root, str(self.tool))
        self.assertEqual(est.governor, str(self.tool / "vpscfg-control.json"))
        self.assertEqual(est.policies, str(self.tool / "policies"))

    def test_default_for_this_checkout_matches_the_old_paths(self):
        """Byte-for-byte: what each module built from the repo root before."""
        if (REPO / "estate.path").exists():
            self.skipTest("this checkout carries an estate.path pointer")
        from vpscfg import contracts, control, fingerprint, playbook, repair, secretscensus, vpsexecpolicy
        old = Path(control.__file__).resolve().parent.parent
        self.assertEqual(estate.current().source, "default")
        self.assertEqual(Path(estate.current().root), old)
        self.assertEqual(contracts.CONTRACT_DIR, old / "contracts")
        self.assertEqual(vpsexecpolicy.POLICY_DIR, old / "policies")
        self.assertEqual(fingerprint.BASELINE_DIR, old / "inventory" / "fingerprints")
        self.assertEqual(playbook.PLAYBOOK_DIR, old / "playbooks")
        self.assertEqual(secretscensus.ESCROW_DIR, old / "escrow")
        self.assertEqual(secretscensus.RECIPIENTS, old / "policies" / "escrow-recipients.txt")
        self.assertEqual(repair.GOVERNOR, old / "vpscfg-control.json")

    def test_valid_pointer_resolves_and_records(self):
        self.point(str(self.target) + "\n")
        est = estate.resolve(str(self.tool))
        self.assertEqual((est.source, est.root), ("pointer", str(self.target)))
        rec = est.record("ab" * 32)
        self.assertEqual(rec["estate_root"], str(self.target))
        self.assertEqual(rec["governor"], str(self.target / "vpscfg-control.json"))
        self.assertEqual(rec["estate_pointer"], str(self.pointer))
        self.assertEqual(rec["governor_sha256"], "ab" * 32)

    def test_read_only_pointer_modes_are_fine(self):
        for mode in (0o400, 0o444, 0o600, 0o644):
            self.point(str(self.target), mode)
            self.assertEqual(estate.resolve(str(self.tool)).root, str(self.target))

    # --- the pointer file ---------------------------------------------------

    def test_group_writable_pointer_refuses(self):
        self.point(str(self.target), 0o620)
        self.refuses("group- or world-writable")

    def test_world_writable_pointer_refuses(self):
        self.point(str(self.target), 0o602)
        self.refuses("group- or world-writable")

    def test_pointer_owned_by_someone_else_refuses(self):
        self.point(str(self.target))
        real = os.lstat
        hostile = os.geteuid() + 4242

        def lstat(path):
            st = real(path)
            return _with_uid(st, hostile) if path == str(self.pointer) else st
        self.refuses("not the operator", lstat=lstat)

    def test_operator_mismatch_refuses(self):
        """Same thing from the other side: the process is not the owner."""
        self.point(str(self.target))
        self.refuses("not the operator", euid=os.geteuid() + 4242)

    def test_symlinked_pointer_refuses(self):
        real = self.tool / "elsewhere.path"
        real.write_text(str(self.target))
        os.chmod(str(real), 0o600)
        os.symlink(str(real), str(self.pointer))
        self.refuses("symlink")

    def test_pointer_that_is_a_directory_refuses(self):
        self.pointer.mkdir()
        self.refuses("not a regular file")

    def test_relative_target_refuses(self):
        self.point("estate")
        self.refuses("not an absolute path")

    def test_non_normalised_target_refuses(self):
        for text in (str(self.target) + "/", str(self.target / ".." / "estate"),
                     str(self.target).replace("/estate", "/./estate"), "/" + str(self.target)):
            self.point(text)
            self.refuses("not normalised")

    def test_garbage_pointer_refuses(self):
        cases = {
            b"": "exactly one line",
            b"\n": "exactly one line",
            str(self.target).encode() + b"\n/etc\n": "exactly one line",
            str(self.target).encode() + b"\r\n": "exactly one line",
            b"\xff\xfe\x00garbage": "not UTF-8",
            (" " + str(self.target)).encode(): "whitespace or control",
            (str(self.target) + " ").encode(): "whitespace or control",
            (str(self.target) + "\x00").encode(): "whitespace or control",
            b"/" + b"a" * (estate.MAX_POINTER_BYTES + 10): "bytes",
            b"{\"root\": \"/srv/estate\"}": "not an absolute path",
        }
        for raw, needle in cases.items():
            with self.subTest(raw=raw[:40]):
                self.point(raw)
                self.refuses(needle)

    # --- the target ---------------------------------------------------------

    def test_missing_target_refuses(self):
        self.point(str(self.target) + "-gone")
        self.refuses("does not exist")

    def test_target_that_is_a_file_refuses(self):
        self.point(str(self.target / "vpscfg-control.json"))
        self.refuses("not a directory")

    def test_target_writable_by_others_refuses(self):
        self.point(str(self.target))
        for mode in (0o770, 0o707, 0o777, 0o1777):
            with self.subTest(mode=oct(mode)):
                os.chmod(str(self.target), mode)
                self.refuses("group- or world-writable")
        os.chmod(str(self.target), 0o700)

    def test_target_owned_by_someone_else_refuses(self):
        self.point(str(self.target))
        real = os.lstat

        def lstat(path):
            st = real(path)
            return _with_uid(st, os.geteuid() + 4242) if path == str(self.target) else st
        self.refuses("not the operator", lstat=lstat)

    def test_symlinked_target_refuses_and_names_the_real_path(self):
        link = self.target.parent / "estate-link"
        os.symlink(str(self.target), str(link))
        self.point(str(link))
        err = self.refuses("is a symlink")
        self.assertIn(str(self.target), str(err))

    def test_target_under_a_symlinked_directory_refuses(self):
        link = self.target.parent / "via-link"
        os.symlink(str(self.target.parent), str(link))
        self.point(str(link / "estate"))
        self.refuses("passes through a symlink")

    def test_ancestor_owned_by_another_user_refuses(self):
        self.point(str(self.target))
        real = os.lstat
        parent = str(self.target.parent)

        def lstat(path):
            st = real(path)
            return _with_uid(st, os.geteuid() + 4242) if path == parent else st
        self.refuses("could rename things away", lstat=lstat)

    def test_shared_ancestor_without_sticky_bit_refuses(self):
        self.point(str(self.target))
        os.chmod(str(self.target.parent), 0o777)
        try:
            self.refuses("without the sticky bit")
            os.chmod(str(self.target.parent), 0o1777)  # sticky: like /tmp, fine
            self.assertEqual(estate.resolve(str(self.tool)).root, str(self.target))
        finally:
            os.chmod(str(self.target.parent), 0o700)

    # --- what the doors read inside a pointed estate ------------------------

    def test_symlinked_governor_in_pointed_estate_refuses(self):
        gov = self.target / "vpscfg-control.json"
        other = self.target / "other.json"
        gov.rename(other)
        os.symlink(str(other), str(gov))
        self.point(str(self.target))
        self.refuses("symlink or the wrong kind")

    def test_shared_governor_in_pointed_estate_refuses(self):
        os.chmod(str(self.target / "vpscfg-control.json"), 0o666)
        self.point(str(self.target))
        self.refuses("group- or world-writable")

    def test_symlinked_policies_dir_refuses(self):
        (self.target / "policies").rmdir()
        os.symlink(str(self.tool), str(self.target / "policies"))
        self.point(str(self.target))
        self.refuses("symlink or the wrong kind")

    def test_shared_or_symlinked_policy_file_refuses(self):
        pol = self.target / "policies" / "groups.yaml"
        pol.write_text("version: 1\n")
        os.chmod(str(pol), 0o646)
        self.point(str(self.target))
        self.refuses("group- or world-writable")
        pol.unlink()
        os.symlink(str(self.target / "vpscfg-control.json"), str(pol))
        self.refuses("symlink")

    def test_missing_governor_is_left_to_the_doors(self):
        (self.target / "vpscfg-control.json").unlink()
        self.point(str(self.target))
        self.assertEqual(estate.resolve(str(self.tool)).root, str(self.target))

    # --- no environment variable, ever --------------------------------------

    def test_source_reads_no_environment(self):
        src = (REPO / "vpscfg" / "estate.py").read_text()
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        body = code.split('"""', 2)[2]  # past the module docstring
        for banned in ("os.environ", "getenv", "expanduser", "Path.home", "expandvars", "sys.argv"):
            self.assertNotIn(banned, body, banned)

    def _resolve_in_child(self, env):
        code = ("import sys; sys.path.insert(0, %r); from vpscfg import estate; "
                "e = estate.resolve(%r); print(e.source + ' ' + e.root)" % (str(REPO), str(self.tool)))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, timeout=30, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_env_vars_change_nothing(self):
        evil = _real_tmpdir(self)
        (evil / "vpscfg-control.json").write_text("{}")
        env = {k: v for k, v in os.environ.items() if not k.startswith("VPSCFG_")}
        hostile = dict(env, HOME=str(evil), PWD=str(evil),
                       **{k: str(evil) for k in ENV_ATTEMPTS})
        self.assertEqual(self._resolve_in_child(env), "default %s" % self.tool)
        self.assertEqual(self._resolve_in_child(hostile), "default %s" % self.tool)
        self.point(str(self.target))
        self.assertEqual(self._resolve_in_child(hostile), "pointer %s" % self.target)


class HardeningUnit(ResolveUnit.__bases__[0]):
    """W4 review M3, L1-L5: case variants, a tracked pointer, ACLs, the tool
    checkout's own chain, every estate file the package reads, the TOCTOU
    compare, and lstat errors that must refuse rather than crash."""

    setUp = ResolveUnit.setUp
    point = ResolveUnit.point
    refuses = ResolveUnit.refuses

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(HOME=str(self.tool), GIT_CONFIG_NOSYSTEM="1")
        r = subprocess.run(["git", "-C", str(self.tool)] + list(args), env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)

    # --- M3: case variants and a tracked pointer ------------------------------

    def test_case_variant_pointer_refuses(self):
        self.refuses("case-variant", listdir=lambda d: ["ESTATE.PATH", "vpsexec"])
        self.refuses("case-variant", listdir=lambda d: ["estate.path", "Estate.path"])

    def test_case_variant_on_disk_refuses_even_without_a_pointer(self):
        (self.tool / "Estate.Path").write_text(str(self.target))
        os.chmod(str(self.tool / "Estate.Path"), 0o600)
        self.refuses("case-variant")

    def test_tracked_pointer_refuses_and_untracked_is_fine(self):
        self.git("init", "-q")
        self.point(str(self.target))
        self.assertEqual(estate.resolve(str(self.tool)).source, "pointer")  # untracked
        self.git("add", "-f", "estate.path")  # staged counts as tracked
        self.refuses("git tracks estate.path")

    def test_tracked_case_variant_refuses(self):
        self.git("init", "-q")
        self.git("config", "core.ignorecase", "false")
        (self.tool / "Estate.Path").write_text("x")
        self.git("add", "-f", "Estate.Path")
        (self.tool / "Estate.Path").unlink()
        self.point(str(self.target))
        self.refuses("git tracks Estate.Path")

    def test_tracked_pointer_found_in_index_v4_and_through_a_worktree_file(self):
        for name in ("aaa/one.txt", "estate/README.md", "zzz.txt"):
            path = self.tool / name
            path.parent.mkdir(exist_ok=True)
            path.write_text("x")
        self.git("init", "-q")
        self.git("add", "-A")
        self.point(str(self.target))
        self.git("add", "-f", "estate.path")
        self.git("update-index", "--index-version", "4")
        self.refuses("git tracks estate.path")
        # A linked worktree's .git is a file naming the gitdir.
        real_git = self.tool.parent / "gitdir"
        (self.tool / ".git").rename(real_git)
        (self.tool / ".git").write_text("gitdir: %s\n" % real_git)
        self.refuses("git tracks estate.path")

    def test_unparseable_index_refuses(self):
        (self.tool / ".git").mkdir()
        (self.tool / ".git" / "index").write_bytes(b"DIRC\x00\x00\x00\x02\x00\x00\x00\x05garbage")
        self.point(str(self.target))
        self.refuses("cannot tell whether git tracks")

    def test_no_git_binary_changes_nothing(self):
        """Decided: the index is read directly, git is never run, so a missing
        (or PATH-substituted) git cannot change the answer."""
        self.git("init", "-q")
        self.point(str(self.target))
        code = ("import sys; sys.path.insert(0, %r); from vpscfg import estate; "
                "print(estate.resolve(%r).source)" % (str(REPO), str(self.tool)))
        env = dict(os.environ, PATH=str(self.target))  # no git on it
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           timeout=30, env=env)
        self.assertEqual(r.stdout.strip(), "pointer", r.stderr)

    def test_index_parser_reads_this_checkout(self):
        try:
            index = estate._git_index_path(str(REPO))
            data = open(index, "rb").read() if index else None
        except OSError:
            data = None
        if not data:
            self.skipTest("not a git checkout")
        names = estate._index_names(data)
        self.assertIn("vpsexec", names)
        self.assertIn("vpscfg/control.py", names)

    def test_truncated_index_refuses_cleanly(self):
        """W4 L-a: too short for a header must be EstateRefused, not struct.error."""
        (self.tool / ".git").mkdir()
        self.point(str(self.target))
        for raw in (b"DIRC", b"DIRC\x00\x00", b""):
            with self.subTest(raw=raw):
                (self.tool / ".git" / "index").write_bytes(raw)
                self.refuses("cannot tell whether git tracks")

    def test_corrupt_index_checksum_refuses(self):
        """W4 L-b: the trailing checksum decides SHA-1 vs SHA-256; a flipped
        byte anywhere refuses."""
        self.git("init", "-q")
        (self.tool / "a.txt").write_text("x")
        self.git("add", "a.txt")
        self.point(str(self.target))
        index = self.tool / ".git" / "index"
        good = index.read_bytes()
        self.assertEqual(estate._index_hash_lengths(good), (20,))
        bad = bytearray(good)
        bad[20] ^= 0xFF
        index.write_bytes(bytes(bad))
        self.refuses("checksum does not verify")
        index.write_bytes(good[:-1])
        self.refuses("checksum does not verify")

    def test_skiphash_index_is_still_read(self):
        self.git("init", "-q")
        self.git("config", "index.skipHash", "true")
        (self.tool / "a.txt").write_text("x")
        self.git("add", "a.txt")
        self.point(str(self.target))
        data = (self.tool / ".git" / "index").read_bytes()
        if data[-20:].strip(b"\0"):
            self.skipTest("this git ignores index.skipHash")
        self.assertEqual(estate.resolve(str(self.tool)).source, "pointer")
        self.git("add", "-f", "estate.path")
        self.refuses("git tracks estate.path")

    def test_split_index_keeps_its_own_message(self):
        self.git("init", "-q")
        (self.tool / "a.txt").write_text("x")
        self.git("add", "a.txt")
        self.git("update-index", "--split-index")
        self.point(str(self.target))
        self.refuses("split index")

    def test_git_dir_outside_the_checkout_is_not_a_checkout(self):
        """Documented: with no .git in the tool root (core.worktree, --git-dir)
        nothing is tracked as far as the resolver can tell without reading
        the environment."""
        self.point(str(self.target))
        self.assertIsNone(estate._git_index_path(str(self.tool)))
        self.assertEqual(estate.resolve(str(self.tool)).source, "pointer")

    # --- L3: the tool checkout's own chain ------------------------------------

    def test_tool_root_owned_by_another_user_refuses(self):
        self.point(str(self.target))
        real = os.lstat

        def lstat(path):
            st = real(path)
            return _with_uid(st, os.geteuid() + 4242) if path == str(self.tool) else st
        self.refuses("the tool checkout holding the pointer", lstat=lstat)

    def test_shared_tool_root_refuses(self):
        self.point(str(self.target))
        os.chmod(str(self.tool), 0o777)
        try:
            self.refuses("the tool checkout holding the pointer")
        finally:
            os.chmod(str(self.tool), 0o700)

    def test_tool_root_chain_is_not_checked_without_a_pointer(self):
        os.chmod(str(self.tool), 0o777)
        try:
            self.assertEqual(estate.resolve(str(self.tool)).source, "default")
        finally:
            os.chmod(str(self.tool), 0o700)

    # --- L1: extended ACLs ----------------------------------------------------

    def test_acl_on_pointer_root_governor_or_policies_refuses(self):
        self.point(str(self.target))
        for victim in (self.pointer, self.target, self.target / "vpscfg-control.json",
                       self.target / "policies"):
            with self.subTest(victim=victim.name):
                self.refuses("extended ACL", has_acl=lambda p, v=str(victim): p == v)
        self.assertEqual(estate.resolve(str(self.tool), has_acl=lambda p: False).source,
                         "pointer")

    def test_unreadable_acl_refuses(self):
        self.point(str(self.target))

        def broken(path):
            raise PermissionError(13, "denied", path)
        self.refuses("cannot read the ACL", has_acl=broken)

    @unittest.skipUnless(sys.platform == "darwin", "macOS ACL probe")
    def test_real_macos_acl_is_detected(self):
        self.point(str(self.target))
        self.assertEqual(estate.resolve(str(self.tool)).source, "pointer")
        r = subprocess.run(["/bin/chmod", "+a", "everyone allow write", str(self.pointer)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("chmod +a unavailable: %s" % r.stderr)
        self.refuses("extended ACL")
        subprocess.run(["/bin/chmod", "-N", str(self.pointer)], check=True)
        self.assertEqual(estate.resolve(str(self.tool)).source, "pointer")

    def test_ancestor_acl_granting_write_refuses(self):
        """W4: an ACL that lets someone add/delete/rename entries in an
        ancestor of the estate root, or of the tool checkout, refuses."""
        self.point(str(self.target))
        parent = str(self.target.parent)
        for victim, needle in ((parent, "add, delete or rename"),
                               (str(self.tool), "tool checkout holding the pointer"),
                               (os.path.dirname(parent), "add, delete or rename")):
            with self.subTest(victim=victim):
                self.refuses(needle, grants_write=lambda p, v=victim: p == v)
        self.assertEqual(estate.resolve(str(self.tool), grants_write=lambda p: False).source,
                         "pointer")

    def test_unreadable_ancestor_acl_refuses(self):
        self.point(str(self.target))

        def broken(path):
            raise OSError(5, "I/O error", path)
        self.refuses("cannot read the ACL", grants_write=broken)

    @unittest.skipUnless(sys.platform == "darwin", "macOS ACL probe")
    def test_real_macos_ancestor_acl(self):
        self.point(str(self.target))
        parent = str(self.target.parent)
        deny = subprocess.run(["/bin/chmod", "+a", "everyone deny delete", parent],
                              capture_output=True, text=True)
        if deny.returncode != 0:
            self.skipTest("chmod +a unavailable: %s" % deny.stderr)
        try:
            # A deny entry (what macOS puts on every home directory) is fine.
            self.assertEqual(estate.resolve(str(self.tool)).source, "pointer")
            subprocess.run(["/bin/chmod", "+a", "everyone allow add_file,delete_child", parent],
                           check=True)
            self.refuses("add, delete or rename")
        finally:
            subprocess.run(["/bin/chmod", "-N", parent], check=True)

    def test_linux_acl_parser(self):
        import struct as _struct

        def xattr(*entries):
            return _struct.pack("<I", 2) + b"".join(_struct.pack("<HHI", t, p, 0) for t, p in entries)
        real = getattr(os, "getxattr", None)
        cases = (((0x01, 7), (0x04, 5), (0x20, 5)), False,             # plain mode bits
                 ((0x01, 7), (0x02, 7), (0x04, 5), (0x10, 7), (0x20, 5)), True,  # named user rwx
                 ((0x01, 7), (0x08, 6), (0x04, 5), (0x10, 5), (0x20, 5)), False)  # masked off
        try:
            for entries, want in zip(cases[0::2], cases[1::2]):
                os.getxattr = lambda p, n, follow_symlinks=False, e=entries: (
                    xattr(*e) if n == "system.posix_acl_access" else
                    (_ for _ in ()).throw(OSError(61, "no data")))
                with self.subTest(entries=entries):
                    self.assertIs(estate._linux_grants_write("/x"), want)
        finally:
            if real is None:
                del os.getxattr
            else:
                os.getxattr = real

    # --- L2: every estate file the package reads ------------------------------

    def test_every_read_dir_is_walked(self):
        cases = (("contracts/web.yaml", 0o664, "group- or world-writable"),
                 ("contracts/skeletons/x.yaml", 0o646, "group- or world-writable"),
                 ("playbooks/inc/tasks.yml", 0o666, "group- or world-writable"),
                 ("plays/p.yaml", 0o620, "group- or world-writable"),
                 ("inventory/fingerprints/h.json", 0o666, "group- or world-writable"),
                 ("policies/escrow-recipients.txt", 0o666, "group- or world-writable"))
        self.point(str(self.target))
        for rel, mode, needle in cases:
            with self.subTest(rel=rel):
                path = self.target / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x")
                os.chmod(str(path), mode)
                self.refuses(needle)
                os.chmod(str(path), 0o644)
        self.assertEqual(estate.resolve(str(self.tool)).source, "pointer")

    def test_symlink_anywhere_in_a_read_dir_refuses(self):
        self.point(str(self.target))
        for rel in ("contracts/link.yaml", "plays/sub/link.yaml", "inventory/link"):
            with self.subTest(rel=rel):
                path = self.target / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(str(self.target / "vpscfg-control.json"), str(path))
                self.refuses("symlink")
                path.unlink()

    def test_shared_subdirectory_refuses(self):
        self.point(str(self.target))
        sub = self.target / "contracts" / "skeletons"
        sub.mkdir(parents=True)
        os.chmod(str(sub), 0o777)
        self.refuses("group- or world-writable")

    def test_read_dir_that_is_a_symlink_refuses(self):
        self.point(str(self.target))
        os.symlink(str(self.tool), str(self.target / "contracts"))
        self.refuses("must be a real directory")

    # --- L4 / L5: the TOCTOU compare, and errors that must refuse --------------

    def test_pointer_swapped_between_check_and_read_refuses(self):
        """Fails if the dev/ino compare after open() is removed."""
        self.point(str(self.target))
        real = os.lstat

        def lstat(path):
            st = real(path)
            if path != str(self.pointer):
                return st
            fields = list(st)
            fields[stat.ST_INO] = st.st_ino + 1  # what was checked is not what opens
            return os.stat_result(fields)
        self.refuses("changed while it was being read", lstat=lstat)

    def test_lstat_error_inside_the_estate_refuses_not_crashes(self):
        self.point(str(self.target))
        victim = self.target / "contracts" / "web.yaml"
        victim.parent.mkdir()
        victim.write_text("x")
        real = os.lstat

        def lstat(path):
            if path == str(victim):
                raise PermissionError(13, "Permission denied", path)
            return real(path)
        self.refuses("cannot stat", lstat=lstat)

    def test_unreadable_read_dir_refuses(self):
        self.point(str(self.target))
        locked = self.target / "contracts"
        locked.mkdir()
        os.chmod(str(locked), 0o000)
        try:
            if os.access(str(locked), os.R_OK):
                self.skipTest("running as root")
            self.refuses("cannot read")
        finally:
            os.chmod(str(locked), 0o755)



class EstateRecordStaysLocal(unittest.TestCase):
    """W4 L5/L6: the estate's paths stay on this machine; a pointed estate's
    play listing works."""

    def test_telemetry_drops_estate_and_interpreter_paths(self):
        from vpscfg import telemetry
        sent = []

        class Resp(object):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def urlopen(req, timeout=None):
            sent.append(json.loads(req.data))
            return Resp()
        real_key, real_open = telemetry._key, telemetry._opener
        real_url = telemetry.integrations.telemetry_url
        telemetry._key = lambda: "k"
        telemetry._opener = lambda: type("O", (), {"open": staticmethod(urlopen)})()
        telemetry.integrations.telemetry_url = lambda: "https://telemetry.example.com/v1"
        try:
            record = {"event": "allowed_read", "estate_root": "/Users/op/estate",
                      "estate_pointer": "/Users/op/tool/estate.path", "estate_source": "pointer",
                      "governor": "/Users/op/estate/vpscfg-control.json",
                      "governor_sha256": "ab" * 32, "interpreter": "/Users/op/py/bin/python3"}
            self.assertTrue(telemetry.push_event(record))
        finally:
            telemetry._key, telemetry._opener = real_key, real_open
            telemetry.integrations.telemetry_url = real_url
        payload = sent[0]["payload"]
        for field in ("estate_root", "estate_pointer", "governor", "interpreter"):
            self.assertNotIn(field, payload)
        self.assertNotIn("/Users/op", json.dumps(sent[0]))
        self.assertEqual(payload["governor_sha256"], "ab" * 32)
        self.assertEqual(payload["estate_source"], "pointer")
        self.assertIn("estate_root", record)  # the caller's (local) record is untouched

    def test_vpsrun_lists_plays_from_a_pointed_estate(self):
        import contextlib
        import importlib.machinery
        import io
        loader = importlib.machinery.SourceFileLoader("vpsrun_estate", str(REPO / "vpsrun"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        plays = _real_tmpdir(self) / "plays"
        plays.mkdir()
        (plays / "fix-web.yaml").write_text("steps: []\n")
        mod.PLAY_DIR = plays
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(mod.main(["--help"]), 0)
        self.assertIn("plays/fix-web.yaml", out.getvalue())


class DoorsAgree(unittest.TestCase):
    """All three doors, in a temp checkout, against a pointed estate."""

    def setUp(self):
        self.base = _real_tmpdir(self)
        self.tool = self.base / "tool"
        self.tool.mkdir(mode=0o700)
        for name in ("vpscfg-control.py", "vpsexec"):
            shutil.copy(str(REPO / name), str(self.tool / name))
        # The tool checkout's own governor: the example's (mode test) with a
        # host the estate lacks, so the output says which governor was read.
        tool_gov = json.loads((EXAMPLE / "vpscfg-control.json").read_text())
        tool_gov["hosts"] = {"toolhost": {"posture": "frozen", "reason": "tool checkout"}}
        (self.tool / "vpscfg-control.json").write_text(json.dumps(tool_gov, indent=2))
        os.chmod(str(self.tool / "vpscfg-control.json"), 0o644)
        shutil.copytree(str(REPO / "vpscfg"), str(self.tool / "vpscfg"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        self.home = self.base / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        shutil.copy(str(EXAMPLE / "ssh_config.example"), str(self.home / ".ssh" / "config"))
        # The estate: the contrib example's governor, distinguishable by mode,
        # and a policies/ with a group the tool checkout's policies lack.
        self.estate = self.base / "estate"
        (self.estate / "policies").mkdir(parents=True)
        os.chmod(str(self.estate), 0o700)
        gov = json.loads((EXAMPLE / "vpscfg-control.json").read_text())
        gov["mode"] = "supervised"
        (self.estate / "vpscfg-control.json").write_text(json.dumps(gov, indent=2))
        (self.estate / "policies" / "groups.yaml").write_text(
            "version: 1\nreason: estate-only group\ngroups:\n  estonly: [web1, edge1]\n")
        for p in (self.estate / "vpscfg-control.json", self.estate / "policies" / "groups.yaml"):
            os.chmod(str(p), 0o644)
        self.gov_sha = hashlib.sha256((self.estate / "vpscfg-control.json").read_bytes()).hexdigest()

    def point(self):
        p = self.tool / "estate.path"
        p.write_text(str(self.estate) + "\n")
        os.chmod(str(p), 0o600)

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith("VPSCFG_")}
        env.pop("VPSCFG_TELEMETRY_KEY", None)
        env["HOME"] = str(self.home)  # the doors find PyYAML from the passwd home, not HOME
        env.update(extra)
        return env

    def run_door(self, *argv, env=None):
        return subprocess.run([sys.executable, *argv], capture_output=True, text=True,
                              timeout=60, cwd=str(self.tool), env=env or self.env())

    def journal(self, stream):
        p = self.tool / "journal" / ("%s.jsonl" % stream)
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

    def test_control_door_and_package_judge_the_pointed_governor(self):
        self.point()
        r = self.run_door("vpscfg-control.py", "status")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("mode: supervised", r.stdout)
        # The outer door's token is the hash of what IT read; the inner door
        # verifies it against what IT resolved. True = one governor, not two.
        self.assertIn("verified via wrapper token: True", r.stdout)
        rec = self.journal("control")[-1]
        self.assertEqual(rec["estate_root"], str(self.estate))
        self.assertEqual(rec["estate_source"], "pointer")
        self.assertEqual(rec["governor"], str(self.estate / "vpscfg-control.json"))
        self.assertEqual(rec["governor_sha256"], self.gov_sha)

    def test_default_checkout_journals_the_tool_root(self):
        r = self.run_door("vpscfg-control.py", "status")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("mode: test", r.stdout)
        rec = self.journal("control")[-1]
        self.assertEqual((rec["estate_root"], rec["estate_source"]), (str(self.tool), "default"))
        self.assertEqual(rec["governor_sha256"], hashlib.sha256(
            (self.tool / "vpscfg-control.json").read_bytes()).hexdigest())

    def test_vpsexec_outer_and_inner_read_the_pointed_estate(self):
        self.point()
        r = self.run_door("vpsexec", "groups")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("estonly", r.stdout)  # the inner door's policy loader
        r = self.run_door("vpsexec", "hosts")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("web1", r.stdout)
        self.assertNotIn("toolhost", r.stdout)
        # The outer door's own group resolution: an @estonly read plan only
        # resolves if the OUTER door read the estate's policies too.
        r = self.run_door("vpsexec", "@estonly", "uptime", "--help")
        self.assertNotIn("no host group", r.stderr)
        rec = [e for e in self.journal("vpsexec") if e.get("door") == "vpsexec-wrapper"][-1]
        self.assertEqual(rec["estate_root"], str(self.estate))
        self.assertEqual(rec["governor_sha256"], self.gov_sha)

    def test_inner_door_refuses_the_old_governor_once_the_estate_moved(self):
        """No split brain: a caller passing the tool checkout's governor and
        its genuine token is refused, because the canonical governor is now the
        estate's."""
        self.point()
        old = self.tool / "vpscfg-control.json"
        token = hashlib.sha256(old.read_bytes()).hexdigest()
        r = self.run_door("-m", "vpscfg", "status", env=self.env(
            VPSCFG_CONTROL_PATH=str(old), VPSCFG_CONTROL_TOKEN=token))
        self.assertEqual(r.returncode, 2)
        self.assertIn("spoofing", r.stderr)

    def test_env_vars_do_not_move_any_door(self):
        hostile = {k: str(self.estate) for k in ENV_ATTEMPTS if k != "VPSCFG_CONTROL_PATH"}
        r = self.run_door("vpscfg-control.py", "status", env=self.env(**hostile))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("mode: test", r.stdout)  # the tool checkout's governor
        r = self.run_door("vpsexec", "groups", env=self.env(**hostile))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("estonly", r.stdout)
        self.assertEqual(self.journal("control")[-1]["estate_source"], "default")

    def test_bad_pointer_refuses_every_door(self):
        p = self.tool / "estate.path"
        p.write_text(str(self.estate) + "\n")
        os.chmod(str(p), 0o666)
        for argv in (("vpscfg-control.py", "status"), ("vpsexec", "hosts"),
                     ("-m", "vpscfg", "status")):
            with self.subTest(door=argv[0]):
                r = self.run_door(*argv)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("REFUSED", r.stderr)
                self.assertIn("group- or world-writable", r.stderr)
        self.assertEqual(self.journal("control")[-1]["event"], "refused")


if __name__ == "__main__":
    unittest.main()
