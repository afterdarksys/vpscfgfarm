"""Every door runs under `python3 -I` (W4 review H1).

The attack: a sitecustomize.py on PYTHONPATH (or a usercustomize.py under
PYTHONUSERBASE) patches pathlib.Path.read_bytes so that BOTH doors read a forged
governor. The outer door hashes the forged bytes, the inner door hashes the
same forged bytes, the token verifies, and the doors obey mode `released`.

What this pins, against real copies of the doors in a temp checkout:
  - with a hostile PYTHONPATH, PYTHONUSERBASE or PYTHONHOME the doors judge the
    REAL governor (its mode, its hash in the journal) or do not start at all;
  - the outer door re-execs itself isolated when started as `python3 door`,
    and journals the interpreter and that it was isolated;
  - started by path, the shebang makes even the first interpreter isolated;
  - vpsrun starts both doors with -I.
Nothing here reaches a host.
"""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

FORGE = '''
import json, pathlib
open(%(marker)r, "a").write("hook ran\\n")
_real = pathlib.Path.read_bytes
def _forged(self):
    data = _real(self)
    if self.name == "vpscfg-control.json":
        doc = json.loads(data)
        doc["mode"] = "released"
        doc["mutation_enabled"] = True
        doc.setdefault("hosts", {})["forgedhost"] = {"posture": "test"}
        return json.dumps(doc).encode()
    return data
pathlib.Path.read_bytes = _forged
'''


PIN = REPO / "tools" / "pin-interpreter.sh"
REAL_PYTHON = os.path.realpath(sys.executable)
DOORS = ("vpscfg-control.py", "vpsexec", "vpsrun")


def _shebang_interpreter(path):
    first = Path(path).read_text().splitlines()[0]
    assert first.startswith("#!") and first.endswith(" -I"), first
    return first[2:-3]


def _user_site(base):
    scheme = ("osx_framework_user" if sys.platform == "darwin"
              and sysconfig.get_config_var("PYTHONFRAMEWORK") else "posix_user")
    return sysconfig.get_path("purelib", scheme, vars={"userbase": base})


class IsolatedDoors(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.root = self.base / "tool"
        self.root.mkdir()
        for name in ("vpscfg-control.py", "vpsexec", "vpsrun"):
            shutil.copy2(str(REPO / name), str(self.root / name))
        shutil.copy2(str(REPO / "contrib" / "example-estate" / "vpscfg-control.json"),
                     str(self.root / "vpscfg-control.json"))
        shutil.copytree(str(REPO / "vpscfg"), str(self.root / "vpscfg"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        self.home = self.base / "home"
        self.home.mkdir()
        self.marker = self.base / "hook-ran"
        self.real_sha = hashlib.sha256((self.root / "vpscfg-control.json").read_bytes()).hexdigest()
        # The committed shebang names this Mac's interpreter. Where it does not
        # exist (Linux CI), pin the copies the way an install does.
        if not os.path.isfile(_shebang_interpreter(REPO / "vpsexec")):
            r = subprocess.run([str(PIN), "--root", str(self.root), REAL_PYTHON],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)

    def hook_dir(self, filename, where):
        where.mkdir(parents=True, exist_ok=True)
        (where / filename).write_text(FORGE % {"marker": str(self.marker)})
        return where

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("VPSCFG_", "PYTHON"))}
        env.pop("VPSCFG_TELEMETRY_KEY", None)
        env["HOME"] = str(self.home)
        env.update(extra)
        return env

    def run_door(self, argv, env):
        return subprocess.run(argv, capture_output=True, text=True, timeout=60,
                              cwd=str(self.root), env=env)

    def journal(self, stream):
        p = self.root / "journal" / ("%s.jsonl" % stream)
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

    def assert_real_governor(self, r):
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("mode: test", r.stdout)
        self.assertNotIn("released", r.stdout)
        # The inner door verified the outer door's token: both read the real bytes.
        self.assertIn("verified via wrapper token: True", r.stdout)
        rec = [e for e in self.journal("control") if e.get("event") == "allowed_read"][-1]
        self.assertEqual(rec["policy_hash"], self.real_sha[:12])
        self.assertTrue(rec["isolated"])
        self.assertEqual(os.path.realpath(rec["interpreter"]), REAL_PYTHON)

    def test_the_forge_works_without_isolation(self):
        """Control: the hook really does forge the governor when it loads, so
        the tests below are not passing by accident."""
        hooks = self.hook_dir("sitecustomize.py", self.base / "pp")
        code = ("import pathlib; print(pathlib.Path(%r).read_bytes().decode())"
                % str(self.root / "vpscfg-control.json"))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           timeout=30, env=self.env(PYTHONPATH=str(hooks)))
        self.assertEqual(json.loads(r.stdout)["mode"], "released")

    def test_pythonpath_sitecustomize_cannot_forge_the_governor(self):
        hooks = self.hook_dir("sitecustomize.py", self.base / "pp")
        r = self.run_door([sys.executable, "vpscfg-control.py", "status"],
                          self.env(PYTHONPATH=str(hooks)))
        self.assert_real_governor(r)

    def test_pythonuserbase_usercustomize_cannot_forge_the_governor(self):
        userbase = self.base / "userbase"
        self.hook_dir("usercustomize.py", Path(_user_site(str(userbase))))
        r = self.run_door([sys.executable, "vpscfg-control.py", "status"],
                          self.env(PYTHONUSERBASE=str(userbase)))
        self.assert_real_governor(r)

    def test_pythonhome_cannot_supply_a_forged_stdlib(self):
        """A PYTHONHOME without a usable stdlib stops the first interpreter
        before any door code runs: fail-closed, nothing judged, nothing run."""
        fake = self.base / "fakehome"
        self.hook_dir("pathlib.py", fake / "lib" / ("python%d.%d" % sys.version_info[:2]))
        r = self.run_door([sys.executable, "vpscfg-control.py", "status"],
                          self.env(PYTHONHOME=str(fake)))
        self.assertNotIn("mode: released", r.stdout)
        if r.returncode == 0:
            self.assert_real_governor(r)

    def test_vpsexec_door_judges_the_real_governor(self):
        hooks = self.hook_dir("sitecustomize.py", self.base / "pp")
        r = self.run_door([sys.executable, "vpsexec", "hosts"],
                          self.env(PYTHONPATH=str(hooks)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        rec = [e for e in self.journal("vpsexec") if e.get("door") == "vpsexec-wrapper"][-1]
        self.assertEqual(rec["policy_hash"], self.real_sha[:12])
        self.assertEqual(rec["mode"], "test")
        self.assertTrue(rec["isolated"])

    # --- W4 R1: started by path, PATH cannot choose the interpreter -----------

    def fake_python_first_on_path(self):
        """A `python3` that drops -I and injects the forging hook, first on PATH.
        With `#!/usr/bin/env -S python3 -I` it would run every door."""
        hooks = self.hook_dir("sitecustomize.py", self.base / "pp")
        fakebin = self.base / "fakebin"
        fakebin.mkdir()
        fake = fakebin / "python3"
        fake.write_text(
            "#!/bin/sh\n"
            "echo fake-python3 >> %s\n"
            "for a do\n  shift\n  [ \"$a\" = \"-I\" ] || set -- \"$@\" \"$a\"\ndone\n"
            "PYTHONPATH=%s exec %s \"$@\"\n" % (self.marker, hooks, sys.executable))
        os.chmod(str(fake), 0o755)
        return os.pathsep.join([str(fakebin), os.environ.get("PATH", "")]), hooks

    def test_a_fake_python3_on_path_cannot_run_any_door(self):
        path, hooks = self.fake_python_first_on_path()
        env = self.env(PATH=path, PYTHONPATH=str(hooks))
        r = self.run_door([str(self.root / "vpscfg-control.py"), "status"], env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("mode: test", r.stdout)
        self.assertIn("verified via wrapper token: True", r.stdout)
        rec = [e for e in self.journal("control") if e.get("event") == "allowed_read"][-1]
        self.assertEqual(rec["policy_hash"], self.real_sha[:12])
        self.assertTrue(rec["isolated"])

        r = self.run_door([str(self.root / "vpsexec"), "hosts"], env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("forgedhost", r.stdout)
        rec = [e for e in self.journal("vpsexec") if e.get("door") == "vpsexec-wrapper"][-1]
        self.assertEqual(rec["policy_hash"], self.real_sha[:12])

        r = self.run_door([str(self.root / "vpsrun"), "--help"], env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.marker.exists(),
                         "a python3 found on PATH ran a door: %s" % (
                             self.marker.read_text() if self.marker.exists() else ""))

    def test_vpsexec_inner_door_runs_isolated(self):
        """W4 gap (a): started by path, the outer door is isolated by its
        shebang, so only the INNER child's -I keeps the hook out of the
        governor the inner door renders. `forgedhost` exists only in the
        forged governor."""
        hooks = self.hook_dir("sitecustomize.py", self.base / "pp")
        r = self.run_door([str(self.root / "vpsexec"), "hosts"],
                          self.env(PYTHONPATH=str(hooks)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("forgedhost", r.stdout)
        self.assertIn("edge1", r.stdout)  # the on-disk governor's hosts were rendered
        self.assertFalse(self.marker.exists(), "the hook ran in a door interpreter")

    # --- W4 follow-up: macOS /usr/bin shims honour DEVELOPER_DIR ---------------

    def fake_developer_dir(self):
        """A DEVELOPER_DIR whose xcrun (and python3) drops -I and loads the
        forging hook. /usr/bin/python3 on macOS runs `xcrun python3 -I ...`
        from DEVELOPER_DIR."""
        hooks = self.hook_dir("sitecustomize.py", self.base / "pp")
        dev = self.base / "devdir"
        (dev / "usr" / "bin").mkdir(parents=True)
        script = ("#!/bin/sh\n"
                  "echo \"fake-xcrun $*\" >> %s\n"
                  "[ \"$1\" = python3 ] && shift\n"
                  "for a do\n  shift\n  [ \"$a\" = \"-I\" ] || set -- \"$@\" \"$a\"\ndone\n"
                  "PYTHONPATH=%s exec %s \"$@\"\n" % (self.marker, hooks, REAL_PYTHON))
        for name in ("xcrun", "python3"):
            (dev / "usr" / "bin" / name).write_text(script)
            os.chmod(str(dev / "usr" / "bin" / name), 0o755)
        return dev

    @unittest.skipUnless(sys.platform == "darwin", "the xcrun shims are macOS")
    def test_a_fake_developer_dir_cannot_run_any_door(self):
        dev = self.fake_developer_dir()
        env = self.env(DEVELOPER_DIR=str(dev), TOOLCHAINS="fake", SDKROOT=str(dev))
        r = self.run_door([str(self.root / "vpscfg-control.py"), "status"], env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("mode: test", r.stdout)
        self.assertIn("verified via wrapper token: True", r.stdout)
        rec = [e for e in self.journal("control") if e.get("event") == "allowed_read"][-1]
        self.assertEqual(rec["policy_hash"], self.real_sha[:12])
        self.assertFalse(self.marker.exists(), "DEVELOPER_DIR chose the control door's "
                         "interpreter: %s" % (self.marker.read_text() if self.marker.exists() else ""))

        r = self.run_door([str(self.root / "vpsexec"), "hosts"], env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("forgedhost", r.stdout)
        rec = [e for e in self.journal("vpsexec") if e.get("door") == "vpsexec-wrapper"][-1]
        self.assertEqual(rec["policy_hash"], self.real_sha[:12])

        r = self.run_door([str(self.root / "vpsrun"), "--help"], env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.marker.exists(), "DEVELOPER_DIR chose a door's interpreter: %s" % (
            self.marker.read_text() if self.marker.exists() else ""))

    def test_shebangs_name_one_absolute_isolated_interpreter(self):
        firsts = {door: (REPO / door).read_text().splitlines()[0] for door in DOORS}
        self.assertEqual(len(set(firsts.values())), 1, firsts)
        target = _shebang_interpreter(REPO / "vpsexec")
        self.assertTrue(os.path.isabs(target), target)
        self.assertNotIn("env", os.path.basename(target))

    @unittest.skipUnless(sys.platform == "darwin", "the committed shebang is this Mac's")
    def test_darwin_shebang_is_a_real_root_owned_binary_not_a_shim(self):
        target = _shebang_interpreter(REPO / "vpsexec")
        self.assertTrue(os.path.isfile(target) and not os.path.islink(target), target)
        with open(target, "rb") as f:
            self.assertNotEqual(f.read(2), b"#!", "the interpreter is a script")
        st = os.stat(target)
        self.assertEqual(st.st_uid, 0, "the pinned interpreter is not root-owned")
        self.assertFalse(st.st_mode & 0o022)
        self.assertNotIn(target, ("/usr/bin/python3", "/usr/bin/xcrun"))
        self.assertNotEqual(os.path.dirname(target), "/usr/bin")

    def test_doors_refuse_to_relaunch_through_a_shim_or_nothing(self):
        """_interpreter(): sys.executable must resolve to a real file, and on
        macOS not to a /usr/bin shim, or the door exits before doing anything."""
        bogus = ["/nonexistent/python3"]
        if sys.platform == "darwin":
            bogus.append("/usr/bin/python3")
        real = sys.executable
        sys.path.insert(0, str(REPO))
        try:
            for door in DOORS:
                for exe in bogus:
                    with self.subTest(door=door, exe=exe):
                        sys.executable = exe
                        loader = importlib.machinery.SourceFileLoader(
                            "door_" + door.replace("-", "_").replace(".", "_"), str(REPO / door))
                        mod = importlib.util.module_from_spec(
                            importlib.util.spec_from_loader(loader.name, loader))
                        with self.assertRaises(SystemExit) as cm:
                            loader.exec_module(mod)
                        self.assertEqual(cm.exception.code, 2)
        finally:
            sys.executable = real

    def test_vpsrun_starts_both_doors_isolated(self):
        loader = importlib.machinery.SourceFileLoader("vpsrun_isolation", str(REPO / "vpsrun"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(REPO))
        loader.exec_module(mod)
        self.assertEqual(mod.VPSEXEC[:2], [REAL_PYTHON, "-I"])
        self.assertEqual(mod.VPSCFG[:2], [REAL_PYTHON, "-I"])


class OperatorSite(unittest.TestCase):
    """W4 gap (b): under -I the package re-adds the operator's user site, and
    only one the operator owns and nobody else can write."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.site = Path(os.path.realpath(tmp.name)) / "site-packages"
        self.site.mkdir(mode=0o755)
        os.chmod(str(self.site), 0o755)
        import vpscfg
        self.vpscfg = vpscfg

    def add(self, **kw):
        path_list = []
        added = self.vpscfg._operator_site(path=str(self.site), sys_path=path_list, **kw)
        return added, path_list

    def test_own_unshared_site_is_appended(self):
        added, path_list = self.add()
        self.assertTrue(added)
        self.assertEqual(path_list, [str(self.site)])

    def test_group_writable_site_is_refused(self):
        os.chmod(str(self.site), 0o775)
        self.assertEqual(self.add(), (False, []))

    def test_world_writable_site_is_refused(self):
        os.chmod(str(self.site), 0o757)
        self.assertEqual(self.add(), (False, []))

    def test_site_owned_by_another_uid_is_refused(self):
        real = os.lstat

        def lstat(path):
            fields = list(real(path))
            fields[stat.ST_UID] = os.geteuid() + 4242
            return os.stat_result(fields)
        self.assertEqual(self.add(lstat=lstat), (False, []))
        self.assertEqual(self.add(euid=os.geteuid() + 4242), (False, []))

    def test_symlinked_or_missing_site_is_refused(self):
        link = self.site.parent / "link"
        os.symlink(str(self.site), str(link))
        path_list = []
        self.assertFalse(self.vpscfg._operator_site(path=str(link), sys_path=path_list))
        self.assertFalse(self.vpscfg._operator_site(path=str(self.site) + "-gone",
                                                    sys_path=path_list))
        self.assertEqual(path_list, [])

    def test_site_comes_from_the_password_database_not_home(self):
        import pwd
        code = ("import sys; sys.path.insert(0, %r); import vpscfg; "
                "print(vpscfg._operator_site_path())" % str(REPO))
        env = dict(os.environ, HOME=str(self.site), PYTHONUSERBASE=str(self.site))
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True,
                           text=True, timeout=30, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.strip().startswith(pwd.getpwuid(os.geteuid()).pw_dir))
        self.assertNotIn(str(self.site), r.stdout)


class PinInterpreter(unittest.TestCase):
    """tools/pin-interpreter.sh: the install step, and everything it refuses."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        os.chmod(str(self.base), 0o755)
        self.root = self.base / "tool"
        self.root.mkdir()
        for door in DOORS:
            shutil.copy2(str(REPO / door), str(self.root / door))
        self.before = {d: (self.root / d).read_bytes() for d in DOORS}

    def pin(self, target, *extra):
        return subprocess.run([str(PIN), "--root", str(self.root)] + list(extra) + [str(target)],
                              capture_output=True, text=True, timeout=60)

    def refused(self, target, needle):
        r = self.pin(target)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn(needle, r.stderr)
        for d in DOORS:  # nothing written
            self.assertEqual((self.root / d).read_bytes(), self.before[d], d)

    def binary_copy(self, mode=0o755, where=None):
        where = where or (self.base / "bin")
        where.mkdir(exist_ok=True)
        os.chmod(str(where), 0o755)
        dest = where / "notpython"
        shutil.copyfile("/bin/ls", str(dest))
        os.chmod(str(dest), mode)
        return dest

    def test_pins_all_three_doors_in_place(self):
        r = self.pin(REAL_PYTHON)
        self.assertEqual(r.returncode, 0, r.stderr)
        for d in DOORS:
            lines = (self.root / d).read_text().split("\n", 1)
            self.assertEqual(lines[0], "#!%s -I" % REAL_PYTHON)
            self.assertEqual(lines[1], self.before[d].decode().split("\n", 1)[1])
            self.assertTrue(os.access(str(self.root / d), os.X_OK))

    def test_relative_path_refuses(self):
        self.refused("python3", "not an absolute path")

    def test_whitespace_refuses(self):
        self.refused("/opt/my python/bin/python3", "whitespace")

    def test_too_long_refuses(self):
        self.refused("/" + "a" * 130, "127")

    def test_missing_refuses(self):
        self.refused(self.base / "nope", "not a regular file")

    def test_symlink_refuses(self):
        link = self.base / "python-link"
        os.symlink(REAL_PYTHON, str(link))
        self.refused(link, "symlink")

    def test_script_refuses(self):
        script = self.base / "python3"
        script.write_text("#!/bin/sh\nexec /bin/true\n")
        os.chmod(str(script), 0o755)
        self.refused(script, "is a script")

    def test_not_executable_refuses(self):
        self.refused(self.binary_copy(mode=0o644), "not executable")

    def test_group_or_world_writable_refuses(self):
        for mode in (0o775, 0o757):
            with self.subTest(mode=oct(mode)):
                self.refused(self.binary_copy(mode=mode), "group- or world-writable")

    def test_writable_directory_refuses(self):
        target = self.binary_copy()
        os.chmod(str(target.parent), 0o777)
        try:
            self.refused(target, "group- or world-writable")
        finally:
            os.chmod(str(target.parent), 0o755)

    def test_binary_that_is_not_an_isolated_python_refuses(self):
        self.refused(self.binary_copy(), "does not run isolated")

    @unittest.skipUnless(sys.platform == "darwin", "the xcrun shims are macOS")
    def test_darwin_shims_refuse(self):
        for shim in ("/usr/bin/python3", "/usr/bin/xcrun"):
            with self.subTest(shim=shim):
                if os.path.exists(shim):
                    self.refused(shim, "xcrun shim")

    def test_missing_door_refuses_before_writing_any(self):
        (self.root / "vpsrun").unlink()
        del self.before["vpsrun"]
        r = self.pin(REAL_PYTHON)
        self.assertEqual(r.returncode, 2)
        self.assertIn("missing", r.stderr)
        for d in self.before:
            self.assertEqual((self.root / d).read_bytes(), self.before[d])

    def test_another_owner_is_refused_by_the_script(self):
        """Owned by neither root nor the operator: needs a second account to
        set up for real, so this pins the check itself in the source."""
        text = PIN.read_text()
        self.assertIn('[ "$owner" = "0" ] || [ "$owner" = "$me" ] || refuse', text)


if __name__ == "__main__":
    unittest.main()
