"""The launchd helpers: remote-influenced text never becomes AppleScript
source, and a checkout path never rewrites the plist's XML.

Threats: a `fleet watch:` summary carrying a quote that ends the AppleScript
string and runs `do shell script`; a checkout path with `<`, `&` or a quote
injecting plist keys (ProgramArguments) into the launch agent.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"


class FleetwatchScriptsTest(unittest.TestCase):
    def test_scripts_parse(self):
        for name in ("fleetwatch-cron.sh", "install-fleetwatch.sh"):
            r = subprocess.run(["sh", "-n", str(TOOLS / name)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_summary_reaches_osascript_as_argv_only(self):
        text = (TOOLS / "fleetwatch-cron.sh").read_text()
        call = text[text.index("/usr/bin/osascript"):]
        call = call[:call.index("2>/dev/null")]
        self.assertNotIn('-e "', call)  # no double-quoted (expanding) script source
        sources = re.findall(r"-e '([^']*)'", call)
        self.assertTrue(sources)
        for src in sources:
            self.assertNotIn("$", src)
        self.assertIn("item 1 of argv", text)

    def test_install_refuses_a_path_with_xml_metacharacters(self):
        for bad in ("a&b", "a<b", "a>b", 'a"b', "a'b"):
            with tempfile.TemporaryDirectory() as tmp:
                checkout = Path(tmp) / bad
                (checkout / "tools").mkdir(parents=True)
                shutil.copy(TOOLS / "install-fleetwatch.sh", checkout / "tools")
                home = Path(tmp) / "home"
                home.mkdir()
                env = dict(os.environ, HOME=str(home), PATH="/usr/bin:/bin")
                r = subprocess.run(["sh", str(checkout / "tools" / "install-fleetwatch.sh")],
                                   capture_output=True, text=True, env=env, timeout=30)
                self.assertNotEqual(r.returncode, 0, bad)
                self.assertIn("refusing", r.stderr, bad)
                self.assertFalse((home / "Library").exists(), bad)


if __name__ == "__main__":
    unittest.main()
