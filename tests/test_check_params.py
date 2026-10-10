"""Typed parameters on named read plays (docs/NO-PASTE.md F4).

`$` stays banned from commands; a check's params are substituted in Python,
after each value passes its regex AND the door's fixed character ceiling. The
finished command is then classified like any other: it must be a read.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import gates, vpsexecpolicy  # noqa: E402
from vpscfg.vpsexec import Refused  # noqa: E402

DENY = gates.DENY_ALWAYS_FLOOR


def _load(yaml_text):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "c.yaml").write_text(yaml_text)
        return vpsexecpolicy.load(d, deny_patterns=DENY)["checks"]


CHECK = '''version: 1
reason: t
checks:
  logs:
    cmd: "docker logs --tail @@lines@@ @@name@@"
    why: w
    params:
      name: {re: "[a-z][a-z0-9-]{0,30}"}
      lines: {re: "[0-9]{1,4}", default: "50"}
'''


class BindTest(unittest.TestCase):
    def setUp(self):
        self.check = _load(CHECK)["logs"]

    def test_binds_and_defaults(self):
        self.assertEqual(vpsexecpolicy.bind_params(self.check, ["name=web"]),
                         "docker logs --tail 50 web")
        self.assertEqual(vpsexecpolicy.bind_params(self.check, ["name=web", "lines=5"]),
                         "docker logs --tail 5 web")

    def test_injection_shapes_refuse(self):
        for value in ("web;reboot", "web x", "$(id)", "`id`", "web|sh", "web>/etc/x",
                      "web&&id", "'web'", "we*", "web\nid", "", "a" * 200, "{a,b}",
                      "-f", "--follow", "@/etc/shadow"):
            with self.assertRaises(Refused, msg=value):
                vpsexecpolicy.bind_params(self.check, ["name=" + value])

    def test_door_ceiling_refuses_flag_and_file_shapes_whatever_the_policy_says(self):
        for value in ("-f", "--follow", "-1h", "@/etc/shadow", "a b", "a;b", "a$b"):
            self.assertIsNone(vpsexecpolicy.PARAM_VALUE_RE.match(value), value)
        for value in ("shop-caddy", "1h", "deploy/shop-api", "https://x.io/health"):
            self.assertIsNotNone(vpsexecpolicy.PARAM_VALUE_RE.match(value), value)

    def test_policy_regex_is_fullmatch_not_search(self):
        with self.assertRaises(Refused):
            vpsexecpolicy.bind_params(self.check, ["name=web", "lines=5x"])

    def test_missing_unknown_and_repeated_refuse(self):
        for supplied in ([], ["name=web", "nmae=x"], ["name=web", "name=db"]):
            with self.assertRaises(Refused, msg=supplied):
                vpsexecpolicy.bind_params(self.check, supplied)


class LoadTest(unittest.TestCase):
    def test_undeclared_placeholder_refuses(self):
        with self.assertRaises(Refused):
            _load(CHECK.replace("@@name@@", "@@nmae@@"))

    def test_unused_param_refuses(self):
        with self.assertRaises(Refused):
            _load(CHECK + "      extra: {re: \"x\"}\n")

    def test_default_must_match_its_own_regex(self):
        with self.assertRaises(Refused):
            _load(CHECK.replace('default: "50"', 'default: "fifty"'))

    def test_bad_regex_and_unknown_key_refuse(self):
        with self.assertRaises(Refused):
            _load(CHECK.replace('"[0-9]{1,4}"', '"[0-9"'))
        with self.assertRaises(Refused):
            _load(CHECK.replace('default: "50"', 'default: "50", grant: yes'))


if __name__ == "__main__":
    unittest.main()
