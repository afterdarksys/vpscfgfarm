"""Per-host timeouts: --timeout, then a runbook's timeout, then a prediction
from the command (capped), instead of one fixed 120 s for everything.

A fixed 120 s can cut a long break-glass step (a credential rotation) off
mid-run.
"""
import unittest
from pathlib import Path

from vpscfg.vpsexec import PREDICTED_TIMEOUT_CAP, choose_timeout, predict_timeout
from vpscfg.vpsexecpolicy import RUNBOOK_TIMEOUT_MAX, Refused, _check_runbook


class PredictTimeoutTest(unittest.TestCase):
    CASES = [
        ("ls /root", "read", 60),
        ("k3s kubectl get pods -A", "read", 60),
        ("touch /tmp/x", "mutating", 120),
        ("systemctl restart nginx", "mutating", 90),
        ("psql -v ON_ERROR_STOP=1 -f /tmp/m.sql", "mutating", 180),
        ("docker pull registry.example/app:1", "mutating", 240),
        ("docker compose --project-directory /srv/compose/t up -d --no-deps web", "mutating", 240),
        ("k3s kubectl rollout restart deploy/x -n y", "mutating", 240),
        ("bash /var/tmp/vpscfg-push/abc/rotate.sh secretref", "mutating", 300),
        ("apt-get install -y foo", "mutating", 300),
    ]

    def test_prediction_by_command_shape(self):
        for command, tier, seconds in self.CASES:
            with self.subTest(command=command):
                self.assertEqual(predict_timeout(command, tier)[0], seconds)

    def test_every_prediction_is_capped(self):
        self.assertEqual(predict_timeout("touch /x", "mutating", base=9999)[0],
                         PREDICTED_TIMEOUT_CAP)
        for command in ("bash x.sh", "docker pull a", "psql -f a", "touch a"):
            self.assertLessEqual(predict_timeout(command, "mutating")[0], PREDICTED_TIMEOUT_CAP)

    def test_precedence_explicit_then_runbook_then_prediction(self):
        self.assertEqual(choose_timeout(1800, [600], "ls", "read"), (1800, "--timeout"))
        self.assertEqual(choose_timeout(None, [None, 600, 1200], "touch /x", "mutating"),
                         (1200, "runbook"))
        self.assertTrue(choose_timeout(None, [None], "docker pull a", "mutating")[1]
                        .startswith("predicted"))


class RunbookTimeoutTest(unittest.TestCase):
    def runbook(self, **extra):
        entry = dict(hosts=["web1"], cmd="docker pull a", why="t", **extra)
        return _check_runbook(Path("p.yaml"), 1, entry, [], None, None, "2099-01-01")

    def test_runbook_timeout_is_validated(self):
        self.assertEqual(self.runbook(timeout=1200)["timeout"], 1200)
        self.assertIsNone(self.runbook()["timeout"])
        for bad in (0, -1, RUNBOOK_TIMEOUT_MAX + 1, "600", 1.5, True):
            with self.subTest(bad=bad), self.assertRaises(Refused):
                self.runbook(timeout=bad)


if __name__ == "__main__":
    unittest.main()
