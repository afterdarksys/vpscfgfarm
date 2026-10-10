"""Recursive content reads ("tree reads") and the roots they may start from.

deny_extra matches command TEXT. Without this gate `grep -r -a . /etc` names
no credential path, classifies as a READ (no --run, no approval, fine on a frozen
host) and prints every credential under /etc: /etc/hsmd/pin, every
server.key, every .pem. readpolicy.tree_read_verdict looks at the ROOT of every
command that reads file contents across a directory:

  refused on every tier  root is relative/missing/`..`, under /proc, equal to or
                         an ancestor of a broad root or an absolute deny path
  never a read           any other root outside the log trees (a filename
                         pattern such as .env.production can sit anywhere)
  unchanged              roots under /var/log

Hermetic: ssh is faked by the test_vpsexec harness; nothing dials a host.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
from vpscfg import readpolicy, vpsexec  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

# Every recursive-content form the door could be handed, `{r}` the root. The
# grep forms are reads today; the others are mutations, refused here too so a
# runbook, approval or break-glass cannot carry them.
FORMS = (
    "grep -r -a . {r}", "grep -R . {r}", "grep -ra secret {r}", "grep -rn foo {r}",
    "grep -rail password {r}", "grep -rc x {r}", "grep -rq x {r}",
    "grep foo {r} -r", "grep -e foo -r {r}", "grep -r -e foo -- {r}",
    "grep -r ERROR /var/log/nginx {r}", "grep -r . {r} 2>/dev/null",
    "grep -r . {r} | head -n 5",
    "grep --recursive foo {r}", "grep --rec foo {r}", "grep --dereference-recursive foo {r}",
    "grep -d recurse foo {r}", "grep -drecurse foo {r}", "grep -d rec foo {r}",
    "grep --directories=recurse foo {r}", "grep --directories recurse foo {r}",
    "grep --regexp=foo -r {r} /var/log", "grep -f /var/log/pats -r {r}",
    "egrep -r foo {r}", "fgrep -r foo {r}", "rgrep foo {r}", "zgrep -r foo {r}",
    "zegrep -r foo {r}", "rg foo {r}", "ag foo {r}", "ack foo {r}",
    "/bin/grep -r foo {r}", "sudo grep -r . {r}", "sudo -u root grep -r . {r}",
    "timeout 5 grep -r . {r}", "nice -n 5 grep -r . {r}", "env grep -r . {r}",
    "GREP_OPTIONS=-r grep . {r}", "env GREP_OPTIONS=-r grep . {r}",
    "export GREP_OPTIONS=-r; grep . {r}",
    "sh -c 'grep -r . {r}'", "bash -c 'grep -R . {r}'", "ssh h 'grep -r . {r}'",
    "docker exec c grep -r . {r}",
    "diff -r {r} /var/log/x", "diff -ru /var/log/x {r}", "diff --recursive /var/log/x {r}",
    "diff -rN {r} /var/log/x", "diff -N {r} /var/log/x", "diff --new-file {r} /var/log/x",
    "diff {r} /var/log/x", "diff -q /var/log/x {r}", "diff --to-file={r} /var/log/x",
    "find {r} -type f -exec cat '{{}}' +", "find {r} -exec grep -H . '{{}}' ';'",
    "find -L {r} -execdir strings '{{}}' ';'", "find {r} -ok head '{{}}' ';'",
    "find {r} -okdir tail -n 50 '{{}}' ';'",
)

BROAD = ("/", "/etc", "/var", "/var/lib", "/root", "/home", "/opt", "/srv", "/run",
         "/usr/local/etc", "/usr/local", "/usr", "/proc", "/sys", "/tmp",
         "/var/lib/docker", "/etc/ssl")

# Spellings of a broad root (or of a root the door cannot resolve).
EVASIONS = ("//etc", "/etc/", "/./etc", "/etc/.", "'/etc'", '"/e"tc', "/e\\tc",
            "///", "/var//lib/", "/usr/local/./etc", "/var/log/../../etc",
            "/var/log/..", "/var/log/nginx/../../../root",
            "/proc/self/root", "/proc/1/root/var/log", "/proc/self/cwd",
            "/proc/thread-self/root/etc", ".", "./", "etc", "var/lib", "~", "~root",
            "../../etc")

# Unknown roots, whatever the spelling: the door does not know the remote cwd.
UNKNOWN = (
    "grep -r foo", "grep -r -e foo", "grep -R foo", "rgrep foo", "rg foo",
    "cd /etc && grep -r foo .", "cd /var/log && grep -r ERROR nginx",
    "cd /etc; grep -r foo", "bash -c 'cd /etc; grep -r x .'",
    "find -exec cat '{}' +", "find . -exec cat '{}' +",
    "find /var/log -files0-from /var/log/list -print",
    "find /etc -type f | xargs cat", "find /var/log -type f | xargs -n 1 cat",
    "xargs -a /var/log/list cat", "xargs -0 -I X head X",
    "find /etc -print0 | xargs -0 grep -H .",
)

# Recursive reads that stay reads: rooted in a log tree.
NARROW_READS = (
    "grep -r ERROR /var/log/nginx", "grep -rn timeout /var/log",
    "grep -ri 'upstream timed out' /var/log/nginx/",
    "grep -r ERROR /var/log/nginx 2>/dev/null | tail -n 5",
    "grep -rc 502 /var/log/nginx /var/log/apache2",
    "diff -r /var/log/a /var/log/b", "zgrep -r x /var/log/nginx",
    "grep -r -e foo -e bar /var/log/syslog.d",
)

# Unchanged neighbours: not tree content reads at all.
NOT_TREE_READS = (
    "grep -c foo /etc/hosts", "grep foo /etc/nginx/nginx.conf",
    "grep -cxE 'shop-postgres|shop-redis' /var/log/x", "grep xargs /var/log/syslog",
    "grep -c find /var/log/x", "ls -R /etc", "ls -la /opt", "du -sh /var/lib",
    "find /etc -name '*.conf' -print", "find / -xdev -name x -ls",
    "diff -u /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak",
    "lsattr -R /etc/nginx", "getfacl -R /opt/app",
    "docker ps --format {{.Names}} | grep -cx shop-redis",
    "echo 'grep -r . /etc'", "journalctl -u nginx -n 20 --no-pager",
)

# Recursive reads of a narrow tree that is not a log tree: never a read.
DEMOTED = (
    "grep -r foo /opt/app/src", "grep -r server_name /etc/nginx",
    "grep -rn DATABASE_URL /opt/acme-api", "diff -r /etc/nginx /etc/nginx.bak",
    "diff -N /etc/nginx/a.conf /etc/nginx/b.conf",
    "grep -r ERROR /var/log/nginx /home/op/src",
)


def _all_broad():
    return [f.format(r=r) for f in FORMS for r in BROAD]


class TreeReadClassifierTest(unittest.TestCase):

    def test_every_form_times_every_broad_root_is_refused(self):
        for cmd in _all_broad():
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, tv.DENY)

    def test_normalisation_evasions_are_refused(self):
        for root in EVASIONS:
            for form in ("grep -r -a . {r}", "grep -R . {r}", "diff -r {r} /var/log/x",
                         "find {r} -exec cat '{{}}' +", "diff {r} /var/log/x"):
                cmd = form.format(r=root)
                with self.assertRaises(Refused, msg=cmd):
                    vpsexec.classify(cmd, tv.DENY)

    def test_unknown_roots_are_refused(self):
        for cmd in UNKNOWN:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, tv.DENY)

    def test_refusal_says_why_and_what_to_do(self):
        with self.assertRaises(Refused) as cm:
            vpsexec.classify("grep -r -a . /etc", tv.DENY)
        msg = str(cm.exception)
        self.assertIn("/etc", msg)
        self.assertIn("deny_extra matches command text", msg)
        self.assertIn("Name the exact files", msg)
        self.assertIn("/var/log", msg)
        self.assertIn("Nothing lifts this", msg)
        with self.assertRaises(Refused) as cm:
            vpsexec.classify("cd /etc && grep -r foo .", tv.DENY)
        self.assertIn("working directory", str(cm.exception))
        with self.assertRaises(Refused) as cm:
            vpsexec.classify("find /etc -type f | xargs cat", tv.DENY)
        self.assertIn("stdin", str(cm.exception))

    def test_ancestor_of_or_inside_an_absolute_deny_path_is_refused(self):
        deny = tv.DENY + ["/data/app/secrets", "/var/log/vault-audit"]
        for cmd in ("grep -r . /data", "grep -r . /data/app", "grep -r . /data/app/",
                    "grep -r . /data//app/secrets/x",     # dodges the substring
                    "grep -r . /data/./app/secrets",
                    "grep -r x /var/log", "grep -r x /var/log/"):
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)
        # A sibling of the denied log tree is still a read.
        self.assertEqual(vpsexec.classify("grep -r x /var/log/nginx", deny)[0], "read")

    def test_a_relative_deny_pattern_in_a_normalised_root_is_refused(self):
        deny = tv.DENY + ["hsmd/"]
        for cmd in ("grep -r . /var/log/hsmd/", "grep -r . /var/log//hsmd/x"):
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_narrow_log_tree_reads_are_still_reads(self):
        for cmd in NARROW_READS:
            self.assertEqual(vpsexec.classify(cmd, tv.DENY), ("read", None), cmd)

    def test_neighbours_that_are_not_tree_reads_are_unchanged(self):
        for cmd in NOT_TREE_READS:
            self.assertEqual(vpsexec.classify(cmd, tv.DENY)[0], "read", cmd)
        for cmd in ("git diff --stat", "kubectl diff -f x.yaml", "echo a | xargs",
                    "docker ps -q | xargs -r -P 8 docker restart -t 30",
                    "find /var/tmp -mtime +3 | xargs rm",
                    "find /var -name '*.tmp' -exec rm '{}' +",
                    "find /var/log/nginx -exec cat '{}' +"):
            self.assertIn(vpsexec.classify(cmd, tv.DENY)[0], ("mutating", "risky"), cmd)

    def test_narrow_trees_outside_the_log_trees_are_never_reads(self):
        for cmd in DEMOTED:
            tier, detail = vpsexec.classify(cmd, tv.DENY)
            self.assertEqual(tier, "mutating", cmd)
            self.assertIn("is not a read", detail, cmd)
            self.assertIn("/var/log", detail, cmd)

    def test_the_gate_only_ever_tightens(self):
        """Against the classifier with the gate removed: nothing that was refused
        is now allowed, and nothing that is now a read was not a read before."""
        corpus = (_all_broad() + list(UNKNOWN) + list(NARROW_READS) +
                  list(NOT_TREE_READS) + list(DEMOTED) +
                  [f.format(r=r) for f in FORMS[:6] for r in EVASIONS])

        def verdict(cmd):
            try:
                return vpsexec.classify(cmd, tv.DENY)[0]
            except Refused:
                return "refused"

        before = {}
        with mock.patch.object(vpsexec, "tree_reads", return_value=None):
            for cmd in corpus:
                before[cmd] = verdict(cmd)
        for cmd in corpus:
            now = verdict(cmd)
            if before[cmd] == "refused":
                self.assertEqual(now, "refused", cmd)
            if now == "read":
                self.assertEqual(before[cmd], "read", cmd)
        # ...and it is load-bearing: these were reads before the gate.
        for cmd in ("grep -r -a . /etc", "grep -R . /var/lib", "grep -ra secret /opt",
                    "grep -r -a . /", "diff -rN /root /var/log/x"):
            self.assertEqual(before[cmd], "read", cmd)
            self.assertEqual(verdict(cmd), "refused", cmd)


class TreeReadEveryTierTest(tv._Harness):
    """Refused before any tier, posture, runbook or approval is consulted."""

    GROUPS = {"web": ["web1", "web3"]}
    SAMPLE = ("grep -r -a . /etc", "grep -R . /var/lib", "grep -ra secret /opt",
              "grep -r . /", "rgrep x /root", "diff -rN /home /var/log/x",
              "find /etc -type f -exec cat '{}' +", "grep -r . //etc/",
              "cd /etc && grep -r foo .", "grep -r foo /proc/self/root")

    def _dispatch(self, argv, runbooks=(), prompt=None):
        return vpsexec.dispatch(
            argv, guard=tv._guard(), prober=self.prober(),
            policy=tv._yaml_policy(groups=self.GROUPS, runbooks=list(runbooks)),
            ssh=self.fake_ssh(),
            stream=tv.ApprovalTest._TTY() if prompt else tv.ApprovalTest._NoTTY(),
            prompt=prompt, today="2026-08-27",
            blackout_runner=self.blackout_runner(unavailable=True))

    def test_refused_as_a_plain_read_on_every_host_posture(self):
        for cmd in _all_broad()[::7] + list(self.SAMPLE):
            for spec in ("edge1", "web3", "web1", "edge1,web3,web1"):
                self.ssh_calls = []
                with self.assertRaises(Refused, msg=(spec, cmd)):
                    self._dispatch([spec, cmd])
                self.assertEqual(self.ssh_calls, [], (spec, cmd))

    def test_refused_with_run_and_approval_on_a_test_host(self):
        control = "grep -r foo /opt/app/src"    # demoted, so it runs approved
        self.assertEqual(self._dispatch(["edge1", control, "--run", "--reason", "x"],
                                        prompt=lambda m: "edge1"), 0)
        self.assertIn(control, self.cmds("edge1"), "control must reach the host")
        for cmd in self.SAMPLE:
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd):
                self._dispatch(["edge1", cmd, "--run", "--reason", "x"],
                               prompt=lambda m: "edge1")
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_refused_inside_a_container(self):
        for cmd in self.SAMPLE:
            for flags in (["--in", "blog-web"], ["--in", "blog-web", "--run",
                                                  "--reason", "x"]):
                self.ssh_calls = []
                with self.assertRaises(Refused, msg=(cmd, flags)):
                    self._dispatch(["edge1", cmd] + flags, prompt=lambda m: "edge1")
                self.assertEqual(self.ssh_calls, [], cmd)

    def test_break_glass_with_a_committed_runbook_still_refuses(self):
        control = "systemctl restart nginx"
        self.assertEqual(self._dispatch(
            ["@web", control, "--break-glass", "--run", "--reason", "OPS-1"],
            runbooks=[tv._runbook(["web1", "web3"], control, break_glass=True)],
            prompt=lambda m: "BREAK-GLASS:2"), 0, "control run must reach the hosts")
        for cmd in self.SAMPLE:
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd) as cm:
                self._dispatch(["@web", cmd, "--break-glass", "--run", "--reason", "OPS-1"],
                               runbooks=[tv._runbook(["web1", "web3"], cmd,
                                                     break_glass=True)],
                               prompt=lambda m: "BREAK-GLASS:2")
            self.assertNotIn("not authorised", str(cm.exception), cmd)
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_a_check_or_a_verify_cannot_carry_one(self):
        import contextlib
        import io
        for cmd in ("grep -r -a . /etc", "grep -r foo /opt/app/src"):
            pol = tv._yaml_policy(groups=self.GROUPS)
            pol["checks"] = {"bad": tv._check(cmd)}
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd), \
                    contextlib.redirect_stdout(io.StringIO()):
                vpsexec.dispatch(["check", "bad"], guard=tv._guard(), policy=pol,
                                 prober=self.prober(), ssh=self.fake_ssh(),
                                 stream=tv.ApprovalTest._NoTTY(),
                                 blackout_runner=self.blackout_runner(unavailable=True))
            self.assertEqual(self.ssh_calls, [], cmd)
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd):
                self._dispatch(["edge1", "systemctl restart nginx", "--verify", cmd,
                                "--run", "--reason", "x"], prompt=lambda m: "edge1")
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_an_override_naming_one_is_rejected_as_tampered(self):
        for cmd in ("grep -r -a . /etc", "find /etc -type f -exec cat '{}' +",
                    "cd /etc && grep -r foo ."):
            body = ("version: 1\nexpires: \"2999-01-01\"\nreason: \"please\"\nallow:\n"
                    "  - hosts: [edge1]\n    cmd: \"%s\"\n    where: host\n"
                    "    why: \"i need it\"\n" % cmd)
            with self.assertRaises(Refused, msg=cmd) as cm:
                vpsexec.load_override(tv._write(body), tv.DENY, today="2026-08-27")
            self.assertIn("tampered", str(cm.exception), cmd)

    def test_narrow_log_reads_still_run_unapproved(self):
        for cmd in ("grep -r ERROR /var/log/nginx", "diff -r /var/log/a /var/log/b"):
            self.ssh_calls = []
            self.assertEqual(self._dispatch(["edge1,web3,web1", cmd]), 0, cmd)
            self.assertEqual(sorted(h for h, _ in self.ssh_calls),
                             ["edge1", "web1", "web3"], cmd)
            self.assertEqual(set(self.cmds()), {cmd})


class TreeReadVerdictUnitTest(unittest.TestCase):
    """The pure function, for the forms that never reach it through classify."""

    def test_value_options_do_not_hide_a_root(self):
        v = readpolicy.tree_read_verdict
        for argv in (["grep", "-r", "-m", "1", "x", "/etc"],
                     ["grep", "-rA", "3", "x", "/etc"],
                     ["grep", "-r", "--include", "x.conf", "x", "/etc"],
                     ["grep", "-r", "--max-count=1", "x", "/etc"],
                     ["diff", "-r", "-x", "pat", "/var/log/a", "/etc"],
                     ["xargs", "-n", "1", "-P", "4", "strings"]):
            self.assertEqual(v(argv, [])[0], "refuse", argv)

    def test_skip_and_read_directory_actions_are_not_recursive(self):
        for argv in (["grep", "-d", "skip", "x", "/etc"],
                     ["grep", "--directories=read", "x", "/etc"]):
            self.assertIsNone(readpolicy.tree_read_verdict(argv, []), argv)


if __name__ == "__main__":
    unittest.main()
