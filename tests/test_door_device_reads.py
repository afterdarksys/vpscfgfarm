"""Raw devices, process memory, credential files and the tree-read gaps found
by a security review of vpsexec's tree reads.

Until this change `cat /dev/vda`, `strings -n 8 /dev/vda1` and
`cat /proc/1/environ` were READS (no --run, no approval, fine on a frozen
host): a raw block device is every file on the disk, and the masker does not
see `grep -o` output. readpolicy.path_read_verdict:

  refused on every tier  a content read of /dev/* (but /dev/null and the
                         unbounded streams), /proc/kcore, /proc/<pid>/{environ,
                         mem,pagemap,fd,map_files}, a `..` path, an ssh host
                         private key (any command), *.key / .env files
  never a read           /dev/zero|full|random|urandom, /proc/<pid>/root|cwd,
                         /proc/kmsg, /sys
  unchanged              /dev/null, /proc/loadavg, /proc/<pid>/status|cmdline,
                         `ls /dev`, `stat /dev/sda`, `*.pub`

plus the credential paths added to policies/secrets.yaml, the plain-diff
demotion and the wrappers, keywords and tools that now reach the tree-read
refusal. Every input string from the review is pinned verbatim.

Hermetic: ssh is faked by the test_vpsexec harness; nothing dials a host.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_vpsexec as tv  # noqa: E402
from vpscfg import readpolicy, vpsexec, vpsexecpolicy  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

# --- finding 1 [HIGH]: raw device / kernel and process memory reads --------
REVIEW_DEVICE = (
    "grep -a -o -E '[A-Za-z0-9]{40}' /dev/sda",
    "strings -n 8 /dev/vda1",
    "cat /dev/vda",
    "head -c 99999999999 /dev/sda1",
    "zcat -f /dev/sda",
    "cat /dev/mem",
    "tail -n+1 /proc/kcore",
    "cat /proc/1/environ",
    "grep -a -o -m 50 -E 'hunter[0-9]+' /proc/1/environ",
    "cat /proc/self/root/etc/shadow",
)
# Spellings and shapes beyond the review's list, all refused.
DEVICE_EVASIONS = (
    "cat //dev//sda", "cat /dev/./sda", "cat /dev/sda/", "cat '/dev/sda'",
    'cat "/de"v/sda', "cat /de\\v/sda", "cat /var/log/../../dev/sda",
    "cat /var/run/../proc/kcore", "cat ../../dev/sda", "cat dev/sda",
    "cat proc/1/environ", "cat /dev/disk/by-id/ata-X", "cat /dev/mapper/vg-root",
    "cat /dev/kmem", "cat /dev/port", "cat /dev/stdin", "cat /dev/fd/3",
    "cat /dev/shm/x", "cat < /dev/sda", "cat </dev/sda", "cat 0</dev/sda",
    "base64 < /proc/1/environ", "sort < /proc/self/environ",
    "cat /proc/1/task/1/environ", "cat /proc/self/mem", "cat /proc/1/pagemap",
    "cat /proc/self/fd/0", "cat /proc/1/map_files/55d0-55d1",
    "cat /proc/1/root/dev/sda", "cat /proc/1/cwd/proc/kcore",
    "cat /proc/thread-self/environ", "od -An -tx1 /dev/sda", "xxd /dev/sda",
    "hexdump -C /dev/nvme0n1", "base64 /dev/vda", "tac /dev/sda",
    "cut -c1-100 /dev/sda", "sort /proc/1/environ", "cmp -l /dev/sda /dev/sdb",
    "diff /dev/sda /dev/sdb", "jq . /proc/1/environ", "xargs -a /proc/1/environ echo",
    "grep -f /proc/1/environ /var/log/syslog", "grep --file=/proc/1/environ x /var/log/x",
    "grep -f/proc/1/environ x /var/log/x", "zgrep x /dev/sda", "rg x /dev/sda",
    "sudo cat /dev/sda", "timeout 5 head -c 9 /dev/sda", "sh -c 'cat /dev/sda'",
    "ssh h 'strings /dev/vda1'", "cat /etc/hostname /dev/sda",
    "cat /dev/sda 2>/dev/null", "cat /dev/sda | head -c 99",
    "dd if=/dev/sda bs=1M count=1", "dd bs=1M < /dev/sda",
)
# Not reads (mutating: --run and an approval), not refused.
DEVICE_DEMOTED = (
    "head -c 16 /dev/urandom", "head -c 16 /dev/random", "head -c 1 /dev/zero",
    "cat /sys/class/net/eth0/operstate", "cat /sys/firmware/acpi/tables/DSDT",
    "cat /proc/1/root/etc/nginx/nginx.conf", "cat /proc/self/cwd/app.log",
    "cat /proc/kmsg", "wc -c /dev/sda", "md5sum /dev/sda", "sha256sum /proc/1/environ",
)

# --- finding 2 [MEDIUM]: credential files --------------------------------
REVIEW_CREDENTIALS = (
    "cat /etc/hsmd/pin",
    "cat /root/.vault-token",
    "cat /etc/ssh/ssh_host_ed25519_key",
    "cat /var/lib/rancher/k3s/server/token",
    "cat /var/lib/rancher/k3s/server/tls/client-admin.key",
    "cat /var/lib/rancher/k3s/server/cred/passwd",
    "cat /etc/postfix/sasl_passwd",
    "cat /root/.my.cnf",
    "cat /root/.bash_history",
    "cat /etc/shadow",
    "cat /opt/app/.env",
    "head -n 100 /etc/shadow /etc/gshadow /etc/hsmd/pin /root/.vault-token",
    # the two the masker misses
    "tail -n +2 /etc/ssh/ssh_host_ed25519_key",
    "cut -d= -f2 /opt/app/.env",
)
CREDENTIAL_MORE = (
    "cat /etc/gshadow", "cat /etc/shadow-", "cat /etc//shadow", "cat /etc/./shadow",
    "cat /etc/postfix/sasl_passwd.db", "cat /etc/mysql/debian.cnf",
    "cat /root/.zsh_history", "cat /root/.psql_history", "cat /root/.mysql_history",
    "cat /root/.rediscli_history", "cat /root/.python_history",
    "cat /var/lib/rancher/k3s/server/node-token",
    "cat /var/lib/rancher/k3s//server/token",          # dodges the substring
    "cat /var/lib/rancher/k3s/server/./tls/x.crt",
    "cat /var/lib/rancher/k3s/server/db/state.db",
    "cat /var/lib/rancher/k3s/server/cred/node-passwd",
    "cat /var/lib/rancher/k3s/server/cred/ipsec.psk",
    "cat /etc/ssh/ssh_host_rsa_key", "cat /etc/ssh//ssh_host_ecdsa_key",
    "cat /etc/ssl/private/site.key", "head -c 99 /opt/app/tls/server2.KEY",
    "base64 /opt/app/client.key", "cat /opt/app/.env.example", "cat /opt/app/.env.bak",
    "cat /opt/registry/idp.env", "grep PASSWORD /opt/app/.env",
    "grep -c x /srv/x/prod.env", "jq . /opt/app/.env", "sort /opt/app/.env",
    "diff /opt/app/.env /opt/app/.env.bak", "sudo cat /opt/app/.env",
    "base64 < /opt/app/.env", "sh -c 'cat /opt/app/.env'",
)

# --- finding 3 [LOW]: plain diff of what may be directories ---------------
REVIEW_DIFF = ("diff /opt/app /opt/app.bak", "diff /etc/postfix /etc/postfix.orig")
DIFF_DEMOTED = ("diff /etc/nginx/conf.d /etc/nginx/conf.d.bak",
                "diff -q /opt/app/src /opt/app/src.old",
                "diff /etc/nginx/nginx.conf /etc/nginx/",
                "diff /var/log/x.log /opt/app")

# --- finding 4 [LOW]: wrappers, keywords and tools ------------------------
REVIEW_REFUSE_NOT_APPROVE = (
    "toybox grep -r . /etc",
    "unshare grep -r . /etc", "unshare -r grep -r . /etc",
    "systemd-run --pipe grep -r . /etc",
    "setpriv grep -r . /etc", "setpriv --reuid=0 grep -r . /etc",
    "prlimit grep -r . /etc", "prlimit --nofile=9 grep -r . /etc",
    "strace -o /dev/null grep -r . /etc",
    "numactl -N0 grep -r . /etc",
    "ltrace grep -r . /etc", "cgexec -g cpu:x grep -r . /etc", "firejail grep -r . /etc",
    "then grep -r . /etc", "! grep -r . /etc", "if true; then grep -r . /etc; fi",
    "do grep -r . /etc", "else grep -r . /etc", "elif grep -r . /etc",
    "while grep -r . /etc; do true; done", "until grep -r . /etc; do true; done",
    "time grep -r . /etc",
    "find /etc | parallel cat", "find /etc -type f | parallel cat",
    "find /etc -type f | parallel -j 4 cat", "parallel cat ::: /etc/hosts",
    "bzgrep -r x /etc", "xzgrep -r x /etc", "lzgrep -r x /etc", "zstdgrep -r x /etc",
    "pcregrep -r x /etc", "pcre2grep -r x /etc", "ugrep -r x /etc", "ug -r x /etc",
    "sift x /etc", "pt x /etc", "rg x /etc", "ag x /etc",
    "git grep --no-index x /etc", "git grep --no-index x", "git -C /etc grep --no-index x",
    "tar -cO /etc", "tar cf - /etc", "tar c /etc", "tar -c /etc", "tar czf - /etc",
    "tar --create --file=- /etc", "tar -cf /dev/stdout /etc", "tar -C / -c etc",
    "tar -cT /var/log/list",
)

# --- what must stay a read --------------------------------------------------
STILL_READS = (
    "grep -r ERROR /var/log/nginx", "cat /etc/nginx/nginx.conf", "cat /dev/null",
    "echo x > /dev/null", "ls /dev", "ls /proc", "cat /proc/loadavg",
    "cat /proc/meminfo", "cat /proc/1/status", "cat /proc/1/cmdline", "df", "docker ps",
    "diff /var/log/a.log /var/log/b.log", "cat /etc/ssh/ssh_host_ed25519_key.pub",
    "ls /var/lib/rancher/k3s/server",
    # neighbours
    "cat /etc/hosts 2>/dev/null", "ls -la /opt 2>/dev/null", "ls -la /dev/disk/by-id",
    "ls /proc/1/fd", "stat /dev/sda", "stat -c %a /etc/ssh/ssh_host_ed25519_key.pub",
    "smartctl -H /dev/sda", "lsblk /dev/sda", "df -h /dev/sda1", "file /dev/sda",
    "mdadm --detail /dev/md0", "findmnt /dev/sda1", "grep /dev/sda1 /var/log/syslog",
    "grep ssh_host_ed25519_key /var/log/auth.log", "dmesg | grep -i /dev/sda",
    "journalctl -u sshd -n 50 --no-pager", "cat /proc/sys/net/ipv4/ip_forward",
    "cat /proc/1/limits", "head -n 5 /proc/net/dev",
    "diff -u /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak",
    "diff /etc/docker/daemon.json /opt/x/daemon.json",
    "jq -r '.[] | .key' /var/log/x.json", "jq -r .data.key /var/log/x.json",
    "stat -c '%a %U:%G' /opt/app/.env | grep -qx '600 root:root'",
    "cat /etc/mysql/my.cnf", "cat /etc/passwd", "cat /etc/environment",
    "curl -qsS -o /dev/null http://127.0.0.1/health",
)


def _verdict(cmd, deny=None):
    try:
        return vpsexec.classify(cmd, tv.DENY if deny is None else deny)[0]
    except Refused:
        return "refused"


def _shipped_deny():
    """The floor plus the credential-path deny list an estate ships
    (tv.SECRETS_POLICY; tests/estate/ pins it equal to the shipped one)."""
    pol = vpsexecpolicy.load(tv.SECRETS_POLICY, deny_patterns=tv.DENY)
    return tv.DENY + pol["deny_extra"]


class DeviceReadTest(unittest.TestCase):

    def test_review_inputs_are_refused(self):
        for cmd in REVIEW_DEVICE:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, _shipped_deny())

    def test_review_inputs_are_refused_without_secrets_yaml(self):
        # Not by luck of a deny pattern: the floor alone refuses them, except
        # /proc/self/root/etc/shadow, which is another namespace's tree (demoted;
        # its /shadow is deny_extra's).
        for cmd in REVIEW_DEVICE:
            want = ("mutating",) if "/root/" in cmd else ("refused",)
            self.assertIn(_verdict(cmd), want, cmd)

    def test_spellings_shapes_and_wrappers_are_refused(self):
        for cmd in DEVICE_EVASIONS:
            self.assertEqual(_verdict(cmd), "refused", cmd)

    def test_streams_sys_and_namespace_aliases_are_not_reads(self):
        for cmd in DEVICE_DEMOTED:
            self.assertEqual(_verdict(cmd), "mutating", cmd)

    def test_refusal_says_why(self):
        with self.assertRaises(Refused) as cm:
            vpsexec.classify("strings -n 8 /dev/vda1", tv.DENY)
        msg = str(cm.exception)
        self.assertIn("/dev/vda1", msg)
        self.assertIn("whole disk", msg)
        self.assertIn("Nothing lifts this", msg)
        with self.assertRaises(Refused) as cm:
            vpsexec.classify("cat /var/run/../proc/kcore", tv.DENY)
        self.assertIn("symlinked parent", str(cm.exception))

    def test_legitimate_reads_stay_reads(self):
        deny = _shipped_deny()
        for cmd in STILL_READS:
            self.assertEqual(vpsexec.classify(cmd, deny), ("read", None), cmd)


class CredentialFileTest(unittest.TestCase):

    def test_review_inputs_are_refused(self):
        deny = _shipped_deny()
        for cmd in REVIEW_CREDENTIALS:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_more_shapes_are_refused(self):
        deny = _shipped_deny()
        for cmd in CREDENTIAL_MORE:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_name_rules_need_no_deny_list(self):
        for cmd in ("cat /etc/ssh/ssh_host_ed25519_key", "cat /opt/app/.env",
                    "cat /etc/ssl/private/site.key", "cut -d= -f2 /opt/app/.env"):
            self.assertEqual(_verdict(cmd), "refused", cmd)

    def test_metadata_on_a_credential_file_keeps_its_tier(self):
        # policies/secret-perms.yaml chmods and stats .env files; that must
        # keep working (chmod is an approved mutation, stat a read).
        deny = _shipped_deny()
        self.assertEqual(_verdict("chmod 0600 /opt/acme-login/.env", deny), "mutating")
        self.assertEqual(_verdict("stat -c '%a %U:%G' /opt/x/.env", deny), "read")
        self.assertEqual(_verdict("ls -l /etc/ssl/private/site.key", deny), "read")
        # F7 (second review): host-key FILENAMES bind content readers only, as
        # on main: listing, stat and find -name are reads, chmod/cp approvals.
        for cmd in ("ls -l /etc/ssh/ssh_host_rsa_key", "stat /etc/ssh/ssh_host_rsa_key",
                    "find /etc/ssh -name ssh_host_rsa_key"):
            self.assertEqual(_verdict(cmd, deny), "read", cmd)
        for cmd in ("chmod 644 /etc/ssh/ssh_host_ed25519_key",
                    "cp /etc/ssh/ssh_host_rsa_key /tmp/k"):
            self.assertEqual(_verdict(cmd, deny), "mutating", cmd)


class PlainDiffTest(unittest.TestCase):

    def test_review_inputs_need_an_approval(self):
        for cmd in REVIEW_DIFF + DIFF_DEMOTED:
            tier, detail = vpsexec.classify(cmd, tv.DENY)
            self.assertEqual(tier, "mutating", cmd)
            self.assertIn("cannot stat", detail, cmd)

    def test_files_and_log_trees_stay_reads(self):
        for cmd in ("diff /var/log/a.log /var/log/b.log", "diff /var/log/a /var/log/b",
                    "diff -u /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak",
                    "diff /etc/docker/daemon.json /opt/x/daemon.json"):
            self.assertEqual(vpsexec.classify(cmd, tv.DENY)[0], "read", cmd)


class WrapperKeywordToolTest(unittest.TestCase):

    def test_review_forms_are_refused_not_merely_mutating(self):
        for cmd in REVIEW_REFUSE_NOT_APPROVE:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, tv.DENY)

    def test_narrow_neighbours_are_not_refused(self):
        for cmd in ("tar czf /var/backups/etc.tgz /etc/nginx",
                    "tar --extract --gzip --file=/var/tmp/x.tgz --directory=/opt/app",
                    "tar cf - /var/log/nginx", "git grep x", "bzgrep x /var/log/x.bz2",
                    "strace -o /dev/null grep -r x /var/log/nginx",
                    "docker ps -q | parallel docker restart"):
            self.assertIn(_verdict(cmd), ("read", "mutating", "risky"), cmd)
        self.assertEqual(_verdict("tar cf - /opt/app"), "mutating")


class EveryTierTest(tv._Harness):
    """Refused before any tier, posture, runbook or approval is consulted."""

    SAMPLE = ("cat /dev/vda", "cat /proc/1/environ", "tail -n+1 /proc/kcore",
              "cat /etc/ssh/ssh_host_ed25519_key", "cut -d= -f2 /opt/app/.env",
              "tar cf - /etc", "strace -o /dev/null grep -r . /etc")

    def _dispatch(self, argv, runbooks=(), prompt=None):
        return vpsexec.dispatch(
            argv, guard=tv._guard(), prober=self.prober(),
            policy=tv._yaml_policy(groups={"web": ["web1", "web3"]},
                                   runbooks=list(runbooks)),
            ssh=self.fake_ssh(),
            stream=tv.ApprovalTest._TTY() if prompt else tv.ApprovalTest._NoTTY(),
            prompt=prompt, today="2026-08-27",
            blackout_runner=self.blackout_runner(unavailable=True))

    def test_refused_with_run_and_approval(self):
        control = "head -c 16 /dev/urandom"     # demoted, so it runs approved
        self.assertEqual(self._dispatch(["edge1", control, "--run", "--reason", "x"],
                                        prompt=lambda m: "edge1"), 0)
        self.assertIn(control, self.cmds("edge1"))
        for cmd in self.SAMPLE:
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd):
                self._dispatch(["edge1", cmd, "--run", "--reason", "x"],
                               prompt=lambda m: "edge1")
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_refused_inside_a_container(self):
        for cmd in self.SAMPLE + ("cat proc/1/environ",):
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd):
                self._dispatch(["edge1", cmd, "--in", "blog-web", "--run", "--reason",
                                "x"], prompt=lambda m: "edge1")
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_break_glass_with_a_committed_runbook_still_refuses(self):
        for cmd in self.SAMPLE:
            self.ssh_calls = []
            with self.assertRaises(Refused, msg=cmd) as cm:
                self._dispatch(["@web", cmd, "--break-glass", "--run", "--reason", "I"],
                               runbooks=[tv._runbook(["web1", "web3"], cmd,
                                                     break_glass=True)],
                               prompt=lambda m: "BREAK-GLASS:2")
            self.assertNotIn("not authorised", str(cm.exception), cmd)
            self.assertEqual(self.ssh_calls, [], cmd)

    def test_an_override_naming_one_is_rejected_as_tampered(self):
        for cmd in self.SAMPLE:
            body = ("version: 1\nexpires: \"2999-01-01\"\nreason: \"please\"\nallow:\n"
                    "  - hosts: [edge1]\n    cmd: \"%s\"\n    where: host\n"
                    "    why: \"i need it\"\n" % cmd)
            with self.assertRaises(Refused, msg=cmd) as cm:
                vpsexec.load_override(tv._write(body), tv.DENY, today="2026-08-27")
            self.assertIn("tampered", str(cm.exception), cmd)


class OnlyTightensTest(unittest.TestCase):

    def test_the_new_rules_only_ever_tighten(self):
        """Against the classifier with the path rules removed: nothing refused
        is now allowed, nothing now a read was not a read before."""
        corpus = (REVIEW_DEVICE + DEVICE_EVASIONS + DEVICE_DEMOTED + REVIEW_CREDENTIALS
                  + CREDENTIAL_MORE + REVIEW_DIFF + DIFF_DEMOTED + STILL_READS
                  + R2_REFUSED + R2_NOT_READS + R2_READS
                  + R3_REFUSED + R3_NOT_READS + R3_READS
                  + R4_REFUSED + R4_NOT_READS + R4_READS + R5_REFUSED + R5_READS
                  + R6_REFUSED + R6_NOT_READS)
        with mock.patch.object(readpolicy, "path_read_verdict", return_value=None), \
                mock.patch.object(readpolicy, "_path_class", return_value=None), \
                mock.patch.object(readpolicy, "_credential_file", return_value=None):
            before = dict((c, _verdict(c)) for c in corpus)
        for cmd in corpus:
            now = _verdict(cmd)
            if before[cmd] == "refused":
                self.assertEqual(now, "refused", cmd)
            if now == "read":
                self.assertEqual(before[cmd], "read", cmd)
        # ...and load-bearing: these were reads before.
        for cmd in ("cat /dev/vda", "strings -n 8 /dev/vda1", "cat /proc/1/environ",
                    "cat /opt/app/.env", "cat /etc/ssh/ssh_host_ed25519_key"):
            self.assertEqual(before[cmd], "read", cmd)
            self.assertEqual(_verdict(cmd), "refused", cmd)


# --- second review of ce3ded1 (F1-F6), every repro verbatim ---------------
R2_REFUSED = (
    # F1: ps BSD `e` prints every process's environment
    "ps axe", "ps eww", "ps -p 1 e", "ps axeww | tr ' ' '\\n' | cut -d= -f2",
    "ps eww -p 1 | grep -o '=[^ ]*'", "ps -o pid,environ", "ps --format=pid,env",
    "ps --format pid,env", "ps ef", "sudo ps axe",
    # F2: file options of kubectl and friends
    "kubectl get -f /dev/sda", "kubectl get -f /proc/kcore",
    "kubectl get -f /proc/1/environ", "k3s kubectl get -f /dev/sda",
    "kubectl get --filename=/dev/sda", "kubectl get --filename /dev/sda",
    "kubectl get -f/dev/sda", "helm template x --values /proc/1/environ",
    "docker run --env-file /opt/app/.env img",
    # F3: jq after `--`
    "jq -- '-1,.' /dev/sda", "jq -r -- '-1,.' /opt/app/x.key",
    # F5: name variants
    "cat /etc/ssh/ssh_host_rsa_key.bak", "cat /etc/ssh/ssh_host_ed25519_key.orig",
    "cat /opt/app/.env-prod", "cat /opt/app/.env_prod", "cat /opt/app/prod.env.bak",
    "cat /etc/ssl/private/tls.key.old", "cat /etc/ssl/private/.key",
    # F6: credential paths
    "cat /etc/rancher/k3s/config.yaml", "cat /etc/rancher/k3s/registries.yaml",
    "cat /var/lib/docker/containers/abc/config.v2.json", "cat /run/secrets/db_password",
    "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
    "cat /etc/wireguard/wg0.conf", "cat /opt/x/wg.private", "cat /root/.netrc",
    "cat /etc/security/opasswd", "cat /root/.config/rclone/rclone.conf",
    "cat /etc/vault.d/vault.hcl",
)
R2_NOT_READS = (
    "kubectl get -f /dev/zero", "jq -r -- '-1,.' /proc/1/root/opt/app/secrets.json",
    # F4: directory-looking diff operands
    "diff /etc/systemd/system/app.service.d /etc/systemd/system/app2.service.d",
    "diff /etc/apt/sources.list.d /etc/apt/sources.list.d.bak",
    "diff /etc/ld.so.conf.d /tmp/x.conf.d", "diff /etc/hosts /etc/hosts.bak",
    "chmod 0600 /etc/rancher/k3s/registries.yaml",
)
R2_READS = (
    "ps -ef", "ps aux", "ps auxww", "ps -eo pid,comm", "ps -p 1 -o pid,comm",
    "kubectl get pods -A", "k3s kubectl get pods -A", "docker logs --tail 200 app",
    "journalctl -u nginx -n 20 --no-pager", "systemctl status nginx",
    "diff -u /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak",
    "cat /etc/ssh/ssh_host_ed25519_key.pub", "cat /etc/ssh/ssh_host_ed25519_key-cert.pub",
    "jq -r '.[] | .key' /var/log/x.json", "cat /etc/environment",
    "stat -c '%a %U:%G' /etc/rancher/k3s/registries.yaml | grep -qx '600 root:root'",
)


class SecondReviewTest(unittest.TestCase):

    def test_repros_are_refused(self):
        deny = _shipped_deny()
        for cmd in R2_REFUSED:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_repros_that_need_an_approval(self):
        deny = _shipped_deny()
        for cmd in R2_NOT_READS:
            self.assertEqual(_verdict(cmd, deny), "mutating", cmd)

    def test_neighbours_stay_reads(self):
        deny = _shipped_deny()
        for cmd in R2_READS:
            self.assertEqual(vpsexec.classify(cmd, deny), ("read", None), cmd)


# --- third review of f4c5992 (G1-G3), every repro verbatim ----------------
R3_REFUSED = (
    # G1: procps reparses a failed UNIX argv as BSD, where `e` is environ
    "ps -aue", "ps -ue", "ps -u e", "ps -u axe", "ps --user=e", "ps -p e",
    # G2: leading-dot credential files, no slash
    "cat .key", "cat .tls.key", "cat .key.bak", "cat .private", "cat .dkim.private",
    "cat .ssh_host_rsa_key",
    # G3
    "cat /etc/ssh/ssh_host_rsa_key.bak.pub", "cat /etc/ssh/backup_ssh_host_rsa_key",
    "cat /opt/app/.envrc", "cat /etc/opendkim/keys/x/mail.private.bak",
)
R3_NOT_READS = ("ps -u nobody", "ps -C nginx", "ps -C nginx -o pid,comm",
                "ps --sort pid")
R3_READS = ("ps -u 1000", "ps -ef", "ps aux", "ps -eo pid,comm",
            "docker ps --format '{{.Names}}'",
            "jq .key f.json", "jq '.key' f.json", "jq -r '.[] | .key' f.json",
            "jq .data.key f.json", "jq -r -- .key f.json",
            "cat /etc/ssh/ssh_host_ed25519_key.pub",
            "cat /etc/ssh/ssh_host_ed25519_key-cert.pub", "cat /etc/environment")


class ThirdReviewTest(unittest.TestCase):

    def test_repros_are_refused(self):
        deny = _shipped_deny()
        for cmd in R3_REFUSED:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_ps_values_that_may_name_no_user_need_an_approval(self):
        deny = _shipped_deny()
        for cmd in R3_NOT_READS:
            tier, detail = vpsexec.classify(cmd, deny)
            self.assertEqual(tier, "mutating", cmd)
            if cmd.startswith(("ps -u", "ps -C")):
                self.assertIn("ps -u <uid>", detail, cmd)

    def test_neighbours_stay_reads(self):
        deny = _shipped_deny()
        for cmd in R3_READS:
            self.assertEqual(vpsexec.classify(cmd, deny), ("read", None), cmd)


# --- fourth review of eed2f01 (H1-H3), every repro verbatim ---------------
R4_REFUSED = (
    # H1: the WHOLE argv is reparsed as BSD when the UNIX parse fails
    "ps -eux", "ps -e -u x", "ps -ef -u ax", "ps -ef -ux", "ps -le -u wx",
    "ps -fe -u nobody", "ps -e -p x", "ps -ef -p ax", "ps -ef -C ax",
    "ps -e -o pid -u ax", "ps -eux | cat",
    # G1 values, now refused whatever their letters
    "ps -u postgres", "ps -C sendmail", "ps --user=postgres", "ps -C postgres -o pid,user",
    # H2: the jq program is the word before `--` when there is one
    "jq . -- /dev/sda", "jq -- . /dev/sda", "jq -r . -- /opt/app/x.key",
    # H3: a ps after a "parent" word is still procps
    "sudo -u docker ps axe", "doas -u docker ps axe", "runuser -u docker ps axe",
    "flock docker ps axe", "chroot docker ps axe", "strace -o docker ps axe",
    "sudo docker ps axe", "docker exec docker ps axe", "kubectl exec git ps axe",
)
R4_NOT_READS = ("jq . -- /proc/123/root/opt/app/creds.json",)
R4_READS = ("ps -ef", "ps aux", "ps auxww", "ps -eo pid,comm", "ps -ef -u 1000",
            "ps -u 1000", "ps -p 1,2", "jq -- .key f.json")


class FourthReviewTest(unittest.TestCase):

    def test_repros_are_refused(self):
        deny = _shipped_deny()
        for cmd in R4_REFUSED:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_namespace_alias_after_jq_dashdash_needs_an_approval(self):
        for cmd in R4_NOT_READS:
            self.assertEqual(_verdict(cmd, _shipped_deny()), "mutating", cmd)

    def test_reads_that_must_remain(self):
        deny = _shipped_deny()
        for cmd in R4_READS:
            self.assertEqual(vpsexec.classify(cmd, deny), ("read", None), cmd)


# --- fifth review of 52c550c (J1 + jq), every repro verbatim ---------------
# ps is a read only inside a strict allowlist: ANY UNIX parse failure makes
# procps reparse the whole argv as BSD, where an `e` prints environments.
R5_REFUSED = (
    "ps -e -p 0", "ps -e -p 99999999999", "ps -e -u 4294967295", "ps -e -u 99999999999",
    "ps -e -o x", "ps -e -ox", "ps -e --format=x", "ps -e - x", "ps -e -- x",
    "jq --rawfile -x /dev/sda .", "jq --slurpfile -x /proc/1/environ . f",
    "jq --arg -n /dev/sda .",
    # behind a wrapper `ps` is procps; `{{.Names}}` is no ps field and has an e
    "sudo docker ps --format '{{.Names}}'",
    # refused on 52c550c, so still refused
    "ps -e --sort pid", "ps -eo pid,pcpu,pmem,comm --sort=-pcpu",
)
R5_READS = (
    "ps -ef", "ps aux", "ps auxww", "ps -eo pid,comm", "ps -eo pid,comm,args",
    "ps -eo pid,args", "ps -ef -u 1000", "ps -u 1000", "ps -p 1,2",
    "ps -p 1 -o pid,comm", "ps -e --forest", "ps -o user", "ps -o pid= -p 1",
    "ps -u 4294967294", "ps aux | tr -s ' '",
)


class FifthReviewTest(unittest.TestCase):

    def test_repros_are_refused(self):
        deny = _shipped_deny()
        for cmd in R5_REFUSED:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_allowlisted_ps_forms_stay_reads(self):
        deny = _shipped_deny()
        for cmd in R5_READS:
            self.assertEqual(vpsexec.classify(cmd, deny), ("read", None), cmd)

    def test_the_grammar_rejects_every_unknown_token(self):
        ok = readpolicy._ps_in_grammar
        for argv in (["-ef"], ["aux"], ["-elf"], ["-p", "1,2"], ["-u0"],
                     ["--pid=4194304"], ["-o", "pid,%cpu,args"]):
            self.assertTrue(ok(argv), argv)
        for argv in (["-p", "0"], ["-p", "4194305"], ["-u", "4294967295"], ["-o", "x"],
                     ["-o", "pid=a b"], ["-C", "nginx"], ["-N"], ["-a"], ["-"], ["--"],
                     ["--x"], ["axe"], ["e"], ["-p"], ["-o", "pid,environ"],
                     ["--sort=-pcpu"], ["-k", "pid"], ["-eLf"], ["-efww"], ["-eT"],
                     ["-eH"], ["-U", "0"], ["--user=0"], ["--no-headers"]):
            self.assertFalse(ok(argv), argv)


ORACLE = REPO / "tests" / "data" / "procps_oracle"
# `ps -u UID` exits 1 when no process has that uid (none does in the oracle's
# container); that is "no match", not a failed parse, and printed nothing.
ORACLE_NO_MATCH = {"ps -u 1000", "ps -u 4294967294", "ps -u 1000 -o pid,args"}


def _oracle():
    """{form: {image: verdict}} recorded by tools/procps-oracle.sh."""
    out = {}
    for image in ("buster", "bookworm"):
        lines = (ORACLE / ("%s.out" % image)).read_text().splitlines()
        assert lines[0].startswith("ps from procps-ng"), lines[0]
        for line in lines[1:]:
            out.setdefault(line[9:], {})[image] = line[:8].strip()
    return out


class ProcpsOracleTest(unittest.TestCase):
    """Real procps (Debian 10 3.3.15 and Debian 12 4.0.2) run every form with
    CANARY=leak123 in every environment. A form whose output held the canary
    LEAKED an environment; the door must refuse it, not merely demote it."""

    def test_the_oracle_covers_both_images_and_every_form(self):
        oracle = _oracle()
        forms = [l for l in (ORACLE / "forms.txt").read_text().splitlines() if l]
        self.assertEqual(sorted(oracle), sorted("ps " + f for f in forms))
        for form, verdicts in oracle.items():
            self.assertEqual(set(verdicts), {"buster", "bookworm"}, form)
        self.assertGreaterEqual(sum("LEAK" in v.values() for v in oracle.values()), 25)

    def test_every_leak_is_refused(self):
        deny = _shipped_deny()
        for form, verdicts in sorted(_oracle().items()):
            if "LEAK" in verdicts.values():
                with self.assertRaises(Refused, msg=form):
                    vpsexec.classify(form, deny)

    def test_a_door_read_never_leaks_or_fails_to_parse(self):
        deny = _shipped_deny()
        for form, verdicts in sorted(_oracle().items()):
            if _verdict(form, deny) != "read":
                continue
            self.assertNotIn("LEAK", verdicts.values(), form)
            if form not in ORACLE_NO_MATCH:
                self.assertEqual(set(verdicts.values()), {"ok"}, form)

    def test_the_reviewed_reads_are_oracle_ok_and_stay_reads(self):
        oracle, deny = _oracle(), _shipped_deny()
        for cmd in ("ps -ef", "ps aux", "ps auxww", "ps -eo pid,comm",
                    "ps -eo pid,comm,args", "ps -eo pid,args", "ps -ef -u 1000",
                    "ps -p 1,2", "ps -p 1 -o pid,comm", "ps -e --forest",
                    "ps -o pid= -p 1", "ps -eo user,pid"):
            self.assertEqual(set(oracle[cmd].values()), {"ok"}, cmd)
            self.assertEqual(vpsexec.classify(cmd, deny), ("read", None), cmd)

    def test_every_format_field_exists_on_the_oldest_fleet_procps(self):
        names = {l.split()[0] for l in (ORACLE / "buster-psL.txt").read_text().splitlines()
                 if l.strip()}
        self.assertEqual(readpolicy.PS_FIELDS - names, set())
        oracle = _oracle()
        for field in readpolicy.PS_FIELDS:
            self.assertEqual(set(oracle["ps -e -o " + field].values()), {"ok"}, field)


# --- sixth review of 2209950 (K1, K1b), every repro verbatim --------------
R6_REFUSED = (
    "ps -ef -o args", "ps -ef -o pid,args", "ps -e -f -o args", "ps -e -o args -f",
    "ps -fe --format args", "ps -ef --format=pid,args", "ps -eux", "ps -ef -ux",
    "ps -aue", "ps -ue", "ps axe", "ps eww", "ps -p 1 e",
    "jq -rf /dev/sda f.json", "jq -rf /proc/1/environ",
)
R6_NOT_READS = ("ps aux ax", "ps -ef -ef")      # more than one format source/word


class SixthReviewTest(unittest.TestCase):

    def test_repros_are_refused(self):
        deny = _shipped_deny()
        for cmd in R6_REFUSED:
            with self.assertRaises(Refused, msg=cmd):
                vpsexec.classify(cmd, deny)

    def test_one_format_source_one_bsd_word(self):
        ok = readpolicy._ps_in_grammar
        for argv in (["-ef"], ["-eo", "pid,args"], ["aux"], ["-elf"]):
            self.assertTrue(ok(argv), argv)
        for argv in (["-ef", "-o", "args"], ["-e", "-o", "pid", "-o", "args"],
                     ["-el", "-o", "args"], ["aux", "ax"], ["aux", "-e"], ["-e", "aux"],
                     ["-j", "--format=pid"]):
            self.assertFalse(ok(argv), argv)

    def test_jq_short_cluster_with_f_reads_its_program_file(self):
        self.assertEqual(readpolicy._read_args("jq", ["-rf", "/x/prog.jq", "f.json"]),
                         ["-rf", "/x/prog.jq", "f.json"])
        self.assertEqual(_verdict("jq -rf /var/log/p.jq /var/log/x.json"), "mutating")


class ParserUnitTest(unittest.TestCase):

    def test_tar_to_stdout(self):
        t = readpolicy._tar_tree
        self.assertEqual(t(["cf", "-", "/etc"]), (True, ["/etc"]))
        self.assertEqual(t(["-cO", "/etc"]), (True, ["/etc"]))
        self.assertEqual(t(["-C", "/", "-c", "etc"]), (True, ["/etc"]))
        self.assertEqual(t(["czf", "/var/backups/x.tgz", "/etc"]), (False, []))
        self.assertEqual(t(["--extract", "--file=x.tgz"]), (False, []))
        self.assertEqual(t(["-cT", "/var/log/list"])[1], ["<a --files-from list>"])

    def test_parallel_command(self):
        self.assertEqual(readpolicy._parallel_head(["-j", "4", "cat"]), "cat")
        self.assertIsNone(readpolicy._parallel_head(["--jobs", "4"]))
        self.assertEqual(readpolicy._parallel_head(["--unknown", "4", "rm"]), "4")

    def test_file_looking_diff_operands(self):
        f = readpolicy._looks_like_file
        for yes in ("/etc/nginx/nginx.conf", "/etc/nginx/nginx.conf.bak", "/x/a.yaml"):
            self.assertTrue(f(yes), yes)
        for no in ("/opt/app", "/opt/app.bak", "/etc/postfix.orig", "/etc/nginx/conf.d",
                   "/root/.bashrc", "/etc/systemd/system/app.service.d",
                   "/etc/apt/sources.list.d.bak", "/tmp/x.conf.d", "/etc/hosts.bak"):
            self.assertFalse(f(no), no)


if __name__ == "__main__":
    unittest.main()
