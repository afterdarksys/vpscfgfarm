"""Positive option grammars for automatically executed observations.

Threats: unknown options, helper execution, arbitrary executable paths and
writing forms do not qualify as reads. A recursive content read (grep -r,
diff -r, find -exec cat, xargs cat, ...) rooted at a broad or unresolvable
directory is refused on every tier, and one rooted outside the log trees is
never a read (tree_read_verdict). A content read of a raw device, kernel or
process memory (/dev/sda, /dev/mem, /proc/kcore, /proc/<pid>/environ|mem|fd)
or of a credential file a substring cannot match precisely (ssh host keys,
*.key, .env) is refused on every tier, and /sys, /proc/<pid>/root and the
unbounded /dev streams are never reads (path_read_verdict). Assumes trusted
host binaries and system configuration (a symlink already on the host can
still point anywhere); this does not sandbox a compromised host, and it does
not see inside interpreters (awk, sed, perl -e, python3 -c), which are never
reads and are left to the approval.
"""
import posixpath
import re

# Options ending in ':' consume a value. Unknown options never qualify.
OPTIONS = {
    'ls': 'a A l h n i d R t r S F p 1 --all --almost-all --human-readable --color:',
    'cat': 'n b s v E T A --number --show-all',
    'head': 'n: c: q v --lines: --bytes:',
    'tail': 'n: c: q v f F --lines: --bytes: --follow: --pid: --retry',
    'wc': 'c l w m L --bytes --lines --words',
    'stat': 'c: f: L --format: --printf:',
    'df': 'h H i k m a T P x: t: --human-readable --output:',
    'du': 'h H s a x c k m d: --max-depth: --exclude: --human-readable',
    'sort': 'h n r u f b g M V k: t: --human-numeric-sort --numeric-sort --reverse --unique --key: --field-separator:',
    'uniq': 'c d u i f: s: w:',
    'grep': 'a b c E F G H h i l L n o q r R s v w x e: f: m: A: B: C: --color: --include: --exclude: --exclude-dir:',
    'find': '-name: -iname: -path: -ipath: -type: -maxdepth: -mindepth: -mtime: -mmin: -size: -user: -group: -print -print0 -ls -empty -readable -writable -executable -o -a -not -perm: -newer: -xdev -uid: -gid: -nouser -nogroup -links: -inum: -samefile: -prune',
    'journalctl': 'u: n: p: b: k f r x e --unit: --lines: --priority: --boot: --since: --until: --no-pager --no-hostname --no-legend --disk-usage --verify --utc --output:',
    'ss': 'l n t u p a r s e i o 4 6 --listening --numeric --tcp --udp --processes',
    'netstat': 'l n t u p a r s e i 4 6',
    'dmesg': 'T H d e k l: --ctime --human --level:',
    'ping': 'c: W: w: i: n q 4 6',
    'curl': 'q s S f I i L k 4 6 w: H: --disable --silent --show-error --fail --head --include --location --connect-timeout: --max-time: --cacert: --insecure --write-out: --header: --resolve:',
    'openssl': '-noout -subject -issuer -dates -enddate -startdate -serial -fingerprint -sha256 -text -checkend: -in: -connect: -servername: -starttls: -CAfile: -CApath: -verify_return_error -brief -quiet -showcerts',
    'docker': 'a q s f: n: --all --quiet --filter: --format: --no-trunc --size --tail: --since: --until: --timestamps --details --follow --no-stream --no-resolve --services --volumes --images --profiles',
    'systemctl': 'l a q --all --full --quiet --no-pager --no-legend --plain --type: --state: --property: --value --failed',
    'kubectl': 'A n: o: l: f: --all-namespaces --namespace: --output: --selector: --field-selector: --sort-by: --no-headers --show-labels --watch --request-timeout: --tail: --since: --timestamps --previous --containers --all-containers --short',
    'ps': 'a e f l u: p: o: C: --pid: --format: --forest',
    'free': 'h b k m g t w --human',
    'hostname': 'f s i I d --fqdn --short --ip-address --all-ip-addresses',
    'date': 'u R I --utc --iso-8601:',
    'uname': 'a s n r v m p i o',
    'id': 'u g G n r',
    'cut': 'b: c: d: f: s --bytes: --characters: --delimiter: --fields:',
    'lsblk': 'a f l n p o: --output:',
    'md5sum': 'b t c --check --status --quiet',
    'sha256sum': 'b t c --check --status --quiet',
    # --- investigation additions (docs/NO-PASTE.md F3) -------------------
    # Performance. Operands are checked numeric below: interval and count.
    'vmstat': 'a d s S: w t n --active --disks --stats --unit: --wide --timestamp',
    'iostat': 'x z c d k m h t y N p: --human',
    'mpstat': 'u P: A I:',
    'pidstat': 'u r d w h l t p: C: --human',
    'top': 'b n: d: c H o: p: w: E: e: 1 i',
    'findmnt': 'l n r J D a o: t: --list --json --df --output: --types: --real',
    'lsof': 'n P i t l a u: p: c:',
    'last': 'n: F i w x a d R',
    'lastb': 'n: F i w x a d R',
    'lastlog': 'u: b: t:',
    'who': 'a b d H l m p q r s t u --all --heading',
    'w': 'h u s f i o --no-header --short',
    'readlink': 'f e m n --canonicalize',
    'realpath': 'e m s q',
    'file': 'b i L z --brief --mime',
    'strings': 'a n: t:',
    'lsattr': 'a d R v',
    'getfacl': 'a d R L P n p --omit-header',
    'sysctl': 'n e N a A b --values --all',
    'jq': 'r j c S e a n s C M --raw-output --compact-output --sort-keys --slurp --exit-status',
    'diff': 'u q r N y w b B i a --brief --unified --recursive',
    'cmp': 's l b',
    'zcat': 'f q',
    'zgrep': 'a b c E F G H h i l L n o q r R s v w x e: m: A: B: C:',
    'tr': 'd s c C',
    'column': 't s: o: N: J',
    'traceroute': 'n I T U q: w: m: p: 4 6 z:',
    'mtr': 'r n c: w b 4 6 T u P: --report --report-wide --no-dns',
    'nc': 'z v n w: u 4 6',
    'helm': 'A n: o: a --all-namespaces --namespace: --output: --max: --all',
    'crictl': 'a q o: n: --all --quiet --output: --name: --namespace: --label: --pod: --state: --tail: --since: --timestamps --previous',
    'postconf': 'n d h M F P m l a A x c:',
    'postqueue': 'p j c:',
    'postcat': 'h q e c:',
    'opendkim-testkey': 'd: s: k: v x:',
    'named-checkconf': 'z j l',
    'named-checkzone': 'q j i: k: m: n: r: s: D',
    'debsums': 's c a l e --silent --changed --all --config',
    'smartctl': 'H A i a x l: --health --attributes --info --all --xall',
}
BARE = {'uptime', 'whoami', 'pwd', 'printenv', 'echo', 'nproc', 'arch', 'lsmod',
        'mount', 'mailq'}
DOCKER = {('ps',), ('inspect',), ('logs',), ('images',), ('version',), ('info',),
          ('stats',), ('top',), ('port',), ('diff',), ('history',), ('system', 'df'),
          ('network', 'ls'), ('volume', 'ls'), ('compose', 'ps'), ('compose', 'logs'), ('compose', 'config'),
          ('compose', 'ls'), ('events',), ('network', 'inspect'), ('volume', 'inspect')}
SYSTEMCTL = {'status', 'list-units', 'list-unit-files', 'is-active', 'is-enabled',
             'is-failed', 'is-system-running', 'get-default', 'list-sockets',
             'list-timers', 'list-dependencies', 'show', 'cat'}
KUBECTL = {('get',), ('describe',), ('logs',), ('top',), ('version',), ('explain',),
           ('api-resources',), ('events',), ('api-versions',), ('auth', 'can-i'),
           ('cluster-info',), ('config', 'get-contexts'), ('config', 'current-context')}


HELM = {'list', 'ls', 'status', 'history'}  # never `get values`: it prints secrets
CRICTL = {'ps', 'pods', 'logs', 'stats', 'statsp', 'images', 'version'}  # not inspect: env
# `getent shadow|gshadow` would print password hashes.
GETENT_DBS = {'passwd', 'group', 'hosts', 'services', 'protocols', 'networks',
              'ahosts', 'ahostsv4', 'ahostsv6', 'initgroups', 'netgroup'}
IP_OBJECTS = {'addr', 'address', 'a', 'link', 'l', 'route', 'ro', 'r', 'rule', 'ru',
              'neigh', 'neighbour', 'neighbor', 'n', 'maddr', 'm'}
IP_FLAGS = {'-s', '-stats', '-4', '-6', '-br', '-brief', '-d', '-details', '-o',
            '-oneline', '-j', '-json', '-p', '-pretty', '-c', '-color'}
# iproute2 accepts ANY prefix of a verb (`ip r d default` deletes the default
# route), so a deny list of verbs is unsound. Only these read verbs pass.
IP_READ_VERBS = {'show', 'sh', 'list', 'lst', 'ls'}
NUMERIC = re.compile(r'^[0-9]+$')
SMART_LOGS = {'error', 'xerror', 'selftest', 'xselftest', 'selective', 'directory',
              'background', 'sasphy', 'sataphy', 'scttemp', 'scttempsts',
              'scttemphist', 'devstat', 'ssd'}
JQ_REFUSED = re.compile(r'\b(range|repeat|until|while|recurse|limit|inputs?|env|'
                        r'input_filename|getpath|paths|walk|splits|combinations)\b|\$')
RELATIVE_PAST = re.compile(r'^[0-9]{1,5}[smh]$')


def _exact(head, args):
    """Commands whose read form is a short, closed list. True/False decides;
    None means "not special, use the option grammar"."""
    if head == 'ip':
        i = 0
        while i < len(args) and args[i].startswith('-'):
            if args[i] not in IP_FLAGS:
                return False  # -b/-batch reads a command file; -n enters a netns
            i += 1
        rest = args[i:]
        if not rest or rest[0] not in IP_OBJECTS:
            return False
        if len(rest) > 1:
            verb = rest[1]
            if verb == 'get':
                if rest[0] not in ('route', 'ro', 'r'):
                    return False
            elif verb not in IP_READ_VERBS:
                return False
        return not any(a.startswith('-') for a in rest[1:])
    if head == 'timedatectl':
        return args in ([], ['status'], ['show'], ['timesync-status'], ['show-timesync'])
    if head == 'chronyc':
        args = [a for a in args if a not in ('-n', '-c')]
        return len(args) == 1 and args[0] in ('tracking', 'sources', 'sourcestats', 'activity')
    if head == 'ntpq':
        return args in (['-p'], ['-pn'], ['-np'], ['-p', '-n'], ['-n', '-p'])
    if head == 'swapon':
        return bool(args) and set(args) <= {'--show', '-s', '--summary', '--bytes'}
    if head == 'mdadm':
        return (len(args) >= 2 and args[0] in ('--detail', '-D', '--examine', '-E', '--query', '-Q')
                and all(re.fullmatch(r'/dev/[A-Za-z0-9_/-]+', a) and '..' not in a
                        for a in args[1:]))
    if head == 'getent':
        return bool(args) and args[0] in GETENT_DBS and not any(a.startswith('-') for a in args)
    if head == 'crontab':
        # `crontab FILE` installs. Only -l, optionally for one user.
        return args == ['-l'] or (len(args) == 3 and args[0] == '-l' and args[1] == '-u') \
            or (len(args) == 3 and args[0] == '-u' and args[2] == '-l')
    if head == 'dpkg':
        modes = ('-l', '--list', '-V', '--verify', '-S', '--search', '-L', '--listfiles',
                 '-s', '--status', '--get-selections')
        return bool(args) and args[0] in modes and not any(a.startswith('-') for a in args[1:])
    if head == 'apt':
        return bool(args) and args[0] == 'list' and set(args[1:]) <= {
            '--installed', '--upgradable', '--all-versions'}
    if head == 'apt-cache':
        return len(args) >= 2 and args[0] in ('policy', 'show', 'depends', 'rdepends', 'madison') \
            and not any(a.startswith('-') for a in args[1:])
    if head == 'conntrack':
        return args in (['-C'], ['--count'], ['-S'], ['--stats'], ['-L'])
    if head == 'fail2ban-client':
        return args in (['status'], ['ping'], ['version']) or \
            (len(args) == 2 and args[0] == 'status' and not args[1].startswith('-'))
    if head == 'auditctl':
        return args in (['-l'], ['-s'])
    if head == 'ausearch':
        return _ausearch(args)
    if head == 'aa-status':
        return set(args) <= {'--enabled', '--profiled', '--enforced', '--complaining',
                             '--json', '--pretty-json'}
    if head == 'postmulti':
        if args in (['-l'], ['-l', '-a'], ['-a', '-l']):
            return True
        # -x runs ANY command in the instance's environment; pin it to reads.
        return (len(args) >= 4 and args[0] == '-i' and args[2] == '-x'
                and args[3:] in (['postqueue', '-p'], ['postqueue', '-j'], ['postconf', '-n']))
    if head == 'rndc':
        return args == ['status']
    if head == 'certbot':
        return args == ['certificates'] or (
            len(args) == 3 and args[0] == 'certificates' and args[1] == '--cert-name')
    if head == 'apachectl':
        return args in (['-S'], ['-t'], ['-M'], ['-v'])
    if head == 'caddy':
        if args == ['version']:
            return True
        return (len(args) in (3, 5) and args[:2] == ['validate', '--config']
                and (len(args) == 3 or args[3] == '--adapter'))
    return None


AUSEARCH_ONE = {'-m', '-k', '-ui', '-x', '-f', '-sc', '-c', '-p', '-ua', '-ul', '-hn',
                '--message', '--key', '--uid', '--executable', '--file', '--syscall',
                '--comm', '--pid'}
AUSEARCH_TIME = {'-ts', '-te', '--start', '--end'}
AUSEARCH_BARE = {'-i', '--interpret', '-r', '--raw', '--just-one'}


def _ausearch(args):
    i = 0
    while i < len(args):
        a = args[i]
        if a in AUSEARCH_BARE:
            i += 1
        elif a in AUSEARCH_ONE:
            if i + 1 >= len(args):
                return False
            i += 2
        elif a in AUSEARCH_TIME:
            # `-ts recent`, `-ts today`, `-ts 09/27/2026 10:00:00`
            if i + 1 >= len(args):
                return False
            i += 2
            if i < len(args) and re.fullmatch(r'[0-9]{1,2}:[0-9]{2}(:[0-9]{2})?', args[i]):
                i += 1
        else:
            return False  # -if/--input names a file; everything else unknown
    return True


def options(tokens, grammar, parsed=None):
    """Operands, or None if any option is outside the grammar. When `parsed`
    is a list, every option actually recognised is appended as (flag, value).
    Callers that REQUIRE a flag must test `parsed`, never the raw tokens:
    `postcat -c -h Q` has no -h in effect (-c ate it as its value)."""
    parsed = [] if parsed is None else parsed
    flags = {}
    for flag in grammar.split():
        value = flag.endswith(':')
        name = flag.rstrip(':')
        flags[name if name.startswith('-') else '-' + name] = value
    operands, i, ended = [], 0, False
    while i < len(tokens):
        token = tokens[i]
        i += 1
        if ended or not token.startswith('-') or token == '-':
            operands.append(token)
            continue
        if token == '--':
            ended = True
            continue
        name, equals, value = token.partition('=')
        if name in flags:
            if equals and not flags[name]:
                return None
            if flags[name] and not equals:
                if i == len(tokens):
                    return None
                value = tokens[i]
                i += 1
            parsed.append((name, value if flags[name] else None))
            continue
        if token.startswith('--'):
            return None
        if re.fullmatch(r'-[0-9]+', token):
            # Historic head/tail count notation handled by their caller.
            return None
        # Short option bundles and attached values.
        for index, char in enumerate(token[1:], 1):
            key = '-' + char
            if key not in flags:
                return None
            if flags[key]:
                if index == len(token) - 1:
                    if i == len(tokens):
                        return None
                    parsed.append((key, tokens[i]))
                    i += 1
                else:
                    parsed.append((key, token[index + 1:]))
                break
            parsed.append((key, None))
    return operands


def _curl_output_devnull(args):
    """Strip `-o /dev/null` (the only output file a read may name) and refuse
    `@file` values, which make curl read a local file into the request or the
    output format (`-w @/etc/shadow`). Returns the remaining args or None."""
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a in ('-o', '--output'):
            if i + 1 >= len(args) or args[i + 1] != '/dev/null':
                return None
            i += 2
            continue
        if a.startswith('--output='):
            if a != '--output=/dev/null':
                return None
            i += 1
            continue
        if a.startswith('-') and not a.startswith('--') and 'o' in a[1:]:
            return None  # bundled -so FILE: spell -o /dev/null on its own
        if a in ('-w', '--write-out', '-H', '--header') and i + 1 < len(args) \
                and args[i + 1].startswith('@'):
            return None
        if a.startswith(('--write-out=@', '--header=@')):
            return None
        out.append(a)
        i += 1
    return out


def is_read(tokens):
    if not tokens:
        return False
    head, args = tokens[0], tokens[1:]
    # A basename is not executable identity. Custom and relative paths need
    # mutation authorization, even when named after a familiar utility.
    if '/' in head:
        return False
    if head in BARE:
        return head in ('echo', 'printenv') or not args
    # A raw device, process memory, /sys or a credential file is never read
    # by a read, whatever the tool (path_read_verdict refuses the worst of
    # them before this runs). Heads that print only names and metadata keep
    # their /dev operands: `ls /dev`, `stat /dev/sda`, `smartctl -H /dev/sda`.
    if head not in METADATA_HEADS and any(
            _path_class(c) or _credential_file(c)
            for a in _read_args(head, args) for c in _path_candidates(a)):
        return False
    exact = _exact(head, args)
    if exact is not None:
        return exact
    if head in ('nginx', 'apachectl', 'sshd', 'named'):
        return args in (['-t'], ['-v'])
    if head in ('python3', 'node', 'psql'):
        return args == ['--version']
    if head in ('dig', 'host', 'nslookup'):
        # dig -f reads files, -k loads keys; keep the automatic form small.
        return all(not a.startswith('-') and not a.startswith('+') or a in ('+short', '+tcp', '+trace', '+noall', '+answer') for a in args)
    if head == 'k3s':
        if not args or args[0] not in ('kubectl', 'crictl'):
            return False
        if args[0] == 'kubectl':
            head, args = 'kubectl', args[1:]
    if head == 'k3s' and args and args[0] == 'crictl':
        head, args = 'crictl', args[1:]
    prefixes = DOCKER if head == 'docker' else KUBECTL if head == 'kubectl' else None
    helm_sub = None
    docker_events = head == 'docker' and args[:1] == ['events']
    if head in ('helm', 'crictl'):
        allowed = HELM if head == 'helm' else CRICTL
        if not args or args[0] not in allowed:
            return False
        helm_sub = args[0]
        args = args[1:]
    if head == 'docker' and args[:1] == ['events']:
        # Unbounded `docker events` never returns; both ends of the window are required.
        if not any(a.startswith('--since') for a in args) or not any(a.startswith('--until') for a in args):
            return False
    if prefixes:
        prefix = next((p for p in sorted(prefixes, key=len, reverse=True) if tuple(args[:len(p)]) == p), None)
        if prefix is None:
            return False
        args = args[len(prefix):]
        if head == 'kubectl' and prefix == ('cluster-info',) and args:
            return False  # cluster-info dump can write files
    elif head == 'systemctl':
        if not args or args[0] not in SYSTEMCTL:
            return False
        args = args[1:]
    elif head == 'openssl':
        if not args or args[0] not in ('x509', 's_client', 'verify', 'version'):
            return False
        args = args[1:]
    elif head == 'curl':
        # curl reads ~/.curlrc by default; that can contain writes/uploads.
        if not args or not (args[0] == '--disable' or args[0].startswith('-q')):
            return False
        args = _curl_output_devnull(args)
        if args is None:
            return False
    if head not in OPTIONS:
        return False
    if head in ('head', 'tail'):
        args = [a if not re.fullmatch(r'-[0-9]+', a) else '--lines=' + a[1:] for a in args]
    parsed = []
    operands = options(args, OPTIONS[head], parsed)
    if operands is None:
        return False
    seen = set(f for f, _ in parsed)
    values = dict((f, [v for g, v in parsed if g == f]) for f in seen)
    if head == 'uniq' and len(operands) > 1:
        return False
    if head in ('vmstat', 'iostat', 'mpstat', 'pidstat') and \
            any(not NUMERIC.match(o) and not (head == 'iostat' and o.startswith('sd')) for o in operands):
        return False
    if head == 'top' and '-b' not in seen:
        return False  # interactive top never exits
    if head == 'sysctl' and any('=' in o for o in operands):
        return False  # `sysctl key=value` writes
    if head == 'postconf' and any('=' in o for o in operands):
        return False  # `postconf -M name/type=...` / `-P ...=` edit master.cf
    if head == 'postqueue' and not seen & {'-p', '-j'}:
        return False  # -f flushes, -s schedules; only list forms
    if head == 'postcat' and '-h' not in seen:
        return False  # with no section flag postcat prints message bodies
    if head == 'nc' and '-z' not in seen:
        return False  # without -z netcat sends stdin / listens
    if head == 'mtr' and not seen & {'-r', '--report', '--report-wide'}:
        return False  # curses mode never exits
    if head == 'smartctl' and any(v not in SMART_LOGS for v in values.get('-l', [])):
        return False  # -l scterc,70,70 / scttempint,N,p WRITE drive settings
    if head == 'helm' and helm_sub == 'status' and seen & {'-o', '--output'}:
        return False  # status -o json|yaml prints release config and rendered Secrets
    if head == 'curl':
        for flag in ('-w', '--write-out', '-H', '--header'):
            for v in values.get(flag, []):
                if v.startswith('@') or '%output' in v:
                    return False  # @file reads a local file; %output{f} writes one
    if head == 'jq':
        # -n with a generator pins a CPU or eats RAM on a host with no failover;
        # the ssh timeout kills only the local client, not the remote jq.
        if '-n' in seen or len(operands) < 2 or len(operands[0]) > 200 or \
                JQ_REFUSED.search(operands[0]):
            return False
    if head == 'docker' and docker_events:
        for flag in ('--since', '--until'):
            if not all(v and RELATIVE_PAST.match(v) for v in values.get(flag, [])):
                return False  # a future --until never returns
    if head == 'lsof' and any(o.startswith('+') for o in operands):
        return False
    if head == 'named-checkzone' and len(operands) != 2:
        return False
    if head == 'smartctl' and not all(o.startswith('/dev/') for o in operands):
        return False

    if head == 'hostname' and operands:
        return False
    if head == 'date' and any(not a.startswith('+') for a in operands):
        return False
    if head == 'curl' and any(not re.match(r'^(https?://|localhost[:/]|127\.0\.0\.1[:/])', a) for a in operands):
        return False
    return True


# ---------------------------------------------------------------------------
# Refusal hints. MESSAGE ONLY: nothing here is consulted by is_read(), so a
# hint can never widen what counts as a read. It explains the accepted form
# when a familiar read tool was refused for its flags or shape.
# ---------------------------------------------------------------------------

def _grammar(head):
    return " ".join(f.rstrip(":") if f.startswith("-") else "-" + f.rstrip(":")
                    for f in OPTIONS[head].split())


FORM_HINTS = {
    'curl': ("curl is a read only as `curl -q<flags> URL` (or `curl --disable ...`): "
             "-q/--disable must be the FIRST argument so ~/.curlrc is ignored; flags "
             "only from: %s; output only as a separate `-o /dev/null`; no @file "
             "values; URLs only http(s)://, localhost or 127.0.0.1. "
             "e.g. `curl -qfsS http://127.0.0.1/healthz`"
             % " ".join(f for f in _grammar('curl').split() if f not in ('-q', '--disable'))),
    'docker': "docker is a read only as: %s" % ", ".join(
        sorted("docker " + " ".join(p) for p in DOCKER)),
    'kubectl': "kubectl is a read only as: %s" % ", ".join(
        sorted("kubectl " + " ".join(p) for p in KUBECTL)),
    'systemctl': "systemctl is a read only as: %s" % ", ".join(
        sorted("systemctl " + s for s in SYSTEMCTL)),
    'helm': "helm is a read only as: %s" % ", ".join(sorted("helm " + s for s in HELM)),
    'crictl': "crictl is a read only as: %s" % ", ".join(sorted("crictl " + s for s in CRICTL)),
    'openssl': "openssl is a read only as: openssl x509 | s_client | verify | version",
    'ip': ("ip is a read only as `ip [-s|-br|-d|-j|-4|-6...] <addr|link|route|rule|neigh|maddr> "
           "[show|list]` (or `ip route get ...`)"),
    'top': "top is a read only in batch mode, e.g. `top -b -n 1`",
    'nc': "nc is a read only as a port probe with -z, e.g. `nc -z -w 3 HOST PORT`",
    'mtr': "mtr is a read only in report mode, e.g. `mtr -r -c 5 HOST`",
    'postqueue': "postqueue is a read only as `postqueue -p` or `postqueue -j`",
    'postcat': "postcat is a read only with -h, e.g. `postcat -h -q QUEUEID`",
    'jq': "jq is a read only as `jq FILTER FILE...` (no -n, no generators or $env)",
    'sysctl': ("sysctl is a read only as `sysctl [-n] [-e] [-N] [-b] KEY...` or "
               "`sysctl -a`: no -w, -p, -f or --system, and no `key=value` operand "
               "(those write or load settings)"),
    'crontab': "crontab is a read only as `crontab -l` (optionally `-u USER`)",
}


def read_form_hint(tokens):
    """A one-line hint naming the accepted read form of a known read tool, or
    None when the head is not one (unknown commands get no hint: they are
    simply mutations). Never used to decide anything."""
    if not tokens:
        return None
    head = tokens[0]
    if '/' in head:
        base = head.rsplit('/', 1)[1]
        if base in OPTIONS or base in BARE or _exact(base, []) is not None:
            return ("%r is a path; only the bare command name `%s` can be a read "
                    "(a path is not executable identity)" % (head, base))
        return None
    if head == 'k3s':
        sub = tokens[1] if len(tokens) > 1 else None
        if sub in ('kubectl', 'crictl'):
            return "k3s " + FORM_HINTS[sub]
        return "k3s is a read only as `k3s kubectl <read>` or `k3s crictl <read>`"
    if head in FORM_HINTS:
        return FORM_HINTS[head]
    if head in BARE:
        return ("%s is a read only with no arguments" % head
                if head not in ('echo', 'printenv') else None)
    if head in ('nginx', 'sshd', 'named'):
        return "%s is a read only as `%s -t` or `%s -v`" % (head, head, head)
    if head in ('python3', 'node', 'psql'):
        return "%s is a read only as `%s --version`" % (head, head)
    if head in ('dig', 'host', 'nslookup'):
        return ("%s is a read only with no options other than +short +tcp +trace "
                "+noall +answer" % head)
    if _exact(head, []) is not None:
        return ("%s is a read only in a short closed list of forms "
                "(vpscfg/readpolicy.py, _exact)" % head)
    if head in OPTIONS:
        return "%s is a read only with options from: %s" % (head, _grammar(head))
    return None


# ---------------------------------------------------------------------------
# Directory-expanding content reads ("tree reads").
#
# deny_extra matches COMMAND TEXT. `grep -r -a . /etc` names no credential
# path, yet prints an HSM PIN, every server.key and every .pem under
# /etc. The deny list cannot see what a directory argument expands to, so this
# gate looks at the ROOT of every command that reads file contents across a
# directory, whatever its tier:
#
#   grep egrep fgrep zgrep zegrep zfgrep  with -r/-R, --recursive (or any
#                    prefix of it), --dereference-recursive, -d/--directories
#                    with any value but read/skip, or GREP_OPTIONS in the line
#   rgrep rg ag ack  recursive by default
#   diff             -r/--recursive, -N/--new-file, --unidirectional-new-file
#                    (full tree rule); plain diff of two directories compares
#                    their same-named files, so its operands get the
#                    refuse rule below too
#   find             -exec/-execdir/-ok/-okdir running anything that is not
#                    a known name-only command (NAME_ONLY below)
#   xargs parallel   running anything not in NAME_ONLY: its file list comes
#                    from stdin, so its tree is never known
#   tar              creating an archive on stdout (no -f, -f -, -O)
#   git grep --no-index  a grep -r of its pathspecs
#
# A plain (non-recursive) diff outside the log trees is never a read unless
# both operands look like files (a known suffix such as .conf, .yaml, .log in
# the basename): the door cannot stat, and two directories compare every
# same-named file in them (.env.production before and after a rotation).
#
# The rule, per root (fail closed at every step):
#   REFUSE (absolute, like deny_extra: no runbook, override, break-glass or
#   approval lifts it) when the root
#     - is not an absolute path (relative, `.`, `~`, missing => the remote
#       cwd is unknown), or has a `..` component (a symlinked parent makes
#       lexical normalisation wrong);
#     - is /proc or under it (/proc/<pid>/root and /proc/<pid>/cwd are `/`);
#     - is equal to or an ancestor of a BROAD_ROOTS entry;
#     - is equal to, an ancestor of, or inside an absolute deny_extra path,
#       or contains a deny pattern once normalised (`/etc//hsmd`).
#   DEMOTE (not a read: --run and an approval, with the plan in front of a
#   human) when it is a full tree read rooted anywhere else outside
#   CONTENT_SAFE_TREES. Most deny entries are FILENAME patterns
#   (.env.production, id_rsa, .pem, server.key, htpasswd): a tree anywhere
#   can hold one — /opt/app/src/.env.production is the common case — so no
#   tree is provably free of them except the log trees named here.
#   Otherwise the command keeps its tier: `grep -r ERROR /var/log/nginx` is
#   still a read.
#
# Paths are normalised component-wise (`//`, `/./`, trailing `/`), after the
# shell's own quote and backslash removal (shlex). Globs, braces, `$` and
# command substitution are refused by classify before this runs.
#
# Residuals (documented in docs/VPSEXEC.md): a symlink already on the host
# inside an allowed tree (host configuration is trusted, as everywhere in this
# module); a plain `diff` of two directories whose names look like files
# (`/opt/app.conf.d`); and, for commands that are not reads at all, anything a
# shell can assemble that this scanner cannot see (`python3 -c ...`,
# `awk 'BEGIN{system(...)}'`, an alias) — an approved mutation can read
# anything, which is why it needs the approval.
# ---------------------------------------------------------------------------

BROAD_ROOTS = ('/etc', '/var/lib', '/root', '/home', '/opt', '/srv', '/run',
               '/usr/local/etc', '/proc', '/sys', '/tmp', '/var/tmp', '/var/backups',
               '/var/www', '/var/spool', '/mnt', '/media', '/boot', '/dev',
               '/var/lib/docker', '/var/lib/rancher', '/var/lib/kubelet',
               '/etc/ssl', '/etc/letsencrypt', '/etc/rancher')
CONTENT_SAFE_TREES = ('/var/log',)
GREP_HEADS = {'grep', 'egrep', 'fgrep', 'zgrep', 'zegrep', 'zfgrep',
              'bzgrep', 'bzegrep', 'bzfgrep', 'xzgrep', 'xzegrep', 'xzfgrep',
              'lzgrep', 'lzegrep', 'lzfgrep', 'zstdgrep', 'pcregrep', 'pcre2grep',
              'ugrep', 'ug'}
IMPLICIT_RECURSIVE = {'rgrep', 'rg', 'ag', 'ack', 'ack-grep', 'sift', 'pt'}
TREE_HEADS = GREP_HEADS | IMPLICIT_RECURSIVE | {'diff', 'find', 'xargs', 'parallel',
                                                'tar', 'git'}
# Prefixes that run the next word as a command. A tree head after one of these
# (anywhere earlier in the segment) is analysed as a command, not an argument,
# so a wrapper's own value-taking options (`strace -o /dev/null`, `numactl
# -N0`, `systemd-run --pipe`, `prlimit --nofile=9`) cannot hide it. Shell
# keywords are here too: `then grep -r . /etc` and `! grep ...` run grep.
WRAPPERS = {'sudo', 'doas', 'env', 'nice', 'nohup', 'timeout', 'stdbuf', 'ionice',
            'command', 'exec', 'time', 'chroot', 'setsid', 'taskset', 'chrt',
            'busybox', 'xargs', 'flock', 'unbuffer', 'runuser', 'watch', 'nsenter',
            'toybox', 'unshare', 'systemd-run', 'setpriv', 'prlimit', 'strace',
            'ltrace', 'numactl', 'cgexec', 'firejail', 'parallel',
            'then', 'do', 'else', 'elif', '!', 'if', 'while', 'until'}
# `git diff`, `kubectl diff`, `docker diff` are not diff(1).
DIFF_PARENTS = {'git', 'kubectl', 'docker', 'helm', 'oc', 'podman', 'nerdctl', 'k3s'}
# What find -exec / xargs may run without counting as a content read: these
# print names, sizes, hashes or metadata, never file contents.
NAME_ONLY = {'rm', 'rmdir', 'chmod', 'chown', 'chgrp', 'touch', 'ls', 'stat', 'du',
             'file', 'wc', 'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'echo',
             'basename', 'dirname', 'realpath', 'readlink', 'lsattr', 'getfacl',
             # Their arguments are object names and pids, not paths in a tree:
             # a reboot-prep runbook runs `docker ps -q | xargs -r -P 8
             # docker stop -t 30`. Every docker form is still classified on its
             # own merits (risky/mutating), this only says xargs feeds it names.
             'docker', 'kill'}
# Heads whose quoted arguments are patterns or data, never a command line.
# Every other head has its whitespace-bearing arguments re-scanned as shell
# text, so `sh -c 'grep -r . /etc'` and `ssh h 'grep -r . /etc'` are seen.
PATTERN_HEADS = GREP_HEADS | IMPLICIT_RECURSIVE | {
    'jq', 'echo', 'printf', 'date', 'curl', 'journalctl', 'column', 'cut', 'tr',
    'awk', 'sed', 'stat', 'ps'}


ASSIGNMENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')


def _norm_root(root):
    """Absolute, component-normalised path, or None when unresolvable."""
    if not root.startswith('/'):
        return None
    parts = []
    for part in root.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            return None
        parts.append(part)
    return '/' + '/'.join(parts)


def _under(path, top):
    """path is top or beneath it (component-wise)."""
    return top == '/' or path == top or path.startswith(top + '/')


def _grep_tree(args, head, grep_options):
    """(recursive, roots) for one grep-family invocation."""
    recursive, files, _ = _grep_args(args, head, grep_options)
    if not recursive:
        return False, []
    return True, files or ['.']


def _grep_args(args, head, grep_options):
    """(recursive, files, pattern_files) for one grep-family invocation: the
    operands that name files (never the pattern) and the -f/--file values."""
    recursive = head in IMPLICIT_RECURSIVE or (grep_options and head in GREP_HEADS)
    pattern_files = []
    value_short = set('efmABCdD') if head in GREP_HEADS else set()
    value_long = {'regexp', 'file', 'max-count', 'after-context', 'before-context',
                  'context', 'devices', 'label', 'include', 'exclude', 'exclude-from',
                  'exclude-dir', 'binary-files', 'group-separator'}
    by_option = False   # pattern came from -e/-f, so every operand is a root
    operands, i, ended = [], 0, False
    while i < len(args):
        a = args[i]
        i += 1
        if ended or a == '-' or not a.startswith('-'):
            operands.append(a)
            continue
        if a == '--':
            ended = True
            continue
        if a.startswith('--'):
            name, eq, value = a[2:].partition('=')
            if not name:
                continue
            # GNU getopt accepts any unambiguous prefix; an ambiguous one is an
            # error there, so treating it as the dangerous option costs nothing.
            if 'recursive'.startswith(name) or 'dereference-recursive'.startswith(name):
                recursive = True
            if 'regexp'.startswith(name) or 'file'.startswith(name):
                by_option = True
            if 'file'.startswith(name):
                pattern_files.append(value if eq else (args[i] if i < len(args) else ''))
            if len(name) >= 2 and 'directories'.startswith(name):
                if not eq:
                    value = args[i] if i < len(args) else ''
                    i += 1
                if value not in ('read', 'skip'):
                    recursive = True
            elif not eq and name in value_long and head in GREP_HEADS:
                i += 1
            continue
        for index, char in enumerate(a[1:], 1):
            if char in 'rR':
                recursive = True
            if char in 'ef':
                by_option = True
            if char in value_short:
                value = a[index + 1:]
                if not value:
                    value = args[i] if i < len(args) else ''
                    i += 1
                if char == 'd' and value not in ('read', 'skip'):
                    recursive = True
                if char == 'f':
                    pattern_files.append(value)
                break
    files = [o for o in (operands if by_option else operands[1:]) if o != '-']
    return recursive, files, pattern_files


def _diff_tree(args):
    """(full_tree, roots) for one diff invocation."""
    tree, roots, i, ended = False, [], 0, False
    while i < len(args):
        a = args[i]
        i += 1
        if ended or a == '-' or not a.startswith('-'):
            roots.append(a)
            continue
        if a == '--':
            ended = True
            continue
        if a.startswith('--'):
            name, eq, value = a[2:].partition('=')
            if not name:
                continue
            if any(o.startswith(name) for o in ('recursive', 'new-file',
                                                 'unidirectional-new-file')):
                tree = True
            if any(o.startswith(name) for o in ('from-file', 'to-file')):
                if not eq:
                    value = args[i] if i < len(args) else ''
                    i += 1
                roots.append(value)
            continue
        for index, char in enumerate(a[1:], 1):
            if char in 'rN':
                tree = True
            if char in 'CDFILSUWxX':
                if index == len(a) - 1:
                    i += 1
                break
    return tree, [r for r in roots if r != '-']


def _find_tree(args):
    """(content, roots) for one find invocation."""
    i = 0
    while i < len(args):
        if args[i] == '-D':
            i += 2
        elif args[i] in ('-H', '-L', '-P') or args[i].startswith(('-D', '-O')):
            i += 1
        else:
            break
    roots = []
    while i < len(args) and not args[i].startswith(('-', '(', '!', ')', ',')):
        roots.append(args[i])
        i += 1
    content = False
    for j in range(i, len(args)):
        if args[j] == '-files0-from':
            content, roots = True, ['<a -files0-from list>']
        if args[j] in ('-exec', '-execdir', '-ok', '-okdir'):
            nxt = args[j + 1] if j + 1 < len(args) else ''
            if nxt.rsplit('/', 1)[-1] not in NAME_ONLY:
                content = True
    return content, roots or ['.']


def _xargs_head(args):
    """The command xargs runs, or None (it then runs echo)."""
    value_short = set('aEILnPsd')
    value_long = {'arg-file', 'delimiter', 'max-args', 'max-lines', 'max-procs',
                  'max-chars', 'replace', 'eof', 'process-slot-var'}
    i = 0
    while i < len(args):
        a = args[i]
        if a == '--':
            i += 1
            break
        if not a.startswith('-') or a == '-':
            break
        i += 1
        if a.startswith('--'):
            if '=' not in a and a[2:] in value_long:
                i += 1
            continue
        for index, char in enumerate(a[1:], 1):
            if char in value_short:
                if index == len(a) - 1:
                    i += 1
                break
    return args[i] if i < len(args) else None


def _parallel_head(args):
    """The command GNU parallel runs, or None (it then reads commands from
    stdin). Unknown options consume nothing, so a misparse names a value as
    the command, which is not NAME_ONLY and so fails closed."""
    value_short = set('jPNnLlaIdES')
    value_long = {'jobs', 'max-procs', 'max-args', 'max-lines', 'arg-file',
                  'delimiter', 'eof', 'sshlogin', 'workdir', 'timeout', 'joblog',
                  'results', 'tmpdir', 'colsep', 'basefile', 'return', 'env'}
    i = 0
    while i < len(args):
        a = args[i]
        if a == '--':
            i += 1
            break
        if not a.startswith('-') or a == '-':
            break
        i += 1
        if a.startswith('--'):
            if '=' not in a and a[2:] in value_long:
                i += 1
            continue
        if a[1:2] in value_short and len(a) == 2:
            i += 1
    return args[i] if i < len(args) and args[i] != ':::' else None


TAR_VALUE_SHORT = set('fCTbHKLNVgXI')
TAR_VALUE_LONG = {'file', 'directory', 'files-from', 'exclude', 'exclude-from',
                  'format', 'blocking-factor', 'label', 'newer', 'after-date',
                  'newer-mtime', 'owner', 'group', 'mode', 'mtime', 'transform',
                  'xform', 'use-compress-program', 'index-file', 'listed-incremental',
                  'volno-file', 'info-script', 'new-volume-script', 'tape-length',
                  'rmt-command', 'rsh-command', 'record-size', 'to-command',
                  'exclude-tag', 'exclude-tag-under', 'exclude-tag-all',
                  'starting-file', 'quoting-style', 'level'}
# An archive written here is the tree's contents on the terminal.
TAR_STDOUT = {'-', '/dev/stdout', '/dev/stderr', '/dev/fd/1', '/dev/fd/2',
              '/proc/self/fd/1', '/proc/self/fd/2'}


def _tar_tree(args):
    """(to_stdout, roots) for one tar invocation: roots only when it creates
    an archive on stdout (no -f at all, -f -, or -O/--to-stdout). Unknown
    options consume nothing, so a misparse adds a root, never hides one."""
    state = {'create': False, 'stdout': False, 'files': [], 'cdir': None,
             'from': False}
    roots = []

    def apply(char, value):
        if char == 'f':
            state['files'].append(value)
        elif char == 'C':
            state['cdir'] = value
        elif char == 'T':
            state['from'] = True

    def mark(char):
        if char == 'c':
            state['create'] = True
        elif char == 'O':
            state['stdout'] = True

    def operand(value):
        cdir = state['cdir']
        roots.append(cdir.rstrip('/') + '/' + value
                     if cdir and not value.startswith('/') else value)

    if args and not args[0].startswith('-'):
        # Old-style bundle (`tar czf - /etc`): its value letters take the
        # following words in order.
        bundle, rest = args[0], list(args[1:])
        for char in bundle:
            mark(char)
            if char in TAR_VALUE_SHORT:
                apply(char, rest.pop(0) if rest else '')
        args = rest
    i, ended = 0, False
    while i < len(args):
        a = args[i]
        i += 1
        if ended or not a.startswith('-') or a == '-':
            operand(a)
            continue
        if a == '--':
            ended = True
            continue
        if a.startswith('--'):
            name, eq, value = a[2:].partition('=')
            if len(name) >= 3 and 'create'.startswith(name):
                state['create'] = True
            if len(name) >= 4 and 'to-stdout'.startswith(name):
                state['stdout'] = True
            if name in TAR_VALUE_LONG and not eq:
                value = args[i] if i < len(args) else ''
                i += 1
            short = {'file': 'f', 'directory': 'C', 'files-from': 'T'}.get(name)
            if short:
                apply(short, value)
            continue
        for index, char in enumerate(a[1:], 1):
            mark(char)
            if char in TAR_VALUE_SHORT:
                value = a[index + 1:]
                if not value:
                    value = args[i] if i < len(args) else ''
                    i += 1
                apply(char, value)
                break
    if not state['create']:
        return False, []
    if not (state['stdout'] or not state['files']
            or any(f in TAR_STDOUT for f in state['files'])):
        return False, []
    if state['from']:
        roots.append('<a --files-from list>')
    return True, roots


def _git_grep_roots(args):
    """Roots of `git [opts] grep --no-index ...`, or None when it is not one.
    Without --no-index git grep reads only tracked files of a repository."""
    i, cdir = 0, None
    while i < len(args) and args[i].startswith('-'):
        a = args[i]
        i += 1
        if a in ('-C', '-c', '--git-dir', '--work-tree', '--namespace'):
            if a == '-C':
                cdir = args[i] if i < len(args) else ''
            i += 1
    if i >= len(args) or args[i] != 'grep' or '--no-index' not in args[i + 1:]:
        return None
    rest = [a for a in args[i + 1:] if a != '--no-index']
    _, roots = _grep_tree(rest, 'grep', True)
    return [cdir.rstrip('/') + '/' + r if cdir and not r.startswith('/') else r
            for r in roots]


def _at_command_position(tokens, i):
    """tokens[i] runs as a command: first in the segment, or after a wrapper
    or a `VAR=value` prefix anywhere earlier (GREP_OPTIONS=-r changes grep)."""
    if not i:
        return True
    before = [t.rsplit('/', 1)[-1] for t in tokens[:i]]
    return bool(WRAPPERS.intersection(before)) or \
        any(ASSIGNMENT.match(t) for t in tokens[:i])


def _tree_findings(tokens, grep_options):
    """[(tool, full_tree_rule, roots)] for every tree head in one segment."""
    found = []
    for i, token in enumerate(tokens):
        head = token.rsplit('/', 1)[-1]
        if head not in TREE_HEADS:
            continue
        if not _at_command_position(tokens, i):
            continue
        before = [t.rsplit('/', 1)[-1] for t in tokens[:i]]
        if head == 'diff' and i and before[-1] in DIFF_PARENTS:
            continue
        args = tokens[i + 1:]
        if head in GREP_HEADS or head in IMPLICIT_RECURSIVE:
            recursive, roots = _grep_tree(args, head, grep_options)
            if recursive:
                found.append(('%s (recursive)' % head, True, roots))
        elif head == 'diff':
            tree, roots = _diff_tree(args)
            if roots:
                found.append(('diff' + (' (recursive)' if tree else ''), tree, roots))
        elif head == 'find':
            content, roots = _find_tree(args)
            if content:
                found.append(('find -exec', True, roots))
        elif head == 'xargs':
            runs = _xargs_head(args)
            if runs is not None and runs.rsplit('/', 1)[-1] not in NAME_ONLY:
                found.append(('xargs %s' % runs, True, ['<stdin>']))
        elif head == 'parallel':
            runs = _parallel_head(args)
            if runs is None or runs.rsplit('/', 1)[-1] not in NAME_ONLY:
                found.append(('parallel %s' % (runs or '(commands from stdin)'),
                              True, ['<stdin>']))
        elif head == 'tar':
            to_stdout, roots = _tar_tree(args)
            if to_stdout and roots:
                found.append(('tar (archive to stdout)', True, roots))
        elif head == 'git':
            roots = _git_grep_roots(args)
            if roots is not None:
                found.append(('git grep --no-index', True, roots))
    return found


def tree_read_verdict(tokens, deny_patterns, grep_options=False):
    """None, ('refuse', why) or ('demote', why) for one segment's argv.

    Pure. `grep_options` is True when GREP_OPTIONS appears anywhere in the
    command line (grep 3.3 on Debian 10, the compatibility floor, still honours it)."""
    demote = None
    absolute_deny = [p for p in (_norm_root(d) for d in deny_patterns
                                 if d.startswith('/')) if p]
    for tool, full, roots in _tree_findings(tokens, grep_options):
        for root in roots:
            path = _norm_root(root)
            why = None
            if root.startswith('<'):
                why = ("its file list comes from %s, so the door never sees which "
                       "tree it reads" % root.strip('<>'))
            elif path is None:
                why = ("%r is not an absolute path without '..' — the door does not "
                       "know the remote working directory or where a symlinked "
                       "parent leads" % root)
            elif _under(path, '/proc'):
                why = "%s is under /proc, where /proc/<pid>/root is / again" % path
            else:
                broad = next((b for b in BROAD_ROOTS if _under(b, path)), None)
                denied = next((d for d in absolute_deny
                               if _under(d, path) or _under(path, d)), None)
                pattern = next((d for d in deny_patterns if d.lower() in path.lower()), None)
                if broad:
                    why = "%s is or contains %s" % (path, broad)
                elif denied:
                    why = "%s overlaps the credential path %s" % (path, denied)
                elif pattern:
                    why = "%s names the credential pattern %r" % (path, pattern)
            if why:
                return ('refuse',
                        "%s reads the contents of a whole tree and %s. deny_extra "
                        "matches command text, not what a directory expands to, so "
                        "this would print every credential beneath it (.env.production, "
                        "id_rsa, an HSM PIN, ...). Name the exact files, or "
                        "narrow the root to a tree under %s. Nothing lifts this: not "
                        "a runbook, an override or break-glass"
                        % (tool, why, ' '.join(CONTENT_SAFE_TREES)))
            if demote is not None or any(_under(path, t) for t in CONTENT_SAFE_TREES):
                continue
            if full:
                demote = ('demote',
                          "%s of %s is not a read: only trees under %s are known to "
                          "hold no credential file, and a filename pattern "
                          "(.env.production, .pem, server.key) can sit in any other "
                          "tree. Narrow it to explicit files, or run it with --run "
                          "and an approval (or a runbook) so a human sees the plan"
                          % (tool, path, ' '.join(CONTENT_SAFE_TREES)))
            elif tool == 'diff' and not _looks_like_file(path):
                demote = ('demote',
                          "diff of %s is not a read: the door cannot stat it, and if "
                          "it is a directory diff compares every same-named file in "
                          "it (an .env.production before and after a rotation). Name "
                          "files with a known suffix (%s), or run it with --run and "
                          "an approval" % (path, ' '.join(
                              '.' + s for s in sorted(FILE_SUFFIXES)[:6]) + ' ...'))
    return demote


# A plain diff operand outside the log trees counts as a FILE only when its
# LAST dot-component names one of these (nginx.conf, compose.yaml), or is a
# backup suffix right after one (nginx.conf.bak). `postfix.orig`, `app.bak`,
# `conf.d`, `app.service.d`, `sources.list.d.bak` and every suffix-less name
# are taken to be directories: when unsure, demote.
FILE_SUFFIXES = {'conf', 'cfg', 'cf', 'cnf', 'ini', 'yaml', 'yml', 'json', 'toml',
                 'xml', 'txt', 'log', 'service', 'socket', 'timer', 'mount',
                 'target', 'path', 'rules', 'list', 'sources', 'sh', 'py', 'sql',
                 'csv', 'md', 'html', 'js', 'css', 'properties', 'zone', 'crt'}


BACKUP_SUFFIXES = {'bak', 'orig', 'old', 'save', 'dist', 'prev', 'new', 'backup'}


def _looks_like_file(path):
    parts = [p.lower() for p in path.rsplit('/', 1)[-1].split('.')[1:]]
    if not parts:
        return False
    if parts[-1] in FILE_SUFFIXES:
        return True
    return parts[-1] in BACKUP_SUFFIXES and len(parts) >= 2 and parts[-2] in FILE_SUFFIXES


# ---------------------------------------------------------------------------
# Raw devices, kernel and process memory, credential files ("path reads").
#
# A raw block device holds every file on the disk, /dev/mem and /proc/kcore
# are physical and kernel memory, /proc/<pid>/environ is a process's secrets:
# `cat /dev/vda`, `strings -n 8 /dev/sda1` and `cat /proc/1/environ` name no
# deny_extra path, and without this check they are READS. Some credential files
# are also shaped so that a substring cannot match them precisely: `*.key`
# against jq's `.key`, `ssh_host_*_key` against its `.pub`, `.env` against
# `chmod 0600 /opt/x/.env` in policies/secret-perms.yaml. They are matched
# here, by basename.
#
# Every path a CONTENT_HEADS command at command position reads (its operands,
# `if=`/`--file=` values, attached option values; for grep the files and -f
# values, never the pattern; for jq not the filter), and every `<` source
# whatever the head, on every tier:
#   REFUSE (nothing lifts it, exactly like deny_extra) when it
#     - is under /dev, except /dev/null and DEV_STREAMS (a block device is the
#       whole disk, /dev/mem and /dev/kmem are memory, /dev/fd/N and
#       /dev/stdin are whatever is open; the door cannot tell them apart by
#       name, so it does not try);
#     - is /proc/kcore or has a PROC_SECRETS component at any depth
#       (/proc/1/environ, /proc/self/task/7/mem, /proc/1/fd/3,
#       /proc/1/map_files/...): memory and open handles have no name the
#       deny list can see;
#     - has a `..` component: a symlinked parent makes lexical normalisation
#       wrong (/var/run is /run, so /var/run/../proc/kcore is /proc/kcore);
#     - names a credential file (_credential_file): an ssh host private key
#       (ssh_host_<alg>_key anywhere in the name, any copy of it; only
#       `_key.pub`/`_key-cert.pub` endings are public), a `.key` file (x.key,
#       x.key.old, .key), an environment file (.env, .envrc, .env-prod,
#       .env_prod, prod.env, prod.env.bak), a `.private` file (mail.private,
#       mail.private.bak), or k3s's registries.yaml (registry passwords).
#   `ps` with a BSD `e` (ps axe, ps eww, ps -p 1 e) or an env format field
#   prints every process's environment: refused like /proc/<pid>/environ. So
#   is any ps outside a strict allowlist with an `e` anywhere in its argv
#   (`-u e`, `-eux`, `-e -p 0`, `-e -o x`): when the UNIX parse fails procps
#   reparses the whole argv as BSD. Outside it without an `e` (`-u nobody`,
#   `-C nginx`) it is not a read (_ps_verdict).
#   kubectl/k3s/helm/crictl/docker read the files named by -f/--filename/
#   --values/--env-file/--set-file/-k/--from-file: those get the same rule.
#   DEMOTE (not a read: --run and an approval) for DEV_STREAMS (unbounded
#     output), /proc/<pid>/root|cwd (another mount namespace's whole tree; the
#     path behind it still meets deny_extra as text, and a device or memory
#     path behind it is refused), /proc/kmsg (reading consumes the kernel log)
#     and anything under /sys.
# A relative path is also checked as if the cwd were `/`: --in runs in a
# container whose WORKDIR is often `/`, where `proc/1/environ` is the real one.
#
# Any command at all, any tier: a path that contains a deny pattern only once
# normalised (`/var/lib/rancher/k3s//server/token`) is refused. Credential
# FILENAMES bind only content readers: `ls -l`, `stat` and `find -name` on an
# ssh host key or an .env stay reads, and secret-perms.yaml can chmod them.
#
# is_read() applies both classes to every allowlisted read except the heads
# that print only names and metadata (METADATA_HEADS: `ls /dev`, `stat
# /dev/sda`, `smartctl -H /dev/sda`, `df /dev/sda1`).
#
# Residuals: a symlink already on the host that leads into /dev or /proc;
# `cd /dev && ...` (cd is never a read, so that is an approved mutation);
# interpreters (awk, sed, perl, python3) and network tools sending a file
# elsewhere, which are never reads and are left to the approval.
# ---------------------------------------------------------------------------

CONTENT_HEADS = GREP_HEADS | IMPLICIT_RECURSIVE | {
    'cat', 'tac', 'nl', 'head', 'tail', 'more', 'less', 'most', 'strings', 'od',
    'xxd', 'hexdump', 'hd', 'base64', 'base32', 'basenc', 'zcat', 'zless', 'zmore',
    'bzcat', 'xzcat', 'lzcat', 'zstdcat', 'gzip', 'gunzip', 'bzip2', 'xz', 'zstd',
    'lz4', 'cut', 'sort', 'uniq', 'paste', 'join', 'fold', 'fmt', 'pr', 'expand',
    'unexpand', 'column', 'comm', 'cmp', 'diff', 'sdiff', 'rev', 'iconv', 'jq',
    'yq', 'dd', 'xargs', 'parallel'}
# Not openssl: `-CAkey ca.key` signs with a key without printing it (an
# approved mutation); its read forms still get is_read's device check.
# Heads that print only names and metadata, whatever their operands. Not
# kubectl/docker/helm/journalctl/systemctl/ps: they read files they are given.
METADATA_HEADS = {'ls', 'stat', 'df', 'du', 'lsblk', 'findmnt', 'file', 'readlink',
                  'realpath', 'lsattr', 'getfacl', 'lsof', 'smartctl', 'mdadm',
                  'find', 'echo', 'printenv', 'dmesg', 'mount', 'swapon', 'ip', 'ss',
                  'netstat', 'sysctl'}
# Heads whose file-naming options read the file (`kubectl get -f /dev/sda`).
FILE_OPTION_HEADS = {'kubectl', 'k3s', 'helm', 'crictl', 'docker', 'oc'}
FILE_OPTIONS = {'-f', '-k', '--filename', '--values', '--env-file', '--set-file',
                '--kustomize', '--from-file', '--from-env-file', '--file'}
DEV_STREAMS = ('/dev/zero', '/dev/full', '/dev/random', '/dev/urandom')
PROC_SECRETS = {'kcore', 'environ', 'mem', 'pagemap', 'fd', 'map_files'}
PROC_ALIASES = ('root', 'cwd')
SSH_HOST_KEY = re.compile(r'ssh_host_[a-z0-9]+_key', re.I)
ENV_FILE = re.compile(r'\.env([._-]|rc$|$)')
KEY_FILE = re.compile(r'\.key(\.|$)')
PRIVATE_FILE = re.compile(r'\.private(\.|$)')
# Substrings of a normalised path read as content (chmod of it stays legal:
# secret-perms.yaml tightens registries.yaml's mode).
CONTENT_CREDENTIAL_PATHS = ('rancher/k3s/registries.yaml',)
# ps: a STRICT allowlist. procps parses argv as UNIX options and, if that
# fails for ANY reason (an unknown user, a pid out of range, an unknown format
# field, a stray `-`), reparses the WHOLE argv as BSD, where any `e` (`ps -eux`
# is e, u, x) prints every process's environment. The door cannot know what
# exists on the host, so ps is a read only when every token is one of these.
# Never wider than ps's read grammar (OPTIONS['ps']: a e f l u: p: o: C:
# --pid: --format: --forest; `a` excluded). A wider allowlist grants nothing
# and lets a leak through as merely mutating: `ps -eT --forest` fails the
# thread check, is reparsed as BSD and printed every environment.
PS_FLAGS = set('efl')                            # -e -ef -el -elf
PS_LONG_FLAGS = {'--forest'}
PS_BSD_WORDS = {'aux', 'auxww', 'auxw', 'ax', 'axu', 'axww', 'axf', 'auxf', 'axjf'}
PS_FIELDS = {'pid', 'ppid', 'pgid', 'sid', 'tid', 'lwp', 'nlwp', 'uid', 'user', 'ruser',
             'euser', 'gid', 'group', 'comm', 'args', 'cmd', 'command', 'etime',
             'etimes', 'lstart', 'start', 'stime', 'time', 'cputime', 'pcpu', '%cpu',
             'pmem', '%mem', 'rss', 'rsz', 'vsz', 'vsize', 'sz', 'stat', 'state', 's',
             'tty', 'tt', 'nice', 'ni', 'pri', 'psr', 'wchan', 'class', 'cls', 'cgroup',
             'label', 'f', 'flags'}
# Every field is in `ps L` of procps-ng 3.3.15 (Debian 10, the compatibility floor);
# an unknown field fails the UNIX parse. Pinned by tests/test_door_device_reads.py
# against tests/data/procps_oracle/buster-psL.txt.
PS_PIDS = re.compile(r'[1-9][0-9]{0,6}(,[1-9][0-9]{0,6})*')
PS_IDS = re.compile(r'(0|[1-9][0-9]{0,9})(,(0|[1-9][0-9]{0,9}))*')
PS_HEADER = re.compile(r'[A-Za-z0-9_%-]*')
PS_PID_MAX = 4194304          # Linux PID_MAX_LIMIT
PS_ID_MAX = 4294967294        # (uid_t)-1 is "no id"


def _ps_value_ok(kind, value):
    if kind == 'pid':
        return bool(PS_PIDS.fullmatch(value)) and \
            all(int(v) <= PS_PID_MAX for v in value.split(','))
    if kind == 'id':
        return bool(PS_IDS.fullmatch(value)) and \
            all(int(v) <= PS_ID_MAX for v in value.split(','))
    if kind == 'format':
        for field in value.split(','):
            name, eq, header = field.partition('=')
            if eq and not PS_HEADER.fullmatch(header):
                return False
            if name.lower() not in PS_FIELDS:
                return False
        return True
    return False    # -C and anything else: never a read


# option -> kind of value
PS_VALUE_SHORT = {'p': 'pid', 'u': 'id', 'o': 'format', 'C': 'command'}
# Not --sort/-k: ps's read grammar (OPTIONS) has no sort, so allowing it here
# would grant nothing and would let `ps -e --sort pid` escape the refusal.
PS_VALUE_LONG = {'pid': 'pid', 'format': 'format'}


# UNIX flags that choose an output format. With an -o/-O/--format list too,
# procps 3.3.15 and 4.0.2 both fail ("conflicting format options") and
# reparse argv as BSD: `ps -ef -o args` printed every environment
# (tools/procps-oracle.sh, tests/data/procps_oracle/).
PS_FORMAT_FLAGS = set('fl')


def _ps_in_grammar(args):
    if any(a in PS_BSD_WORDS for a in args):
        # a BSD word only alone: `aux -ef` and `axu -e -o args` fail the parse
        return len(args) == 1
    formats = flags = 0
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a in PS_LONG_FLAGS:
            continue
        if a.startswith('--'):
            name, eq, value = a[2:].partition('=')
            kind = PS_VALUE_LONG.get(name)
            if not kind:
                return False          # `--`, unknown long options
            if not eq:
                if i >= len(args):
                    return False
                value = args[i]
                i += 1
            if not _ps_value_ok(kind, value):
                return False
            formats += kind == 'format'
            continue
        if a.startswith('-'):
            if a == '-':
                return False
            for index, char in enumerate(a[1:], 1):
                if char in PS_FLAGS:
                    flags += char in PS_FORMAT_FLAGS
                    continue
                kind = PS_VALUE_SHORT.get(char)
                if not kind:
                    return False
                value = a[index + 1:]
                if not value:
                    if i >= len(args):
                        return False
                    value = args[i]
                    i += 1
                if not _ps_value_ok(kind, value):
                    return False
                formats += kind == 'format'
                break
            continue
        return False      # any other word
    # At most one format source: one -o/-O/--format list, or format flags.
    return formats <= 1 and not (formats and flags)


def _ps_verdict(args):
    """None when every ps token is in the allowlist above. Otherwise ps is
    not a read: 'refuse' if an `e` appears anywhere in its argv once leading
    dashes are stripped (a reparse as BSD prints environments), else 'demote'.
    An env field is never in PS_FIELDS, so `-o pid,environ` is refused."""
    if _ps_in_grammar(args):
        return None
    if any('e' in a.lstrip('-').lower() for a in args):
        return 'refuse'
    return 'demote'


def _file_option_values(args):
    out = []
    for n, a in enumerate(args):
        name, eq, value = a.partition('=')
        if name in FILE_OPTIONS:
            out.append(value if eq else (args[n + 1] if n + 1 < len(args) else ''))
        elif a[:2] in ('-f', '-k') and len(a) > 2 and not a.startswith('--'):
            out.append(a[2:])
    return out


JQ_TWO_WORDS = {'--arg', '--argjson', '--slurpfile', '--rawfile'}


def _read_args(head, args):
    """The arguments of one command that may name what it reads."""
    if head in GREP_HEADS or head in IMPLICIT_RECURSIVE:
        _, files, pattern_files = _grep_args(args, head, True)
        return files + pattern_files
    if head in ('jq', 'yq'):
        # The program is the first positional word unless -f/--from-file
        # names it; `--arg/--argjson/--slurpfile/--rawfile NAME VALUE` always
        # take exactly two words, even `-x` (and a slurped file is a read).
        # `-f FILE`, and any short cluster holding f (`-rf FILE`)
        from_file = '--from-file' in args or any(
            a.startswith('-') and not a.startswith('--') and 'f' in a[1:]
            for a in args)
        out, prog, ended, i = [], from_file, False, 0
        while i < len(args):
            a = args[i]
            i += 1
            if not ended and a == '--':
                ended = True
            elif not ended and a in JQ_TWO_WORDS:
                out += args[i:i + 2]
                i += 2
            elif not ended and a.startswith('-') and a != '-':
                out.append(a)
            elif not prog:
                prog = True
            else:
                out.append(a)
        return out
    return list(args)


def _path_candidates(token):
    """Every spelling of a path one argument can carry."""
    out = [token]
    if '=' in token:
        out.append(token.split('=', 1)[1])        # if=/dev/sda, --file=/x
    if token.startswith('-') and '/' in token:
        out.append(token[token.index('/'):])      # -f/proc/1/environ
    return [c for c in out if c]


def _path_class(path):
    """None, ('refuse', why) or ('demote', why) for one path a command reads."""
    if '..' in path.split('/'):
        return ('refuse', "%r has a '..' component: a symlinked parent makes it "
                          "unresolvable (/var/run/../proc is /proc)" % path)
    norm = _norm_root(path if path.startswith('/') else '/' + path)
    if norm is None or norm == '/dev/null':
        return None
    if _under(norm, '/dev'):
        if norm in DEV_STREAMS:
            return ('demote', "%s never ends" % norm)
        return ('refuse', "%s is a device: a block device is the whole disk, "
                          "/dev/mem is memory" % norm)
    if _under(norm, '/proc'):
        parts = norm.split('/')[2:]
        if PROC_SECRETS.intersection(parts):
            return ('refuse', "%s is kernel or process memory, environment or an "
                              "open file handle" % norm)
        for alias in PROC_ALIASES:
            if alias in parts:
                inner = _path_class('/' + '/'.join(parts[parts.index(alias) + 1:]))
                if inner and inner[0] == 'refuse':
                    return inner
                return ('demote', "%s is another mount namespace's tree" % norm)
        if norm == '/proc/kmsg':
            return ('demote', "reading /proc/kmsg consumes the kernel log")
        return None
    if _under(norm, '/sys'):
        return ('demote', "%s is under /sys (device registers, firmware tables)" % norm)
    return None


def _credential_file(path):
    """What credential file a content read of `path` would print, or None."""
    base = path.rstrip('/').rsplit('/', 1)[-1].lower()
    if SSH_HOST_KEY.search(base) and not base.endswith(('_key.pub', '_key-cert.pub')):
        return 'an ssh host private key'
    if ENV_FILE.search(base):
        return 'an environment file'
    # jq filters (`.key`, `.data.key`) never get here: _read_args drops them.
    if KEY_FILE.search(base) or PRIVATE_FILE.search(base):
        return 'a private key file'
    if any(c in _lexical(path).lower() for c in CONTENT_CREDENTIAL_PATHS):
        return 'a credential file'
    return None


def _lexical(path):
    """`path` with `//`, `/./` and `..` resolved lexically: for MATCHING deny
    patterns only, never to decide that a path is safe."""
    norm = posixpath.normpath(path)
    return '/' + norm.lstrip('/') if path.startswith('/') else norm


def path_read_verdict(tokens, deny_patterns):
    """None, ('refuse', why) or ('demote', why) for one segment's argv.

    Pure. See the block comment above for what is read and the rule."""
    reads = []    # (tool, path) pairs read as content
    ps_demote = None
    for i, token in enumerate(tokens):
        head = token.rsplit('/', 1)[-1]
        if head in CONTENT_HEADS and _at_command_position(tokens, i):
            reads += [(head, a) for a in _read_args(head, tokens[i + 1:])]
        if head in FILE_OPTION_HEADS and _at_command_position(tokens, i):
            reads += [(head, a) for a in _file_option_values(tokens[i + 1:])]
        ps = head == 'ps' and _at_command_position(tokens, i) and \
            _ps_verdict(tokens[i + 1:])
        if ps == 'refuse':
            return ('refuse', "this ps is outside the read allowlist and has an `e` "
                              "in its argv: a BSD `e` (or a whole argv procps "
                              "reparses as BSD after any UNIX parse failure) prints "
                              "every process's environment, like /proc/<pid>/environ. "
                              "Nothing lifts this: not a runbook, an override or "
                              "break-glass. `ps -ef`, `ps aux` and `ps -eo ...` are "
                              "reads")
        if ps == 'demote':
            ps_demote = ('demote', "this ps is not a read: only an allowlisted form "
                                   "is (flags -e -f -F -l -y -H -w -L -T -j, aux/ax "
                                   "words, numeric -p/-u/-g, known -o/--sort "
                                   "fields). If its UNIX parse fails procps reparses "
                                   "argv as BSD options, where `e` prints every "
                                   "environment. Use `ps -u <uid>`, `ps -p <pid>` or "
                                   "`ps -ef | grep NAME`, or run it with --run and "
                                   "an approval")
        if '<' in token and not token.startswith('<<'):
            source = token[token.index('<') + 1:].lstrip('>&')
            if not source and i + 1 < len(tokens):
                source = tokens[i + 1]
            reads.append(('a < redirection', source))
    demote = ps_demote
    for tool, arg in reads:
        for path in _path_candidates(arg):
            kind = _credential_file(path)
            if kind:
                return ('refuse',
                        "%s reads %s, which is %s. deny_extra cannot name it "
                        "precisely, so it is matched by name here. Nothing lifts "
                        "this: not a runbook, an override or break-glass"
                        % (tool, path, kind))
            verdict = _path_class(path)
            if verdict and verdict[0] == 'refuse':
                return ('refuse',
                        "%s reads %s: %s. That is every secret on the host with no "
                        "path deny_extra can see. Nothing lifts this: not a "
                        "runbook, an override or break-glass" % (tool, path, verdict[1]))
            if verdict and demote is None:
                demote = ('demote', "%s of %s is not a read: %s. Run it with --run "
                                    "and an approval so a human sees the plan"
                          % (tool, path, verdict[1]))
    lowered = [d.lower() for d in deny_patterns]
    for token in tokens:
        for path in _path_candidates(token):
            norm = _lexical(path).lower()
            hit = next((d for d in lowered if d in norm), None) if norm != path.lower() else None
            if hit:
                return ('refuse', "%s names the credential pattern %r once "
                                  "normalised to %s" % (path, hit, norm))
    return demote
