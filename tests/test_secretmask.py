"""secretmask tests — secret VALUES never leave the door.

Every output path (vpsexec display, --compare, the journal, `vpsexec last`,
`vpscfg logs`) is proven end-to-end with a fake host that prints a secret.
The negative tests matter most: a masker that crashes must withhold, not
pass through; hostile input must finish in bounded time; the shapes known to
leak (a k8s env name/value pair) must stay masked.
"""
import contextlib
import io
import json
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from vpscfg import journal, logsearch, secretmask, vpsexeclog  # noqa: E402
from vpscfg.secretmask import MASK, mask  # noqa: E402

try:  # module import (not `from ... import Class`): its tests are not re-discovered here
    import tests.test_vpsexec as tv  # noqa: E402  unittest discover from the repo root
except ImportError:
    import test_vpsexec as tv  # noqa: E402  pytest rootdir/rootless import of tests/

DENY = tv.DENY

PW = "Hunt3r2-Zq9"  # the canary: must never appear in any output


class MaskShapesTest(unittest.TestCase):
    """Each shape a secret has actually been seen in on the fleet."""

    def assertMasked(self, text, *keep):
        out = mask(text)
        self.assertNotIn(PW, out, "secret survived: %r" % out)
        self.assertIn(MASK, out)
        for k in keep:
            self.assertIn(k, out)
        return out

    def test_env_file_and_export(self):
        self.assertMasked("DB_PASSWORD=%s\nHOST=db" % PW, "DB_PASSWORD=", "HOST=db")
        self.assertMasked("export API_TOKEN='%s'" % PW, "API_TOKEN")
        self.assertMasked("DB_PASS=%s with spaces" % PW)
        self.assertNotIn("spaces", mask("DB_PASS=%s with spaces" % PW))

    def test_k8s_env_name_value_pair_leak(self):
        text = ("        - name: DB_PASSWORD\n"
                "          value: %s\n"
                "        - name: DB_HOST\n"
                "          value: pg.shop.svc\n" % PW)
        self.assertMasked(text, "name: DB_PASSWORD", "pg.shop.svc")

    def test_k8s_env_block_scalar_value(self):
        text = "- name: API_SECRET\n  value: |\n    %s\n- name: X\n  value: y" % PW
        self.assertMasked(text, "value: y")

    def test_k8s_env_json(self):
        text = json.dumps([{"name": "DB_PASSWORD", "value": PW}, {"name": "HOST", "value": "h"}])
        self.assertMasked(text, '"h"')
        rev = '{"value": "%s", "name": "PG_PASSWORD"}' % PW
        self.assertMasked(rev)

    def test_k8s_secret_yaml_and_json(self):
        self.assertMasked("apiVersion: v1\nkind: Secret\ndata:\n  anything: %s\n"
                          "  cert: |\n    %s\nmetadata:\n  name: keep-me\n" % (PW, PW),
                          "anything:", "keep-me")
        self.assertMasked(json.dumps({"kind": "Secret", "data": {"u": PW}}))

    def test_docker_inspect_env_and_proc_environ(self):
        self.assertMasked('"Env": ["POSTGRES_PASSWORD=%s", "PATH=/usr/bin"]' % PW, "PATH=/usr/bin")
        self.assertMasked("A=1\x00SECRET_KEY=%s\x00B=2" % PW, "B=2")

    def test_urls_dsns_and_connection_strings(self):
        self.assertMasked("postgres://app:%s@db:5432/app" % PW, "postgres://app:", "@db:5432")
        self.assertMasked("host=db user=app password=%s dbname=x" % PW, "dbname=x")
        self.assertMasked("Server=x;Password=%s;User=y" % PW, "User=y")
        self.assertMasked("https://h/cb?token=%s&x=1" % PW, "x=1")

    def test_argv_flags_and_headers(self):
        self.assertMasked("python app.py --db-password %s --port 80" % PW, "--port 80")
        self.assertMasked("app --api-key=%s" % PW)
        self.assertMasked("curl -u admin:%s https://x" % PW, "admin:")
        self.assertMasked("Authorization: Bearer %s" % PW)
        self.assertMasked("authorization: Basic %s" % PW)
        self.assertMasked("requirepass %s" % PW)
        self.assertMasked("machine h login bob password %s" % PW)

    def test_pem_private_key_including_truncated(self):
        full = "-----BEGIN " "RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\ntail" % PW
        self.assertMasked(full, "tail")
        # output capped mid-key: no END line, still masked to the end
        self.assertMasked("-----BEGIN " "OPENSSH PRIVATE KEY-----\n%s\n%s" % (PW, PW))

    def test_vault_init_output(self):
        self.assertMasked("Unseal Key 1: %s\nInitial Root Token: %s" % (PW, PW))

    def test_known_token_formats_without_context(self):
        for tok in ("ghp_" + "a" * 36, "AKIA" + "B" * 16, "hvs." + "c" * 24,
                    "xoxb-" + "1" * 20, "sk-ant-" + "d" * 30, "glpat-" + "e" * 20,
                    "eyJhbGciOiJIUzI1." "eyJzdWIiOiIxMjM0.abcdefghijk"):
            out = mask("found %s here" % tok)
            self.assertNotIn(tok, out)
            self.assertIn("found", out)


class ReviewRegressionTest(unittest.TestCase):
    """Every bypass a security review demonstrated. Each input
    must come out without the canary."""

    CASES = {
        # 1. the incident shape, as kubectl -o json (pretty, reversed, escaped)
        "json_env_pretty": '{\n  "name": "DB_PASSWORD",\n  "value": "%s"\n}',
        "json_env_reversed": '{\n  "value": "%s",\n  "name": "PG_PASSWORD"\n}',
        "json_env_escaped": '"last-applied": "{\\"env\\":[{\\"name\\":\\"DB_PASSWORD\\",\\"value\\":\\"%s\\"}]}"',
        # 2. mid-line values inside strings and structures
        "env_semicolon": '"Env": ["X=1","POSTGRES_PASSWORD=S3cr;%s"]',
        "env_comma": '"POSTGRES_PASSWORD=S3cr,%s"',
        "env_space": '"POSTGRES_PASSWORD=S3cr3t %s"',
        "json_list_value": '"passwords": ["%s"]',
        "json_object_value": '"password": {"value": "%s"}',
        # 3. vault
        "vault_kv_table": "====== Data ======\nKey         Value\n---         -----\ndb          %s",
        "vault_read_table": "Key  Value\n---  -----\npassword            %s",
        "vault_legacy_token": "Key  Value\n---  -----\ntoken                s.%s",
        "vault_kv2_json": '{"data":{"data":{"db":"%s"}}}',
        # 4. redis and friends
        "docker_cmd_pretty": '"Cmd": [\n  "redis-server",\n  "--requirepass",\n  "%s"\n]',
        "docker_cmd_min": '"Cmd":["redis-server","--requirepass","%s"]',
        "compose_list": "    command:\n      - redis-server\n      - --requirepass\n      - %s",
        "redis_config_get": '1) "requirepass"\n2) "%s"',
        "redis_config_raw": "requirepass\n%s",
        "redis_cli_a": "redis-cli -a %s ping",
        "mysql_glued": "mysql -uroot -p%s",
        "sshpass": "sshpass -p %s ssh host",
        # 5. k3s unit continuation
        "k3s_unit": "ExecStart=/usr/local/bin/k3s \\\n    server \\\n        '--token' \\\n        '%s' \\",
        # 8. hashes
        "htpasswd_yaml": '        users:\n          - "admin:$apr1$xyz$%s"',
        "basicauth_label": "traefik.http.middlewares.admin-basic.basicauth.users=admin:$$apr1$$H6uskkkW$$%s",
        "bcrypt": "admin:$2y$05$%sabcdefghijk",
        "shadow": "root:$6$%s$abc:19000:0:99999:7:::",
        # 9. key names, XML
        "pgpass": "PGPASS=%s", "db_pw": "DB_PW=%s", "hmac": "HMAC=%s", "private": "PRIVATE=%s",
        "private_key": "PRIVATE_KEY=%s",
        "bare_key": "KEY=%s", "jwt_signing": "- name: JWT_SIGNING\n  value: %s",
        "xml": "<password>%s</password>",
        # 10. url userinfo with / and @
        "url_slash": "psql postgres://app:ab/cd+%s@db:5432/app",
        "url_at": "postgres://app:S3cr3t@%s@db/app",
        # 13. evasions
        "ansi": "\x1b[32mDB_PASSWORD\x1b[0m=%s",
        "zero_width": "DB_PASSWORD​=%s",
        "fullwidth": "DB_PASSWORD＝%s",
        "two_line_yaml": "password:\n  %s",
        "curl_empty_user": "curl -u :%s https://x",
        "mysql_dsn": "user:%s@tcp(db:3306)/x",
        "cookie": "Cookie: session=%s",
        "set_cookie": "Set-Cookie: sid=%s; Path=/",
    }

    CASES.update({
        # verification pass (v2) findings
        "unbalanced_brace_then_pair": 'msg="x" token={\nroot 12 psql host=db password=%s\n',
        "unbalanced_bracket_then_pair": "log: config token=[ loaded\nuser=app password=%s sslmode=disable",
        "bracket_unquoted": "x password=[%s]",
        "brace_unquoted": "x auth={user:admin,pass:%s}",
        "camel_token_value": "tokenValue: %s", "camel_secret_value": "secretValue: %s",
        "camel_password_hash": "passwordHash=%s", "camel_admin_hash": "adminPasswordHash: %s",
        "camel_api_key_value": "apiKeyValue=%s", "camel_private_key_pem": "privateKeyPem: %s",
        "authkey": "AUTHKEY=%s", "tailscale": "TS_AUTHKEY=tskey-auth-k%s-abcdef",
        "go_map_labels": "map[com.docker.compose.project:app db_password:%s]",
        "go_map_secret": "map[password:" "%s]",
        "bare_colon_env": "env DB_PASSWORD:%s x",
        "vault_kv1_table": "Key   Value\n---   -----\nrefresh_interval    768h\nadmin               %s",
        "vault_kv1_json": '{"request_id":"x","lease_duration":2764800,"data":{"admin":"%s"}}',
        "compose_single_quoted": "    command: ['redis-server', '--requirepass', '%s']",
        "spaced_env": "CF_API_TOKEN %s",
        "redis_auth": "redis> AUTH %s",
        "pg_alter_user": "LOG:  statement: ALTER USER app WITH PASSWORD '%s'",
        "nginx_auth": 'proxy_set_header Authorization "Basic %s";',
        "nginx_api_key": "proxy_set_header X-Api-Key %s;",
        "vertical_tab": "DB_PASSWORD\v=%s",
    })

    def test_every_review_bypass_is_closed(self):
        leaked = {}
        for name, template in self.CASES.items():
            out = mask(template % PW)
            if PW in out:
                leaked[name] = out
        self.assertEqual(leaked, {})

    def test_known_formats_without_context(self):
        for tok in ("K10" + "ab12" * 8 + "::server:" + PW,
                    "AGE-SECRET-KEY-1" + "Q" * 58,
                    "SCRAM-SHA-256$4096:" + PW,
                    "md5" + "0123456789abcdef" * 2):
            self.assertNotIn(tok, mask("x %s y" % tok), tok)

    def test_large_secret_json_is_masked_whole(self):
        big = json.dumps({"kind": "Secret", "data": {"release": PW * 8000, "tls.key": PW}})
        self.assertNotIn(PW, mask(big))


class MaskTagsTest(unittest.TestCase):
    """<masked:tag> — distinct values stay distinguishable within a run
    (--compare must not report false agreement), identical values agree."""

    def test_same_value_same_tag_different_value_different_tag(self):
        a, b, c = (mask(t, tags=True) for t in ("PW=one", "PW=one", "PW=two"))
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_tags_are_off_by_default_no_guessing_oracle(self):
        """Verification finding 5: an injected `password=<guess>` log line
        tagged like the real secret confirms the guess. Default output
        carries no tags; untag() strips them."""
        out = mask("DB_PASSWORD=" "Summer2026!\npassword=Summer2026!\n")
        self.assertEqual(out.count("<masked>"), 2)
        self.assertNotIn("<masked:", out)
        self.assertNotIn("<masked:", secretmask.untag(mask("PW=x", tags=True)))

    def test_idempotent_with_tags(self):
        once = mask('password = "S3cr3t"\n"k": {"password": "x"}', tags=True)
        self.assertEqual(mask(once, tags=True), once)

    def test_tag_is_not_a_bare_hash_of_the_value(self):
        import hashlib
        out = mask("PW=%s" % PW)
        self.assertNotIn(hashlib.sha256(PW.encode()).hexdigest()[:8], out)


class MaskPreservesTest(unittest.TestCase):
    """Masking must not eat the output an incident read is for."""

    def test_image_tags_and_addresses_are_not_pairs(self):
        """tokenmint:v1.1.0 is an image; masking it hid version drift and made
        fingerprints flap (review finding 7)."""
        for text in ("registry.example.com/trusted/tokenmint:v1.1.0",
                     "secretsvc-web\tsecretsvc-web:latest\tUp 3 days",
                     "passwordcheck:latest",
                     '        url: "http://secretsvc-web:8080"'):
            self.assertEqual(mask(text), text)

    def test_fleet_container_names_are_not_secret_keys(self):
        for text in ('"passwordcheck-pwned": {"image": "sha256:abc"}',
                     "secretsvc-prod=running", "tokenmint=v1", "saltstack=ok",
                     '"data-tokenizer": {"image": "x"}'):
            self.assertEqual(mask(text), text)

    def test_secret_object_keeps_structure(self):
        out = mask('"password": {"value": "%s", "n": 3}' % PW)
        self.assertNotIn(PW, out)
        self.assertIn('{"value": "<masked>", "n": ', out)

    def test_ordinary_output_is_untouched(self):
        for text in ("Filesystem  Size  Used\n/dev/sda1  40G  12G",
                     "nginx.service - active (running)",
                     "password authentication failed for user \"app\"",
                     "bypass=true compass: north author=me",
                     'PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8"'):
            self.assertEqual(mask(text), text)

    def test_variable_references_are_kept(self):
        text = "value: ${DB_PASSWORD}\npassword: $PW"
        self.assertEqual(mask(text), text)

    def test_idempotent(self):
        once = mask("DB_PASSWORD=%s\npostgres://a:%s@h" % (PW, PW))
        self.assertEqual(mask(once), once)

    def test_empty_and_none_pass_through(self):
        self.assertEqual(mask(""), "")
        self.assertIsNone(mask(None))


class PrivateAddressListTest(unittest.TestCase):
    """`private` stays a secret key. Only a value that is strictly a list of
    IP addresses/CIDRs under a key whose ONLY secret word is bare `private`
    is shown: a firewall script's PRIVATE="10.0.0.0/8 ..." allowlist."""

    ALLOWLIST = 'PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8"'

    def test_firewall_private_cidr_line_is_preserved_verbatim(self):
        for text in (self.ALLOWLIST, "PRIVATE=10.0.0.0/8", "export PRIVATE='10.0.0.0/8,fd00::/8'",
                     "private: 10.0.0.0/8, 192.168.1.1", "x PRIVATE=\"::1/128 10.1.2.3\" y"):
            self.assertEqual(mask(text), text)

    def test_non_address_values_stay_masked(self):
        cases = {
            "word": "PRIVATE=%s" % PW,
            "quoted_word": 'PRIVATE="%s"' % PW,
            "stripe_live": "STRIPE_PRIVATE=sk_live_%s0123456789" % PW,
            "stripe_plain": "STRIPE_PRIVATE=%s" % PW,
            "cidr_then_secret_quoted": 'PRIVATE="10.0.0.0/8 %s"' % PW,
            "cidr_then_secret_comma": 'PRIVATE="10.0.0.0/8,%s"' % PW,
            "cidr_then_secret_line": "PRIVATE=10.0.0.0/8 %s" % PW,
            "cidr_then_secret_unquoted_comma": "PRIVATE=" "10.0.0.0/8,%s" % PW,
            "cidr_then_secret_yaml": "private: 10.0.0.0/8 %s" % PW,
            "secret_then_cidr": 'PRIVATE="%s 10.0.0.0/8"' % PW,
            "private_key": "PRIVATE_KEY=%s" % PW,
            "private_token": "PRIVATE_TOKEN=" "%s" % PW,
            "private_key_mid_line": "x PRIVATE_KEY=%s y" % PW,
        }
        leaked = dict((k, mask(v)) for k, v in cases.items() if PW in mask(v))
        self.assertEqual(leaked, {})

    def test_near_miss_addresses_stay_masked(self):
        for value in ("10.0.0.1x", "10.0.0.256", "10.0.0.0/33", "10.0.0", "010.0.0.1",
                      "fe80::1%eth0", "192.0.2.4/8/8", "deadbeef", "::g", '"10.0.0.0/8',
                      '"10.0.0.0/8\'', "10.0.0.0/8 ,, 10.0.0.1", "10.0.0.0/8;id"):
            out = mask("PRIVATE=%s" % value)
            self.assertIn(MASK, out, value)

    def test_addresses_under_strong_keys_stay_masked(self):
        """The exemption is for bare `private` only: an address-shaped value
        under a password/key/token name is still that secret's value."""
        for key in ("PRIVATE_KEY", "PASSWORD", "DB_PASSWORD", "PRIVATE_TOKEN", "privateKey",
                    "PRIVKEY", "API_KEY", "PRIVATE_SECRET"):
            self.assertIn(MASK, mask("%s=10.0.0.1" % key), key)
            self.assertIn(MASK, mask('%s="10.0.0.0/8 172.16.0.0/12"' % key), key)

    def test_pem_block_still_masked(self):
        pem = ("PRIVATE=\"10.0.0.0/8\"\n-----BEGIN " "PRIVATE KEY-----\n%s\n"
               "-----END PRIVATE KEY-----" % PW)
        out = mask(pem)
        self.assertNotIn(PW, out)
        self.assertIn('PRIVATE="10.0.0.0/8"', out)

    def test_oversized_address_list_is_masked(self):
        """Past the length/token caps it is not judged a list: masked."""
        for text in ('PRIVATE="%s"' % " ".join(["10.0.0.0/8"] * 1000),
                     "PRIVATE=" + "1" * 100_000):
            out = mask(text)
            self.assertTrue(out.startswith("PRIVATE=") and MASK in out,
                            "not masked (%d chars): %r" % (len(out), out[:80]))

    def _elapsed(self, text):
        start = time.monotonic()
        mask(text)
        return time.monotonic() - start

    def test_address_lists_scale_linearly(self):
        """Doubling the input must roughly double the time (same ratio test
        as MaskFailsClosedTest.test_hostile_input_scales_linearly)."""
        units = {"cidr_lines": 'PRIVATE="10.0.0.0/8 172.16.0.0/12 fd00::/8"\n',
                 "near_miss_lines": 'PRIVATE="10.0.0.0/8 10.0.0.1x"\n',
                 "unterminated_run": "10.0.0.0/8 ", "colon_run": ":",
                 "comma_run": ","}
        for name, unit in units.items():
            n = 120_000 // len(unit)
            prefix = "" if name.endswith("lines") else 'PRIVATE="'
            t1 = min(self._elapsed(prefix + unit * n) for _ in range(3))
            t2 = min(self._elapsed(prefix + unit * 2 * n) for _ in range(3))
            self.assertLess(t2, 3.5 * t1 + 0.25, "%s: %.2fs -> %.2fs" % (name, t1, t2))


class MaskFailsClosedTest(unittest.TestCase):
    """Negative tests: a broken or overwhelmed masker never leaks."""

    def test_masker_exception_withholds_everything(self):
        real = secretmask._mask
        def boom(text):
            raise RuntimeError("regex engine exploded")
        secretmask._mask = boom
        try:
            out = mask("DB_PASSWORD=%s" % PW)
        finally:
            secretmask._mask = real
        self.assertNotIn(PW, out)
        self.assertIn("withheld", out)
        self.assertIn("RuntimeError", out)

    def test_non_string_input_is_masked_not_crashed(self):
        out = mask(b"DB_PASSWORD=" + PW.encode())
        self.assertNotIn(PW, out)

    def test_oversized_input_is_withheld_not_passed_through(self):
        out = mask("DB_PASSWORD=%s\n" % PW + "x" * (secretmask.MAX_INPUT + 1))
        self.assertNotIn(PW, out)
        self.assertIn("withheld", out)

    # Hostile shapes: long word runs, near-miss keys, backtracking bait, and
    # the verification pass's slow cases. Each unit repeated n times.
    HOSTILE = {
        "word_run": "a", "near_miss_keys": "x_password_", "dash_run": "-",
        "backslashes": "\\", "secret_name_lines": "name: DB_PASSWORD\n",
        "trailing_ws": " ", "kv_run": "a=", "jwt_bait": "-eyJ", "url_bait": "a://a:",
        "cli_bait": "mysql ", "header_lines": "  x\n", "dollars": "$",
    }

    def _elapsed(self, text):
        start = time.monotonic()
        mask(text)
        return time.monotonic() - start

    def test_hostile_input_scales_linearly(self):
        """Doubling the input must roughly double the time. A ratio, not a
        wall-clock bound: it holds on a loaded machine, and quadratic
        backtracking (review findings 4 and 11) shows up as ~4x."""
        for name, unit in self.HOSTILE.items():
            n = 120_000 // len(unit)
            prefix = "password=a" if name == "trailing_ws" else (
                "password:\n" if name == "header_lines" else "")
            t1 = min(self._elapsed(prefix + unit * n) for _ in range(3))
            t2 = min(self._elapsed(prefix + unit * 2 * n) for _ in range(3))
            self.assertLess(t2, 3.5 * t1 + 0.25, "%s: %.2fs -> %.2fs" % (name, t1, t2))

    def test_secret_past_4096_chars_is_not_split_and_leaked(self):
        long_pw = "Q" * 10_000
        out = mask("DB_PASSWORD=%s" % long_pw)
        self.assertNotIn("Q" * 64, out)


class DoorMasksTest(tv._Harness):
    """End to end: a host prints a secret; nothing downstream sees it."""

    def _run(self, argv, prompt=None, ssh=None):
        return tv.vpsexec.dispatch(
            argv, guard=tv._guard(), policy=tv._yaml_policy(),
            prober=self.prober(), ssh=ssh or self.fake_ssh(),
            stream=tv.ApprovalTest._TTY() if prompt else tv.ApprovalTest._NoTTY(),
            prompt=prompt, today="2026-08-27",
            blackout_runner=self.blackout_runner(unavailable=True))

    LEAK = "        - name: DB_PASSWORD\n          value: %s\nDATABASE_URL=postgres://u:%s@db/x\n" % (PW, PW)

    def _journal_text(self):
        path = journal.JOURNAL_DIR / "vpsexec.jsonl"
        return path.read_text() if path.exists() else ""

    def test_read_output_is_masked_on_the_terminal(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run(["edge1", "kubectl get deploy x -o yaml"],
                           ssh=self.fake_ssh(out=self.LEAK, err="token=%s" % PW))
        self.assertEqual(rc, 0)
        self.assertNotIn(PW, buf.getvalue())
        self.assertIn(MASK, buf.getvalue())
        self.assertNotIn(PW, self._journal_text())

    def test_compare_groups_on_masked_output(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._run(["edge1,web3", "printenv", "--compare"],
                      ssh=self.fake_ssh(out="SECRET_KEY=%s\n" % PW))
        self.assertNotIn(PW, buf.getvalue())

    def test_compare_splits_differing_secrets_without_printing_tags(self):
        """Tags are the grouping key only: edge1 and web3 hold different
        passwords, so --compare must NOT say they agree — and no tag, which
        could confirm a guess, reaches the terminal or journal."""
        def ssh(host, cmd, timeout=None, connect_timeout=None):
            return 0, "SECRET_KEY=%s\n" % ("one" if host == "edge1" else "two"), ""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._run(["edge1,web3", "printenv", "--compare"], ssh=ssh)
        text = buf.getvalue()
        self.assertNotIn("<masked:", text)
        self.assertNotIn("<masked:", self._journal_text())
        self.assertNotRegex(text.lower(), r"all \d+ hosts? agree|identical")
        self.assertEqual(text.count("SECRET_KEY=<masked>"), 2, text)

    def test_mutation_output_is_masked_in_journal_and_last(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._run(["edge1", "touch /tmp/vpscfg-mask-test", "--run", "--reason", "x"],
                      prompt=lambda m: "edge1",
                      ssh=self.fake_ssh(out=self.LEAK, err="Authorization: Bearer %s" % PW))
        raw = self._journal_text()
        self.assertIn('"event": "step"', raw.replace('":"', '": "'))
        self.assertNotIn(PW, raw)
        self.assertNotIn(PW, buf.getvalue())
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        self.assertNotIn(PW, vpsexeclog.render_runs(vpsexeclog.runs(records)))


class JournalRenderMasksOldRecordsTest(unittest.TestCase):
    """Records written BEFORE masking existed hold raw output. The journal is
    hash-chained and is not rewritten; `vpsexec last`/`log` mask on render."""

    OLD = [{"event": "mutation_attempt", "hosts": ["web2"], "command": "kubectl get deploy",
            "reason": "r", "approval": "tty", "plan_hash": "h"},
           {"event": "step", "host": "web2", "target": "web2",
            "remote": "PGPASSWORD=%s psql" % PW, "rc": 0,
            "detail": "value: x", "stdout": "- name: DB_PASSWORD\n  value: %s\n" % PW,
            "stderr": ""},
           {"event": "step", "host": "web2", "remote": "true", "rc": 0,
            "detail": "password=%s" % PW},
           {"event": "mutation_complete"}]

    def test_render_runs_masks_raw_legacy_output(self):
        out = vpsexeclog.render_runs(vpsexeclog.runs(self.OLD))
        self.assertNotIn(PW, out)
        self.assertIn(MASK, out)

    def test_render_one_line_view_masks(self):
        self.assertNotIn(PW, vpsexeclog.render(self.OLD))

    def test_legacy_terminal_escapes_are_shown_not_replayed(self):
        old = [{"event": "mutation_attempt", "hosts": ["edge1"], "command": "x"},
               {"event": "step", "host": "edge1", "remote": "x", "rc": 0,
                "stdout": "ok\x1b[2Jfake", "stderr": ""}]
        out = vpsexeclog.render_runs(vpsexeclog.runs(old))
        self.assertNotIn("\x1b", out)

    def test_raw_export_is_masked_not_raw(self):
        out = json.dumps(vpsexeclog.export(self.OLD, redact=False))
        self.assertNotIn(PW, out)


class LogsMaskTest(unittest.TestCase):
    def test_vpscfg_logs_output_is_masked(self):
        r = logsearch.run("edge1", {"target": "nginx", "searches": ["dsn"]}, DENY,
                          runner=lambda h, c: (0, "connecting dsn=postgres://u:%s@db/x" % PW, ""))
        self.assertNotIn(PW, r["stdout"])
        self.assertTrue(r["matched"])


if __name__ == "__main__":
    unittest.main()
