"""Tests for the mail-perimeter and replication check types. The one that
matters most: an accepting relay FAILS the check, and DATA is never sent."""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import verify  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402


class FakeSMTP(object):
    """Scripted SMTP server side. Records everything the check sends."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []
        self.closed = False

    def makefile(self, mode):
        fake = self

        class R(object):
            def readline(self):
                return fake.replies.pop(0) if fake.replies else b""
        return R()

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True

    def transcript(self):
        return b"".join(self.sent)


def _connector(fake):
    def connect(host, port, timeout):
        return fake
    return connect


class SmtpBannerTest(unittest.TestCase):
    def test_matching_banner_passes(self):
        fake = FakeSMTP([b"220 Example SMTP Relay ready\r\n"])
        r = verify._check_smtp_banner(
            {"host": "web1.example.internal", "port": 25,
             "expect": "Example SMTP Relay"}, connector=_connector(fake))
        self.assertTrue(r["ok"])
        self.assertEqual(fake.transcript(), b"QUIT\r\n")

    def test_wrong_banner_fails(self):
        fake = FakeSMTP([b"220 Postfix at your service\r\n"])
        r = verify._check_smtp_banner(
            {"host": "x.example", "port": 25, "expect": "Example"},
            connector=_connector(fake))
        self.assertFalse(r["ok"])

    def test_unreachable_fails_not_passes(self):
        def boom(host, port, timeout):
            raise OSError("connection refused")
        r = verify._check_smtp_banner(
            {"host": "x.example", "port": 25, "expect": "x"}, connector=boom)
        self.assertFalse(r["ok"])

    def test_bad_host_refused(self):
        with self.assertRaises(Refused):
            verify._check_smtp_banner({"host": "bad host!", "port": 25})


class RelayRefusedTest(unittest.TestCase):
    """The check must survive a STORE-AND-FORWARD proxy: RCPT accepted at the
    edge, real answer only at DATA. So the verdict is the post-DATA response,
    and the probe stays safe (null sender, reserved-domain recipient)."""

    def _spec(self):
        return {"host": "web1.example.internal", "port": 25}

    def test_refused_at_rcpt_passes(self):
        # A plain MX that rejects foreign RCPT — closed, no DATA needed.
        fake = FakeSMTP([b"220 hi\r\n", b"250-hello\r\n250 DONE\r\n",
                         b"250 ok\r\n", b"554 5.7.1 Relay access denied\r\n",
                         b"250 ok\r\n", b"221 bye\r\n"])
        r = verify._check_smtp_relay_refused(self._spec(), connector=_connector(fake))
        self.assertTrue(r["ok"])
        self.assertNotIn(b"DATA", fake.transcript())  # no DATA once RCPT refused

    def test_forwarding_proxy_deferred_reject_passes(self):
        # The store-and-forward proxy shape: edge accepts RCPT, upstream 554 surfaces later.
        fake = FakeSMTP([b"220 hi\r\n", b"250 hello\r\n",
                         b"250 ok\r\n",     # MAIL FROM
                         b"250 ok\r\n",     # RCPT accepted at edge
                         b"354 go ahead\r\n",  # DATA
                         b"554 5.7.1 Relay access denied\r\n",  # end-of-DATA
                         b"250 ok\r\n", b"221 bye\r\n"])
        r = verify._check_smtp_relay_refused(self._spec(), connector=_connector(fake))
        self.assertTrue(r["ok"])
        self.assertIn("not an open relay", r["detail"])

    def test_actual_open_relay_FAILS(self):
        # RCPT accepted, DATA accepted, message ACCEPTED for delivery.
        fake = FakeSMTP([b"220 hi\r\n", b"250 hello\r\n",
                         b"250 ok\r\n", b"250 ok\r\n",
                         b"354 go ahead\r\n",
                         b"250 2.0.0 queued as ABC123\r\n",  # the disaster
                         b"250 ok\r\n", b"221 bye\r\n"])
        r = verify._check_smtp_relay_refused(self._spec(), connector=_connector(fake))
        self.assertFalse(r["ok"])
        self.assertIn("OPEN RELAY", r["detail"])

    def test_probe_is_safe_null_sender_reserved_recipient(self):
        fake = FakeSMTP([b"220 hi\r\n", b"250 hello\r\n",
                         b"250 ok\r\n", b"250 ok\r\n", b"354 go\r\n",
                         b"554 no\r\n", b"250 ok\r\n", b"221 bye\r\n"])
        verify._check_smtp_relay_refused(self._spec(), connector=_connector(fake))
        tx = fake.transcript()
        self.assertIn(b"MAIL FROM:<>", tx)            # null sender: no backscatter
        self.assertIn(b"@example.com", tx)            # RFC 2606 reserved: routes nowhere

    def test_rcpt_accepted_then_data_refused_passes(self):
        fake = FakeSMTP([b"220 hi\r\n", b"250 hello\r\n",
                         b"250 ok\r\n", b"250 ok\r\n",
                         b"503 bad sequence\r\n",  # DATA refused outright
                         b"250 ok\r\n", b"221 bye\r\n"])
        r = verify._check_smtp_relay_refused(self._spec(), connector=_connector(fake))
        self.assertTrue(r["ok"])
        self.assertIn("not relayed", r["detail"])

    def test_no_greeting_fails_closed(self):
        fake = FakeSMTP([b"garbage\r\n"])
        r = verify._check_smtp_relay_refused(self._spec(), connector=_connector(fake))
        self.assertFalse(r["ok"])
        self.assertIn("failing closed", r["detail"])

    def test_rejected_mail_from_passes_without_sending_data(self):
        fake = FakeSMTP([b"220 hi\r\n", b"250 hello\r\n",
                         b"550 no\r\n", b"250 ok\r\n", b"221 bye\r\n"])
        r = verify._check_smtp_relay_refused(self._spec(), connector=_connector(fake))
        self.assertTrue(r["ok"])
        self.assertNotIn(b"RCPT", fake.transcript())

    def test_bad_rcpt_address_refused_before_dialing(self):
        with self.assertRaises(Refused):
            verify._check_smtp_relay_refused(
                {"host": "x.example", "port": 25, "rcpt_to": "not an address"})


class RelayViaHostTest(unittest.TestCase):
    """The port-25 test that must run FROM a fleet host (relay1 reaches
    web1:25; the ops machine's ISP does not). Fixed remote probe, parsed
    verdict — the fleet is never actually dialed in a unit test."""

    def _spec(self):
        return {"host": "web1.example.internal", "port": 25, "via": "relay1"}

    def _runner(self, stdout, rc=0):
        return lambda via, remote: (rc, stdout)

    def test_remote_refusal_passes(self):
        r = verify._check_smtp_relay_refused(
            self._spec(),
            runner=self._runner("RELAY|ok|503|DATA refused; not relayed\n"))
        self.assertTrue(r["ok"])
        self.assertIn("via relay1", r["name"])
        self.assertIn("relay1", r["detail"])

    def test_remote_open_relay_FAILS(self):
        r = verify._check_smtp_relay_refused(
            self._spec(),
            runner=self._runner("RELAY|open|250|message ACCEPTED for delivery\n"))
        self.assertFalse(r["ok"])
        self.assertIn("OPEN RELAY", r["detail"])

    def test_remote_command_is_fixed_and_quotes_inputs(self):
        seen = {}
        def runner(via, remote):
            seen["via"], seen["remote"] = via, remote
            return 0, "RELAY|ok|554|refused\n"
        verify._check_smtp_relay_refused(self._spec(), runner=runner)
        self.assertEqual(seen["via"], "relay1")
        # fixed probe, no operator interpolation beyond validated host/port/rcpt
        self.assertIn("python3 -c", seen["remote"])
        self.assertIn("web1.example.internal", seen["remote"])
        self.assertIn("example.com", seen["remote"])  # reserved recipient
        self.assertNotIn("rm ", seen["remote"])

    def test_no_verdict_line_fails_closed(self):
        r = verify._check_smtp_relay_refused(
            self._spec(), runner=self._runner("ssh: some noise\n", rc=255))
        self.assertFalse(r["ok"])
        self.assertIn("failing closed", r["detail"])

    def test_probe_crash_fails_closed(self):
        def boom(via, remote):
            raise OSError("ssh died")
        r = verify._check_smtp_relay_refused(self._spec(), runner=boom)
        self.assertFalse(r["ok"])
        self.assertIn("failing closed", r["detail"])

    def test_bad_via_host_refused(self):
        with self.assertRaises(Refused):
            verify._check_smtp_relay_refused(
                {"host": "web1.example.internal", "port": 25, "via": "bad host!"})

    def test_remote_probe_script_is_valid_python(self):
        import ast
        ast.parse(verify._REMOTE_RELAY_PROBE)  # must compile — it ships as code


class TlsExpiryTest(unittest.TestCase):
    def _fetcher(self, days_from_now):
        def fetch(host, port, timeout, starttls):
            return time.time() + days_from_now * 86400
        return fetch

    def test_healthy_cert_passes(self):
        r = verify._check_tls_expiry(
            {"host": "web1.example.internal", "port": 465, "min_days": 14},
            fetcher=self._fetcher(60))
        self.assertTrue(r["ok"])

    def test_near_expiry_fails(self):
        r = verify._check_tls_expiry(
            {"host": "web1.example.internal", "port": 465, "min_days": 14},
            fetcher=self._fetcher(3))
        self.assertFalse(r["ok"])

    def test_expired_cert_fails(self):
        r = verify._check_tls_expiry(
            {"host": "web1.example.internal", "port": 465},
            fetcher=self._fetcher(-1))
        self.assertFalse(r["ok"])

    def test_uninspectable_cert_fails_closed(self):
        def boom(host, port, timeout, starttls):
            raise OSError("handshake refused")
        r = verify._check_tls_expiry(
            {"host": "web1.example.internal", "port": 465}, fetcher=boom)
        self.assertFalse(r["ok"])
        self.assertIn("failing closed", r["detail"])

    def test_unknown_starttls_mode_refused(self):
        with self.assertRaises(Refused):
            verify._check_tls_expiry(
                {"host": "x.example", "port": 993, "starttls": "imap"})


class PgReplicationTest(unittest.TestCase):
    SPEC = {"host": "edge1", "name": "acme-postgres-dr", "lag_max_s": 300}

    def test_standby_with_bounded_lag_passes(self):
        r = verify._check_pg_replication(self.SPEC, runner=lambda h, n: (0, "t|12.5"))
        self.assertTrue(r["ok"])

    def test_not_in_recovery_fails(self):
        # A "DR replica" that is not actually a standby.
        r = verify._check_pg_replication(self.SPEC, runner=lambda h, n: (0, "f|0"))
        self.assertFalse(r["ok"])
        self.assertIn("aspiration", r["detail"])

    def test_lag_over_max_fails(self):
        r = verify._check_pg_replication(self.SPEC, runner=lambda h, n: (0, "t|4000"))
        self.assertFalse(r["ok"])

    def test_never_replayed_fails(self):
        r = verify._check_pg_replication(self.SPEC, runner=lambda h, n: (0, "t|-1"))
        self.assertFalse(r["ok"])

    def test_query_failure_fails(self):
        r = verify._check_pg_replication(self.SPEC, runner=lambda h, n: (1, ""))
        self.assertFalse(r["ok"])

    def test_garbage_answer_fails(self):
        r = verify._check_pg_replication(self.SPEC, runner=lambda h, n: (0, "wat"))
        self.assertFalse(r["ok"])

    def test_bad_container_name_refused(self):
        with self.assertRaises(Refused):
            verify._check_pg_replication(
                {"host": "edge1", "name": "x; rm -rf /", "lag_max_s": 1})

    def test_sql_is_fixed_and_readonly(self):
        self.assertNotIn("%", verify._PG_REPLICATION_SQL)
        for verb in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER"):
            self.assertNotIn(verb, verify._PG_REPLICATION_SQL.upper())


class DispatchTest(unittest.TestCase):
    def test_new_checks_are_dispatched_not_unknown(self):
        # Stub every network-touching check: dispatch is what is under test,
        # and a unit test must never dial the real fleet.
        from unittest import mock
        contract = {"verify": [
            {"smtp_banner": {"host": "h.example", "port": 25}},
            {"smtp_relay_refused": {"host": "h.example", "port": 25}},
            {"tls_expiry": {"host": "h.example", "port": 465}},
            {"pg_replication": {"host": "edge1", "name": "pg", "lag_max_s": 60}},
        ]}
        def fake(name):
            return lambda spec, **kw: {"check": name, "ok": True, "detail": ""}
        with mock.patch.object(verify, "_check_smtp_banner", fake("smtp_banner")), \
             mock.patch.object(verify, "_check_smtp_relay_refused", fake("smtp_relay_refused")), \
             mock.patch.object(verify, "_check_tls_expiry", fake("tls_expiry")), \
             mock.patch.object(verify, "_check_pg_replication", fake("pg_replication")):
            ok, results = verify.run_checks(contract, "edge1")
        self.assertTrue(ok)
        self.assertEqual([r["check"] for r in results],
                         ["smtp_banner", "smtp_relay_refused",
                          "tls_expiry", "pg_replication"])


if __name__ == "__main__":
    unittest.main()
