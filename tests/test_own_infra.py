"""Open relay and open resolver tests, and the gates that keep them off
everything except infrastructure the operator says is theirs.

These two differ from every other check here: they ask a mail server to relay
and a nameserver to recurse. Against a stranger's host that is a probe, and
against a badly configured one it is indistinguishable from the abuse the
test looks for. Most of this file is therefore about them NOT running.

Two gates, and both must pass. A single on/off switch would turn "test my
infrastructure" into "test everything I happen to scan", which is the failure
worth designing out rather than documenting.
"""

import unittest
from unittest import mock

import own_infra


ENABLED = {"enabled": True, "domains": ["example.com", "mine.test"]}
DISABLED = {"enabled": False, "domains": ["example.com"]}


class AllowlistTests(unittest.TestCase):
    def test_a_listed_domain_is_allowed(self):
        self.assertTrue(own_infra.is_allowed("example.com", ENABLED))

    def test_a_subdomain_of_a_listed_domain_is_allowed(self):
        """Someone who lists example.com means their mail and nameservers
        under it. Making them enumerate every host pushes people towards a
        bare wildcard, which is worse."""
        self.assertTrue(own_infra.is_allowed("mail.example.com", ENABLED))

    def test_an_unlisted_domain_is_refused(self):
        self.assertFalse(own_infra.is_allowed("someone-else.com", ENABLED))

    def test_a_domain_that_merely_ends_with_the_same_letters_is_refused(self):
        """notexample.com is not a subdomain of example.com, and a suffix
        match without the dot would probe a stranger's server."""
        self.assertFalse(own_infra.is_allowed("notexample.com", ENABLED))

    def test_nothing_is_allowed_while_the_feature_is_off(self):
        """The first gate: a filled-in allowlist is not consent on its own."""
        self.assertFalse(own_infra.is_allowed("example.com", DISABLED))

    def test_an_empty_allowlist_allows_nothing_even_when_enabled(self):
        """The second gate: enabling without listing anything must not mean
        "everything"."""
        self.assertFalse(own_infra.is_allowed("example.com",
                                              {"enabled": True, "domains": []}))

    def test_missing_config_allows_nothing(self):
        for config in (None, {}, {"domains": ["example.com"]}):
            with self.subTest(config=config):
                self.assertFalse(own_infra.is_allowed("example.com", config))

    def test_case_and_trailing_dots_do_not_defeat_the_list(self):
        self.assertTrue(own_infra.is_allowed("EXAMPLE.COM.", ENABLED))


class NothingIsProbedWithoutConsentTests(unittest.TestCase):
    """Not just "no finding" -- no connection at all."""

    def test_no_smtp_connection_for_an_unlisted_domain(self):
        with mock.patch.object(own_infra.smtplib, "SMTP") as smtp:
            result = own_infra.check_open_relay("someone-else.com", ENABLED)
        smtp.assert_not_called()
        self.assertEqual("not_applicable", result["state"])
        self.assertIn("not on the own-infrastructure list", result["reason"])

    def test_no_smtp_connection_while_disabled(self):
        with mock.patch.object(own_infra.smtplib, "SMTP") as smtp:
            result = own_infra.check_open_relay("example.com", DISABLED)
        smtp.assert_not_called()
        self.assertIn("disabled", result["reason"])

    def test_no_dns_query_for_an_unlisted_domain(self):
        with mock.patch.object(own_infra.dns.resolver, "Resolver") as resolver:
            result = own_infra.check_open_resolver("someone-else.com", ENABLED)
        resolver.assert_not_called()
        self.assertEqual("not_applicable", result["state"])

    def test_the_refusal_says_what_to_do_about_it(self):
        """"Not applicable" with no reason sends someone hunting for a bug."""
        off = own_infra.check_open_relay("example.com", DISABLED)
        self.assertIn("Settings", off["reason"])
        unlisted = own_infra.check_open_relay("other.com", ENABLED)
        self.assertIn("Settings", unlisted["reason"])


class RelayProbeIsGentleTests(unittest.TestCase):
    """One connection, and it stops before anything is sent."""

    def _smtp(self, rcpt_code):
        session = mock.MagicMock()
        session.__enter__.return_value = session
        session.rcpt.return_value = (rcpt_code, b"whatever")
        return session

    def test_the_probe_never_reaches_DATA(self):
        """Delivering a message to find out whether it would be delivered
        makes the tool the thing it is checking for."""
        session = self._smtp(250)
        with mock.patch.object(own_infra.smtplib, "SMTP", return_value=session):
            own_infra.check_open_relay("example.com", ENABLED, mx_hosts=["mx.example.com"])
        session.data.assert_not_called()
        session.send_message.assert_not_called()
        session.quit.assert_called()

    def test_a_relaying_server_is_detected(self):
        session = self._smtp(250)
        with mock.patch.object(own_infra.smtplib, "SMTP", return_value=session):
            result = own_infra.check_open_relay("example.com", ENABLED,
                                                mx_hosts=["mx.example.com"])
        self.assertTrue(result["open_relay"])
        self.assertTrue(result["hosts"][0]["relays"])

    def test_a_refusing_server_is_not_a_finding(self):
        session = self._smtp(550)
        with mock.patch.object(own_infra.smtplib, "SMTP", return_value=session):
            result = own_infra.check_open_relay("example.com", ENABLED,
                                                mx_hosts=["mx.example.com"])
        self.assertFalse(result["open_relay"])

    def test_a_connection_failure_is_unknown_not_a_finding(self):
        """A server that will not talk to us is usually behaving correctly,
        and never evidence of a relay."""
        with mock.patch.object(own_infra.smtplib, "SMTP", side_effect=OSError("refused")):
            result = own_infra.check_open_relay("example.com", ENABLED,
                                                mx_hosts=["mx.example.com"])
        self.assertFalse(result["open_relay"])
        self.assertIsNone(result["hosts"][0]["relays"])

    def test_the_probe_recipient_is_a_reserved_domain(self):
        """.invalid can never resolve and belongs to nobody, so the probe
        cannot deliver anywhere even if a server accepted it."""
        self.assertTrue(own_infra._PROBE_RECIPIENT.endswith(".invalid"))

    def test_a_domain_with_no_mx_is_not_applicable(self):
        result = own_infra.check_open_relay("example.com", ENABLED, mx_hosts=[])
        self.assertEqual("not_applicable", result["state"])
        self.assertIn("no mail host", result["reason"])

    def test_at_most_three_hosts_are_contacted(self):
        session = self._smtp(550)
        hosts = [f"mx{i}.example.com" for i in range(9)]
        with mock.patch.object(own_infra.smtplib, "SMTP", return_value=session) as smtp:
            own_infra.check_open_relay("example.com", ENABLED, mx_hosts=hosts)
        self.assertLessEqual(smtp.call_count, 3)


class ResolverProbeTests(unittest.TestCase):
    def _resolver(self, answer=None, exc=None):
        instance = mock.MagicMock()
        if exc is not None:
            instance.resolve.side_effect = exc
        else:
            instance.resolve.return_value = answer
        return instance

    def test_a_recursing_nameserver_is_detected(self):
        instance = self._resolver(answer=["93.184.216.34"])
        with mock.patch.object(own_infra.dns.resolver, "Resolver", return_value=instance):
            result = own_infra.check_open_resolver("example.com", ENABLED,
                                                   nameservers=["192.0.2.1"])
        self.assertTrue(result["open_resolver"])

    def test_a_refusing_nameserver_is_correct_behaviour(self):
        import dns.resolver as dnsres
        instance = self._resolver(exc=dnsres.NoNameservers("refused"))
        with mock.patch.object(own_infra.dns.resolver, "Resolver", return_value=instance):
            result = own_infra.check_open_resolver("example.com", ENABLED,
                                                   nameservers=["192.0.2.1"])
        self.assertFalse(result["open_resolver"])
        self.assertIn("correct", result["nameservers"][0]["detail"])

    def test_a_timeout_is_unknown_not_a_finding(self):
        instance = self._resolver(exc=TimeoutError("slow"))
        with mock.patch.object(own_infra.dns.resolver, "Resolver", return_value=instance):
            result = own_infra.check_open_resolver("example.com", ENABLED,
                                                   nameservers=["192.0.2.1"])
        self.assertFalse(result["open_resolver"])
        self.assertIsNone(result["nameservers"][0]["recurses"])

    def test_at_most_three_nameservers_are_contacted(self):
        instance = self._resolver(answer=[])
        servers = [f"192.0.2.{i}" for i in range(9)]
        with mock.patch.object(own_infra.dns.resolver, "Resolver", return_value=instance):
            result = own_infra.check_open_resolver("example.com", ENABLED,
                                                   nameservers=servers)
        self.assertLessEqual(len(result["nameservers"]), 3)


class ScanIntegrationTests(unittest.TestCase):
    def test_the_check_is_in_the_opt_in_set(self):
        """A full scan must never reach it on the strength of a ticked
        checkbox alone."""
        import os
        import tempfile
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            os.environ["DOMAINLENS_DB"] = os.path.join(tmp, "oi.db")
            os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
            try:
                import db
                db.init_db()
                import app
                self.assertIn("own_infra", app._OPT_IN_ACTIVE_CHECKS)
            finally:
                os.environ.pop("DOMAINLENS_DB", None)

    def test_it_is_off_by_default(self):
        from settings.defaults import DEFAULTS
        self.assertFalse(DEFAULTS["own_infra"]["enabled"])
        self.assertEqual([], DEFAULTS["own_infra"]["domains"])

    def test_recommendations_stay_silent_for_a_domain_not_allowed(self):
        import recommendations
        results = {"own_infra": {"allowed": False,
                                 "relay": {"open_relay": True,
                                           "hosts": [{"host": "m", "relays": True}]}}}
        self.assertEqual([], recommendations._own_infra(results))


if __name__ == "__main__":
    unittest.main()
