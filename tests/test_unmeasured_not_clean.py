import os
import unittest
from unittest import mock

import dns.resolver


class UnmeasuredIsNotCleanTests(unittest.TestCase):
    """A probe that failed returned the same value as a clean result, so the
    page said "Disabled (safe)", "(none)" or "no PTR records" about things
    that were never measured -- a clean bill of health nobody had issued."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        import security_checks
        cls.app = app
        cls.sc = security_checks

    def test_tls_compression_is_unknown_when_the_handshake_fails(self):
        with mock.patch("app.ssl.SSLContext.wrap_socket", side_effect=OSError("refused")):
            self.assertIsNone(self.app._check_tls_compression("example.com"))

    def test_cors_is_unknown_when_the_probe_gets_no_answer(self):
        with mock.patch("security_checks._get", side_effect=OSError("timeout")):
            cors = self.sc._cors_probe("https://example.com")
        self.assertIn("error", cors)
        self.assertNotIn("allow_origin", cors)

    def test_methods_are_unknown_when_options_gets_no_answer(self):
        with mock.patch("security_checks._get", side_effect=OSError("timeout")):
            self.assertIn("error", self.sc._methods_probe("https://example.com"))

    def test_a_failed_reverse_lookup_is_not_an_empty_answer(self):
        client = self.app.app.test_client()
        with mock.patch("app.dns.resolver.resolve", side_effect=dns.resolver.LifetimeTimeout()):
            resp = client.post("/api/reverse-dns", json={"ip": "192.0.2.10"})
        self.assertEqual(resp.status_code, 502)
        self.assertIsNone(resp.get_json()["ptr_records"])

    def test_an_address_without_ptr_is_still_an_empty_answer(self):
        with mock.patch("app.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            self.assertEqual(self.app.lookup_reverse_dns("192.0.2.10"), [])


if __name__ == "__main__":
    unittest.main()
