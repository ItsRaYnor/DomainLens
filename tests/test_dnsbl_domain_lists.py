import os
import unittest
from unittest import mock

import dns.resolver


class DnsblDomainListTests(unittest.TestCase):
    """Reported against a live domain: "Listed on 2 blacklist(s)!" naming
    dbl and zrd, while the domain was not listed anywhere.

    dbl (Domain Block List) and zrd (Zero Reputation Domains) are DOMAIN
    lists, but every zone was queried with a reversed IP address. Spamhaus
    answers an IP query to those zones with 127.0.1.255, "IP queries
    prohibited" — which looked exactly like an ordinary 127.0.x.y listing,
    so every scanned domain came back listed on both.
    """

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        cls.app = app

    def _rdata(self, ip):
        r = mock.Mock()
        r.to_text.return_value = ip
        return r

    # --- response classification ---

    def test_ip_queries_prohibited_is_not_a_listing(self):
        self.assertFalse(self.app._dnsbl_is_real_hit([self._rdata("127.0.1.255")]))

    def test_auth_or_quota_error_is_not_a_listing(self):
        for code in ("127.255.255.252", "127.255.255.254", "127.255.255.255"):
            self.assertFalse(self.app._dnsbl_is_real_hit([self._rdata(code)]), code)

    def test_genuine_listings_are_still_detected(self):
        for code in ("127.0.0.2", "127.0.0.4", "127.0.1.2", "127.0.1.106"):
            self.assertTrue(self.app._dnsbl_is_real_hit([self._rdata(code)]), code)

    def test_non_loopback_answer_is_not_a_listing(self):
        self.assertFalse(self.app._dnsbl_is_real_hit([self._rdata("93.184.216.34")]))

    # --- query construction ---

    def test_domain_zones_are_queried_with_the_domain(self):
        with mock.patch("app._spamhaus_dqs_key", return_value="KEY"):
            servers = dict(self.app._build_dnsbl_list())
        self.assertEqual(servers["KEY.dbl.dq.spamhaus.net"], "domain")
        self.assertEqual(servers["KEY.zrd.dq.spamhaus.net"], "domain")
        self.assertEqual(servers["KEY.zen.dq.spamhaus.net"], "ip")

    def test_open_lists_are_all_ip_based(self):
        with mock.patch("app._spamhaus_dqs_key", return_value=""):
            servers = self.app._build_dnsbl_list()
        self.assertTrue(all(kind == "ip" for _, kind in servers))

    def test_no_spamhaus_zones_without_a_key(self):
        with mock.patch("app._spamhaus_dqs_key", return_value=""):
            hosts = [h for h, _ in self.app._build_dnsbl_list()]
        self.assertFalse(any("spamhaus" in h for h in hosts))

    def test_scan_sends_the_domain_to_domain_zones_and_the_ip_to_ip_zones(self):
        queried = []

        def fake_resolve(name, rdtype):
            queried.append(name)
            raise dns.resolver.NXDOMAIN()

        with mock.patch("app._spamhaus_dqs_key", return_value="KEY"), \
             mock.patch("app._safe_resolve_ip", return_value="185.229.190.148"), \
             mock.patch("dns.resolver.resolve", side_effect=fake_resolve):
            self.app.check_blacklist("example.com")

        self.assertIn("example.com.KEY.dbl.dq.spamhaus.net", queried)
        self.assertIn("example.com.KEY.zrd.dq.spamhaus.net", queried)
        self.assertIn("148.190.229.185.KEY.zen.dq.spamhaus.net", queried)
        # The reversed IP must never be sent to a domain list again.
        self.assertNotIn("148.190.229.185.KEY.dbl.dq.spamhaus.net", queried)
        self.assertNotIn("148.190.229.185.KEY.zrd.dq.spamhaus.net", queried)

    # --- the reported symptom, end to end ---

    def test_prohibited_ip_query_no_longer_reports_a_listing(self):
        """The exact original failure: domain zones answering 127.0.1.255."""
        def fake_resolve(name, rdtype):
            if ".dbl." in name or ".zrd." in name:
                return [self._rdata("127.0.1.255")]
            raise dns.resolver.NXDOMAIN()

        with mock.patch("app._spamhaus_dqs_key", return_value="KEY"), \
             mock.patch("app._safe_resolve_ip", return_value="185.229.190.148"), \
             mock.patch("dns.resolver.resolve", side_effect=fake_resolve):
            result = self.app.check_blacklist("example.com")

        self.assertEqual(result["listed"], [])
        self.assertFalse(result["is_listed"])

    def test_a_real_domain_listing_is_still_reported(self):
        def fake_resolve(name, rdtype):
            if ".dbl." in name:
                return [self._rdata("127.0.1.2")]  # spam domain
            raise dns.resolver.NXDOMAIN()

        with mock.patch("app._spamhaus_dqs_key", return_value="KEY"), \
             mock.patch("app._safe_resolve_ip", return_value="185.229.190.148"), \
             mock.patch("dns.resolver.resolve", side_effect=fake_resolve):
            result = self.app.check_blacklist("bad.example")

        self.assertTrue(result["is_listed"])
        self.assertEqual(result["listed"], ["KEY.dbl.dq.spamhaus.net"])

    def test_a_real_ip_listing_is_still_reported(self):
        def fake_resolve(name, rdtype):
            if ".zen." in name:
                return [self._rdata("127.0.0.4")]
            raise dns.resolver.NXDOMAIN()

        with mock.patch("app._spamhaus_dqs_key", return_value="KEY"), \
             mock.patch("app._safe_resolve_ip", return_value="185.229.190.148"), \
             mock.patch("dns.resolver.resolve", side_effect=fake_resolve):
            result = self.app.check_blacklist("bad.example")

        self.assertTrue(result["is_listed"])
        self.assertEqual(result["listed"], ["KEY.zen.dq.spamhaus.net"])


if __name__ == "__main__":
    unittest.main()
