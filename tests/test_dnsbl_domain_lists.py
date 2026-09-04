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
        # Its own database: importing app opens one, and relying on another
        # test file having set the path first makes this file pass or fail
        # depending on what ran before it.
        import tempfile
        cls._tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOMAINLENS_DB"] = os.path.join(cls._tempdir.name, "dnsbl.db")
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import db
        db.init_db()
        import app
        cls.app = app

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("DOMAINLENS_DB", None)
        cls._tempdir.cleanup()

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
            servers = {host: kind for host, kind, _label in self.app._build_dnsbl_list()}
        self.assertEqual(servers["KEY.dbl.dq.spamhaus.net"], "domain")
        self.assertEqual(servers["KEY.zrd.dq.spamhaus.net"], "domain")
        self.assertEqual(servers["KEY.zen.dq.spamhaus.net"], "ip")

    def test_open_lists_are_all_ip_based(self):
        with mock.patch("app._spamhaus_dqs_key", return_value=""):
            servers = self.app._build_dnsbl_list()
        self.assertTrue(all(kind == "ip" for _, kind, _label in servers))

    def test_no_spamhaus_zones_without_a_key(self):
        with mock.patch("app._spamhaus_dqs_key", return_value=""):
            hosts = [h for h, _kind, _label in self.app._build_dnsbl_list()]
        self.assertFalse(any("spamhaus" in h for h in hosts))

    # --- the key must not leave the query ---

    def test_the_dqs_key_is_not_in_the_name_that_gets_stored(self):
        """A DQS query carries the account key as the first label of the
        hostname. Storing the queried name published it on the results page,
        in the saved scan, and in every exported report -- so a report shared
        with anyone handed them a working key."""
        with mock.patch("app._spamhaus_dqs_key", return_value="SECRETKEY"):
            labels = [label for _host, _kind, label in self.app._build_dnsbl_list()]
        self.assertTrue(any("spamhaus" in l for l in labels), "no spamhaus zone at all")
        for label in labels:
            self.assertNotIn("SECRETKEY", label)

    def test_the_key_is_still_used_for_the_actual_query(self):
        """Redacting the label must not redact the lookup: without the key in
        the queried name Spamhaus answers nothing useful."""
        with mock.patch("app._spamhaus_dqs_key", return_value="SECRETKEY"):
            hosts = [h for h, _kind, _label in self.app._build_dnsbl_list()]
        self.assertTrue(any(h.startswith("SECRETKEY.") for h in hosts))

    def test_a_stored_result_never_carries_the_key(self):
        """End to end: whatever check_blacklist writes is what reaches the
        database and the report."""
        with mock.patch("app._spamhaus_dqs_key", return_value="SECRETKEY"),              mock.patch("app._safe_resolve_ip", return_value="192.0.2.1"),              mock.patch("dns.resolver.resolve",
                        side_effect=dns.resolver.NXDOMAIN("clean")):
            result = self.app.check_blacklist("example.com")
        blob = " ".join(result.get("listed", []) + result.get("clean", [])
                        + result.get("errors", []))
        self.assertTrue(blob, "nothing was recorded at all")
        self.assertNotIn("SECRETKEY", blob)

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
        # The zone without the key: that is what is safe to store and show.
        self.assertEqual(result["listed"], ["dbl.dq.spamhaus.net"])

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
        self.assertEqual(result["listed"], ["zen.dq.spamhaus.net"])


if __name__ == "__main__":
    unittest.main()
