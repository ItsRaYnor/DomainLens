import os
import tempfile
import unittest
from unittest import mock

import dns.resolver

import security_checks as s


# Subdomain enumeration goes through the cached crt.sh path. Without an
# isolated, empty cache these tests read whatever this machine happened to
# have stored for example.com, and the mocked response is never consulted --
# which is how a passing suite started reporting 2 subdomains instead of 10.
_tempdir = None


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "takeover.db")
    import db
    db.init_db()


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


class NxdomainDistinctionTests(unittest.TestCase):
    """_resolve() collapses NXDOMAIN, SERVFAIL, timeout and NoAnswer into an
    empty list. Takeover detection read "no records" as "unclaimed target",
    so any transient resolver failure during a scan produced a reported
    takeover on a healthy CNAME.
    """

    def _resolver_raising(self, exc):
        resolver = mock.Mock()
        resolver.resolve.side_effect = exc
        return resolver

    def test_nxdomain_is_true(self):
        with mock.patch.object(s, "_RESOLVER", self._resolver_raising(dns.resolver.NXDOMAIN())):
            self.assertTrue(s._is_nxdomain("gone.example.com"))

    def test_timeout_is_not_nxdomain(self):
        with mock.patch.object(s, "_RESOLVER", self._resolver_raising(dns.exception.Timeout())):
            self.assertFalse(s._is_nxdomain("slow.example.com"))

    def test_servfail_is_not_nxdomain(self):
        with mock.patch.object(s, "_RESOLVER", self._resolver_raising(dns.resolver.NoNameservers())):
            self.assertFalse(s._is_nxdomain("broken.example.com"))

    def test_noanswer_is_not_nxdomain(self):
        # The name exists, it just has no A record.
        with mock.patch.object(s, "_RESOLVER", self._resolver_raising(dns.resolver.NoAnswer())):
            self.assertFalse(s._is_nxdomain("aaaa-only.example.com"))

    def test_resolving_name_is_not_nxdomain(self):
        resolver = mock.Mock()
        resolver.resolve.return_value = ["1.2.3.4"]
        with mock.patch.object(s, "_RESOLVER", resolver):
            self.assertFalse(s._is_nxdomain("live.example.com"))


class TakeoverClassificationTests(unittest.TestCase):

    def test_healthy_cname_not_flagged_on_transient_dns_failure(self):
        # Known service, target currently unresolvable due to a timeout (not
        # NXDOMAIN), no fingerprint on the page: must NOT be reported.
        with mock.patch("security_checks._resolve", side_effect=lambda n, t: ["app.herokuapp.com"] if t == "CNAME" else []), \
             mock.patch("security_checks._is_nxdomain", return_value=False), \
             mock.patch("security_checks._safe_host", return_value=False):
            result = s._check_one_takeover("www.example.com")
        self.assertIsNone(result)

    def test_known_service_with_nxdomain_target_is_takeover(self):
        with mock.patch("security_checks._resolve", side_effect=lambda n, t: ["app.herokuapp.com"] if t == "CNAME" else []), \
             mock.patch("security_checks._is_nxdomain", return_value=True), \
             mock.patch("security_checks._safe_host", return_value=False):
            result = s._check_one_takeover("www.example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["kind"], "takeover")
        self.assertEqual(result["service"], "Heroku")
        self.assertEqual(result["confidence"], "medium")

    def test_fingerprint_match_is_high_confidence(self):
        resp = mock.Mock(status_code=404, text="No such app")
        with mock.patch("security_checks._resolve", side_effect=lambda n, t: ["app.herokuapp.com"] if t == "CNAME" else []), \
             mock.patch("security_checks._is_nxdomain", return_value=False), \
             mock.patch("security_checks._safe_host", return_value=True), \
             mock.patch("security_checks._get", return_value=resp):
            result = s._check_one_takeover("www.example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["confidence"], "high")
        self.assertTrue(result["fingerprint_match"])

    def test_unknown_service_with_nxdomain_reported_as_dangling(self):
        # Previously dropped silently, hiding every dangling CNAME pointing at
        # a provider not in the signature list.
        with mock.patch("security_checks._resolve", side_effect=lambda n, t: ["thing.some-unknown-saas.example"] if t == "CNAME" else []), \
             mock.patch("security_checks._is_nxdomain", return_value=True):
            result = s._check_one_takeover("old.example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["kind"], "dangling")
        self.assertIsNone(result["service"])

    def test_unknown_service_that_resolves_is_ignored(self):
        with mock.patch("security_checks._resolve", side_effect=lambda n, t: ["thing.some-unknown-saas.example"] if t == "CNAME" else []), \
             mock.patch("security_checks._is_nxdomain", return_value=False):
            result = s._check_one_takeover("fine.example.com")
        self.assertIsNone(result)

    def test_no_cname_is_ignored(self):
        with mock.patch("security_checks._resolve", return_value=[]):
            self.assertIsNone(s._check_one_takeover("apex.example.com"))


class EnumerationTruncationTests(unittest.TestCase):
    def setUp(self):
        # A sibling test caches a result for the same domain; without this
        # the mock below is bypassed entirely.
        import db
        with db._lock, db._connect() as conn:
            conn.execute("DELETE FROM external_cache")

    """A capped subdomain list rendered identically to a complete one, so
    "no takeovers found" read as "all subdomains are clean" even when most
    were never checked.
    """

    def test_enumerate_reports_discovered_count(self):
        rows = [{"name_value": "\n".join(f"h{i}.example.com" for i in range(100))}]
        resp = mock.Mock(status_code=200)
        resp.json.return_value = rows
        with mock.patch("security_checks.requests.get", return_value=resp):
            subs, discovered, source_error, _meta = s.enumerate_subdomains("example.com", limit=10)
        self.assertEqual(len(subs), 10)
        self.assertEqual(discovered, 101)  # 100 hosts + the apex

    def test_truncation_is_recorded_on_the_result(self):
        with mock.patch("security_checks.enumerate_subdomains", return_value=(["a.example.com"], 50, None, {})), \
             mock.patch("security_checks._check_one_takeover", return_value=None):
            result = s.check_subdomain_takeover("example.com", limit=1)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["discovered_count"], 50)

        # Coverage limits describe the scan, not the domain, so they are
        # reported with the subdomain result rather than as an advice item.
        self.assertEqual(s.audit_findings({"subdomains": result}), [])

    def test_not_truncated_when_all_checked(self):
        with mock.patch("security_checks.enumerate_subdomains", return_value=(["a.example.com"], 1, None, {})), \
             mock.patch("security_checks._check_one_takeover", return_value=None):
            result = s.check_subdomain_takeover("example.com")
        self.assertFalse(result["truncated"])
        findings = s.audit_findings({"subdomains": result})
        self.assertNotIn("Subdomain scan was truncated", [f["title"] for f in findings])


class TakeoverFindingsTests(unittest.TestCase):

    def test_unconfirmed_dangling_record_is_low(self):
        audit = {"subdomains": {"success": True, "takeovers": [], "dangling": [
            {"subdomain": "old.example.com", "cname": "gone.example.net"},
        ]}}
        findings = s.audit_findings(audit)
        dangling = [f for f in findings if f["title"].startswith("Dangling CNAME")]
        self.assertEqual(len(dangling), 1)
        self.assertEqual(dangling[0]["severity"], "low")

    def test_high_confidence_possible_takeover_is_high_until_claimed(self):
        audit = {"subdomains": {"success": True, "dangling": [], "takeovers": [
            {"subdomain": "www.example.com", "cname": "a.herokuapp.com", "service": "Heroku",
             "confidence": "high", "fingerprint_match": True, "target_resolves": False,
             "http_status": 404},
        ]}}
        findings = s.audit_findings(audit)
        self.assertEqual(findings[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
