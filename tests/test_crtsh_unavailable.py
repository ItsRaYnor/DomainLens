import os
import tempfile
import unittest
from unittest import mock

import crtsh
import security_checks as s
import osint


# crt.sh answers are cached in the database for a day. Without an isolated
# one these tests read whatever the developer's own DomainLens happens to
# have cached, and a mocked outage quietly returns a real earlier answer --
# which is exactly how they started failing on a machine that had run a scan.
_tempdir = None


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "crtsh.db")
    import db
    db.init_db()


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


def _clear_cache():
    """Between tests, not just between runs.

    Several of these ask about the same domain: the one that succeeds caches
    an answer, and the next one -- which mocks an outage -- gets that answer
    back instead of the failure it set up.
    """
    import db
    with db._lock, db._connect() as conn:
        conn.execute("DELETE FROM external_cache")


class CacheIsolatedTestCase(unittest.TestCase):
    def setUp(self):
        _clear_cache()


def _resp(status, payload=None):
    r = mock.Mock(status_code=status)
    r.json.return_value = payload if payload is not None else []
    return r


class CrtShRetryTests(CacheIsolatedTestCase):
    """crt.sh answers 502/503 for seconds at a time under load, so a single
    attempt fails far more often than the service is actually down.
    """

    def test_transient_502_is_retried_then_succeeds(self):
        rows = [{"name_value": "www.example.com"}]
        responses = [_resp(502), _resp(502), _resp(200, rows)]
        with mock.patch("crtsh.requests.get", side_effect=responses), \
             mock.patch("crtsh.time.sleep"):
            data, error, _meta = s._fetch_crtsh("example.com")
        self.assertIsNone(error)
        self.assertEqual(data, rows)

    def test_persistent_502_reports_a_clear_error(self):
        with mock.patch("crtsh.requests.get", return_value=_resp(502)), \
             mock.patch("crtsh.time.sleep"):
            data, error, _meta = s._fetch_crtsh("example.com")
        self.assertIsNone(data)
        self.assertIn("outage at crt.sh", error)

    def test_404_is_treated_as_transient(self):
        """The same query answered 502 and then 404 minutes apart during a
        real outage, so 404 is an availability symptom rather than "this
        domain has no certificates" — an empty result set comes back as an
        HTTP 200 with an empty array.
        """
        rows = [{"name_value": "www.example.com"}]
        getter = mock.Mock(side_effect=[_resp(404), _resp(200, rows)])
        with mock.patch("crtsh.requests.get", getter), \
             mock.patch("crtsh.time.sleep"):
            data, error, _meta = s._fetch_crtsh("example.com")
        self.assertIsNone(error)
        self.assertEqual(data, rows)
        self.assertEqual(getter.call_count, 2)

    def test_persistent_404_reports_it_as_an_outage(self):
        with mock.patch("crtsh.requests.get", return_value=_resp(404)), \
             mock.patch("crtsh.time.sleep"):
            data, error, _meta = s._fetch_crtsh("example.com")
        self.assertIsNone(data)
        self.assertIn("404", error)
        self.assertIn("not a problem with the scanned domain", error)

    def test_non_transient_status_is_not_retried(self):
        getter = mock.Mock(return_value=_resp(400))
        with mock.patch("crtsh.requests.get", getter), \
             mock.patch("crtsh.time.sleep"):
            data, error, _meta = s._fetch_crtsh("example.com")
        self.assertIsNone(data)
        self.assertEqual(getter.call_count, 1)

    def test_html_error_page_served_as_200_is_not_parsed_as_rows(self):
        bad = mock.Mock(status_code=200)
        bad.json.side_effect = ValueError("not json")
        with mock.patch("crtsh.requests.get", return_value=bad), \
             mock.patch("crtsh.time.sleep"):
            data, error, _meta = s._fetch_crtsh("example.com")
        self.assertIsNone(data)
        self.assertIn("non-JSON", error)

    def test_empty_result_set_is_a_success_not_an_error(self):
        with mock.patch("crtsh.requests.get", return_value=_resp(200, [])), \
             mock.patch("crtsh.time.sleep"):
            data, error, _meta = s._fetch_crtsh("example.com")
        self.assertIsNone(error)
        self.assertEqual(data, [])

    def test_connection_error_is_reported(self):
        with mock.patch("crtsh.requests.get", side_effect=OSError("boom")), \
             mock.patch("crtsh.time.sleep"):
            data, error, _meta = s._fetch_crtsh("example.com")
        self.assertIsNone(data)
        self.assertIn("failed", error)


class EnumerationFailureHonestyTests(CacheIsolatedTestCase):
    """A failed crt.sh lookup was swallowed, leaving only the apex — so a
    takeover scan that had enumerated nothing still reported "no dangling
    subdomains detected", which reads as a clean bill of health rather than
    an absent one.
    """

    def test_failure_is_reported_not_swallowed(self):
        with mock.patch("security_checks._fetch_crtsh", return_value=(None, "crt.sh is temporarily unavailable (HTTP 502)", {})):
            subs, discovered, error, _meta = s.enumerate_subdomains("example.com")
        self.assertEqual(subs, ["example.com"])  # apex only
        self.assertIsNotNone(error)
        self.assertIn("502", error)

    def test_success_reports_no_error(self):
        rows = [{"name_value": "a.example.com\nb.example.com"}]
        with mock.patch("security_checks._fetch_crtsh", return_value=(rows, None, {})):
            subs, discovered, error, _meta = s.enumerate_subdomains("example.com")
        self.assertIsNone(error)
        self.assertIn("a.example.com", subs)

    def test_scan_result_carries_the_source_error(self):
        with mock.patch("security_checks.enumerate_subdomains",
                        return_value=(["example.com"], 1, "crt.sh is temporarily unavailable (HTTP 502)", {})), \
             mock.patch("security_checks._check_one_takeover", return_value=None):
            result = s.check_subdomain_takeover("example.com")
        self.assertTrue(result["success"])
        self.assertIn("502", result["source_error"])

    def test_unavailable_source_is_not_listed_as_a_finding(self):
        """crt.sh being down is a limit of the scan, not a defect in the
        scanned domain. The owner cannot act on it, so putting it in the
        advice list only pads it with noise."""
        audit = {"subdomains": {
            "success": True, "takeovers": [], "dangling": [],
            "source_error": "crt.sh is temporarily unavailable (HTTP 502)",
        }}
        self.assertEqual(s.audit_findings(audit), [])

    def test_a_truncated_scan_is_not_listed_as_a_finding_either(self):
        audit = {"subdomains": {
            "success": True, "takeovers": [], "dangling": [],
            "truncated": True, "discovered_count": 200, "limit": 60,
        }}
        self.assertEqual(s.audit_findings(audit), [])

    def test_the_coverage_caveat_still_reaches_the_result(self):
        # Suppressing the finding must not suppress the fact itself, or
        # "no takeovers found" starts reading as a clean bill of health.
        with mock.patch("security_checks.enumerate_subdomains",
                        return_value=(["example.com"], 1, "crt.sh unavailable (HTTP 502)", {})), \
             mock.patch("security_checks._check_one_takeover", return_value=None):
            result = s.check_subdomain_takeover("example.com")
        self.assertIn("502", result["source_error"])

    def test_real_takeover_findings_are_unaffected(self):
        audit = {"subdomains": {
            "success": True, "dangling": [], "source_error": "crt.sh down",
            "takeovers": [{
                "subdomain": "a.example.com", "cname": "x.herokuapp.com",
                "service": "Heroku", "confidence": "high",
                "fingerprint_match": True, "target_resolves": False,
                "http_status": 404,
            }],
        }}
        titles = [f["title"] for f in s.audit_findings(audit)]
        self.assertTrue(any("Possible subdomain takeover" in t for t in titles))


class OsintCrtShTests(CacheIsolatedTestCase):

    def test_transient_502_is_retried(self):
        rows = [{"name_value": "www.example.com", "issuer_name": "CA"}]
        session = mock.Mock()
        session.get.side_effect = [_resp(502), _resp(200, rows)]
        with mock.patch("osint._session", return_value=session), \
             mock.patch("crtsh.time.sleep"):
            result = osint.certificate_transparency("example.com")
        self.assertTrue(result["success"])
        self.assertIn("www.example.com", result["subdomains"])

    def test_persistent_502_explains_it_is_a_crtsh_outage(self):
        session = mock.Mock()
        session.get.return_value = _resp(502)
        with mock.patch("osint._session", return_value=session), \
             mock.patch("crtsh.time.sleep"):
            result = osint.certificate_transparency("example.com")
        self.assertFalse(result["success"])
        self.assertIn("crt.sh", result["error"])
        self.assertIn("not a problem with the scanned domain", result["error"])

    def test_persistent_404_is_reported_as_an_outage_too(self):
        session = mock.Mock()
        session.get.return_value = _resp(404)
        with mock.patch("osint._session", return_value=session), \
             mock.patch("crtsh.time.sleep"):
            result = osint.certificate_transparency("example.com")
        self.assertFalse(result["success"])
        self.assertIn("404", result["error"])
        self.assertIn("not a problem with the scanned domain", result["error"])

    def test_both_call_sites_share_one_implementation(self):
        """The retry logic lived in two copies and had to be fixed twice."""
        import inspect
        self.assertIn("crtsh", inspect.getsource(s._fetch_crtsh))
        self.assertIn("crtsh", inspect.getsource(osint.certificate_transparency))


if __name__ == "__main__":
    unittest.main()
