import os
import tempfile
import unittest

import scan_diff


class ScanDiffDirectionTests(unittest.TestCase):
    """A comparison must say which way a dimension moved, and must never invent
    a direction where one side was not measured — an absent check is not a
    regression.
    """

    def test_tls_grade_drop_is_worse(self):
        old = {"tls_deep": {"success": True, "grade": "A"}}
        new = {"tls_deep": {"success": True, "grade": "F"}}
        row = self._row(scan_diff.compare_dimensions(old, new), "tls_grade")
        self.assertEqual(row["status"], "worse")
        self.assertEqual((row["old"], row["new"]), ("A", "F"))

    def test_tls_grade_rise_is_better(self):
        old = {"tls_deep": {"success": True, "grade": "C"}}
        new = {"tls_deep": {"success": True, "grade": "A+"}}
        self.assertEqual(self._row(scan_diff.compare_dimensions(old, new), "tls_grade")["status"], "better")

    def test_missing_check_on_one_side_is_unmeasured_not_worse(self):
        old = {"tls_deep": {"success": True, "grade": "A"}}
        new = {}  # this scan did not run the TLS check
        self.assertEqual(self._row(scan_diff.compare_dimensions(old, new), "tls_grade")["status"], "unmeasured")

    def test_new_blacklist_listing_is_worse(self):
        old = {"blacklist": {"is_listed": False, "listed": []}}
        new = {"blacklist": {"is_listed": True, "listed": ["sbl", "xbl"]}}
        row = self._row(scan_diff.compare_dimensions(old, new), "blacklist")
        self.assertEqual(row["status"], "worse")
        self.assertEqual((row["old"], row["new"]), (0, 2))

    def test_a_newly_open_port_is_worse(self):
        old = {"ports": {"open": [443]}}
        new = {"ports": {"open": [443, 22]}}
        self.assertEqual(self._row(scan_diff.compare_dimensions(old, new), "open_ports")["status"], "worse")

    def test_closing_a_port_is_better(self):
        old = {"ports": {"open": [443, 22]}}
        new = {"ports": {"open": [443]}}
        self.assertEqual(self._row(scan_diff.compare_dimensions(old, new), "open_ports")["status"], "better")

    def test_losing_dnssec_is_worse(self):
        old = {"dnssec": {"signed": True}}
        new = {"dnssec": {"signed": False}}
        self.assertEqual(self._row(scan_diff.compare_dimensions(old, new), "dnssec")["status"], "worse")

    def test_a_new_critical_recommendation_is_worse(self):
        diff = scan_diff.compare_dimensions({}, {},
                                 old_severity={"critical": 0, "high": 1},
                                 new_severity={"critical": 1, "high": 1})
        self.assertEqual(self._row(diff, "recommendations")["status"], "worse")

    def test_summary_counts_the_directions(self):
        old = {"tls_deep": {"success": True, "grade": "A"},
               "dnssec": {"signed": True}}
        new = {"tls_deep": {"success": True, "grade": "F"},
               "dnssec": {"signed": True}}
        summary = scan_diff.compare_dimensions(old, new)["summary"]
        self.assertEqual(summary["worse"], 1)

    def test_a_header_going_missing_is_worse(self):
        old = {"http_headers": {"success": True, "headers_missing": []}}
        new = {"http_headers": {"success": True, "headers_missing": ["Strict-Transport-Security"]}}
        row = self._row(scan_diff.compare_dimensions(old, new), "missing_headers")
        self.assertEqual(row["status"], "worse")
        self.assertEqual(row["new"], ["Strict-Transport-Security"])

    def test_fixing_a_header_is_better(self):
        old = {"http_headers": {"success": True, "headers_missing": ["Content-Security-Policy"]}}
        new = {"http_headers": {"success": True, "headers_missing": []}}
        self.assertEqual(self._row(scan_diff.compare_dimensions(old, new), "missing_headers")["status"], "better")

    def test_losing_an_email_mechanism_is_worse(self):
        old = {"spf": {"pass": True}, "dmarc": {"pass": True}, "dkim": {"pass": True}}
        new = {"spf": {"pass": True}, "dmarc": {"pass": False}, "dkim": {"pass": True}}
        row = self._row(scan_diff.compare_dimensions(old, new), "email_auth")
        self.assertEqual(row["status"], "worse")
        self.assertEqual((row["old"], row["new"]), (3, 2))

    def test_email_dimension_absent_when_no_email_check_ran(self):
        # No email keys at all: the dimension must be unmeasured, not 0 pass.
        row = self._row(scan_diff.compare_dimensions({"tls_deep": {"success": True, "grade": "A"}},
                                          {"tls_deep": {"success": True, "grade": "A"}}), "email_auth")
        self.assertEqual(row["status"], "unmeasured")

    def test_new_threat_feed_hits_are_worse(self):
        old = {"osint": {"success": True, "summary": {"threat_hits": 0}}}
        new = {"osint": {"success": True, "summary": {"threat_hits": 3}}}
        self.assertEqual(self._row(scan_diff.compare_dimensions(old, new), "reputation")["status"], "worse")

    def test_a_new_leaked_secret_is_worse(self):
        old = {"js_scan": {"success": True, "secrets_found": []}}
        new = {"js_scan": {"success": True, "secrets_found": [{"type": "aws_key"}]}}
        self.assertEqual(self._row(scan_diff.compare_dimensions(old, new), "secrets")["status"], "worse")

    def test_a_new_vulnerable_library_is_worse(self):
        old = {"js_scan": {"success": True, "vulnerable_libraries": [{"name": "jquery"}]}}
        new = {"js_scan": {"success": True, "vulnerable_libraries": [{"name": "jquery"}, {"name": "lodash"}]}}
        self.assertEqual(self._row(scan_diff.compare_dimensions(old, new), "vulnerable_js")["status"], "worse")

    def _row(self, diff, key):
        return next(r for r in diff["dimensions"] if r["key"] == key)


class CompareEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "cmp.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["AUTH_REQUIRE_LOGIN"] = "0"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        import importlib
        import db
        import app
        self.db = importlib.reload(db)
        self.db.init_db()
        self.app = importlib.reload(app)
        self.client = self.app.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "AUTH_REQUIRE_LOGIN", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    def test_compare_two_saved_scans_reports_regression_and_links(self):
        a = self.db.save_scan("example.com", {"tls_deep": {"success": True, "grade": "A"}})
        b = self.db.save_scan("example.com", {"tls_deep": {"success": True, "grade": "F"}})
        payload = self.client.get(f"/api/compare?a={a}&b={b}").get_json()
        self.assertEqual(payload["a"]["report_url"], f"/report/{a}")
        self.assertEqual(payload["b"]["report_url"], f"/report/{b}")
        tls = next(r for r in payload["diff"]["dimensions"] if r["key"] == "tls_grade")
        self.assertEqual(tls["status"], "worse")

    def test_missing_scan_is_404(self):
        a = self.db.save_scan("example.com", {"tls_deep": {"success": True, "grade": "A"}})
        self.assertEqual(self.client.get(f"/api/compare?a={a}&b=999999").status_code, 404)


if __name__ == "__main__":
    unittest.main()
