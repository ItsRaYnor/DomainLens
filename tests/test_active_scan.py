import unittest
from unittest import mock

import active_scan


class ActiveScanTests(unittest.TestCase):
    def test_disabled_by_default(self):
        result = active_scan.scan("example.com", {"enabled": False})
        self.assertTrue(result["skipped"])
        self.assertFalse(result["enabled"])

    def test_hard_request_cap_is_enforced(self):
        homepage = mock.Mock(status_code=200, text="<html></html>", url="https://example.com/")

        def fake_get(url, timeout, allow_redirects=False, params=None):
            if url.rstrip("/") == "https://example.com":
                return homepage
            probe = mock.Mock(status_code=200, text="", headers={})
            return probe

        settings = {
            "enabled": True,
            "max_requests_per_scan": 3,
            "max_pages_crawled": 0,
            "delay_seconds": 0,
            "timeout_seconds": 3,
            "include_http": False,
            "extra_params": ["redirect", "url", "next", "dest", "target"],
        }
        with mock.patch("active_scan._get", side_effect=fake_get):
            result = active_scan.scan("example.com", settings)

        self.assertEqual(result["attempts"], 3)
        self.assertTrue(result["capped"])

    def test_detects_reflected_xss(self):
        from urllib.parse import unquote_plus

        def fake_get(url, timeout, allow_redirects=False, params=None):
            if url.rstrip("/") == "https://example.com":
                return mock.Mock(status_code=200, text='<html><a href="/search?q=x">s</a></html>', headers={}, url="https://example.com/")
            if "/search" in url and "q=" in url:
                # Reflect the injected marker verbatim (vulnerable behavior).
                # Real web frameworks decode query strings with '+' as space,
                # so use unquote_plus to mimic actual server-side parsing.
                value = unquote_plus(url.split("q=", 1)[1])
                return mock.Mock(status_code=200, text=f"<html>{value}</html>", headers={}, url=url)
            return mock.Mock(status_code=200, text="", headers={}, url=url)

        settings = {
            "enabled": True, "max_requests_per_scan": 30, "max_pages_crawled": 0,
            "delay_seconds": 0, "timeout_seconds": 3, "include_http": False,
            "extra_params": [],
        }
        with mock.patch("active_scan._get", side_effect=fake_get):
            result = active_scan.scan("example.com", settings)

        types = [f["type"] for f in result["findings"]]
        self.assertIn("reflected_xss", types)

    def test_detects_open_redirect(self):
        def fake_get(url, timeout, allow_redirects=False, params=None):
            if url.rstrip("/") == "https://example.com":
                return mock.Mock(status_code=200, text='<html><a href="/go?redirect=/home">g</a></html>', headers={}, url="https://example.com/")
            if "/go?" in url and "redirect=" in url and "domainlens-redirect-check.invalid" in url:
                return mock.Mock(status_code=302, headers={"Location": "https://domainlens-redirect-check.invalid/landing"}, text="", url=url)
            return mock.Mock(status_code=200, text="", headers={}, url=url)

        settings = {
            "enabled": True, "max_requests_per_scan": 30, "max_pages_crawled": 0,
            "delay_seconds": 0, "timeout_seconds": 3, "include_http": False,
            "extra_params": [],
        }
        with mock.patch("active_scan._get", side_effect=fake_get):
            result = active_scan.scan("example.com", settings)

        types = [f["type"] for f in result["findings"]]
        self.assertIn("open_redirect", types)

    def test_detects_sqli_error_signature(self):
        resp = mock.Mock(status_code=500, text="You have an error in your SQL syntax near ''", url="https://example.com/item?id=1")
        with mock.patch("active_scan._get", return_value=resp):
            result = active_scan._probe_sqli_error("https://example.com/item?id=1", "id", 3)
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "sqli_error_based")

    def test_no_findings_on_clean_target(self):
        def fake_get(url, timeout, allow_redirects=False, params=None):
            return mock.Mock(status_code=200, text="clean", headers={}, url=url)

        settings = {
            "enabled": True, "max_requests_per_scan": 30, "max_pages_crawled": 0,
            "delay_seconds": 0, "timeout_seconds": 3, "include_http": False,
            "extra_params": ["redirect"],
        }
        with mock.patch("active_scan._get", side_effect=fake_get):
            result = active_scan.scan("example.com", settings)
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["vulnerabilities_found"])

    def test_findings_from_scan_grading(self):
        scan_result = {
            "success": True,
            "enabled": True,
            "findings": [
                {"type": "reflected_xss", "url": "https://x/", "param": "q", "evidence": "e"},
                {"type": "open_redirect", "url": "https://x/", "param": "r", "evidence": "e"},
                {"type": "sqli_error_based", "url": "https://x/", "param": "id", "evidence": "e"},
            ],
        }
        findings = active_scan.findings_from_scan(scan_result)
        severities = {f["title"].split("'")[0].strip(): f["severity"] for f in findings}
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f["severity"] in ("critical", "medium") for f in findings))


if __name__ == "__main__":
    unittest.main()
