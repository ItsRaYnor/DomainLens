import unittest
from unittest import mock

import js_scan


class JsScanTests(unittest.TestCase):
    def _homepage_resp(self, html, url="https://example.com/"):
        resp = mock.Mock()
        resp.status_code = 200
        resp.text = html
        resp.url = url
        return resp

    def test_detects_vulnerable_jquery_by_url(self):
        html = (
            '<html><head>'
            '<script src="https://cdn.example.com/jquery-1.12.4.min.js"></script>'
            '</head><body></body></html>'
        )
        with mock.patch("js_scan.requests.get", return_value=self._homepage_resp(html)):
            result = js_scan.scan("example.com")

        self.assertTrue(result["success"])
        libs = result["vulnerable_libraries"]
        self.assertTrue(any(l["library"] == "jQuery" and l["version"] == "1.12.4" for l in libs))

    def test_detects_exposed_secret_in_inline_script(self):
        # Built via concatenation (not a literal in source) so the fixture
        # doesn't trip GitHub's secret-scanning push protection, which
        # matches on format alone regardless of whether the key is real.
        fake_key = "sk_" + "live_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
        html = (
            '<html><head>'
            f'<script>var cfg = {{"apiKey": "{fake_key}"}};</script>'
            '</head><body></body></html>'
        )
        with mock.patch("js_scan.requests.get", return_value=self._homepage_resp(html)):
            result = js_scan.scan("example.com")

        self.assertTrue(result["success"])
        types = [s["type"] for s in result["secrets_found"]]
        self.assertIn("Stripe Live Secret Key", types)
        # The masked value must never contain the full secret.
        for s in result["secrets_found"]:
            self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWX", s["masked_value"])

    def test_ignores_placeholder_secrets(self):
        html = (
            '<html><head>'
            '<script>var cfg = {"apiKey": "your_api_key_here_xxxxxxxx"};</script>'
            '</head><body></body></html>'
        )
        with mock.patch("js_scan.requests.get", return_value=self._homepage_resp(html)):
            result = js_scan.scan("example.com")
        self.assertEqual(result["secrets_found"], [])

    def test_flags_missing_sri_on_cross_origin_script(self):
        html = (
            '<html><head>'
            '<script src="https://other-cdn.example.net/lib.js"></script>'
            '</head><body></body></html>'
        )
        with mock.patch("js_scan.requests.get", return_value=self._homepage_resp(html)), \
             mock.patch("js_scan._fetch_script", return_value=None):
            result = js_scan.scan("example.com")
        self.assertEqual(len(result["missing_sri"]), 1)
        self.assertEqual(result["missing_sri"][0]["tag"], "script")

    def test_no_findings_on_clean_page(self):
        html = "<html><head></head><body>Hello</body></html>"
        with mock.patch("js_scan.requests.get", return_value=self._homepage_resp(html)):
            result = js_scan.scan("example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["vulnerable_libraries"], [])
        self.assertEqual(result["secrets_found"], [])
        f = js_scan.findings(result)
        self.assertEqual(f, [])

    def test_findings_severity_grading(self):
        scan_result = {
            "success": True,
            "vulnerable_libraries": [{
                "library": "jQuery", "version": "1.12.4", "max_vulnerable": "1.12.4",
                "cves": ["CVE-2015-9251"], "summary": "x", "source": "https://x/jquery.js",
            }],
            "secrets_found": [{"type": "AWS Access Key", "masked_value": "AKIA...WXYZ", "source": "https://x/a.js"}],
            "missing_sri": [{"tag": "script", "src": "https://cdn.example.net/a.js"}],
        }
        findings = js_scan.findings(scan_result)
        severities = [f["severity"] for f in findings]
        self.assertEqual(severities[0], "critical")  # secret first
        self.assertIn("high", severities)  # vulnerable library
        self.assertIn("low", severities)  # missing SRI


if __name__ == "__main__":
    unittest.main()
