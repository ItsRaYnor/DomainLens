import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch


class HstsProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(cls.tempdir.name, "hsts.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import app
        import recommendations

        cls.app = importlib.reload(app)
        cls.recommendations = importlib.reload(recommendations)

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_blocked_response_without_hsts_is_inconclusive(self):
        resp = MagicMock()
        resp.status_code = 403
        resp.headers = {
            "Server": "BunnyCDN-XX-1",
            "CDN-PullZone": "100001",
            "CDN-RequestCountryCode": "US",
            "Cache-Control": "no-cache",
        }
        with patch.object(self.app, "_http_request", return_value=resp):
            result = self.app._probe_hsts("cdn.example.com")
        self.assertIsNone(result["enabled"])
        self.assertTrue(result["blocked"])
        self.assertIn("cdn_blocked", result["block_reason"])
        self.assertIn("_geo", result["block_reason"])
        self.assertEqual(result["request_country"], "US")
        self.assertIn("NL/DE/BE", result["block_detail"])

    def test_benelux_country_block_still_inconclusive(self):
        resp = MagicMock()
        resp.status_code = 403
        resp.headers = {
            "Server": "BunnyCDN",
            "CDN-PullZone": "1",
            "CDN-RequestCountryCode": "NL",
        }
        with patch.object(self.app, "_http_request", return_value=resp):
            result = self.app._probe_hsts("example.com")
        self.assertIsNone(result["enabled"])
        self.assertTrue(result["blocked"])
        self.assertEqual(result["request_country"], "NL")
        self.assertNotIn("_geo", result["block_reason"])

    def test_hsts_present_on_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Server": "BunnyCDN",
        }
        with patch.object(self.app, "_http_request", return_value=resp):
            result = self.app._probe_hsts("example.com")
        self.assertTrue(result["enabled"])
        self.assertEqual(result["max_age"], 31536000)
        self.assertTrue(result["include_subdomains"])
        self.assertFalse(result["blocked"])

    def test_recommendation_skips_missing_hsts_when_blocked(self):
        results = {
            "tls_deep": {
                "success": True,
                "grade": "A",
                "protocols": [],
                "cipher_summary": {},
                "hsts": {
                    "enabled": None,
                    "blocked": True,
                    "block_reason": "cdn_blocked_403_US_geo",
                    "block_detail": (
                        "CDN geo-blocked this probe (request country US; "
                        "site may allow only NL/DE/BE)."
                    ),
                    "request_country": "US",
                    "value": "",
                },
            }
        }
        recs = self.recommendations.generate(results)
        titles = [r["title"] for r in recs]
        self.assertIn("HSTS could not be verified", titles)
        self.assertNotIn("HSTS header missing", titles)
        hsts_rec = next(r for r in recs if r["title"] == "HSTS could not be verified")
        self.assertIn("NL/DE/BE", hsts_rec["problem"])
        self.assertIn("NL", hsts_rec["fix"])


if __name__ == "__main__":
    unittest.main()
