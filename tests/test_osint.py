import os
import tempfile
import unittest
from unittest import mock


class OsintFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "test-domainlens.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ.pop("ABUSECH_AUTH_KEY", None)
        os.environ.pop("OTX_API_KEY", None)

        import importlib
        import osint

        self.osint = importlib.reload(osint)

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "ABUSECH_AUTH_KEY", "OTX_API_KEY"):
            os.environ.pop(key, None)

    def test_certificate_transparency_parses_hosts(self):
        payload = [
            {"name_value": "www.example.com\nexample.com", "issuer_name": "Let's Encrypt"},
            {"name_value": "*.cdn.example.com", "issuer_name": "DigiCert"},
            {"name_value": "evil.com", "issuer_name": "Other"},
        ]
        fake = mock.Mock(status_code=200)
        fake.raise_for_status.return_value = None
        fake.json.return_value = payload
        with mock.patch.object(self.osint.requests.Session, "get", return_value=fake):
            result = self.osint.certificate_transparency("example.com")
        self.assertTrue(result["success"])
        self.assertIn("www.example.com", result["subdomains"])
        self.assertIn("cdn.example.com", result["subdomains"])
        self.assertNotIn("evil.com", result["subdomains"])

    def test_collect_osint_skips_optional_feeds_without_keys(self):
        with mock.patch.object(self.osint, "certificate_transparency", return_value={"success": True, "subdomains": ["a.example.com"], "subdomain_count": 1, "certificate_count": 1}):
            with mock.patch.object(self.osint, "wayback_snapshots", return_value={"success": True, "snapshots": [], "count": 0}):
                with mock.patch.object(self.osint, "ip_context", return_value={"success": True, "ip": "93.184.216.34", "geo": {"asn": "AS15133", "country": "US"}}):
                    result = self.osint.collect_osint("example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["summary"]["subdomain_count"], 1)
        self.assertTrue(result["sources"]["threatfox"]["skipped"])
        self.assertTrue(result["sources"]["urlhaus"]["skipped"])
        self.assertTrue(result["sources"]["otx"]["skipped"])


if __name__ == "__main__":
    unittest.main()
