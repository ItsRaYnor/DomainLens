import unittest
from unittest import mock

import hubspot_cf


class HubspotCloudflareTests(unittest.TestCase):
    def test_detects_hubspot_behind_cloudflare(self):
        html = """
        <html><head>
        <script src="https://js.hs-scripts.com/123456.js"></script>
        </head><body>hs-script-loader</body></html>
        """
        fake = mock.Mock()
        fake.status_code = 200
        fake.url = "https://example.com/"
        fake.headers = {
            "Server": "cloudflare",
            "CF-Ray": "abc-AMS",
            "Set-Cookie": "__cf_bm=x; Path=/; __hstc=1; hubspotutk=abc",
        }
        fake.text = html
        fake.history = []

        with mock.patch("hubspot_cf.requests.get", return_value=fake):
            with mock.patch("hubspot_cf._cname_chain", return_value=["cdn.example.net"]):
                with mock.patch("hubspot_cf.socket.gethostbyname", return_value="1.2.3.4"):
                    with mock.patch("hubspot_cf._probe_paths", return_value=[]):
                        result = hubspot_cf.scan_hubspot_cloudflare("example.com")

        self.assertTrue(result["success"])
        self.assertTrue(result["hubspot"]["detected"])
        self.assertTrue(result["cloudflare"]["detected"])
        self.assertTrue(result["behind_cloudflare"])
        self.assertIn("123456", result["hubspot"]["portal_ids"])
        ids = {f["id"] for f in result["findings"]}
        self.assertIn("hubspot_behind_cloudflare", ids)
        self.assertIn("hubspot_tracking_without_banner", ids)

    def test_recommendations_include_hubspot_findings(self):
        import recommendations
        results = {
            "hubspot_cf": {
                "success": True,
                "findings": [{
                    "severity": "high",
                    "title": "HubSpot tracking cookies without consent banner script",
                    "problem": "cookies without banner",
                    "fix": "Enable consent banner",
                }],
            }
        }
        recs = recommendations.generate(results)
        self.assertTrue(any(r["category"] == "HubSpot" for r in recs))


if __name__ == "__main__":
    unittest.main()
