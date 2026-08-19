import unittest

import recommendations


class WeakAuthRecommendationsTests(unittest.TestCase):
    def test_weak_credentials_generate_critical_advies(self):
        results = {
            "domain": "example.com",
            "weak_auth": {
                "success": True,
                "weak_credentials_found": True,
                "findings": [
                    {"url": "https://example.com/admin", "username": "admin", "method": "http_basic"},
                ],
            },
        }
        recs = recommendations.generate(results)
        titles = [r["title"] for r in recs]
        self.assertIn("Weak or default credentials accepted", titles)
        rec = next(r for r in recs if r["title"] == "Weak or default credentials accepted")
        self.assertIn("Re-run DomainLens", rec["retest"])
        self.assertEqual(rec["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
