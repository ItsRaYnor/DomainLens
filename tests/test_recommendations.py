import unittest

import ncsc_tls
import recommendations


class RecommendationsAdviesTests(unittest.TestCase):
    def test_every_item_has_fix_and_retest(self):
        results = {
            "domain": "cdn.example.com",
            "spf": {"found": False},
            "dmarc": {"found": False},
            "https_redirect": {"pass": False},
        }
        recs = recommendations.generate(results)
        self.assertGreater(len(recs), 0)
        for r in recs:
            self.assertTrue(r.get("fix"), r["title"])
            self.assertTrue(r.get("retest"), r["title"])
            self.assertIn("cdn.example.com", r["retest"])

    def test_ncsc_cipher_order_includes_advies_and_retest(self):
        deep = {
            "success": True,
            "protocols": [
                {"name": "TLS 1.2", "supported": True},
                {"name": "TLS 1.3", "supported": True},
            ],
            "ciphers": [
                {"name": "ECDHE-ECDSA-AES256-SHA384", "protocol": "TLSv1.2"},
                {"name": "ECDHE-ECDSA-AES128-CCM", "protocol": "TLSv1.2"},
                {"name": "ECDHE-ECDSA-AES128-SHA", "protocol": "TLSv1.2"},
            ],
            "cipher_order": {
                "applicable": True,
                "pass": False,
                "server_preferred": "ECDHE-ECDSA-AES256-SHA384",
                "server_preferred_iana": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                "server_preferred_level": "phased_out",
                "expected_preferred": "ECDHE-ECDSA-AES128-CCM",
                "expected_preferred_iana": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
                "expected_preferred_level": "sufficient",
                "detail": "Server preferred phase-out over Sufficient.",
            },
            "certificate": {"success": True, "key_type": "EC", "key_bits": 256},
            "tls_compression": False,
            "ocsp_stapling": False,
            "hsts": {"enabled": True, "value": "max-age=31536000"},
        }
        report = ncsc_tls.assess(deep)
        order = next(f for f in report["findings"] if f["id"] == "cipher-order")
        self.assertIn("ssl_prefer_server_ciphers", order["fix"])
        self.assertIn("internet.nl", order["retest"])

        recs = recommendations.generate({"domain": "cdn.example.com", "ncsc_tls": report})
        titles = [r["title"] for r in recs]
        self.assertTrue(any("Cipher suite order" in t for t in titles))
        order_rec = next(r for r in recs if "Cipher suite order" in r["title"])
        self.assertIn("DomainLens", order_rec["retest"])
        self.assertIn("Volgorde", order_rec["retest"])


if __name__ == "__main__":
    unittest.main()
