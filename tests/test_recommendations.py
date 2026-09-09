import unittest
from datetime import datetime, timedelta, timezone

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

    def test_unmeasured_mail_dns_does_not_become_missing_findings(self):
        """A DNS outage says nothing about the domain's SPF or DMARC posture."""
        recs = recommendations.generate({
            "domain": "example.com",
            "spf": {"state": "unmeasured", "found": None},
            "dmarc": {"state": "unmeasured", "found": None},
            "dkim": {"state": "unmeasured", "found": None},
        })
        titles = [r["title"] for r in recs]
        self.assertFalse(any("SPF record missing" in t for t in titles), titles)
        self.assertFalse(any("DMARC record missing" in t for t in titles), titles)
        self.assertFalse(any("DKIM selectors" in t for t in titles), titles)

    def test_tls_and_ncsc_emit_one_condition(self):
        """Compliance context may enrich a TLS finding but must not duplicate it."""
        deep = {
            "success": True,
            "grade": "B",
            "protocols": [
                {"name": "TLS 1.0", "supported": True},
                {"name": "TLS 1.2", "supported": True},
                {"name": "TLS 1.3", "supported": True},
            ],
            "ciphers": [],
            "cipher_summary": {},
            "certificate": {},
            "hsts": {"enabled": True, "max_age": 31536000,
                     "include_subdomains": True, "preload": True},
            "tls_compression": False,
        }
        report = ncsc_tls.assess(deep)
        recs = recommendations.generate({"tls_deep": deep, "ncsc_tls": report})
        tls10 = [r for r in recs if "TLS 1.0" in r["title"]]
        self.assertEqual(1, len(tls10), tls10)
        self.assertEqual("high", tls10[0]["severity"])

    def test_optional_header_count_does_not_inflate_severity(self):
        recs = recommendations._headers({"http_headers": {
            "success": True,
            "headers_missing": [
                "Cross-Origin-Embedder-Policy", "Cross-Origin-Opener-Policy",
                "Cross-Origin-Resource-Policy", "Permissions-Policy",
            ],
        }})
        self.assertEqual("info", recs[0]["severity"])

    def test_expiry_warning_escalates_with_urgency(self):
        def severity(days):
            exp = (datetime.now(timezone.utc) + timedelta(days=days, hours=1)).isoformat()
            return recommendations._whois({
                "whois": {"data": {"expiration_date": exp}},
            })[0]["severity"]

        self.assertEqual("info", severity(20))
        self.assertEqual("medium", severity(5))
        self.assertEqual("high", severity(1))

    def test_dnsbl_without_mail_egress_context_is_informational(self):
        recs = recommendations._blacklist({
            "blacklist": {"is_listed": True, "listed": ["example.invalid"]},
        })
        self.assertEqual("info", recs[0]["severity"])
        self.assertIn("context", recs[0]["title"].lower())

    def test_ct_hostname_count_is_inventory_not_a_defect(self):
        recs = recommendations._osint({
            "osint": {
                "success": True,
                "summary": {"subdomain_count": 25},
                "sources": {},
            },
        })
        item = next(r for r in recs if "Certificate Transparency footprint" in r["title"])
        self.assertEqual("info", item["severity"])

    def test_provider_specific_csp_advice_enriches_one_finding(self):
        """HubSpot remediation is context for missing CSP, not another defect."""
        recs = recommendations.generate({
            "domain": "example.com",
            "http_headers": {
                "success": True,
                "headers_missing": ["Content-Security-Policy"],
            },
            "hubspot_cf": {
                "success": True,
                "findings": [{
                    "severity": "medium",
                    "title": "HubSpot site missing Content-Security-Policy",
                    "problem": "Missing CSP",
                    "fix": "Configure CSP in HubSpot.",
                }],
            },
        })
        csp = [r for r in recs if "Content-Security-Policy" in r["title"]]
        self.assertEqual(1, len(csp), csp)
        self.assertIn("HubSpot", csp[0]["fix"])


if __name__ == "__main__":
    unittest.main()
