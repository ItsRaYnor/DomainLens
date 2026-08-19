import unittest

import ncsc_tls
import recommendations


class NcscTlsClassificationTests(unittest.TestCase):
    def test_tls13_aes256_gcm_is_good(self):
        result = ncsc_tls.classify_cipher_suite("TLS_AES_256_GCM_SHA384")
        self.assertEqual(result["level"], ncsc_tls.LEVEL_GOOD)
        self.assertEqual(result["components"]["bulk_encryption"]["level"], ncsc_tls.LEVEL_GOOD)

    def test_ecdhe_aes128_gcm_is_sufficient(self):
        result = ncsc_tls.classify_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")
        self.assertEqual(result["level"], ncsc_tls.LEVEL_SUFFICIENT)
        self.assertEqual(result["components"]["key_exchange"]["name"], "ECDHE")
        self.assertEqual(result["components"]["bulk_encryption"]["level"], ncsc_tls.LEVEL_SUFFICIENT)

    def test_ecdsa_aes256_gcm_not_misclassified_as_des(self):
        """Regression: 'DES' substring must not match inside 'ECDSA'."""
        result = ncsc_tls.classify_cipher_suite("ECDHE-ECDSA-AES256-GCM-SHA384")
        self.assertEqual(result["level"], ncsc_tls.LEVEL_SUFFICIENT)
        self.assertEqual(result["components"]["bulk_encryption"]["level"], ncsc_tls.LEVEL_GOOD)

    def test_ecdsa_cbc_sha1_insufficient_like_internet_nl(self):
        result = ncsc_tls.classify_cipher_suite("ECDHE-ECDSA-AES256-SHA")
        self.assertEqual(result["level"], ncsc_tls.LEVEL_INSUFFICIENT)
        result = ncsc_tls.classify_cipher_suite("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA")
        self.assertEqual(result["level"], ncsc_tls.LEVEL_INSUFFICIENT)

    def test_ecdsa_cbc_sha384_is_phased_out(self):
        result = ncsc_tls.classify_cipher_suite("ECDHE-ECDSA-AES256-SHA384")
        self.assertEqual(result["level"], ncsc_tls.LEVEL_PHASED_OUT)

    def test_cbc_is_phased_out(self):
        result = ncsc_tls.classify_cipher_suite("ECDHE-RSA-AES256-SHA384")
        self.assertEqual(result["level"], ncsc_tls.LEVEL_PHASED_OUT)
        self.assertEqual(result["components"]["bulk_encryption"]["level"], ncsc_tls.LEVEL_PHASED_OUT)

    def test_static_rsa_sha1_is_insufficient(self):
        result = ncsc_tls.classify_cipher_suite("AES256-SHA")
        self.assertEqual(result["level"], ncsc_tls.LEVEL_INSUFFICIENT)
        self.assertEqual(result["components"]["key_exchange"]["level"], ncsc_tls.LEVEL_INSUFFICIENT)
        self.assertEqual(result["components"]["hash"]["level"], ncsc_tls.LEVEL_INSUFFICIENT)

    def test_3des_is_insufficient(self):
        result = ncsc_tls.classify_cipher_suite("ECDHE-RSA-DES-CBC3-SHA")
        self.assertEqual(result["level"], ncsc_tls.LEVEL_INSUFFICIENT)

    def test_dhe_is_phased_out(self):
        result = ncsc_tls.classify_cipher_suite("DHE-RSA-AES128-GCM-SHA256")
        self.assertEqual(result["components"]["key_exchange"]["level"], ncsc_tls.LEVEL_PHASED_OUT)
        self.assertEqual(result["level"], ncsc_tls.LEVEL_PHASED_OUT)


class NcscTlsAssessTests(unittest.TestCase):
    def _tls_deep(self, **overrides):
        base = {
            "success": True,
            "protocols": [
                {"name": "TLS 1.0", "supported": False},
                {"name": "TLS 1.1", "supported": False},
                {"name": "TLS 1.2", "supported": True},
                {"name": "TLS 1.3", "supported": True},
            ],
            "ciphers": [
                {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
                {"name": "ECDHE-RSA-AES128-GCM-SHA256", "protocol": "TLSv1.2", "bits": 128},
            ],
            "tls_compression": False,
            "ocsp_stapling": True,
            "certificate": {
                "success": True,
                "expired": False,
                "self_signed": False,
                "key_type": "RSA",
                "key_bits": 3072,
            },
            "hsts": {"enabled": True, "preload": True},
        }
        base.update(overrides)
        return base

    def test_compliant_configuration(self):
        report = ncsc_tls.assess(self._tls_deep())
        self.assertTrue(report["success"])
        self.assertTrue(report["pass"])
        self.assertIn(report["overall_level"], {ncsc_tls.LEVEL_GOOD, ncsc_tls.LEVEL_SUFFICIENT})
        self.assertEqual(report["guideline"], ncsc_tls.GUIDELINE)

    def test_tls10_makes_insufficient(self):
        deep = self._tls_deep()
        deep["protocols"] = [
            {"name": "TLS 1.0", "supported": True},
            {"name": "TLS 1.1", "supported": False},
            {"name": "TLS 1.2", "supported": True},
            {"name": "TLS 1.3", "supported": True},
        ]
        report = ncsc_tls.assess(deep)
        self.assertEqual(report["overall_level"], ncsc_tls.LEVEL_INSUFFICIENT)
        self.assertFalse(report["pass"])
        ids = {f["id"] for f in report["findings"]}
        self.assertIn("proto-tls-1.0", ids)

    def test_compression_insufficient(self):
        report = ncsc_tls.assess(self._tls_deep(tls_compression=True))
        self.assertEqual(report["overall_level"], ncsc_tls.LEVEL_INSUFFICIENT)
        self.assertTrue(any(f["id"] == "tls-compression" for f in report["findings"]))

    def test_rsa_2048_phased_out(self):
        deep = self._tls_deep()
        deep["certificate"]["key_bits"] = 2048
        report = ncsc_tls.assess(deep)
        self.assertEqual(report["certificate"]["level"], ncsc_tls.LEVEL_PHASED_OUT)
        self.assertTrue(any(f["id"] == "cert-key-phased-out" for f in report["findings"]))

    def test_recommendations_include_ncsc_findings(self):
        deep = self._tls_deep()
        deep["protocols"][0]["supported"] = True  # TLS 1.0
        results = {"ncsc_tls": ncsc_tls.assess(deep)}
        recs = recommendations.generate(results)
        self.assertTrue(any(r["category"] == "NCSC TLS" for r in recs))

    def test_internet_nl_style_outdated_ciphers_fail(self):
        """Suites commonly reported by internet.nl for outdated TLS configs must fail NCSC."""
        deep = self._tls_deep()
        deep["ciphers"] = [
            {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
            {"name": "ECDHE-ECDSA-AES256-GCM-SHA384", "protocol": "TLSv1.2", "bits": 256},
            {"name": "ECDHE-ECDSA-AES256-SHA", "protocol": "TLSv1.2", "bits": 256},
            {"name": "ECDHE-ECDSA-AES128-SHA", "protocol": "TLSv1.2", "bits": 128},
            {"name": "ECDHE-ECDSA-AES256-SHA384", "protocol": "TLSv1.2", "bits": 256},
            {"name": "ECDHE-ECDSA-AES128-SHA256", "protocol": "TLSv1.2", "bits": 128},
        ]
        report = ncsc_tls.assess(deep)
        self.assertEqual(report["overall_level"], ncsc_tls.LEVEL_INSUFFICIENT)
        self.assertFalse(report["pass"])
        self.assertGreaterEqual(report["cipher_summary"]["insufficient"], 2)
        self.assertGreaterEqual(report["cipher_summary"]["phased_out"], 2)

    def test_cipher_order_finding_from_tls_deep(self):
        deep = self._tls_deep()
        deep["cipher_order"] = {
            "server_preferred_iana": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "expected_preferred_iana": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
            "applicable": True,
            "pass": False,
            "server_preferred": "ECDHE-ECDSA-AES256-SHA384",
            "server_preferred_level": "phased_out",
            "expected_preferred": "ECDHE-ECDSA-AES128-CCM",
            "expected_preferred_level": "sufficient",
            "detail": "Server preferred a phase-out suite over a Sufficient suite.",
        }
        report = ncsc_tls.assess(deep)
        self.assertFalse(report["pass"])
        self.assertTrue(any(f["id"] == "cipher-order" for f in report["findings"]))
        self.assertEqual(report["cipher_order"]["server_preferred"], "ECDHE-ECDSA-AES256-SHA384")


if __name__ == "__main__":
    unittest.main()
