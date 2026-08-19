import unittest
from unittest.mock import patch

import cdn_hardening
import ncsc_tls
import recommendations


class CdnDetectTests(unittest.TestCase):
    def test_detect_bunny(self):
        http = {
            "success": True,
            "server": "BunnyCDN-XX-1",
            "headers_found": {},
            "notable_headers": {
                "cdn-pullzone": "100001",
                "cdn-requestcountrycode": "US",
            },
            "blocked": True,
        }
        cdn = cdn_hardening.detect_cdn(http_headers=http)
        self.assertEqual(cdn["id"], cdn_hardening.CDN_BUNNY)
        self.assertEqual(cdn["geo_country"], "US")

    def test_detect_cloudflare(self):
        http = {
            "server": "cloudflare",
            "notable_headers": {"cf-ray": "abc-AMS", "cf-ipcountry": "NL"},
        }
        cdn = cdn_hardening.detect_cdn(http_headers=http)
        self.assertEqual(cdn["id"], cdn_hardening.CDN_CLOUDFLARE)

    def test_detect_ovh_cname(self):
        deep = {"cname_chain": ["example.cdn.ovh.net"], "infrastructure": []}
        cdn = cdn_hardening.detect_cdn(http_deep=deep)
        self.assertEqual(cdn["id"], cdn_hardening.CDN_OVH)


class SignatureHashNcscTests(unittest.TestCase):
    def _tls_deep(self, **sig):
        return {
            "success": True,
            "protocols": [
                {"name": "TLS 1.0", "supported": False},
                {"name": "TLS 1.1", "supported": False},
                {"name": "TLS 1.2", "supported": True},
                {"name": "TLS 1.3", "supported": True},
            ],
            "ciphers": [
                {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
                {"name": "ECDHE-ECDSA-AES128-GCM-SHA256", "protocol": "TLSv1.2", "bits": 128},
            ],
            "tls_compression": False,
            "ocsp_stapling": True,
            "certificate": {
                "success": True,
                "expired": False,
                "self_signed": False,
                "key_type": "EC",
                "key_bits": 256,
            },
            "hsts": {"enabled": True},
            "signature_hashes": {
                "applicable": True,
                "evaluated": True,
                "pass": not bool(sig.get("insufficient")),
                "insufficient": sig.get("insufficient", []),
                "phased_out": sig.get("phased_out", []),
                "good": sig.get("good", ["SHA256"]),
                "by_address": sig.get("by_address", []),
                "detail": sig.get("detail"),
            },
        }

    def test_sha1_fails_ncsc_like_internet_nl(self):
        deep = self._tls_deep(
            insufficient=["SHA1"],
            by_address=[
                {
                    "address": "203.0.113.10",
                    "family": "IPv4",
                    "insufficient": ["SHA1"],
                    "good": ["SHA256"],
                },
                {
                    "address": "2001:db8::10",
                    "family": "IPv6",
                    "insufficient": ["SHA1"],
                    "good": ["SHA256"],
                },
            ],
            detail="Server accepts SHA1",
        )
        report = ncsc_tls.assess(deep)
        self.assertEqual(report["overall_level"], ncsc_tls.LEVEL_INSUFFICIENT)
        self.assertFalse(report["pass"])
        ids = {f["id"] for f in report["findings"]}
        self.assertIn("signature-hash-insufficient", ids)

    def test_good_hashes_pass(self):
        report = ncsc_tls.assess(self._tls_deep(good=["SHA256", "SHA384"]))
        self.assertTrue(report["pass"])
        ids = {f["id"] for f in report["findings"]}
        self.assertNotIn("signature-hash-insufficient", ids)

    def test_bunny_advice_mentions_support_ticket(self):
        adv = cdn_hardening.advice_for_signature_hashes(
            cdn={"id": cdn_hardening.CDN_BUNNY, "name": "BunnyCDN"}
        )
        self.assertIn("BunnyCDN", adv["fix"])
        self.assertIn("SHA-1", adv["fix"])
        self.assertIn("SignatureAlgorithms", adv["fix"])

    def test_cloudflare_and_ovh_advice(self):
        cf = cdn_hardening.advice_for_signature_hashes(
            cdn={"id": cdn_hardening.CDN_CLOUDFLARE}
        )
        self.assertIn("Cloudflare", cf["fix"])
        ovh = cdn_hardening.advice_for_signature_hashes(
            cdn={"id": cdn_hardening.CDN_OVH}
        )
        self.assertIn("OVH", ovh["fix"])

    def test_optimizations_and_recommendations(self):
        deep = self._tls_deep(insufficient=["SHA1"])
        deep["cipher_order"] = {"applicable": True, "pass": False}
        cdn = {"id": cdn_hardening.CDN_BUNNY, "name": "BunnyCDN"}
        opts = cdn_hardening.optimizations_summary(cdn, tls_deep=deep, http_headers={"blocked": True})
        ids = {o["id"] for o in opts}
        self.assertIn("cdn-sig-hash", ids)
        self.assertIn("cdn-cipher-order", ids)

        ncsc = ncsc_tls.assess(deep)
        results = {
            "domain": "cdn.example.com",
            "tls_deep": deep,
            "ncsc_tls": {
                **ncsc,
                "cdn": cdn,
                "cdn_optimizations": opts,
            },
            "cdn": cdn,
            "http_headers": {"success": True, "blocked": True},
        }
        # Enrich finding like _attach_ncsc_tls
        for item in results["ncsc_tls"]["findings"]:
            if item["id"] == "signature-hash-insufficient":
                adv = cdn_hardening.advice_for_signature_hashes(cdn=cdn)
                item["fix"] = adv["fix"]

        recs = recommendations.generate(results)
        ncsc_rec = [r for r in recs if "signature" in (r.get("title") or "").lower() or "SHA-1" in (r.get("title") or "")]
        self.assertTrue(ncsc_rec)
        self.assertIn("BunnyCDN", ncsc_rec[0]["fix"])


class SignatureHashProbeUnitTests(unittest.TestCase):
    def test_parse_sha1_via_mock(self):
        import os
        import tempfile
        import importlib

        tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(tempdir.name, "sig.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import app

        app = importlib.reload(app)

        sample = (
            b"Peer signing digest: SHA1\n"
            b"New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384\n"
            b"    Protocol  : TLSv1.2\n"
        )

        class FakeProc:
            stdout = sample
            stderr = b""

        with patch("subprocess.run", return_value=FakeProc()):
            digest = app._openssl_peer_signing_digest(
                "cdn.example.com", 443, "203.0.113.10", "ECDSA+SHA1:RSA+SHA1"
            )
        self.assertEqual(digest, "SHA1")

        with patch.object(app, "_resolve_tls_endpoints", return_value=[
            {"family": "IPv4", "address": "203.0.113.10"},
        ]):
            with patch.object(app, "_test_protocol", return_value={"supported": True}):
                with patch.object(app, "_openssl_peer_signing_digest") as probe:
                    def side_effect(domain, port, host, sigalgs, timeout=8):
                        if "SHA1" in sigalgs:
                            return "SHA1"
                        if "SHA256" in sigalgs:
                            return "SHA256"
                        return None

                    probe.side_effect = side_effect
                    result = app.check_tls_signature_hashes("cdn.example.com")

        self.assertTrue(result["evaluated"])
        self.assertIn("SHA1", result["insufficient"])
        self.assertFalse(result["pass"])
        tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)


if __name__ == "__main__":
    unittest.main()
