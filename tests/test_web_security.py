"""Tests for CSP analysis, cookie/CORS vulns, and header Advies."""

from __future__ import annotations

import unittest

import recommendations
import web_security


class CspAnalysisTests(unittest.TestCase):
    def test_missing_csp(self):
        result = web_security.analyze_csp(None)
        self.assertFalse(result["present"])
        self.assertEqual(result["grade"], "missing")
        self.assertTrue(any(i["id"] == "csp_missing" for i in result["issues"]))
        self.assertTrue(result["suggestions"])

    def test_weak_csp_unsafe_inline_and_eval(self):
        policy = "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'self'"
        result = web_security.analyze_csp(policy)
        self.assertTrue(result["present"])
        self.assertEqual(result["grade"], "weak")
        ids = {i["id"] for i in result["issues"]}
        self.assertTrue(any("unsafe_inline" in i for i in ids))
        self.assertTrue(any("unsafe_eval" in i for i in ids))
        self.assertIn("csp_no_frame_ancestors", ids)
        self.assertTrue(any("nonce" in s.lower() or "unsafe-inline" in s.lower() for s in result["suggestions"]))

    def test_strongish_csp(self):
        policy = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'; report-uri /csp"
        )
        result = web_security.analyze_csp(policy)
        self.assertIn(result["grade"], {"good", "strong"})
        high = [i for i in result["issues"] if i["severity"] == "high"]
        self.assertEqual(high, [])


class CookieCorsFramingTests(unittest.TestCase):
    def test_session_cookie_flags(self):
        headers = {"Set-Cookie": "sessionid=abc123; Path=/"}
        result = web_security.analyze_cookies(headers)
        ids = {i["id"] for i in result["issues"]}
        self.assertIn("cookie_no_secure", ids)
        self.assertIn("cookie_no_httponly", ids)
        self.assertIn("cookie_no_samesite", ids)

    def test_secure_session_cookie_ok(self):
        headers = {"Set-Cookie": "sessionid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"}
        result = web_security.analyze_cookies(headers)
        self.assertEqual(result["issues"], [])

    def test_cors_star_with_credentials(self):
        result = web_security.analyze_cors({
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        })
        ids = {i["id"] for i in result["issues"]}
        self.assertIn("cors_star", ids)
        self.assertIn("cors_star_with_credentials", ids)

    def test_framing_unprotected(self):
        csp = web_security.analyze_csp(None)
        result = web_security.analyze_framing({}, csp)
        self.assertTrue(any(i["id"] == "framing_unprotected" for i in result["issues"]))

    def test_info_disclosure_server_version(self):
        result = web_security.analyze_info_disclosure({
            "server": "nginx/1.18.0",
            "x-powered-by": "Express",
        })
        ids = {i["id"] for i in result["issues"]}
        self.assertIn("disclosure_server_version", ids)
        self.assertIn("disclosure_x_powered_by", ids)


class HeaderAdviesTests(unittest.TestCase):
    def test_missing_csp_advies_includes_build_steps(self):
        results = {
            "domain": "example.com",
            "http_headers": {
                "success": True,
                "blocked": False,
                "headers_missing": ["Content-Security-Policy", "Permissions-Policy"],
                "headers_found": {"X-Content-Type-Options": "nosniff"},
                "csp": {"present": False, "grade": "missing", "issues": [], "suggestions": []},
                "web_security": {"issues": []},
                "vuln_findings": [],
            },
        }
        recs = recommendations.generate(results)
        csp_rec = next(r for r in recs if "Content-Security-Policy missing" in r["title"])
        self.assertIn("Report-Only", csp_rec["fix"])
        self.assertIn("default-src 'self'", csp_rec["fix"])
        self.assertIn("frame-ancestors", csp_rec["fix"])
        self.assertIn("example.com", csp_rec["retest"])

    def test_weak_csp_and_cookie_advies(self):
        csp = web_security.analyze_csp(
            "default-src *; script-src 'unsafe-inline' 'unsafe-eval'"
        )
        cookies = web_security.analyze_cookies({"Set-Cookie": "auth_token=x; Path=/"})
        results = {
            "domain": "shop.example",
            "http_headers": {
                "success": True,
                "blocked": False,
                "headers_missing": [],
                "headers_found": {"Content-Security-Policy": csp["raw"]},
                "csp": csp,
                "web_security": {
                    "csp": csp,
                    "cookies": cookies,
                    "issues": cookies["issues"],
                },
                "vuln_findings": cookies["issues"],
            },
        }
        recs = recommendations.generate(results)
        titles = [r["title"] for r in recs]
        self.assertTrue(any("tighten policy" in t for t in titles))
        self.assertTrue(any("Secure" in t or "auth_token" in t for t in titles))
        weak = next(r for r in recs if "tighten policy" in r["title"])
        self.assertIn("nonce", weak["fix"].lower())


class AnalyzeResponseSecurityTests(unittest.TestCase):
    def test_combined_analysis(self):
        class _H(dict):
            def getlist(self, key):
                if key == "Set-Cookie":
                    return ["sid=1; Path=/"]
                return []

        headers = _H({
            "Content-Security-Policy": "default-src *",
            "Access-Control-Allow-Origin": "*",
            "Server": "Apache/2.4.49",
            "Set-Cookie": "sid=1; Path=/",
        })
        result = web_security.analyze_response_security(headers)
        self.assertGreater(result["issue_count"], 2)
        ids = {i["id"] for i in result["issues"]}
        self.assertTrue(any("wildcard" in i or "frame" in i for i in ids))
        self.assertIn("cors_star", ids)


if __name__ == "__main__":
    unittest.main()
