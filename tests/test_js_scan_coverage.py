"""The JavaScript secrets scan, made to look where secrets actually are.

It read only the scripts the HTML loads, while a Vite or Next.js app keeps
most of its code in chunks those scripts name; it ignored public source
maps, which carry the original source; it read a Supabase service_role key
-- which bypasses every row-level security policy -- as just "a JWT"; it
reported `apiKey: "some-word"` as a possible secret; and its advice said a
key had leaked without saying which one or where.

Fake credentials are assembled from pieces so the fixtures do not trip
secret-scanning push protection, which matches on format alone.
"""

import base64
import json
import pathlib
import unittest
from unittest import mock

import js_scan
import recommendations

ROOT = pathlib.Path(__file__).resolve().parent.parent
SENDGRID = "S" + "G." + "A" * 11 + "b1" * 5 + "C" + "." + "d2E" * 14 + "x"


def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return "ey" + enc({"alg": "HS256", "typ": "JWT"})[2:] + "." + enc(claims) + "." + "s1gnatureX" * 3


def _site(pages):
    """requests.get answering from a dict of url -> body (None: 404)."""
    def get(url, **kwargs):
        body = pages.get(url)
        resp = mock.Mock()
        resp.status_code = 200 if body is not None else 404
        resp.text = body or ""
        resp.url = url
        data = (body or "").encode()
        resp.iter_content = lambda chunk_size=65536: [data]
        return resp
    return mock.patch("js_scan.requests.get", side_effect=get)


def _scan(pages):
    with _site(pages), mock.patch("js_scan._safe_host", return_value=True):
        return js_scan.scan("example.com")


HOME = "https://example.com"


class CoverageTests(unittest.TestCase):
    def test_a_secret_in_a_code_chunk_is_found(self):
        result = _scan({
            HOME: '<script src="/assets/index-AbCd1234.js"></script>',
            HOME + "/assets/index-AbCd1234.js": 'import("./Admin-Xy12Ab34.js")',
            HOME + "/assets/Admin-Xy12Ab34.js": f'const mail = "{SENDGRID}";',
        })
        self.assertEqual(1, result["chunks_followed"])
        self.assertEqual(["SendGrid API Key"], [s["type"] for s in result["secrets_found"]])
        self.assertTrue(result["secrets_found"][0]["source"].endswith("Admin-Xy12Ab34.js"))

    def test_a_public_source_map_is_reported_and_read(self):
        source = f'export const key = "{SENDGRID}";'
        result = _scan({
            HOME: '<script src="/assets/index-AbCd1234.js"></script>',
            HOME + "/assets/index-AbCd1234.js": "console.log(1)\n//# sourceMappingURL=index-AbCd1234.js.map",
            HOME + "/assets/index-AbCd1234.js.map": json.dumps({"version": 3, "sources": ["src/a.ts"],
                                                                  "sourcesContent": [source]}),
        })
        self.assertEqual([HOME + "/assets/index-AbCd1234.js.map"], result["source_maps"])
        self.assertEqual(["SendGrid API Key"], [s["type"] for s in result["secrets_found"]])
        titles = [f["title"] for f in js_scan.findings(result)]
        self.assertIn("1 public source map(s)", titles)

    def test_one_key_in_two_files_is_one_finding(self):
        result = _scan({
            HOME: '<script src="/a.js"></script><script src="/b.js"></script>',
            HOME + "/a.js": f'x("{SENDGRID}")',
            HOME + "/b.js": f'y("{SENDGRID}")',
        })
        self.assertEqual(1, len(result["secrets_found"]))
        self.assertEqual(1, result["secrets_found"][0]["also_in"])

    def test_a_script_that_could_not_be_fetched_is_counted_not_clean(self):
        result = _scan({HOME: '<script src="/gone.js"></script>'})
        self.assertEqual((0, 1), (result["scripts_analyzed"], result["scripts_failed"]))


class ClassificationTests(unittest.TestCase):
    def _types(self, body):
        return {s["type"]: s["severity"] for s in js_scan._scan_secrets("https://example.com/a.js", body)}

    def test_a_supabase_service_role_key_is_critical(self):
        token = _jwt({"iss": "supabase", "role": "service_role"})
        self.assertEqual({"Supabase service_role key": "critical"}, self._types(f'createClient(u, "{token}")'))

    def test_a_supabase_anon_key_is_public_by_design(self):
        token = _jwt({"iss": "supabase", "role": "anon"})
        self.assertEqual({"Supabase anon key": "info"}, self._types(f'createClient(u, "{token}")'))

    def test_a_low_entropy_value_is_not_a_secret(self):
        self.assertEqual({}, self._types('const cfg = {apiKey: "public-identifier-name"};'))

    def test_a_random_value_still_is(self):
        self.assertIn("Generic Bearer/API secret assignment",
                      self._types('const cfg = {apiKey: "q8Zr2LmX9vT4kPw7Yb3N"};'))


class AdviceTests(unittest.TestCase):
    def test_the_advice_says_which_key_and_where(self):
        result = _scan({HOME: '<script src="/a.js"></script>', HOME + "/a.js": f'x("{SENDGRID}")'})
        recs = recommendations._js_scan({"domain": "example.com", "js_scan": {
            "success": True, "findings": js_scan.findings(result)}})
        secret = next(r for r in recs if r["category"] == "Exposed Secret")
        self.assertIn("found in https://example.com/a.js", secret["problem"])
        self.assertNotIn(SENDGRID, secret["problem"])


class ScreenTests(unittest.TestCase):
    def test_the_card_is_with_the_security_audit(self):
        html = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
        security = html.split('id="tab-security"', 1)[1]
        self.assertIn('id="jsScanContent"', security)
        js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("<tr><th>Coverage</th>", js)


if __name__ == "__main__":
    unittest.main()
