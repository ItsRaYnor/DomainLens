import unittest

import web_security as w


def _cookies(header):
    return w.parse_set_cookie_headers({"Set-Cookie": header})


def _by_name(header):
    return {c["name"]: c for c in _cookies(header)}


class JoinedCookieSplitTests(unittest.TestCase):
    """Reported from a live scan: "Cookie `max-age` missing Secure".

    max-age is a cookie attribute, not a cookie. requests folds multiple
    Set-Cookie headers into one comma-separated string, and an Expires
    attribute always carries a comma of its own ("Expires=Mon, 12 Aug 2026"),
    which the old split mistook for a cookie boundary. That invented a cookie
    named after whatever attribute followed the date — and moved the real
    cookie's Secure/HttpOnly onto the phantom, so a correctly secured cookie
    was reported as insecure.
    """

    EXPIRES_CASE = (
        "sess=v; Expires=Mon, 12 Aug 2026 20:00:00 GMT, max-age=3600; "
        "Path=/; Secure; HttpOnly"
    )

    def test_no_phantom_cookie_from_an_expires_date(self):
        names = [c["name"] for c in _cookies(self.EXPIRES_CASE)]
        self.assertEqual(names, ["sess"])

    def test_flags_stay_with_the_real_cookie(self):
        cookie = _by_name(self.EXPIRES_CASE)["sess"]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])

    def test_no_attribute_is_ever_reported_as_a_cookie(self):
        header = (
            "a=1; Expires=Thu, 01 Jan 2026 00:00:00 GMT, Path=/, "
            "Domain=example.com, SameSite=Lax, Secure"
        )
        names = {c["name"].lower() for c in _cookies(header)}
        self.assertTrue(names.isdisjoint(w._COOKIE_ATTRS), names)

    # --- genuinely joined cookies must still split ---

    def test_two_joined_cookies_are_split(self):
        cookies = _by_name("a=1; Path=/; Secure, b=2; Max-Age=100; HttpOnly")
        self.assertEqual(set(cookies), {"a", "b"})
        self.assertTrue(cookies["a"]["secure"])
        self.assertFalse(cookies["a"]["httponly"])
        self.assertTrue(cookies["b"]["httponly"])
        self.assertFalse(cookies["b"]["secure"])

    def test_two_joined_cookies_where_the_first_has_an_expires(self):
        cookies = _by_name("a=1; Expires=Thu, 01 Jan 2026 00:00:00 GMT, b=2; Secure")
        self.assertEqual(set(cookies), {"a", "b"})
        self.assertTrue(cookies["b"]["secure"])
        self.assertFalse(cookies["a"]["secure"])

    # --- ordinary cases are unaffected ---

    def test_single_cookie_with_every_attribute(self):
        cookie = _by_name(
            "session=abc; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
        )["session"]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "lax")
        self.assertTrue(cookie["sessionish"])

    def test_cookie_without_a_comma_is_untouched(self):
        self.assertEqual([c["name"] for c in _cookies("id=1; Path=/")], ["id"])

    def test_insecure_cookie_is_still_reported_as_insecure(self):
        # The fix must not paper over the finding it was masking.
        cookie = _by_name("session=abc; Path=/")["session"]
        self.assertFalse(cookie["secure"])
        self.assertFalse(cookie["httponly"])

    def test_comma_inside_a_cookie_value_does_not_split(self):
        cookies = _by_name("prefs=a,b,c; Path=/; Secure")
        self.assertIn("prefs", cookies)
        self.assertTrue(cookies["prefs"]["secure"])

    def test_empty_header_is_handled(self):
        self.assertEqual(_cookies(""), [])


class CookieAnalysisTests(unittest.TestCase):

    def test_secure_cookie_produces_no_issue(self):
        result = w.analyze_cookies(
            {"Set-Cookie": "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"}
        )
        self.assertEqual(result["issues"], [])

    def test_expires_case_no_longer_produces_a_phantom_issue(self):
        result = w.analyze_cookies({"Set-Cookie": JoinedCookieSplitTests.EXPIRES_CASE})
        for issue in result["issues"]:
            self.assertNotIn("max-age", str(issue).lower())



class HeaderObjectTypeTests(unittest.TestCase):
    """Found in a real scan export: a "cookie" whose name was the entire
    header dictionary, on a site that sets no cookies at all.

    requests returns a CaseInsensitiveDict, which is a Mapping but not a dict
    subclass, so an isinstance(..., dict) test missed it and fell through to
    str(raw_headers). Because Cache-Control commonly reads
    "public, max-age=31536000", that string contained both a comma and an "=",
    so it parsed as a cookie — the original source of the reported
    "Cookie max-age missing Secure".
    """

    def _requests_headers(self, mapping):
        import requests
        return requests.structures.CaseInsensitiveDict(mapping)

    def test_case_insensitive_dict_is_recognised(self):
        headers = self._requests_headers({
            "Cache-Control": "public, max-age=31536000",
            "Set-Cookie": "session=abc; Path=/; Secure; HttpOnly",
        })
        cookies = w.parse_set_cookie_headers(headers)
        self.assertEqual([c["name"] for c in cookies], ["session"])
        self.assertTrue(cookies[0]["secure"])

    def test_cookieless_site_reports_no_cookies(self):
        headers = self._requests_headers({
            "Date": "Thu, 13 Aug 2026 07:37:09 GMT",
            "Server": "BunnyCDN-AMS1-1444",
            "Cache-Control": "public, max-age=31536000",
        })
        self.assertEqual(w.parse_set_cookie_headers(headers), [])

    def test_cookieless_site_produces_no_findings(self):
        headers = self._requests_headers({"Cache-Control": "public, max-age=31536000"})
        self.assertEqual(w.analyze_cookies(headers)["issues"], [])

    def test_plain_dict_still_works(self):
        cookies = w.parse_set_cookie_headers({"Set-Cookie": "a=1; Secure"})
        self.assertEqual([c["name"] for c in cookies], ["a"])

    def test_raw_string_still_works(self):
        cookies = w.parse_set_cookie_headers("a=1; Secure")
        self.assertEqual([c["name"] for c in cookies], ["a"])

    def test_unusable_object_yields_nothing_rather_than_a_repr_cookie(self):
        class Odd:
            def __repr__(self):
                return "weird=object"
        self.assertEqual(w.parse_set_cookie_headers(Odd()), [])
if __name__ == "__main__":
    unittest.main()
