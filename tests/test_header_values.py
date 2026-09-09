import unittest

import recommendations
import web_security as ws


class InvalidHeaderValueTests(unittest.TestCase):
    """Only the presence of these headers was checked. A typo is discarded by
    the browser, so the site is in the same position as if the header were
    never sent — but it scored as protected.
    """

    def _issues(self, **headers):
        return ws.check_header_values(headers)

    def test_a_typo_in_corp_is_caught(self):
        issues = self._issues(**{"Cross-Origin-Resource-Policy": "samesite"})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["problem"], "invalid")
        self.assertIn("discard", issues[0]["detail"])

    def test_a_correct_corp_is_silent(self):
        self.assertEqual(self._issues(**{"Cross-Origin-Resource-Policy": "same-site"}), [])
        self.assertEqual(self._issues(**{"Cross-Origin-Resource-Policy": "same-origin"}), [])

    def test_case_does_not_matter(self):
        self.assertEqual(self._issues(**{"X-Frame-Options": "SAMEORIGIN"}), [])
        self.assertEqual(self._issues(**{"Cross-Origin-Resource-Policy": "Same-Site"}), [])

    def test_nosniff_is_the_only_accepted_content_type_options(self):
        self.assertEqual(self._issues(**{"X-Content-Type-Options": "nosniff"}), [])
        issues = self._issues(**{"X-Content-Type-Options": "no-sniff"})
        self.assertEqual(issues[0]["problem"], "invalid")

    def test_allow_from_is_not_honoured_anywhere(self):
        issues = self._issues(**{"X-Frame-Options": "ALLOW-FROM https://example.org"})
        self.assertEqual(issues[0]["problem"], "invalid")

    def test_an_empty_value_is_not_reported_twice(self):
        # Absence is the missing-headers list's job, not this check's.
        self.assertEqual(self._issues(**{"Cross-Origin-Resource-Policy": ""}), [])

    def test_unknown_headers_are_left_alone(self):
        self.assertEqual(self._issues(**{"X-Powered-By": "nonsense"}), [])

    def test_no_headers_at_all(self):
        self.assertEqual(ws.check_header_values(None), [])
        self.assertEqual(ws.check_header_values({}), [])


class PermissiveHeaderValueTests(unittest.TestCase):
    """The dangerous case: a value the browser accepts that grants exactly
    what the header exists to deny. It looks configured and does nothing."""

    def _issues(self, **headers):
        return ws.check_header_values(headers)

    def test_corp_cross_origin_gives_no_protection(self):
        issues = self._issues(**{"Cross-Origin-Resource-Policy": "cross-origin"})
        self.assertEqual(issues[0]["problem"], "permissive")
        self.assertIn("Any site", issues[0]["detail"])

    def test_coop_unsafe_none_is_the_browser_default(self):
        issues = self._issues(**{"Cross-Origin-Opener-Policy": "unsafe-none"})
        self.assertEqual(issues[0]["problem"], "permissive")

    def test_coep_unsafe_none_is_the_browser_default(self):
        issues = self._issues(**{"Cross-Origin-Embedder-Policy": "unsafe-none"})
        self.assertEqual(issues[0]["problem"], "permissive")

    def test_protective_values_are_silent(self):
        self.assertEqual(self._issues(**{
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-origin",
        }), [])

    def test_parameters_after_a_semicolon_are_ignored(self):
        self.assertEqual(self._issues(**{"Cross-Origin-Opener-Policy": "same-origin; report-to=default"}), [])


class ReferrerPolicyTests(unittest.TestCase):
    """Referrer-Policy takes a fallback list and browsers skip tokens they do
    not know, so it is only broken when nothing is recognised."""

    def _issues(self, value):
        return ws.check_header_values({"Referrer-Policy": value})

    def test_the_recommended_value_is_silent(self):
        self.assertEqual(self._issues("strict-origin-when-cross-origin"), [])

    def test_a_nonsense_value_has_no_effect(self):
        issues = self._issues("strict-origin-when-crossorigin")
        self.assertEqual(issues[0]["problem"], "invalid")

    def test_a_fallback_list_is_accepted(self):
        # Older browsers take the first token they understand.
        self.assertEqual(self._issues("no-referrer, strict-origin-when-cross-origin"), [])

    def test_the_last_understood_token_is_the_one_judged(self):
        issues = self._issues("no-referrer, unsafe-url")
        self.assertEqual(issues[0]["problem"], "permissive")

    def test_unsafe_url_leaks_the_full_url(self):
        issues = self._issues("unsafe-url")
        self.assertEqual(issues[0]["problem"], "permissive")
        self.assertIn("path and query", issues[0]["detail"])

    def test_an_unknown_token_beside_a_known_one_is_fine(self):
        self.assertEqual(self._issues("made-up-token, same-origin"), [])


class HeaderValueRecommendationTests(unittest.TestCase):

    def _recs(self, issues):
        return recommendations._headers({"http_headers": {
            "success": True, "headers_missing": [], "header_value_issues": issues,
        }})

    def test_an_ignored_contextual_header_is_informational(self):
        """Invalid CORP loses optional isolation, not baseline site security."""
        recs = self._recs([{
            "header": "Cross-Origin-Resource-Policy", "value": "samesite",
            "problem": "invalid", "expected": "same-site (or same-origin)",
            "detail": "browsers discard the header",
        }])
        item = next(r for r in recs if "browsers ignore" in r["title"])
        self.assertEqual(item["severity"], "info")
        self.assertIn("same-site", item["fix"])

    def test_a_permissive_value_is_low(self):
        recs = self._recs([{
            "header": "Cross-Origin-Resource-Policy", "value": "cross-origin",
            "problem": "permissive", "expected": "same-site (or same-origin)",
            "detail": "Any site may load your resources.",
        }])
        item = next(r for r in recs if "permissive value" in r["title"])
        self.assertEqual(item["severity"], "low")
        self.assertIn("cross-origin", item["problem"])

    def test_nothing_is_said_when_every_value_is_right(self):
        self.assertEqual(
            [r for r in self._recs([]) if "ignore" in r["title"] or "permissive" in r["title"]],
            [])


if __name__ == "__main__":
    unittest.main()
