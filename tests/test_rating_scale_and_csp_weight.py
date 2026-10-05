"""A rating with A+ and A-, and CSP weaknesses weighed by what they reach.

One medium finding made a domain a B, the same letter as one with ten, and
a domain with nothing open got the same A as one with a few low findings.
And 'unsafe-inline' on style-src counted as a medium, while inline styles
cannot run code: a policy that only allowed inline styles cost a domain
its A. 'unsafe-inline' where it reaches scripts stays high -- that is what
cross-site scripting needs -- unless a nonce or hash beside it makes
browsers ignore it.
"""

import pathlib
import unittest

import management
import recommendations
import web_security

ROOT = pathlib.Path(__file__).resolve().parent.parent
_REST = "; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"


def _inline(policy):
    return {i["id"]: i["severity"] for i in web_security.analyze_csp(policy)["issues"]
            if "unsafe" in i["id"]}


class CspWeightTests(unittest.TestCase):
    def test_inline_styles_are_low(self):
        self.assertEqual({"csp_unsafe_inline_style_src": "low"},
                         _inline("default-src 'self'; style-src 'self' 'unsafe-inline'" + _REST))

    def test_inline_scripts_are_high(self):
        self.assertEqual({"csp_unsafe_inline_script_src": "high"},
                         _inline("default-src 'self'; script-src 'self' 'unsafe-inline'" + _REST))

    def test_a_nonce_beside_it_makes_browsers_ignore_it(self):
        self.assertEqual({"csp_unsafe_inline_script_src": "low"},
                         _inline("default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-abc'" + _REST))

    def test_default_src_counts_for_what_it_still_governs(self):
        # No script-src: default-src governs scripts.
        self.assertEqual({"csp_unsafe_inline_default_src": "high"},
                         _inline("default-src 'self' 'unsafe-inline'" + _REST))
        # script-src of its own: default-src only reaches styles.
        self.assertEqual({"csp_unsafe_inline_default_src": "low"},
                         _inline("default-src 'self' 'unsafe-inline'; script-src 'self'" + _REST))

    def test_a_policy_with_only_inline_styles_is_a_low_finding_not_a_medium(self):
        policy = "default-src 'self'; style-src 'self' 'unsafe-inline'" + _REST
        csp = web_security.analyze_csp(policy)
        recs = [r for r in recommendations._headers({"domain": "example.com",
                                                     "http_headers": {"success": True, "csp": csp}})
                if r["title"].startswith("Content-Security-Policy is")]
        self.assertEqual(["low"], [r["severity"] for r in recs])
        self.assertIn("refine", recs[0]["title"])


class RatingScaleTests(unittest.TestCase):
    def test_the_scale(self):
        cases = [({}, "A+"), ({"info": 2}, "A+"), ({"low": 1}, "A"), ({"medium": 1}, "A-"),
                 ({"medium": 2, "low": 9}, "A-"), ({"medium": 3}, "B"), ({"high": 1}, "C"),
                 ({"high": 3}, "D"), ({"critical": 1}, "F")]
        self.assertEqual([want for _, want in cases], [management.rating(c) for c, _ in cases])
        self.assertEqual(set(management.RATINGS), set(management.RATING_TEXT))

    def test_charts_count_the_a_letters_together(self):
        self.assertEqual(["A", "A", "A", "B", "F"], [management.band(r) for r in ("A+", "A", "A-", "B", "F")])

    def test_the_report_shows_the_rating_beside_the_tls_grade(self):
        """The shared document showed only the TLS grade, easily read as the
        rating the dashboard gives."""
        html = (ROOT / "templates" / "report.html").read_text(encoding="utf-8")
        self.assertIn('class="stat stat-rating"', html)
        self.assertIn("{{ posture.rating }}", html)

    def test_plus_and_minus_get_class_names(self):
        app_js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn(".replace('+', 'plus').replace('-', 'minus')", app_js)
        css = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".history-grade.g-aminus", css)


if __name__ == "__main__":
    unittest.main()
