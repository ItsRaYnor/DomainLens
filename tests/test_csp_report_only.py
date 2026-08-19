import unittest

import recommendations as r
import web_security as w


ENFORCED = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob: https:; frame-ancestors 'self'"
)
STAGED = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob: https://x.supabase.co; frame-ancestors 'none'; "
    "object-src 'none'"
)


class CompareCspTests(unittest.TestCase):
    """A Content-Security-Policy-Report-Only header is a staged change: it says
    what the policy is about to become. Reporting only the enforcing policy
    hid the part of the configuration actively being worked on.
    """

    def test_no_report_only_header(self):
        delta = w.compare_csp(ENFORCED, None)
        self.assertFalse(delta["has_report_only"])

    def test_identical_policies_are_flagged(self):
        delta = w.compare_csp(ENFORCED, ENFORCED)
        self.assertTrue(delta["has_report_only"])
        self.assertTrue(delta["identical"])

    def test_removed_source_is_reported_as_stricter(self):
        delta = w.compare_csp(ENFORCED, STAGED)
        img = [e for e in delta["stricter"] if e["directive"] == "img-src"]
        self.assertEqual(img[0]["sources"], ["https:"])

    def test_added_source_is_reported_as_looser(self):
        delta = w.compare_csp(ENFORCED, STAGED)
        img = [e for e in delta["looser"] if e["directive"] == "img-src"]
        self.assertEqual(img[0]["sources"], ["https://x.supabase.co"])

    def test_gaining_none_counts_as_stricter_not_looser(self):
        """'none' grants nothing, so reporting it as "would additionally
        allow" says the opposite of what the change does."""
        delta = w.compare_csp(ENFORCED, STAGED)
        looser_directives = {e["directive"] for e in delta["looser"]}
        self.assertNotIn("frame-ancestors", looser_directives)
        stricter_directives = {e["directive"] for e in delta["stricter"]}
        self.assertIn("frame-ancestors", stricter_directives)

    def test_new_directive_is_reported(self):
        delta = w.compare_csp(ENFORCED, STAGED)
        added = {e["directive"] for e in delta["added_directives"]}
        self.assertEqual(added, {"object-src"})

    def test_dropped_directive_is_reported(self):
        delta = w.compare_csp("default-src 'self'; object-src 'none'", "default-src 'self'")
        dropped = {e["directive"] for e in delta["removed_directives"]}
        self.assertEqual(dropped, {"object-src"})


class ResponseAnalysisTests(unittest.TestCase):

    def test_report_only_header_is_captured(self):
        analysis = w.analyze_response_security({
            "Content-Security-Policy": ENFORCED,
            "Content-Security-Policy-Report-Only": STAGED,
        })
        self.assertIsNotNone(analysis["csp_report_only"])
        self.assertTrue(analysis["csp_delta"]["has_report_only"])

    def test_absent_report_only_leaves_delta_empty(self):
        analysis = w.analyze_response_security({"Content-Security-Policy": ENFORCED})
        self.assertIsNone(analysis["csp_report_only"])
        self.assertFalse(analysis["csp_delta"]["has_report_only"])

    def test_report_only_issues_do_not_leak_into_the_enforced_score(self):
        # The staged policy must not add findings that would penalise the
        # score for something that is not actually being enforced.
        with_ro = w.analyze_response_security({
            "Content-Security-Policy": ENFORCED,
            "Content-Security-Policy-Report-Only": "default-src *",
        })
        without = w.analyze_response_security({"Content-Security-Policy": ENFORCED})
        self.assertEqual(len(with_ro["issues"]), len(without["issues"]))

    def test_case_insensitive_header_lookup(self):
        import requests
        headers = requests.structures.CaseInsensitiveDict({
            "content-security-policy": ENFORCED,
            "content-security-policy-report-only": STAGED,
        })
        analysis = w.analyze_response_security(headers)
        self.assertTrue(analysis["csp_delta"]["has_report_only"])


class RecommendationTests(unittest.TestCase):

    def _rec(self, enforced, report_only):
        delta = w.compare_csp(enforced, report_only)
        return r._csp_report_only({"csp_delta": delta}, "example.com")

    def test_no_advice_without_a_report_only_header(self):
        self.assertEqual(self._rec(ENFORCED, None), [])

    def test_identical_policy_gets_its_own_advice(self):
        recs = self._rec(ENFORCED, ENFORCED)
        self.assertEqual(len(recs), 1)
        self.assertIn("identical", recs[0]["title"].lower())

    def test_staged_change_points_at_the_reporting_tool(self):
        recs = self._rec(ENFORCED, STAGED)
        self.assertEqual(len(recs), 1)
        self.assertIn("report-uri", recs[0]["fix"])
        self.assertIn("uriports", recs[0]["fix"])

    def test_advice_names_the_directives_that_change(self):
        problem = self._rec(ENFORCED, STAGED)[0]["problem"]
        self.assertIn("img-src", problem)
        self.assertIn("https:", problem)

    def test_advice_says_nothing_is_blocked(self):
        problem = self._rec(ENFORCED, STAGED)[0]["problem"]
        self.assertIn("Nothing is blocked", problem)

    def test_a_looser_staged_policy_is_called_out_as_unusual(self):
        recs = self._rec("default-src 'self'", "default-src 'self' https://cdn.example.com")
        self.assertIn("looser", recs[0]["problem"])

    def test_advice_is_informational_only(self):
        self.assertEqual(self._rec(ENFORCED, STAGED)[0]["severity"], r.SEVERITY_INFO)


if __name__ == "__main__":
    unittest.main()
