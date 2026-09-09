import unittest

import recommendations
import web_security as ws


class HstsValueTests(unittest.TestCase):
    """max-age was parsed but never judged, so a header that switches HSTS off
    and one that protects for a year were both simply "HSTS enabled"."""

    def _advice(self, **hsts):
        base = {"enabled": True, "preload": False, "include_subdomains": True}
        base.update(hsts)
        recs = recommendations._tls({"tls_deep": {"success": True, "hsts": base}})
        return [r for r in recs if "HSTS" in r["title"]]

    def test_max_age_zero_is_high(self):
        # The header is present and actively disables the protection.
        items = self._advice(max_age=0)
        self.assertEqual(items[0]["severity"], "high")
        self.assertIn("switched off", items[0]["title"])

    def test_a_few_minutes_is_medium(self):
        items = self._advice(max_age=300)
        self.assertEqual(items[0]["severity"], "medium")
        self.assertIn("300 seconds", items[0]["title"])

    def test_under_a_year_blocks_preload(self):
        items = self._advice(max_age=2592000)
        self.assertEqual(items[0]["severity"], "low")
        self.assertIn("below one year", items[0]["title"])

    def test_a_full_year_is_not_flagged_for_length(self):
        titles = [i["title"] for i in self._advice(max_age=31536000)]
        self.assertFalse(any("max-age" in t for t in titles))

    def test_missing_include_subdomains_is_reported(self):
        items = self._advice(max_age=31536000, include_subdomains=False)
        titles = [i["title"] for i in items]
        self.assertIn("HSTS does not cover subdomains", titles)

    def test_preload_advice_waits_for_subdomain_coverage(self):
        # Advising preload before includeSubDomains is advising a submission
        # that will be rejected.
        titles = [i["title"] for i in self._advice(max_age=31536000, include_subdomains=False)]
        self.assertNotIn("HSTS not preload-ready", titles)

    def test_preload_advice_appears_once_subdomains_are_covered(self):
        titles = [i["title"] for i in self._advice(max_age=31536000, include_subdomains=True)]
        self.assertIn("HSTS not preload-ready", titles)

    def test_the_irreversibility_of_preload_is_stated(self):
        item = next(i for i in self._advice(max_age=31536000)
                    if i["title"] == "HSTS not preload-ready")
        self.assertIn("irreversible", item["fix"])

    def test_a_fully_configured_header_says_nothing(self):
        self.assertEqual(
            self._advice(max_age=31536000, include_subdomains=True, preload=True), [])

    def test_a_missing_header_still_reports_as_before(self):
        recs = recommendations._tls({"tls_deep": {"success": True, "hsts": {"enabled": False}}})
        self.assertIn("HSTS header missing", [r["title"] for r in recs])


class XssProtectionTests(unittest.TestCase):
    """The legacy auditor was itself a source of vulnerabilities, so 0 is the
    recommended value and 1 is the weakness — the opposite of the intuition."""

    def test_the_legacy_filter_is_flagged(self):
        issues = ws.check_header_values({"X-XSS-Protection": "1; mode=block"})
        self.assertEqual(issues[0]["problem"], "permissive")
        self.assertIn("deprecated", issues[0]["detail"])

    def test_zero_is_correct_and_silent(self):
        self.assertEqual(ws.check_header_values({"X-XSS-Protection": "0"}), [])

    def test_a_nonsense_value_is_invalid(self):
        issues = ws.check_header_values({"X-XSS-Protection": "block"})
        self.assertEqual(issues[0]["problem"], "invalid")


class PermissionsPolicyTests(unittest.TestCase):
    """Only presence was checked, so a policy handing the camera to every
    embedded frame scored the same as one denying it."""

    def test_a_wildcard_feature_is_found(self):
        result = ws.analyze_permissions_policy("camera=*, microphone=()")
        self.assertEqual(result["sensitive_wide_open"], ["camera"])

    def test_self_and_empty_are_not_wide_open(self):
        result = ws.analyze_permissions_policy(
            "camera=(), geolocation=(self), fullscreen=(self)")
        self.assertEqual(result["sensitive_wide_open"], [])

    def test_a_wildcard_inside_parentheses_counts(self):
        result = ws.analyze_permissions_policy("geolocation=(*)")
        self.assertEqual(result["sensitive_wide_open"], ["geolocation"])

    def test_report_to_parameters_do_not_confuse_the_parser(self):
        result = ws.analyze_permissions_policy(
            "camera=();report-to=default, geolocation=(self);report-to=default")
        self.assertEqual(result["sensitive_wide_open"], [])
        self.assertEqual(result["features"]["geolocation"], "(self)")
        # report-to is a parameter of the entry, not a browser feature.
        # Matching across the semicolon listed it as one.
        self.assertNotIn("report-to", result["features"])
        self.assertEqual(sorted(result["features"]), ["camera", "geolocation"])

    def test_an_absent_feature_is_not_reported(self):
        # The browser default for the sensitive features is already `self`;
        # calling omission a finding would be inventing one.
        result = ws.analyze_permissions_policy("fullscreen=(self)")
        self.assertEqual(result["sensitive_wide_open"], [])

    def test_a_harmless_wildcard_is_not_escalated(self):
        result = ws.analyze_permissions_policy("fullscreen=*")
        self.assertEqual(result["wide_open"], ["fullscreen"])
        self.assertEqual(result["sensitive_wide_open"], [])

    def test_no_header_at_all(self):
        result = ws.analyze_permissions_policy(None)
        self.assertFalse(result["present"])
        self.assertEqual(result["sensitive_wide_open"], [])

    def test_the_recommendation_names_the_features(self):
        recs = recommendations._headers({"http_headers": {
            "success": True, "headers_missing": [],
            "permissions_policy": {"sensitive_wide_open": ["camera", "microphone"]},
        }})
        item = next(r for r in recs if "Permissions-Policy grants" in r["title"])
        self.assertEqual(item["severity"], "low")
        self.assertIn("camera", item["title"])
        self.assertIn("(self)", item["fix"])

    def test_a_restrictive_policy_produces_nothing(self):
        recs = recommendations._headers({"http_headers": {
            "success": True, "headers_missing": [],
            "permissions_policy": {"sensitive_wide_open": []},
        }})
        self.assertEqual([r for r in recs if "Permissions-Policy grants" in r["title"]], [])



class MissingHeaderWordingTests(unittest.TestCase):
    """"1 security header(s) missing … does not send several recommended
    headers" named nothing and did not agree with itself, so the reader had to
    reverse-engineer which header it meant from the fix text.
    """

    def _item(self, missing):
        recs = recommendations._headers({"http_headers": {
            "success": True, "headers_missing": list(missing),
        }})
        return next(r for r in recs if "missing" in r["title"])

    def test_a_single_header_is_named_in_the_title(self):
        item = self._item(["Permissions-Policy"])
        self.assertEqual(item["title"], "Permissions-Policy header missing")

    def test_a_single_header_reads_as_singular(self):
        item = self._item(["Permissions-Policy"])
        self.assertNotIn("several", item["problem"])
        self.assertIn("does not send `Permissions-Policy`", item["problem"])

    def test_several_headers_are_all_named(self):
        item = self._item(["Permissions-Policy", "X-Frame-Options"])
        self.assertEqual(item["title"], "2 security headers missing")
        self.assertIn("`Permissions-Policy`", item["problem"])
        self.assertIn("`X-Frame-Options`", item["problem"])

    def test_every_header_explains_what_it_buys_you(self):
        # "Add this header" without saying what it does is not advice.
        item = self._item(["Referrer-Policy"])
        self.assertIn("path and query", item["problem"])

    def test_the_permissions_policy_fix_is_copy_pasteable(self):
        item = self._item(["Permissions-Policy"])
        self.assertIn("accelerometer=()", item["fix"])
        self.assertIn("(self)", item["fix"])

    def test_csp_keeps_its_own_dedicated_item(self):
        recs = recommendations._headers({"http_headers": {
            "success": True,
            "headers_missing": ["Content-Security-Policy", "X-Frame-Options"],
        }})
        titles = [r["title"] for r in recs]
        self.assertIn("Content-Security-Policy missing — build a safe policy", titles)
        # And it is not counted twice in the generic item.
        self.assertIn("X-Frame-Options header missing", titles)

    def test_every_known_header_has_a_purpose_line(self):
        import settings.defaults as d
        for header in d.DEFAULT_SECURITY_HEADERS:
            self.assertIn(header, recommendations._HEADER_PURPOSE, header)


if __name__ == "__main__":
    unittest.main()
