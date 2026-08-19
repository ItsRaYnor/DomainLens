import unittest

import recommendations
import web_security


class CoepBreakingSourceTests(unittest.TestCase):
    """COEP was listed alongside HSTS as a plain missing header. It is not
    comparable: `require-corp` blocks every cross-origin subresource that does
    not return CORP, so a site embedding third-party images that follows the
    advice breaks those images. Advice you cannot act on without breaking your
    site is worse than no advice.
    """

    def _analysis(self, policy):
        return web_security.analyze_csp(policy)

    def test_third_party_images_are_reported(self):
        found = web_security.coep_breaking_sources(
            self._analysis("default-src 'self'; img-src 'self' https://cdn.example.org"))
        self.assertEqual(found, ["https://cdn.example.org"])

    def test_a_self_only_policy_has_nothing_to_break(self):
        found = web_security.coep_breaking_sources(
            self._analysis("default-src 'self'; img-src 'self'; script-src 'self'"))
        self.assertEqual(found, [])

    def test_data_and_blob_do_not_need_corp(self):
        # Their responses are same-origin by construction.
        found = web_security.coep_breaking_sources(
            self._analysis("default-src 'self'; img-src 'self' data: blob:"))
        self.assertEqual(found, [])

    def test_inline_keywords_and_nonces_are_not_sources(self):
        found = web_security.coep_breaking_sources(self._analysis(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'nonce-abc123' 'sha256-xyz'"))
        self.assertEqual(found, [])

    def test_connect_src_is_not_counted(self):
        # fetch/XHR is a CORS request, and a CORS response satisfies COEP on
        # its own. An API call cross-origin is not what COEP breaks.
        found = web_security.coep_breaking_sources(self._analysis(
            "default-src 'self'; connect-src 'self' https://api.example.org "
            "wss://api.example.org"))
        self.assertEqual(found, [])

    def test_a_broad_scheme_counts(self):
        found = web_security.coep_breaking_sources(
            self._analysis("default-src 'self'; img-src 'self' https:"))
        self.assertEqual(found, ["https:"])

    def test_sources_are_deduplicated_across_directives(self):
        found = web_security.coep_breaking_sources(self._analysis(
            "default-src 'self'; img-src 'self' https://cdn.example.org; "
            "font-src 'self' https://cdn.example.org"))
        self.assertEqual(found, ["https://cdn.example.org"])

    def test_no_csp_means_no_evidence_either_way(self):
        self.assertEqual(web_security.coep_breaking_sources(None), [])
        self.assertEqual(web_security.coep_breaking_sources({}), [])


class CoepRecommendationTests(unittest.TestCase):

    def _recs(self, headers):
        return recommendations._headers({"http_headers": headers})

    def test_a_deliberate_omission_is_explained_not_demanded(self):
        recs = self._recs({
            "success": True,
            "headers_missing": [],
            "coep": {"applicable": False,
                     "blocking_sources": ["https://cdn.example.org"]},
        })
        titles = [r["title"] for r in recs]
        self.assertIn("Cross-Origin-Embedder-Policy intentionally not advised here", titles)
        item = next(r for r in recs if r["title"].startswith("Cross-Origin-Embedder"))
        self.assertEqual(item["severity"], "info")
        self.assertIn("cdn.example.org", item["problem"])

    def test_it_is_not_also_listed_as_missing(self):
        # Saying "add this header" and "do not add this header" in one report
        # is worse than either alone.
        recs = self._recs({
            "success": True,
            "headers_missing": [],
            "coep": {"applicable": False, "blocking_sources": ["https:"]},
        })
        missing = [r for r in recs if "missing" in r["title"]]
        self.assertEqual(missing, [])

    def test_a_self_only_site_still_gets_the_normal_advice(self):
        recs = self._recs({
            "success": True,
            "headers_missing": ["Cross-Origin-Embedder-Policy"],
            "coep": {"applicable": True, "blocking_sources": []},
        })
        titles = [r["title"] for r in recs]
        self.assertNotIn("Cross-Origin-Embedder-Policy intentionally not advised here", titles)
        self.assertIn("Cross-Origin-Embedder-Policy header missing", titles)

    def test_the_prerequisite_is_spelled_out_in_the_fix(self):
        fix = recommendations._HEADER_FIX["Cross-Origin-Embedder-Policy"]
        self.assertIn("Cross-Origin-Resource-Policy", fix)
        self.assertIn("stop loading", fix)


class CoepScoringTests(unittest.TestCase):
    """A header we decline to recommend must not count against the score, or
    the site is marked down for making the right call."""

    def setUp(self):
        import os
        import tempfile
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = f"{self.tempdir.name}/coep.db"
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        importlib.reload(db_module).init_db()
        self.app_module = importlib.reload(app_module)

    def tearDown(self):
        import os
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _resolve(self, policy, missing=None):
        results = {"headers_missing": list(
            missing if missing is not None else ["Cross-Origin-Embedder-Policy"])}
        self.app_module._resolve_coep_applicability(
            results, web_security.analyze_csp(policy))
        return results

    def test_it_leaves_the_missing_list_when_it_would_break_things(self):
        results = self._resolve("default-src 'self'; img-src 'self' https://cdn.example.org")
        self.assertNotIn("Cross-Origin-Embedder-Policy", results["headers_missing"])
        self.assertTrue(results["coep"]["excluded_from_score"])

    def test_it_stays_missing_for_a_self_contained_site(self):
        results = self._resolve("default-src 'self'; img-src 'self' data:")
        self.assertIn("Cross-Origin-Embedder-Policy", results["headers_missing"])
        self.assertTrue(results["coep"]["applicable"])

    def test_other_missing_headers_are_untouched(self):
        results = self._resolve(
            "default-src 'self'; img-src 'self' https:",
            missing=["Cross-Origin-Embedder-Policy", "Permissions-Policy"])
        self.assertEqual(results["headers_missing"], ["Permissions-Policy"])

    def test_a_site_without_a_csp_keeps_the_default_advice(self):
        # No policy is no evidence; withholding advice would need a reason.
        results = self._resolve(None)
        self.assertIn("Cross-Origin-Embedder-Policy", results["headers_missing"])


if __name__ == "__main__":
    unittest.main()
