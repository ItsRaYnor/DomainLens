import unittest
from unittest import mock

import osint
import recommendations
import scan_diff


class VirusTotalLookupTests(unittest.TestCase):
    """An optional reputation source must report "not measured" without a key.
    Turning an unconfigured lookup into a clean verdict would put a conclusion
    in the report about something that was never checked.
    """

    def test_without_a_key_it_is_skipped_not_clean(self):
        with mock.patch.object(osint, "_api_key", return_value=""):
            result = osint.virustotal_lookup("example.com")
        self.assertTrue(result["skipped"])
        self.assertFalse(result["configured"])
        # success=True means "the collector ran fine", so it must be paired
        # with skipped so nothing reads 0 detections as a verdict.
        self.assertTrue(result["success"])

    def test_a_key_produces_counts_and_the_engines_that_flagged_it(self):
        payload = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 60, "undetected": 8},
            "last_analysis_results": {
                "VendorA": {"category": "malicious"},
                "VendorB": {"category": "suspicious"},
                "VendorC": {"category": "harmless"},
            },
            "reputation": -14,
        }}}
        with mock.patch.object(osint, "_api_key", return_value="k"), \
             mock.patch.object(osint, "_fetch_json", return_value=(payload, None)):
            result = osint.virustotal_lookup("example.com")
        self.assertTrue(result["success"])
        self.assertFalse(result.get("skipped"))
        self.assertEqual(result["malicious"], 2)
        self.assertEqual(result["reputation"], -14)
        self.assertEqual(result["flagged_by"], ["VendorA", "VendorB"])

    def test_a_rejected_key_is_an_error_not_a_clean_verdict(self):
        with mock.patch.object(osint, "_api_key", return_value="bad"), \
             mock.patch.object(osint, "_fetch_json",
                               return_value=(None, "VirusTotal rejected the API key")):
            result = osint.virustotal_lookup("example.com")
        self.assertFalse(result["success"])
        self.assertIn("rejected", result["error"])


class VirusTotalRecommendationTests(unittest.TestCase):
    def _recs(self, summary, sources=None):
        results = {"osint": {"success": True, "summary": summary, "sources": sources or {}}}
        return recommendations.generate(results)

    def test_unconfigured_virustotal_says_nothing(self):
        recs = self._recs({"threat_hits": 0, "virustotal_measured": False,
                           "virustotal_malicious": None})
        self.assertEqual([r for r in recs if "VirusTotal" in r["title"]], [])

    def test_several_engines_agreeing_is_high_pending_confirmation(self):
        recs = self._recs(
            {"threat_hits": 0, "virustotal_measured": True,
             "virustotal_malicious": 3, "virustotal_suspicious": 0},
            {"virustotal": {"flagged_by": ["VendorA", "VendorB", "VendorC"]}})
        hit = next(r for r in recs if "VirusTotal" in r["title"])
        self.assertEqual(hit["severity"], recommendations.SEVERITY_HIGH)
        self.assertIn("VendorA", hit["problem"])

    def test_a_single_detection_is_reported_for_confirmation_not_as_a_verdict(self):
        recs = self._recs(
            {"threat_hits": 0, "virustotal_measured": True,
             "virustotal_malicious": 1, "virustotal_suspicious": 0},
            {"virustotal": {"flagged_by": ["VendorA"]}})
        hit = next(r for r in recs if "VirusTotal" in r["title"])
        self.assertEqual(hit["severity"], recommendations.SEVERITY_INFO)


class VirusTotalDiffDimensionTests(unittest.TestCase):
    def _row(self, old, new):
        diff = scan_diff.compare_dimensions(old, new)
        return next(r for r in diff["dimensions"] if r["key"] == "virustotal")

    def _osint(self, measured, malicious=0, suspicious=0):
        return {"osint": {"success": True, "summary": {
            "virustotal_measured": measured,
            "virustotal_malicious": malicious,
            "virustotal_suspicious": suspicious,
        }}}

    def test_new_detections_are_worse(self):
        row = self._row(self._osint(True, 0), self._osint(True, 3))
        self.assertEqual(row["status"], "worse")
        self.assertEqual((row["old"], row["new"]), (0, 3))

    def test_unconfigured_on_either_side_is_unmeasured(self):
        row = self._row(self._osint(False), self._osint(True, 2))
        self.assertEqual(row["status"], "unmeasured")


if __name__ == "__main__":
    unittest.main()
