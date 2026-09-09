import os
import tempfile
import unittest
from unittest import mock


class PartialScanAddsNothingUnrequestedTests(unittest.TestCase):
    """A selected-checks scan must return answers only for the checks that were
    selected. Attaching an assessment for a check the operator never picked
    puts a conclusion in the report about something that was not scanned, which
    is the one thing the reporting convention forbids.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "partial.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db
        import app
        self.db = importlib.reload(db)
        self.app = importlib.reload(app)

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _fake_map(self, **overrides):
        base = {
            "tls_deep": lambda: {"success": True, "grade": "A", "protocols": []},
            "dns": lambda: {"A": ["203.0.113.10"]},
            "spf": lambda: {"found": True, "pass": True},
        }
        base.update(overrides)
        return base

    def test_selecting_tls_deep_does_not_attach_an_ncsc_assessment(self):
        with mock.patch.object(self.app, "_build_check_map", return_value=self._fake_map()):
            results = self.app.run_selected_checks("example.com", ["tls_deep"])
        self.assertIn("tls_deep", results)
        self.assertNotIn("ncsc_tls", results,
                         "an NCSC assessment was attached for a check that was not selected")
        self.assertNotIn("cdn", results,
                         "a CDN detection section was attached for a check that was not selected")

    def test_selecting_ncsc_tls_still_produces_the_assessment(self):
        with mock.patch.object(self.app, "_build_check_map", return_value=self._fake_map()):
            results = self.app.run_selected_checks("example.com", ["ncsc_tls"])
        self.assertIn("ncsc_tls", results)

    def test_unselected_checks_produce_no_recommendations(self):
        # Only DNS was scanned, so nothing may conclude about SPF, DMARC, TLS
        # or headers — those were never measured.
        import recommendations
        with mock.patch.object(self.app, "_build_check_map",
                               return_value={"dns": lambda: {"A": ["203.0.113.10"]}}):
            results = self.app.run_selected_checks("example.com", ["dns"])
        results["domain"] = "example.com"
        categories = {r["category"] for r in recommendations.generate(results)}
        self.assertNotIn("Email", categories)
        self.assertNotIn("TLS", categories)
        self.assertNotIn("Web", categories)


if __name__ == "__main__":
    unittest.main()
