import pathlib
import unittest


class DrawerHelperGuardTests(unittest.TestCase):
    """The drawers moved to /monitoring and /reports, so on the scan page
    there is no drawer and no overlay. Four helpers still reached for them
    unguarded, and the throw surfaced as whatever the calling function's catch
    happened to say — which is how a successful scan load reported
    "Network error while loading scan".
    """

    def _app_js(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "js" / "app.js").read_text(encoding="utf-8")

    def _body(self, name, length=500):
        source = self._app_js()
        start = source.index(f"function {name}(")
        return source[start:start + length]

    def test_close_history_survives_a_missing_drawer(self):
        self.assertIn("if (!drawer) return;", self._body("closeHistory"))

    def test_open_history_survives_a_missing_drawer(self):
        self.assertIn("if (!drawer) return;", self._body("openHistory"))

    def test_close_monitors_survives_a_missing_drawer(self):
        self.assertIn("if (!drawer) return;", self._body("closeMonitors"))

    def test_open_monitors_survives_a_missing_drawer(self):
        self.assertIn("if (!drawer) return;", self._body("openMonitors"))

    def test_the_overlay_helpers_are_guarded(self):
        self.assertIn("if (overlay)", self._body("showOverlay"))
        self.assertIn("if (!overlay) return;", self._body("syncOverlay"))

    def test_sync_overlay_tolerates_a_missing_drawer(self):
        # It read .classList off both drawers directly; either being absent
        # threw before the overlay was ever touched.
        body = self._body("syncOverlay", 600)
        self.assertIn("drawer && !drawer.classList", body)


class ErrorMessageHonestyTests(unittest.TestCase):
    """A catch that names one cause for every failure sends the reader after
    the wrong thing. This one claimed a network error after the scan had
    already rendered."""

    def _app_js(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "js" / "app.js").read_text(encoding="utf-8")

    def test_load_scan_no_longer_blames_the_network(self):
        source = self._app_js()
        block = source[source.index("async function loadScan"):][:1400]
        self.assertNotIn("Network error while loading scan", block)

    def test_it_reports_what_actually_went_wrong(self):
        source = self._app_js()
        block = source[source.index("async function loadScan"):][:1400]
        self.assertIn("Could not open that scan", block)
        self.assertIn("err.message", block)

    def test_the_failure_is_logged_for_diagnosis(self):
        source = self._app_js()
        block = source[source.index("async function loadScan"):][:1400]
        self.assertIn("console.error", block)


if __name__ == "__main__":
    unittest.main()
