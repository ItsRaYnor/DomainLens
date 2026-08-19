import os
import unittest
from unittest.mock import MagicMock

import i18n


class I18nTests(unittest.TestCase):
    def test_translate_english(self):
        self.assertIn("Advice", i18n.t("advies.title", "en"))

    def test_translate_dutch(self):
        self.assertIn("Advies", i18n.t("advies.title", "nl"))

    def test_format_vars(self):
        text = i18n.t("loading.scanning", "en", domain="example.com")
        self.assertIn("example.com", text)

    def test_resolve_locale_from_query(self):
        req = MagicMock()
        req.args = {"lang": "nl"}
        req.headers = {}
        self.assertEqual(i18n.resolve_locale(req, None, {"locale": "en"}), "nl")

    def test_api_locale_json_structure(self):
        data = i18n.load_locale("en")
        self.assertIn("nav", data)
        self.assertIn("settings", data)


class I18nFrontendRouteTests(unittest.TestCase):
    """Regression test for a bug where the frontend fetched /api/i18n/<locale>
    (no extension) while the Flask route only matched
    /api/i18n/<locale>.json — every request 404'd, DomainLensI18n.strings
    stayed empty forever, and every t(key) call silently rendered the raw
    key (e.g. "nav.trends") instead of translated text across the entire UI.
    """

    def setUp(self):
        import tempfile
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "i18n_route.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"

        import importlib
        import db
        import app as app_module

        self.db = importlib.reload(db)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_i18n_route_requires_json_suffix(self):
        # This is what the route actually looks like — locale.json.
        resp = self.client.get("/api/i18n/en.json")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("nav", {}).get("trends"), "Trends")

    def test_i18n_js_fetch_url_matches_backend_route(self):
        # Static assertion that the frontend's fetch call includes the
        # ".json" suffix the backend route requires. Would have caught the
        # original mismatch without needing a browser.
        i18n_js_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "static", "js", "i18n.js",
        )
        with open(i18n_js_path) as f:
            lines = f.readlines()
        fetch_lines = [line for line in lines if "fetch('/api/i18n/'" in line]
        self.assertEqual(len(fetch_lines), 1, "Could not find exactly one i18n fetch call in i18n.js")
        self.assertIn(
            ".json", fetch_lines[0],
            "i18n.js fetch call is missing the .json suffix required by the Flask route",
        )


if __name__ == "__main__":
    unittest.main()
