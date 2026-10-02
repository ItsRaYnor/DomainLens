"""Finding your way to the overviews, and reading the history letter right.

The scan page showed nothing but a search box to someone who came back to
look at results; the overviews were two menus away. The history list showed
a big coloured letter that is only the TLS grade but read as a verdict on
the whole domain. And Trends was the one page without the shared footer,
announcing itself as English whatever the language.
"""

import pathlib
import unittest

from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP_JS = ROOT.joinpath("static", "js", "app.js").read_text(encoding="utf-8")


class ScanPageTests(EnterpriseAppTestCase):
    def test_the_scan_page_offers_recent_scans_and_the_overviews(self):
        self.login_as("viewer")
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="homeRecent"', page)
        for href in ("/reports/dashboard", "/monitoring/domains", "/monitoring"):
            self.assertIn(f'href="{href}"', page)

    def test_trends_uses_the_page_language_and_the_shared_footer(self):
        self.login_as("viewer")
        page = self.client.get("/trends").get_data(as_text=True)
        template = ROOT.joinpath("templates", "trends.html").read_text(encoding="utf-8")
        self.assertIn('lang="{{ locale }}"', template)
        self.assertIn("app-footer", page)
        self.assertIn('href="/reports/dashboard"', page)


class ScriptTests(unittest.TestCase):
    def test_the_start_panel_makes_way_for_a_scan(self):
        show = APP_JS[APP_JS.index("function showScanning"):]
        self.assertIn("homeStart", show[:show.index("\n}\n")])

    def test_the_history_letter_says_it_is_the_tls_grade(self):
        history = APP_JS[APP_JS.index("function renderHistoryList"):]
        history = history[:history.index("\n}\n")]
        self.assertIn("'TLS grade '", history)
        self.assertNotIn("finding(s)", history)


if __name__ == "__main__":
    unittest.main()
