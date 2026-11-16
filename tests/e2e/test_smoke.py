"""Every page, opened in a real browser.

The unit tests render templates and call endpoints, but none of them runs the
page's JavaScript: a script that throws on load, a CSP rule that blocks the
page's own script, or a fetch() the server refuses all pass the suite and
leave the page blank or broken. Only a browser shows that.

Runs against a DomainLens started by CI (DOMAINLENS_E2E_URL) and is skipped
everywhere else, so a plain `pytest` needs neither a browser nor a server.
"""

import os
import unittest

BASE = os.environ.get("DOMAINLENS_E2E_URL", "").rstrip("/")

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - only CI installs it
    sync_playwright = None

PAGES = (
    "/", "/monitoring", "/monitoring/domains", "/monitoring/domains/changes",
    "/monitoring/events", "/monitoring/organisation", "/reports", "/reports/dashboard",
    "/reports/compare", "/trends", "/remediate", "/tools/whois", "/tools/dns",
    "/tools/ip", "/tools/mail", "/tools/disclosure", "/tools/impersonation",
    "/tools/versions", "/help", "/admin/settings",
)


@unittest.skipUnless(BASE and sync_playwright, "set DOMAINLENS_E2E_URL and install playwright")
class BrowserSmokeTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._pw = sync_playwright().start()
        cls.browser = cls._pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls._pw.stop()

    def _open(self, path):
        page = self.browser.new_page()
        problems = []
        page.on("pageerror", lambda exc: problems.append(f"script error: {exc}"))
        page.on("console", lambda msg: problems.append(f"console {msg.type}: {msg.text}")
                if msg.type == "error" else None)
        response = page.goto(BASE + path, wait_until="networkidle")
        return page, response, problems

    def test_every_page_loads_without_a_script_error_or_csp_violation(self):
        for path in PAGES:
            with self.subTest(page=path):
                page, response, problems = self._open(path)
                try:
                    self.assertLess(response.status, 400, f"{path} answered {response.status}")
                    self.assertEqual(problems, [], f"{path}: " + "; ".join(problems))
                    self.assertTrue(page.locator("main, .container, body").first.inner_text().strip(),
                                    f"{path} rendered nothing")
                finally:
                    page.close()

    def test_the_pages_own_writes_pass_the_cross_site_check(self):
        # The CSRF check reads headers only a browser sets (Sec-Fetch-Site,
        # Origin); the test client sends neither, so only here is it shown
        # that DomainLens's own fetch() calls are still let through.
        page, _response, _problems = self._open("/tools/mail")
        try:
            status = page.evaluate("""async () => {
                const r = await fetch('/api/linkcheck', {method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({text: 'nothing to check here'})});
                return r.status;
            }""")
            self.assertNotEqual(status, 403, "the page's own POST was refused as cross-site")
        finally:
            page.close()


if __name__ == "__main__":
    unittest.main()
