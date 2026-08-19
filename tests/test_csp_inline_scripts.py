import os
import re
import tempfile
import unittest


class CspInlineScriptTests(unittest.TestCase):
    """The app serves `script-src 'self'` with no 'unsafe-inline', so the
    browser blocks every inline <script>. The settings page put its whole
    bootstrap in one -- including the call to initAdminSettings() -- so that
    page's JavaScript never ran at all: no click handlers, and pressing Save
    did nothing with no error anywhere the user could see.

    Page data now travels in <script type="application/json"> blocks, which
    are data rather than executable script and are therefore allowed, and
    all logic lives in external files.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "csp.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["AUTH_LOCAL_ENABLED"] = "0"
        os.environ["OAUTH_ENABLED"] = "0"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"

        import importlib
        import auth
        import db
        import app
        from settings.store import get_store

        importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "AUTH_LOCAL_ENABLED",
                    "OAUTH_ENABLED", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    PAGES = ("/", "/admin/settings", "/admin/users", "/trends")

    def test_csp_still_forbids_inline_script(self):
        # If this ever gains 'unsafe-inline', the guard below stops being
        # meaningful -- weakening the CSP is not the intended fix.
        csp = self.client.get("/").headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp.split("script-src")[1].split(";")[0])

    def test_no_page_relies_on_an_executable_inline_script(self):
        for path in self.PAGES:
            body = self.client.get(path).data.decode()
            for match in re.finditer(r"<script([^>]*)>", body):
                attrs = match.group(1)
                if "src=" in attrs:
                    continue  # external file: allowed by script-src 'self'
                self.assertIn(
                    'type="application/json"', attrs,
                    f"{path}: executable inline <script> would be blocked by CSP",
                )

    def test_settings_page_ships_its_data_as_json_blocks(self):
        body = self.client.get("/admin/settings").data.decode()
        self.assertIn('<script type="application/json" id="pageLocale">', body)
        self.assertIn('<script type="application/json" id="settingsSchema">', body)
        self.assertIn("admin_settings.js", body)

    def test_settings_schema_json_block_is_valid_json(self):
        import json
        body = self.client.get("/admin/settings").data.decode()
        m = re.search(
            r'<script type="application/json" id="settingsSchema">(.*?)</script>',
            body, re.S,
        )
        self.assertIsNotNone(m)
        schema = json.loads(m.group(1))
        self.assertIsInstance(schema, dict)
        # Sections are grouped into categories now; the form is built from
        # both halves, so both have to survive the trip to the browser.
        self.assertIn("general", schema["sections"])
        self.assertTrue(schema["categories"])

    def test_locale_json_block_is_valid_on_every_page_that_uses_it(self):
        import json
        for path in self.PAGES:
            body = self.client.get(path).data.decode()
            m = re.search(
                r'<script type="application/json" id="pageLocale">(.*?)</script>',
                body, re.S,
            )
            if m is None:
                continue
            self.assertIsInstance(json.loads(m.group(1)), str, path)


if __name__ == "__main__":
    unittest.main()
