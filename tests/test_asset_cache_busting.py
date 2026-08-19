import os
import tempfile
import unittest


class AssetCacheBustingTests(unittest.TestCase):
    """A redeploy of the same version shipped new JS under an unchanged URL,
    so browsers kept running the JS they had cached from the previous image.
    On the settings page that looked like "the Save button does nothing":
    the new markup was served, but the old script was still driving it.

    The git revision changes on every build, so it is appended to static
    URLs as a cache-busting token.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "assets.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["AUTH_LOCAL_ENABLED"] = "0"
        os.environ["OAUTH_ENABLED"] = "0"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        os.environ["DOMAINLENS_GIT_SHA"] = "deadbeefcafe1234"

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
                    "OAUTH_ENABLED", "DOMAINLENS_SECRET_KEY", "DOMAINLENS_GIT_SHA"):
            os.environ.pop(key, None)

    def test_token_derives_from_git_revision(self):
        self.assertEqual(self.app_module._asset_token(), "deadbeefcafe")

    def test_pages_version_their_static_assets(self):
        for path in ("/", "/admin/settings", "/trends"):
            body = self.client.get(path).data.decode()
            self.assertIn("?v=deadbeefcafe", body, path)

    def test_no_unversioned_static_asset_remains(self):
        for path in ("/", "/admin/settings", "/trends"):
            body = self.client.get(path).data.decode()
            for marker in ('src="/static/js/', 'href="/static/css/'):
                idx = 0
                while True:
                    idx = body.find(marker, idx)
                    if idx == -1:
                        break
                    end = body.find('"', idx + len(marker))
                    url = body[idx + len(marker) - len('/static/'):end] if end != -1 else ""
                    self.assertIn("?v=", body[idx:end], f"{path}: unversioned asset {url}")
                    idx = end

    def test_static_files_still_serve_with_the_query_string(self):
        resp = self.client.get("/static/js/admin_settings.js?v=deadbeefcafe")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(resp.data) > 0)


class SettingsPageInitResilienceTests(unittest.TestCase):
    """initAdminSettings() sat behind a bare `await DomainLensI18n.init(...)`,
    so any failure in i18n meant it never ran at all — every button on the
    settings page then silently did nothing, with no error shown.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "init.db")
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

    def _bootstrap_js(self):
        # The bootstrap moved out of the page into an external file, because
        # the strict CSP blocks inline <script>. Assert the invariant where
        # the code now lives.
        resp = self.client.get("/static/js/admin_settings.js")
        self.assertEqual(resp.status_code, 200)
        return resp.data.decode()

    def test_i18n_failure_cannot_block_init(self):
        js = self._bootstrap_js()
        i18n_call = js.find("DomainLensI18n.init")
        self.assertNotEqual(i18n_call, -1)
        preceding = js[max(0, i18n_call - 300):i18n_call]
        self.assertIn("try {", preceding)

    def test_init_failure_surfaces_a_visible_banner(self):
        js = self._bootstrap_js()
        self.assertIn("failed to initialise", js)
        self.assertIn("apiKeysMsg", js)

    def test_init_is_actually_invoked_from_the_external_file(self):
        # The call used to live in a CSP-blocked inline block, so the page
        # rendered fine while none of its JavaScript ever ran.
        js = self._bootstrap_js()
        self.assertIn("DOMContentLoaded", js)
        self.assertIn("window.initAdminSettings()", js)


if __name__ == "__main__":
    unittest.main()
