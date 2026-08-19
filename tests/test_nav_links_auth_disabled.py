import os
import tempfile
import unittest


class NavLinksWhenAuthDisabledTests(unittest.TestCase):
    """require_admin() and require_login() both wave every request through
    once no auth method (local/OAuth/SAML) is enabled — that's intentional
    for an internal-only deployment. But the nav templates hid the Settings
    and Users links behind `auth_status.enabled`, so /admin/settings and
    /admin/users were reachable yet undiscoverable: a user with auth fully
    off had no way to find the page short of typing the URL from memory.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "nav.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["AUTH_LOCAL_ENABLED"] = "0"
        os.environ["OAUTH_ENABLED"] = "0"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"

        import importlib
        import auth
        import db
        import app
        from settings.store import get_store

        self.auth = importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "AUTH_LOCAL_ENABLED", "OAUTH_ENABLED", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    def test_index_shows_admin_links_when_auth_disabled(self):
        resp = self.client.get("/")
        body = resp.data.decode()
        self.assertIn('href="/admin/settings"', body)
        self.assertIn('href="/admin/users"', body)

    def test_trends_shows_admin_links_when_auth_disabled(self):
        resp = self.client.get("/trends")
        body = resp.data.decode()
        self.assertIn('href="/admin/settings"', body)
        self.assertIn('href="/admin/users"', body)

    def test_admin_pages_are_actually_reachable(self):
        for path in ("/admin/settings", "/admin/users"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, path)


class NavLinksWhenAuthEnabledTests(unittest.TestCase):
    """Guard against the fix above accidentally exposing admin links to
    anonymous users once auth IS configured.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "nav2.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["OAUTH_ENABLED"] = "0"
        os.environ["AUTH_LOCAL_ENABLED"] = "1"
        os.environ["AUTH_REQUIRE_LOGIN"] = "0"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        os.environ["LOCAL_ADMIN_EMAIL"] = "admin@example.com"
        os.environ["LOCAL_ADMIN_PASSWORD"] = "Str0ng-Local-Pass!"

        import importlib
        import auth
        import db
        import app
        from settings.store import get_store

        self.auth = importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.auth.bootstrap_admin()
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "OAUTH_ENABLED",
                    "AUTH_LOCAL_ENABLED", "AUTH_REQUIRE_LOGIN", "DOMAINLENS_SECRET_KEY",
                    "LOCAL_ADMIN_EMAIL", "LOCAL_ADMIN_PASSWORD"):
            os.environ.pop(key, None)

    def test_anonymous_user_does_not_see_admin_links(self):
        resp = self.client.get("/")
        body = resp.data.decode()
        self.assertNotIn('href="/admin/settings"', body)
        self.assertNotIn('href="/admin/users"', body)
        self.assertIn('href="/login"', body)

    def test_logged_in_admin_sees_admin_links(self):
        user = self.db.get_user_by_email("admin@example.com")
        with self.client.session_transaction() as sess:
            sess[self.auth.SESSION_USER_KEY] = {
                "id": user["id"], "email": user["email"],
                "role": user["role"], "provider": "local",
            }
        for path in ("/", "/trends"):
            resp = self.client.get(path)
            body = resp.data.decode()
            self.assertIn('href="/admin/settings"', body, path)
            self.assertIn('href="/admin/users"', body, path)


if __name__ == "__main__":
    unittest.main()
