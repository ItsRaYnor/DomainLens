import json
import os
import tempfile
import unittest


class AdminSettingsApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "admin.db")
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
        user = self.db.get_user_by_email("admin@example.com")
        with self.client.session_transaction() as sess:
            sess[self.auth.SESSION_USER_KEY] = {
                "id": user["id"],
                "email": user["email"],
                "role": user["role"],
                "provider": "local",
            }

    def tearDown(self):
        self.tempdir.cleanup()
        for key in (
            "DOMAINLENS_DB",
            "DOMAINLENS_DISABLE_SCHEDULER",
            "OAUTH_ENABLED",
            "AUTH_LOCAL_ENABLED",
            "AUTH_REQUIRE_LOGIN",
            "DOMAINLENS_SECRET_KEY",
            "LOCAL_ADMIN_EMAIL",
            "LOCAL_ADMIN_PASSWORD",
        ):
            os.environ.pop(key, None)

    def test_admin_settings_page_requires_admin(self):
        resp = self.client.get("/admin/settings")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"settings-layout", resp.data)

    def test_patch_settings_section(self):
        resp = self.client.patch(
            "/api/admin/settings/general",
            json={"app_title": "ProbeNet"},
        )
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertEqual(payload["values"]["app_title"], "ProbeNet")

    def test_i18n_endpoint(self):
        resp = self.client.get("/api/i18n/nl.json")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["tabs"]["advies"], "Advies")


if __name__ == "__main__":
    unittest.main()
