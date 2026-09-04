import os
import tempfile
import unittest


class ApiKeyEndpointTests(unittest.TestCase):
    """The admin API for the optional OSINT keys must be write-only: it can
    accept a key but must never hand one back, or the "secrets stay out of the
    settings surface" property is lost the moment they become UI-editable.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "keys.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["OAUTH_ENABLED"] = "0"
        os.environ["AUTH_LOCAL_ENABLED"] = "1"
        os.environ["AUTH_REQUIRE_LOGIN"] = "0"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        os.environ["LOCAL_ADMIN_EMAIL"] = "admin@example.com"
        os.environ["LOCAL_ADMIN_PASSWORD"] = "Str0ng-Local-Pass!"
        for env in ("SPAMHAUS_DQS_KEY", "ABUSECH_AUTH_KEY", "OTX_API_KEY"):
            os.environ.pop(env, None)

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
        self.user = self.db.get_user_by_email("admin@example.com")

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "OAUTH_ENABLED",
                    "AUTH_LOCAL_ENABLED", "AUTH_REQUIRE_LOGIN", "DOMAINLENS_SECRET_KEY",
                    "LOCAL_ADMIN_EMAIL", "LOCAL_ADMIN_PASSWORD",
                    "SPAMHAUS_DQS_KEY", "ABUSECH_AUTH_KEY", "OTX_API_KEY"):
            os.environ.pop(key, None)

    def _login(self):
        with self.client.session_transaction() as sess:
            sess[self.auth.SESSION_USER_KEY] = {
                "id": self.user["id"], "email": self.user["email"],
                "role": self.user["role"], "provider": "local",
            }

    def test_set_then_key_never_returned(self):
        self._login()
        secret = "canary-secret-value-123"
        resp = self.client.put("/api/admin/api-keys/OTX_API_KEY", json={"value": secret})
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(secret.encode(), resp.data)

        listing = self.client.get("/api/admin/api-keys")
        self.assertEqual(listing.status_code, 200)
        self.assertNotIn(secret.encode(), listing.data)

        page = self.client.get("/admin/settings")
        self.assertNotIn(secret.encode(), page.data)

    def test_key_takes_effect_without_restart(self):
        self._login()
        self.client.put("/api/admin/api-keys/SPAMHAUS_DQS_KEY", json={"value": "dqs123"})
        # _build_dnsbl_list used to read a module-level constant captured at
        # import time, so a key added at runtime had no effect.
        # _build_dnsbl_list() returns (zone_host, kind, label) triples.
        servers = self.app_module._build_dnsbl_list()
        # (host, kind, label): the label is key-free for storage, the host
        # still carries the key because that is what Spamhaus is queried with.
        self.assertTrue(any("dqs123" in host for host, _kind, _label in servers))
        self.assertFalse(any("dqs123" in label for _host, _kind, label in servers))

    def test_delete_removes_key(self):
        self._login()
        self.client.put("/api/admin/api-keys/OTX_API_KEY", json={"value": "abc"})
        resp = self.client.delete("/api/admin/api-keys/OTX_API_KEY")
        self.assertEqual(resp.status_code, 200)
        from settings import api_keys
        self.assertEqual(api_keys.resolve("OTX_API_KEY", db=self.db), "")

    def test_env_locked_key_rejected(self):
        self._login()
        os.environ["OTX_API_KEY"] = "from-env"
        resp = self.client.put("/api/admin/api-keys/OTX_API_KEY", json={"value": "from-ui"})
        self.assertEqual(resp.status_code, 409)
        from settings import api_keys
        self.assertEqual(api_keys.resolve("OTX_API_KEY", db=self.db), "from-env")

    def test_unmanaged_key_rejected(self):
        self._login()
        # Integration credentials became manageable; the app's own secrets and
        # arbitrary environment variables must still be refused.
        for name in ("DOMAINLENS_SECRET_KEY", "DOMAINLENS_DB", "PATH", "MADE_UP_KEY"):
            resp = self.client.put(f"/api/admin/api-keys/{name}", json={"value": "x"})
            self.assertEqual(resp.status_code, 404, name)

    def test_integration_credentials_are_manageable(self):
        self._login()
        for name in ("SERVICENOW_PASSWORD", "RAPID7_API_KEY", "SCIM_BEARER_TOKEN"):
            resp = self.client.put(f"/api/admin/api-keys/{name}", json={"value": "secret-" + name})
            self.assertEqual(resp.status_code, 200, name)
            self.assertNotIn(b"secret-", resp.data)

    def test_empty_value_rejected(self):
        self._login()
        resp = self.client.put("/api/admin/api-keys/OTX_API_KEY", json={"value": ""})
        self.assertEqual(resp.status_code, 400)

    def test_requires_admin(self):
        # Not logged in at all.
        resp = self.client.put("/api/admin/api-keys/OTX_API_KEY", json={"value": "x"})
        self.assertNotEqual(resp.status_code, 200)
        from settings import api_keys
        self.assertEqual(api_keys.resolve("OTX_API_KEY", db=self.db), "")

    def test_non_admin_cannot_write(self):
        self.db.create_user(email="user@example.com", name="U", role="user",
                            provider="local", password="Another-Str0ng-Pass!")
        viewer = self.db.get_user_by_email("user@example.com")
        with self.client.session_transaction() as sess:
            sess[self.auth.SESSION_USER_KEY] = {
                "id": viewer["id"], "email": viewer["email"],
                "role": viewer["role"], "provider": "local",
            }
        resp = self.client.put("/api/admin/api-keys/OTX_API_KEY", json={"value": "x"})
        self.assertNotEqual(resp.status_code, 200)
        from settings import api_keys
        self.assertEqual(api_keys.resolve("OTX_API_KEY", db=self.db), "")


if __name__ == "__main__":
    unittest.main()
