import os
import tempfile
import unittest


class AuthFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "test-domainlens.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["OAUTH_ENABLED"] = "1"
        os.environ["OAUTH_REQUIRE_LOGIN"] = "1"
        os.environ["OAUTH_PROVIDER"] = "google"
        os.environ["OAUTH_CLIENT_ID"] = "client"
        os.environ["OAUTH_CLIENT_SECRET"] = "secret"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        os.environ.pop("AUTH_LOCAL_ENABLED", None)
        os.environ.pop("LOCAL_ADMIN_EMAIL", None)
        os.environ.pop("LOCAL_ADMIN_PASSWORD", None)
        os.environ.pop("AUTH_MFA_REQUIRED", None)

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
        for key in (
            "DOMAINLENS_DB",
            "DOMAINLENS_DISABLE_SCHEDULER",
            "OAUTH_ENABLED",
            "OAUTH_REQUIRE_LOGIN",
            "OAUTH_PROVIDER",
            "OAUTH_CLIENT_ID",
            "OAUTH_CLIENT_SECRET",
            "DOMAINLENS_SECRET_KEY",
            "OAUTH_ALLOWED_EMAILS",
            "OAUTH_ALLOWED_DOMAINS",
            "AUTH_LOCAL_ENABLED",
            "AUTH_REQUIRE_LOGIN",
            "LOCAL_ADMIN_EMAIL",
            "LOCAL_ADMIN_PASSWORD",
            "AUTH_MFA_REQUIRED",
            "AUTH_MFA_ENABLED",
            "AUTH_PASSWORD_MIN_LENGTH",
        ):
            os.environ.pop(key, None)

    def test_unauthenticated_api_is_blocked(self):
        resp = self.client.get("/api/monitors")
        self.assertEqual(resp.status_code, 401)
        payload = resp.get_json()
        self.assertEqual(payload["error"], "Authentication required")

    def test_health_remains_public(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_login_page_renders(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Continue with Google", resp.data)

    def test_email_allowlist(self):
        os.environ["OAUTH_ALLOWED_EMAILS"] = "alice@example.com"
        import importlib
        auth = importlib.reload(self.auth)
        self.assertTrue(auth.user_allowed({"email": "alice@example.com"}))
        self.assertFalse(auth.user_allowed({"email": "bob@example.com"}))

    def test_password_policy_and_hash(self):
        errors = self.auth.validate_password("short", "admin@example.com")
        self.assertTrue(errors)
        password = "Valid-Passw0rd!"
        self.assertEqual(self.auth.validate_password(password, "admin@example.com"), [])
        hashed = self.auth.hash_password(password)
        self.assertTrue(self.auth.verify_password(password, hashed))
        self.assertFalse(self.auth.verify_password("wrong", hashed))

    def test_totp_roundtrip(self):
        secret = self.auth.generate_totp_secret()
        code = self.auth.totp_at(secret)
        self.assertTrue(self.auth.verify_totp(secret, code))
        self.assertFalse(self.auth.verify_totp(secret, "000000"))


class LocalAuthTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "test-local.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["OAUTH_ENABLED"] = "0"
        os.environ["AUTH_LOCAL_ENABLED"] = "1"
        os.environ["AUTH_REQUIRE_LOGIN"] = "1"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret-local"
        os.environ["LOCAL_ADMIN_EMAIL"] = "admin@example.com"
        os.environ["LOCAL_ADMIN_PASSWORD"] = "Str0ng-Local-Pass!"
        os.environ["AUTH_MFA_ENABLED"] = "1"
        os.environ["AUTH_MFA_REQUIRED"] = "0"

        import importlib
        import auth
        import db
        import app

        self.auth = importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        self.app_module = importlib.reload(app)
        self.auth.bootstrap_admin()
        self.client = self.app_module.app.test_client()

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
            "AUTH_MFA_ENABLED",
            "AUTH_MFA_REQUIRED",
        ):
            os.environ.pop(key, None)

    def test_local_login_and_session(self):
        resp = self.client.get("/api/monitors")
        self.assertEqual(resp.status_code, 401)

        resp = self.client.post(
            "/auth/local/login",
            data={"email": "admin@example.com", "password": "Str0ng-Local-Pass!", "next": "/"},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)

        me = self.client.get("/api/auth/me").get_json()
        self.assertTrue(me["authenticated"])
        self.assertEqual(me["user"]["email"], "admin@example.com")
        self.assertEqual(me["user"]["role"], "admin")

        resp = self.client.get("/api/monitors")
        self.assertEqual(resp.status_code, 200)

    def test_bad_password_rejected(self):
        resp = self.client.post(
            "/auth/local/login",
            data={"email": "admin@example.com", "password": "wrong-password", "next": "/"},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])
        me = self.client.get("/api/auth/me").get_json()
        self.assertFalse(me["authenticated"])

    def test_mfa_challenge(self):
        user = self.db.get_user_by_email("admin@example.com", include_secrets=True)
        secret = self.auth.generate_totp_secret()
        self.db.update_user(user["id"], mfa_enabled=True, mfa_secret=secret, mfa_backup_codes=[])

        resp = self.client.post(
            "/auth/local/login",
            data={"email": "admin@example.com", "password": "Str0ng-Local-Pass!", "next": "/"},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/auth/mfa", resp.headers["Location"])
        me = self.client.get("/api/auth/me").get_json()
        self.assertFalse(me["authenticated"])

        code = self.auth.totp_at(secret)
        resp = self.client.post(
            "/auth/mfa",
            data={"code": code, "next": "/"},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        me = self.client.get("/api/auth/me").get_json()
        self.assertTrue(me["authenticated"])

    def test_admin_can_create_user(self):
        self.client.post(
            "/auth/local/login",
            data={"email": "admin@example.com", "password": "Str0ng-Local-Pass!", "next": "/"},
        )
        resp = self.client.post(
            "/admin/users",
            data={
                "email": "analyst@example.com",
                "name": "Analyst",
                "role": "user",
                "password": "Reviewer-Passw0rd!",
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        created = self.db.get_user_by_email("analyst@example.com")
        self.assertIsNotNone(created)
        self.assertEqual(created["role"], "user")

    def test_login_page_shows_local_form(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'name="email"', resp.data)
        self.assertIn(b"Sign in", resp.data)


if __name__ == "__main__":
    unittest.main()
