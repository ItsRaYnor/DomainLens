import importlib
import io
import os
import tempfile
import unittest

_ENV = {
    "DOMAINLENS_DISABLE_SCHEDULER": "1",
    "OAUTH_ENABLED": "0",
    "AUTH_LOCAL_ENABLED": "1",
    "AUTH_REQUIRE_LOGIN": "1",
    "DOMAINLENS_SECRET_KEY": "test-secret-hardening",
    "LOCAL_ADMIN_EMAIL": "admin@example.com",
    "LOCAL_ADMIN_PASSWORD": "Str0ng-Local-Pass!",
    "AUTH_MFA_ENABLED": "1",
    "AUTH_MFA_REQUIRED": "0",
}
_PASSWORD = _ENV["LOCAL_ADMIN_PASSWORD"]


class _LocalLoginCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "hardening.db")
        os.environ.update(_ENV)
        import auth
        import db
        import app
        self.auth = importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        self.module = importlib.reload(app)
        self.auth.bootstrap_admin()
        self.client = self.module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ["DOMAINLENS_DB", *_ENV]:
            os.environ.pop(key, None)

    def _sign_in(self, next_url="/", password=_PASSWORD, client=None, **kwargs):
        return (client or self.client).post(
            "/auth/local/login",
            data={"email": "admin@example.com", "password": password, "next": next_url},
            **kwargs)


class SafeNextTests(unittest.TestCase):
    """`next` comes from a link anyone can write. Only "starts with /" was
    checked (and on /login not even that), so a link to the real sign-in page
    could send the user on to a copy of it on another host."""

    def test_a_path_on_this_site_is_kept(self):
        import auth
        for value in ("/", "/monitoring", "/scan?domain=example.com#dns", "/a/%2F/b"):
            with self.subTest(value=value):
                self.assertEqual(auth.safe_next(value), value)

    def test_anything_a_browser_reads_as_another_host_is_refused(self):
        import auth
        for value in ("https://evil.example/", "//evil.example/", "/\\evil.example/",
                      "\\\\evil.example", "/\t/evil.example", "/\n/evil.example",
                      "javascript:alert(1)", "evil.example", "", None, 42):
            with self.subTest(value=value):
                self.assertEqual(auth.safe_next(value), "/")


class OpenRedirectTests(_LocalLoginCase):
    def test_a_signed_in_user_is_not_sent_to_another_host_from_the_login_page(self):
        self.assertEqual(self._sign_in().status_code, 302)
        for target in ("https://evil.example/", "//evil.example/"):
            with self.subTest(target=target):
                resp = self.client.get("/login", query_string={"next": target})
                self.assertEqual(resp.status_code, 302)
                self.assertNotIn("evil.example", resp.headers["Location"])

    def test_signing_in_does_not_end_on_another_host(self):
        resp = self._sign_in("//evil.example/")
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn("evil.example", resp.headers["Location"])

    def test_a_local_next_still_works(self):
        resp = self._sign_in("/monitoring")
        self.assertTrue(resp.headers["Location"].endswith("/monitoring"))


class SecureCookieTests(_LocalLoginCase):
    """The cookie lacked Secure unless an environment variable said so, so a
    browser sent it over a plain http:// link to an HTTPS installation."""

    def _cookie_header(self, resp):
        return "; ".join(v for k, v in resp.headers.items() if k.lower() == "set-cookie"
                         and v.startswith("session="))

    def test_a_session_set_over_https_is_marked_secure(self):
        resp = self._sign_in(base_url="https://lens.example.com")
        self.assertIn("Secure", self._cookie_header(resp))

    def test_plain_http_installations_keep_working(self):
        resp = self._sign_in(base_url="http://lens.example.com")
        self.assertNotIn("Secure", self._cookie_header(resp))
        me = self.client.get("/api/auth/me", base_url="http://lens.example.com").get_json()
        self.assertTrue(me["authenticated"])


class LoginRateLimitTests(_LocalLoginCase):
    """Only the account was locked after failures. One address could try a
    password against every account, or lock any account at will."""

    def test_an_address_that_keeps_failing_is_stopped_across_accounts(self):
        limit = self.module._LOGIN_RATE["requests"]
        for n in range(limit):
            self.client.post("/auth/local/login",
                             data={"email": f"user{n}@example.com", "password": "Winter2026!"})
        resp = self._sign_in()
        self.assertIn("Too+many+sign-in+attempts", resp.headers["Location"])
        self.assertFalse(self.client.get("/api/auth/me").get_json()["authenticated"])

    def test_another_address_is_not_affected(self):
        limit = self.module._LOGIN_RATE["requests"]
        for _ in range(limit):
            self._sign_in(password="wrong", environ_base={"REMOTE_ADDR": "203.0.113.9"})
        resp = self._sign_in(environ_base={"REMOTE_ADDR": "198.51.100.4"})
        self.assertNotIn("Too+many", resp.headers["Location"])


class RateStoreTests(_LocalLoginCase):
    def test_addresses_whose_requests_expired_are_forgotten(self):
        # Keys were never removed: every address ever seen stayed in memory.
        store = self.module._rate_store
        store.clear()
        self.module._rate_windows["scan"] = 60
        store[("scan", "203.0.113.1")] = [1000.0]
        store[("scan", "203.0.113.2")] = [5000.0]
        self.module._prune_rate_store(5010.0)
        self.assertNotIn(("scan", "203.0.113.1"), store)
        self.assertIn(("scan", "203.0.113.2"), store)


class UploadLimitTests(_LocalLoginCase):
    """No limit on a request body: any size was accepted and spooled to /tmp
    -- memory, in the read-only container -- before a handler saw it."""

    def test_an_oversized_upload_is_refused_before_the_handler_reads_it(self):
        self._sign_in()
        self.module.app.config["MAX_CONTENT_LENGTH"] = 1024
        try:
            resp = self.client.post(
                "/api/portfolio/import",
                data={"file": (io.BytesIO(b"x" * 4096), "big.xlsx")},
                content_type="multipart/form-data")
        finally:
            self.module.app.config["MAX_CONTENT_LENGTH"] = self.module.MAX_UPLOAD_BYTES
        self.assertEqual(resp.status_code, 413)
        self.assertIn("larger than", resp.get_json()["error"])

    def test_the_limit_is_set_and_leaves_room_for_the_largest_import(self):
        self.assertGreater(self.module.app.config["MAX_CONTENT_LENGTH"], 50 * 1024 * 1024)


class UserAdminRoutesTests(_LocalLoginCase):
    def test_the_user_pages_still_answer_after_moving_out_of_app_py(self):
        self._sign_in()
        self.assertEqual(self.client.get("/admin/users").status_code, 200)
        users = self.client.get("/api/admin/users").get_json()["users"]
        self.assertIn("admin@example.com", [u["email"] for u in users])
        with self.module.app.test_request_context():
            from flask import url_for
            self.assertEqual(url_for("admin_users_page"), "/admin/users")


if __name__ == "__main__":
    unittest.main()
