import os
import tempfile
import unittest
from unittest import mock

import dns.resolver

import connection_tests as ct


class SpamhausDqsTests(unittest.TestCase):
    """Reported by a user who saved a Spamhaus DQS key and had no way to
    confirm it actually worked short of waiting for a scan to hit a listed
    domain by chance.
    """

    def _rdata(self, ip):
        r = mock.Mock()
        r.to_text.return_value = ip
        return r

    def test_no_key_configured(self):
        with mock.patch("settings.api_keys.resolve", return_value=""):
            result = ct.test_spamhaus_dqs()
        self.assertFalse(result["ok"])
        self.assertIn("No key configured", result["detail"])

    def test_valid_key_sees_test_entry_listed(self):
        with mock.patch("settings.api_keys.resolve", return_value="mykey"), \
             mock.patch("dns.resolver.resolve", return_value=[self._rdata("127.0.0.2")]):
            result = ct.test_spamhaus_dqs()
        self.assertTrue(result["ok"])

    def test_quota_or_auth_error_code_is_not_a_pass(self):
        # Spamhaus's documented "something's wrong" signal, not a real hit.
        with mock.patch("settings.api_keys.resolve", return_value="badkey"), \
             mock.patch("dns.resolver.resolve", return_value=[self._rdata("127.255.255.254")]):
            result = ct.test_spamhaus_dqs()
        self.assertFalse(result["ok"])
        self.assertIn("error code", result["detail"])

    def test_nxdomain_is_a_clear_failure(self):
        with mock.patch("settings.api_keys.resolve", return_value="badkey"), \
             mock.patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = ct.test_spamhaus_dqs()
        self.assertFalse(result["ok"])
        self.assertIn("NXDOMAIN", result["detail"])

    def test_servfail_is_a_clear_failure(self):
        with mock.patch("settings.api_keys.resolve", return_value="badkey"), \
             mock.patch("dns.resolver.resolve", side_effect=dns.resolver.NoNameservers()):
            result = ct.test_spamhaus_dqs()
        self.assertFalse(result["ok"])


class AbuseChTests(unittest.TestCase):

    def test_no_key_configured(self):
        with mock.patch("settings.api_keys.resolve", return_value=""):
            result = ct.test_abusech()
        self.assertFalse(result["ok"])

    def test_401_is_rejected_key(self):
        resp = mock.Mock(status_code=401)
        with mock.patch("settings.api_keys.resolve", return_value="badkey"), \
             mock.patch("connection_tests.requests.post", return_value=resp):
            result = ct.test_abusech()
        self.assertFalse(result["ok"])
        self.assertIn("401", result["detail"])

    def test_ok_query_status_passes(self):
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = mock.Mock()
        resp.json.return_value = {"query_status": "ok"}
        with mock.patch("settings.api_keys.resolve", return_value="goodkey"), \
             mock.patch("connection_tests.requests.post", return_value=resp):
            result = ct.test_abusech()
        self.assertTrue(result["ok"])

    def test_no_result_query_status_still_passes(self):
        # Zero hits is a valid authenticated response, not a failure.
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = mock.Mock()
        resp.json.return_value = {"query_status": "no_result"}
        with mock.patch("settings.api_keys.resolve", return_value="goodkey"), \
             mock.patch("connection_tests.requests.post", return_value=resp):
            result = ct.test_abusech()
        self.assertTrue(result["ok"])


class OtxTests(unittest.TestCase):

    def test_no_key_configured(self):
        with mock.patch("settings.api_keys.resolve", return_value=""):
            result = ct.test_otx()
        self.assertFalse(result["ok"])

    def test_401_is_rejected_key(self):
        resp = mock.Mock(status_code=401)
        with mock.patch("settings.api_keys.resolve", return_value="badkey"), \
             mock.patch("connection_tests.requests.get", return_value=resp):
            result = ct.test_otx()
        self.assertFalse(result["ok"])

    def test_200_with_username_passes(self):
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = mock.Mock()
        resp.json.return_value = {"username": "someone"}
        with mock.patch("settings.api_keys.resolve", return_value="goodkey"), \
             mock.patch("connection_tests.requests.get", return_value=resp):
            result = ct.test_otx()
        self.assertTrue(result["ok"])
        self.assertIn("someone", result["detail"])


class ServiceNowTests(unittest.TestCase):

    def test_missing_fields_reported(self):
        cfg = {"instance": "", "user": "u", "password": ""}
        with mock.patch("servicenow.config", return_value=cfg):
            result = ct.test_servicenow()
        self.assertFalse(result["ok"])
        self.assertIn("instance", result["detail"])
        self.assertIn("password", result["detail"])

    def test_401_is_rejected_credentials(self):
        cfg = {"instance": "https://example.service-now.com", "user": "u", "password": "p"}
        resp = mock.Mock(status_code=401)
        with mock.patch("servicenow.config", return_value=cfg), \
             mock.patch("connection_tests.requests.get", return_value=resp):
            result = ct.test_servicenow()
        self.assertFalse(result["ok"])

    def test_200_passes(self):
        cfg = {"instance": "https://example.service-now.com", "user": "u", "password": "p"}
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = mock.Mock()
        with mock.patch("servicenow.config", return_value=cfg), \
             mock.patch("connection_tests.requests.get", return_value=resp):
            result = ct.test_servicenow()
        self.assertTrue(result["ok"])


class Rapid7Tests(unittest.TestCase):

    def test_nothing_configured(self):
        cfg = {"console_configured": False, "cloud_configured": False}
        with mock.patch("insightvm.config", return_value=cfg):
            result = ct.test_rapid7()
        self.assertFalse(result["ok"])

    def test_console_api_success(self):
        cfg = {
            "console_configured": True, "cloud_configured": False,
            "api_base_url": "https://console.example.com", "username": "u",
            "password": "p", "verify_ssl": True,
        }
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = mock.Mock()
        with mock.patch("insightvm.config", return_value=cfg), \
             mock.patch("connection_tests.requests.get", return_value=resp):
            result = ct.test_rapid7()
        self.assertTrue(result["ok"])
        self.assertIn("Console API", result["detail"])

    def test_console_api_401(self):
        cfg = {
            "console_configured": True, "cloud_configured": False,
            "api_base_url": "https://console.example.com", "username": "u",
            "password": "wrong", "verify_ssl": True,
        }
        resp = mock.Mock(status_code=401)
        with mock.patch("insightvm.config", return_value=cfg), \
             mock.patch("connection_tests.requests.get", return_value=resp):
            result = ct.test_rapid7()
        self.assertFalse(result["ok"])

    def test_cloud_api_success_when_console_not_configured(self):
        cfg = {
            "console_configured": False, "cloud_configured": True,
            "cloud_api_base_url": "https://us.api.insight.rapid7.com",
            "api_key": "key123",
        }
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = mock.Mock()
        with mock.patch("insightvm.config", return_value=cfg), \
             mock.patch("connection_tests.requests.get", return_value=resp):
            result = ct.test_rapid7()
        self.assertTrue(result["ok"])
        self.assertIn("Cloud API", result["detail"])


class RunTestDispatchTests(unittest.TestCase):

    def test_unknown_target(self):
        result = ct.run_test("NOT_A_REAL_TARGET")
        self.assertFalse(result["ok"])

    def test_crash_is_caught_not_raised(self):
        with mock.patch.dict(ct.KEY_TESTS, {"BOOM": mock.Mock(side_effect=RuntimeError("kaboom"))}):
            result = ct.run_test("BOOM")
        self.assertFalse(result["ok"])
        self.assertIn("crashed", result["detail"])


class ApiKeyTestEndpointTests(unittest.TestCase):
    """The HTTP surface: admin-only, never leaks the credential value even
    inside a test's detail message.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "test.db")
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
                "id": user["id"], "email": user["email"],
                "role": user["role"], "provider": "local",
            }

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "OAUTH_ENABLED",
                    "AUTH_LOCAL_ENABLED", "AUTH_REQUIRE_LOGIN", "DOMAINLENS_SECRET_KEY",
                    "LOCAL_ADMIN_EMAIL", "LOCAL_ADMIN_PASSWORD"):
            os.environ.pop(key, None)

    def test_unknown_target_404(self):
        resp = self.client.post("/api/admin/api-keys/NOT_REAL/test")
        self.assertEqual(resp.status_code, 404)

    def test_known_key_returns_ok_field(self):
        # run_test() is looked up as a module attribute at call time (app.py
        # does `import connection_tests; connection_tests.run_test(...)`),
        # unlike the KEY_TESTS dict values which are bound at module-load
        # time — patch the dispatcher itself, not an inner function.
        with mock.patch("connection_tests.run_test", return_value={"ok": True, "detail": "works"}) as mocked:
            resp = self.client.post("/api/admin/api-keys/SPAMHAUS_DQS_KEY/test")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": True, "detail": "works"})
        mocked.assert_called_once_with("SPAMHAUS_DQS_KEY")

    def test_group_target_returns_ok_field(self):
        with mock.patch("connection_tests.run_test", return_value={"ok": False, "detail": "missing fields"}) as mocked:
            resp = self.client.post("/api/admin/api-keys/ServiceNow/test")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["ok"])
        mocked.assert_called_once_with("ServiceNow")

    def test_admin_required(self):
        anon_client = self.app_module.app.test_client()
        resp = anon_client.post("/api/admin/api-keys/SPAMHAUS_DQS_KEY/test")
        self.assertNotEqual(resp.status_code, 200)

    def test_credential_value_never_leaked_in_response(self):
        # Even if a test's detail message were built carelessly, the key
        # itself must never round-trip back to the client.
        from settings import api_keys
        api_keys.set_key("SPAMHAUS_DQS_KEY", "super-secret-canary-9999", db=self.db)
        resp = self.client.post("/api/admin/api-keys/SPAMHAUS_DQS_KEY/test")
        self.assertNotIn(b"super-secret-canary-9999", resp.data)


if __name__ == "__main__":
    unittest.main()
