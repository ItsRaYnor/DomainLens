import importlib
import os
import tempfile
import unittest


_ALL_ENV = (
    "SERVICENOW_USER", "SERVICENOW_PASSWORD",
    "RAPID7_USERNAME", "RAPID7_PASSWORD", "RAPID7_API_KEY",
    "OAUTH_CLIENT_SECRET", "AZURE_CLIENT_SECRET",
    "SCIM_BEARER_TOKEN", "SCIM_CLIENT_SECRET", "SCIM_TOKEN",
)


class ManagedCredentialTests(unittest.TestCase):
    """The integration credentials were environment-only, which is not the
    safer default: a value in docker-compose.yml is plaintext in a file that
    tends to reach git, is readable to anyone with stack access, and shows up
    in `docker inspect` and /proc/<pid>/environ. Encrypted in the database
    with the key in DOMAINLENS_SECRET_KEY, an attacker needs both.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "cred.db")
        os.environ["DOMAINLENS_SECRET_KEY"] = "unit-test-secret-key"
        for env in _ALL_ENV:
            os.environ.pop(env, None)
        import db as db_module
        importlib.reload(db_module)
        self.db = db_module
        self.db.init_db()
        from settings import api_keys
        self.api_keys = api_keys
        api_keys._fernet_cache.clear()

    def tearDown(self):
        self.tempdir.cleanup()
        self.api_keys._fernet_cache.clear()
        for env in _ALL_ENV + ("DOMAINLENS_DB", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(env, None)

    # --- storage ---

    def test_all_credentials_are_managed(self):
        for env in ("SERVICENOW_PASSWORD", "RAPID7_API_KEY",
                    "OAUTH_CLIENT_SECRET", "SCIM_BEARER_TOKEN"):
            self.assertTrue(self.api_keys.is_managed(env), env)

    def test_arbitrary_env_var_is_not_managed(self):
        # The admin API must not be pointable at any environment variable.
        for env in ("PATH", "DOMAINLENS_SECRET_KEY", "DOMAINLENS_DB", "HOME"):
            self.assertFalse(self.api_keys.is_managed(env), env)

    def test_credential_round_trip_and_encryption(self):
        self.api_keys.set_key("SERVICENOW_PASSWORD", "sn-canary-1234", db=self.db)
        self.assertEqual(
            self.api_keys.resolve("SERVICENOW_PASSWORD", db=self.db), "sn-canary-1234")
        blob = str(self.db.get_setting_section("api_keys"))
        self.assertNotIn("sn-canary-1234", blob)
        self.assertIn("enc:v2:", blob)

    # --- fallback chains must behave exactly as before ---

    def test_env_beats_stored_across_the_whole_chain(self):
        # Old behaviour: env AZURE wins, else env OAUTH. A stored AZURE value
        # must not outrank an environment OAUTH value that used to win.
        self.api_keys.set_key("AZURE_CLIENT_SECRET", "stored-azure", db=self.db)
        os.environ["OAUTH_CLIENT_SECRET"] = "env-oauth"
        self.assertEqual(
            self.api_keys.resolve_first("AZURE_CLIENT_SECRET", "OAUTH_CLIENT_SECRET", db=self.db),
            "env-oauth",
        )

    def test_chain_order_respected_within_env(self):
        os.environ["AZURE_CLIENT_SECRET"] = "env-azure"
        os.environ["OAUTH_CLIENT_SECRET"] = "env-oauth"
        self.assertEqual(
            self.api_keys.resolve_first("AZURE_CLIENT_SECRET", "OAUTH_CLIENT_SECRET", db=self.db),
            "env-azure",
        )

    def test_chain_order_respected_within_store(self):
        self.api_keys.set_key("OAUTH_CLIENT_SECRET", "stored-oauth", db=self.db)
        self.api_keys.set_key("AZURE_CLIENT_SECRET", "stored-azure", db=self.db)
        self.assertEqual(
            self.api_keys.resolve_first("AZURE_CLIENT_SECRET", "OAUTH_CLIENT_SECRET", db=self.db),
            "stored-azure",
        )

    def test_unmanaged_name_in_chain_falls_back_to_env_only(self):
        # SCIM_TOKEN is a legacy alias that is not storable.
        os.environ["SCIM_TOKEN"] = "legacy-env-token"
        self.assertEqual(
            self.api_keys.resolve_first("SCIM_BEARER_TOKEN", "SCIM_TOKEN", db=self.db),
            "legacy-env-token",
        )

    # --- consumers ---

    def test_servicenow_reads_stored_credentials(self):
        import servicenow
        importlib.reload(servicenow)
        self.api_keys.set_key("SERVICENOW_USER", "sn-user", db=self.db)
        self.api_keys.set_key("SERVICENOW_PASSWORD", "sn-pass", db=self.db)
        self.assertEqual(servicenow._managed_secret("SERVICENOW_USER"), "sn-user")
        self.assertEqual(servicenow._managed_secret("SERVICENOW_PASSWORD"), "sn-pass")

    def test_insightvm_reads_stored_credentials(self):
        import insightvm
        importlib.reload(insightvm)
        self.api_keys.set_key("RAPID7_API_KEY", "r7-key", db=self.db)
        self.assertEqual(insightvm._managed_secret("RAPID7_API_KEY"), "r7-key")

    def test_scim_oauth_reads_stored_credentials(self):
        import scim_oauth
        importlib.reload(scim_oauth)
        self.api_keys.set_key("SCIM_BEARER_TOKEN", "scim-token", db=self.db)
        self.assertEqual(scim_oauth.legacy_bearer_token(), "scim-token")

    def test_env_still_wins_in_consumers(self):
        import servicenow
        importlib.reload(servicenow)
        self.api_keys.set_key("SERVICENOW_PASSWORD", "from-db", db=self.db)
        os.environ["SERVICENOW_PASSWORD"] = "from-env"
        self.assertEqual(servicenow._managed_secret("SERVICENOW_PASSWORD"), "from-env")

    # --- status output ---

    def test_credential_status_is_grouped_and_leak_free(self):
        self.api_keys.set_key("SERVICENOW_PASSWORD", "leak-canary-7777", db=self.db)
        groups = self.api_keys.credential_status(db=self.db)
        names = [g["group"] for g in groups]
        self.assertIn("ServiceNow", names)
        self.assertIn("Rapid7", names)
        self.assertNotIn("leak-canary-7777", str(groups))

    def test_credentials_absent_from_settings_surface(self):
        self.api_keys.set_key("SERVICENOW_PASSWORD", "leak-canary-6666", db=self.db)
        from settings.store import SettingsStore
        store = SettingsStore(db_module=self.db)
        self.assertNotIn("leak-canary-6666", str(store.merged(force_reload=True)))
        self.assertNotIn("leak-canary-6666", str(store.public_snapshot()))
        self.assertNotIn("leak-canary-6666", str(store.admin_form_schema()))


if __name__ == "__main__":
    unittest.main()
