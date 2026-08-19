import importlib
import os
import tempfile
import unittest


class ApiKeyStoreTests(unittest.TestCase):
    """The three optional OSINT keys are UI-manageable. They are read-only,
    low-privilege enrichment keys, so the usability win is worth it — but only
    if they cannot leak back out through the settings surface.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "test.db")
        os.environ["DOMAINLENS_SECRET_KEY"] = "unit-test-secret-key"
        for env in ("SPAMHAUS_DQS_KEY", "ABUSECH_AUTH_KEY", "OTX_API_KEY"):
            os.environ.pop(env, None)

        import db as db_module
        importlib.reload(db_module)
        self.db = db_module
        self.db.init_db()

        from settings import api_keys
        self.api_keys = api_keys

    def tearDown(self):
        self.tempdir.cleanup()
        for env in ("DOMAINLENS_DB", "DOMAINLENS_SECRET_KEY",
                    "SPAMHAUS_DQS_KEY", "ABUSECH_AUTH_KEY", "OTX_API_KEY"):
            os.environ.pop(env, None)

    # --- round trip ---

    def test_set_and_resolve(self):
        self.api_keys.set_key("OTX_API_KEY", "super-secret-value", db=self.db)
        self.assertEqual(self.api_keys.resolve("OTX_API_KEY", db=self.db), "super-secret-value")

    def test_clear_key(self):
        self.api_keys.set_key("OTX_API_KEY", "abc", db=self.db)
        self.api_keys.clear_key("OTX_API_KEY", db=self.db)
        self.assertEqual(self.api_keys.resolve("OTX_API_KEY", db=self.db), "")

    def test_unknown_key_rejected(self):
        # Integration credentials are managed too now, but anything outside
        # the catalogue must still be refused — the admin API must never be
        # pointable at an arbitrary environment variable.
        for env in ("DOMAINLENS_SECRET_KEY", "DOMAINLENS_DB", "PATH", "MADE_UP_KEY"):
            with self.assertRaises(ValueError, msg=env):
                self.api_keys.set_key(env, "nope", db=self.db)

    def test_empty_value_rejected(self):
        with self.assertRaises(ValueError):
            self.api_keys.set_key("OTX_API_KEY", "   ", db=self.db)

    # --- environment precedence ---

    def test_environment_wins_over_stored_value(self):
        self.api_keys.set_key("OTX_API_KEY", "from-database", db=self.db)
        os.environ["OTX_API_KEY"] = "from-environment"
        self.assertEqual(self.api_keys.resolve("OTX_API_KEY", db=self.db), "from-environment")
        self.assertTrue(self.api_keys.is_env_locked("OTX_API_KEY"))

    def test_env_locked_key_is_not_editable_in_status(self):
        os.environ["ABUSECH_AUTH_KEY"] = "env-value"
        row = next(r for r in self.api_keys.status(db=self.db) if r["env"] == "ABUSECH_AUTH_KEY")
        self.assertFalse(row["editable"])
        self.assertEqual(row["source"], "environment")

    # --- at rest ---

    def test_value_is_not_stored_in_plaintext(self):
        secret = "plaintext-canary-value"
        self.api_keys.set_key("OTX_API_KEY", secret, db=self.db)
        raw = self.db.get_setting_section("api_keys")
        blob = str(raw)
        self.assertNotIn(secret, blob)
        self.assertRegex(blob, r"enc:v\d+:")

    def test_wrong_secret_key_does_not_crash(self):
        self.api_keys.set_key("OTX_API_KEY", "abc", db=self.db)
        os.environ["DOMAINLENS_SECRET_KEY"] = "a-different-key"
        # Unrecoverable, but an optional enrichment key must not break a scan.
        self.assertEqual(self.api_keys.resolve("OTX_API_KEY", db=self.db), "")

    def test_protection_state_is_honest_without_secret_key(self):
        self.assertEqual(self.api_keys.protection_state(db=self.db)["mode"], "encrypted")
        os.environ.pop("DOMAINLENS_SECRET_KEY")
        state = self.api_keys.protection_state(db=self.db)
        self.assertEqual(state["mode"], "obfuscated")
        self.assertIn("DOMAINLENS_SECRET_KEY", state["detail"])

    # --- no leakage through the settings surface ---

    def test_status_never_contains_the_value(self):
        self.api_keys.set_key("OTX_API_KEY", "top-secret-1234", db=self.db)
        blob = str(self.api_keys.status(db=self.db))
        self.assertNotIn("top-secret-1234", blob)

    def test_mask_reveals_only_last_four(self):
        self.api_keys.set_key("OTX_API_KEY", "abcdefghijkl3f2a", db=self.db)
        row = next(r for r in self.api_keys.status(db=self.db) if r["env"] == "OTX_API_KEY")
        self.assertTrue(row["hint"].endswith("3f2a"))
        self.assertNotIn("abcdefgh", row["hint"])

    def test_keys_are_absent_from_merged_settings_and_snapshot(self):
        self.api_keys.set_key("OTX_API_KEY", "leak-canary-9999", db=self.db)
        from settings.store import SettingsStore
        store = SettingsStore(db_module=self.db)
        merged = store.merged(force_reload=True)
        self.assertNotIn("api_keys", merged)
        self.assertNotIn("leak-canary-9999", str(merged))
        self.assertNotIn("leak-canary-9999", str(store.public_snapshot()))

    def test_keys_are_absent_from_admin_form_schema(self):
        self.api_keys.set_key("OTX_API_KEY", "leak-canary-8888", db=self.db)
        from settings.store import SettingsStore
        store = SettingsStore(db_module=self.db)
        self.assertNotIn("leak-canary-8888", str(store.admin_form_schema()))

    def test_stored_key_marks_integration_configured(self):
        from settings.store import SettingsStore
        self.api_keys.set_key("ABUSECH_AUTH_KEY", "abc123", db=self.db)
        store = SettingsStore(db_module=self.db)
        flags = store.merged(force_reload=True)["integrations"]
        self.assertTrue(flags["abusech_configured"])



class KeyDerivationTests(unittest.TestCase):
    """v1 derived the Fernet key with a bare SHA-256 of DOMAINLENS_SECRET_KEY.
    If that secret is a weak passphrase, SHA-256 is cheap to brute force and
    one cracked secret applies to every install using it. v2 uses scrypt with
    a per-install random salt.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "kdf.db")
        os.environ["DOMAINLENS_SECRET_KEY"] = "unit-test-secret-key"
        for env in ("SPAMHAUS_DQS_KEY", "ABUSECH_AUTH_KEY", "OTX_API_KEY"):
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
        for env in ("DOMAINLENS_DB", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(env, None)

    def test_new_writes_use_v2(self):
        self.api_keys.set_key("OTX_API_KEY", "abc", db=self.db)
        raw = self.db.get_setting_section("api_keys")["otx_api_key"]
        self.assertTrue(raw.startswith("enc:v2:"))

    def test_v1_values_still_decrypt(self):
        # Simulate a value written by the previous build.
        legacy = self.api_keys._ENC_PREFIX_V1 + self.api_keys._fernet(
            self.db, version=1).encrypt(b"legacy-value").decode("ascii")
        self.db.set_setting_section("api_keys", {"otx_api_key": legacy})
        self.assertEqual(self.api_keys.resolve("OTX_API_KEY", db=self.db), "legacy-value")

    def test_salt_is_persistent(self):
        self.api_keys.set_key("OTX_API_KEY", "abc", db=self.db)
        salt1 = self.db.get_setting_section("_api_key_salt")["salt"]
        self.api_keys._fernet_cache.clear()
        self.assertEqual(self.api_keys.resolve("OTX_API_KEY", db=self.db), "abc")
        salt2 = self.db.get_setting_section("_api_key_salt")["salt"]
        self.assertEqual(salt1, salt2)

    def test_same_secret_different_salt_gives_different_ciphertext(self):
        self.api_keys.set_key("OTX_API_KEY", "same-value", db=self.db)
        first = self.db.get_setting_section("api_keys")["otx_api_key"]

        # A second installation: same DOMAINLENS_SECRET_KEY, fresh database.
        with tempfile.TemporaryDirectory() as other:
            os.environ["DOMAINLENS_DB"] = os.path.join(other, "other.db")
            import db as db2
            importlib.reload(db2)
            db2.init_db()
            self.api_keys._fernet_cache.clear()
            self.api_keys.set_key("OTX_API_KEY", "same-value", db=db2)
            second = db2.get_setting_section("api_keys")["otx_api_key"]
            self.assertNotEqual(first, second)
            # And each install can only read its own.
            self.assertEqual(self.api_keys.resolve("OTX_API_KEY", db=db2), "same-value")

    def test_derivation_is_cached(self):
        self.api_keys.set_key("OTX_API_KEY", "abc", db=self.db)
        import time
        start = time.time()
        for _ in range(20):
            self.api_keys.resolve("OTX_API_KEY", db=self.db)
        elapsed = time.time() - start
        # 20 uncached scrypt derivations would take ~2s; caching keeps it well under.
        self.assertLess(elapsed, 1.0)
if __name__ == "__main__":
    unittest.main()
