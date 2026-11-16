import importlib
import os
import tempfile
import unittest

EXAMPLE = "change-me-openssl-rand-hex-32"


class PublishedExampleKeyTests(unittest.TestCase):
    """The compose files ship DOMAINLENS_SECRET_KEY as "change-me-...". An
    installation started from them unchanged signed its session cookies and
    SCIM tokens with a value anyone can read on GitHub: forge a cookie naming
    an admin, or a SCIM token, and you are in.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "secret.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import db as db_module
        importlib.reload(db_module).init_db()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "DOMAINLENS_SECRET_KEY", "SCIM_TOKEN_SIGNING_KEY"):
            os.environ.pop(key, None)

    def _app(self, key):
        if key is None:
            os.environ.pop("DOMAINLENS_SECRET_KEY", None)
        else:
            os.environ["DOMAINLENS_SECRET_KEY"] = key
        import app as app_module
        return importlib.reload(app_module)

    def test_session_cookies_are_not_signed_with_the_documented_example(self):
        module = self._app(EXAMPLE)
        self.assertNotEqual(module.app.secret_key, EXAMPLE)
        self.assertGreaterEqual(len(module.app.secret_key), 32)

    def test_the_other_documented_example_is_refused_too(self):
        module = self._app("long-random-string")
        self.assertNotEqual(module.app.secret_key, "long-random-string")

    def test_scim_tokens_are_not_signed_with_the_documented_example(self):
        os.environ["DOMAINLENS_SECRET_KEY"] = EXAMPLE
        import scim_oauth
        self.assertNotEqual(scim_oauth._signing_key(), EXAMPLE)

    def test_an_example_scim_key_does_not_fall_through_to_another_example(self):
        os.environ["SCIM_TOKEN_SIGNING_KEY"] = "long-random-string"
        os.environ["DOMAINLENS_SECRET_KEY"] = EXAMPLE
        import scim_oauth
        self.assertNotIn(scim_oauth._signing_key(), {EXAMPLE, "long-random-string"})

    def test_an_operators_own_key_is_still_used(self):
        own = "9f1c2e7a4b6d8e0f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f"
        module = self._app(own)
        self.assertEqual(module.app.secret_key, own)
        import scim_oauth
        self.assertEqual(scim_oauth._signing_key(), own)

    def test_stored_credentials_stay_readable_and_the_page_says_the_key_is_public(self):
        # Switching the encryption key would lose every stored credential, so
        # encryption keeps the example key -- but must not be called protected.
        os.environ["DOMAINLENS_SECRET_KEY"] = EXAMPLE
        from settings import api_keys
        self.assertEqual(api_keys._key_material(), EXAMPLE)
        self.assertEqual(api_keys.protection_state()["mode"], "public")


if __name__ == "__main__":
    unittest.main()
