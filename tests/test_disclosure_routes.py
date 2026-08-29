"""What the disclosure endpoints publish, and what they must never publish.

The load-bearing test here is the one that scans the whole database for a
private key block after a generation. Everything else can be right while that
one thing is wrong, and that one thing is the entire reason the feature was
built this way.
"""

import os
import sqlite3
import tempfile
import unittest
from unittest import mock

PUBLIC_BLOCK = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
PRIVATE_BLOCK = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

FAKE_PUBLIC = f"{PUBLIC_BLOCK}\n\nmDMEZfakepublic\n-----END PGP PUBLIC KEY BLOCK-----\n"
FAKE_PRIVATE = f"{PRIVATE_BLOCK}\n\nlFgEZfakeprivate\n-----END PGP PRIVATE KEY BLOCK-----\n"

FAKE_RESULT = {
    "fingerprint": "E6C99E9092A9B99A8BB76C0817A06D29D4C90D3C",
    "uid": "DomainLens Security <security@example.com>",
    "public_key": FAKE_PUBLIC,
    "private_key": FAKE_PRIVATE,
    "expiry": "2y",
    "protected": False,
}


class DisclosureRouteTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tempdir.name, "disclosure.db")
        os.environ["DOMAINLENS_DB"] = self.db_path
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
        self.store = get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "AUTH_LOCAL_ENABLED", "OAUTH_ENABLED", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)
        self.tempdir.cleanup()

    def _configure(self, **overrides):
        patch = {"enabled": True, "contact": "security@example.com",
                 "expires_days": 30}
        patch.update(overrides)
        self.app_module._settings_store.update_section(
            "disclosure", patch, user_id=None)

    def _database_text(self):
        """Everything stored, as one blob. Crude on purpose: it does not care
        which column a secret leaked into."""
        conn = sqlite3.connect(self.db_path)
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            chunks = []
            for table in tables:
                for row in conn.execute(f"SELECT * FROM [{table}]"):
                    chunks.append(" ".join(str(v) for v in row))
            return "\n".join(chunks)
        finally:
            conn.close()

    # --- the promise -----------------------------------------------------

    def test_the_private_key_is_returned_exactly_once(self):
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=True), \
             mock.patch.object(self.app_module.pgp_keys, "generate",
                               return_value=dict(FAKE_RESULT)):
            resp = self.client.post("/api/admin/pgp/generate", json={
                "name": "DomainLens Security", "email": "security@example.com"})
        self.assertEqual(201, resp.status_code)
        self.assertIn(PRIVATE_BLOCK, resp.get_json()["private_key"])

        # Asking again returns status, never the secret.
        status = self.client.get("/api/admin/pgp/status").get_json()
        self.assertNotIn("private_key", status)
        self.assertEqual(FAKE_RESULT["fingerprint"], status["fingerprint"])

    def test_no_private_key_reaches_the_database(self):
        """The load-bearing test. If this fails, a stolen backup hands over
        the key to every disclosure the operator ever received."""
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=True), \
             mock.patch.object(self.app_module.pgp_keys, "generate",
                               return_value=dict(FAKE_RESULT)):
            self.client.post("/api/admin/pgp/generate", json={
                "name": "DomainLens Security", "email": "security@example.com"})
        stored = self._database_text()
        self.assertIn(PUBLIC_BLOCK, stored, "the public key was not stored at all")
        self.assertNotIn(PRIVATE_BLOCK, stored)
        self.assertNotIn("lFgEZfakeprivate", stored)

    def test_settings_refuse_a_private_key_however_it_arrives(self):
        """The generate route is not the only way in: the admin settings API
        patches the same section."""
        with self.assertRaises(ValueError):
            self.app_module._settings_store.update_section(
                "disclosure", {"pgp_public_key": FAKE_PRIVATE}, user_id=None)

    def test_the_key_endpoint_refuses_to_serve_a_private_block(self):
        """Belt and braces for a key that somehow got past the guard above."""
        self._configure()
        with mock.patch.object(self.app_module, "_disclosure_config",
                               return_value={"pgp_public_key": FAKE_PRIVATE}):
            resp = self.client.get("/.well-known/pgp-key.asc")
        self.assertEqual(500, resp.status_code)
        self.assertNotIn(PRIVATE_BLOCK, resp.get_data(as_text=True))

    # --- publishing ------------------------------------------------------

    def test_security_txt_is_404_until_it_is_configured(self):
        resp = self.client.get("/.well-known/security.txt")
        self.assertEqual(404, resp.status_code)

    def test_security_txt_is_served_as_plain_text(self):
        self._configure()
        resp = self.client.get("/.well-known/security.txt")
        self.assertEqual(200, resp.status_code)
        self.assertEqual("text/plain", resp.mimetype)
        # Flask adds the charset; spelling it out in the mimetype too gave
        # "text/plain; charset=utf-8; charset=utf-8".
        self.assertEqual(1, resp.headers["Content-Type"].count("charset="))
        body = resp.get_data(as_text=True)
        self.assertIn("Contact: mailto:security@example.com", body)
        self.assertIn("Expires:", body)

    def test_security_txt_offers_the_key_once_one_exists(self):
        self._configure(pgp_public_key=FAKE_PUBLIC)
        body = self.client.get("/.well-known/security.txt").get_data(as_text=True)
        self.assertIn("Encryption:", body)
        self.assertIn("/.well-known/pgp-key.asc", body)

    def test_the_public_key_is_served_with_its_own_media_type(self):
        self._configure(pgp_public_key=FAKE_PUBLIC)
        resp = self.client.get("/.well-known/pgp-key.asc")
        self.assertEqual(200, resp.status_code)
        self.assertEqual("application/pgp-keys", resp.mimetype)
        self.assertIn(PUBLIC_BLOCK, resp.get_data(as_text=True))

    def test_the_key_endpoint_is_404_when_no_key_is_configured(self):
        self._configure()
        self.assertEqual(404, self.client.get("/.well-known/pgp-key.asc").status_code)

    def test_both_files_are_reachable_without_signing_in(self):
        """RFC 9116: a researcher who has to log in to find out how to report
        a bug does not report it."""
        self.assertTrue(self.auth._public_path("/.well-known/security.txt"))
        self.assertTrue(self.auth._public_path("/.well-known/pgp-key.asc"))

    # --- generation endpoint ---------------------------------------------

    def test_a_missing_gpg_is_reported_as_such(self):
        """Not a 500: the operator can install a package, but only if they
        are told that is what is wrong."""
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=False):
            resp = self.client.post("/api/admin/pgp/generate", json={
                "name": "Security", "email": "a@example.com"})
        self.assertEqual(503, resp.status_code)
        self.assertIn("gpg", resp.get_json()["error"])

    def test_bad_input_is_a_400_not_a_502(self):
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=True):
            resp = self.client.post("/api/admin/pgp/generate", json={
                "name": "Security", "email": "nope"})
        self.assertEqual(400, resp.status_code)

    def test_a_gpg_failure_is_a_502(self):
        import pgp_keys
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=True), \
             mock.patch.object(self.app_module.pgp_keys, "generate",
                               side_effect=pgp_keys.PgpError("gpg exploded")):
            resp = self.client.post("/api/admin/pgp/generate", json={
                "name": "Security", "email": "a@example.com"})
        self.assertEqual(502, resp.status_code)

    def test_generation_stores_the_public_half_and_the_fingerprint(self):
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=True), \
             mock.patch.object(self.app_module.pgp_keys, "generate",
                               return_value=dict(FAKE_RESULT)):
            self.client.post("/api/admin/pgp/generate", json={
                "name": "DomainLens Security", "email": "security@example.com"})
        section = self.app_module._settings_store.section("disclosure",
                                                          force_reload=True)
        self.assertEqual(FAKE_RESULT["fingerprint"], section["pgp_fingerprint"])
        self.assertEqual(FAKE_RESULT["uid"], section["pgp_uid"])
        self.assertIn(PUBLIC_BLOCK, section["pgp_public_key"])
        self.assertTrue(section["pgp_generated_at"])

    def test_the_response_warns_that_this_is_the_only_copy(self):
        """The operator has one chance to save it. Saying so is part of the
        feature, not decoration."""
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=True), \
             mock.patch.object(self.app_module.pgp_keys, "generate",
                               return_value=dict(FAKE_RESULT)):
            body = self.client.post("/api/admin/pgp/generate", json={
                "name": "DomainLens Security", "email": "security@example.com"}).get_json()
        self.assertIn("only copy", body["warning"].lower())


if __name__ == "__main__":
    unittest.main()
