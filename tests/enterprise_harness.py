"""A fresh app with local accounts and login required, for role-aware tests.

Every test module that checks who may do what needs the same setup: a
throwaway database, local auth switched on and required, and accounts of each
role to sign in as. Kept in one place so those tests differ only in what they
assert.
"""

import importlib
import os
import tempfile
import unittest

_ENV = {
    "DOMAINLENS_DISABLE_SCHEDULER": "1",
    "OAUTH_ENABLED": "0",
    "AUTH_LOCAL_ENABLED": "1",
    "AUTH_REQUIRE_LOGIN": "1",
    "DOMAINLENS_SECRET_KEY": "test-secret",
}


class EnterpriseAppTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._saved_env = {k: os.environ.get(k) for k in [*_ENV, "DOMAINLENS_DB",
                                                          "LOCAL_ADMIN_EMAIL",
                                                          "LOCAL_ADMIN_PASSWORD"]}
        os.environ.update(_ENV)
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "enterprise.db")
        os.environ.pop("LOCAL_ADMIN_EMAIL", None)
        os.environ.pop("LOCAL_ADMIN_PASSWORD", None)

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
        self.users = {
            role: self.db.create_user(
                email=f"{role}@example.com",
                password_hash=self.auth.hash_password("Str0ng-Local-Pass!"),
                name=role,
                role=role,
                enabled=True,
                provider="local",
            )
            for role in ("viewer", "user", "admin")
        }

    def tearDown(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def login_as(self, role, client=None):
        client = client or self.client
        row = self.db.get_user(self.users[role])
        with client.session_transaction() as sess:
            sess[self.auth.SESSION_USER_KEY] = {
                "id": row["id"],
                "email": row["email"],
                "role": row["role"],
                "provider": "local",
            }
        return row
