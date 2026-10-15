"""Replacing an authenticator that is lost or may be compromised.

There was no way to replace one: MFA had to be turned off first, which a
policy that requires MFA forbids. And starting a new setup on an account
that already had an authenticator asked for nothing -- a session someone
else had got hold of could put their own phone in its place with two posts.

Now replacing asks for the password and a current code (or a backup code),
keeps the old authenticator working until the new one is confirmed, then
retires the old secret and backup codes and signs out every other session.
An administrator can reset MFA for someone who has lost both.
"""

import time
from unittest import mock

from enterprise_harness import EnterpriseAppTestCase

PASSWORD = "Str0ng-Local-Pass!"


class ReplaceTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.secret = self.auth.generate_totp_secret()
        self.backup = ["aaaa1111", "bbbb2222"]
        self.uid = self.users["user"]
        self.db.update_user(self.uid, mfa_enabled=True, mfa_secret=self.secret,
                            mfa_backup_codes=self.auth.hash_backup_codes(self.backup))

    def _row(self):
        return self.db.get_user(self.uid, include_secrets=True)

    def _setup_secret(self, client=None):
        with (client or self.client).session_transaction() as sess:
            return sess.get(self.auth.SESSION_MFA_SETUP_SECRET)

    def _replace(self, code, password=PASSWORD):
        return self.client.post("/account/mfa/replace", data={"password": password, "code": code})

    def test_starting_over_with_an_authenticator_in_place_is_refused(self):
        self.login_as("user")
        self.client.post("/account/mfa/start")
        self.assertIsNone(self._setup_secret())
        # Even with a setup secret in the session, confirming needs the proof.
        attacker = self.auth.generate_totp_secret()
        with self.client.session_transaction() as sess:
            sess[self.auth.SESSION_MFA_SETUP_SECRET] = attacker
        self.client.post("/account/mfa/confirm", data={"code": self.auth.totp_at(attacker)})
        self.assertEqual(self.secret, self._row()["mfa_secret"])

    def test_replacing_needs_the_password_and_a_current_code(self):
        self.login_as("user")
        self._replace(self.auth.totp_at(self.secret), password="wrong")
        self.assertIsNone(self._setup_secret())
        self._replace("000000")
        self.assertIsNone(self._setup_secret())
        self._replace(self.auth.totp_at(self.secret))
        self.assertIsNotNone(self._setup_secret())

    def test_the_new_authenticator_takes_over_and_the_old_codes_retire(self):
        self.login_as("user")
        self._replace(self.auth.totp_at(self.secret))
        new = self._setup_secret()
        # Until the new one is confirmed, the old one still works.
        self.assertEqual(self.secret, self._row()["mfa_secret"])
        resp = self.client.post("/account/mfa/confirm", data={"code": self.auth.totp_at(new)})
        self.assertIn("mfa_replaced", resp.headers["Location"])
        row = self._row()
        self.assertEqual(new, row["mfa_secret"])
        self.assertFalse(self.auth.consume_backup_code(row, self.backup[0]))

    def test_a_backup_code_can_start_it_and_is_used_up(self):
        self.login_as("user")
        self._replace(self.backup[1])
        self.assertIsNotNone(self._setup_secret())
        self.assertFalse(self.auth.consume_backup_code(self._row(), self.backup[1]))

    def test_every_other_session_ends_and_this_one_stays(self):
        other = self.app_module.app.test_client()
        self.login_as("user", client=other)
        self.login_as("user")
        self._replace(self.auth.totp_at(self.secret))
        self.client.post("/account/mfa/confirm", data={"code": self.auth.totp_at(self._setup_secret())})
        self.assertEqual(200, self.client.get("/account").status_code)
        self.assertIn("/login", other.get("/account").headers.get("Location", ""))

    def test_the_proof_does_not_last_the_whole_session(self):
        self.login_as("user")
        self._replace(self.auth.totp_at(self.secret))
        new = self._setup_secret()
        later = time.time() + self.app_module._MFA_REPLACE_WINDOW + 5
        with mock.patch.object(self.app_module.time, "time", return_value=later):
            self.client.post("/account/mfa/confirm", data={"code": self.auth.totp_at(new, later)})
        self.assertEqual(self.secret, self._row()["mfa_secret"])


class AdminResetTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.uid = self.users["user"]
        self.db.update_user(self.uid, mfa_enabled=True, mfa_secret=self.auth.generate_totp_secret())

    def test_an_admin_resets_mfa_and_the_user_is_signed_out(self):
        victim = self.app_module.app.test_client()
        self.login_as("user", client=victim)
        self.login_as("admin")
        self.client.post(f"/admin/users/{self.uid}/reset-mfa")
        row = self.db.get_user(self.uid, include_secrets=True)
        self.assertEqual((False, None), (row["mfa_enabled"], row["mfa_secret"]))
        self.assertIn("/login", victim.get("/account").headers.get("Location", ""))

    def test_an_admin_does_not_reset_their_own_this_way(self):
        admin = self.users["admin"]
        self.db.update_user(admin, mfa_enabled=True, mfa_secret=self.auth.generate_totp_secret())
        self.login_as("admin")
        self.client.post(f"/admin/users/{admin}/reset-mfa")
        self.assertTrue(self.db.get_user(admin)["mfa_enabled"])

    def test_only_an_admin_can_reset(self):
        self.login_as("user")
        self.client.post(f"/admin/users/{self.users['viewer']}/reset-mfa")
        self.login_as("viewer")
        resp = self.client.post(f"/admin/users/{self.uid}/reset-mfa")
        self.assertIn(resp.status_code, (302, 403))
        self.assertTrue(self.db.get_user(self.uid)["mfa_enabled"])
