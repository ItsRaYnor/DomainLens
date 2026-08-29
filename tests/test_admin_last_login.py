"""The admin user list showed role, status and MFA but never said when an
account was last used, so a dormant account was indistinguishable from a
busy one and there was nothing to audit against.

The value already existed: every sign-in path writes users.last_login_at.
Only the column was missing.
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone


class LastLoginFormattingTests(unittest.TestCase):
    """Three states, kept apart: a known sign-in, never signed in, and a
    record that cannot be read. Collapsing the third into "Never" would
    invent a fact about the person out of a fault in the row -- and it is
    the reading an admin acts on when clearing out dormant accounts.
    """

    def setUp(self):
        # ignore_cleanup_errors: sqlite3's `with conn` commits but does not
        # close, so Windows still holds the file when the dir is removed.
        # That is a harness artefact, not something under test here.
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "ll.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        import importlib
        import db
        import app
        from settings.store import get_store
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.last_login = self.app_module._format_last_login
        self.time_ago = self.app_module._format_time_ago

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    def test_a_stored_sign_in_is_shown_in_utc(self):
        self.assertEqual("2026-08-20 14:30 UTC",
                         self.last_login("2026-08-20T14:30:00+00:00"))

    def test_an_offset_is_converted_rather_than_dropped(self):
        """Reading the wall clock off the string would report 16:30 for a
        sign-in that happened at 14:30 UTC."""
        self.assertEqual("2026-08-20 14:30 UTC",
                         self.last_login("2026-08-20T16:30:00+02:00"))

    def test_a_trailing_z_is_understood(self):
        self.assertEqual("2026-08-20 14:30 UTC",
                         self.last_login("2026-08-20T14:30:00Z"))

    def test_never_signed_in_says_so(self):
        for empty in (None, ""):
            with self.subTest(value=empty):
                self.assertEqual("Never", self.last_login(empty))

    def test_an_unreadable_record_is_not_laundered_into_never(self):
        """The one that matters: "Never" here would read as a fact about the
        account and get it disabled, when what is broken is the row."""
        for broken in ("not-a-date", "2026-13-45T99:99", "0"):
            with self.subTest(value=broken):
                rendered = self.last_login(broken)
                self.assertNotEqual("Never", rendered)
                self.assertIn("Unreadable", rendered)
                self.assertIn(broken, rendered)

    def test_a_naive_timestamp_is_read_as_utc(self):
        """Older rows were written without an offset; guessing local time
        would shift them by the host's zone."""
        self.assertEqual("2026-08-20 14:30 UTC",
                         self.last_login("2026-08-20T14:30:00"))

    def test_the_relative_age_is_stated_for_a_real_timestamp(self):
        stamp = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        self.assertEqual("3 days ago", self.time_ago(stamp))

    def test_the_relative_age_is_silent_when_there_is_no_age(self):
        """An empty caption beats a wrong one: the column above already
        states what is known."""
        for value in (None, "", "not-a-date"):
            with self.subTest(value=value):
                self.assertEqual("", self.time_ago(value))

    def test_a_future_timestamp_gets_no_caption(self):
        """Clock skew between a container and its host writes these. "in 3
        days" is noise and "just now" is false."""
        ahead = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
        self.assertEqual("", self.time_ago(ahead))

    def test_singular_and_plural_agree_with_the_count(self):
        one_day = (datetime.now(timezone.utc) - timedelta(days=1, hours=1)).isoformat()
        self.assertEqual("1 day ago", self.time_ago(one_day))


class AdminUserListShowsLastLoginTests(unittest.TestCase):
    """The column has to reach the page, not just the filter."""

    def setUp(self):
        # ignore_cleanup_errors: sqlite3's `with conn` commits but does not
        # close, so Windows still holds the file when the dir is removed.
        # That is a harness artefact, not something under test here.
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "llp.db")
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
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "AUTH_LOCAL_ENABLED", "OAUTH_ENABLED", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    def _add_user(self, email, last_login_at=None):
        user_id = self.db.create_user(
            email=email, password_hash="x", name=email.split("@")[0],
            role="user", enabled=True,
        )
        if last_login_at is not None:
            self.db.update_user(user_id, last_login_at=last_login_at)
        return user_id

    def test_the_column_is_on_the_page(self):
        self._add_user("someone@example.com")
        body = self.client.get("/admin/users").data.decode()
        self.assertIn("Last login", body)

    def test_every_row_has_a_cell_for_every_header(self):
        """Adding the column by replacing the MFA cell shifted every value
        after Status one place left, so MFA's "off" was read as the sign-in
        time. Counting is the only check that catches that."""
        import re
        self._add_user("someone@example.com")
        body = self.client.get("/admin/users").data.decode()
        table = body[body.index('class="users-table"'):]
        headers = len(re.findall(r"<th", table[:table.index("</thead>")]))
        first_row = table[table.index("<tbody>"):table.index("</tr>", table.index("<tbody>"))]
        self.assertEqual(headers, len(re.findall(r"<td", first_row)))

    def test_a_users_sign_in_time_is_rendered(self):
        self._add_user("active@example.com", "2026-08-20T14:30:00+00:00")
        body = self.client.get("/admin/users").data.decode()
        self.assertIn("2026-08-20 14:30 UTC", body)

    def test_an_account_that_never_signed_in_says_never(self):
        """Not a blank cell: dormant accounts are the reason to look."""
        self._add_user("dormant@example.com")
        body = self.client.get("/admin/users").data.decode()
        self.assertIn("Never", body)

    def test_the_stored_value_survives_list_users(self):
        """The template can only show what the query selects."""
        self._add_user("active@example.com", "2026-08-20T14:30:00+00:00")
        rows = [u for u in self.db.list_users()
                if u["email"] == "active@example.com"]
        self.assertEqual(1, len(rows))
        self.assertEqual("2026-08-20T14:30:00+00:00", rows[0]["last_login_at"])


if __name__ == "__main__":
    unittest.main()
