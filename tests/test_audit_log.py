"""Who did what, recorded where it cannot be quietly rewritten.

Nothing recorded a deleted scan, a changed setting, a failed login or a
scan that asked for active probes. After an incident, "who pointed login
attempts at that domain" had no answer, and an ISO 27001 or NIS2 auditor
asking for access and change logging got none.
"""

import csv
import io
import sqlite3
import unittest
from unittest import mock

from enterprise_harness import EnterpriseAppTestCase


class RecordedActionsTests(EnterpriseAppTestCase):
    def _actions(self):
        import audit_log
        return [e["action"] for e in audit_log.list_entries(limit=500)["entries"]]

    def test_a_failed_login_is_recorded_with_the_attempted_email(self):
        """Password spraying shows up here first, or nowhere."""
        import audit_log
        self.client.post("/auth/local/login",
                         data={"email": "viewer@example.com", "password": "wrong"})
        entry = audit_log.list_entries(action="auth.login")["entries"][0]
        self.assertEqual("failure", entry["outcome"])
        self.assertEqual("viewer@example.com", entry["actor_email"])

    def test_a_successful_login_is_recorded(self):
        self.client.post("/auth/local/login",
                         data={"email": "user@example.com", "password": "Str0ng-Local-Pass!"})
        self.assertIn("auth.login", self._actions())

    def test_a_scan_records_which_active_checks_were_asked_for(self):
        import audit_log
        self.login_as("user")
        with mock.patch.object(self.app_module.scan_jobs, "start", return_value={"job_id": "x"}):
            self.client.post("/api/scan/start",
                             json={"domain": "example.com", "checks": ["ssl", "weak_auth"]})
        entry = audit_log.list_entries(action="scan.start")["entries"][0]
        self.assertEqual("example.com", entry["target_id"])
        self.assertEqual(["weak_auth"], entry["details"]["active_checks_requested"])
        self.assertEqual("user@example.com", entry["actor_email"])

    def test_clearing_history_is_recorded(self):
        self.login_as("admin")
        self.client.delete("/api/history")
        self.assertIn("history.clear", self._actions())

    def test_a_viewer_refused_a_write_leaves_a_trace(self):
        import audit_log
        self.login_as("viewer")
        self.client.post("/api/scan/start", json={"domain": "example.com"})
        entry = audit_log.list_entries(action="access.denied")["entries"][0]
        self.assertEqual("denied", entry["outcome"])
        self.assertEqual("viewer@example.com", entry["actor_email"])

    def test_a_role_change_records_before_and_after(self):
        import audit_log
        self.login_as("admin")
        self.client.post(f"/admin/users/{self.users['viewer']}/role", data={"role": "user"})
        entry = audit_log.list_entries(action="user.role_change")["entries"][0]
        self.assertEqual({"from": "viewer", "to": "user"}, entry["details"])

    def test_a_settings_change_records_keys_but_never_values(self):
        """weak_auth.passwords is a setting; its values must not land in a
        log that is exported to spreadsheets."""
        import audit_log
        self.login_as("admin")
        self.client.patch("/api/admin/settings/weak_auth",
                          json={"passwords": ["hunter2-secret"]})
        entries = audit_log.list_entries(action="settings.update")["entries"]
        self.assertTrue(entries)
        self.assertNotIn("hunter2-secret", str(entries))

    def test_a_scim_change_is_attributed_to_the_directory(self):
        import audit_log
        import scim
        scim._audit("scim.user_disable", {"email": "gone@example.com"})
        entry = audit_log.list_entries(action="scim.")["entries"][0]
        self.assertEqual("scim", entry["auth_method"])
        self.assertEqual("scim-directory", entry["actor_email"])


class AuditAccessTests(EnterpriseAppTestCase):
    def test_only_admins_read_the_log(self):
        self.login_as("user")
        self.assertEqual(403, self.client.get("/api/admin/audit").status_code)

    def test_the_admin_page_renders(self):
        self.login_as("admin")
        resp = self.client.get("/admin/audit")
        self.assertEqual(200, resp.status_code)
        self.assertIn(b"audit-table", resp.data)

    def test_csv_export_defuses_spreadsheet_formulas(self):
        """The attempted email on a failed login is attacker-chosen text."""
        self.client.post("/auth/local/login",
                         data={"email": "=HYPERLINK(\"http://x\")", "password": "x"})
        self.login_as("admin")
        body = self.client.get("/api/admin/audit.csv").get_data(as_text=True)
        cells = [c for row in csv.reader(io.StringIO(body)) for c in row]
        self.assertFalse(any(c.startswith("=") for c in cells))


class HashChainTests(EnterpriseAppTestCase):
    def _raw(self, sql, *params):
        conn = sqlite3.connect(self.db._db_path())
        with conn:
            conn.execute(sql, params)
        conn.close()

    def test_an_untouched_log_verifies(self):
        import audit_log
        for i in range(3):
            audit_log.record("test.entry", details={"i": i})
        self.assertTrue(audit_log.verify()["intact"])

    def test_editing_a_row_is_detected(self):
        import audit_log
        first = audit_log.record("test.entry", details={"i": 1})
        audit_log.record("test.entry", details={"i": 2})
        self._raw("UPDATE audit_log SET actor_email='someone-else' WHERE id=?", first)
        result = audit_log.verify()
        self.assertFalse(result["intact"])
        self.assertEqual(first, result["broken_at"])

    def test_deleting_a_row_from_the_middle_is_detected(self):
        import audit_log
        audit_log.record("test.entry")
        middle = audit_log.record("test.entry")
        last = audit_log.record("test.entry")
        self._raw("DELETE FROM audit_log WHERE id=?", middle)
        result = audit_log.verify()
        self.assertFalse(result["intact"])
        self.assertEqual(last, result["broken_at"])

    def test_a_retention_purge_does_not_read_as_tampering(self):
        import audit_log
        audit_log.record("test.old")
        self._raw("UPDATE audit_log SET created_at='2000-01-01T00:00:00+00:00'")
        # The edit above breaks the old row's own hash, but the purge removes
        # it; what remains must verify from the new first row.
        audit_log.record("test.new")
        audit_log.purge_older_than("2001-01-01")
        self.assertTrue(audit_log.verify()["intact"])


class AuditWriteFailureTests(unittest.TestCase):
    def test_a_failed_audit_write_does_not_break_the_action(self):
        """A full disk must not stop people signing in."""
        import audit_log
        with mock.patch.object(audit_log.db, "_connect", side_effect=OSError("disk full")):
            self.assertIsNone(audit_log.record("auth.login"))


if __name__ == "__main__":
    unittest.main()
