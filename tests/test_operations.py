"""Running DomainLens as a service: metrics, retention and backups.

/health said the process was up and nothing more; whether the scheduler kept
up or alerts were delivered could only be read off the UI by a person. The
documented retention target was enforced by nothing, and the only backup
advice was to copy a live SQLite file, which can capture a half-written WAL.
"""

import os
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone

from enterprise_harness import EnterpriseAppTestCase


def _old(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


class MetricsTests(EnterpriseAppTestCase):
    def test_metrics_need_a_login_when_auth_is_on(self):
        self.assertEqual(401, self.client.get("/metrics").status_code)

    def test_an_api_token_can_scrape(self):
        """Prometheus sends a bearer token; it cannot sign in."""
        import api_tokens
        raw, _ = api_tokens.create(self.db.get_user(self.users["viewer"]), name="prometheus")
        resp = self.client.get("/metrics", headers={"Authorization": f"Bearer {raw}"})
        self.assertEqual(200, resp.status_code)
        self.assertIn("text/plain", resp.content_type)

    def test_the_format_is_prometheus_text(self):
        self.login_as("viewer")
        body = self.client.get("/metrics").get_data(as_text=True)
        self.assertIn("# TYPE domainlens_monitors gauge", body)
        self.assertIn('domainlens_monitors{state="enabled"}', body)
        self.assertIn("domainlens_build_info{version=", body)

    def test_a_started_scan_is_counted(self):
        import metrics
        self.login_as("user")
        from unittest import mock
        with mock.patch.object(self.app_module.scan_jobs, "start", return_value={"job_id": "x"}):
            self.client.post("/api/scan/start", json={"domain": "example.com"})
        body = self.client.get("/metrics").get_data(as_text=True)
        self.assertIn("domainlens_scans_started_total", body)

    def test_no_domain_names_leak_into_metrics(self):
        """Metrics end up in systems with wider access than DomainLens."""
        self.db.save_scan("secret-project.example", {"domain": "secret-project.example"})
        self.login_as("viewer")
        self.assertNotIn("secret-project", self.client.get("/metrics").get_data(as_text=True))

    def test_a_scheduler_that_never_ran_reports_no_duration(self):
        """'No run yet' is not 'a run that took 0 seconds'."""
        self.login_as("viewer")
        body = self.client.get("/metrics").get_data(as_text=True)
        self.assertNotIn("domainlens_scheduler_last_run_duration_seconds ", body)


class RetentionTests(EnterpriseAppTestCase):
    def _set(self, **values):
        from settings.store import get_store
        get_store().update_section("retention", values)
        self.app_module._reload_settings()

    def _age_scan(self, scan_id, days):
        with self.db._connect() as conn:
            conn.execute("UPDATE scans SET created_at=? WHERE id=?", (_old(days), scan_id))

    def test_nothing_is_deleted_by_default(self):
        """An upgrade must not delete anything nobody asked it to."""
        import maintenance
        scan_id = self.db.save_scan("example.com", {"domain": "example.com"})
        self._age_scan(scan_id, 4000)
        self.assertEqual(0, maintenance.purge()["scans"])
        self.assertIsNotNone(self.db.get_scan(scan_id))

    def test_old_scans_are_deleted_when_configured(self):
        import maintenance
        self._set(scan_days=30)
        old = self.db.save_scan("example.com", {"domain": "example.com"})
        new = self.db.save_scan("example.com", {"domain": "example.com"})
        self._age_scan(old, 60)
        maintenance.purge()
        self.assertIsNone(self.db.get_scan(old))
        self.assertIsNotNone(self.db.get_scan(new))

    def test_a_monitors_baseline_survives(self):
        """Deleting it would make the next run a new baseline, and a
        regression in between would never be reported."""
        import maintenance
        self._set(scan_days=30)
        monitor_id = self.db.create_monitor(
            name="m", domain="example.com", target="example.com", record_type="A",
            record_value=None, source_type="manual", source_label="m", provider="manual",
            schedule_minutes=1440, checks=["all"], enabled=True, metadata={})
        baseline = self.db.save_scan("example.com", {"domain": "example.com"})
        self.db.mark_monitor_scanned(monitor_id, baseline, 1440)
        self._age_scan(baseline, 365)
        maintenance.purge()
        self.assertIsNotNone(self.db.get_scan(baseline))

    def test_a_purge_is_audited(self):
        import audit_log
        import maintenance
        self._set(scan_days=30)
        self._age_scan(self.db.save_scan("example.com", {"domain": "example.com"}), 60)
        maintenance.purge()
        self.assertTrue(audit_log.list_entries(action="retention.purge")["entries"])


class BackupTests(EnterpriseAppTestCase):
    def test_the_snapshot_is_a_readable_copy_of_the_live_database(self):
        import maintenance
        self.db.save_scan("example.com", {"domain": "example.com"})
        with tempfile.TemporaryDirectory() as target_dir:
            path = maintenance.backup_to(os.path.join(target_dir, "copy.db"))
            conn = sqlite3.connect(path)
            try:
                self.assertEqual("ok", conn.execute("PRAGMA integrity_check").fetchone()[0])
                self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
            finally:
                conn.close()

    def test_only_admins_download_a_backup(self):
        self.login_as("user")
        self.assertEqual(403, self.client.get("/api/admin/backup").status_code)

    def test_an_admin_download_is_audited(self):
        import audit_log
        self.login_as("admin")
        resp = self.client.get("/api/admin/backup")
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.data.startswith(b"SQLite format 3"))
        resp.close()
        self.assertTrue(audit_log.list_entries(action="backup.download")["entries"])
