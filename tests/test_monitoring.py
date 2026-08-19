import os
import tempfile
import unittest
from unittest import mock


class MonitoringFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "test-domainlens.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["SERVICENOW_ENABLED"] = "0"

        import importlib
        import db
        import app
        import servicenow

        self.db = importlib.reload(db)
        self.servicenow = importlib.reload(servicenow)
        self.app_module = importlib.reload(app)
        self.db.init_db()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in (
            "DOMAINLENS_DB",
            "DOMAINLENS_DISABLE_SCHEDULER",
            "SERVICENOW_ENABLED",
            "SERVICENOW_INSTANCE",
            "SERVICENOW_USER",
            "SERVICENOW_PASSWORD",
            "SERVICENOW_MIN_SEVERITY",
        ):
            os.environ.pop(key, None)

    def test_zone_import_creates_monitorable_targets(self):
        zone_text = """
$ORIGIN example.com.
@ 3600 IN A 203.0.113.10
www 3600 IN CNAME app.example.net.
mail 3600 IN MX 10 mx1.mailhost.test.
"""
        monitors = self.app_module._zone_records_to_monitors("example.com", zone_text)
        targets = {(item["target"], item["record_type"]) for item in monitors}
        self.assertIn(("example.com", "A"), targets)
        self.assertIn(("www.example.com", "CNAME"), targets)
        self.assertIn(("app.example.net", "CNAME"), targets)
        self.assertIn(("mail.example.com", "MX"), targets)
        self.assertIn(("mx1.mailhost.test", "MX"), targets)

    def test_monitor_scan_updates_schedule_and_links_history(self):
        monitor_id = self.db.create_monitor(
            name="Example monitor",
            domain="example.com",
            target="example.com",
            record_type="A",
            schedule_minutes=60,
            checks=["dns"],
        )
        monitor = self.db.get_monitor(monitor_id)

        original_runner = self.app_module.run_selected_checks
        try:
            self.app_module.run_selected_checks = lambda domain, checks, progress_cb=None: {
                "dns": {"A": ["93.184.216.34"]},
                "domain": domain,
                "timestamp": "2026-01-01T00:00:00+00:00",
            }
            outcome = self.app_module._scan_monitor(monitor)
        finally:
            self.app_module.run_selected_checks = original_runner

        self.assertIsInstance(outcome["scan_id"], int)
        updated = self.db.get_monitor(monitor_id)
        self.assertEqual(updated["last_scan_id"], outcome["scan_id"])
        self.assertIsNotNone(updated["last_scan_at"])
        self.assertIsNotNone(updated["next_scan_at"])
        events = self.db.list_monitor_events(monitor_id=monitor_id, limit=5)
        self.assertEqual(events[0]["event_type"], "baseline_created")
        self.assertEqual(events[0]["severity"], "info")

        overview = self.db.reporting_overview(days=30)
        self.assertGreaterEqual(overview["scans"], 1)
        trends = self.db.reporting_trends(days=7)
        self.assertEqual(len(trends["series"]), 7)

    def test_changed_monitor_scan_creates_change_event(self):
        monitor_id = self.db.create_monitor(
            name="Example monitor",
            domain="example.com",
            target="example.com",
            record_type="A",
            schedule_minutes=60,
            checks=["dns"],
        )
        monitor = self.db.get_monitor(monitor_id)

        original_runner = self.app_module.run_selected_checks
        try:
            self.app_module.run_selected_checks = lambda domain, checks, progress_cb=None: {
                "dns": {"A": ["93.184.216.34"]},
                "blacklist": {"is_listed": False},
                "tls_deep": {"grade": "A", "warnings": []},
            }
            self.app_module._scan_monitor(monitor)

            monitor = self.db.get_monitor(monitor_id)
            self.app_module.run_selected_checks = lambda domain, checks, progress_cb=None: {
                "dns": {"A": ["203.0.113.10"]},
                "blacklist": {"is_listed": True},
                "tls_deep": {"grade": "F", "warnings": ["downgraded"]},
            }
            self.app_module._scan_monitor(monitor)
        finally:
            self.app_module.run_selected_checks = original_runner

        events = self.db.list_monitor_events(monitor_id=monitor_id, limit=5)
        self.assertEqual(events[0]["event_type"], "scan_changed")
        self.assertEqual(events[0]["severity"], "critical")

    def test_servicenow_should_notify_respects_threshold(self):
        os.environ["SERVICENOW_ENABLED"] = "1"
        os.environ["SERVICENOW_INSTANCE"] = "https://example.service-now.com"
        os.environ["SERVICENOW_USER"] = "bot"
        os.environ["SERVICENOW_PASSWORD"] = "secret"
        os.environ["SERVICENOW_MIN_SEVERITY"] = "high"
        import importlib
        sn = importlib.reload(self.servicenow)
        self.assertTrue(sn.should_notify("critical"))
        self.assertTrue(sn.should_notify("high"))
        self.assertFalse(sn.should_notify("medium"))

    def test_servicenow_create_incident_posts_payload(self):
        os.environ["SERVICENOW_ENABLED"] = "1"
        os.environ["SERVICENOW_INSTANCE"] = "https://example.service-now.com"
        os.environ["SERVICENOW_USER"] = "bot"
        os.environ["SERVICENOW_PASSWORD"] = "secret"
        os.environ["SERVICENOW_MIN_SEVERITY"] = "high"
        import importlib
        sn = importlib.reload(self.servicenow)

        fake_response = mock.Mock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "result": {"sys_id": "abc123", "number": "INC0010001"}
        }

        with mock.patch("servicenow.requests.post", return_value=fake_response) as post:
            result = sn.create_incident(
                summary="example.com is now listed on a DNS blacklist",
                severity="critical",
                details={"target": "example.com", "blacklist_listed": True},
                monitor={"target": "example.com", "domain": "example.com", "record_type": "A"},
            )

        self.assertEqual(result["sys_id"], "abc123")
        self.assertEqual(result["number"], "INC0010001")
        self.assertTrue(post.called)


if __name__ == "__main__":
    unittest.main()
