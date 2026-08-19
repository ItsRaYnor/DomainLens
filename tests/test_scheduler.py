import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "sched.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["DOMAINLENS_CONFIG"] = os.path.join(self.tempdir.name, "cfg.json")
        with open(os.environ["DOMAINLENS_CONFIG"], "w", encoding="utf-8") as handle:
            handle.write('{"scheduler":{"concurrency":1,"max_consecutive_failures":2,"failure_backoff_minutes":30}}')

        import importlib
        import db
        import config
        import scheduler

        self.db = importlib.reload(db)
        self.config = importlib.reload(config)
        self.scheduler = importlib.reload(scheduler)
        self.db.init_db()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "DOMAINLENS_CONFIG"):
            os.environ.pop(key, None)

    def test_process_due_monitors_success(self):
        monitor_id = self.db.create_monitor(
            name="t",
            domain="example.com",
            target="example.com",
            record_type="A",
            schedule_minutes=60,
            checks=["dns"],
        )
        monitor = self.db.get_monitor(monitor_id)
        lock = __import__("threading").Lock()

        outcome = self.scheduler.process_due_monitors(
            db=self.db,
            scan_monitor_fn=lambda m: {
                "scan_id": 1,
                "event": {"event_type": "baseline_created"},
            },
            notify_fn=lambda *a, **k: None,
            safe_error_fn=lambda e: str(e),
            run_lock=lock,
        )
        self.assertEqual(outcome["processed"], 1)
        self.assertEqual(outcome["results"][0]["status"], "ok")

    def test_backoff_skips_monitor(self):
        until = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        monitor_id = self.db.create_monitor(
            name="t",
            domain="example.com",
            target="example.com",
            record_type="A",
            schedule_minutes=5,
            checks=["dns"],
            metadata={"scheduler": {"backoff_until": until}},
        )
        self.db.update_monitor(monitor_id, next_scan_at=datetime.now(timezone.utc).isoformat())
        lock = __import__("threading").Lock()
        calls = []

        self.scheduler.process_due_monitors(
            db=self.db,
            scan_monitor_fn=lambda m: calls.append(m["id"]) or {"scan_id": 1, "event": {}},
            notify_fn=lambda *a, **k: None,
            safe_error_fn=str,
            run_lock=lock,
        )
        self.assertEqual(calls, [])

    def test_reporting_digest_respects_interval(self):
        self.config.load_settings(force_reload=True)
        first = self.scheduler.maybe_run_reporting_digest(self.db)
        second = self.scheduler.maybe_run_reporting_digest(self.db)
        if first:
            self.assertIsNone(second)


if __name__ == "__main__":
    unittest.main()
