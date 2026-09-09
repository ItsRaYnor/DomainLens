import os
import tempfile
import unittest


class MonitorWatchesTheChosenRecordTests(unittest.TestCase):
    """A monitor's record type was stored but never resolved, so choosing
    "CNAME" for a host watched the same full scan as everything else and never
    noticed the record itself changing or going NXDOMAIN — the stale dangling
    CNAME case. The watched record now drives change detection.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "rec.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["SERVICENOW_ENABLED"] = "0"
        import importlib
        import db
        import app
        import servicenow
        self.db = importlib.reload(db)
        self.servicenow = importlib.reload(servicenow)
        self.app = importlib.reload(app)
        self.db.init_db()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "SERVICENOW_ENABLED"):
            os.environ.pop(key, None)

    def _monitor(self, record_type="CNAME"):
        mid = self.db.create_monitor(
            name="rec", domain="example.com", target="chat.example.com",
            record_type=record_type, schedule_minutes=60, checks=["dns"])
        return self.db.get_monitor(mid), mid

    def _scan_with_record(self, monitor, record):
        original_runner = self.app.run_selected_checks
        original_record = self.app._resolve_monitored_record
        try:
            self.app.run_selected_checks = lambda domain, checks, progress_cb=None: {
                "dns": {}, "blacklist": {"is_listed": False},
            }
            self.app._resolve_monitored_record = lambda target, record_type: record
            self.app._scan_monitor(self.db.get_monitor(monitor["id"]))
        finally:
            self.app.run_selected_checks = original_runner
            self.app._resolve_monitored_record = original_record

    def _present(self, values):
        return {"type": "CNAME", "measured": True, "present": True,
                "records": sorted(values), "rcode": "NOERROR",
                "authenticated": True, "error": None}

    def _nxdomain(self):
        return {"type": "CNAME", "measured": True, "present": False,
                "records": [], "rcode": "NXDOMAIN",
                "authenticated": False, "error": None}

    def _unmeasured(self):
        return {"type": "CNAME", "measured": False, "present": False,
                "records": [], "rcode": None, "authenticated": None,
                "error": "timeout"}

    def test_record_going_nxdomain_raises_a_high_event(self):
        monitor, mid = self._monitor()
        self._scan_with_record(monitor, self._present(["app.internal.example.net."]))
        self._scan_with_record(monitor, self._nxdomain())
        event = self.db.list_monitor_events(monitor_id=mid, limit=1)[0]
        self.assertEqual(event["event_type"], "scan_changed")
        self.assertEqual(event["severity"], "high")
        self.assertIn("disappeared", event["summary"])

    def test_record_value_change_raises_a_medium_event(self):
        monitor, mid = self._monitor()
        self._scan_with_record(monitor, self._present(["a.example.net."]))
        self._scan_with_record(monitor, self._present(["b.example.net."]))
        event = self.db.list_monitor_events(monitor_id=mid, limit=1)[0]
        self.assertEqual(event["event_type"], "scan_changed")
        self.assertEqual(event["severity"], "medium")
        self.assertIn("changed value", event["summary"])

    def test_unmeasured_lookup_is_never_a_change(self):
        # A resolver hiccup must not read as "the record disappeared": an
        # unmeasured second scan leaves the fingerprint untouched.
        monitor, mid = self._monitor()
        self._scan_with_record(monitor, self._present(["a.example.net."]))
        self._scan_with_record(monitor, self._unmeasured())
        event = self.db.list_monitor_events(monitor_id=mid, limit=1)[0]
        self.assertEqual(event["event_type"], "scan_unchanged")


class ResolveMonitoredRecordStateTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "rec2.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import app
        self.app = importlib.reload(app)

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_query_error_is_unmeasured_not_absent(self):
        # dns_tools.query returns a dict with an error string on SERVFAIL /
        # network failure; that must surface as measured=False, so it is kept
        # out of change detection rather than mistaken for NXDOMAIN.
        import dns_tools
        orig = dns_tools.query
        try:
            dns_tools.query = lambda name, rtype, resolver="system": {
                "rcode": "SERVFAIL", "records": [], "error": "boom",
                "authenticated": None,
            }
            out = self.app._resolve_monitored_record("x.example.com", "A")
        finally:
            dns_tools.query = orig
        self.assertFalse(out["measured"])
        self.assertFalse(out["present"])

    def test_nxdomain_is_measured_and_absent(self):
        import dns_tools
        orig = dns_tools.query
        try:
            dns_tools.query = lambda name, rtype, resolver="system": {
                "rcode": "NXDOMAIN", "records": [], "error": None,
                "authenticated": False,
            }
            out = self.app._resolve_monitored_record("x.example.com", "CNAME")
        finally:
            dns_tools.query = orig
        self.assertTrue(out["measured"])
        self.assertFalse(out["present"])
        self.assertEqual(out["rcode"], "NXDOMAIN")


if __name__ == "__main__":
    unittest.main()
