import os
import tempfile
import unittest


class MonitorScanLinkTests(unittest.TestCase):
    """Monitoring showed what changed but gave no way to reach the scan that
    detected it, so the report had to be hunted down through the history.
    Both the monitor list and its events carry a scan id; neither was used.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "mon.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()

        self.scan_id = self.db.save_scan("example.com", {"domain": "example.com"})
        self.monitor_id = self.db.create_monitor(
            name="m1", domain="example.com", target="example.com", record_type="A")
        self.db.update_monitor(
            self.monitor_id, last_scan_id=self.scan_id, last_scan_at="2026-08-13T10:00:00Z")
        self.db.create_monitor_event(
            self.monitor_id, scan_id=self.scan_id, event_type="change",
            severity="high", summary="TLS grade dropped")

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_monitor_exposes_its_last_scan(self):
        monitor = self.client.get("/api/monitors").get_json()["monitors"][0]
        self.assertEqual(monitor["last_scan_id"], self.scan_id)
        self.assertIsNotNone(monitor["last_scan_at"])

    def test_event_exposes_the_scan_that_detected_it(self):
        event = self.client.get("/api/monitors").get_json()["events"][0]
        self.assertEqual(event["scan_id"], self.scan_id)

    def test_the_linked_report_actually_renders(self):
        # A link is only useful if the target exists.
        monitor = self.client.get("/api/monitors").get_json()["monitors"][0]
        resp = self.client.get(f"/report/{monitor['last_scan_id']}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"example.com", resp.data)

    def test_a_monitor_that_never_ran_has_no_scan_id(self):
        fresh = self.db.create_monitor(
            name="m2", domain="other.com", target="other.com", record_type="A")
        monitors = {m["id"]: m for m in self.client.get("/api/monitors").get_json()["monitors"]}
        self.assertIsNone(monitors[fresh]["last_scan_id"])


class LatestScanForDomainTests(unittest.TestCase):
    """Only the monitor path calls mark_monitor_scanned, so a manual scan of
    the same domain never moved the monitor's pointer. The monitor therefore
    linked to an old report while newer ones sat in the history unreachable
    from monitoring.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "mon.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()

        self.monitor_scan = self.db.save_scan("example.com", {"domain": "example.com"})
        self.monitor_id = self.db.create_monitor(
            name="m1", domain="example.com", target="example.com", record_type="A")
        self.db.update_monitor(
            self.monitor_id, last_scan_id=self.monitor_scan,
            last_scan_at="2026-08-13T10:00:00Z")

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _monitor(self):
        return self.client.get("/api/monitors").get_json()["monitors"][0]

    def test_manual_scan_surfaces_as_the_latest_scan(self):
        manual = self.db.save_scan("example.com", {"domain": "example.com"})
        monitor = self._monitor()
        self.assertEqual(monitor["last_scan_id"], self.monitor_scan)
        self.assertEqual(monitor["latest_scan"]["id"], manual)

    def test_latest_scan_matches_the_monitor_scan_when_nothing_newer_ran(self):
        monitor = self._monitor()
        self.assertEqual(monitor["latest_scan"]["id"], self.monitor_scan)

    def test_a_scan_of_another_domain_is_not_borrowed(self):
        self.db.save_scan("other.com", {"domain": "other.com"})
        self.assertEqual(self._monitor()["latest_scan"]["id"], self.monitor_scan)

    def test_a_monitor_with_no_scans_at_all_has_no_latest_scan(self):
        fresh = self.db.create_monitor(
            name="m2", domain="unscanned.com", target="unscanned.com", record_type="A")
        monitors = {m["id"]: m for m in self.client.get("/api/monitors").get_json()["monitors"]}
        self.assertIsNone(monitors[fresh].get("latest_scan"))

    def test_the_latest_report_renders(self):
        manual = self.db.save_scan("example.com", {"domain": "example.com"})
        resp = self.client.get(f"/report/{manual}")
        self.assertEqual(resp.status_code, 200)

    def test_lookup_is_one_query_per_batch_not_per_monitor(self):
        for i in range(5):
            domain = f"d{i}.example"
            self.db.save_scan(domain, {"domain": domain})
            self.db.create_monitor(
                name=domain, domain=domain, target=domain, record_type="A")
        found = self.db.latest_scans_by_domain(
            [f"d{i}.example" for i in range(5)] + ["never-scanned.example"])
        self.assertEqual(len(found), 5)
        self.assertNotIn("never-scanned.example", found)

    def test_empty_domain_list_is_handled(self):
        self.assertEqual(self.db.latest_scans_by_domain([]), {})
        self.assertEqual(self.db.latest_scans_by_domain([None, ""]), {})


class MonitorRenderingTests(unittest.TestCase):
    """The markup must actually emit the links, not just have the data."""

    def _app_js(self):
        import pathlib
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "js" / "app.js").read_text(encoding="utf-8")

    def test_monitor_list_renders_a_last_scan_link(self):
        js = self._app_js()
        start = js.index("function monitorReportLinks")
        block = js[start:start + 1500]
        self.assertIn("last_scan_id", block)
        self.assertIn("latest_scan", block)
        self.assertIn("function reportLink", js)

    def test_monitor_list_uses_the_link_helper(self):
        js = self._app_js()
        start = js.index("function renderMonitorList")
        block = js[start:start + 3000]
        self.assertIn("monitorReportLinks(m)", block)

    def test_event_list_renders_a_scan_link(self):
        js = self._app_js()
        start = js.index("function renderMonitorEvents")
        block = js[start:start + 2000]
        self.assertIn("event.scan_id", block)
        self.assertIn("/report/", block)

    def test_links_are_escaped(self):
        js = self._app_js()
        start = js.index("function renderMonitorEvents")
        block = js[start:start + 2000]
        self.assertIn("escapeHtml(String(event.scan_id))", block)


class DeletedScanTests(unittest.TestCase):
    """Both monitors.last_scan_id and monitor_events.scan_id are foreign keys
    declared ON DELETE SET NULL, so removing a scan from the history quietly
    empties them. The monitor then claimed "not scanned yet" despite a row of
    events proving it had run, and the next run threw away a real change
    detection by treating the missing report as "no baseline".
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "mon.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()

        self.scan_id = self.db.save_scan("example.com", {"domain": "example.com"})
        self.monitor_id = self.db.create_monitor(
            name="m1", domain="example.com", target="example.com", record_type="A")
        self.db.update_monitor(
            self.monitor_id, last_scan_id=self.scan_id,
            last_scan_at="2026-08-13T10:00:00Z", last_state_hash="oldhash")
        self.db.create_monitor_event(
            self.monitor_id, scan_id=self.scan_id, event_type="scan_changed",
            severity="medium", summary="Observed changes")

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_deleting_the_scan_nulls_the_monitor_pointer(self):
        # Documents the cause: it is the database doing this, not the UI.
        self.db.delete_scan(self.scan_id)
        self.assertIsNone(self.db.get_monitor(self.monitor_id)["last_scan_id"])
        self.assertIsNone(self.db.list_monitor_events(limit=5)[0]["scan_id"])

    def test_last_scan_at_survives_so_the_ui_can_tell_the_truth(self):
        # "not scanned yet" is only honest when the monitor never ran; the
        # timestamp is what distinguishes that from a deleted report.
        self.db.delete_scan(self.scan_id)
        monitor = self.client.get("/api/monitors").get_json()["monitors"][0]
        self.assertIsNone(monitor["last_scan_id"])
        self.assertIsNotNone(monitor["last_scan_at"])

    def _event_for(self, previous_record):
        monitor = self.db.get_monitor(self.monitor_id)
        results = {"domain": "example.com", "tls_deep": {"grade": "A"}}
        _, event = self.app_module._monitor_event_from_results(
            monitor, results, previous_record)
        return event

    def test_missing_baseline_still_reports_the_change(self):
        event = self._event_for(None)
        self.assertEqual(event["event_type"], "scan_changed")
        self.assertTrue(event["details"]["baseline_missing"])

    def test_missing_baseline_does_not_invent_a_blacklist_listing(self):
        monitor = self.db.get_monitor(self.monitor_id)
        results = {"domain": "example.com", "blacklist": {"is_listed": True}}
        _, event = self.app_module._monitor_event_from_results(monitor, results, None)
        # The domain may well have been listed before the report was deleted.
        self.assertEqual(event["severity"], "medium")
        self.assertNotIn("now listed", event["summary"])
        self.assertNotIn("previous_blacklist_listed", event["details"])

    def test_a_monitor_that_never_ran_still_creates_a_baseline(self):
        self.db.update_monitor(self.monitor_id, last_state_hash=None)
        monitor = self.db.get_monitor(self.monitor_id)
        _, event = self.app_module._monitor_event_from_results(
            monitor, {"domain": "example.com"}, None)
        self.assertEqual(event["event_type"], "baseline_created")

    def test_an_intact_baseline_still_detects_the_transition(self):
        record = {"data": {"blacklist": {"is_listed": False}, "tls_deep": {"grade": "A"}}}
        monitor = self.db.get_monitor(self.monitor_id)
        _, event = self.app_module._monitor_event_from_results(
            monitor, {"domain": "example.com", "blacklist": {"is_listed": True}}, record)
        self.assertEqual(event["severity"], "critical")
        self.assertIn("now listed", event["summary"])

    def test_delete_reports_which_monitors_lose_their_baseline(self):
        resp = self.client.delete(f"/api/history/{self.scan_id}")
        self.assertEqual(resp.status_code, 200)
        affected = resp.get_json()["monitors_affected"]
        self.assertEqual([m["id"] for m in affected], [self.monitor_id])
        self.assertEqual(affected[0]["name"], "m1")

    def test_delete_of_an_unreferenced_scan_reports_nothing(self):
        spare = self.db.save_scan("example.com", {"domain": "example.com"})
        resp = self.client.delete(f"/api/history/{spare}")
        self.assertEqual(resp.get_json()["monitors_affected"], [])

    def test_affected_monitors_are_read_before_the_delete_clears_them(self):
        # Reading after the delete would always come back empty.
        self.assertEqual(len(self.db.monitors_using_scan(self.scan_id)), 1)
        self.db.delete_scan(self.scan_id)
        self.assertEqual(self.db.monitors_using_scan(self.scan_id), [])

    def test_deleting_a_missing_scan_is_still_a_404(self):
        self.assertEqual(self.client.delete("/api/history/999999").status_code, 404)

    def test_ui_distinguishes_a_deleted_report_from_a_missing_one(self):
        import pathlib
        js = (pathlib.Path(__file__).resolve().parent.parent
              / "static" / "js" / "app.js").read_text(encoding="utf-8")
        block = js[js.index("function monitorReportLinks"):][:1500]
        self.assertIn("report deleted", block)
        self.assertIn("no monitor check yet", block)


if __name__ == "__main__":
    unittest.main()
