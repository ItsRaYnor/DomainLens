"""Wrong monitor events: their cause, and a way to remove them.

A certificate that could not be fetched at all -- DNS down, a timeout, the
port closed -- was graded T, "certificate not trusted". A monitor then
raised a HIGH "TLS grade regressed from A+ to T" for an outage of the
scanner's own network, and those events could not be removed afterwards.
"""

import pathlib
from unittest import mock

import audit_log
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


class TlsGradeTests(EnterpriseAppTestCase):
    def _grade(self, cert):
        return self.app_module._calculate_tls_grade([], [], cert, False, False, True)[0]

    def test_a_certificate_that_failed_verification_is_t(self):
        self.assertEqual("T", self._grade({"success": False, "trusted": False, "error": "verify failed"}))

    def test_a_certificate_that_could_not_be_fetched_is_not_graded(self):
        self.assertIsNone(self._grade({"success": False, "error": "timed out"}))

    def test_a_server_that_does_not_answer_is_not_measured(self):
        app = self.app_module
        silent = lambda *a, **k: {"supported": False, "error": "timed out"}
        with mock.patch.object(app, "_test_protocol", side_effect=silent), \
             mock.patch.object(app, "_test_tls13", side_effect=silent), \
             mock.patch.object(app, "_get_cert_details", return_value={"success": False, "error": "timed out"}), \
             mock.patch.object(app, "_enumerate_ciphers") as ciphers:
            result = app.check_tls_deep("example.org")
        ciphers.assert_not_called()
        self.assertEqual((False, "unmeasured"), (result["success"], result["state"]))
        self.assertNotIn("grade", result)
        import recommendations
        titles = [r["title"] for r in recommendations.generate({"domain": "example.org", "tls_deep": result})]
        self.assertFalse([t for t in titles if "TLS" in t])


class DeleteEventsTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.monitor_id = self.db.create_monitor(name="example.org", domain="example.org", target="example.org",
                                                 record_type="A", schedule_minutes=1440, checks=["all"])
        self.wrong = self.db.create_monitor_event(self.monitor_id, event_type="scan_changed", severity="high",
                                                  summary="example.org TLS grade regressed from A+ to T")
        self.kept = self.db.create_monitor_event(self.monitor_id, event_type="scan_unchanged", severity="info",
                                                 summary="No changes detected for example.org")

    def _ids(self):
        return {e["id"] for e in self.db.list_monitor_events(limit=100)}

    def test_selected_events_are_removed_and_the_rest_kept(self):
        self.login_as("user")
        resp = self.client.post("/api/monitor-events/delete", json={"ids": [self.wrong]})
        self.assertEqual((200, 1), (resp.status_code, resp.get_json()["deleted"]))
        self.assertNotIn(self.wrong, self._ids())
        self.assertIn(self.kept, self._ids())

    def test_the_removal_is_kept_in_the_audit_log(self):
        self.login_as("user")
        self.client.post("/api/monitor-events/delete", json={"ids": [self.wrong]})
        entry = audit_log.list_entries(limit=5, action="monitor_event.delete")["entries"][0]
        self.assertIn("regressed from A+ to T", str(entry["details"]))

    def test_a_viewer_cannot_remove_events(self):
        self.login_as("viewer")
        self.assertEqual(403, self.client.post("/api/monitor-events/delete", json={"ids": [self.wrong]}).status_code)
        self.assertIn(self.wrong, self._ids())

    def test_nothing_selected_is_refused(self):
        self.login_as("user")
        self.assertEqual(400, self.client.post("/api/monitor-events/delete", json={"ids": []}).status_code)

    def test_the_page_offers_it(self):
        self.login_as("user")
        html = self.client.get("/monitoring").get_data(as_text=True)
        self.assertIn('id="eventDeleteBtn"', html)
        js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn('class="event-select"', js)
