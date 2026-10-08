"""A monitor reports a change only when the comparison shows one.

A monitor fingerprinted the raw scan results, which hold values that differ
on every scan without anything changing -- header values, the order of a
list, counts from public logs. It raised "Observed changes" while every row
of its "what changed?" panel read unchanged. A change is now what the
comparison shows: a field or dimension measured in both scans that moved,
or a finding that appeared or went away; the event says which.
"""

import pathlib
import unittest

import scan_diff
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _scan(grade="B", headers=None, clean=("a.example", "b.example"), ports=(443, 80), header_value="abc"):
    return {
        "domain": "example.com",
        "tls_deep": {"success": True, "grade": grade},
        "http_headers": {"success": True, "score": 61, "headers_missing": headers or ["Cross-Origin-Opener-Policy"],
                         "raw": {"Date": header_value, "CF-Ray": header_value}},
        "blacklist": {"is_listed": False, "listed": [], "clean": list(clean)},
        "ports": {"open": [{"port": p, "service": "HTTPS" if p == 443 else "HTTP"} for p in ports]},
    }


class EventTests(EnterpriseAppTestCase):
    MONITOR = {"target": "example.com", "record_type": "A", "last_state_hash": "earlier"}

    def _event(self, before, after):
        _, event = self.app_module._monitor_event_from_results(dict(self.MONITOR), after, {"id": 1, "data": before})
        return event

    def test_values_that_differ_on_every_scan_are_no_change(self):
        before = _scan(header_value="Mon", clean=("a.example", "b.example"))
        after = _scan(header_value="Tue", clean=("b.example", "a.example"))
        self.assertEqual("scan_unchanged", self._event(before, after)["event_type"])

    def test_a_real_change_is_reported_and_named(self):
        event = self._event(_scan(grade="B"), _scan(grade="A"))
        self.assertEqual("scan_changed", event["event_type"])
        self.assertIn("TLS grade B → A", event["summary"])

    def test_a_port_that_opened_is_a_change(self):
        event = self._event(_scan(ports=(443,)), _scan(ports=(443, 8080)))
        self.assertEqual("scan_changed", event["event_type"])
        self.assertIn("Open ports", event["summary"])

    def test_a_new_finding_is_a_change(self):
        before = _scan()
        after = _scan(headers=["Cross-Origin-Opener-Policy", "Strict-Transport-Security"])
        changes = scan_diff.monitor_changes(before, [], after,
                                            [{"severity": "high", "title": "HSTS header missing", "finding_key": "web:hsts"}])
        self.assertEqual(["HSTS header missing"], [f["title"] for f in changes["findings"]["new"]])
        self.assertTrue(changes["changed"])

    def test_without_the_earlier_scan_the_fingerprint_decides(self):
        """The stored hash now holds what is compared, so a raw value that
        changes does not change it either."""
        first = self.app_module._monitor_state_hash(_scan(header_value="Mon"), [])
        second = self.app_module._monitor_state_hash(_scan(header_value="Tue"), [])
        self.assertEqual(first, second)
        self.assertNotEqual(first, self.app_module._monitor_state_hash(_scan(grade="A"), []))


class CompareTests(unittest.TestCase):
    def test_open_ports_read_as_ports_not_as_python(self):
        """The panel showed "{'port': 443, 'service': 'HTTPS'}"."""
        self.assertEqual(["443/HTTPS", "80/HTTP"], scan_diff._open_ports(_scan()))

    def test_the_panel_leads_with_what_moved(self):
        js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("const moved = shown.filter(", js)
        self.assertIn("Unchanged or not measured (", js)
        self.assertIn("Nothing that is compared moved between these two scans.", js)
        css = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".data-table.cmp-table td { word-break: normal; overflow-wrap: anywhere; }", css)


class ApiTests(EnterpriseAppTestCase):
    def test_compare_returns_the_findings_and_fields_that_moved(self):
        self.login_as("user")
        a = self.db.save_scan("example.com", _scan(grade="B"))
        b = self.db.save_scan("example.com", _scan(grade="A"))
        data = self.client.get(f"/api/compare?a={a}&b={b}").get_json()
        self.assertTrue(data["changed"])
        self.assertIn("findings", data)
        self.assertEqual(["TLS grade"], [f["label"] for f in data["fields"]])


if __name__ == "__main__":
    unittest.main()
