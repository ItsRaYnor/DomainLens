"""New known CVEs for the versions monitored domains showed, without a new scan.

A CVE published the day after a scan, or one CISA adds to its list of
exploited flaws, was only seen at the next scan of that site, and only by
someone who opened the report and counted. After each sync of the CVE data
the versions the monitors last measured are compared again, and what came
after the scan becomes a monitor event that the notification channels send.
"""

import os
import pathlib
import tempfile
import unittest
from datetime import timedelta
from unittest import mock

import cve_alerts
import cve_feed
from test_cve_feed import NOW, PHP, PHP_RECORDS, _all_synced, _clear, _cve, _enabled, _match, _page, _shown

ROOT = pathlib.Path(__file__).resolve().parent.parent
_tempdir = None
LATER = NOW + timedelta(days=1)


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "cve-alerts.db")
    import db
    db.init_db()


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


# Published after the scan: 8.1 up to 8.1.20.
NEW_CVE = _cve("CVE-2026-10010", [_match("php:php", versionStartIncluding="8.1.0", versionEndExcluding="8.1.20")],
               score=8.8)


def _sync(records, now):
    with _enabled():
        cve_feed.sync_nvd([PHP], get=mock.Mock(return_value=_page(records)), sleep=mock.Mock(), now=now)
    _all_synced(now)


def _scan_of(version_text):
    with _enabled(), mock.patch.object(cve_feed, "_now", return_value=NOW):
        assessment = cve_feed.assess_product(PHP, _shown(version_text))
    return {"security": {"info_disclosure": {"cves": [assessment]}}}


class _MonitorCase(unittest.TestCase):
    version = "PHP/8.1.5"

    def setUp(self):
        import db
        _clear()
        with db._lock, db._connect() as conn:
            for table in ("monitor_events", "monitors", "scans", "cve_alert_known", "cve_alert_scans"):
                conn.execute(f"DELETE FROM {table}")
        _sync(PHP_RECORDS, NOW)
        self.monitor_id = db.create_monitor(name="example.org", domain="example.org", target="example.org",
                                            record_type="A")
        self.results = _scan_of(self.version)
        self.scan_id = db.save_scan("example.org", self.results)
        db.mark_monitor_scanned(self.monitor_id, self.scan_id, 1440)

    def _note(self):
        with _enabled(), mock.patch.object(cve_feed, "_now", return_value=NOW):
            cve_alerts.note_scan(self.monitor_id, self.scan_id, self.results)

    def _recheck(self, now=LATER):
        sent = mock.Mock()
        with _enabled(), mock.patch.object(cve_feed, "_now", return_value=now), \
                mock.patch.object(cve_alerts, "notifier", sent):
            report = cve_alerts.recheck(now=now)
        return report, sent

    def _events(self):
        import db
        return [e for e in db.list_monitor_events(self.monitor_id) if e["event_type"] == cve_alerts.EVENT_TYPE]


class NewCveTests(_MonitorCase):
    def test_a_cve_published_after_the_scan_is_reported_and_sent(self):
        """It was only seen at the next scan, by whoever opened the report."""
        self._note()
        _sync([NEW_CVE], LATER)
        report, sent = self._recheck()
        events = self._events()
        self.assertEqual(1, report["events"])
        self.assertEqual(1, len(events))
        self.assertIn("CVE-2026-10010", events[0]["summary"])
        self.assertIn("PHP/8.1.5 on example.org", events[0]["summary"])
        self.assertEqual("high", events[0]["severity"])
        self.assertEqual(self.scan_id, events[0]["scan_id"])
        sent.assert_called_once()
        self.assertEqual(cve_alerts.EVENT_TYPE, sent.call_args.args[1]["event_type"])

    def test_what_the_scan_already_reported_is_not_reported_again(self):
        self._note()
        report, sent = self._recheck()
        self.assertEqual(0, report["events"])
        sent.assert_not_called()
        _sync([NEW_CVE], LATER)
        self._recheck()
        report, _ = self._recheck(LATER + timedelta(hours=3))
        self.assertEqual(0, report["events"], "a CVE once reported is not reported at every sync")
        self.assertEqual(1, len(self._events()))

    def test_a_known_cve_that_becomes_exploited_is_reported(self):
        """CISA listing a flaw as exploited changes what to do first."""
        self._note()
        exploited = _cve("CVE-2026-10002", [_match("php:php", versionStartIncluding="8.1.0",
                                                    versionEndExcluding="8.1.11")], score=5.3, kev="2026-10-29")
        _sync([exploited], LATER)
        self._recheck()
        events = self._events()
        self.assertEqual(1, len(events))
        self.assertIn("Now exploited (CISA KEV)", events[0]["summary"])
        self.assertNotIn("new known CVE", events[0]["summary"])
        self.assertEqual("high", events[0]["severity"], "exploited outranks a 5.3 score")

    def test_a_scan_from_before_is_taken_stock_of_silently(self):
        """A monitor scanned before this existed would otherwise report every
        CVE its version ever had as new."""
        report, sent = self._recheck()
        self.assertEqual(0, report["events"])
        sent.assert_not_called()
        _sync([NEW_CVE], LATER + timedelta(hours=3))
        self._recheck(LATER + timedelta(hours=3))
        self.assertEqual(["CVE-2026-10010"], [c["cve"] for c in self._events()[0]["details"]["new"]])

    def test_data_that_is_not_current_compares_nothing(self):
        self._note()
        _sync([NEW_CVE], LATER)
        report, sent = self._recheck(LATER + timedelta(days=10))
        self.assertEqual(0, report["events"])
        sent.assert_not_called()
        report, _ = self._recheck()
        self.assertEqual(1, report["events"], "reported once the data is current again")

    def test_switched_off_nothing_is_compared(self):
        self._note()
        _sync([NEW_CVE], LATER)
        with _enabled(enabled=False):
            self.assertIsNone(cve_alerts.recheck(now=LATER))
        self.assertEqual([], self._events())

    def test_the_sync_itself_compares_afterwards(self):
        self._note()
        get = mock.Mock(return_value=_page([NEW_CVE]))
        with _enabled(), mock.patch.object(cve_feed, "_now", return_value=LATER), \
                mock.patch.object(cve_alerts, "notifier", mock.Mock()):
            result = cve_feed.sync(get=get, sleep=mock.Mock(), now=LATER)
        self.assertEqual(1, result["report"]["alerts"]["events"])


class DistributionBuildTests(_MonitorCase):
    version = "PHP/8.1.5-1ubuntu1"

    def test_a_distribution_build_gives_no_event(self):
        """Its package may carry the fix: a new CVE for the upstream number
        is not a measured fact about this server."""
        self._note()
        _sync([NEW_CVE], LATER)
        report, sent = self._recheck()
        self.assertEqual(0, report["events"])
        sent.assert_not_called()


class HiddenVersionTests(_MonitorCase):
    def setUp(self):
        super().setUp()
        import db
        with _enabled(), mock.patch.object(cve_feed, "_now", return_value=NOW):
            hidden = cve_feed.assess_product(PHP, None)
        self.results = {"security": {"info_disclosure": {"cves": [hidden]}}}
        self.scan_id = db.save_scan("example.org", self.results)
        db.mark_monitor_scanned(self.monitor_id, self.scan_id, 1440)

    def test_a_hidden_version_gives_no_event(self):
        self._note()
        _sync([NEW_CVE], LATER)
        report, _ = self._recheck()
        self.assertEqual(0, report["events"])


class WiringTests(unittest.TestCase):
    def test_a_monitor_scan_notes_what_it_found_and_events_go_out(self):
        app = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn('cve_alerts.note_scan(monitor["id"], scan_id, results)', app)
        self.assertIn("cve_alerts.notifier = _notify_event", app)

    def test_the_monitoring_pages_show_the_event_type(self):
        import db
        self.assertEqual("New known CVE", db.EVENT_TYPE_TEXT[cve_alerts.EVENT_TYPE])
        events = (ROOT / "static" / "js" / "events.js").read_text(encoding="utf-8")
        self.assertIn("const EV_DEFAULT_TYPES = ['scan_changed', 'known_cve_new'", events)
        trends = (ROOT / "static" / "js" / "trends.js").read_text(encoding="utf-8")
        self.assertIn("known_cve_new", trends)


if __name__ == "__main__":
    unittest.main()
