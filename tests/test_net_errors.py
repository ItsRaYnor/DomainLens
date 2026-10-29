"""Third-party lookups that fail are said in words, and count as not measured.

During a DNS hiccup on the server every OSINT source showed the exception
chain ("HTTPSConnectionPool(host=...): Max retries exceeded ... Caused by
NameResolutionError ...") while the summary above it said "Threat feed hits:
0" in green and "Wayback snapshots: 0" -- feeds that were never reached,
presented as a clean result.
"""

import socket
import unittest
from unittest import mock

import requests

import net_errors
import osint
import scan_diff


def _dns_failure(host="web.archive.org"):
    return requests.ConnectionError(
        f"HTTPSConnectionPool(host='{host}', port=443): Max retries exceeded with url: /x "
        f"(Caused by NameResolutionError(\"HTTPSConnection(host='{host}', port=443): Failed to "
        f"resolve '{host}' ([Errno -3] Temporary failure in name resolution)\"))")


class DescribeTests(unittest.TestCase):
    def test_a_dns_failure_names_the_source_and_this_server(self):
        kind, text = net_errors.classify(_dns_failure())
        self.assertEqual(net_errors.DNS, kind)
        self.assertEqual("This server could not look up web.archive.org: its DNS did not answer. "
                         "Not measured; try again later.", text)
        self.assertNotIn("HTTPSConnectionPool", text)

    def test_a_bare_resolver_error_gets_the_name_it_was_for(self):
        text = net_errors.describe(socket.gaierror(-3, "Temporary failure in name resolution"), "example.org")
        self.assertIn("could not look up example.org", text)

    def test_timeouts_and_http_errors(self):
        self.assertEqual(net_errors.TIMEOUT, net_errors.classify(requests.ReadTimeout("read timed out"))[0])
        response = mock.Mock(status_code=503)
        error = requests.HTTPError("503", response=response)
        error.request = mock.Mock(url="https://web.archive.org/cdx")
        self.assertEqual("web.archive.org answered HTTP 503. Not measured; try again later.", net_errors.describe(error))


class OsintSummaryTests(unittest.TestCase):
    # Each feed's answer is now kept for a day, so every collect gets an empty
    # cache of its own: a stub answer kept by one test is not the next one's.
    def setUp(self):
        import os
        import tempfile
        import db
        self._tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._old_db = os.environ.get("DOMAINLENS_DB")
        os.environ["DOMAINLENS_DB"] = os.path.join(self._tempdir.name, "net-errors.db")
        db.init_db()

    def tearDown(self):
        import os
        if self._old_db is None:
            os.environ.pop("DOMAINLENS_DB", None)
        else:
            os.environ["DOMAINLENS_DB"] = self._old_db
        self._tempdir.cleanup()

    def _collect(self, failing):
        def fail(*a, **k):
            return {"success": False, "source": "x", "error": net_errors.describe(_dns_failure())}
        ok = {"success": True, "source": "x", "hit_count": 0, "url_count": 0, "pulses": 0, "count": 0}
        patches = {name: mock.patch.object(osint, name, side_effect=fail if name in failing else (lambda *a, **k: dict(ok)))
                   for name in ("certificate_transparency", "wayback_snapshots", "ip_context",
                                "threatfox_lookup", "urlhaus_lookup", "otx_lookup", "virustotal_lookup")}
        for p in patches.values():
            p.start()
        try:
            return osint.collect_osint("example.org")["summary"]
        finally:
            for p in patches.values():
                p.stop()

    def test_feeds_that_were_not_reached_are_not_zero_hits(self):
        summary = self._collect({"threatfox_lookup", "urlhaus_lookup", "otx_lookup", "wayback_snapshots",
                                 "certificate_transparency"})
        self.assertIsNone(summary["threat_hits"])
        self.assertIsNone(summary["listed_in_threat_feeds"])
        self.assertIsNone(summary["wayback_count"])
        self.assertIsNone(summary["subdomain_count"])
        self.assertEqual(5, len(summary["dns_failures"]))

    def test_reached_feeds_still_count(self):
        summary = self._collect(set())
        self.assertEqual((0, False, []), (summary["threat_hits"], summary["listed_in_threat_feeds"],
                                          summary["dns_failures"]))

    def test_a_temporary_dns_failure_is_tried_once_more(self):
        session = mock.Mock()
        good = mock.Mock(status_code=200)
        good.json.return_value = {"ok": True}
        session.get.side_effect = [_dns_failure(), good]
        with mock.patch.object(osint.time, "sleep"):
            data, error = osint._fetch_json(session, "https://web.archive.org/x", label="x", timeout=5)
        self.assertEqual(({"ok": True}, None), (data, error))


class ComparisonTests(unittest.TestCase):
    def test_a_scan_that_reached_no_feed_is_not_a_drop_to_zero(self):
        results = {"osint": {"success": True, "summary": {"threat_hits": None, "threat_feeds_measured": 0}}}
        self.assertIsNone(scan_diff._threat_feed_hits(results))



class ScreenTests(unittest.TestCase):
    def test_the_page_says_not_measured(self):
        import pathlib
        js = (pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("const count = v => (v === null ? '<span class=\"status status-warn\">Not measured</span>'", js)
        self.assertIn("? '<span class=\"status status-warn\">Not measured</span>'\n            : '<span class=\"muted\">not configured</span>';", js)
        self.assertIn("state: data.osint?.summary?.listed_in_threat_feeds === null ? 'not_tested' : undefined", js)



class HttpErrorTests(unittest.TestCase):
    def test_a_refused_request_is_not_called_a_connection_failure(self):
        """An HTTPError is an OSError too, so a 403 read as "could not connect"."""
        self.assertEqual("the source answered HTTP 403. Not measured.",
                         net_errors.describe(requests.HTTPError("403 Forbidden")))


if __name__ == "__main__":
    unittest.main()
