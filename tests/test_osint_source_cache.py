"""One OSINT feed that is down no longer sends every feed out again.

The OSINT result was kept for a day only as a whole, and only when no feed
had failed for a reason that may pass. One Wayback timeout therefore meant
the next scan of the same domain that day asked all seven feeds again,
the slow ones included, and spent VirusTotal's four-a-minute budget again.
"""

import os
import tempfile
import unittest
from unittest import mock

import osint
import scan_cache

_tempdir = None

FEEDS = ("certificate_transparency", "wayback_snapshots", "ip_context",
         "threatfox_lookup", "urlhaus_lookup", "otx_lookup", "virustotal_lookup")


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "osint-cache.db")
    import db
    db.init_db()


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


def _ok(**extra):
    return dict({"success": True, "source": "x", "hit_count": 0, "url_count": 0,
                 "pulses": 0, "count": 0}, **extra)


class SourceCacheTests(unittest.TestCase):
    def setUp(self):
        import db
        with db._lock, db._connect() as conn:
            conn.execute("DELETE FROM external_cache")

    def _collect(self, answers, force=False):
        mocks = {name: mock.Mock(side_effect=lambda *a, _n=name, **k: dict(answers.get(_n) or _ok()))
                 for name in FEEDS}
        with mock.patch.multiple(osint, **mocks):
            result = osint.collect_osint("example.org", force=force)
        return result, mocks

    def test_only_the_feed_that_failed_is_asked_again(self):
        timeout = {"success": False, "source": "web.archive.org",
                   "error": "Wayback Machine did not respond within 15s. Not measured; try again later."}
        first, _ = self._collect({"wayback_snapshots": timeout})
        self.assertFalse(osint.cacheable(first))

        _second, mocks = self._collect({})
        self.assertEqual(1, mocks["wayback_snapshots"].call_count)
        for name in ("ip_context", "threatfox_lookup", "urlhaus_lookup", "otx_lookup", "virustotal_lookup"):
            self.assertEqual(0, mocks[name].call_count, name)

    def test_a_reused_answer_says_how_old_it_is(self):
        self._collect({})
        second, _ = self._collect({})
        otx = second["sources"]["otx"]
        self.assertTrue(otx["cached"])
        self.assertIn("cache_age_seconds", otx)

    def test_a_forced_scan_asks_every_feed(self):
        self._collect({})
        _again, mocks = self._collect({}, force=True)
        for name in FEEDS:
            self.assertEqual(1, mocks[name].call_count, name)

    def test_a_feed_without_a_key_is_not_kept(self):
        """A skipped feed kept for a day would stay "not configured" until
        tomorrow after an admin adds the key."""
        skipped = {"success": False, "skipped": True, "source": "OTX", "message": "OTX_API_KEY not set"}
        self._collect({"otx_lookup": skipped})
        _again, mocks = self._collect({})
        self.assertEqual(1, mocks["otx_lookup"].call_count)

    def test_certificate_transparency_is_left_to_crtsh_own_cache(self):
        self._collect({})
        _again, mocks = self._collect({})
        self.assertEqual(1, mocks["certificate_transparency"].call_count)
        self.assertNotIn("certificate_transparency", scan_cache.OSINT_SOURCE_KINDS)

    def test_a_crtsh_outage_is_not_kept_for_a_day(self):
        """The outage text does not end in the "try again later" marker, so a
        result with crt.sh down was kept whole, and the subdomain list read
        "unavailable" on every scan until the next day."""
        down = {"success": False, "source": "crt.sh",
                "error": "Certificate Transparency lookup unavailable — crt.sh answered HTTP 502 "
                         "after 3 attempts. This is an outage at crt.sh, not a problem with the "
                         "scanned domain; re-run the scan shortly."}
        result, _ = self._collect({"certificate_transparency": down})
        self.assertFalse(osint.cacheable(result))

    def test_the_scan_passes_its_force_flag_to_the_feeds(self):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        with mock.patch.object(app.osint, "collect_osint", return_value={"success": True, "sources": {}}) as collect:
            app._build_check_map("example.org", "example.org", force_refresh=True)["osint"]()
        collect.assert_called_once_with("example.org", force=True)


if __name__ == "__main__":
    unittest.main()
