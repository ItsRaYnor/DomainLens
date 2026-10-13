"""Free API tiers are kept to, and a lookup that was not made says why.

A few scans close together went past VirusTotal's 4 lookups a minute (500 a
day) or ip-api.com's 45 a minute. The answer was HTTP 429, shown as an error
or as nothing; the next requests failed the same way and still counted
against the quota; and the OSINT result with those failures in it was
cached for a day, so the failure was what every scan showed until the next.
"""

import unittest
from unittest import mock

import link_check
import net_errors
import osint
import rate_limits


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class BudgetTests(unittest.TestCase):
    def setUp(self):
        rate_limits.reset()
        self.clock = _Clock()
        patches = [mock.patch.object(rate_limits.time, "monotonic", self.clock.monotonic),
                   mock.patch.object(rate_limits.time, "sleep", self.clock.sleep),
                   mock.patch.object(rate_limits, "limits", return_value=(4, 500))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_the_fifth_lookup_in_a_minute_is_not_made(self):
        for _ in range(4):
            self.assertEqual((True, None), rate_limits.acquire("virustotal", wait=0))
        allowed, reason = rate_limits.acquire("virustotal", wait=0)
        self.assertFalse(allowed)
        self.assertEqual("VirusTotal allows 4 lookups a minute and they were in use. "
                         "Not measured; try again later.", reason)

    def test_a_lookup_waits_for_a_slot_when_it_may(self):
        for _ in range(4):
            rate_limits.acquire("virustotal", wait=0)
        self.clock.now += 50
        self.assertEqual((True, None), rate_limits.acquire("virustotal", wait=20))
        self.assertGreaterEqual(self.clock.now, 1060)

    def test_the_daily_quota(self):
        with mock.patch.object(rate_limits, "limits", return_value=(100, 2)):
            rate_limits.acquire("virustotal", wait=0)
            rate_limits.acquire("virustotal", wait=0)
            allowed, reason = rate_limits.acquire("virustotal", wait=0)
        self.assertFalse(allowed)
        self.assertIn("daily limit for VirusTotal (2 lookups) is used up", reason)

    def test_a_429_stops_further_requests_for_as_long_as_asked(self):
        rate_limits.note_response("otx", mock.Mock(status_code=429, headers={"Retry-After": "30"}))
        allowed, reason = rate_limits.acquire("otx", wait=0)
        self.assertFalse(allowed)
        self.assertIn("asked to slow down", reason)
        self.clock.now += 31
        self.assertTrue(rate_limits.acquire("otx", wait=0)[0])


class LookupTests(unittest.TestCase):
    def setUp(self):
        rate_limits.reset()
        self.addCleanup(rate_limits.reset)

    def test_virustotal_is_not_asked_over_its_budget(self):
        session = mock.Mock()
        with mock.patch.object(osint, "_api_key", return_value="k"), \
             mock.patch.object(osint, "_session", return_value=session), \
             mock.patch.object(osint.rate_limits, "acquire", return_value=(False, "VirusTotal allows 4 lookups a minute and they were in use. Not measured; try again later.")):
            result = osint.virustotal_lookup("example.org")
        session.get.assert_not_called()
        self.assertFalse(result["success"])
        self.assertTrue(net_errors.is_transient(result["error"]))

    def test_a_429_is_said_in_words(self):
        session = mock.Mock()
        session.get.return_value = mock.Mock(status_code=429, headers={})
        data, error = osint._fetch_json(session, "https://www.virustotal.com/x", label="VirusTotal",
                                        timeout=5, provider="virustotal")
        self.assertIsNone(data)
        self.assertEqual("VirusTotal limits how often it may be asked, and that limit was reached. "
                         "Not measured; try again later.", error)

    def test_mail_links_share_the_budget(self):
        get = mock.Mock()
        with mock.patch.object(rate_limits, "acquire", return_value=(False, "VirusTotal allows 4 lookups a minute and they were in use. Not measured; try again later.")), \
             mock.patch.object(link_check, "_vt_cached", return_value=None):
            out = link_check.check_virustotal(["https://example.org/a"], get=get, key="k", limit=4)
        get.assert_not_called()
        self.assertEqual("unmeasured", out["https://example.org/a"]["state"])


class CacheTests(unittest.TestCase):
    def test_a_result_with_a_passing_failure_is_not_kept_for_a_day(self):
        failed = {"success": True, "sources": {"virustotal": {"success": False, "error":
                  "VirusTotal limits how often it may be asked, and that limit was reached. Not measured; try again later."}}}
        self.assertFalse(osint.cacheable(failed))

    def test_a_result_with_a_lasting_failure_is(self):
        rejected = {"success": True, "sources": {"otx": {"success": False, "error": "OTX rejected the API key"}}}
        self.assertTrue(osint.cacheable(rejected))


class SettingsTests(unittest.TestCase):
    def test_the_budgets_are_settings_with_the_free_tiers_as_default(self):
        from settings import defaults, registry
        self.assertEqual({"virustotal_per_minute": 4, "virustotal_per_day": 500, "ip_api_per_minute": 45,
                          "wait_seconds": 20}, defaults.DEFAULTS["api_limits"])
        self.assertIn("api_limits", registry.ADMIN_SECTIONS)


if __name__ == "__main__":
    unittest.main()
