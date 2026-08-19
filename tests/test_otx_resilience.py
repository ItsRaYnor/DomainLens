import unittest
from unittest import mock

import requests

import osint


def _resp(status=200, payload=None):
    r = mock.Mock(status_code=status)
    r.json.return_value = payload if payload is not None else {}
    r.raise_for_status = mock.Mock()
    return r


class OtxTimeoutTests(unittest.TestCase):
    """Reported live: "otx.alienvault.com: Read timed out. (read timeout=12)".

    OTX is slower than the other feeds and its passive_dns endpoint slower
    still. Two problems: the shared 12s budget was too tight, and because the
    two calls ran in sequence with no partial handling, a timeout on the
    second one discarded the pulse count the first had already returned —
    the pulse count being the actual threat signal.
    """

    def setUp(self):
        self.key_patch = mock.patch("osint._api_key", return_value="key123")
        self.key_patch.start()

    def tearDown(self):
        self.key_patch.stop()

    def test_otx_gets_a_longer_timeout_than_the_shared_one(self):
        self.assertGreater(osint._OTX_TIMEOUT, osint._TIMEOUT)

    def test_passive_dns_timeout_keeps_the_pulse_count(self):
        session = mock.Mock()
        session.get.side_effect = [
            _resp(200, {"pulse_info": {"count": 3}}),   # general: fine
            requests.Timeout("read timed out"),          # passive_dns: slow
            requests.Timeout("read timed out"),          # ...and on retry
        ]
        with mock.patch("osint._session", return_value=session):
            result = osint.otx_lookup("example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["pulses"], 3)
        self.assertIn("did not respond", result["passive_dns_error"])
        self.assertEqual(result["passive_dns"], [])

    def test_general_timeout_is_retried_once(self):
        session = mock.Mock()
        session.get.side_effect = [
            requests.Timeout("read timed out"),
            _resp(200, {"pulse_info": {"count": 0}}),
            _resp(200, {"passive_dns": []}),
        ]
        with mock.patch("osint._session", return_value=session):
            result = osint.otx_lookup("example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["pulses"], 0)

    def test_persistent_general_timeout_reports_the_budget(self):
        session = mock.Mock()
        session.get.side_effect = requests.Timeout("read timed out")
        with mock.patch("osint._session", return_value=session):
            result = osint.otx_lookup("example.com")
        self.assertFalse(result["success"])
        self.assertIn(str(osint._OTX_TIMEOUT), result["error"])

    def test_rejected_key_is_named_and_not_retried(self):
        session = mock.Mock()
        session.get.return_value = _resp(403)
        with mock.patch("osint._session", return_value=session):
            result = osint.otx_lookup("example.com")
        self.assertFalse(result["success"])
        self.assertIn("rejected the API key", result["error"])
        self.assertEqual(session.get.call_count, 1)

    def test_non_timeout_error_is_not_retried(self):
        session = mock.Mock()
        session.get.side_effect = requests.ConnectionError("boom")
        with mock.patch("osint._session", return_value=session):
            result = osint.otx_lookup("example.com")
        self.assertFalse(result["success"])
        self.assertEqual(session.get.call_count, 1)

    def test_full_success_returns_passive_dns(self):
        session = mock.Mock()
        session.get.side_effect = [
            _resp(200, {"pulse_info": {"count": 1}, "alexa": "x"}),
            _resp(200, {"passive_dns": [
                {"address": "1.2.3.4", "record_type": "A", "first": "a", "last": "b"},
            ]}),
        ]
        with mock.patch("osint._session", return_value=session):
            result = osint.otx_lookup("example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["pulses"], 1)
        self.assertEqual(len(result["passive_dns"]), 1)
        self.assertNotIn("passive_dns_error", result)

    def test_unconfigured_key_is_still_skipped_cleanly(self):
        with mock.patch("osint._api_key", return_value=""):
            result = osint.otx_lookup("example.com")
        self.assertTrue(result["success"])
        self.assertTrue(result["skipped"])


if __name__ == "__main__":
    unittest.main()
