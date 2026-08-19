import unittest
from unittest import mock

import requests

import osint


def _resp(status=200, payload=None):
    r = mock.Mock(status_code=status)
    r.json.return_value = payload if payload is not None else []
    r.raise_for_status = mock.Mock()
    return r


class WaybackTimeoutTests(unittest.TestCase):
    """Reported live: "web.archive.org ... Read timed out. (read timeout=12)".

    The CDX API is queried with url=domain/*, which makes the server walk
    every capture of the whole domain — routinely more than 12s of work.
    """

    def test_wayback_gets_a_longer_timeout_than_the_shared_one(self):
        self.assertGreater(osint._WAYBACK_TIMEOUT, osint._TIMEOUT)

    def test_timeout_is_retried_then_succeeds(self):
        rows = [
            ["timestamp", "original", "statuscode"],
            ["20250101000000", "http://example.com/", "200"],
        ]
        session = mock.Mock()
        session.get.side_effect = [requests.Timeout("read timed out"), _resp(200, rows)]
        with mock.patch("osint._session", return_value=session):
            result = osint.wayback_snapshots("example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 1)

    def test_persistent_timeout_names_the_source_and_budget(self):
        session = mock.Mock()
        session.get.side_effect = requests.Timeout("read timed out")
        with mock.patch("osint._session", return_value=session):
            result = osint.wayback_snapshots("example.com")
        self.assertFalse(result["success"])
        self.assertIn("Wayback Machine", result["error"])
        self.assertIn(str(osint._WAYBACK_TIMEOUT), result["error"])

    def test_never_archived_domain_is_an_empty_success(self):
        # CDX answers with just the header row, or nothing at all.
        session = mock.Mock()
        session.get.return_value = _resp(200, [["timestamp", "original", "statuscode"]])
        with mock.patch("osint._session", return_value=session):
            result = osint.wayback_snapshots("example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["snapshots"], [])
        self.assertEqual(result["count"], 0)
        self.assertNotIn("error", result)

    def test_non_timeout_error_is_not_retried(self):
        session = mock.Mock()
        session.get.side_effect = requests.ConnectionError("boom")
        with mock.patch("osint._session", return_value=session):
            result = osint.wayback_snapshots("example.com")
        self.assertFalse(result["success"])
        self.assertEqual(session.get.call_count, 1)


class SharedFetchHelperTests(unittest.TestCase):
    """The retry-on-timeout logic had been written three times; OTX and
    Wayback now share one implementation.
    """

    def test_both_slow_sources_use_the_shared_helper(self):
        import inspect
        self.assertIn("_fetch_json", inspect.getsource(osint.wayback_snapshots))
        self.assertIn("_fetch_json", inspect.getsource(osint.otx_lookup))

    def test_auth_failure_short_circuits_only_when_a_message_is_given(self):
        # Real requests raises on a 403; the mock must do the same or the
        # test proves nothing about the fall-through path.
        forbidden = _resp(403)
        forbidden.raise_for_status.side_effect = requests.HTTPError("403 Forbidden")
        session = mock.Mock()
        session.get.return_value = forbidden

        # Without auth_message a 403 falls through to raise_for_status.
        data, error = osint._fetch_json(session, "https://x/", label="X", timeout=5)
        self.assertIsNone(data)
        self.assertIn("403", error)

        # With one, it is named up front and not retried.
        session.get.reset_mock()
        data, error = osint._fetch_json(
            session, "https://x/", label="X", timeout=5, auth_message="X rejected the key")
        self.assertIsNone(data)
        self.assertEqual(error, "X rejected the key")
        self.assertEqual(session.get.call_count, 1)

    def test_timeout_message_names_the_source(self):
        session = mock.Mock()
        session.get.side_effect = requests.Timeout("boom")
        data, error = osint._fetch_json(session, "https://x/", label="Some API", timeout=7)
        self.assertIsNone(data)
        self.assertEqual(error, "Some API did not respond within 7s")


if __name__ == "__main__":
    unittest.main()
