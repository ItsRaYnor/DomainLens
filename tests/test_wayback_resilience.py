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

    The CDX API was queried with url=domain/*, which made the server walk
    every capture of the whole domain. It is now asked for the homepage only,
    which answers in about a second, but an outage still needs a budget.
    """

    def test_wayback_gets_a_longer_timeout_than_the_shared_one(self):
        self.assertGreater(osint._WAYBACK_TIMEOUT, osint._TIMEOUT)

    def test_a_timeout_is_not_asked_again(self):
        """A second try after a timeout doubled the OSINT wait to a minute
        during archive outages, and the second try timed out as well."""
        session = mock.Mock()
        session.get.side_effect = [requests.Timeout("read timed out"), _resp(200, [])]
        with mock.patch("osint._session", return_value=session):
            result = osint.wayback_snapshots("example.com")
        self.assertFalse(result["success"])
        self.assertEqual(session.get.call_count, 1)

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
        self.assertIn("_wayback_fetch", inspect.getsource(osint.wayback_snapshots))
        self.assertIn("_fetch_json", inspect.getsource(osint._wayback_fetch))
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
        # Ends in the marker a cache reads as "may pass": not kept for a day.
        self.assertEqual(error, "Some API did not respond within 7s. Not measured; try again later.")


if __name__ == "__main__":
    unittest.main()
