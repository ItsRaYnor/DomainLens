"""The Wayback lookup asks for the homepage's recent captures, and its dates
mean what they say.

The CDX query used url=<domain>/*, which made the archive walk every capture
of every page: 5 to 60 seconds, or a 503, and often the slowest part of a
whole scan. It also asked for the first 15 days in the archive, so "last
seen" was the 15th capture ever made, years ago for an old domain, while the
site had been archived yesterday.
"""

import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse

import requests

import osint

HEADER = ["timestamp", "original", "statuscode"]


def _resp(payload):
    r = mock.Mock(status_code=200)
    r.json.return_value = payload
    r.raise_for_status = mock.Mock()
    return r


def _query(call):
    return parse_qs(urlparse(call.args[0]).query)


class WaybackQueryTests(unittest.TestCase):
    def _run(self, recent, first):
        session = mock.Mock()
        session.get.side_effect = [recent, first]
        with mock.patch("osint._session", return_value=session):
            result = osint.wayback_snapshots("example.com")
        return result, session

    def test_the_archive_is_asked_for_the_homepage_not_every_page(self):
        recent = _resp([HEADER, ["20261020000000", "https://example.com/", "200"]])
        first = _resp([HEADER, ["20020120142510", "http://example.com:80/", "200"]])
        _result, session = self._run(recent, first)
        for call in session.get.call_args_list:
            self.assertEqual(["example.com"], _query(call)["url"])

    def test_last_seen_is_the_newest_capture(self):
        recent = _resp([HEADER,
                        ["20261019000000", "https://example.com/", "200"],
                        ["20261020000000", "https://example.com/", "200"]])
        first = _resp([HEADER, ["20020120142510", "http://example.com:80/", "200"]])
        result, session = self._run(recent, first)
        self.assertEqual("-15", _query(session.get.call_args_list[0])["limit"][0])
        self.assertEqual("20261020000000", result["last_seen"])
        self.assertEqual(2, result["count"])

    def test_first_seen_is_the_first_capture_ever_not_the_oldest_recent_one(self):
        recent = _resp([HEADER, ["20261019000000", "https://example.com/", "200"]])
        first = _resp([HEADER, ["20020120142510", "http://example.com:80/", "200"]])
        result, session = self._run(recent, first)
        self.assertEqual("1", _query(session.get.call_args_list[1])["limit"][0])
        self.assertEqual("20020120142510", result["first_seen"])

    def test_an_unanswered_first_capture_question_leaves_first_seen_unmeasured(self):
        """Filling it from the recent captures would state a first-seen date
        that is only the start of the window that was asked for."""
        recent = _resp([HEADER, ["20261019000000", "https://example.com/", "200"]])
        result, _session = self._run(recent, requests.Timeout("read timed out"))
        self.assertTrue(result["success"])
        self.assertIsNone(result["first_seen"])
        self.assertIn("Wayback Machine", result["first_seen_error"])
        self.assertEqual("20261019000000", result["last_seen"])

    def test_a_domain_never_archived_asks_only_once(self):
        session = mock.Mock()
        session.get.return_value = _resp([HEADER])
        with mock.patch("osint._session", return_value=session):
            result = osint.wayback_snapshots("example.com")
        self.assertTrue(result["success"])
        self.assertEqual(0, result["count"])
        self.assertEqual(1, session.get.call_count)


if __name__ == "__main__":
    unittest.main()
