"""crt.sh is asked once more after a fast failure, not after a timeout.

Three tries of 20 seconds with pauses in between made one crt.sh outage cost
a full scan over a minute (64.5 s), and the Security audit was the slowest
part of every cold scan. A query that did not answer within 20 seconds is
crt.sh overloaded on that query; asking the same heavy query again did not
make an answer more likely. A 502 or a dropped connection comes back in a
second, and those are still retried.
"""

import os
import tempfile
import unittest
from unittest import mock

import requests

import crtsh
import scan_cache

_tempdir = None


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "crtsh-timeout.db")
    import db
    db.init_db()


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


def _resp(status, payload=None):
    r = mock.Mock(status_code=status)
    r.json.return_value = payload if payload is not None else []
    return r


class CrtshTimeoutTests(unittest.TestCase):
    def setUp(self):
        import db
        with db._lock, db._connect() as conn:
            conn.execute("DELETE FROM external_cache")

    def test_a_timeout_is_not_asked_again(self):
        with mock.patch("crtsh.requests.get", side_effect=requests.ReadTimeout("read timed out")) as get, \
                mock.patch("crtsh.time.sleep") as sleep:
            rows, error = crtsh.fetch("example.com")
        self.assertIsNone(rows)
        self.assertEqual(1, get.call_count)
        sleep.assert_not_called()
        self.assertIn("did not answer within 20s", error)
        self.assertIn("not a problem with the scanned domain", error)

    def test_a_fast_failure_is_still_retried(self):
        rows = [{"name_value": "www.example.com"}]
        with mock.patch("crtsh.requests.get", side_effect=[_resp(502), _resp(200, rows)]) as get, \
                mock.patch("crtsh.time.sleep"):
            got, error = crtsh.fetch("example.com")
        self.assertEqual(rows, got)
        self.assertIsNone(error)
        self.assertEqual(2, get.call_count)

    def test_after_a_timeout_the_last_known_list_is_shown_as_such(self):
        rows = [{"name_value": "www.example.com"}]
        scan_cache.store(scan_cache.KIND_CRTSH, "example.com", rows)
        with mock.patch("crtsh.scan_cache.lookup", return_value=None), \
                mock.patch("crtsh.requests.get", side_effect=requests.ReadTimeout("read timed out")):
            got, error, meta = crtsh.fetch_detailed("example.com")
        self.assertEqual(rows, got)
        self.assertIsNone(error)
        self.assertTrue(meta["stale"])
        self.assertIn("did not answer", meta["outage"])


if __name__ == "__main__":
    unittest.main()
