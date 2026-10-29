"""A full scan asks crt.sh for the same domain from three places at once.

OSINT, takeover enumeration and the CAA check each sent their own request
and their own retries. During a crt.sh outage that was up to nine requests
per scan to a service that is down because it is overloaded, and the tabs
could disagree about the same certificate list. Concurrent lookups of one
domain now share a single request.
"""

import inspect
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

import crtsh
import osint
import security_checks

_tempdir = None


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "crtsh-shared.db")
    import db
    db.init_db()


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


def _resp(status, payload=None):
    r = mock.Mock(status_code=status)
    r.json.return_value = payload if payload is not None else []
    return r


def _wait_for(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return False


def _waiters(domain):
    flight = getattr(crtsh, "_flights", {}).get(domain)
    return flight.waiters if flight else 0


class SharedLookupTests(unittest.TestCase):
    def setUp(self):
        import db
        with db._lock, db._connect() as conn:
            conn.execute("DELETE FROM external_cache")
        getattr(crtsh, "_flights", {}).clear()

    def _run_two(self, getter, first=None, second=None):
        """Start one lookup, let it reach crt.sh, then start a second for the
        same domain while the first is still waiting for the answer."""
        first = first or {}
        second = second or {}
        results = {}
        release = threading.Event()
        entered = threading.Event()

        def slow_get(*args, **kwargs):
            entered.set()
            release.wait(5)
            return getter(*args, **kwargs)

        with mock.patch("crtsh.requests.get", side_effect=slow_get) as get, \
                mock.patch("crtsh.time.sleep"):
            a = threading.Thread(target=lambda: results.__setitem__(
                "first", crtsh.fetch_detailed("example.com", **first)))
            a.start()
            self.assertTrue(entered.wait(5), "the first lookup never reached crt.sh")
            b = threading.Thread(target=lambda: results.__setitem__(
                "second", crtsh.fetch_detailed("example.com", **second)))
            b.start()
            joined = _wait_for(lambda: _waiters("example.com") == 1, seconds=2)
            release.set()
            a.join(10)
            b.join(10)
        return results, get, joined

    def test_a_second_caller_joins_the_lookup_already_under_way(self):
        rows = [{"name_value": "www.example.com"}]
        results, get, joined = self._run_two(lambda *a, **k: _resp(200, rows))
        self.assertTrue(joined, "the second caller sent its own request instead of joining")
        self.assertEqual(get.call_count, 1)
        self.assertEqual(results["first"][0], rows)
        self.assertEqual(results["second"][0], rows)
        self.assertIsNone(results["second"][1])

    def test_an_outage_is_asked_about_once_not_once_per_caller(self):
        """Three tries by one caller already say crt.sh is down; three more
        by the next caller only add load to a service that is overloaded."""
        results, get, joined = self._run_two(lambda *a, **k: _resp(502))
        self.assertTrue(joined)
        self.assertEqual(get.call_count, 3)
        for key in ("first", "second"):
            rows, error, _meta = results[key]
            self.assertIsNone(rows)
            self.assertIn("outage at crt.sh", error)

    def test_a_less_patient_lookup_does_not_answer_for_a_more_patient_caller(self):
        """A failure after one try is not the answer for a caller that would
        have tried three times: that would turn a shorter wait into a
        missing measurement."""
        calls = iter([_resp(502), _resp(200, [{"name_value": "a.example.com"}])])
        results, get, joined = self._run_two(
            lambda *a, **k: next(calls), first={"attempts": 1}, second={"attempts": 3})
        self.assertTrue(joined)
        self.assertIsNone(results["first"][0])
        self.assertEqual(results["second"][0], [{"name_value": "a.example.com"}])
        self.assertEqual(get.call_count, 2)

    def test_different_domains_are_not_merged(self):
        seen = []

        def get(url, **kwargs):
            seen.append(url)
            return _resp(200, [])

        with mock.patch("crtsh.requests.get", side_effect=get), mock.patch("crtsh.time.sleep"):
            crtsh.fetch_detailed("example.com")
            crtsh.fetch_detailed("example.org")
        self.assertEqual(len(seen), 2)
        self.assertIn("example.org", seen[1])

    def test_the_lookup_is_forgotten_once_it_is_done(self):
        """A finished lookup left behind would hand its answer to tomorrow's
        scan without the cache's age check."""
        with mock.patch("crtsh.requests.get", return_value=_resp(502)), mock.patch("crtsh.time.sleep"):
            crtsh.fetch_detailed("example.com")
        self.assertNotIn("example.com", getattr(crtsh, "_flights", {}))

    def test_osint_asks_as_patiently_as_the_security_audit(self):
        """OSINT asked with a 12 second timeout and the security audit with
        20, so OSINT could never stand in for the audit's lookup and the two
        could not share one request."""
        osint_timeout = inspect.signature(crtsh.fetch).parameters["timeout"].default
        source = inspect.getsource(osint.certificate_transparency)
        self.assertNotIn("timeout=", source.split("crtsh.fetch(", 1)[1].split(")", 1)[0])
        audit_timeout = inspect.signature(security_checks._fetch_crtsh).parameters["timeout"].default
        self.assertGreaterEqual(osint_timeout, audit_timeout)


if __name__ == "__main__":
    unittest.main()
