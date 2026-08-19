import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


class ScanCacheTests(unittest.TestCase):
    """Every scan asked crt.sh and the OSINT feeds again, so a daily monitor
    plus a few manual scans of one domain hit them repeatedly for an answer
    that had not moved. crt.sh is chronically overloaded; not asking is the
    most useful thing we can do for it.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "cache.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import scan_cache as sc_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.sc = importlib.reload(sc_module)

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _age_entry(self, kind, domain, hours):
        stamp = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with self.db._lock, self.db._connect() as conn:
            conn.execute("UPDATE external_cache SET created_at = ? WHERE cache_key = ?",
                         (stamp, f"{kind}:{domain}"))

    def test_a_stored_lookup_is_reused(self):
        self.sc.store(self.sc.KIND_OSINT, "example.com", {"success": True, "n": 1})
        hit = self.sc.lookup(self.sc.KIND_OSINT, "example.com")
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0]["n"], 1)

    def test_an_expired_entry_is_not_reused(self):
        self.sc.store(self.sc.KIND_OSINT, "example.com", {"success": True})
        self._age_entry(self.sc.KIND_OSINT, "example.com", 25)
        self.assertIsNone(self.sc.lookup(self.sc.KIND_OSINT, "example.com"))

    def test_force_bypasses_a_fresh_entry(self):
        self.sc.store(self.sc.KIND_OSINT, "example.com", {"success": True})
        self.assertIsNone(self.sc.lookup(self.sc.KIND_OSINT, "example.com", force=True))

    def test_kinds_and_domains_do_not_collide(self):
        self.sc.store(self.sc.KIND_OSINT, "example.com", {"which": "osint"})
        self.sc.store(self.sc.KIND_CRTSH, "example.com", [{"which": "crtsh"}])
        self.sc.store(self.sc.KIND_OSINT, "other.com", {"which": "other"})
        self.assertEqual(self.sc.lookup(self.sc.KIND_OSINT, "example.com")[0]["which"], "osint")
        self.assertEqual(self.sc.lookup(self.sc.KIND_CRTSH, "example.com")[0][0]["which"], "crtsh")
        self.assertEqual(self.sc.lookup(self.sc.KIND_OSINT, "other.com")[0]["which"], "other")

    def test_a_second_store_replaces_the_first(self):
        self.sc.store(self.sc.KIND_OSINT, "example.com", {"v": 1})
        self.sc.store(self.sc.KIND_OSINT, "example.com", {"v": 2})
        self.assertEqual(self.sc.lookup(self.sc.KIND_OSINT, "example.com")[0]["v"], 2)

    def test_cached_results_are_labelled(self):
        marked = self.sc.mark({"success": True}, 7200)
        self.assertTrue(marked["cached"])
        self.assertEqual(marked["cache_age_seconds"], 7200)
        self.assertIn("cached_at", marked)

    def test_a_cached_result_never_pretends_to_be_fresh(self):
        self.sc.store(self.sc.KIND_OSINT, "example.com", {"success": True})
        result = self.sc.cached_call(
            self.sc.KIND_OSINT, "example.com",
            lambda: self.fail("producer must not run on a cache hit"))
        self.assertTrue(result["cached"])

    def test_a_failed_lookup_is_not_cached(self):
        # Otherwise one outage gets replayed for the rest of the day.
        self.sc.cached_call(self.sc.KIND_OSINT, "example.com",
                            lambda: {"success": False, "error": "feed down"})
        self.assertIsNone(self.sc.lookup(self.sc.KIND_OSINT, "example.com"))

    def test_a_successful_lookup_is_cached(self):
        calls = []

        def producer():
            calls.append(1)
            return {"success": True, "n": len(calls)}

        first = self.sc.cached_call(self.sc.KIND_OSINT, "example.com", producer)
        second = self.sc.cached_call(self.sc.KIND_OSINT, "example.com", producer)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("cached", first)
        self.assertTrue(second["cached"])

    def test_force_reruns_the_producer(self):
        calls = []
        producer = lambda: (calls.append(1), {"success": True})[1]
        self.sc.cached_call(self.sc.KIND_OSINT, "example.com", producer)
        self.sc.cached_call(self.sc.KIND_OSINT, "example.com", producer, force=True)
        self.assertEqual(len(calls), 2)

    def test_disabling_the_cache_always_runs_the_producer(self):
        with mock.patch.object(self.sc, "_config", return_value={"enabled": False}):
            calls = []
            producer = lambda: (calls.append(1), {"success": True})[1]
            self.sc.cached_call(self.sc.KIND_OSINT, "example.com", producer)
            self.sc.cached_call(self.sc.KIND_OSINT, "example.com", producer)
            self.assertEqual(len(calls), 2)

    def test_ttl_is_configurable(self):
        with mock.patch.object(self.sc, "_config", return_value={"ttl_hours": 48}):
            self.sc.store(self.sc.KIND_OSINT, "example.com", {"success": True})
            self._age_entry(self.sc.KIND_OSINT, "example.com", 30)
            self.assertIsNotNone(self.sc.lookup(self.sc.KIND_OSINT, "example.com"))

    def test_clearing_removes_entries(self):
        self.sc.store(self.sc.KIND_OSINT, "example.com", {"a": 1})
        self.sc.store(self.sc.KIND_CRTSH, "example.com", [1])
        self.db.external_cache_clear(kind=self.sc.KIND_OSINT)
        self.assertIsNone(self.sc.lookup(self.sc.KIND_OSINT, "example.com"))
        self.assertIsNotNone(self.sc.lookup(self.sc.KIND_CRTSH, "example.com"))

    def test_a_broken_cache_never_fails_a_scan(self):
        with mock.patch.object(self.db, "external_cache_get", side_effect=RuntimeError("boom")), \
             mock.patch.object(self.sc, "db", self.db):
            self.assertIsNone(self.sc.lookup(self.sc.KIND_OSINT, "example.com"))


class CrtShCacheTests(unittest.TestCase):
    """crt.sh is asked twice inside one scan (CT tab and subdomain
    enumeration) and again by tomorrow's monitor run."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "cache.db")
        import importlib
        import db as db_module
        import scan_cache as sc_module
        import crtsh as crtsh_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.sc = importlib.reload(sc_module)
        self.crtsh = importlib.reload(crtsh_module)

    def tearDown(self):
        self.tempdir.cleanup()
        os.environ.pop("DOMAINLENS_DB", None)

    def _ok(self, rows):
        resp = mock.Mock(status_code=200)
        resp.json.return_value = rows
        return resp

    def test_a_second_fetch_does_not_hit_the_network(self):
        with mock.patch("crtsh.requests.get", return_value=self._ok([{"name_value": "a.example.com"}])) as get:
            self.crtsh.fetch("example.com")
            self.crtsh.fetch("example.com")
        self.assertEqual(get.call_count, 1)

    def test_the_cached_answer_is_the_same_data(self):
        rows = [{"name_value": "a.example.com"}]
        with mock.patch("crtsh.requests.get", return_value=self._ok(rows)):
            first, _ = self.crtsh.fetch("example.com")
            second, _ = self.crtsh.fetch("example.com")
        self.assertEqual(first, second)

    def test_a_cache_hit_is_reported_as_such(self):
        with mock.patch("crtsh.requests.get", return_value=self._ok([])):
            self.crtsh.fetch("example.com")
            _rows, _err, meta = self.crtsh.fetch_detailed("example.com")
        self.assertTrue(meta["cached"])

    def test_force_goes_back_to_the_network(self):
        with mock.patch("crtsh.requests.get", return_value=self._ok([])) as get:
            self.crtsh.fetch("example.com")
            self.crtsh.fetch("example.com", force=True)
        self.assertEqual(get.call_count, 2)

    def test_an_outage_is_not_cached(self):
        bad = mock.Mock(status_code=502)
        with mock.patch("crtsh.requests.get", return_value=bad), \
             mock.patch("crtsh.time.sleep"):
            rows, error = self.crtsh.fetch("example.com", attempts=1)
        self.assertIsNone(rows)
        self.assertIsNone(self.sc.lookup(self.sc.KIND_CRTSH, "example.com"))
        # And the next attempt must go back out rather than replay the failure.
        with mock.patch("crtsh.requests.get", return_value=self._ok([])) as get:
            self.crtsh.fetch("example.com")
        self.assertEqual(get.call_count, 1)

    def test_an_empty_result_is_still_a_real_answer(self):
        # crt.sh returns 200 with [] for a domain with no logged certificates;
        # that is an answer worth caching, not a failure.
        with mock.patch("crtsh.requests.get", return_value=self._ok([])) as get:
            self.crtsh.fetch("example.com")
            self.crtsh.fetch("example.com")
        self.assertEqual(get.call_count, 1)

    def test_enumeration_passes_the_cache_state_up(self):
        import security_checks
        with mock.patch("crtsh.requests.get", return_value=self._ok([])):
            self.crtsh.fetch("example.com")
            _subs, _n, _err, meta = security_checks.enumerate_subdomains("example.com")
        self.assertTrue(meta["cached"])


class ForceRefreshRequestTests(unittest.TestCase):
    """Refreshing has to be asked for; if it were the default the cache would
    never be used and nothing would change."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "cache.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _params(self, body):
        with self.app_module.app.test_request_context(json=body):
            params, error = self.app_module._scan_request_params()
        return params, error

    def test_default_is_not_forced(self):
        params, _ = self._params({"domain": "example.com"})
        self.assertFalse(params["force_refresh"])

    def test_force_refresh_is_accepted(self):
        params, _ = self._params({"domain": "example.com", "force_refresh": True})
        self.assertTrue(params["force_refresh"])

    def test_refresh_alias_is_accepted(self):
        params, _ = self._params({"domain": "example.com", "refresh": True})
        self.assertTrue(params["force_refresh"])

    def test_it_reaches_the_scan(self):
        seen = {}

        def fake(domain, checks, extra_dkim_selectors=None, progress_cb=None,
                 force_refresh=False):
            seen["force"] = force_refresh
            return {"domain": domain}

        with mock.patch.object(self.app_module, "run_selected_checks", fake):
            self.client.post("/api/scan", json={"domain": "example.com",
                                                "force_refresh": True,
                                                "save_history": False})
        self.assertTrue(seen["force"])


if __name__ == "__main__":
    unittest.main()


class StaleFallbackTests(unittest.TestCase):
    """crt.sh is down often enough that returning nothing blanks the subdomain
    section for hours. The last answer known to be real is more use than no
    answer — provided it is dated, so it is never read as current.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "cache.db")
        import importlib
        import db as db_module
        import scan_cache as sc_module
        import crtsh as crtsh_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.sc = importlib.reload(sc_module)
        self.crtsh = importlib.reload(crtsh_module)

    def tearDown(self):
        self.tempdir.cleanup()
        os.environ.pop("DOMAINLENS_DB", None)

    def _age(self, hours):
        stamp = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with self.db._lock, self.db._connect() as conn:
            conn.execute("UPDATE external_cache SET created_at = ? WHERE kind = ?",
                         (stamp, self.sc.KIND_CRTSH))

    def _seed(self, rows, hours):
        ok = mock.Mock(status_code=200)
        ok.json.return_value = rows
        with mock.patch("crtsh.requests.get", return_value=ok):
            self.crtsh.fetch("example.com")
        self._age(hours)

    def _outage(self, attempts=1):
        bad = mock.Mock(status_code=502)
        with mock.patch("crtsh.requests.get", return_value=bad), \
             mock.patch("crtsh.time.sleep"):
            return self.crtsh.fetch_detailed("example.com", attempts=attempts)

    def test_an_expired_entry_is_served_during_an_outage(self):
        rows = [{"name_value": "a.example.com"}]
        self._seed(rows, hours=48)
        got, error, meta = self._outage()
        self.assertEqual(got, rows)
        self.assertTrue(meta["stale"])

    def test_the_moment_of_the_last_success_is_reported(self):
        self._seed([{"name_value": "a.example.com"}], hours=48)
        _rows, _err, meta = self._outage()
        self.assertIn("cached_at", meta)
        self.assertGreater(meta["cache_age_seconds"], 47 * 3600)

    def test_the_outage_travels_with_the_stale_data(self):
        # Serving old data silently would be the worst of both worlds.
        self._seed([], hours=48)
        _rows, _err, meta = self._outage()
        self.assertIn("502", meta["outage"])

    def test_no_error_is_raised_when_stale_data_covers_the_outage(self):
        # The subdomain section must not print "lookup failed, only the apex
        # was checked" when it did in fact check a real list.
        self._seed([{"name_value": "a.example.com"}], hours=48)
        _rows, error, _meta = self._outage()
        self.assertIsNone(error)

    def test_a_fresh_entry_is_not_marked_stale(self):
        self._seed([{"name_value": "a.example.com"}], hours=1)
        _rows, _err, meta = self.crtsh.fetch_detailed("example.com")
        self.assertTrue(meta["cached"])
        self.assertFalse(meta["stale"])

    def test_data_older_than_the_stale_limit_is_withheld(self):
        # A months-old certificate list looks like coverage it cannot provide.
        self._seed([{"name_value": "a.example.com"}], hours=24 * 30)
        rows, error, meta = self._outage()
        self.assertIsNone(rows)
        self.assertIn("502", error)
        self.assertFalse(meta["cached"])

    def test_force_does_not_fall_back_to_stale_data(self):
        # Asking explicitly for fresh data and silently getting old data back
        # would defeat the point of asking.
        self._seed([{"name_value": "a.example.com"}], hours=48)
        bad = mock.Mock(status_code=502)
        with mock.patch("crtsh.requests.get", return_value=bad), \
             mock.patch("crtsh.time.sleep"):
            rows, error, _meta = self.crtsh.fetch_detailed(
                "example.com", attempts=1, force=True)
        self.assertIsNone(rows)
        self.assertIn("502", error)

    def test_an_outage_with_no_cache_at_all_still_reports_the_failure(self):
        rows, error, meta = self._outage()
        self.assertIsNone(rows)
        self.assertIn("502", error)
        self.assertFalse(meta["cached"])

    def test_the_subdomain_result_carries_the_staleness(self):
        import security_checks
        self._seed([{"name_value": "a.example.com"}], hours=48)
        bad = mock.Mock(status_code=502)
        with mock.patch("crtsh.requests.get", return_value=bad), \
             mock.patch("crtsh.time.sleep"), \
             mock.patch("security_checks._check_one_takeover", return_value=None):
            result = security_checks.check_subdomain_takeover("example.com")
        self.assertTrue(result["source_stale"])
        self.assertIsNone(result["source_error"])
        self.assertIn("502", result["source_outage"])

    def test_stale_coverage_is_still_not_a_finding(self):
        import security_checks
        audit = {"subdomains": {
            "success": True, "takeovers": [], "dangling": [],
            "source_stale": True, "source_outage": "crt.sh 502",
        }}
        self.assertEqual(security_checks.audit_findings(audit), [])
