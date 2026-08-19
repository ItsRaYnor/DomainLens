import os
import tempfile
import threading
import time
import unittest
from datetime import timedelta
from unittest import mock

import scan_jobs


class ScanJobRegistryTests(unittest.TestCase):
    """Scanning was a single synchronous request, so there was no progress to
    show, navigating away threw the result away, and nothing stopped a second
    scan of the same domain being started on top of the first.
    """

    def setUp(self):
        scan_jobs.reset()

    def tearDown(self):
        scan_jobs.reset()

    def _runner(self, steps=4, delay=0.01, result=None, raises=None):
        def runner(progress_cb):
            for i in range(1, steps + 1):
                progress_cb(i, steps, f"check{i}")
                time.sleep(delay)
            if raises:
                raise raises
            return result if result is not None else {"ok": True}
        return runner

    def _wait(self, job_id, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = scan_jobs.get(job_id)
            if job["status"] != "running":
                return job
            time.sleep(0.01)
        self.fail("job did not finish in time")

    def test_job_starts_running_and_finishes(self):
        job = scan_jobs.start("example.com", self._runner())
        self.assertEqual(job["status"], "running")
        finished = self._wait(job["job_id"])
        self.assertEqual(finished["status"], "done")
        self.assertEqual(finished["percent"], 100)

    def test_result_is_only_returned_when_asked_for(self):
        job = scan_jobs.start("example.com", self._runner(result={"scan_id": 7}))
        self._wait(job["job_id"])
        self.assertNotIn("result", scan_jobs.get(job["job_id"]))
        full = scan_jobs.get(job["job_id"], include_result=True)
        self.assertEqual(full["result"], {"scan_id": 7})
        self.assertEqual(full["scan_id"], 7)

    def test_progress_is_reported(self):
        seen = []
        started = threading.Event()

        def runner(progress_cb):
            for i in range(1, 5):
                progress_cb(i, 4, f"check{i}")
                started.set()
                time.sleep(0.05)
            return {}

        job = scan_jobs.start("example.com", runner)
        started.wait(2)
        for _ in range(20):
            snapshot = scan_jobs.get(job["job_id"])
            seen.append(snapshot["percent"])
            if snapshot["status"] != "running":
                break
            time.sleep(0.02)
        self.assertTrue(any(0 < p < 100 for p in seen), seen)

    def test_percent_never_reaches_100_while_still_running(self):
        """A bar sitting at 100% while work continues reads as a hang."""
        gate = threading.Event()

        def runner(progress_cb):
            progress_cb(4, 4, "last")   # every check done...
            gate.wait(2)                 # ...but the result is not stored yet
            return {}

        job = scan_jobs.start("example.com", runner)
        time.sleep(0.05)
        mid = scan_jobs.get(job["job_id"])
        self.assertEqual(mid["status"], "running")
        self.assertEqual(mid["percent"], 99)
        gate.set()
        self.assertEqual(self._wait(job["job_id"])["percent"], 100)

    def test_failure_is_recorded_not_raised(self):
        job = scan_jobs.start("example.com", self._runner(raises=RuntimeError("boom")))
        finished = self._wait(job["job_id"])
        self.assertEqual(finished["status"], "error")
        self.assertIn("boom", finished["error"])

    # --- duplicate prevention ---

    def test_active_job_is_found_by_domain(self):
        job = scan_jobs.start("example.com", self._runner(delay=0.05))
        active = scan_jobs.find_active("example.com")
        self.assertEqual(active["job_id"], job["job_id"])
        self._wait(job["job_id"])

    def test_no_active_job_for_a_different_domain(self):
        job = scan_jobs.start("example.com", self._runner(delay=0.05))
        self.assertIsNone(scan_jobs.find_active("other.com"))
        self._wait(job["job_id"])

    def test_finished_job_is_no_longer_active(self):
        job = scan_jobs.start("example.com", self._runner())
        self._wait(job["job_id"])
        self.assertIsNone(scan_jobs.find_active("example.com"))

    def test_a_stuck_job_stops_blocking_the_domain(self):
        job = scan_jobs.start("example.com", self._runner(delay=0.01))
        self._wait(job["job_id"])
        # Force it back to a running state that started long ago.
        with scan_jobs._lock:
            stored = scan_jobs._jobs[job["job_id"]]
            stored["status"] = "running"
            stored["started_at"] = scan_jobs._now() - timedelta(
                seconds=scan_jobs._MAX_RUNTIME_SECONDS + 10)
        self.assertIsNone(scan_jobs.find_active("example.com"))
        self.assertEqual(scan_jobs.get(job["job_id"])["status"], "error")

    # --- housekeeping ---

    def test_unknown_job_returns_none(self):
        self.assertIsNone(scan_jobs.get("does-not-exist"))

    def test_finished_jobs_are_pruned_after_retention(self):
        job = scan_jobs.start("example.com", self._runner())
        self._wait(job["job_id"])
        with scan_jobs._lock:
            scan_jobs._jobs[job["job_id"]]["finished_at"] = scan_jobs._now() - timedelta(
                seconds=scan_jobs._RETENTION_SECONDS + 10)
        scan_jobs.start("other.com", self._runner())  # triggers a prune
        self.assertIsNone(scan_jobs.get(job["job_id"]))


class ScanJobEndpointTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "jobs.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()
        scan_jobs.reset()

    def tearDown(self):
        scan_jobs.reset()
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _slow_scan(self, gate):
        def fake(domain, checks, extra, save_history=True, progress_cb=None,
                 force_refresh=False):
            if progress_cb:
                progress_cb(1, 2, "dns")
            gate.wait(3)
            return {"domain": domain, "scan_id": 1}
        return fake

    def test_start_returns_a_job(self):
        with mock.patch.object(self.app_module, "_perform_scan",
                               return_value={"domain": "example.com"}):
            resp = self.client.post("/api/scan/start", json={"domain": "example.com"})
        self.assertEqual(resp.status_code, 202)
        self.assertIn("job_id", resp.get_json())

    def test_second_scan_of_the_same_domain_is_refused(self):
        gate = threading.Event()
        with mock.patch.object(self.app_module, "_perform_scan",
                               side_effect=self._slow_scan(gate)):
            first = self.client.post("/api/scan/start", json={"domain": "example.com"})
            second = self.client.post("/api/scan/start", json={"domain": "example.com"})
            self.assertEqual(second.status_code, 409)
            body = second.get_json()
            self.assertTrue(body["already_running"])
            # It hands back the job already in flight, so the caller can follow it.
            self.assertEqual(body["job_id"], first.get_json()["job_id"])
            gate.set()

    def test_a_different_domain_may_scan_concurrently(self):
        gate = threading.Event()
        with mock.patch.object(self.app_module, "_perform_scan",
                               side_effect=self._slow_scan(gate)):
            self.client.post("/api/scan/start", json={"domain": "example.com"})
            other = self.client.post("/api/scan/start", json={"domain": "other.com"})
            self.assertEqual(other.status_code, 202)
            gate.set()

    def test_active_endpoint_reports_the_running_job(self):
        gate = threading.Event()
        with mock.patch.object(self.app_module, "_perform_scan",
                               side_effect=self._slow_scan(gate)):
            started = self.client.post("/api/scan/start", json={"domain": "example.com"})
            active = self.client.get("/api/scan/active?domain=example.com").get_json()
            self.assertEqual(active["job"]["job_id"], started.get_json()["job_id"])
            gate.set()

    def test_active_endpoint_is_empty_without_a_scan(self):
        active = self.client.get("/api/scan/active?domain=example.com").get_json()
        self.assertIsNone(active["job"])

    def test_status_of_an_unknown_job_is_404(self):
        self.assertEqual(self.client.get("/api/scan/status/nope").status_code, 404)

    def test_invalid_domain_is_rejected(self):
        resp = self.client.post("/api/scan/start", json={"domain": "not a domain"})
        self.assertEqual(resp.status_code, 400)

    def test_synchronous_endpoint_still_works(self):
        # Existing API consumers must keep their blocking call.
        with mock.patch.object(self.app_module, "_perform_scan",
                               return_value={"domain": "example.com", "scan_id": 3}):
            resp = self.client.post("/api/scan", json={"domain": "example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["scan_id"], 3)


if __name__ == "__main__":
    unittest.main()
