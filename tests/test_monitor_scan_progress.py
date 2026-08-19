import os
import pathlib
import tempfile
import time
import unittest
from unittest import mock

import scan_jobs


class MonitorScanProgressTests(unittest.TestCase):
    """"Run now" posted to a synchronous endpoint and sat there until every
    check had finished, so there was no progress, no percentage and no sign
    the click had registered. Manual scans already ran as background jobs;
    monitor scans did not.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "mon.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()
        scan_jobs.reset()

        self.monitor_id = self.db.create_monitor(
            name="m1", domain="example.com", target="example.com", record_type="A")

    def tearDown(self):
        scan_jobs.reset()
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _wait(self, job_id, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = scan_jobs.get(job_id, include_result=True)
            if job and job["status"] != "running":
                return job
            time.sleep(0.01)
        self.fail("job did not finish in time")

    def _fake_scan(self, progress=(("dns", 1, 2), ("ssl", 2, 2))):
        def fake(monitor, progress_cb=None):
            for name, done, total in progress:
                if progress_cb:
                    progress_cb(done, total, name)
            return {"monitor": monitor, "scan_id": 99,
                    "results": {"domain": "example.com"}, "event": {}}
        return fake

    def test_start_returns_a_job_immediately(self):
        with mock.patch.object(self.app_module, "_scan_monitor", self._fake_scan()):
            resp = self.client.post(f"/api/monitors/{self.monitor_id}/scan/start")
            self.assertEqual(resp.status_code, 202)
            body = resp.get_json()
            self.assertIn("job_id", body)
            self.assertEqual(body["domain"], "example.com")
            self._wait(body["job_id"])

    def test_progress_reaches_the_job(self):
        with mock.patch.object(self.app_module, "_scan_monitor", self._fake_scan()):
            job_id = self.client.post(
                f"/api/monitors/{self.monitor_id}/scan/start").get_json()["job_id"]
            finished = self._wait(job_id)
        self.assertEqual(finished["status"], "done")
        self.assertEqual(finished["percent"], 100)
        self.assertEqual(finished["scan_id"], 99)

    def test_the_outcome_is_carried_on_the_job(self):
        with mock.patch.object(self.app_module, "_scan_monitor", self._fake_scan()):
            job_id = self.client.post(
                f"/api/monitors/{self.monitor_id}/scan/start").get_json()["job_id"]
            finished = self._wait(job_id)
        # The monitor outcome wraps the results; the client unwraps it.
        self.assertEqual(finished["result"]["results"]["domain"], "example.com")

    def test_status_endpoint_serves_a_monitor_job(self):
        with mock.patch.object(self.app_module, "_scan_monitor", self._fake_scan()):
            job_id = self.client.post(
                f"/api/monitors/{self.monitor_id}/scan/start").get_json()["job_id"]
            self._wait(job_id)
            resp = self.client.get(f"/api/scan/status/{job_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "done")

    def test_a_failing_scan_becomes_a_job_error(self):
        def boom(monitor, progress_cb=None):
            raise ValueError("resolver exploded")

        with mock.patch.object(self.app_module, "_scan_monitor", boom):
            job_id = self.client.post(
                f"/api/monitors/{self.monitor_id}/scan/start").get_json()["job_id"]
            finished = self._wait(job_id)
        self.assertEqual(finished["status"], "error")
        self.assertIn("resolver exploded", finished["error"])

    def test_unknown_monitor_is_404(self):
        resp = self.client.post("/api/monitors/999999/scan/start")
        self.assertEqual(resp.status_code, 404)


class MonitorAndManualScansShareTheRegistryTests(MonitorScanProgressTests):
    """Manual and monitor scans of one domain used to be able to run at the
    same time, racing each other into the history.
    """

    def test_run_now_adopts_an_already_running_manual_scan(self):
        started = scan_jobs.start("example.com", lambda cb: time.sleep(0.4) or {})
        resp = self.client.post(f"/api/monitors/{self.monitor_id}/scan/start")
        self.assertEqual(resp.status_code, 409)
        body = resp.get_json()
        self.assertTrue(body["already_running"])
        self.assertEqual(body["job_id"], started["job_id"])
        self._wait(started["job_id"])

    def test_a_scan_of_another_domain_does_not_block_run_now(self):
        scan_jobs.start("other.com", lambda cb: time.sleep(0.3) or {})
        with mock.patch.object(self.app_module, "_scan_monitor", self._fake_scan()):
            resp = self.client.post(f"/api/monitors/{self.monitor_id}/scan/start")
            self.assertEqual(resp.status_code, 202)
            self._wait(resp.get_json()["job_id"])

    def test_the_sync_endpoint_still_works_for_api_callers(self):
        with mock.patch.object(self.app_module, "_scan_monitor", self._fake_scan()):
            resp = self.client.post(f"/api/monitors/{self.monitor_id}/scan")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["scan_id"], 99)


class MonitorProgressRenderingTests(unittest.TestCase):
    """The drawer covers the main progress bar, so the button that was
    pressed has to show the state itself."""

    def _app_js(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "js" / "app.js").read_text(encoding="utf-8")

    def test_run_now_uses_the_job_endpoint(self):
        js = self._app_js()
        block = js[js.index("async function runMonitorScan"):][:2000]
        self.assertIn("/scan/start", block)
        self.assertIn("followJob", block)

    def test_the_button_shows_a_percentage(self):
        js = self._app_js()
        block = js[js.index("async function runMonitorScan"):][:2000]
        self.assertIn("job.percent", block)

    def test_results_are_unwrapped_for_both_job_kinds(self):
        js = self._app_js()
        self.assertIn("function jobResults", js)
        block = js[js.index("function jobResults"):][:400]
        self.assertIn("payload.results || payload", block)

    def test_resume_uses_the_unwrapper_too(self):
        js = self._app_js()
        block = js[js.index("async function resumeScanIfRunning"):][:1400]
        self.assertIn("jobResults(job)", block)


if __name__ == "__main__":
    unittest.main()
