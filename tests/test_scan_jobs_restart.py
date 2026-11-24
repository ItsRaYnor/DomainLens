import importlib
import os
import tempfile
import threading
import time
import unittest

import scan_jobs


class ScanJobsSurviveRestartTests(unittest.TestCase):
    """Jobs lived only in memory. After a restart a browser polling its scan
    got a 404, hid the progress bar and said nothing: the scan vanished, and
    whether it had run or not could not be told."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "jobs.db")
        import db
        self.db = importlib.reload(db)
        self.db.init_db()
        scan_jobs.reset()

    def tearDown(self):
        scan_jobs.wait_idle()
        scan_jobs.reset()
        os.environ.pop("DOMAINLENS_DB", None)
        self.tempdir.cleanup()

    def _restart(self):
        scan_jobs.reset()       # the process's memory is gone
        self.db.init_db()       # what start-up runs

    def _wait(self, job_id):
        deadline = time.time() + 5
        while time.time() < deadline:
            if scan_jobs.get(job_id)["status"] != "running":
                return
            time.sleep(0.01)
        self.fail("job did not finish")

    def test_a_scan_running_at_restart_is_reported_as_interrupted(self):
        release = threading.Event()

        def runner(progress_cb):
            release.wait(5)
            return {"ok": True}

        job = scan_jobs.start("example.com", runner)
        self._restart()
        try:
            after = scan_jobs.get(job["job_id"], include_result=True)
            self.assertIsNotNone(after, "the job vanished: the browser gets a 404 and says nothing")
            self.assertEqual(after["status"], "error")
            self.assertIn("restarted", after["error"])
        finally:
            release.set()

    def test_a_finished_scan_is_still_answered_with_its_result(self):
        scan_id = self.db.save_scan("example.com", {"domain": "example.com", "grade": "B"})

        def runner(progress_cb):
            return {"domain": "example.com", "grade": "B", "scan_id": scan_id}

        job = scan_jobs.start("example.com", runner)
        self._wait(job["job_id"])
        self._restart()
        after = scan_jobs.get(job["job_id"], include_result=True)
        self.assertEqual(after["status"], "done")
        self.assertEqual(after["scan_id"], scan_id)
        self.assertEqual(after["result"]["grade"], "B")
        self.assertEqual(after["result"]["scan_id"], scan_id)

    def test_a_failed_scan_keeps_its_reason_across_a_restart(self):
        def runner(progress_cb):
            raise RuntimeError("resolver unreachable")

        job = scan_jobs.start("example.com", runner)
        self._wait(job["job_id"])
        self._restart()
        after = scan_jobs.get(job["job_id"])
        self.assertEqual(after["status"], "error")
        self.assertIn("resolver unreachable", after["error"])

    def test_an_unknown_job_is_still_unknown(self):
        self.assertIsNone(scan_jobs.get("0" * 32))


class GoneJobMessageTests(unittest.TestCase):
    """A scan the server no longer knew made the progress bar vanish without
    a word, which reads as a scan that quietly finished."""

    def test_the_page_says_the_scan_is_gone(self):
        import pathlib
        js = (pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "app.js").read_text(encoding="utf-8")
        follow = js[js.index("async function followJob"):]
        gone = follow[follow.index("resp.status === 404"):follow.index("job = await resp.json()")]
        self.assertIn("showError(SCAN_GONE_MESSAGE)", gone)
        self.assertIn("This scan is no longer available", js)


if __name__ == "__main__":
    unittest.main()
