import importlib
import io
import json
import logging
import os
import tempfile
import unittest

import log_setup


class StructuredLoggingTests(unittest.TestCase):
    """Text log lines are unreadable to a log collector: a traceback became a
    dozen unrelated events, and nothing tied a warning a scan logged to the
    request that started it."""

    def tearDown(self):
        log_setup.configure("INFO", "text")

    def _capture(self, fmt):
        handler = log_setup.configure("INFO", fmt)
        stream = io.StringIO()
        handler.setStream(stream)
        return stream

    def test_a_traceback_stays_inside_one_json_line(self):
        stream = self._capture("json")
        try:
            raise ValueError("boom")
        except ValueError:
            logging.getLogger("domainlens.test").exception("scan failed for %s", "example.com")
        lines = stream.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 1, "the traceback spilled over several lines")
        entry = json.loads(lines[0])
        self.assertEqual(entry["message"], "scan failed for example.com")
        self.assertEqual(entry["level"], "ERROR")
        self.assertIn("ValueError: boom", entry["exception"])

    def test_text_remains_the_default(self):
        stream = self._capture("text")
        logging.getLogger("domainlens.test").warning("plain")
        self.assertNotIn("{", stream.getvalue())
        self.assertIn("plain", stream.getvalue())


class RequestIdTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "log.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import db as db_module
        import app as app_module
        importlib.reload(db_module).init_db()
        self.module = importlib.reload(app_module)

        @self.module.app.route("/__logs")
        def logs():
            logging.getLogger("domainlens.test").warning("inside the request")
            return "ok"

        self.client = self.module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)
        log_setup.configure("INFO", "text")

    def test_the_log_line_and_the_response_carry_the_same_id(self):
        handler = log_setup.configure("INFO", "json")
        stream = io.StringIO()
        handler.setStream(stream)
        resp = self.client.get("/__logs")
        request_id = resp.headers.get("X-Request-ID")
        self.assertTrue(request_id)
        entries = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
        mine = [e for e in entries if e["message"] == "inside the request"]
        self.assertEqual(mine[0].get("request_id"), request_id)

    def test_a_proxys_request_id_is_kept_so_both_logs_line_up(self):
        resp = self.client.get("/__logs", headers={"X-Request-ID": "edge-7f3a.42"})
        self.assertEqual(resp.headers["X-Request-ID"], "edge-7f3a.42")

    def test_a_forged_request_id_cannot_inject_into_the_log(self):
        forged = 'x" admin=true {"level":"INFO"}'
        resp = self.client.get("/__logs", headers={"X-Request-ID": forged})
        self.assertNotEqual(resp.headers["X-Request-ID"], forged)
        self.assertRegex(resp.headers["X-Request-ID"], r"^[0-9a-f]{32}$")


if __name__ == "__main__":
    unittest.main()
