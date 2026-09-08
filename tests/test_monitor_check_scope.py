import os
import tempfile
import unittest


class CheckCatalogTests(unittest.TestCase):
    """The monitor form renders its check selection from CHECK_CATALOG. If a
    catalog key does not exist as a real check, a monitor could be scoped to a
    check that never runs, so the catalog must stay a subset of what the
    scanner can actually execute.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "cat.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["AUTH_REQUIRE_LOGIN"] = "0"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        import importlib
        import db
        import app
        self.db = importlib.reload(db)
        self.db.init_db()
        self.app = importlib.reload(app)
        self.client = self.app.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "AUTH_REQUIRE_LOGIN", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    def test_every_catalog_key_is_a_runnable_check(self):
        catalog_keys = {c["key"] for g in self.app.CHECK_CATALOG for c in g["checks"]}
        runnable = set(self.app._build_check_map("example.com", "example.com").keys())
        # ncsc_tls is derived from tls_deep rather than being in the check map.
        runnable.add("ncsc_tls")
        self.assertTrue(catalog_keys <= runnable,
                        f"catalog keys not runnable: {catalog_keys - runnable}")

    def test_catalog_endpoint_returns_groups(self):
        payload = self.client.get("/api/checks").get_json()
        groups = payload["catalog"]
        self.assertTrue(any(c["key"] == "tls_deep" for g in groups for c in g["checks"]))


class MonitorHonoursCheckScopeTests(unittest.TestCase):
    """A monitor scoped to specific checks must run only those, not a full
    scan: the record type was made functional, and the same must hold for the
    check selection the operator picks.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "scope.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["SERVICENOW_ENABLED"] = "0"
        import importlib
        import db
        import app
        import servicenow
        self.db = importlib.reload(db)
        self.servicenow = importlib.reload(servicenow)
        self.app = importlib.reload(app)
        self.db.init_db()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "SERVICENOW_ENABLED"):
            os.environ.pop(key, None)

    def test_scan_runs_only_the_selected_checks(self):
        mid = self.db.create_monitor(
            name="scoped", domain="example.com", target="example.com",
            record_type="A", schedule_minutes=60, checks=["dns", "tls_deep"])
        monitor = self.db.get_monitor(mid)
        self.assertEqual(monitor["checks"], ["dns", "tls_deep"])

        seen = {}
        original_runner = self.app.run_selected_checks
        original_record = self.app._resolve_monitored_record
        try:
            def fake(domain, checks, progress_cb=None):
                seen["checks"] = checks
                return {"dns": {}, "tls_deep": {"grade": "A", "warnings": []}}
            self.app.run_selected_checks = fake
            self.app._resolve_monitored_record = lambda target, record_type: {
                "type": "A", "measured": True, "present": True,
                "records": ["203.0.113.10"], "rcode": "NOERROR",
                "authenticated": None, "error": None}
            self.app._scan_monitor(monitor)
        finally:
            self.app.run_selected_checks = original_runner
            self.app._resolve_monitored_record = original_record

        self.assertEqual(seen["checks"], ["dns", "tls_deep"])


if __name__ == "__main__":
    unittest.main()
