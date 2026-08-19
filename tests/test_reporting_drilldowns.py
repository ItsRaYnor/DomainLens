import importlib
import os
import tempfile
import unittest
from datetime import datetime, timezone


class ReportingDrilldownTests(unittest.TestCase):
    """The KPI tiles summed every scan in the period, so a problem that had
    since been fixed kept being counted: a domain rescanned clean still
    showed its old blacklist hit until it aged out. Quality figures now come
    from the latest scan per domain, and the tiles drill down into the rows
    behind them.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "drill.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import db as db_module
        import app as app_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()
        self._seed()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _seed(self):
        now = datetime.now(timezone.utc).isoformat()
        today = datetime.now(timezone.utc).date().isoformat()
        # alpha was scanned twice: listed first, clean afterwards.
        rows = [
            (1, "alpha.example", 20, 1, 10, 20),
            (2, "alpha.example", 2, 0, 90, 80),
            (3, "beta.example", 9, 1, 50, 40),
        ]
        with self.db._lock, self.db._connect() as conn:
            for scan_id, domain, issues, listed, grade, header in rows:
                conn.execute(
                    "INSERT INTO scans (id, domain, created_at, grade, score, issues_count, data)"
                    " VALUES (?, ?, ?, 'A', ?, ?, '{}')",
                    (scan_id, domain, now, grade, issues),
                )
                conn.execute(
                    """
                    INSERT INTO scan_metrics
                        (scan_id, domain, created_at, day, grade, grade_score, header_score,
                         issues_count, recommendation_count, blacklist_listed,
                         dnssec_signed, https_redirect)
                    VALUES (?, ?, ?, ?, 'A', ?, ?, ?, 0, ?, 1, 1)
                    """,
                    (scan_id, domain, now, today, grade, header, issues, listed),
                )

    # --- KPI semantics ---

    def test_activity_counts_cover_every_scan(self):
        ov = self.db.reporting_overview(days=7)
        self.assertEqual(ov["scans"], 3)
        self.assertEqual(ov["domains"], 2)

    def test_quality_figures_use_only_the_latest_scan_per_domain(self):
        ov = self.db.reporting_overview(days=7)
        # (2 + 9) / 2, not (20 + 2 + 9) / 3
        self.assertEqual(ov["avg_issues"], 5.5)
        self.assertEqual(ov["avg_grade_score"], 70.0)

    def test_superseded_blacklist_hit_no_longer_counts(self):
        ov = self.db.reporting_overview(days=7)
        self.assertEqual(ov["blacklist_hits"], 1)  # beta only; alpha was rescanned clean

    # --- domain drill-down ---

    def test_domains_endpoint_returns_one_row_per_domain(self):
        data = self.client.get("/api/reporting/domains?days=7").get_json()
        by_domain = {r["domain"]: r for r in data["domains"]}
        self.assertEqual(set(by_domain), {"alpha.example", "beta.example"})
        self.assertEqual(by_domain["alpha.example"]["scan_id"], 2)
        self.assertEqual(by_domain["alpha.example"]["issues_count"], 2)
        self.assertEqual(by_domain["alpha.example"]["scans"], 2)

    def test_domains_endpoint_honours_the_domain_filter(self):
        data = self.client.get("/api/reporting/domains?days=7&domain=beta.example").get_json()
        self.assertEqual([r["domain"] for r in data["domains"]], ["beta.example"])

    def test_domains_endpoint_rejects_a_bad_domain(self):
        resp = self.client.get("/api/reporting/domains?days=7&domain=not a domain")
        self.assertEqual(resp.status_code, 400)

    # --- scan drill-down ---

    def test_history_supports_the_period_filter(self):
        all_scans = self.client.get("/api/history?days=7&limit=200").get_json()
        self.assertEqual(len(all_scans["scans"]), 3)
        scoped = self.client.get("/api/history?days=7&domain=alpha.example").get_json()
        self.assertEqual({s["domain"] for s in scoped["scans"]}, {"alpha.example"})

    def test_history_without_days_is_unchanged(self):
        data = self.client.get("/api/history").get_json()
        self.assertEqual(len(data["scans"]), 3)

    # --- deletion ---

    def test_deleting_a_scan_updates_the_figures(self):
        before = self.db.reporting_overview(days=7)["scans"]
        resp = self.client.delete("/api/history/1")
        self.assertEqual(resp.status_code, 200)
        after = self.db.reporting_overview(days=7)
        self.assertEqual(after["scans"], before - 1)

    def test_deleting_the_latest_scan_falls_back_to_the_previous_one(self):
        # Removing alpha's clean rescan must resurface its older listed state
        # rather than leaving a stale average behind.
        self.client.delete("/api/history/2")
        ov = self.db.reporting_overview(days=7)
        self.assertEqual(ov["blacklist_hits"], 2)
        self.assertEqual(ov["avg_issues"], 14.5)  # (20 + 9) / 2

    def test_deleting_a_missing_scan_is_404(self):
        self.assertEqual(self.client.delete("/api/history/999").status_code, 404)


if __name__ == "__main__":
    unittest.main()
