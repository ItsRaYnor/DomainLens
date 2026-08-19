import os
import tempfile
import unittest
from datetime import datetime, timezone


class ReportingDomainFilterTests(unittest.TestCase):
    """The trends dashboard has a domain filter, but only the scan count ever
    honoured it: average issues, scores, blacklist hits, ServiceNow incident
    counts and the whole event-severity chart stayed fleet-wide. A per-domain
    report therefore showed other domains' numbers under one domain's heading.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "test.db")
        import importlib
        import db as db_module
        importlib.reload(db_module)
        self.db = db_module
        self.db.init_db()
        self._seed()

    def tearDown(self):
        self.tempdir.cleanup()
        os.environ.pop("DOMAINLENS_DB", None)

    def _seed(self):
        today = datetime.now(timezone.utc).date().isoformat()
        now = datetime.now(timezone.utc).isoformat()
        with self.db._lock, self.db._connect() as conn:
            # alpha.example: 1 scan, 2 issues, clean blacklist
            # beta.example:  1 scan, 20 issues, blacklisted
            for scan_id, domain, issues, listed, grade, header in (
                (1, "alpha.example", 2, 0, 90, 80),
                (2, "beta.example", 20, 1, 10, 20),
            ):
                conn.execute(
                    "INSERT INTO scans (id, domain, created_at, grade, score, issues_count, data)"
                    " VALUES (?, ?, ?, 'A', 90, ?, '{}')",
                    (scan_id, domain, now, issues),
                )
                conn.execute(
                    """
                    INSERT INTO scan_metrics
                        (scan_id, domain, created_at, day, grade, grade_score,
                         header_score, issues_count, recommendation_count,
                         blacklist_listed, dnssec_signed, https_redirect)
                    VALUES (?, ?, ?, ?, 'A', ?, ?, ?, 0, ?, 1, 1)
                    """,
                    (scan_id, domain, now, today, grade, header, issues, listed),
                )

        self.alpha_monitor = self.db.create_monitor(
            name="alpha", domain="alpha.example", target="alpha.example", record_type="A")
        self.beta_monitor = self.db.create_monitor(
            name="beta", domain="beta.example", target="beta.example", record_type="A")

        self.db.create_monitor_event(
            self.alpha_monitor, event_type="change", severity="low", summary="alpha low")
        for _ in range(3):
            self.db.create_monitor_event(
                self.beta_monitor, event_type="change", severity="critical", summary="beta crit")

    # --- overview ---

    def test_overview_unfiltered_covers_all_domains(self):
        ov = self.db.reporting_overview(days=30)
        self.assertEqual(ov["scans"], 2)
        self.assertEqual(ov["domains"], 2)
        self.assertEqual(ov["avg_issues"], 11.0)
        self.assertEqual(ov["blacklist_hits"], 1)

    def test_overview_filtered_scopes_every_kpi(self):
        ov = self.db.reporting_overview(days=30, domain="alpha.example")
        self.assertEqual(ov["domain"], "alpha.example")
        self.assertEqual(ov["scans"], 1)
        self.assertEqual(ov["domains"], 1)
        # Was 11.0 (the fleet average) before the fix.
        self.assertEqual(ov["avg_issues"], 2.0)
        self.assertEqual(ov["avg_grade_score"], 90.0)
        # beta.example is the blacklisted one; alpha must not inherit its hit.
        self.assertEqual(ov["blacklist_hits"], 0)

    def test_overview_filtered_scopes_event_severity(self):
        ov = self.db.reporting_overview(days=30, domain="alpha.example")
        self.assertEqual(ov["events_by_severity"].get("critical", 0), 0)
        self.assertEqual(ov["events_by_severity"].get("low", 0), 1)

    def test_overview_filtered_scopes_top_domains(self):
        ov = self.db.reporting_overview(days=30, domain="alpha.example")
        self.assertEqual([r["domain"] for r in ov["top_domains"]], ["alpha.example"])

    # --- trends ---

    def test_trends_filtered_scopes_events(self):
        trends = self.db.reporting_trends(days=30, domain="alpha.example")
        totals = {}
        for day in trends["events"].values():
            for sev, count in day.items():
                totals[sev] = totals.get(sev, 0) + count
        # beta.example's 3 critical events used to leak into alpha's chart.
        self.assertEqual(totals.get("critical", 0), 0)
        self.assertEqual(totals.get("low", 0), 1)

    def test_trends_unfiltered_keeps_all_events(self):
        trends = self.db.reporting_trends(days=30)
        totals = {}
        for day in trends["events"].values():
            for sev, count in day.items():
                totals[sev] = totals.get(sev, 0) + count
        self.assertEqual(totals.get("critical", 0), 3)
        self.assertEqual(totals.get("low", 0), 1)

    def test_trends_series_is_scoped_to_domain(self):
        trends = self.db.reporting_trends(days=30, domain="beta.example")
        scanned = [p for p in trends["series"] if p["scans"]]
        self.assertEqual(len(scanned), 1)
        self.assertEqual(scanned[0]["avg_issues"], 20.0)


if __name__ == "__main__":
    unittest.main()
