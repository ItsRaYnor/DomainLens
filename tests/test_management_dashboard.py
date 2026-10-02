"""A management view that says how the domains stand, and stays honest about it.

The stored "grade" of a scan is its TLS grade; shown to management as the
domain's overall standing it would call a domain with no DMARC and an open
relay an A. The dashboard rates each domain on its open findings instead,
counts a control that could not be measured apart from passed and failed,
and leaves accepted risks out of the open findings.
"""

import pathlib
import unittest
from datetime import datetime, timedelta, timezone

import management
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent

GOOD = {
    "dmarc": {"found": True, "policy": "reject", "pass": True},
    "spf": {"found": True, "strict": True, "pass": True},
    "dnssec": {"signed": True},
    "tls_deep": {"success": True, "grade": "A", "hsts": {"enabled": True}, "warnings": []},
    "https_redirect": {"pass": True},
}


def results(domain, **overrides):
    out = {"domain": domain, **{k: dict(v) for k, v in GOOD.items()}}
    out.update(overrides)
    return out


class RatingTests(unittest.TestCase):
    def test_the_rating_follows_the_worst_open_findings(self):
        self.assertEqual("A", management.rating({"low": 4}))
        self.assertEqual("B", management.rating({"medium": 1}))
        self.assertEqual("C", management.rating({"high": 2}))
        self.assertEqual("D", management.rating({"high": 3}))
        self.assertEqual("F", management.rating({"critical": 1, "high": 0}))

    def test_a_control_that_was_not_measured_is_neither_passed_nor_failed(self):
        s = management.summarize_scan(-1, results("example.com", https_redirect={"blocked": True},
                                                  dmarc={"state": "unmeasured"}))
        self.assertEqual(("unmeasured", "unmeasured", "pass"),
                         (s["controls"]["https"], s["controls"]["dmarc"], s["controls"]["spf"]))

    def test_a_good_tls_grade_does_not_make_a_spoofable_domain_an_a(self):
        s = management.summarize_scan(-2, results("example.org", dmarc={"found": False}))
        self.assertEqual("fail", s["controls"]["dmarc"])
        self.assertNotEqual("A", s["rating"])


class DashboardTests(EnterpriseAppTestCase):
    def scan(self, domain, data, days_ago=0):
        scan_id = self.db.save_scan(domain, data)
        at = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
        with self.db._connect() as conn:
            conn.execute("UPDATE scans SET created_at = ? WHERE id = ?", (at, scan_id))
            conn.execute("UPDATE scan_metrics SET created_at = ?, day = ? WHERE scan_id = ?",
                         (at, at[:10], scan_id))
        return scan_id

    def test_ratings_controls_and_common_risks_across_domains(self):
        self.scan("example.com", results("example.com"))
        self.scan("example.org", results("example.org", dmarc={"found": False}))
        self.scan("example.net", results("example.net", dmarc={"found": False},
                                         dnssec={"signed": False}))
        d = management.dashboard(days=90)
        self.assertEqual(3, d["kpis"]["domains"])
        dmarc = next(c for c in d["controls"] if c["key"] == "dmarc")
        self.assertEqual((1, 2, 33), (dmarc["pass"], dmarc["fail"], dmarc["pass_rate"]))
        top = next(f for f in d["top_findings"] if f["title"] == "DMARC record missing")
        self.assertEqual(2, top["domains"])

    def test_change_is_measured_against_the_scan_before_the_period(self):
        self.scan("example.com", results("example.com", dmarc={"found": False}), days_ago=100)
        self.scan("example.com", results("example.com"), days_ago=1)
        self.scan("example.org", results("example.org"), days_ago=100)
        d = management.dashboard(days=90)
        self.assertEqual((1, 0, 1), (d["kpis"]["improved"], d["kpis"]["worsened"], d["kpis"]["compared"]))
        # Not scanned in the period: left out, and said so, not counted as fine.
        self.assertEqual(["example.org"], d["not_rescanned"])
        self.assertEqual(1, d["kpis"]["domains"])

    def test_the_trend_follows_scan_time_not_the_order_scans_were_stored(self):
        """Scans stored out of time order made the line jump at the end."""
        self.scan("example.com", results("example.com", dmarc={"found": False}), days_ago=2)
        self.scan("example.com", results("example.com"), days_ago=60)
        trend = management.dashboard(days=90)["trend"]
        # Mid-period the domain is already known, from the scan 60 days ago.
        self.assertEqual(1, trend[5]["domains"])
        self.assertGreater(trend[-1]["open_findings"], trend[5]["open_findings"])

    def test_a_portfolio_group_narrows_the_view_to_its_domains_and_their_subdomains(self):
        import domain_portfolio
        domain_portfolio.import_domains([("example.com", "Sales")])
        group_id = domain_portfolio.list_groups()[0]["id"]
        self.scan("www.example.com", results("www.example.com"))
        self.scan("example.org", results("example.org"))
        d = management.dashboard(days=90, group_id=group_id)
        self.assertEqual(("Sales", 1), (d["group"], d["kpis"]["domains"]))

    def test_the_api_and_the_page(self):
        self.login_as("viewer")
        self.scan("example.com", results("example.com"))
        body = self.client.get("/api/reporting/dashboard?days=30").get_json()
        self.assertEqual(1, body["kpis"]["domains"])
        self.assertEqual(400, self.client.get("/api/reporting/dashboard?group=999").status_code)
        page = self.client.get("/reports/dashboard").get_data(as_text=True)
        self.assertIn("dashboard.js", page)
        self.assertIn('href="/reports/dashboard"', self.client.get("/reports").get_data(as_text=True))


class ViewTests(unittest.TestCase):
    def test_the_page_prints_and_keeps_unmeasured_apart(self):
        js = ROOT.joinpath("static", "js", "dashboard.js").read_text(encoding="utf-8")
        self.assertIn("window.print()", js)
        self.assertIn("Could not be measured", js)
        css = ROOT.joinpath("static", "css", "style.css").read_text(encoding="utf-8")
        self.assertIn(".no-print", css)


if __name__ == "__main__":
    unittest.main()
