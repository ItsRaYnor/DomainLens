"""Five things that made the organisation view hard to work with.

Security monitoring had to be set up one domain at a time while
registration monitoring came with one import; everything of a unit was
spread over three filtered pages; the domains someone wants sat under Tools,
apart from the ones they hold; the monitor list did not say how anything
stood; and the history showed the TLS grade where the dashboard showed a
rating, two different letters for one domain.
"""

import pathlib
import unittest
from datetime import datetime, timedelta, timezone

import domain_portfolio
import management
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent
JS = {name: ROOT.joinpath("static", "js", f"{name}.js").read_text(encoding="utf-8")
      for name in ("app", "lookup", "unit", "organisation")}

BAD = {"dmarc": {"found": False}, "spf": {"found": True, "strict": True},
       "dnssec": {"signed": True}, "https_redirect": {"pass": True},
       "tls_deep": {"success": True, "grade": "A", "hsts": {"enabled": True}, "warnings": []}}


class Case(EnterpriseAppTestCase):
    def scan(self, host, data=None):
        return self.db.save_scan(host, {"domain": host, **{k: dict(v) for k, v in (data or BAD).items()}})


class BulkMonitorTests(Case):
    def test_a_unit_gets_security_monitors_in_one_go_spread_over_the_interval(self):
        self.login_as("user")
        sales = domain_portfolio.ensure_path("Org X > Sales")
        # (The test setup already monitors example.com, so other names are used.)
        domain_portfolio.import_domains([("example.nl", "Org X > Sales"), ("example.net", "Org X"),
                                         ("example.org", "Org X > Sales")])
        # Already monitored on one of its hosts: shown as monitored, so skipped.
        self.db.create_monitor(name="www", domain="www.example.org", target="www.example.org", record_type="A")
        top = domain_portfolio.ensure_path("Org X")
        resp = self.client.post("/api/portfolio/monitor", json={"group_id": top, "schedule_minutes": 1440})
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        body = resp.get_json()
        self.assertEqual((["example.net", "example.nl"], 1), (sorted(body["created"]), body["already_monitored"]))
        due = sorted(m["next_scan_at"] for m in self.db.list_monitors() if m["source_type"] == "portfolio")
        gap = datetime.fromisoformat(due[1]) - datetime.fromisoformat(due[0])
        self.assertGreaterEqual(gap, timedelta(hours=11))
        self.assertTrue(sales)

    def test_a_viewer_cannot_create_monitors(self):
        self.login_as("viewer")
        self.assertEqual(403, self.client.post("/api/portfolio/monitor", json={"ids": [1]}).status_code)


class UnitPageTests(Case):
    def test_one_page_holds_domains_monitors_risks_and_changes_of_a_unit(self):
        self.login_as("viewer")
        top = domain_portfolio.ensure_path("Org X")
        domain_portfolio.import_domains([("example.nl", "Org X > Sales"), ("example.com", None)])
        # Scanned only as www.: the domain is rated by that scan, not "not scanned".
        self.scan("www.example.nl")
        self.db.create_monitor(name="m", domain="shop.example.nl", target="shop.example.nl", record_type="A")
        body = self.client.get(f"/api/organisation/{top}").get_json()
        self.assertEqual(["example.nl"], [d["domain"] for d in body["domains"]])
        self.assertEqual("C", body["domains"][0]["posture"]["rating"])
        self.assertTrue(body["domains"][0]["monitored"])
        self.assertEqual(["shop.example.nl"], [m["target"] for m in body["monitors"]])
        self.assertEqual(["Sales"], [u["name"] for u in body["children"]])
        self.assertEqual(404, self.client.get("/api/organisation/999").status_code)
        page = self.client.get(f"/monitoring/organisation/{top}").get_data(as_text=True)
        self.assertIn("unit.js", page)

    def test_the_organisation_table_links_each_unit_to_its_page(self):
        self.assertIn("href=\"/monitoring/organisation/${u.id}\"", JS["organisation"])


class WantedDomainsTests(Case):
    def test_wanted_domains_are_in_the_portfolio_and_whois_still_adds_to_them(self):
        self.login_as("user")
        whois = self.client.get("/tools/whois").get_data(as_text=True)
        self.assertIn('id="whoisWatchBtn"', whois)
        self.assertIn('href="/monitoring/domains?flag=wanted"', whois)
        init = JS["lookup"][JS["lookup"].index("function initWatchlist"):]
        self.assertIn("addToWatchlist(watchBtn.dataset.domain", init)


class MonitorTableTests(Case):
    def test_each_monitor_says_how_its_domain_stands_and_what_changed_last(self):
        self.login_as("user")
        self.scan("example.nl")
        monitor_id = self.db.create_monitor(name="m", domain="example.nl", target="example.nl", record_type="A")
        self.db.create_monitor_event(monitor_id=monitor_id, event_type="change", severity="high",
                                     summary="MX changed", details={})
        m = self.client.get("/api/monitors").get_json()["monitors"][0]
        self.assertEqual("C", m["posture"]["rating"])
        self.assertEqual("MX changed", m["last_event"]["summary"])

    def test_the_list_is_a_searchable_table(self):
        body = JS["app"][JS["app"].index("function renderMonitorList"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("monitor-table", body)
        self.assertIn("monitorSearch", body)


class RatingTests(Case):
    def test_a_scan_keeps_its_rating_and_old_ones_get_it_when_listed(self):
        self.login_as("user")
        new = self.scan("example.nl")
        old = self.scan("example.org")
        with self.db._connect() as conn:
            conn.execute("UPDATE scan_metrics SET rating = NULL WHERE scan_id = ?", (old,))
            stored = conn.execute("SELECT rating FROM scan_metrics WHERE scan_id = ?", (new,)).fetchone()[0]
        self.assertEqual("C", stored)
        listed = {s["domain"]: s["rating"] for s in self.client.get("/api/history").get_json()["scans"]}
        self.assertEqual({"example.nl": "C", "example.org": "C"}, listed)

    def test_a_stored_scan_opens_with_its_current_rating(self):
        self.login_as("user")
        scan_id = self.scan("example.nl")
        posture = self.client.get(f"/api/history/{scan_id}").get_json()["data"]["posture"]
        self.assertEqual("C", posture["rating"])

    def test_the_rating_follows_the_open_findings(self):
        self.assertEqual("F", management.posture([{"severity": "critical"}])["rating"])
        self.assertEqual("A", management.posture([{"severity": "critical", "accepted": True}])["rating"])


if __name__ == "__main__":
    unittest.main()
