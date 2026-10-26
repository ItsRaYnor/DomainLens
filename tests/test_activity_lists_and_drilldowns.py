"""What happened, findable; and the domains behind every figure.

The portfolio's changes were fifteen sentences under the domains, and only
the registry's: who switched threat intelligence off, or which domains
changed registrar last month, had no answer. The monitor events were a
hundred cards under the monitors, the "no changes" ones in between, and an
event for a changed A record opened a comparison that said nothing moved.
The dashboard said "8 domains" next to a risk without a way to see which;
on Trends every chart opened the same scan list, the events chart too.
"""

import json
import os
import pathlib
import re
import subprocess
import unittest
from datetime import datetime, timedelta, timezone

import contacts
import db
import domain_portfolio
import management
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _answer(registrar="Example Registrar", nameservers=("ns1.example.net", "ns2.example.net"), phase="registered"):
    return {"success": True, "source": "rdap", "status": ["active"], "registrar": {"name": registrar},
            "reseller": None, "expires": None, "nameservers": list(nameservers), "lifecycle": {"phase": phase}}


def _id(domain):
    return next(d["id"] for d in domain_portfolio.list_all() if d["domain"] == domain)


class PortfolioChangeLogTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.sales = domain_portfolio.ensure_path("Example BV > Sales")
        self.support = domain_portfolio.ensure_path("Example BV > Support")
        domain_portfolio.import_domains([("example.nl", "Example BV > Sales"), ("example.org", None)])

    def _events(self, **filters):
        return domain_portfolio.query_events(**filters)["events"]

    def test_a_change_by_hand_is_kept_with_before_after_and_who(self):
        """Switching threat intelligence off left no trace of who or when."""
        self.login_as("user")
        resp = self.client.post("/api/portfolio/domains", json={
            "ids": [_id("example.nl")], "action": "threat_intel", "value": True})
        self.assertEqual(200, resp.status_code)
        self.client.post("/api/portfolio/domains", json={
            "ids": [_id("example.nl")], "action": "lifecycle", "value": "cancel"})
        rows = self._events(kinds=["threat_intel", "decision"])
        self.assertEqual([("decision", "Keep and renew", "Cancel (let it lapse)", "edit", "user@example.com"),
                          ("threat_intel", "Not enrolled", "Enrolled", "edit", "user@example.com")],
                         [(r["kind"], r["before"], r["after"], r["source"], r["actor"]) for r in rows])

    def test_setting_a_value_a_domain_already_has_is_no_change(self):
        domain_portfolio.set_lifecycle([_id("example.nl")], "keep")
        self.assertEqual([], self._events(kinds=["decision"]))

    def test_a_move_names_both_units_and_a_removal_is_kept_after_the_domain_is_gone(self):
        domain_portfolio.move([_id("example.nl")], self.support)
        domain_portfolio.remove([_id("example.org")])
        moved = self._events(kinds=["unit"])[0]
        self.assertEqual(("Example BV › Sales", "Example BV › Support"), (moved["before"], moved["after"]))
        removed = self._events(kinds=["removed"])[0]
        self.assertEqual("example.org", removed["domain"])

    def test_an_import_is_named_as_such_and_lists_what_it_added_and_changed(self):
        self.login_as("user")
        resp = self.client.post("/api/portfolio/import", json={
            "text": "\n".join(["domain;unit;threat intel", "example.nl;Example BV > Support;yes",
                               "example.com;Example BV > Sales;no"])})
        self.assertEqual(201, resp.status_code)
        rows = self._events(sources=["import"])
        self.assertEqual({("example.nl", "unit"), ("example.nl", "threat_intel"), ("example.com", "added")},
                         {(r["domain"], r["kind"]) for r in rows})
        self.assertTrue(all(r["actor"] == "user@example.com" for r in rows))

    def test_a_registry_change_keeps_its_severity_and_both_values(self):
        row = domain_portfolio.raw(_id("example.nl"))
        domain_portfolio.check(row, fetch=lambda d: _answer(), notify=lambda *a: None, probe=None)
        domain_portfolio.check(domain_portfolio.raw(_id("example.nl")), fetch=lambda d: _answer("Other Registrar"),
                               notify=lambda *a: None, probe=None)
        change = self._events(kinds=["registrar"])[0]
        self.assertEqual(("high", "Example Registrar", "Other Registrar", "registry", None),
                         (change["severity"], change["before"], change["after"], change["source"], change["actor"]))

    def test_an_older_row_reads_before_and_after_back_from_its_sentence(self):
        """Rows written before the values were stored are most of the log."""
        with db._lock, db._connect() as conn:
            conn.execute("INSERT INTO portfolio_events (domain, at, kind, detail) VALUES (?, ?, ?, ?)",
                         ("example.nl", "2026-01-02T03:04:05+00:00", "nameservers",
                          "example.nl has new name servers: ns1.new.example (was ns1.old.example)."))
        row = self._events(kinds=["nameservers"])[0]
        self.assertEqual(("ns1.old.example", "ns1.new.example", "registry", "high"),
                         (row["before"], row["after"], row["source"], row["severity"]))

    def test_filters_combine_and_each_kind_says_what_choosing_it_would_show(self):
        domain_portfolio.set_threat_intel([_id("example.nl")], True)
        domain_portfolio.set_threat_intel([_id("example.org")], True)
        result = domain_portfolio.query_events(kinds=["threat_intel"], domains={"example.nl"})
        self.assertEqual(["example.nl"], [r["domain"] for r in result["events"]])
        self.assertEqual(1, result["kinds"]["threat_intel"])
        self.assertEqual(1, result["kinds"]["added"])        # the other kinds, under the same other filters
        self.assertEqual(0, domain_portfolio.query_events(text="nothing-like-this")["total"])
        self.assertEqual(1, domain_portfolio.query_events(text="example.org", kinds=["threat_intel"])["total"])
        future = (datetime.now(timezone.utc) + timedelta(days=2)).date().isoformat()
        self.assertEqual(0, domain_portfolio.query_events(since=future + "T00:00:00+00:00")["total"])

    def test_the_api_filters_on_a_unit_and_the_csv_holds_the_same_rows(self):
        domain_portfolio.set_threat_intel([_id("example.nl"), _id("example.org")], True)
        self.login_as("viewer")
        data = self.client.get(f"/api/portfolio/changes?kind=threat_intel&unit={self.sales}").get_json()
        self.assertEqual(["example.nl"], [e["domain"] for e in data["events"]])
        self.assertEqual("Example BV › Sales", data["events"][0]["unit"])
        csv = self.client.get(f"/api/portfolio/changes.csv?kind=threat_intel&unit={self.sales}").get_data(as_text=True)
        self.assertEqual(2, len(csv.strip().splitlines()))
        self.assertIn("example.nl", csv)
        self.assertEqual(400, self.client.get("/api/portfolio/changes?from=yesterday").status_code)

    def test_the_changes_have_a_page_of_their_own_next_to_the_portfolio(self):
        self.login_as("viewer")
        page = self.client.get("/monitoring/domains/changes").get_data(as_text=True)
        self.assertIn("/static/js/changes.js", page)
        self.assertIn('href="/monitoring/domains/changes"', page)     # in the sub-navigation
        portfolio = self.client.get("/monitoring/domains").get_data(as_text=True)
        self.assertNotIn('id="pfEvents"', portfolio)
        self.assertIn('href="/monitoring/domains/changes"', portfolio)


class MonitorEventTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.monitor = self.db.create_monitor(name="www", domain="example.com", target="www.example.com",
                                              record_type="A", schedule_minutes=60, checks=["dns"])
        self.other = self.db.create_monitor(name="mail", domain="example.org", target="mail.example.org",
                                            record_type="MX", schedule_minutes=60, checks=["dns"])

    def _scan(self, records):
        app = self.app_module
        runner, resolve = app.run_selected_checks, app._resolve_monitored_record
        try:
            app.run_selected_checks = lambda domain, checks, progress_cb=None: {"dns": {}, "blacklist": {"is_listed": False}}
            app._resolve_monitored_record = lambda target, record_type: {
                "type": "A", "measured": True, "present": bool(records), "records": records,
                "rcode": "NOERROR", "authenticated": True, "error": None}
            app._scan_monitor(self.db.get_monitor(self.monitor))
        finally:
            app.run_selected_checks, app._resolve_monitored_record = runner, resolve

    def test_a_changed_record_says_from_what_to_what_and_its_comparison_shows_it(self):
        """The event read "changed value" and its comparison "nothing moved"."""
        self._scan(["192.0.2.10"])
        self._scan(["192.0.2.11"])
        event = self.db.list_monitor_events(monitor_id=self.monitor, limit=1)[0]
        self.assertEqual("scan_changed", event["event_type"])
        self.assertIn("192.0.2.10 -> 192.0.2.11", event["summary"])
        self.assertEqual(["192.0.2.10"], event["details"]["previous_record_values"])
        self.login_as("viewer")
        compare = self.client.get(f"/api/compare?a={event['details']['previous_scan_id']}&b={event['scan_id']}").get_json()
        self.assertEqual({"type": "A", "before": ["192.0.2.10"], "after": ["192.0.2.11"],
                          "rcode_before": "NOERROR", "rcode_after": "NOERROR"}, compare["record"])
        listed = self.client.get("/api/monitor-events?type=scan_changed").get_json()["events"][0]
        self.assertEqual("yes", listed["explained"])

    def test_the_comparison_view_shows_the_watched_record_and_does_not_claim_nothing_moved(self):
        script = (ROOT / "static/js/compare_view.js").read_text(encoding="utf-8")
        out = _node(script + """
            const html = renderCompareHtml({ a: { report_url: '/r/1', domain: 'x' }, b: { report_url: '/r/2', domain: 'x' },
                diff: { dimensions: [] }, fields: [], findings: { new: [], resolved: [] },
                record: { type: 'A', before: ['192.0.2.10'], after: ['192.0.2.11'] } });
            console.log(JSON.stringify(html));""")
        self.assertIn("A record (watched)", out)
        self.assertIn("192.0.2.10 → 192.0.2.11", out)
        self.assertNotIn("Nothing that is compared moved", out)

    def test_events_filter_on_severity_kind_monitor_and_text_with_counts_per_choice(self):
        for mid, kind, sev, text in ((self.monitor, "scan_changed", "high", "www changed"),
                                     (self.monitor, "scan_unchanged", "info", "No changes for www"),
                                     (self.other, "scan_changed", "medium", "mail changed")):
            self.db.create_monitor_event(mid, event_type=kind, severity=sev, summary=text, details={})
        self.login_as("viewer")
        data = self.client.get("/api/monitor-events?type=scan_changed").get_json()
        self.assertEqual(2, data["total"])
        self.assertEqual({"scan_changed": 2, "scan_unchanged": 1}, data["types"])
        self.assertEqual({"high": 1, "medium": 1}, data["severities"])
        one = self.client.get(f"/api/monitor-events?type=scan_changed&severity=high&monitor_id={self.monitor}").get_json()
        self.assertEqual(["www changed"], [e["summary"] for e in one["events"]])
        self.assertEqual(["mail changed"], [e["summary"] for e in
                                            self.client.get("/api/monitor-events?q=mail.example").get_json()["events"]])
        self.assertEqual(["mail changed"], [e["summary"] for e in
                                            self.client.get("/api/monitor-events?domain=example.org").get_json()["events"]])

    def test_a_change_event_whose_comparison_moved_nothing_is_marked_before_it_is_opened(self):
        self.db.create_monitor_event(self.monitor, event_type="scan_changed", severity="medium", summary="Observed",
                                     details={"changes": {"fields": 0, "dimensions": 0, "new_findings": 0,
                                                          "resolved_findings": 0}})
        self.login_as("viewer")
        self.assertEqual("no", self.client.get("/api/monitor-events").get_json()["events"][0]["explained"])

    def test_the_events_have_a_page_that_opens_without_the_no_change_events(self):
        self.login_as("viewer")
        page = self.client.get("/monitoring/events").get_data(as_text=True)
        self.assertIn("/static/js/events.js", page)
        self.assertNotIn('id="evDelete"', page)                     # a viewer deletes nothing
        js = (ROOT / "static/js/events.js").read_text(encoding="utf-8")
        defaults = re.search(r"EV_DEFAULT_TYPES = \[([^\]]*)\]", js).group(1)
        self.assertIn("scan_changed", defaults)
        self.assertNotIn("scan_unchanged", defaults)
        monitors = self.client.get("/monitoring").get_data(as_text=True)
        self.assertIn('href="/monitoring/events"', monitors)


class DashboardDrillTests(EnterpriseAppTestCase):
    FINDINGS = {
        "weak": [{"severity": "high", "category": "TLS", "title": "Weak hash"},
                 {"severity": "medium", "category": "Web", "title": "No clickjacking protection"}],
        "clean": [],
    }

    def setUp(self):
        super().setUp()
        management._cache.clear()
        self._generate = management.recommendations.generate
        management.recommendations.generate = lambda data: [dict(f) for f in self.FINDINGS[(data or {}).get("case", "clean")]]
        # More domains than the five a tooltip used to name.
        for n in range(7):
            db.save_scan(f"weak{n}.example.com", {"case": "weak"})
        db.save_scan("clean.example.com", {"case": "clean"})

    def tearDown(self):
        management.recommendations.generate = self._generate
        management._cache.clear()
        super().tearDown()

    def test_a_risk_lists_every_domain_it_counts(self):
        """The bar said 7 and its tooltip named five."""
        data = management.drill("finding", "Weak hash", severity="high")
        self.assertEqual(7, data["total"])
        self.assertEqual({f"weak{n}.example.com" for n in range(7)}, {r["domain"] for r in data["domains"]})
        self.assertTrue(all(r["scan_id"] for r in data["domains"]))

    def test_an_area_a_rating_and_a_severity_list_their_domains(self):
        self.assertEqual(7, management.drill("category", "Web")["total"])
        self.assertEqual(["clean.example.com"], [r["domain"] for r in management.drill("rating", "A")["domains"]])
        self.assertEqual(8, management.drill("rating", "A,B,C")["total"])
        high = management.drill("severity", "high")
        self.assertEqual(["Weak hash"], [f["title"] for f in high["domains"][0]["findings"]])

    def test_a_control_shows_each_domain_with_its_state_and_counts_unmeasured_apart(self):
        data = management.drill("control", "dmarc")
        self.assertEqual({"unmeasured": 8}, data["states"])
        self.assertEqual([], management.drill("control", "dmarc", state="fail")["domains"])

    def test_the_api_answers_with_the_same_list_and_refuses_an_unknown_kind(self):
        self.login_as("viewer")
        data = self.client.get("/api/reporting/dashboard/drill?kind=finding&value=Weak%20hash&severity=high").get_json()
        self.assertEqual(7, data["total"])
        self.assertEqual(400, self.client.get("/api/reporting/dashboard/drill?kind=everything").status_code)

    def test_every_figure_on_the_dashboard_carries_what_it_counts(self):
        js = (ROOT / "static/js/dashboard.js").read_text(encoding="utf-8")
        for drill in ("kind: 'finding'", "kind: 'category'", "kind: 'control'", "kind: 'rating'",
                      "kind: 'severity'", "kind: 'domains'", "kind: 'accepted'"):
            self.assertIn(drill, js)
        self.assertIn("/api/reporting/dashboard/drill?", js)


class TrendDayTests(EnterpriseAppTestCase):
    def test_a_day_lists_its_scans_with_the_scan_of_the_same_domain_before_it(self):
        first = db.save_scan("example.com", {"dns": {}})
        second = db.save_scan("example.com", {"dns": {}})
        day = datetime.now(timezone.utc).date().isoformat()
        self.login_as("viewer")
        scans = self.client.get(f"/api/reporting/day?day={day}&domain=example.com").get_json()["scans"]
        newest = next(s for s in scans if s["scan_id"] == second)
        self.assertEqual(first, newest["previous_scan_id"])
        self.assertIsNone(next(s for s in scans if s["scan_id"] == first)["previous_scan_id"])
        self.assertEqual(400, self.client.get("/api/reporting/day?day=today").status_code)

    def test_each_chart_opens_what_it_counts_and_the_events_chart_opens_events(self):
        js = (ROOT / "static/js/trends.js").read_text(encoding="utf-8")
        mapping = re.search(r"CHART_DRILL = \{([^}]*)\}", js).group(1)
        self.assertIn("eventsChart: 'day_events'", mapping)
        self.assertIn("issuesChart: 'day_issues'", mapping)
        self.assertIn("drill: 'servicenow'", js)
        self.assertIn("/api/monitor-events?", js)


class HelpTests(EnterpriseAppTestCase):
    MANUAL = ROOT / "static/help/handleiding.md"

    def test_the_manual_is_a_page_of_the_app_and_linked_from_every_page(self):
        self.login_as("viewer")
        page = self.client.get("/help").get_data(as_text=True)
        self.assertIn("/static/help/handleiding.md", page)
        self.assertIn('href="/help"', self.client.get("/monitoring").get_data(as_text=True))
        self.assertEqual(200, self.client.get("/static/help/handleiding.md").status_code)

    def test_the_manual_ships_in_the_image_although_markdown_does_not(self):
        """.dockerignore leaves out docs/ and *.md: without an exception the
        Help page of every container would be empty."""
        lines = [l.strip() for l in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()]
        self.assertIn("*.md", lines)
        self.assertGreater(lines.index("!static/help/*.md"), lines.index("*.md"))

    def test_the_manual_names_every_page_of_the_menus(self):
        """A page added without a word in the manual is a page nobody finds."""
        app = self.app_module
        from routes.admin_nav import ADMIN_SUBNAV
        english = json.loads((ROOT / "i18n/locales/en.json").read_text(encoding="utf-8"))["nav"]
        manual = self.MANUAL.read_text(encoding="utf-8")
        missing = [english[key.split(".", 1)[1]] for key, _ in
                   app._MONITORING_SUBNAV + app._REPORTS_SUBNAV + app._TOOLS_SUBNAV + ADMIN_SUBNAV
                   if english[key.split(".", 1)[1]] not in manual]
        self.assertEqual([], missing)

    def test_the_manual_renders_without_markup_of_its_own_and_its_links_have_targets(self):
        script = (ROOT / "static/js/help.js").read_text(encoding="utf-8")
        manual = self.MANUAL.read_text(encoding="utf-8")
        out = json.loads(_node(script + f"""
            const r = module.exports.hlRender({json.dumps(manual)});
            const bad = module.exports.hlRender('<img src=x onerror=alert(1)> [x](javascript:alert(1))');
            console.log(JSON.stringify({{ html: r.html, toc: r.toc.length, bad: bad.html }}));""",
                                     module=True))
        self.assertNotIn("<img", out["bad"])
        self.assertNotIn("javascript:", out["bad"].split("href=")[-1] if "href=" in out["bad"] else "")
        self.assertGreater(out["toc"], 20)
        ids = set(re.findall(r'id="([^"]+)"', out["html"]))
        self.assertEqual([], [ref for ref in re.findall(r"\]\(#([^)]+)\)", manual) if ref not in ids])


def _node(script, module=False):
    prelude = "const module = { exports: {} };\n" if module else ""
    done = subprocess.run(["node", "-e", prelude + script], capture_output=True, text=True, timeout=60,
                          encoding="utf-8")
    if done.returncode:
        raise AssertionError(done.stderr)
    return done.stdout.strip()


if __name__ == "__main__":
    unittest.main()
