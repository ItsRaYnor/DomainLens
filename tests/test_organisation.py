"""Domains, monitors and scans placed in one organisation tree.

Security monitoring and registration monitoring were two flat lists with
no notion of who a domain belongs to: a company with several business units
could not see its own domains together, and a unit called "Sales" could
exist only once. Units now nest, a domain sits in one unit, and every
monitor and scan of its hostnames counts in that unit and the units above.
"""

import pathlib
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

import domain_portfolio
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


class MigrationTests(unittest.TestCase):
    def test_flat_groups_become_units_keeping_their_ids(self):
        """The first version had a globally unique name and no parent."""
        conn = sqlite3.connect(":memory:", isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE portfolio_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                     "name TEXT NOT NULL UNIQUE COLLATE NOCASE, expected_registrar TEXT, "
                     "created_at TEXT NOT NULL)")
        conn.execute("INSERT INTO portfolio_groups (id, name, created_at) VALUES (7, 'Sales', 'x')")
        domain_portfolio.init_schema(conn)
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(portfolio_groups)")}
        self.assertIn("parent_id", columns)
        self.assertEqual("Sales", conn.execute("SELECT name FROM portfolio_groups WHERE id = 7").fetchone()[0])
        # "Sales" may now exist again, under another unit.
        conn.execute("INSERT INTO portfolio_groups (name, parent_id, created_at) VALUES ('Sales', 7, 'x')")


class OrgTestCase(EnterpriseAppTestCase):
    def unit(self, path):
        return domain_portfolio.ensure_path(path)

    def scan(self, host, days_ago=1, **overrides):
        data = {"domain": host, **{k: dict(v) for k, v in GOOD.items()}, **overrides}
        scan_id = self.db.save_scan(host, data)
        at = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
        with self.db._connect() as conn:
            conn.execute("UPDATE scans SET created_at = ? WHERE id = ?", (at, scan_id))
            conn.execute("UPDATE scan_metrics SET created_at = ?, day = ? WHERE scan_id = ?",
                         (at, at[:10], scan_id))


class TreeTests(OrgTestCase):
    def test_an_import_path_builds_the_tree_and_a_name_may_repeat_per_level(self):
        entries, _, _ = domain_portfolio.parse_import("\n".join([
            "example.nl;Org X > Sales", "example.com;Org Y / Sales"]))
        domain_portfolio.import_domains(entries)
        paths = {d["domain"]: d["group"] for d in domain_portfolio.list_all()}
        self.assertEqual({"example.nl": "Org X › Sales", "example.com": "Org Y › Sales"}, paths)

    def test_a_unit_inherits_the_registrar_of_the_unit_above(self):
        top = self.unit("Org X")
        domain_portfolio.update_group(top, expected_registrar="Example Registrar")
        sales = self.unit("Org X > Sales")
        group = domain_portfolio.get_group(sales)
        self.assertEqual(("Example Registrar", True),
                         (group["effective_registrar"], group["registrar_inherited"]))
        domain = {"phase": "registered", "registrar": "Other Registrar", "reseller": None}
        self.assertEqual("move", domain_portfolio.transfer_state(domain, group))

    def test_a_unit_cannot_be_placed_under_its_own_unit(self):
        top = self.unit("Org X")
        sales = self.unit("Org X > Sales")
        with self.assertRaises(ValueError):
            domain_portfolio.update_group(top, parent_id=sales)

    def test_deleting_a_unit_moves_its_domains_and_units_up(self):
        domain_portfolio.import_domains([("example.nl", "Org X > Sales")])
        self.unit("Org X > Sales > Webshop")
        sales = self.unit("Org X > Sales")
        domain_portfolio.delete_group(sales)
        self.assertEqual("Org X", domain_portfolio.list_all()[0]["group"])
        self.assertIn("Org X › Webshop", [g["path"] for g in domain_portfolio.list_groups()])


class MonitorTests(OrgTestCase):
    def test_a_monitor_on_a_subdomain_lands_in_the_unit_of_its_domain(self):
        self.login_as("user")
        sales = self.unit("Org X > Sales")
        resp = self.client.post("/api/monitors", json={"domain": "shop.example.nl", "org_unit_id": sales})
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual("Org X › Sales", resp.get_json()["monitor"]["org_unit"]["path"])
        # The domain is now watched for its registration as well.
        self.assertEqual(["example.nl"], [d["domain"] for d in domain_portfolio.list_all()])
        listed = self.client.get("/api/monitors").get_json()["monitors"]
        self.assertEqual(sales, listed[0]["org_unit"]["id"])

    def test_an_unknown_unit_is_refused_not_ignored(self):
        self.login_as("user")
        resp = self.client.post("/api/monitors", json={"domain": "example.nl", "org_unit_id": 999})
        self.assertEqual(400, resp.status_code)


class OverviewTests(OrgTestCase):
    def test_figures_roll_up_to_the_units_above_and_strays_are_counted_apart(self):
        sales = self.unit("Org X > Sales")
        domain_portfolio.assign("example.nl", sales)
        self.scan("www.example.nl", dmarc={"found": False})
        self.scan("example.org")
        self.db.create_monitor(name="m", domain="example.nl", target="shop.example.nl", record_type="A")
        view = management.organisation()
        units = {u["path"]: u for u in view["units"]}
        for path in ("Org X", "Org X › Sales"):
            self.assertEqual((1, 1), (units[path]["security"]["scanned"],
                                      units[path]["security"]["monitors"]), path)
            self.assertEqual(1, units[path]["registration"]["total"], path)
        self.assertEqual(1, view["unassigned"]["scanned"])

    def test_the_dashboard_of_a_company_includes_its_units(self):
        top = self.unit("Org X")
        domain_portfolio.assign("example.nl", self.unit("Org X > Sales"))
        self.scan("example.nl")
        self.scan("example.org")
        self.assertEqual(1, management.dashboard(days=90, group_id=top)["kpis"]["domains"])


class ApiTests(OrgTestCase):
    def test_a_scanned_host_is_assigned_by_its_registered_domain(self):
        self.login_as("user")
        sales = self.unit("Org X > Sales")
        body = self.client.post("/api/portfolio/assign",
                                json={"domain": "www.example.nl", "group_id": sales}).get_json()
        self.assertEqual(("example.nl", "added"), (body["domain"], body["action"]))
        unit = self.client.get("/api/portfolio/unit?domain=mail.example.nl").get_json()["unit"]
        self.assertEqual("Org X › Sales", unit["path"])

    def test_a_viewer_sees_the_overview_but_cannot_assign(self):
        self.login_as("viewer")
        self.assertEqual(200, self.client.get("/api/organisation").status_code)
        self.assertEqual(403, self.client.post("/api/portfolio/assign",
                                               json={"domain": "example.nl"}).status_code)

    def test_the_pages_link_up(self):
        self.login_as("user")
        page = self.client.get("/monitoring/organisation").get_data(as_text=True)
        self.assertIn("organisation.js", page)
        self.assertIn('href="/monitoring/organisation"', self.client.get("/monitoring").get_data(as_text=True))
        self.assertIn('id="scanUnit"', self.client.get("/").get_data(as_text=True))


class ScriptTests(unittest.TestCase):
    def test_the_monitor_list_is_grouped_by_unit(self):
        js = ROOT.joinpath("static", "js", "app.js").read_text(encoding="utf-8")
        body = js[js.index("function renderMonitorList"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("org_unit", body)
        self.assertIn("monitorUnitScope()", body)
        # The unit picker belongs to monitors, not to the scan history list.
        self.assertIn("monitor-unit-select", body)
        history = js[js.index("function renderHistoryList"):]
        self.assertNotIn("monitor-unit-select", history[:history.index("\n}\n")])


if __name__ == "__main__":
    unittest.main()
