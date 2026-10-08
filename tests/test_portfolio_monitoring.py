"""Security monitoring set from the domain portfolio, per domain or per unit.

Monitoring a domain took a selection, a frequency in a list and a separate
button; the row then said only "Security monitored", not whether a monitor
ran or was paused, and a unit had no way to say "monitor everything here,
also what is added later". Now each domain has an on, paused or off state
and a switch, a selection is monitored or paused in one action, and a unit
monitors its domains -- and the units below it inherit that, as they do the
registrar and the contact.
"""

from enterprise_harness import EnterpriseAppTestCase


class PortfolioMonitoringTests(EnterpriseAppTestCase):
    # Not example.com: the test setup already has a (paused) monitor for it.
    def setUp(self):
        super().setUp()
        self.login_as("user")

    def _import(self, text, unit_id=None, lifecycle=None):
        body = {"text": text}
        if unit_id is not None:
            body["unit_id"] = unit_id
        if lifecycle:
            body["lifecycle"] = lifecycle
        resp = self.client.post("/api/portfolio/import", json=body)
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        return resp.get_json()

    def _domains(self):
        return {d["domain"]: d for d in self.client.get("/api/portfolio").get_json()["domains"]}

    def _unit(self, name, parent=None):
        import domain_portfolio
        return domain_portfolio.ensure_group(name, parent_id=parent)

    def test_a_domain_is_monitored_paused_and_resumed_without_a_second_monitor(self):
        self._import("example.info")
        domain_id = self._domains()["example.info"]["id"]
        self.assertEqual("off", self._domains()["example.info"]["monitor"]["state"])
        on = self.client.post("/api/portfolio/domains", json={"action": "monitor", "ids": [domain_id], "value": 1440})
        self.assertEqual(1, on.get_json()["created"])
        self.assertEqual({"state": "on", "schedule_minutes": 1440}, self._domains()["example.info"]["monitor"])
        self.client.post("/api/portfolio/domains", json={"action": "monitor", "ids": [domain_id], "value": 0})
        self.assertEqual("paused", self._domains()["example.info"]["monitor"]["state"])
        again = self.client.post("/api/portfolio/domains", json={"action": "monitor", "ids": [domain_id], "value": 1440})
        self.assertEqual((0, 1), (again.get_json()["created"], again.get_json()["enabled"]))
        self.assertEqual(1, len([m for m in self.db.list_monitors() if m["domain"] == "example.info"]))

    def test_a_unit_monitors_its_domains_and_those_of_the_units_below(self):
        company = self._unit("Example BV")
        sales = self._unit("Sales", company)
        self._import("example.info", unit_id=company)
        self._import("example.org", unit_id=sales)
        resp = self.client.post(f"/api/portfolio/groups/{company}/monitoring", json={"schedule_minutes": 1440})
        self.assertEqual(2, resp.get_json()["created"])
        groups = {g["name"]: g for g in self.client.get("/api/portfolio").get_json()["groups"]}
        self.assertEqual((1440, False), (groups["Example BV"]["monitor_effective"], groups["Example BV"]["monitor_inherited"]))
        self.assertEqual((1440, True), (groups["Sales"]["monitor_effective"], groups["Sales"]["monitor_inherited"]))

    def test_a_domain_added_or_moved_into_a_monitoring_unit_is_monitored(self):
        unit = self._unit("Example BV")
        self.client.post(f"/api/portfolio/groups/{unit}/monitoring", json={"schedule_minutes": 10080})
        added = self._import("example.info", unit_id=unit)
        self.assertEqual(["example.info"], added["monitored"])
        self._import("example.org")
        moved = self.client.post("/api/portfolio/domains", json={
            "action": "move", "ids": [self._domains()["example.org"]["id"]], "unit_id": unit}).get_json()
        self.assertEqual(1, moved["monitored"])
        self.assertEqual({"on"}, {d["monitor"]["state"] for d in self._domains().values()})

    def test_a_domain_to_claim_or_cancel_is_not_scanned_for_its_unit(self):
        """Not held, or let go: scanning it because of its unit would scan
        someone else's domain."""
        unit = self._unit("Example BV")
        self._import("example.net", unit_id=unit, lifecycle="claim")
        self.client.post(f"/api/portfolio/groups/{unit}/monitoring", json={"schedule_minutes": 1440})
        self._import("example.info", unit_id=unit, lifecycle="cancel")
        self.assertEqual({"off"}, {d["monitor"]["state"] for d in self._domains().values()})

    def test_stopping_a_unit_pauses_its_monitors_and_new_domains_stay_off(self):
        unit = self._unit("Example BV")
        self._import("example.info", unit_id=unit)
        self.client.post(f"/api/portfolio/groups/{unit}/monitoring", json={"schedule_minutes": 1440})
        stop = self.client.post(f"/api/portfolio/groups/{unit}/monitoring", json={"schedule_minutes": 0})
        self.assertEqual(1, stop.get_json()["paused"])
        self._import("example.org", unit_id=unit)
        states = {k: v["monitor"]["state"] for k, v in self._domains().items()}
        self.assertEqual({"example.info": "paused", "example.org": "off"}, states)

    def test_a_viewer_cannot_change_monitoring(self):
        unit = self._unit("Example BV")
        self.login_as("viewer")
        self.assertEqual(403, self.client.post(f"/api/portfolio/groups/{unit}/monitoring",
                                               json={"schedule_minutes": 1440}).status_code)
