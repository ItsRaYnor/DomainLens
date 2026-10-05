"""Deleting a unit asks what happens to what it holds.

The only way to delete a unit was a browser confirm that moved everything in
it one level up -- the one choice that was not always wanted. A unit that
holds domains or units now offers three: merge them into another unit, move
them one level up, or delete them with it; the last only after typing the
unit's name. An empty unit is removed after a plain confirmation.
"""

import pathlib
import unittest

import domain_portfolio
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


class DeleteTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.company = domain_portfolio.ensure_path("Example BV")
        self.sales = domain_portfolio.ensure_path("Example BV > Sales")
        self.team = domain_portfolio.ensure_path("Example BV > Sales > Team")
        entries, _, _ = domain_portfolio.parse_import(
            "example.nl;Example BV > Sales\nexample.com;Example BV > Sales > Team\nexample.org;Example BV")
        domain_portfolio.import_domains(entries)

    def units(self):
        return {g["path"] for g in domain_portfolio.list_groups()}

    def domains(self):
        return {d["domain"]: d["group"] for d in domain_portfolio.list_all()}

    def test_moving_up_keeps_everything_one_level_higher(self):
        result = domain_portfolio.delete_group(self.sales)
        self.assertEqual({"domains": 0, "units": 1}, result)
        self.assertEqual({"Example BV", "Example BV › Team"}, self.units())
        self.assertEqual("Example BV", self.domains()["example.nl"])

    def test_deleting_with_contents_takes_units_and_domains_below(self):
        result = domain_portfolio.delete_group(self.sales, with_contents=True)
        self.assertEqual({"domains": 2, "units": 2}, result)
        self.assertEqual({"Example BV"}, self.units())
        self.assertEqual({"example.org": "Example BV"}, self.domains())

    def test_monitors_are_kept_when_their_unit_goes(self):
        self.db.create_monitor(name="site", domain="example.nl", target="www.example.nl", record_type="A")
        domain_portfolio.delete_group(self.sales, with_contents=True)
        self.login_as("user")
        monitors = self.client.get("/api/monitors").get_json()["monitors"]
        mine = [m for m in monitors if m["target"] == "www.example.nl"]
        self.assertEqual([None], [m["org_unit"] for m in mine])

    def test_the_api_takes_the_choice_and_refuses_another(self):
        self.login_as("user")
        bad = self.client.delete(f"/api/organisation/units/{self.sales}?contents=everything")
        self.assertEqual(400, bad.status_code)
        resp = self.client.delete(f"/api/organisation/units/{self.sales}?contents=delete")
        self.assertEqual((200, 2, 2), (resp.status_code, resp.get_json()["units"], resp.get_json()["domains"]))

    def test_without_a_choice_the_contents_move_up_as_before(self):
        self.login_as("user")
        resp = self.client.delete(f"/api/organisation/units/{self.team}")
        self.assertEqual(200, resp.status_code)
        self.assertEqual("Example BV › Sales", self.domains()["example.com"])

    def test_a_viewer_cannot_delete(self):
        self.login_as("viewer")
        self.assertEqual(403, self.client.delete(f"/api/organisation/units/{self.sales}?contents=delete").status_code)


class DialogTests(EnterpriseAppTestCase):
    JS = (ROOT / "static" / "js" / "organisation.js").read_text(encoding="utf-8")

    def test_the_page_has_the_dialog_with_its_three_choices(self):
        self.login_as("user")
        html = self.client.get("/monitoring/organisation").get_data(as_text=True)
        self.assertIn('<dialog class="modal" id="orgDeleteDialog"', html)
        for mode in ("merge", "lift", "delete"):
            self.assertIn(f'name="orgDeleteMode" value="{mode}"', html)

    def test_deleting_everything_waits_for_the_units_name(self):
        """A slip of the mouse should not take a company's domains with it."""
        self.assertIn("(mode === 'delete' && $('orgDeleteConfirm').value.trim().toLowerCase() !== u.name.toLowerCase())",
                      self.JS)
        self.assertNotIn("confirm('Delete this unit?", self.JS)

    def test_a_unit_page_opens_the_dialog_for_its_unit(self):
        unit = domain_portfolio.ensure_path("Example BV")
        self.login_as("user")
        html = self.client.get(f"/monitoring/organisation/{unit}").get_data(as_text=True)
        self.assertIn(f'href="/monitoring/organisation?delete={unit}"', html)
        self.assertIn("new URLSearchParams(location.search).get('delete')", self.JS)


if __name__ == "__main__":
    unittest.main()
