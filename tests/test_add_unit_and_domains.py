"""Creating a unit, and putting new domains in one, took guesswork.

The form to add a unit sat at the bottom of a folded table, with
placeholders for labels and a select called "Top level" that did not say
it meant "this is a company". Adding domains asked for a unit as free text,
so a typo made a second unit; and nothing led from a new unit to adding its
domains. These tests keep the way from "new unit" to "its domains" short.
"""

import io
import pathlib
import re
import unittest

import domain_portfolio
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent
JS = ROOT / "static" / "js"


class OrganisationPageTests(EnterpriseAppTestCase):
    def page(self):
        self.login_as("user")
        return self.client.get("/monitoring/organisation").get_data(as_text=True)

    def test_the_add_form_is_on_top_and_not_folded_away(self):
        """At the bottom of the folded edit table, a first-time user did not
        find it, and an empty overview pointed "below" to a closed fold."""
        html = self.page()
        self.assertIn('id="orgAdd"', html)
        self.assertLess(html.index('id="orgAdd"'), html.index('id="orgTable"'))
        fold = html[html.index('id="orgManage"'):html.index("</details>", html.index('id="orgManage"'))]
        self.assertNotIn('id="orgNewName"', fold)

    def test_every_field_of_the_add_form_has_a_label(self):
        """Placeholders vanish as soon as one types; "Under" was only an aria-label."""
        html = self.page()
        for field in ("orgNewName", "orgNewParent", "orgNewRegistrar", "orgNewNotify"):
            self.assertRegex(html, rf'<label class="form-field" for="{field}"><span>[^<]+')

    def test_a_viewer_gets_no_add_form(self):
        self.login_as("viewer")
        html = self.client.get("/monitoring/organisation").get_data(as_text=True)
        self.assertNotIn('id="orgAdd"', html)

    def test_after_adding_a_unit_the_next_step_is_offered(self):
        """A new unit is empty; the confirmation leads to its domains, with
        the unit already chosen there, and to a unit under it."""
        source = (JS / "organisation.js").read_text(encoding="utf-8")
        self.assertIn("/monitoring/domains?unit=${unit.id}&amp;add=1", source)
        self.assertIn('class="btn-ghost org-add-sub" data-id="${unit.id}"', source)
        self.assertIn("'Nothing — this is a company'", source)

    def test_the_new_unit_comes_back_with_the_id_and_path_the_confirmation_uses(self):
        self.login_as("user")
        top = self.client.post("/api/organisation/units", json={"name": "Example BV"}).get_json()
        sales = self.client.post("/api/organisation/units",
                                 json={"name": "Sales", "parent_id": top["id"]}).get_json()
        self.assertEqual("Example BV › Sales", sales["path"])
        self.assertIsInstance(sales["id"], int)


class UnitPageTests(EnterpriseAppTestCase):
    def test_a_unit_page_leads_to_adding_its_domains_and_units(self):
        unit = domain_portfolio.ensure_path("Example BV > Sales")
        self.login_as("user")
        html = self.client.get(f"/monitoring/organisation/{unit}").get_data(as_text=True)
        self.assertIn(f'href="/monitoring/domains?unit={unit}&amp;add=1"', html)
        self.assertIn(f'href="/monitoring/organisation?parent={unit}#orgAdd"', html)
        # And the organisation page chooses that parent when it gets ?parent=.
        source = (JS / "organisation.js").read_text(encoding="utf-8")
        self.assertIn("new URLSearchParams(location.search).get('parent')", source)


class PortfolioImportTests(EnterpriseAppTestCase):
    def test_the_unit_for_new_domains_is_chosen_from_a_list(self):
        """Typed as free text, "Example BV > Sale" made a second unit next to
        "Example BV > Sales". A list holds the units there are, and one
        option for a new one."""
        self.login_as("user")
        html = self.client.get("/monitoring/domains").get_data(as_text=True)
        self.assertIn('<select id="pfImportUnit"></select>', html)
        source = (JS / "portfolio.js").read_text(encoding="utf-8")
        self.assertIn("<option value=\"new\">New unit…</option>", source)
        self.assertIn("{ unit: newPath } : { unit_id: choice }", source)

    def test_arriving_from_a_unit_opens_the_form_with_it_chosen(self):
        source = (JS / "portfolio.js").read_text(encoding="utf-8")
        self.assertIn("if (wanted) pf.importUnit = wanted;", source)
        self.assertRegex(source, re.compile(r"params\.get\('add'\).*?pfImportFold'\)\.open = true", re.S))

    def test_a_workbook_goes_to_the_unit_chosen_by_its_id(self):
        """The list sends the unit's id, also with an Excel file; a unit
        whose name contains '>' or matches another's would otherwise be
        looked up by name and could land elsewhere."""
        import openpyxl
        unit = domain_portfolio.ensure_path("Example BV > Sales")
        book = openpyxl.Workbook()
        book.active.append(["Domain"])
        book.active.append(["example.nl"])
        buf = io.BytesIO()
        book.save(buf)
        self.login_as("user")
        resp = self.client.post("/api/portfolio/import", content_type="multipart/form-data",
                                data={"file": (io.BytesIO(buf.getvalue()), "domains.xlsx"),
                                      "unit_id": str(unit)})
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(unit, domain_portfolio.unit_of("example.nl")["id"])

    def test_a_new_unit_typed_with_the_import_is_created_where_the_path_says(self):
        self.login_as("user")
        domain_portfolio.ensure_path("Example BV")
        resp = self.client.post("/api/portfolio/import",
                                json={"text": "example.com", "unit": "Example BV > Marketing"})
        self.assertEqual(201, resp.status_code)
        self.assertEqual("Example BV › Marketing", domain_portfolio.unit_of("example.com")["path"])


if __name__ == "__main__":
    unittest.main()
