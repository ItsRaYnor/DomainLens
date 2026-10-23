"""A unit's contact after the fact, and an import that updates what is there.

A unit's contact could only be chosen when the unit was made: on the unit
page there was no way to add one later, change it or take it away, short
of adding the unit again. The page now has its own contact card, and every
change is in the audit log with what it was and what it became.

Importing the portfolio's own CSV, with threat intelligence switched on for
a domain, reported that domain as "already there" and nothing else. The
values were partly applied, but nobody could see it, the export's own state
words ("missing", "unmeasured") and its mail column came back as errors,
and the unit's contact was copied onto every domain that inherited it. An
import now updates existing domains from the columns the file has, lists
each change (field, from, to), and says which values it could not use.
"""

import unittest

import audit_log
import contacts
import db
import domain_portfolio
from enterprise_harness import EnterpriseAppTestCase


class UnitContactTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.company = domain_portfolio.ensure_path("Example BV")
        self.sales = domain_portfolio.ensure_path("Example BV > Sales")
        self.sam = contacts.create(name="Sam Example", email="sam@example.com")
        self.alex = contacts.create(name="Alex Example", email="alex@example.com")

    def test_the_unit_page_offers_an_editor_a_way_to_add_change_and_remove_the_contact(self):
        """Without it, adding a contact later meant making the unit again."""
        self.login_as("user")
        page = self.client.get(f"/monitoring/organisation/{self.sales}").get_data(as_text=True)
        for marker in ('id="unitContactChoice"', 'id="unitContactSave"', 'id="unitContactRemove"',
                       "/static/js/contact_picker.js"):
            self.assertIn(marker, page)

    def test_a_viewer_sees_the_contact_but_gets_no_controls_and_cannot_change_it(self):
        """Roles as for every other unit edit: a viewer reads, a user changes."""
        self.login_as("viewer")
        page = self.client.get(f"/monitoring/organisation/{self.sales}").get_data(as_text=True)
        self.assertIn('id="unitContactNow"', page)
        self.assertNotIn('id="unitContactChoice"', page)
        resp = self.client.put(f"/api/organisation/units/{self.sales}", json={"contact_id": self.sam["id"]})
        self.assertEqual(403, resp.status_code)
        self.assertIsNone(domain_portfolio.get_group(self.sales)["contact_id"])

    def test_the_unit_script_saves_and_removes_the_contact_through_the_unit_api(self):
        source = (self.app_module.app.root_path + "/static/js/unit.js")
        with open(source, encoding="utf-8") as handle:
            js = handle.read()
        self.assertIn("'/api/organisation/units/' + $('main').dataset.unitId", js)
        self.assertIn("contactResolve(pick)", js)
        self.assertIn("unitSetContact(null)", js)

    def test_adding_changing_and_removing_a_unit_contact_is_audited_from_and_to(self):
        """The log said "portfolio.group_update" and nothing about what
        changed, so a contact taken away left no trace of who it was."""
        self.login_as("user")
        url = f"/api/organisation/units/{self.sales}"
        for contact_id in (self.sam["id"], self.alex["id"], None):
            self.assertEqual(200, self.client.put(url, json={"contact_id": contact_id}).status_code)
        entries = audit_log.list_entries(action="portfolio.group_update")["entries"]
        changes = [e["details"]["changes"]["contact"] for e in reversed(entries)]
        sam = {"id": self.sam["id"], "name": "Sam Example"}
        alex = {"id": self.alex["id"], "name": "Alex Example"}
        self.assertEqual([{"from": None, "to": sam}, {"from": sam, "to": alex}, {"from": alex, "to": None}],
                         changes)

    def test_saving_a_unit_without_changing_its_contact_logs_no_contact_change(self):
        domain_portfolio.update_group(self.sales, contact_id=self.sam["id"])
        self.login_as("user")
        self.client.put(f"/api/organisation/units/{self.sales}", json={"name": "Sales and Marketing"})
        details = audit_log.list_entries(action="portfolio.group_update")["entries"][0]["details"]
        self.assertEqual({"name": {"from": "Sales", "to": "Sales and Marketing"}}, details["changes"])

    def test_an_inherited_contact_names_the_unit_it_is_set_on(self):
        """The page has to say where to change a contact it inherits."""
        domain_portfolio.update_group(self.company, contact_id=self.sam["id"])
        sales = domain_portfolio.get_group(self.sales)
        self.assertEqual((True, {"id": self.company, "path": "Example BV"}),
                         (sales["contact_inherited"], sales["contact_unit"]))
        domain_portfolio.update_group(self.sales, contact_id=self.alex["id"])
        self.assertEqual(self.sales, domain_portfolio.get_group(self.sales)["contact_unit"]["id"])


class ImportUpdateTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.company = domain_portfolio.ensure_path("Example BV")
        self.sam = contacts.create(name="Sam Example", email="sam@example.com")
        domain_portfolio.update_group(self.company, contact_id=self.sam["id"])
        entries, _, _, _ = domain_portfolio.parse_import_full(
            "example.nl;Example BV\nexample.com;Example BV\nexample.org")
        domain_portfolio.import_domains(entries)
        # Measured use: the export writes yes / no in its mail and web columns.
        with db._connect() as conn:
            conn.execute("UPDATE portfolio_domains SET uses_mail = 'yes', uses_web = 'no'")

    def run_import(self, text, **kwargs):
        parsed = domain_portfolio.parse_import_details(text)
        return domain_portfolio.import_domains(parsed["entries"], extras=parsed["extras"],
                                               labels=parsed["labels"], **kwargs)

    def row(self, name):
        return next(d for d in domain_portfolio.list_all() if d["domain"] == name)

    def exported(self, **edits):
        """The portfolio's CSV, with cells changed per domain."""
        lines = domain_portfolio.to_csv(domain_portfolio.list_all()).splitlines()
        header = lines[0].split(",")
        out = [lines[0]]
        for line in lines[1:]:
            cells = line.split(",")
            for column, value in edits.get(cells[0].replace(".", "_"), {}).items():
                cells[header.index(column)] = value
            out.append(",".join(cells))
        return "\n".join(out)

    def test_the_export_with_threat_intel_switched_on_updates_that_domain_and_lists_the_change(self):
        """The reported case: the row was counted as "already there"."""
        result = self.run_import(self.exported(example_nl={"threat_intel": "yes"}))
        self.assertTrue(self.row("example.nl")["threat_intel"])
        self.assertEqual(["example.nl"], result["updated"])
        self.assertEqual([{"domain": "example.nl", "field": "threat_intel",
                           "from": "Not enrolled", "to": "Enrolled"}], result["changes"])
        self.assertEqual(sorted(["example.com", "example.org"]), sorted(result["unchanged"]))

    def test_the_export_imported_as_it_is_changes_nothing_and_reports_nothing_unusable(self):
        """Its threat intel states and mail column came back as errors, and
        the unit's contact was written onto each domain that inherited it."""
        result = self.run_import(self.exported())
        self.assertEqual(([], [], []), (result["added"], result["updated"], result["changes"]))
        self.assertEqual([], result["not_used"])
        self.assertTrue(self.row("example.nl")["contact_inherited"])
        self.assertEqual([], result["contacts_created"])

    def test_columns_the_import_does_not_read_are_named(self):
        parsed = domain_portfolio.parse_import_details(self.exported())
        self.assertIn("threat_intel", parsed["columns"]["read"])
        for measured in ("phase", "registrar", "mail", "web", "contact_from"):
            self.assertIn(measured, parsed["columns"]["not_read"])

    def test_the_mail_column_is_not_taken_for_the_contact_address(self):
        """"mail" (yes or no: does the domain take mail) matched the e-mail
        header before contact_email did, so every contact failed on "yes"."""
        parsed = domain_portfolio.parse_import_details(
            "\n".join(["domain,mail,contact,contact_email", "example.nl,yes,Alex Example,alex@example.com"]))
        self.assertEqual("alex@example.com", parsed["extras"]["example.nl"]["email"])

    def test_decision_unit_and_contact_changes_are_listed_per_field(self):
        text = "\n".join(["Domain;Unit;Decision;Contact",
                          "example.com;Example BV > Sales;cancel;Alex Example <alex@example.com>"])
        result = self.run_import(text)
        self.assertEqual([("unit", "Example BV", "Example BV › Sales"),
                          ("decision", "Keep and renew", "Cancel (let it lapse)"),
                          ("contact", "Sam Example (inherited)", "Alex Example")],
                         [(c["field"], c["from"], c["to"]) for c in result["changes"]])
        self.assertEqual("cancel", self.row("example.com")["lifecycle"])

    def test_an_empty_cell_or_a_missing_column_keeps_what_is_stored(self):
        self.run_import("\n".join(["domain,decision,threat_intel", "example.nl,cancel,yes"]))
        result = self.run_import("\n".join(["domain,decision", "example.nl,"]))
        row = self.row("example.nl")
        self.assertEqual(("cancel", True, "Example BV"), (row["lifecycle"], row["threat_intel"], row["group"]))
        self.assertEqual((["example.nl"], []), (result["unchanged"], result["changes"]))

    def test_the_unit_chosen_for_the_file_does_not_move_a_domain_already_in_a_unit(self):
        """A file without a unit column moved every existing domain into
        the unit chosen in the form, overwriting where each one was."""
        other = domain_portfolio.ensure_path("Example Holding")
        result = self.run_import("\n".join(["domain,threat_intel", "example.nl,yes", "example.org,yes"]),
                                 default_group_id=other)
        self.assertEqual("Example BV", self.row("example.nl")["group"])
        # A domain in no unit yet takes the chosen one: that wipes nothing.
        self.assertEqual("Example Holding", self.row("example.org")["group"])
        self.assertEqual([{"domain": "example.nl", "unit": "Example BV"}], result["stayed"])

    def test_a_value_that_cannot_be_used_is_reported_with_its_column_and_why(self):
        result = self.run_import("Domein;Besluit;Threat intel;E-mail\n"
                                 "example.nl;verkopen;misschien;not-an-address")
        by_column = {n["column"]: n for n in result["not_used"]}
        self.assertEqual({"Besluit", "Threat intel", "E-mail"}, set(by_column))
        self.assertEqual(("verkopen", "Not a decision this tool knows"),
                         (by_column["Besluit"]["value"], by_column["Besluit"]["reason"]))
        self.assertEqual("keep", self.row("example.nl")["lifecycle"])

    def test_a_domain_on_a_second_line_is_reported_not_silently_dropped(self):
        parsed = domain_portfolio.parse_import_details(
            "\n".join(["domain;decision", "example.nl;keep", "www.example.nl;cancel"]))
        self.assertEqual(["example.nl"], parsed["repeated"])
        self.assertEqual([("example.nl", None)], parsed["entries"])

    def test_the_import_api_returns_the_overview_and_logs_each_change(self):
        self.login_as("user")
        resp = self.client.post("/api/portfolio/import",
                                json={"text": self.exported(example_com={"threat_intel": "enrolled",
                                                                         "decision": "review"})})
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        body = resp.get_json()
        self.assertEqual((["example.com"], 2, 0), (body["updated"], len(body["changes"]), len(body["added"])))
        self.assertIn("mail", body["columns"]["not_read"])
        logged = audit_log.list_entries(action="portfolio.import")["entries"][0]["details"]
        self.assertEqual((1, body["changes"]), (logged["updated"], logged["changes"]))

    def test_the_portfolio_page_shows_the_changes_and_the_values_not_used(self):
        self.login_as("user")
        page = self.client.get("/monitoring/domains").get_data(as_text=True)
        self.assertIn('<div class="pf-import-result" id="pfImportResult"', page)
        with open(self.app_module.app.root_path + "/static/js/portfolio.js", encoding="utf-8") as handle:
            js = handle.read()
        self.assertIn("Changes to domains already in the portfolio", js)
        self.assertIn("Values from the file that were not used", js)


if __name__ == "__main__":
    unittest.main()
