"""A contact per company or business unit, and decisions from the sheet.

A contact set on every domain one by one does not survive a portfolio of
hundreds: the person to ask is the one for the company or business unit.
Units and domains now inherit their unit's contact, as they inherit its
expected registrar, and a domain names its own only where it differs. The
spreadsheet an organisation already keeps -- with a decision and an owner
per domain -- could not be imported; those columns were ignored.
"""

import unittest

import contacts
import domain_portfolio
from enterprise_harness import EnterpriseAppTestCase


class InheritanceTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.company = domain_portfolio.ensure_path("Example BV")
        self.sales = domain_portfolio.ensure_path("Example BV > Sales")
        self.sam = contacts.create(name="Sam Example", email="sam@example.com")
        entries, _, _ = domain_portfolio.parse_import("example.nl;Example BV > Sales\nexample.com;Example BV")
        domain_portfolio.import_domains(entries)

    def domain(self, name):
        return next(d for d in domain_portfolio.list_all() if d["domain"] == name)

    def test_units_and_domains_below_a_unit_have_its_contact(self):
        domain_portfolio.update_group(self.company, contact_id=self.sam["id"])
        sales = domain_portfolio.get_group(self.sales)
        self.assertEqual(("Sam Example", True), (sales["contact"]["name"], sales["contact_inherited"]))
        row = self.domain("example.nl")
        self.assertEqual(("Sam Example", True), (row["contact"]["name"], row["contact_inherited"]))

    def test_a_domain_or_unit_with_its_own_contact_keeps_it(self):
        alex = contacts.create(name="Alex Example")
        domain_portfolio.update_group(self.company, contact_id=self.sam["id"])
        domain_portfolio.update_group(self.sales, contact_id=alex["id"])
        domain_portfolio.set_contact([self.domain("example.com")["id"]], alex["id"])
        # example.nl names no one: it has the nearest unit's, Sales', not the company's.
        self.assertEqual(("Alex Example", True),
                         (self.domain("example.nl")["contact"]["name"], self.domain("example.nl")["contact_inherited"]))
        self.assertEqual(("Alex Example", False),
                         (self.domain("example.com")["contact"]["name"], self.domain("example.com")["contact_inherited"]))

    def test_clearing_a_domain_contact_falls_back_on_the_unit(self):
        domain_portfolio.update_group(self.company, contact_id=self.sam["id"])
        alex = contacts.create(name="Alex Example")
        domain_id = self.domain("example.com")["id"]
        domain_portfolio.set_contact([domain_id], alex["id"])
        domain_portfolio.set_contact([domain_id], None)
        self.assertEqual("Sam Example", self.domain("example.com")["contact"]["name"])

    def test_a_contact_lists_the_units_it_is_set_on(self):
        domain_portfolio.update_group(self.sales, contact_id=self.sam["id"])
        listed = next(c for c in contacts.list_contacts() if c["id"] == self.sam["id"])
        self.assertEqual(([self.sales], 1), (listed["unit_ids"], listed["units"]))

    def test_deleting_a_contact_clears_it_from_units(self):
        domain_portfolio.update_group(self.company, contact_id=self.sam["id"])
        contacts.delete(self.sam["id"])
        self.assertIsNone(domain_portfolio.get_group(self.company)["contact"])

    def test_a_merge_keeps_a_contact_the_target_did_not_have(self):
        other = domain_portfolio.ensure_path("Example Holding")
        domain_portfolio.update_group(other, contact_id=self.sam["id"])
        domain_portfolio.merge_group(other, self.company)
        self.assertEqual("Sam Example", domain_portfolio.get_group(self.company)["contact"]["name"])

    def test_the_csv_says_where_the_contact_comes_from(self):
        domain_portfolio.update_group(self.company, contact_id=self.sam["id"])
        body = domain_portfolio.to_csv(domain_portfolio.list_all())
        header, *rows = [line.split(",") for line in body.splitlines()]
        by_domain = {r[0]: dict(zip(header, r)) for r in rows}
        self.assertEqual(("Sam Example", "unit"),
                         (by_domain["example.nl"]["contact"], by_domain["example.nl"]["contact_from"]))

    def test_the_api_sets_and_clears_a_unit_contact(self):
        self.login_as("user")
        made = self.client.post("/api/organisation/units",
                                json={"name": "Marketing", "parent_id": self.company,
                                      "contact_id": self.sam["id"]}).get_json()
        self.assertEqual("Sam Example", made["contact"]["name"])
        cleared = self.client.put(f"/api/organisation/units/{made['id']}", json={"contact_id": None}).get_json()
        self.assertIsNone(cleared["contact"])
        bad = self.client.put(f"/api/organisation/units/{made['id']}", json={"contact_id": 999})
        self.assertEqual(400, bad.status_code)


class SheetImportTests(EnterpriseAppTestCase):
    SHEET = "\n".join([
        "Domein;Bedrijf;Besluit;Contactpersoon;E-mail;Threat intel",
        "example.nl;Sales;Opzeggen;Sam Example;sam@example.com;ja",
        "example.com;Sales;Keep and renew;Alex Example <alex@example.com>;;nee",
        "example.org;Sales;verkopen;;;",
    ])

    def run_import(self, text=None):
        entries, _, _, extras = domain_portfolio.parse_import_full(text or self.SHEET)
        return domain_portfolio.import_domains(entries, extras=extras)

    def domain(self, name):
        return next(d for d in domain_portfolio.list_all() if d["domain"] == name)

    def test_decision_contact_and_threat_intel_columns_are_read(self):
        result = self.run_import()
        nl, com = self.domain("example.nl"), self.domain("example.com")
        self.assertEqual(("cancel", True, "Sam Example"), (nl["lifecycle"], nl["threat_intel"], nl["contact"]["name"]))
        self.assertEqual(("keep", False, "alex@example.com"), (com["lifecycle"], com["threat_intel"], com["contact"]["email"]))
        self.assertEqual(sorted(["Sam Example", "Alex Example"]), sorted(result["contacts_created"]))

    def test_a_decision_not_understood_is_reported_and_not_guessed(self):
        """"verkopen" (sell) is no decision this tool has; keep stays."""
        result = self.run_import()
        self.assertEqual("keep", self.domain("example.org")["lifecycle"])
        self.assertIn("example.org: verkopen", result["not_understood"])

    def test_an_existing_contact_is_found_not_made_twice(self):
        self.run_import()
        result = self.run_import("Domain;Owner\nexample.org;SAM@example.com")
        self.assertEqual([], result["contacts_created"])
        self.assertEqual(1, sum(1 for c in contacts.list_contacts() if c["email"] == "sam@example.com"))
        self.assertEqual("Sam Example", self.domain("example.org")["contact"]["name"])

    def test_an_address_of_an_account_links_the_account(self):
        user_id = self.db.create_user(email="lee@example.com", name="Lee Example", provider="oauth")
        self.run_import("Domain;Contact\nexample.net;lee@example.com")
        contact = self.domain("example.net")["contact"]
        self.assertEqual(("Lee Example", user_id), (contact["name"], contact["account"]["id"]))

    def test_an_empty_cell_changes_nothing(self):
        self.run_import()
        self.run_import("\n".join(["Domain;Decision;Contact", "example.nl;;"]))
        nl = self.domain("example.nl")
        self.assertEqual(("cancel", "Sam Example"), (nl["lifecycle"], nl["contact"]["name"]))

    def test_the_import_api_reads_the_columns(self):
        self.login_as("user")
        resp = self.client.post("/api/portfolio/import", json={"text": self.SHEET})
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(2, resp.get_json()["decisions"])

    def test_dutch_and_english_decision_words(self):
        for text, expected in (("Behouden en verlengen", "keep"), ("Cancel (let it lapse)", "cancel"),
                               ("aanvragen", "claim"), ("Nog te besluiten", "review"), ("", None),
                               ("verkopen", "")):
            self.assertEqual(expected, domain_portfolio.decision_of(text), text)


if __name__ == "__main__":
    unittest.main()
