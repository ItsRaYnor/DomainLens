"""A decision, a contact and threat intelligence for every domain.

The portfolio treated every domain as one to keep: a domain someone had
decided to let lapse raised the same expiry and quarantine alarms as the
main website, and a domain the organisation wanted to acquire was reported
as "not registered", critical, when coming free was the point. Nothing said
whether a domain was in use, so nobody could tell which ones belonged with
the threat intelligence service. And the person to ask was nowhere, or a
name typed into a note.
"""

import pathlib
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import contacts
import domain_portfolio
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent
_NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _answer(phase="registered", expires=None, registrar="Example Registrar"):
    return {"success": True, "source": "rdap", "status": ["active"],
            "registrar": {"name": registrar}, "expires": expires,
            "nameservers": ["ns1.example.net"], "lifecycle": {"phase": phase}}


def _dns(answers):
    """A query function over {(name, type): records | "SERVFAIL"}."""
    def query(name, rtype):
        found = answers.get((name, rtype), [])
        if found == "SERVFAIL":
            return {"records": [], "rcode": "SERVFAIL", "error": None}
        return {"records": found, "rcode": "NOERROR" if found else "NXDOMAIN", "error": None}
    return query


class DecisionTestCase(EnterpriseAppTestCase):
    def add(self, domain):
        entries, _, _ = domain_portfolio.parse_import(domain)
        domain_portfolio.import_domains(entries)
        return self.row(domain)["id"]

    def row(self, domain):
        return next(d for d in domain_portfolio.list_all(today=_NOW.date()) if d["domain"] == domain)

    def raw(self, domain):
        return domain_portfolio.raw(self.row(domain)["id"])

    def look_up(self, domain, answer, notify=None, probe=None):
        domain_portfolio.check(self.raw(domain), fetch=lambda d: answer, now=_NOW,
                               notify=notify or mock.Mock(), probe=probe)


class LifecycleTests(DecisionTestCase):
    def test_a_new_domain_is_kept_by_default(self):
        self.add("example.nl")
        self.assertEqual(("keep", "Keep and renew"),
                         (self.row("example.nl")["lifecycle"], self.row("example.nl")["lifecycle_text"]))

    def test_a_domain_being_cancelled_raises_no_expiry_or_quarantine_alarm(self):
        """Letting it lapse was the plan; an alarm about it is advice nobody can act on."""
        domain_id = self.add("example.nl")
        self.look_up("example.nl", _answer())
        domain_portfolio.set_lifecycle([domain_id], "cancel")
        notify = mock.Mock()
        soon = (_NOW + timedelta(days=5)).date().isoformat()
        self.look_up("example.nl", _answer(expires=soon), notify)
        self.look_up("example.nl", _answer(phase="quarantine", expires=soon), notify)
        self.assertEqual(["low"], [c.args[1] for c in notify.call_args_list])
        row = self.row("example.nl")
        self.assertNotIn("attention", row["flags"])
        self.assertNotIn("expiring", row["flags"])

    def test_a_takeover_of_a_domain_being_cancelled_is_still_news(self):
        """Until it lapses it is still yours, and a changed registrar can be a hijack."""
        domain_id = self.add("example.nl")
        self.look_up("example.nl", _answer())
        domain_portfolio.set_lifecycle([domain_id], "cancel")
        notify = mock.Mock()
        self.look_up("example.nl", _answer(registrar="Other Registrar"), notify)
        self.assertEqual("high", notify.call_args.args[1])

    def test_a_domain_to_claim_coming_free_is_the_news_not_an_alarm(self):
        domain_id = self.add("example.com")
        self.look_up("example.com", _answer(registrar="Someone Else's Registrar"))
        domain_portfolio.set_lifecycle([domain_id], "claim")
        notify = mock.Mock()
        self.look_up("example.com", {"success": False, "registered": False}, notify)
        severity, text = notify.call_args.args[1], notify.call_args.args[2]
        self.assertEqual("high", severity)
        self.assertIn("can be requested now", text)
        row = self.row("example.com")
        self.assertIn("claimable", row["flags"])
        self.assertNotIn("attention", row["flags"])

    def test_a_domain_not_held_has_no_registrar_to_move_to(self):
        unit = domain_portfolio.ensure_path("Example BV")
        domain_portfolio.update_group(unit, expected_registrar="Example Registrar")
        domain_id = self.add("example.nl")
        domain_portfolio.move([domain_id], unit)
        self.look_up("example.nl", _answer(registrar="Other Registrar"))
        self.assertIn("move", self.row("example.nl")["flags"])
        domain_portfolio.set_lifecycle([domain_id], "cancel")
        self.assertEqual("not_applicable", self.row("example.nl")["transfer"])

    def test_an_unknown_decision_is_refused(self):
        domain_id = self.add("example.nl")
        with self.assertRaises(ValueError):
            domain_portfolio.set_lifecycle([domain_id], "sell")


class UsageTests(unittest.TestCase):
    def test_a_null_mx_and_spf_without_senders_mean_no_mail(self):
        """"0 ." and "v=spf1 -all" are how a domain says it has no mail."""
        found = domain_portfolio.probe_usage("example.nl", _dns({
            ("example.nl", "MX"): ["0 ."], ("example.nl", "TXT"): ["v=spf1 -all"]}))
        self.assertEqual({"mail": False, "web": False, "dns": "ok"}, found)

    def test_a_domain_that_only_sends_mail_is_in_use(self):
        found = domain_portfolio.probe_usage("example.nl", _dns({
            ("example.nl", "TXT"): ["v=spf1 include:_spf.example.net -all"]}))
        self.assertTrue(found["mail"])

    def test_no_answer_is_not_measured_rather_than_no(self):
        """A resolver failure would otherwise mark a mail domain as unused,
        and so as not needing threat intelligence."""
        found = domain_portfolio.probe_usage("example.nl", _dns({
            ("example.nl", "MX"): "SERVFAIL", ("www.example.nl", "A"): ["192.0.2.1"]}))
        self.assertEqual({"mail": None, "web": True, "dns": "ok"}, found)


class ThreatIntelTests(DecisionTestCase):
    def test_a_domain_in_use_without_threat_intel_is_flagged_and_one_unused_is_not(self):
        self.add("example.nl")
        self.add("example.com")
        self.look_up("example.nl", _answer(), probe=lambda d: {"mail": True, "web": False})
        self.look_up("example.com", _answer(), probe=lambda d: {"mail": False, "web": False})
        used, unused = self.row("example.nl"), self.row("example.com")
        self.assertEqual(("in_use", "missing"), (used["usage"], used["threat_intel_state"]))
        self.assertIn("intel", used["flags"])
        self.assertEqual(("unused", "not_needed"), (unused["usage"], unused["threat_intel_state"]))
        domain_portfolio.set_threat_intel([used["id"]], True)
        self.assertEqual("enrolled", self.row("example.nl")["threat_intel_state"])
        self.assertNotIn("intel", self.row("example.nl")["flags"])

    def test_use_not_measured_is_not_reported_as_not_needed(self):
        self.add("example.nl")
        self.look_up("example.nl", _answer())
        row = self.row("example.nl")
        self.assertEqual(("unmeasured", "unmeasured"), (row["usage"], row["threat_intel_state"]))

    def test_use_not_measured_has_a_count_of_its_own(self):
        """The "Not measured" tile counted only registration lookups: domains
        looked up before use was measured showed 0 there, and appeared in no
        tile at all. A domain being cancelled does not need the answer."""
        self.add("example.nl")
        dropped = self.add("example.com")
        self.look_up("example.nl", _answer())
        self.look_up("example.com", _answer())
        domain_portfolio.set_lifecycle([dropped], "cancel")
        self.assertIn("use_unmeasured", self.row("example.nl")["flags"])
        self.assertNotIn("use_unmeasured", self.row("example.com")["flags"])
        domains = domain_portfolio.list_all(today=_NOW.date())
        totals = domain_portfolio.summary(domains, domain_portfolio.list_groups())["total"]
        self.assertEqual((1, 0), (totals["use_unmeasured"], totals["unmeasured"]))
        source = (ROOT / "static" / "js" / "portfolio.js").read_text(encoding="utf-8")
        self.assertIn("tile('Use not measured', t.use_unmeasured, 'use_unmeasured', '')", source)

    def test_a_failed_measurement_keeps_the_last_one(self):
        self.add("example.nl")
        self.look_up("example.nl", _answer(), probe=lambda d: {"mail": True, "web": True})
        self.look_up("example.nl", _answer(), probe=lambda d: {"mail": None, "web": None})
        self.assertEqual(("yes", "yes"), (self.row("example.nl")["uses_mail"], self.row("example.nl")["uses_web"]))

    def test_a_domain_without_dns_is_measurably_unused(self):
        self.add("example.nl")
        self.look_up("example.nl", _answer(phase="quarantine"))
        self.assertEqual("unused", self.row("example.nl")["usage"])


class ContactTests(DecisionTestCase):
    def test_a_contact_that_is_an_account_follows_the_account(self):
        """With single sign-on the account is kept current; a copy would go stale."""
        user_id = self.db.create_user(email="sam@example.com", name="Sam Example", provider="oauth")
        contact = contacts.create(user_id=user_id)
        self.db.update_user(user_id, name="Sam Example-Other")
        self.assertEqual("Sam Example-Other", contacts.get(contact["id"])["name"])
        self.assertEqual(contact["id"], contacts.create(user_id=user_id)["id"])
        self.assertNotIn(user_id, [a["id"] for a in contacts.accounts()])

    def test_a_removed_account_leaves_the_last_known_name_and_says_so(self):
        user_id = self.db.create_user(email="sam@example.com", name="Sam Example")
        contact = contacts.create(user_id=user_id)
        self.db.delete_user(user_id)
        after = contacts.get(contact["id"])
        self.assertEqual(("Sam Example", "removed"), (after["name"], after["account"]["state"]))

    def test_deleting_a_contact_leaves_its_domains_without_one(self):
        domain_id = self.add("example.nl")
        contact = contacts.create(name="Sam Example", email="sam@example.com")
        domain_portfolio.set_contact([domain_id], contact["id"])
        self.assertEqual("Sam Example", self.row("example.nl")["contact"]["name"])
        contacts.delete(contact["id"])
        self.assertIsNone(self.row("example.nl")["contact"])

    def test_a_contact_needs_a_name_or_a_valid_address(self):
        with self.assertRaises(ValueError):
            contacts.create(phone="+31 20 000 0000")
        with self.assertRaises(ValueError):
            contacts.create(name="Sam", email="not-an-address")


class ApiTests(DecisionTestCase):
    def test_bulk_decision_threat_intel_and_contact(self):
        domain_id = self.add("example.nl")
        self.login_as("user")
        contact = self.client.post("/api/contacts", json={"name": "Sam Example"}).get_json()
        for action, value in (("lifecycle", "review"), ("threat_intel", True), ("contact", contact["id"])):
            resp = self.client.post("/api/portfolio/domains",
                                    json={"action": action, "ids": [domain_id], "value": value})
            self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        row = self.client.get("/api/portfolio").get_json()["domains"][0]
        self.assertEqual(("review", True, "Sam Example"),
                         (row["lifecycle"], row["threat_intel"], row["contact"]["name"]))

    def test_the_decisions_are_offered_with_keep_first(self):
        """Sent as an object, they came out sorted: "Cancel" first, the
        default last, so a careless "Set decision" let domains lapse."""
        self.login_as("user")
        offered = self.client.get("/api/portfolio").get_json()["lifecycles"]
        self.assertEqual(["keep", "review", "cancel", "claim"], [l["value"] for l in offered])

    def test_bad_values_are_refused(self):
        domain_id = self.add("example.nl")
        self.login_as("user")
        for action, value in (("lifecycle", "sell"), ("threat_intel", "yes"), ("contact", 999)):
            resp = self.client.post("/api/portfolio/domains",
                                    json={"action": action, "ids": [domain_id], "value": value})
            self.assertEqual(400, resp.status_code, action)

    def test_a_viewer_sees_contacts_but_not_the_accounts_or_changes_them(self):
        self.login_as("viewer")
        body = self.client.get("/api/contacts").get_json()
        self.assertNotIn("accounts", body)
        self.assertEqual(403, self.client.post("/api/contacts", json={"name": "Sam"}).status_code)
        self.login_as("user")
        self.assertIn("accounts", self.client.get("/api/contacts").get_json())

    def test_the_csv_says_not_measured_with_an_empty_cell_not_no(self):
        self.add("example.nl")
        self.login_as("user")
        lines = self.client.get("/api/portfolio/csv").get_data(as_text=True).splitlines()
        header, row = lines[0].split(","), lines[1].split(",")
        values = dict(zip(header, row))
        self.assertEqual(("keep", "unmeasured", ""), (values["decision"], values["threat_intel"], values["mail"]))


class PageTests(EnterpriseAppTestCase):
    def test_the_portfolio_shows_and_sets_the_new_columns(self):
        self.login_as("user")
        html = self.client.get("/monitoring/domains").get_data(as_text=True)
        for marker in ('data-menu="decision"', 'data-menu="intel"', 'data-menu="contact"',
                       '<option value="intel">', "contact_picker.js"):
            self.assertIn(marker, html)
        source = (ROOT / "static" / "js" / "portfolio.js").read_text(encoding="utf-8")
        self.assertIn("<th>Use · threat intel</th><th>Decision</th><th>Contact</th>", source)

    def test_threat_intel_and_the_contact_are_set_on_the_row_itself(self):
        """Selecting a row and finding the right button above the table for
        one domain was the only way; the row now has a switch and a button."""
        source = (ROOT / "static" / "js" / "portfolio.js").read_text(encoding="utf-8")
        self.assertIn('class="switch pf-intel" role="switch"', source)
        self.assertIn("pfApply('threat_intel', [id], on)", source)
        self.assertIn("pf-contact-link", source)
        # Nobody to choose yet: the picker starts on a new contact.
        self.assertIn("if (!contactBook.contacts.length && !contactBook.accounts.length) select.value = 'new';", source)

    def test_contacts_are_managed_with_the_organisation(self):
        self.login_as("user")
        org = self.client.get("/monitoring/organisation").get_data(as_text=True)
        domains = self.client.get("/monitoring/domains").get_data(as_text=True)
        for marker in ('id="orgContacts"', 'id="orgContactList"', 'id="orgContactUnit"', 'id="orgNewContact"'):
            self.assertIn(marker, org)
        self.assertNotIn("orgContactList", domains)

    def test_a_contact_card_links_to_a_unit_and_unlinks_from_one(self):
        """From the person: which units they are the contact for, and one
        more to link -- without going through every unit's row."""
        source = (ROOT / "static" / "js" / "organisation.js").read_text(encoding="utf-8")
        self.assertIn("org-c-link", source)
        self.assertIn("await orgSetUnitContact(btn.dataset.unit, null);", source)

    def test_small_buttons_are_styled_and_do_not_wrap(self):
        """btn-ghost-sm was used on many pages and defined nowhere: in a
        narrow cell "Save" and "Delete" stood one letter per line."""
        css = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")
        rule = css[css.index("\n.btn-ghost-sm {"):]
        rule = rule[:rule.index("}")]
        self.assertIn("white-space: nowrap", rule)


if __name__ == "__main__":
    unittest.main()
