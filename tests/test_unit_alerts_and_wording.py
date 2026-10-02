"""Smaller things that made the organisation features harder to use.

Alerts went to one list, so a business unit could not hear about its own
domains alone. With the scheduler off the pages said "not measured" without
a reason. The API and the CSV still said "group" where every page said
"unit". The organisation tree could not be folded. And choosing Dutch gave
mixed pages without saying so where the choice is made.
"""

import os
import pathlib
import unittest
from unittest import mock

import domain_portfolio
import notifications
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


class UnitAlertTests(EnterpriseAppTestCase):
    def test_a_unit_and_the_units_above_it_get_its_alerts(self):
        top = domain_portfolio.ensure_path("Org X")
        sales = domain_portfolio.ensure_path("Org X > Sales")
        domain_portfolio.update_group(top, notify_emails="security@example.com")
        domain_portfolio.update_group(sales, notify_emails="sales-it@example.com, security@example.com")
        domain_portfolio.assign("example.nl", sales)
        unit, addresses = domain_portfolio.unit_recipients("www.example.nl")
        self.assertEqual("Org X › Sales", unit)
        self.assertEqual(["sales-it@example.com", "security@example.com"], addresses)

    def test_dispatch_mails_the_unit_once_and_names_it_everywhere(self):
        sales = domain_portfolio.ensure_path("Org X > Sales")
        domain_portfolio.update_group(sales, notify_emails="sales-it@example.com, ops@example.com")
        domain_portfolio.assign("example.nl", sales)
        cfg = {**notifications.config(), "enabled": True, "min_severity": "high",
               "smtp_host": "mail.example", "smtp_from": "dl@example.com", "email_to": ["ops@example.com"]}
        with mock.patch.object(notifications, "config", return_value=cfg), \
                mock.patch.object(notifications, "_deliver", return_value={}) as general, \
                mock.patch.object(notifications, "send_email") as mail:
            result = notifications.dispatch({"event_type": "domain_portfolio", "severity": "critical",
                                             "summary": "example.nl went into quarantine",
                                             "details": {"target": "example.nl"}},
                                            {"target": "example.nl", "name": "x"})
        self.assertEqual("Org X › Sales", general.call_args.args[1]["unit"])
        # ops@ is on the general list already: not mailed twice.
        self.assertEqual(["sales-it@example.com"], mail.call_args.args[0]["email_to"])
        self.assertTrue(result["unit_email"]["ok"])

    def test_a_bad_address_is_refused(self):
        unit = domain_portfolio.ensure_path("Org X")
        with self.assertRaises(ValueError):
            domain_portfolio.update_group(unit, notify_emails="not-an-address")


class SchedulerNoticeTests(EnterpriseAppTestCase):
    def test_the_pages_that_depend_on_the_scheduler_say_it_is_off_and_why(self):
        self.login_as("user")
        page = self.client.get("/monitoring").get_data(as_text=True)
        # The test setup switches it off through the environment.
        self.assertIn("scheduler-banner", page)
        self.assertIn("DOMAINLENS_DISABLE_SCHEDULER", page)
        self.assertNotIn("scheduler-banner", self.client.get("/").get_data(as_text=True))

    def test_switched_off_in_settings_it_links_to_the_setting(self):
        with mock.patch.dict(os.environ, {"DOMAINLENS_DISABLE_SCHEDULER": ""}), \
                mock.patch.object(self.app_module.domainlens_config, "load_settings") as load:
            load.return_value.scheduler.return_value = {"enabled": False}
            self.assertEqual("settings", self.app_module._scheduler_off())
            load.return_value.scheduler.return_value = {"enabled": True}
            self.assertIsNone(self.app_module._scheduler_off())


class UnitWordingTests(EnterpriseAppTestCase):
    def test_units_are_units_in_the_api_and_the_csv_and_old_names_still_work(self):
        self.login_as("user")
        unit = self.client.post("/api/organisation/units", json={"name": "Org X"}).get_json()
        self.client.post("/api/portfolio/import", json={"text": "example.nl", "unit_id": unit["id"]})
        domain = self.client.get("/api/portfolio").get_json()["domains"][0]
        self.assertEqual(("Org X", unit["id"]), (domain["unit"], domain["unit_id"]))
        csv_body = self.client.get(f"/api/portfolio/csv?unit={unit['id']}").get_data(as_text=True)
        self.assertTrue(csv_body.startswith("domain,unit,"))
        self.assertIn("example.nl,Org X", csv_body)
        # The names scripts may already use keep working.
        old = self.client.post("/api/portfolio/groups", json={"name": "Org Y"})
        self.assertEqual(201, old.status_code)


class PageTests(unittest.TestCase):
    def test_the_tree_folds_and_remembers_it_without_needing_storage(self):
        js = ROOT.joinpath("static", "js", "organisation.js").read_text(encoding="utf-8")
        self.assertIn("function orgHidden", js)
        self.assertIn("try { localStorage.setItem", js)

    def test_the_language_setting_says_what_dutch_covers(self):
        import settings.registry as registry
        self.assertEqual("settings.general.locale_warning",
                         registry.FIELD_META["general"]["locale"]["warning"])


if __name__ == "__main__":
    unittest.main()
