"""A monitor lands in its domain's unit however its target is written, the
form says which unit that is, and the portfolio table stays in its card.

The add-monitor form said "Keep as it is / none" for a host whose domain
already sat in a unit, so it looked as if nothing was linked. A target
written as a URL ("https://www.example.com:8443/") was looked up as the
domain "com:8443/", so it fell outside every unit. And the portfolio table
ran off the right of its card: the rule that lets a wide table scroll lived
only in the admin stylesheet.
"""

import pathlib
import unittest

import domain_portfolio
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


class HostTests(unittest.TestCase):
    def test_a_target_written_as_a_url_is_its_host(self):
        for target, host in (("https://WWW.Example.com:8443/x?q=1", "www.example.com"),
                             ("example.com.", "example.com"),
                             ("mail.example.co.uk", "mail.example.co.uk")):
            self.assertEqual(host, domain_portfolio.host_of(target), target)


class MonitorUnitTests(EnterpriseAppTestCase):
    def test_a_url_target_counts_in_the_unit_of_its_domain(self):
        sales = domain_portfolio.ensure_path("Example BV > Sales")
        domain_portfolio.assign("example.com", sales)
        self.db.create_monitor(name="site", domain="example.com",
                               target="https://www.example.com:8443/", record_type="A")
        self.login_as("user")
        listed = self.client.get("/api/monitors").get_json()["monitors"]
        self.assertEqual("Example BV › Sales", listed[0]["org_unit"]["path"])

    def test_the_form_looks_up_the_unit_of_a_host_and_chooses_it(self):
        """Unless the person chose a unit themselves: that choice stands."""
        sales = domain_portfolio.ensure_path("Example BV > Sales")
        domain_portfolio.assign("example.com", sales)
        self.login_as("user")
        info = self.client.get("/api/portfolio/unit?domain=www.example.com").get_json()
        self.assertEqual(sales, info["unit"]["id"])
        source = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("on('monitorDomainInput', 'input', monitorUnitLookupSoon);", source)
        self.assertIn("if (!select.dataset.manual) select.value = String(info.unit.id);", source)
        html = self.client.get("/monitoring").get_data(as_text=True)
        self.assertIn('id="monitorUnitFound"', html)


class LayoutTests(unittest.TestCase):
    def test_wide_tables_scroll_inside_their_card_on_every_page(self):
        css = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".users-table-wrap { overflow-x: auto; max-width: 100%; }", css)

    def test_the_portfolio_table_has_no_column_for_check_now_alone(self):
        """Looking a domain up again is in the row's menu, not a column or a
        button in every row."""
        source = (ROOT / "static" / "js" / "portfolio.js").read_text(encoding="utf-8")
        self.assertIn("<th>Use · threat intel</th><th>Decision</th><th>Contact</th>", source)
        self.assertIn("{ label: 'Look up again now', value: 'check' }", source)
        self.assertNotIn('class="btn-ghost-sm pf-check"', source)


if __name__ == "__main__":
    unittest.main()
