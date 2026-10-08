"""The domain portfolio, made simpler to work with.

Above the domains stood five lists, each with its own "Set ..." button, and
a red remove button -- also with nothing selected; every change took a
choice and then a second click. A row said "Registered", the time it was
looked up and a "Check now" button, and on an ordinary screen the contact
column fell off the table. Monitoring was a list and a button apart from
the domains, with no way to tell a unit to monitor everything in it.
"""

import pathlib
import unittest

from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent
JS = (ROOT / "static" / "js" / "portfolio.js").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")


class ActionBarTests(EnterpriseAppTestCase):
    def test_the_action_bar_shows_only_with_a_selection(self):
        self.login_as("user")
        html = self.client.get("/monitoring/domains").get_data(as_text=True)
        self.assertIn('class="pf-bulkbar hidden" id="pfBulkBar"', html)
        self.assertIn("bar.classList.toggle('hidden', !pf.selected.size);", JS)

    def test_there_is_no_second_set_button(self):
        self.login_as("user")
        html = self.client.get("/monitoring/domains").get_data(as_text=True)
        for gone in ("pfLifecycleBtn", "pfIntelBtn", "pfContactBtn", "pfMoveBtn", "pfMonitorBtn", "Set decision"):
            self.assertNotIn(gone, html)
        for menu in ("move", "monitor", "decision", "intel", "contact", "more"):
            self.assertIn(f'data-menu="{menu}"', html)


class ApplyTests(unittest.TestCase):
    def test_a_choice_is_applied_at_once_and_can_be_undone(self):
        self.assertIn("pfOpenMenu(button, pfUnitItems(), v => pfApply('move', ids, v));", JS)
        self.assertIn("function pfBefore(action, d)", JS)
        self.assertIn("for (const [key, group] of before) await pfPost('/api/portfolio/domains', pfBody(action, group, JSON.parse(key)));", JS)

    def test_removing_asks_first_and_has_no_undo(self):
        self.assertIn("if (action === 'remove' && !confirm(", JS)
        self.assertIn("const undo = action === 'remove' ? null :", JS)


class RowTests(unittest.TestCase):
    def test_a_row_is_compact(self):
        """The lookup time is a tooltip, "Check now" is in the row's menu."""
        self.assertIn("title=\"${esc(looked)}\"", JS)
        self.assertIn('<th>Registration</th>', JS)
        self.assertIn("class=\"btn-ghost-sm pf-row-menu\"", JS)

    def test_the_decision_and_monitoring_are_set_on_the_row(self):
        self.assertIn('<select class="pf-decision"', JS)
        self.assertIn("pfApply('lifecycle', [e.target.closest('tr[data-id]').dataset.id], e.target.value);", JS)
        self.assertIn("button.pf-shield", JS)

    def test_use_is_two_labels(self):
        self.assertIn("chip(d.uses_mail, 'Mail', '✉') + chip(d.uses_web, 'Web', '🌐')", JS)

    def test_the_decision_list_keeps_its_text_and_the_table_its_card(self):
        self.assertIn(".pf-decision { width: 100%; min-width: 8.5rem; max-width: 10rem;", CSS)


class UnitTests(unittest.TestCase):
    def test_a_unit_says_how_much_is_monitored_and_offers_one_menu(self):
        self.assertIn("Security monitoring: ${on} of ${held.length} domains${scope}", JS)
        self.assertIn("`/api/portfolio/groups/${groupId}/monitoring`", JS)

    def test_domains_without_a_unit_stand_out(self):
        self.assertIn("domain(s) are not in a unit yet.", JS)
        self.assertIn('id="pfAssignLoose"', JS)




class MenuTests(unittest.TestCase):
    def test_a_menu_follows_its_button_while_the_page_scrolls(self):
        """The action bar stays at the top while the page scrolls; a menu
        opened from it was placed once and left floating over the domains."""
        self.assertIn("window.addEventListener('scroll', pfPlaceMenu, { passive: true });", JS)
        self.assertIn("if (!document.body.contains(anchor) || r.bottom < 0 || r.top > window.innerHeight) { pfCloseMenu(); return; }", JS)


if __name__ == "__main__":
    unittest.main()
