"""Every page stays within the screen and its cards, on a phone as well.

A walk through every page at phone, tablet and desktop width, in English and
Dutch, found these: the report had no viewport tag, so a phone showed it as
a shrunken desktop page, and once it had one its tables and its toolbar ran
off the screen; a status sentence with a long setting name pushed the scan
result sideways, because the status style was a flex row that could not
wrap; and "nowrap", used on table cells across the pages, had no rule.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
STYLE = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")
REPORT_CSS = (ROOT / "static" / "css" / "report.css").read_text(encoding="utf-8")


def _rule(css, selector):
    start = css.index("\n" + selector + " {")
    return css[start:css.index("}", start)]


class PageTests(unittest.TestCase):
    def test_every_page_tells_a_phone_its_width(self):
        missing = [p.name for p in sorted(TEMPLATES.glob("*.html"))
                   if "<html" in (text := p.read_text(encoding="utf-8"))
                   and 'name="viewport"' not in text]
        self.assertEqual([], missing)


class ReportTests(unittest.TestCase):
    REPORT = (TEMPLATES / "report.html").read_text(encoding="utf-8")

    def test_every_report_table_scrolls_within_the_page(self):
        tables = re.findall(r"(.{0,30})<table class=\"data stack-table\">", self.REPORT)
        self.assertTrue(tables)
        self.assertTrue(all(t.endswith('<div class="table-wrap">') for t in tables), tables)
        self.assertIn("overflow-x: auto", _rule(REPORT_CSS, ".table-wrap"))

    def test_on_a_phone_the_tables_are_cards_and_on_paper_tables(self):
        """Scrolled sideways, a report table on a phone showed the first
        column and hid what each finding was about."""
        self.assertNotIn('<table class="data">', self.REPORT)
        self.assertIn("/static/js/stack_tables.js", self.REPORT)
        self.assertIn("@media screen and (max-width: 720px)", REPORT_CSS)
        self.assertIn(".stack-label {", REPORT_CSS[REPORT_CSS.index("@media screen and (max-width: 720px)"):])

    def test_identifiers_stay_whole(self):
        """.mono breaks anywhere, which suits a long URL; a finding id such as
        "cipher-insufficient" came out one letter per line."""
        self.assertIn('<td class="mono mono-id">{{ f.id }}</td>', self.REPORT)
        self.assertIn('<td class="mono mono-id">{{ p.cipher or \'-\' }}</td>', self.REPORT)
        rule = _rule(REPORT_CSS, ".mono-id")
        self.assertIn("word-break: normal", rule)
        self.assertIn("white-space: nowrap", rule)

    def test_the_report_toolbar_wraps_instead_of_squeezing_its_buttons(self):
        """In one unbroken row each button was 61px wide and 342px high."""
        self.assertIn("flex-wrap: wrap", _rule(REPORT_CSS, ".print-toolbar"))

    def test_a_word_in_a_summary_tile_gets_a_size_that_fits(self):
        self.assertIn('class="stat-value stat-word">{{ ncsc.overall_label', self.REPORT)
        self.assertIn(".stat-value.stat-word", REPORT_CSS)


class PhoneListTests(unittest.TestCase):
    """On a phone the domain portfolio scrolled sideways through eight
    columns and showed only the first; the organisation, monitors, unit,
    dashboard and admin lists did the same. Those lists are cards there,
    each value under its column name."""

    JS = ROOT / "static" / "js"

    def test_every_page_with_the_menu_loads_the_card_script(self):
        nav = (TEMPLATES / "partials" / "nav.html").read_text(encoding="utf-8")
        self.assertIn("/static/js/stack_tables.js", nav)

    def test_the_wide_lists_are_marked(self):
        marked = {
            self.JS / "portfolio.js": "portfolio-table stack-table",
            self.JS / "app.js": "monitor-table stack-table",
            self.JS / "dashboard.js": "mgmt-table stack-table",
            TEMPLATES / "monitoring_organisation.html": 'org-manage-table stack-table" id="orgManageTable"',
            TEMPLATES / "monitoring_unit.html": 'stack-table" id="unitDomains"',
            TEMPLATES / "admin_audit.html": "audit-table stack-table",
            TEMPLATES / "admin_risks.html": "users-table stack-table",
        }
        for path, needle in marked.items():
            self.assertIn(needle, path.read_text(encoding="utf-8"), path.name)

    def test_rows_become_cards_with_their_column_names_on_a_phone_only(self):
        self.assertIn(".stack-label, .stack-only { display: none; }", STYLE)
        phone = STYLE[STYLE.index("@media (max-width: 720px) {\n    .stack-table"):]
        self.assertIn("display: grid", _rule(phone, "    .stack-table tr"))
        self.assertIn(".stack-label {", phone)
        script = (self.JS / "stack_tables.js").read_text(encoding="utf-8")
        self.assertIn("headerOf(table)", script)
        self.assertIn("MutationObserver", script)

    def test_a_units_counts_wrap_instead_of_widening_the_page(self):
        """"2 domains · 1 wanted" pushed the portfolio 46px past a phone."""
        self.assertIn("flex-wrap: wrap", _rule(STYLE, ".monitor-fold > summary"))

    def test_section_tabs_wrap_instead_of_scrolling_out_of_sight(self):
        self.assertNotIn(".subnav { padding: .4rem .75rem; overflow-x: auto; flex-wrap: nowrap; }", STYLE)


class StyleTests(unittest.TestCase):
    def test_a_status_sentence_wraps_like_text(self):
        rule = _rule(STYLE, ".status")
        self.assertIn("display: inline-block", rule)
        self.assertNotIn("inline-flex", rule)

    def test_nowrap_used_on_cells_has_a_rule(self):
        self.assertIn(".nowrap { white-space: nowrap; }", STYLE)


if __name__ == "__main__":
    unittest.main()
