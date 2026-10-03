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
        tables = re.findall(r"(.{0,30})<table class=\"data\">", self.REPORT)
        self.assertTrue(tables)
        self.assertTrue(all(t.endswith('<div class="table-wrap">') for t in tables), tables)
        self.assertIn("overflow-x: auto", _rule(REPORT_CSS, ".table-wrap"))

    def test_the_report_toolbar_wraps_instead_of_squeezing_its_buttons(self):
        """In one unbroken row each button was 61px wide and 342px high."""
        self.assertIn("flex-wrap: wrap", _rule(REPORT_CSS, ".print-toolbar"))

    def test_a_word_in_a_summary_tile_gets_a_size_that_fits(self):
        self.assertIn('class="stat-value stat-word">{{ ncsc.overall_label', self.REPORT)
        self.assertIn(".stat-value.stat-word", REPORT_CSS)


class StyleTests(unittest.TestCase):
    def test_a_status_sentence_wraps_like_text(self):
        rule = _rule(STYLE, ".status")
        self.assertIn("display: inline-block", rule)
        self.assertNotIn("inline-flex", rule)

    def test_nowrap_used_on_cells_has_a_rule(self):
        self.assertIn(".nowrap { white-space: nowrap; }", STYLE)


if __name__ == "__main__":
    unittest.main()
