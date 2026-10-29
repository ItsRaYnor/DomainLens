"""A table read column by column keeps every column readable.

On Monitoring -> Domain changes the "Change" and "By" columns were squeezed
to a letter per line ("Re / gi / str / y"), while "When" had room to spare.
Two rules met: every th of a .data-table was given 28% of the width -- meant
for a label beside its value -- so on a header row of six columns the first
four took the table; and cells broke anywhere (break-all), which lets a
column shrink to a single character. The 28% now applies to a label only,
a header sizes to its column, and no column goes below a short word.

The browser does the layout, so these tests hold the rules that make it.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
STYLE = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")


def _body(selector, css=STYLE):
    """The declarations of the first rule with exactly this selector."""
    match = re.search(r"(?:^|\n)\s*" + re.escape(selector) + r"\s*\{([^}]*)\}", css)
    return match.group(1) if match else None


class ColumnTableTests(unittest.TestCase):
    def test_a_header_row_does_not_take_the_28_percent_meant_for_a_label(self):
        self.assertIn("width: 28%", _body(".data-table th"))
        header = _body(".data-table tr:has(> th + th) > th")
        self.assertIsNotNone(header, "no rule for a header row of a data table")
        self.assertIn("width: auto", header)
        self.assertIn("white-space: nowrap", header)

    def test_a_cell_of_a_column_table_does_not_break_at_every_letter(self):
        cells = _body(".data-table:has(tr > th + th) td")
        self.assertIn("word-break: normal", cells)
        self.assertIn("overflow-wrap: anywhere", cells)

    def test_no_column_goes_below_a_short_word_except_on_a_phone(self):
        wide = re.search(r"@media \(min-width: 721px\) \{(.*?)\n\}", STYLE, re.S)
        self.assertIsNotNone(wide)
        self.assertRegex(wide.group(1), r"\.data-table:has\(tr > th \+ th\) td \{ min-width: 4\.5rem; \}")
        # A checkbox column stays as narrow as its box.
        self.assertIn("td.stack-check", wide.group(1))

    def test_the_change_log_reads_a_name_server_as_one_word(self):
        self.assertIn("overflow-wrap: break-word", _body(".data-table.lv-table:has(tr > th + th) td"))

    def test_a_table_wider_than_its_card_scrolls_instead_of_running_out(self):
        """.table-scroll wrapped the change log and the monitor events but
        had no rule, so a wide table ran out of its card."""
        self.assertIn("overflow-x: auto", _body(".table-scroll"))


if __name__ == "__main__":
    unittest.main()
