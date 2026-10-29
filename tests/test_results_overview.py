"""The security overview of a scan result leads to the details it sums up.

The tiles lifted on hover like buttons and did nothing when clicked, and
below them the tabs sorted the same checks by another scheme, each group
stacking its tabs in a column under its own label. Read together it was not
clear what belonged where. Now every tile sits under the same group names
as the tabs and opens the card with its details; the tabs are one row.

No JS runtime here, so this reads the source, like test_ui_buttons.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
JS = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")
INDEX = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
OVERVIEW = JS[JS.index("function renderScoreOverview"):JS.index("// ===== WHOIS")]
CHECKS = OVERVIEW[OVERVIEW.index("const checks = ["):OVERVIEW.index("    ];\n")]


def _tab_panels():
    """{tab name: its html} for every tab panel of the result page."""
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'<div class="tab-content[^"]*" id="tab-([a-z0-9]+)"', INDEX)]
    ends = [s for s, _ in starts[1:]] + [len(INDEX)]
    return {name: INDEX[start:end] for (start, name), end in zip(starts, ends)}


class TileTests(unittest.TestCase):
    def test_a_tile_with_details_is_a_button_that_opens_them(self):
        self.assertIn("document.createElement(detail ? 'button' : 'div')", OVERVIEW)
        self.assertIn("addEventListener('click', () => openScoreDetail(detail))", OVERVIEW)
        opener = JS[JS.index("function openScoreDetail"):]
        opener = opener[:opener.index("\n}\n")]
        self.assertIn("selectTab(detail.tab)", opener)
        self.assertIn("scrollIntoView", opener)

    def test_every_tile_has_a_card_to_open_in_a_tab(self):
        """A tile whose check has no card in any tab would be a button to
        nowhere -- the complaint this answers."""
        panels = _tab_panels()
        missing = []
        for src in set(re.findall(r"src: '([a-z0-9_]+)'", CHECKS)):
            if not any(f'data-source="{src}"' in html for html in panels.values()):
                missing.append(src)
        for element in set(re.findall(r"at: '([A-Za-z0-9]+)'", CHECKS)):
            if not any(f'id="{element}"' in html for html in panels.values()):
                missing.append(element)
        mapping = re.search(r"const OVERVIEW_SOURCES = \{([^}]*)\}", JS).group(1)
        for src in re.findall(r": '([a-z0-9_]+)'", mapping):
            if not any(f'data-source="{src}"' in html for html in panels.values()):
                missing.append(src)
        self.assertEqual([], sorted(missing))

    def test_a_server_decided_tile_knows_where_its_details_are(self):
        self.assertIn("target: OVERVIEW_SOURCES[key]", OVERVIEW)

    def test_a_tile_with_nowhere_to_go_does_not_lift_like_a_button(self):
        self.assertIn(".score-item:not(button):hover { transform: none;", CSS)
        self.assertIn("button.score-item {", CSS)


class GroupTests(unittest.TestCase):
    def test_the_tiles_are_grouped_by_the_names_of_the_tab_groups(self):
        self.assertIn("#tabs .tab-group-label", OVERVIEW)
        self.assertIn("section.className = 'score-group'", OVERVIEW)
        self.assertIn("closest('.tab-group')?.querySelector('.tab-group-label')", JS)

    def test_the_overview_says_how_it_relates_to_the_tabs(self):
        self.assertIn("Grouped as the tabs below. Click a tile to open its details.", INDEX)

    def test_tabs_of_one_group_sit_in_a_row_not_stacked_under_a_label(self):
        """flex-direction: column put "Advice" above "Security Audit" and
        the group labels at different heights."""
        self.assertIn(".tab-group { display: flex; flex-direction: row; align-items: stretch; }", CSS)
        self.assertNotRegex(CSS, r"\.tab-group \{\s*display: flex;\s*flex-direction: column;")
        # Still named, for screen readers and for the overview to read.
        groups = len(re.findall(r'class="tab-group(?: hidden)?"', INDEX))
        self.assertEqual(groups, INDEX.count('class="tab-group-label"'))
        self.assertGreater(groups, 1)


def _function(name):
    body = JS[JS.index(f"function {name}("):]
    return body[:body.index("\n}\n")]


class TileClarityTests(unittest.TestCase):
    def test_a_tile_says_where_it_leads(self):
        """"Show the details" on every tile said nothing about which details."""
        self.assertIn("div.title = c.note || (detail ? 'Open ' + detail.label : '');", OVERVIEW)

    def test_a_tile_shows_it_opens_something_without_hovering(self):
        """A phone has no hover; the chevron is the only sign there."""
        self.assertIn("button.score-item::after {", CSS)

    def test_forward_secrecy_is_partial_when_only_some_suites_have_it(self):
        """The tile passed on one suite with forward secrecy while the advice
        listed "Forward secrecy not universal" right below it."""
        self.assertIn("pass: fsShare(data.tls_deep) === 'all', warn: fsShare(data.tls_deep) === 'some'", CHECKS)


class AdviceAndMeasurementTests(unittest.TestCase):
    def test_the_plan_links_to_the_items_instead_of_repeating_them(self):
        """Every urgent item stood on the page twice, fix and retest included."""
        plan = _function("renderRemediationPlan")
        self.assertNotIn("advies.fix", plan)
        self.assertNotIn("advies.retest", plan)
        self.assertIn("openAdvice(", plan)

    def test_an_item_shows_what_the_scan_measured_and_its_raw_output(self):
        recs = _function("renderRecommendations")
        self.assertIn('id="rec-${i}"', recs)
        self.assertIn("${adviceEvidenceHtml(r, i)}", recs)
        evidence = _function("adviceEvidenceHtml")
        self.assertIn("What the scan measured", evidence)
        self.assertIn("rec-measured-open", evidence)
        self.assertIn('class="rec-raw"', evidence)
        self.assertIn("JSON.stringify(adviceData ? adviceData[source] : null, null, 2)", _function("fillRawOutput"))

    def test_a_card_lists_the_advice_its_measurement_led_to(self):
        self.assertIn("    hideChecksNotRun(data);\n    linkAdviceToCards();\n", JS)
        self.assertIn("btn.addEventListener('click', () => openAdvice(i));", _function("linkAdviceToCards"))

    def test_every_card_an_item_can_lead_to_is_on_the_page(self):
        panels = _tab_panels()
        for element in re.findall(r"id = '([A-Za-z]+)'", _function("adviceAnchor")):
            self.assertTrue(any(f'id="{element}"' in html for html in panels.values()), element)


class OneCipherTableTests(unittest.TestCase):
    def test_the_suites_are_one_table_with_both_verdicts(self):
        """The TLS scan and the NCSC card each listed every suite, with
        verdicts that disagreed ("acceptable" against "Insufficient")."""
        self.assertEqual(1, JS.count("cipher-table stack-table"))
        table = _function("renderCipherSuites")
        self.assertIn("<th>Strength</th>", table)
        self.assertIn("<th>NCSC level</th>", table)

    def test_the_ncsc_card_keeps_its_verdict_and_drops_the_copies(self):
        ncsc = _function("renderNcscTls")
        self.assertNotIn("data.ciphers", ncsc)
        self.assertNotIn("data.protocols", ncsc)
        self.assertNotIn("ncsc_advice_heading", ncsc)
        self.assertIn("ncsc-summary", ncsc)

    def test_protocols_carry_the_ncsc_level(self):
        self.assertIn("proto-ncsc", _function("renderTlsDeep"))


if __name__ == "__main__":
    unittest.main()
