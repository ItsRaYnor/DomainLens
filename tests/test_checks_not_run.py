"""A scan shows only what it measured.

A WHOIS-only scan showed HTTPS, NCSC TLS, Forward secrecy and Headers as
Fail, HSTS as Partial, and every result tab, each card rendering its missing
result as "lookup failed". None of those checks had run. Absent is not a
defect of the domain, so tiles, cards and tabs for a check that did not run
are hidden.

There is no JS runtime in this suite, so the wiring is checked in the
sources, the way test_ui_buttons does it.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


def _result_keys():
    """The keys a scan's results can carry: the check map, plus the Rapid7
    correlation attached to every scan and ncsc_tls, derived from tls_deep."""
    src = _read("app.py")
    block = src[src.index("def _build_check_map"):]
    block = block[:block.index("\n    }\n")]
    return set(re.findall(r'^\s+"([a-z0-9_]+)": lambda', block, re.M)) | {"rapid7", "ncsc_tls"}


class CardsAndTabsTests(unittest.TestCase):
    def test_every_card_names_a_real_result_key(self):
        """A typo would hide that card on every scan, however complete."""
        sources = set(re.findall(r'data-source="([a-z0-9_]+)"', _read("templates", "index.html")))
        self.assertTrue(sources)
        self.assertEqual(sorted(sources - _result_keys()), [])

    def test_every_result_tab_can_hide(self):
        """A tab with no labelled card would always show, empty or failing."""
        html = _read("templates", "index.html")
        panels = re.split(r'<div class="tab-content[^"]*" id="tab-([a-z0-9]+)">', html)
        for name, body in zip(panels[1::2], panels[2::2]):
            if name == "recommendations":
                continue
            body = body.split('<div class="tab-content')[0]
            with self.subTest(tab=name):
                self.assertIn("data-source=", body)

    def test_the_scan_page_hides_what_did_not_run(self):
        js = _read("static", "js", "app.js")
        render = js[js.index("function renderResults"):]
        self.assertIn("hideChecksNotRun(data);", render[:render.index("\n}\n")])


class OverviewTileTests(unittest.TestCase):
    def setUp(self):
        js = _read("static", "js", "app.js")
        self.body = js[js.index("function renderScoreOverview"):js.index("// ===== WHOIS")]
        self.checks = self.body[self.body.index("const checks = ["):self.body.index("    ];\n")]

    def test_every_tile_names_the_check_it_depends_on(self):
        plain = re.findall(r"\{ label: '([^']+)'", self.checks)
        with_src = re.findall(r"\{ label: '[^']+', src: '([a-z0-9_]+)'", self.checks)
        self.assertEqual(len(plain), len(with_src), "a tile without src shows Fail when absent")
        self.assertEqual(sorted(set(with_src) - _result_keys()), [])

    def test_server_decided_tiles_name_theirs_too(self):
        js = _read("static", "js", "app.js")
        mapping = re.search(r"const OVERVIEW_SOURCES = \{([^}]*)\}", js).group(1)
        used = set(re.findall(r"fromOverview\('[^']+', '([a-z0-9_]+)'", self.checks))
        declared = dict(re.findall(r"([a-z0-9_]+): '([a-z0-9_]+)'", mapping))
        self.assertEqual(sorted(used - set(declared)), [])
        self.assertEqual(sorted(set(declared.values()) - _result_keys()), [])

    def test_a_tile_is_skipped_when_its_check_did_not_run(self):
        self.assertIn("if (c.src && !checkRan(data, c.src)) return;", self.body)


if __name__ == "__main__":
    unittest.main()
