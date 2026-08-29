"""Layout regressions found by driving the real page, not by reading it.

Both were invisible in the markup and only showed up once a real answer was
rendered at a real viewport width, which is why they are pinned here.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


class DnsDetailTableTests(unittest.TestCase):
    """An RRSIG is a few hundred characters of base64. With word-break the
    browser happily squeezed that column to 58px and spent the height
    instead: one cell 699px tall, the page 10045px, and the records the
    table exists to show pushed off screen.
    """

    def _js(self):
        return _read("static", "js", "lookup.js")

    def test_a_long_value_is_shortened_before_it_is_rendered(self):
        js = self._js()
        block = js[js.index("function dnsDetailHtml"):][:1800]
        self.assertIn("full.length > 120", block)
        self.assertIn("slice(0, 120)", block)

    def test_the_shortening_is_visible_and_keeps_the_whole_value(self):
        """A silently cut value reads as the complete record. The ellipsis
        says it was cut and the title keeps what was cut off."""
        block = self._js()[self._js().index("function dnsDetailHtml"):][:1800]
        self.assertIn("'…'", block)
        self.assertIn("title=", block)

    def test_the_table_scrolls_inside_its_own_box(self):
        """Otherwise a wide row pushes the whole page sideways on a phone."""
        js = self._js()
        self.assertIn("dns-detail-table-wrap", js)
        css = _read("static", "css", "style.css")
        wrap = css[css.index(".dns-detail-table-wrap"):][:200]
        self.assertIn("overflow-x: auto", wrap)

    def test_the_value_column_cannot_be_squeezed_to_nothing(self):
        """table-layout: fixed with named column widths is what stops the
        browser from trading width for height on the value column."""
        css = _read("static", "css", "style.css")
        block = css[css.index(".dns-detail table"):][:400]
        self.assertIn("table-layout: fixed", block)
        self.assertIn("min-width", block)


class DnsLookupFormOnNarrowScreensTests(unittest.TestCase):
    """The lookup box was 256px tall on a phone.

    The desktop rule targets `.dns-lookup-form input[type="text"]` and sets
    `flex: 1 1 16rem`. The mobile override targeted a bare `.dns-lookup-form
    input`, which loses on specificity, so the 16rem basis survived -- and in
    a column flex container a flex-basis is a HEIGHT.
    """

    def _mobile_block(self):
        css = _read("static", "css", "style.css")
        start = css.index(".dns-lookup-form { flex-direction: column; }")
        return css[start:start + 700]

    def test_the_narrow_override_matches_the_desktop_specificity(self):
        block = self._mobile_block()
        self.assertIn('.dns-lookup-form input[type="text"]', block,
                      "a bare `input` selector loses to the desktop "
                      '`input[type="text"]` rule and the 16rem basis survives')

    def test_the_override_actually_clears_the_flex_basis(self):
        block = self._mobile_block()
        self.assertIn("flex: 0 0 auto", block)

    def test_the_desktop_rule_is_still_the_one_being_overridden(self):
        """If the desktop selector ever loses its attribute qualifier this
        whole fix becomes dead weight and should be simplified."""
        css = _read("static", "css", "style.css")
        self.assertIn('.dns-lookup-form input[type="text"] {', css)
        self.assertIn("flex: 1 1 16rem", css)


class PropagationHintTests(unittest.TestCase):
    """The link to add your own resolver sat inside a sentence about port 53
    and read as a footnote, so people looked for an address box on the page
    instead and concluded the feature was missing."""

    def test_the_page_has_a_dedicated_slot_for_the_hint(self):
        self.assertIn('id="dnsPropCustomHint"', _read("templates", "lookup_dns.html"))

    def test_the_hint_names_the_configured_resolvers_when_there_are_any(self):
        js = _read("static", "js", "lookup.js")
        block = js[js.index("dnsPropCustomHint"):][:900]
        self.assertIn("dnsCustomResolvers.length", block)
        self.assertIn("Your own resolvers", block)

    def test_the_empty_state_says_where_to_add_one(self):
        js = _read("static", "js", "lookup.js")
        block = js[js.index("dnsPropCustomHint"):][:1200]
        self.assertIn("/admin/settings", block)
        self.assertIn("Custom resolvers", block)


if __name__ == "__main__":
    unittest.main()
