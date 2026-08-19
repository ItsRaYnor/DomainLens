"""The interface had no house style because it had no base layer.

Three scoped rules styled form controls — `.search-box input`, `.stack-form
input`, `.settings-field input` — and nothing styled the element itself. Any
field outside those three containers fell through to the browser default: a
white box with black text and the browser's own padding, on a dark page. The
lookup forms, which are what the tool is used through daily, were all in that
category. Links had the same hole: only `:hover` variants scoped to containers,
so a plain anchor got the browser's blue-and-underline.

These tests pin the base layer in place. They are structural — they check that
the rules exist and carry the declarations that matter — because the failure
mode was an absent rule, not a wrong value.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CSS = ROOT / "static" / "css"
TEMPLATES = ROOT / "templates"

# Templates that deliberately render without the app chrome still need the
# tokens: they are pages, and a page with no palette is a white page.
ALL_TEMPLATES = sorted(p for p in TEMPLATES.glob("*.html"))


def _strip_comments(text):
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _rules(text):
    """Yield (selector, body) for every top-level rule.

    Good enough for the assertions here: at-rule blocks are skipped rather
    than parsed, so a rule only counts when it applies unconditionally.
    """
    text = _strip_comments(text)
    depth = 0
    buf = ""
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
            if depth == 1:
                selector = buf.strip()
                buf = ""
                body, consumed = _read_block(text, i + 1)
                i += consumed
                depth = 0
                if not selector.startswith("@"):
                    out.append((selector, body))
                continue
        buf += ch
        i += 1
    return out


def _read_block(text, start):
    depth = 1
    i = start
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[start:i - 1], i - start + 1


def _selector_parts(selector):
    return [s.strip() for s in selector.split(",")]


def _declares(body, prop):
    return re.search(rf"(^|[;{{\s]){re.escape(prop)}\s*:", body) is not None


class BaseElementRuleTests(unittest.TestCase):
    """The regression that produced the white boxes: no rule for the element."""

    @classmethod
    def setUpClass(cls):
        cls.text = (CSS / "theme.css").read_text(encoding="utf-8")
        cls.rules = _rules(cls.text)

    def _bare_rule_for(self, element, prop):
        for selector, body in self.rules:
            if element in _selector_parts(selector) and _declares(body, prop):
                return selector, body
        return None

    def test_form_controls_have_a_background_of_their_own(self):
        # Without this the control is painted by the browser, which does not
        # know the page is dark.
        for element in ("input", "select", "textarea"):
            self.assertIsNotNone(
                self._bare_rule_for(element, "background-color"),
                f"no unconditional rule gives <{element}> a background",
            )

    def test_form_controls_set_their_own_text_colour(self):
        # A dark background with the browser's default black text is worse
        # than leaving it white.
        for element in ("input", "select", "textarea"):
            self.assertIsNotNone(
                self._bare_rule_for(element, "color"),
                f"no unconditional rule gives <{element}> a text colour",
            )

    def test_form_controls_share_one_size(self):
        # "Te groot bij verschillende velden" was three different paddings
        # and a fourth, the browser's, wherever none of them applied.
        for element in ("input", "select", "textarea"):
            self.assertIsNotNone(
                self._bare_rule_for(element, "padding"),
                f"<{element}> has no shared padding, so its size is the browser's",
            )

    def test_the_control_size_comes_from_a_token(self):
        rule = self._bare_rule_for("input", "padding")
        self.assertIn("var(--control-pad", rule[1],
                      "control padding is hard-coded, so it can drift again")

    def test_links_have_a_colour(self):
        self.assertIsNotNone(
            self._bare_rule_for("a", "color"),
            "no unconditional rule colours <a>, so links fall back to browser blue",
        )

    def test_focus_is_visible_on_controls(self):
        # Keyboard users lose the caret entirely when a control is restyled
        # without restoring a focus ring.
        self.assertIn(":focus-visible", self.text)

    def test_buttons_do_not_keep_the_browser_chrome(self):
        self.assertIsNotNone(
            self._bare_rule_for("button", "font"),
            "buttons do not inherit the page font",
        )


class TokenCoverageTests(unittest.TestCase):
    """A token defined only in one theme is a colour that disappears in the
    other. Every theme block has to answer for every token."""

    @classmethod
    def setUpClass(cls):
        cls.text = _strip_comments((CSS / "theme.css").read_text(encoding="utf-8"))

    def _decls(self, pattern):
        match = re.search(pattern, self.text)
        self.assertIsNotNone(match, f"no block matching {pattern}")
        body, _ = _read_block(self.text, match.end())
        return dict(re.findall(r"(--[a-z0-9-]+)\s*:\s*([^;]+);", body))

    def test_light_is_the_base_definition(self):
        # Defined on bare :root so a viewer with no preference and no choice
        # still gets a complete palette.
        self.assertTrue(self._decls(r":root\s*\{"))

    def test_dark_redefines_every_literal_colour(self):
        # Only literals: a token built out of other tokens follows them into
        # the dark theme by itself, and restating it there would be a second
        # place to forget.
        light = self._decls(r":root\s*\{")
        dark = self._decls(r":root\[data-theme=[\"']dark[\"']\]\s*\{")
        literals = {
            name for name, value in light.items()
            if re.search(r"#[0-9a-f]{3,8}|\brgba?\(|\bhsla?\(", value, re.I)
            and "var(" not in value
        }
        self.assertEqual(sorted(literals - set(dark)), [],
                         "these colours have no dark value and would stay light")

    def test_the_system_preference_is_honoured(self):
        self.assertIn("prefers-color-scheme: dark", self.text)

    def test_an_explicit_light_choice_beats_the_system_preference(self):
        # Without the guard, a viewer who picks light on a dark OS gets dark.
        self.assertRegex(
            self.text,
            r":root:not\(\[data-theme=[\"']light[\"']\]\)")

    def test_the_accent_is_one_value_to_change(self):
        # A custom accent has to reach hover, ring and glow too, or picking
        # one repaints a single button and nothing else.
        for token in ("--accent-h", "--accent-s", "--accent-l"):
            self.assertIn(token, self.text)


class StylesheetWiringTests(unittest.TestCase):
    """Tokens that a page does not load are tokens that page does not have."""

    def _head(self, name):
        return (TEMPLATES / name).read_text(encoding="utf-8")

    def test_every_page_loads_the_tokens(self):
        for path in ALL_TEMPLATES:
            self.assertIn("/static/css/theme.css", path.read_text(encoding="utf-8"),
                          f"{path.name} has no palette")

    def test_the_tokens_load_before_the_page_stylesheet(self):
        # Later sheets override earlier ones; tokens have to be underneath.
        for path in ALL_TEMPLATES:
            body = path.read_text(encoding="utf-8")
            theme = body.index("/static/css/theme.css")
            for sheet in ("style.css", "login.css", "trends.css", "report.css"):
                marker = f"/static/css/{sheet}"
                if marker in body:
                    self.assertLess(theme, body.index(marker),
                                    f"{path.name} loads {sheet} before theme.css")

    def test_every_page_can_carry_the_theme(self):
        # It has to be on <html> before first paint, and the CSP forbids the
        # inline script that would normally put it there, so the server
        # renders it. The attribute itself is absent under "auto" — that is
        # how prefers-color-scheme stays in charge — so what is checked here
        # is that the slot exists on every page.
        for path in ALL_TEMPLATES:
            body = path.read_text(encoding="utf-8")
            self.assertRegex(body, r"<html[^>]*\{\{\s*theme_attr\s*\}\}",
                             f"{path.name} cannot be themed")


class NoStrayColoursTests(unittest.TestCase):
    """Colours written into the page-specific sheets drift away from the
    palette, and cannot follow a theme switch at all."""

    def test_the_page_sheets_do_not_define_their_own_palette(self):
        offenders = []
        for name in ("style.css", "login.css", "trends.css", "report.css"):
            text = _strip_comments((CSS / name).read_text(encoding="utf-8"))
            for match in re.finditer(r"#[0-9a-fA-F]{3,8}\b", text):
                line = text[:match.start()].count("\n") + 1
                offenders.append(f"{name}:{line} {match.group(0)}")
        self.assertEqual(offenders, [], "literal colours outside the token file")


if __name__ == "__main__":
    unittest.main()


class ThemeResolutionTests(unittest.TestCase):
    """Three states, and "auto" is a real one: with no choice made the
    attribute must be absent so the operating system decides. Rendering
    `data-theme="auto"` would be a fourth state the CSS does not know."""

    def setUp(self):
        import os
        import tempfile
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "theme.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        import os
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _html_tag(self, response):
        body = response.data.decode()
        return body[body.index("<html"):body.index(">", body.index("<html")) + 1]

    def test_auto_leaves_the_choice_to_the_operating_system(self):
        tag = self._html_tag(self.client.get("/"))
        self.assertNotIn("data-theme", tag)

    def test_a_chosen_theme_is_rendered_before_first_paint(self):
        self.client.set_cookie("dl_theme", "dark")
        self.assertIn('data-theme="dark"', self._html_tag(self.client.get("/")))

    def test_light_is_stamped_too_rather_than_left_to_the_system(self):
        # Without the attribute a light choice on a dark OS silently loses.
        self.client.set_cookie("dl_theme", "light")
        self.assertIn('data-theme="light"', self._html_tag(self.client.get("/")))

    def test_a_nonsense_theme_falls_back_instead_of_being_echoed(self):
        self.client.set_cookie("dl_theme", '"><script>alert(1)</script>')
        tag = self._html_tag(self.client.get("/"))
        self.assertNotIn("script", tag)
        self.assertNotIn("data-theme", tag)


class AccentValidationTests(unittest.TestCase):
    """A colour that reaches a style attribute is a CSS injection vector.
    It is validated where it enters, not where it is drawn."""

    def test_a_hex_colour_is_accepted(self):
        import theming
        self.assertEqual(theming.normalize_accent("#A1B2C3"), "#a1b2c3")

    def test_shorthand_is_expanded_rather_than_half_accepted(self):
        import theming
        self.assertEqual(theming.normalize_accent("#abc"), "#aabbcc")

    def test_anything_that_is_not_a_colour_is_refused(self):
        import theming
        for value in ("red", "url(x)", "#12345", "#gggggg", "", None,
                      "#fff;background:url(//evil)", "var(--x)"):
            self.assertIsNone(theming.normalize_accent(value), repr(value))

    def test_only_hue_and_saturation_reach_the_page(self):
        # Lightness belongs to the theme. Letting a picked colour set it too
        # means a dark accent chosen in light mode is unreadable in dark.
        import theming
        style = theming.accent_style("#5b8def")
        self.assertIn("--accent-h", style)
        self.assertIn("--accent-s", style)
        self.assertNotIn("--accent-l", style)

    def test_a_refused_colour_produces_no_style_at_all(self):
        import theming
        self.assertEqual(theming.accent_style("javascript:alert(1)"), "")


class TranslationDoesNotEatMarkupTests(unittest.TestCase):
    """`applyDataI18n` assigns `el.textContent`, which replaces everything
    inside the element. Putting `data-i18n` on a link that also holds an icon
    therefore deletes the icon the moment translations run — the page looks
    right in the served HTML and wrong in the browser, which is the hardest
    kind of wrong to notice.

    The label goes on a <span> of its own; the icon stays outside it.
    """

    def test_no_translated_element_wraps_other_markup(self):
        offenders = []
        for path in ALL_TEMPLATES + sorted((TEMPLATES / "partials").glob("*.html")):
            body = path.read_text(encoding="utf-8")
            for match in re.finditer(
                    r'<(\w+)([^>]*\bdata-i18n="[^"]+"[^>]*)>(.*?)</\1>', body, re.S):
                attrs, inner = match.group(2), match.group(3)
                if "data-i18n-attr" in attrs:
                    continue  # writes an attribute, leaves the children alone
                if re.search(r"<\w+", inner):
                    line = body[:match.start()].count("\n") + 1
                    offenders.append(f"{path.name}:{line} <{match.group(1)}>")
        self.assertEqual(offenders, [],
                         "translation would delete the markup inside these")


class StackedFormTests(unittest.TestCase):
    """`flex: 1 1 18rem` reads as a width in a row and as a *height* in a
    column. The lookup forms switch to a column on a phone, so the basis was
    being applied to the wrong axis and the address field grew to roughly
    600px tall — tall enough that the button fell off the screen.
    """

    def test_stacking_releases_the_flex_basis(self):
        text = _strip_comments((CSS / "style.css").read_text(encoding="utf-8"))
        # There is more than one narrow-viewport block; scan them all rather
        # than assume which one a rule happens to sit in.
        rules_in_blocks = []
        for match in re.finditer(r"@media \(max-width: 860px\)\s*\{", text):
            block, _ = _read_block(text, match.end())
            rules_in_blocks.extend(_rules(block))
        self.assertTrue(rules_in_blocks)
        for selector in (".lookup-form", ".dns-lookup-form"):
            rules = [body for sel, body in rules_in_blocks
                     if any(part.startswith(selector) for part in _selector_parts(sel))
                     and "flex-direction" not in body]
            self.assertTrue(
                any("flex: 0 0 auto" in body for body in rules),
                f"{selector} stacks without releasing the flex basis")
