"""Static wiring checks for every button the templates render.

There is no JS runtime in this suite, so these read the sources. That is
enough for the failure this file exists to catch: a handler that reaches for
a node belonging to a different page. The DOM lookup returns null, the
TypeError kills the listener it sits in, and the page reports something
unrelated -- or nothing at all.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


def _templates():
    return sorted(ROOT.glob("templates/**/*.html"))


def _scripts():
    return sorted(ROOT.glob("static/js/*.js"))


def _all_rendered_ids():
    """Every id something in this app actually creates.

    Templates are not the only source: a script that builds markup and
    then looks up an id inside it has created that element just as
    surely. The check worth keeping is "does anything create this", not
    "is it in a template" -- a typo or a removed element still fails.
    """
    ids = set()
    for path in _templates() + _scripts():
        # Skip Jinja-interpolated ids: their value is not knowable here.
        ids.update(re.findall(r'\bid="([^"{}]+)"', path.read_text(encoding="utf-8")))
    return ids


class ButtonWiringTests(unittest.TestCase):
    def test_every_button_with_an_id_is_referenced_by_a_script(self):
        """A button nothing reads is a button that does nothing when clicked,
        and it looks identical to one that works."""
        js = "\n".join(p.read_text(encoding="utf-8") for p in _scripts())
        unreferenced = []
        for path in _templates():
            html = path.read_text(encoding="utf-8")
            for match in re.finditer(r'<button\b[^>]*\bid="([^"{}]+)"', html):
                button_id = match.group(1)
                if button_id not in js:
                    unreferenced.append(f"{path.name}#{button_id}")
        self.assertEqual([], unreferenced,
                         f"buttons no script ever binds: {unreferenced}")

    def test_no_script_dereferences_an_element_nothing_creates(self):
        """The trends page died on one of these: $('refreshBtn') was null, so
        the TypeError took the drill-downs, the close button and the initial
        loadTrends() with it. The page rendered empty, not broken, which is
        the version nobody reports as a bug.
        """
        rendered_ids = _all_rendered_ids()
        dangling = []
        for path in _scripts():
            source = path.read_text(encoding="utf-8")
            for line_no, line in enumerate(source.splitlines(), 1):
                for match in re.finditer(
                        r"\$\('([^']+)'\)\."
                        r"(addEventListener|value|classList|textContent|innerHTML|disabled)",
                        line):
                    if match.group(1) not in rendered_ids:
                        dangling.append(f"{path.name}:{line_no} {match.group(1)}")
        self.assertEqual([], dangling,
                         f"unguarded lookups of ids nothing creates: {dangling}")

    def test_the_shared_helper_is_used_where_a_page_may_lack_the_node(self):
        """app.js and trends.js are each loaded by more than one page, so both
        need the guarded binder rather than a raw addEventListener."""
        for name in ("app.js", "trends.js"):
            source = _read("static", "js", name)
            self.assertIn("function on(id, event, handler)", source,
                          f"{name} has no guarded binder")
            self.assertIn("if (el) el.addEventListener(event, handler)", source)


class PagePanelsAreNotDrawersTests(unittest.TestCase):
    """The history and monitoring blocks were drawers over the scan page and
    are now full pages. The close button survived the move: on a page it had
    nothing behind it to reveal, so it hid the page itself and left the user
    with a blank screen and no way back but a reload.
    """

    BLOCKS = (
        ("partials/_history_block.html", "historyCloseBtn", "closeHistory"),
        ("partials/_monitoring_block.html", "monitorsCloseBtn", "closeMonitors"),
    )

    def test_the_close_button_is_not_rendered_on_a_page(self):
        for template, button_id, _ in self.BLOCKS:
            with self.subTest(template=template):
                html = _read("templates", *template.split("/"))
                self.assertIn("{% if not as_page %}", html)
                index = html.index(button_id)
                guard = html.rfind("{% if not as_page %}", 0, index)
                self.assertNotEqual(-1, guard,
                                    f"{button_id} renders unconditionally")

    def test_the_close_handler_refuses_to_hide_a_page_panel(self):
        """Belt and braces: the template guard can be undone by a future
        include, and the handler is what actually blanks the page."""
        js = _read("static", "js", "app.js")
        for _, _, handler in self.BLOCKS:
            with self.subTest(handler=handler):
                block = js[js.index(f"function {handler}("):][:600]
                self.assertIn("classList.contains('drawer')", block)

    def test_both_blocks_are_only_ever_included_as_pages(self):
        """The premise of the guards above. If either is ever rendered as a
        drawer again, the close button has to come back with it."""
        for template, _, _ in self.BLOCKS:
            with self.subTest(template=template):
                including = [p for p in _templates()
                             if template in p.read_text(encoding="utf-8")]
                self.assertTrue(including, f"nothing includes {template}")
                for page in including:
                    self.assertIn("as_page = True", page.read_text(encoding="utf-8"))


class TrendsPageInitTests(unittest.TestCase):
    """Every binding in the trends DOMContentLoaded listener sits after the
    one that used to throw, so they were all dead together."""

    def _init_block(self):
        js = _read("static", "js", "trends.js")
        return js[js.index("document.addEventListener('DOMContentLoaded'"):]

    def test_the_refresh_button_the_script_binds_actually_exists(self):
        self.assertIn('id="refreshBtn"', _read("templates", "trends.html"))

    def test_the_listener_reaches_its_initial_load(self):
        """loadTrends() is the last statement: anything that throws above it
        leaves the page permanently empty."""
        block = self._init_block()
        for binding in ("refreshBtn", "domainFilter", "kpiGrid",
                        "drilldownClose", "drilldownBody"):
            with self.subTest(binding=binding):
                self.assertNotIn(f"$('{binding}').addEventListener", block,
                                 f"{binding} is bound without a guard")
        self.assertIn("loadTrends();", block)


if __name__ == "__main__":
    unittest.main()


class HonestFetchFailureTests(unittest.TestCase):
    """A failed request said "Network error" whatever had actually happened.

    The case that exposed it: a server still running an older process has the
    new page but not the new route, so the fetch gets a perfectly healthy
    HTTP 404 carrying HTML. Calling that a network error sends someone to
    check their connection instead of restarting their server -- the same
    mistake that made "Run now" report a network error for a scan that was
    running.
    """

    def _js(self):
        return _read("static", "js", "lookup.js")

    def test_there_is_one_shared_request_helper(self):
        js = self._js()
        self.assertIn("async function requestJson(url, options)", js)

    def test_an_unreachable_server_is_named_as_such(self):
        """Only a rejected fetch is actually a connectivity problem."""
        js = self._js()
        block = js[js.index("async function requestJson"):][:1400]
        self.assertIn("Could not reach the server", block)

    def test_a_404_suggests_the_restart_that_fixes_it(self):
        block = self._js()[self._js().index("async function requestJson"):][:1400]
        self.assertIn("404", block)
        self.assertIn("restart", block.lower())

    def test_another_status_reports_the_status(self):
        block = self._js()[self._js().index("async function requestJson"):][:1400]
        self.assertIn("instead of JSON", block)

    def test_no_handler_still_hard_codes_the_old_message(self):
        """One comment explains the history; no branch should still say it."""
        js = self._js()
        offenders = [line.strip() for line in js.splitlines()
                     if "Network error" in line and not line.strip().startswith("//")]
        self.assertEqual([], offenders)

    def test_the_body_is_read_once(self):
        """resp.json() after resp.text() throws; reading text and parsing it
        is what lets the helper report the status on non-JSON."""
        block = self._js()[self._js().index("async function requestJson"):][:1400]
        self.assertIn("await resp.text()", block)
        self.assertIn("JSON.parse(body)", block)
