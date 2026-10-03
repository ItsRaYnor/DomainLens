"""Everything the browser shows has Dutch, and the Dutch keeps its links.

Choosing Dutch translated the menus and left most pages English. The
interface is now translated in the browser from one catalogue, keyed by
the English text (i18n/nl_ui). These tests keep it complete: a fixed text
added to a template without Dutch fails here, and a translated sentence
that lost a link or a code fragment fails too.
"""

import pathlib
import re
import unittest

import i18n
from i18n.extract import template_blocks, template_units

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = sorted(ROOT.joinpath("templates").rglob("*.html"))


def _tags(html):
    """The markup that must survive translation: links and their targets,
    code, emphasis. Order may change with Dutch word order; the set may not."""
    return sorted(re.findall(r"<(a|code|strong|em)\b[^>]*>", html)) + sorted(re.findall(r'href="([^"]*)"', html))


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        i18n.ui_catalogue.cache_clear()
        self.catalogue = i18n.ui_catalogue()

    def test_every_fixed_text_in_a_template_has_dutch(self):
        missing = []
        for path in TEMPLATES:
            texts, blocks = template_units(path)
            parts = template_blocks(path)
            for text in texts:
                if text not in self.catalogue["text"]:
                    missing.append(f"{path.name}: {text}")
            for block in blocks:
                if block in self.catalogue["blocks"]:
                    continue
                # A block may also be translated part by part.
                pieces = parts.get(block, ("", []))[1]
                absent = [p for p in pieces if p not in self.catalogue["text"]]
                if absent or not pieces:
                    missing.append(f"{path.name}: [block] {block}")
        self.assertEqual([], sorted(set(missing)), f"{len(set(missing))} texts without Dutch")

    def test_a_translated_sentence_keeps_its_links_and_code(self):
        sources = {}
        for path in TEMPLATES:
            for key, (html, _) in template_blocks(path).items():
                if html:
                    sources[key] = html
        broken = [key for key, dutch in self.catalogue["blocks"].items()
                  if key in sources and _tags(sources[key]) != _tags(dutch)]
        self.assertEqual([], broken)

    def test_no_pattern_rewrites_dutch_that_is_already_dutch(self):
        """"{} of {}" -> "{} van {}" turned the Dutch "A of B" (A or B) into
        "A van B" in every translated sentence that contained it."""
        compiled = [(re.compile("^" + r + "$"), rep) for r, rep in self.catalogue["patterns"]]
        changed = []
        for dutch in self.catalogue["text"].values():
            for regex, rep in compiled:
                m = regex.match(dutch)
                if m:
                    out = re.sub(r"\$(\d)", lambda g: m.group(int(g.group(1))) or "", rep)
                    if out != dutch:
                        changed.append(f"{regex.pattern} rewrites: {dutch}")
                    break
        self.assertEqual([], changed)

    def test_every_pattern_is_a_valid_expression(self):
        for regex, replacement in self.catalogue["patterns"]:
            re.compile("^" + regex + "$")
            groups = re.compile(regex).groups
            for ref in re.findall(r"\$(\d)", replacement):
                self.assertLessEqual(int(ref), groups, regex)


class SheetTests(unittest.TestCase):
    def test_the_built_catalogue_matches_its_sheets(self):
        """A sheet edited without running the builder would not reach the page."""
        import json
        from i18n.build_catalogue import build_sheet
        for sheet in sorted(ROOT.joinpath("i18n", "nl_ui").glob("*.tsv")):
            built = json.loads(sheet.with_suffix(".json").read_text(encoding="utf-8"))
            self.assertEqual(build_sheet(sheet), built,
                             f"{sheet.name}: run python -m i18n.build_catalogue")


class EngineTests(unittest.TestCase):
    JS = ROOT.joinpath("static", "js", "translate.js").read_text(encoding="utf-8")

    def test_text_filled_in_through_innerHTML_is_seen_as_a_whole(self):
        """Only the added children were looked at, so a sentence with a link
        set through innerHTML never matched as a block."""
        self.assertIn("queue.add(r.target)", self.JS)

    def test_a_pattern_that_changes_nothing_does_not_count_as_translated(self):
        self.assertIn("if (out !== key) return out;", self.JS)

    def test_merged_advice_is_split_at_sentence_ends(self):
        self.assertIn("function sentences(key)", self.JS)


class PageTests(unittest.TestCase):
    def test_every_page_loads_the_translation(self):
        """A page without it stays English in Dutch."""
        for path in TEMPLATES:
            source = path.read_text(encoding="utf-8")
            if "<html" not in source:
                continue
            self.assertTrue("translate.js" in source or "partials/nav.html" in source, path.name)
            self.assertIn('lang="{{ locale }}"', source, path.name)


if __name__ == "__main__":
    unittest.main()
