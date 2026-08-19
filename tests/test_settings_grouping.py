"""Fourteen sections were rendered as one flat row of tabs, so "Scheduler"
sat beside "SCIM" beside "Rapid7" with nothing to say they are different
kinds of thing. Grouping them only helps if the grouping stays complete: a
section that belongs to no category is a section that disappears from the
page while still existing, still having values, and still being saved.
"""

import unittest

from settings.registry import ADMIN_SECTIONS, SETTING_CATEGORIES, FIELD_META


class CategoryCoverageTests(unittest.TestCase):

    def _grouped(self):
        return [section for category in SETTING_CATEGORIES
                for section in category["sections"]]

    def test_every_section_is_in_a_category(self):
        # The failure this guards: someone adds a section, forgets the
        # category, and it silently never renders.
        self.assertEqual(sorted(set(ADMIN_SECTIONS) - set(self._grouped())), [])

    def test_no_category_lists_a_section_that_does_not_exist(self):
        self.assertEqual(sorted(set(self._grouped()) - set(ADMIN_SECTIONS)), [])

    def test_a_section_appears_exactly_once(self):
        grouped = self._grouped()
        duplicates = sorted({s for s in grouped if grouped.count(s) > 1})
        self.assertEqual(duplicates, [], "a section rendered under two headings")

    def test_every_category_has_a_translatable_label(self):
        for category in SETTING_CATEGORIES:
            self.assertTrue(category.get("key", "").startswith("settings.categories."),
                            category)

    def test_every_category_holds_something(self):
        for category in SETTING_CATEGORIES:
            self.assertTrue(category["sections"], f"{category['key']} is empty")

    def test_appearance_leads(self):
        # It is the one a person opens on purpose; the integrations are the
        # ones they open once and never again.
        self.assertEqual(SETTING_CATEGORIES[0]["sections"][0], "appearance")


class SchemaShapeTests(unittest.TestCase):
    """The form is generated from the schema, so the categories have to
    survive the trip to the browser."""

    def setUp(self):
        import os
        import tempfile
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "grouping.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import settings.store as store_module
        importlib.reload(db_module).init_db()
        self.store = importlib.reload(store_module).get_store(
            db_module=db_module, force_new=True)

    def tearDown(self):
        import os
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_the_schema_carries_the_categories(self):
        schema = self.store.admin_form_schema()
        self.assertIn("categories", schema)
        self.assertIn("sections", schema)

    def test_every_section_still_carries_its_fields(self):
        # Regrouping must not change what is editable, only where it sits.
        sections = self.store.admin_form_schema()["sections"]
        for name in ADMIN_SECTIONS:
            self.assertIn(name, sections, name)
            self.assertEqual(set(sections[name]["fields"]),
                             set(FIELD_META.get(name) or {}), name)

    def test_appearance_is_editable(self):
        fields = self.store.admin_form_schema()["sections"]["appearance"]["fields"]
        self.assertEqual(fields["accent"]["type"], "color")
        self.assertEqual(fields["theme"]["options"], ["auto", "light", "dark"])


class ColourValidationTests(unittest.TestCase):
    """A colour reaches a style attribute, so a bad one is refused where it
    is written rather than quietly stored and ignored at render time."""

    def setUp(self):
        import os
        import tempfile
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "colour.db")
        import importlib
        import db as db_module
        import settings.store as store_module
        importlib.reload(db_module).init_db()
        self.store = importlib.reload(store_module).get_store(
            db_module=db_module, force_new=True)

    def tearDown(self):
        import os
        self.tempdir.cleanup()
        os.environ.pop("DOMAINLENS_DB", None)

    def test_a_hex_colour_is_stored_canonically(self):
        result = self.store.update_section("appearance", {"accent": "#ABC"})
        self.assertEqual(result["accent"], "#aabbcc")

    def test_an_injection_attempt_is_refused(self):
        with self.assertRaises(ValueError):
            self.store.update_section(
                "appearance", {"accent": "#fff;background:url(//evil.example)"})

    def test_an_unknown_theme_is_refused(self):
        with self.assertRaises(ValueError):
            self.store.update_section("appearance", {"theme": "neon"})

    def test_a_known_theme_is_accepted(self):
        result = self.store.update_section("appearance", {"theme": "dark"})
        self.assertEqual(result["theme"], "dark")


if __name__ == "__main__":
    unittest.main()
