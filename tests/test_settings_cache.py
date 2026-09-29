"""Settings are read from the cache, and every write empties it.

Nearly every reader passed force_reload=True, so each request rebuilt the
whole configuration from the database -- every settings row, every stored
key decrypted -- several times over: about 40 SQLite connections before a
view ran. On a NAS that was most of the time of every click, and 0.1.0's role
checks, which read the auth config more often, made it worse.
"""

import os
from unittest import mock

from enterprise_harness import EnterpriseAppTestCase


class SettingsCacheTests(EnterpriseAppTestCase):
    def test_a_request_does_not_rebuild_the_settings(self):
        self.login_as("admin")
        self.client.get("/api/history")  # the first request may fill the cache
        with mock.patch.object(self.db, "get_all_settings",
                               wraps=self.db.get_all_settings) as rebuild:
            for _ in range(3):
                self.assertEqual(200, self.client.get("/api/history").status_code)
        self.assertEqual(0, rebuild.call_count)

    def test_a_request_does_not_reread_the_stored_credentials(self):
        """The auth config resolved the OAuth and SCIM secrets on every
        request: three database reads and a decryption before each view."""
        self.login_as("admin")
        self.client.get("/api/history")
        with mock.patch.object(self.db, "get_setting_section",
                               wraps=self.db.get_setting_section) as read:
            for _ in range(3):
                self.assertEqual(200, self.client.get("/api/history").status_code)
        self.assertEqual([], [c for c in read.call_args_list if c.args[:1] == ("api_keys",)])

    def test_a_saved_setting_is_seen_on_the_next_read(self):
        """The cache is only safe if every write empties it."""
        from settings.store import get_store
        store = get_store()
        store.section("notifications")
        store.update_section("notifications", {"min_severity": "critical"})
        self.assertEqual("critical", store.section("notifications")["min_severity"])

    def test_a_stored_api_key_is_seen_on_the_next_read(self):
        """Key writes bypass update_section, so they empty the cache themselves;
        otherwise the page kept saying "not configured" after a save."""
        from settings import api_keys
        from settings.store import get_store
        store = get_store()
        self.assertFalse(store.merged()["integrations"]["otx_configured"])
        api_keys.set_key("OTX_API_KEY", "otx-test-value", db=self.db)
        self.assertTrue(store.merged()["integrations"]["otx_configured"])
        api_keys.clear_key("OTX_API_KEY", db=self.db)
        self.assertFalse(store.merged()["integrations"]["otx_configured"])

    def test_an_environment_override_is_not_hidden_by_the_cache(self):
        """Environment variables override stored settings; a cached copy
        built before one was set kept ServiceNow disabled after it was."""
        from settings.store import get_store
        store = get_store()
        self.assertFalse(store.section("servicenow").get("enabled"))
        with mock.patch.dict(os.environ, {"SERVICENOW_ENABLED": "1"}):
            self.assertTrue(store.section("servicenow").get("enabled"))

    def test_rendering_a_page_keeps_the_settings_store(self):
        """The i18n context processor called _reload_settings(), which built
        a new store -- and dropped the cache -- on every page render."""
        from settings import store as store_module
        self.login_as("admin")
        self.client.get("/")
        before = store_module.get_store()
        for path in ("/", "/admin/settings", "/monitoring"):
            self.assertEqual(200, self.client.get(path).status_code, path)
        self.assertIs(before, store_module.get_store())


class SettingsPageStringsTests(EnterpriseAppTestCase):
    def test_the_settings_page_ships_its_strings(self):
        """The tabs waited for a fetch of the locale file before drawing, so
        the page showed the cards under them first and then jumped."""
        import json
        import pathlib
        import re
        self.login_as("admin")
        html = self.client.get("/admin/settings").get_data(as_text=True)
        block = re.search(r'<script type="application/json" id="pageStrings">(.*?)</script>',
                          html, re.S)
        self.assertIsNotNone(block)
        self.assertIn("categories", json.loads(block.group(1))["settings"])
        js = pathlib.Path(__file__).resolve().parent.parent.joinpath(
            "static", "js", "i18n.js").read_text(encoding="utf-8")
        self.assertIn("pageData('pageStrings'", js)
