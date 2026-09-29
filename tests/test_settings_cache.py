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
