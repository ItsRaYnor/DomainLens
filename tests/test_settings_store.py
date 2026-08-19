import json
import os
import tempfile
import unittest

import db
from settings.store import SettingsStore, get_store


class SettingsStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, "settings.db")
        os.environ["DOMAINLENS_DB"] = self.db_path
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        self.config_path = os.path.join(self.tempdir.name, "domainlens.json")
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump({"scheduler": {"poll_seconds": 90}}, handle)
        os.environ["DOMAINLENS_CONFIG"] = self.config_path
        db.init_db()
        self.store = get_store(db_module=db, force_new=True)

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_CONFIG", "DOMAINLENS_DISABLE_SCHEDULER", "DOMAINLENS_MONITOR_POLL_SECONDS"):
            os.environ.pop(key, None)

    def test_file_defaults_merge(self):
        merged = self.store.merged(force_reload=True)
        self.assertEqual(merged["scheduler"]["poll_seconds"], 90)
        self.assertIn("443", merged["scan"]["ports"])

    def test_db_round_trip_and_nested_patch(self):
        updated = self.store.update_section(
            "scan",
            {"rate_limit.requests": 7, "rate_limit.window_seconds": 42},
            user_id=None,
        )
        self.assertEqual(updated["rate_limit"]["requests"], 7)
        self.assertEqual(updated["rate_limit"]["window_seconds"], 42)
        reloaded = get_store(db_module=db, force_new=True).section("scan", force_reload=True)
        self.assertEqual(reloaded["rate_limit"]["requests"], 7)

    def test_admin_form_schema_nested_values(self):
        self.store.update_section("scan", {"rate_limit.requests": 3}, user_id=None)
        schema = self.store.admin_form_schema()
        self.assertEqual(schema["sections"]["scan"]["fields"]["rate_limit.requests"]["value"], 3)

    def test_env_override_locks_field(self):
        os.environ["DOMAINLENS_MONITOR_POLL_SECONDS"] = "33"
        store = SettingsStore(config_path=self.config_path, db_module=db)
        schema = store.admin_form_schema()
        self.assertTrue(schema["sections"]["scheduler"]["fields"]["poll_seconds"]["locked"])
        self.assertEqual(store.section("scheduler", force_reload=True)["poll_seconds"], 33)


if __name__ == "__main__":
    unittest.main()
