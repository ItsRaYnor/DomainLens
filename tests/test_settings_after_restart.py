"""Settings saved under Admin -> Settings hold after a restart.

The app reads its settings once at start, before the database is attached.
That cache held only the defaults and the config file, and attaching the
database did not clear it, so until an admin saved something again every
section stored in the database was ignored: the known-CVE comparison an admin
had switched on read as switched off after the server restarted.
"""

import unittest

import config
from settings import store as settings_store


class _Db:
    """The one call the store makes on the database module."""

    def __init__(self, sections):
        self.sections = sections

    def get_all_settings(self):
        return self.sections


class SettingsAfterRestartTests(unittest.TestCase):
    def setUp(self):
        self._saved = (settings_store._store, config._settings)
        settings_store._store = None
        config._settings = None

    def tearDown(self):
        settings_store._store, config._settings = self._saved

    def test_sections_saved_in_the_database_count_once_it_is_attached(self):
        before = config.load_settings()          # app start: no database yet
        self.assertFalse(before.raw["cve_feed"]["enabled"])
        settings_store.get_store(db_module=_Db({"cve_feed": {"enabled": True}}))
        self.assertTrue(config.load_settings().raw["cve_feed"]["enabled"])


if __name__ == "__main__":
    unittest.main()
