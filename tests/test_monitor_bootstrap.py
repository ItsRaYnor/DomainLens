"""Config-declared monitors seed a fresh install; they do not keep coming back.

Bootstrap ran on every start and upserted, so deleting the example monitor
was impossible -- the next deploy recreated it -- and an operator who had
built up their own list found it added to theirs again after every restart.
A monitor the operator deleted is a decision, not drift to be corrected.
"""

import os
import tempfile
import unittest


class BootstrapOnlySeedsAnEmptyDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "boot.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db
        import config
        from settings.store import get_store
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.config = importlib.reload(config)

    def tearDown(self):
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)
        self.tempdir.cleanup()

    def _monitors(self):
        return self.db.list_monitors(limit=500)

    def test_an_empty_database_is_seeded(self):
        """The feature still works: a fresh install gets its example."""
        created = self.config.bootstrap_monitors(self.db)
        self.assertGreater(created, 0)
        self.assertTrue(self._monitors())

    def test_a_second_start_adds_nothing(self):
        self.config.bootstrap_monitors(self.db)
        before = len(self._monitors())
        self.assertEqual(0, self.config.bootstrap_monitors(self.db))
        self.assertEqual(before, len(self._monitors()))

    def test_a_deleted_seed_monitor_stays_deleted(self):
        """The bug as an operator met it: delete the example, redeploy, and
        it is back."""
        self.config.bootstrap_monitors(self.db)
        for monitor in self._monitors():
            self.db.delete_monitor(monitor["id"])
        self.assertEqual([], self._monitors())

        self.config.bootstrap_monitors(self.db)
        self.assertEqual([], self._monitors())

    def test_an_operators_own_monitors_are_left_alone(self):
        """Someone with their own list must not gain the example on top of
        it after a restart."""
        self.db.upsert_monitor(
            domain="mine.example", target="mine.example", record_type="A",
            defaults={"name": "mine", "source_type": "manual", "checks": ["dns"],
                      "schedule_minutes": 1440, "enabled": True},
        )
        self.assertEqual(0, self.config.bootstrap_monitors(self.db))
        domains = {m["domain"] for m in self._monitors()}
        self.assertEqual({"mine.example"}, domains)


    def test_deleting_every_monitor_does_not_re_seed(self):
        """The stricter half of the rule: an empty list is a decision too,
        and "seed when empty" would overrule it at the next restart."""
        self.config.bootstrap_monitors(self.db)
        for monitor in self._monitors():
            self.db.delete_monitor(monitor["id"])
        self.assertEqual(0, self.config.bootstrap_monitors(self.db))
        self.assertEqual([], self._monitors())

    def test_an_install_that_predates_the_marker_is_not_re_seeded(self):
        """Upgrading with monitors already in place must not add the example
        on the first start after this change."""
        self.db.upsert_monitor(
            domain="mine.example", target="mine.example", record_type="A",
            defaults={"name": "mine", "source_type": "manual", "checks": ["dns"],
                      "schedule_minutes": 1440, "enabled": True},
        )
        self.assertEqual(0, self.config.bootstrap_monitors(self.db))
        # And the marker is now set, so a later empty list stays empty.
        for monitor in self._monitors():
            self.db.delete_monitor(monitor["id"])
        self.assertEqual(0, self.config.bootstrap_monitors(self.db))
        self.assertEqual([], self._monitors())


if __name__ == "__main__":
    unittest.main()
