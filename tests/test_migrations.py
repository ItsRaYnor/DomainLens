import importlib
import os
import sqlite3
import tempfile
import unittest


class NumberedMigrationTests(unittest.TestCase):
    """Schema changes were made by checking for a column on every start. That
    cannot express a change that must happen exactly once (rewriting stored
    values), and left no record of which schema a database file carries, so a
    backup restored next to the wrong image could not be told apart.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tempdir.name, "migrate.db")
        os.environ["DOMAINLENS_DB"] = self.path
        import db
        self.db = importlib.reload(db)

    def tearDown(self):
        os.environ.pop("DOMAINLENS_DB", None)
        self.tempdir.cleanup()

    def _conn(self):
        conn = sqlite3.connect(self.path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def test_a_new_database_records_the_schema_it_was_created_with(self):
        self.db.init_db()
        self.assertEqual(self.db.schema_version(), self.db.SCHEMA_VERSION)
        with self._conn() as conn:
            rows = conn.execute("SELECT version, app_version FROM schema_migrations").fetchall()
        self.assertEqual([r["version"] for r in rows], [m[0] for m in self.db.MIGRATIONS])
        self.assertTrue(all(r["app_version"] for r in rows))

    def test_a_step_runs_once_however_often_the_app_starts(self):
        self.db.init_db()
        runs = []
        steps = self.db.MIGRATIONS + ((self.db.SCHEMA_VERSION + 1, "count", lambda c: runs.append(1)),)
        for _ in range(3):
            with self.db._connect() as conn:
                self.db._apply_migrations(conn, steps)
        self.assertEqual(runs, [1])

    def test_a_failing_step_leaves_nothing_half_done(self):
        self.db.init_db()
        before = self.db.schema_version()

        def broken(conn):
            conn.execute("ALTER TABLE scans ADD COLUMN half_done TEXT")
            raise RuntimeError("step fails after its first statement")

        steps = self.db.MIGRATIONS + ((before + 1, "broken", broken),)
        with self.db._connect() as conn, self.assertRaises(RuntimeError):
            self.db._apply_migrations(conn, steps)
        self.assertEqual(self.db.schema_version(), before)
        with self._conn() as conn:
            columns = {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}
        self.assertNotIn("half_done", columns, "the step's first statement was not rolled back")

    def test_an_older_release_on_a_newer_database_starts_and_does_not_lower_it(self):
        # A rollback must keep working; the number must not go backwards.
        self.db.init_db()
        with self._conn() as conn:
            conn.execute(f"PRAGMA user_version = {self.db.SCHEMA_VERSION + 5}")
        with self.assertLogs("domainlens.db", level="WARNING"):
            self.db.init_db()
        self.assertEqual(self.db.schema_version(), self.db.SCHEMA_VERSION + 5)

    def test_published_steps_are_numbered_without_gaps(self):
        numbers = [m[0] for m in self.db.MIGRATIONS]
        self.assertEqual(numbers, list(range(1, len(numbers) + 1)))


if __name__ == "__main__":
    unittest.main()
