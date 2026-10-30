"""Bulk writes are one transaction, so they neither hold the write lock for
minutes nor leave half a list behind.

The database connection runs in autocommit mode: every statement was a
transaction of its own, written to disk before the next. Storing PHP's CVE
ranges held the app's global write lock for 28 seconds, a threat list of
100,000 addresses for minutes, and every other write -- the audit entry of a
tool lookup -- waited for it: the tools felt stuck while a sync ran. A write
that failed half-way left the old rows deleted and the new ones missing.
"""

import os
import tempfile
import threading
import time
import unittest
from unittest import mock

import cve_feed
from test_cve_feed import NOW, PHP, _all_synced, _clear, _cve, _enabled, _load_php, _match, _page

_tempdir = None


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "bulk-writes.db")
    import db
    db.init_db()


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


class TransactionTests(unittest.TestCase):
    def setUp(self):
        import db
        with db._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS bulk_probe (n INTEGER)")
            conn.execute("DELETE FROM bulk_probe")

    def _count(self):
        import db
        with db._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM bulk_probe").fetchone()[0]

    def test_a_failure_leaves_nothing_of_the_transaction(self):
        import db
        with self.assertRaises(RuntimeError):
            with db.transaction() as conn:
                conn.executemany("INSERT INTO bulk_probe (n) VALUES (?)", [(i,) for i in range(10)])
                raise RuntimeError("half-way")
        self.assertEqual(0, self._count())

    def test_the_rows_are_there_once_it_ends(self):
        import db
        with db.transaction() as conn:
            conn.executemany("INSERT INTO bulk_probe (n) VALUES (?)", [(i,) for i in range(10)])
        self.assertEqual(10, self._count())

    def test_thousands_of_rows_do_not_hold_the_lock_for_seconds(self):
        """20,000 rows took 35 seconds one commit at a time, 0.04 in one."""
        import db
        start = time.perf_counter()
        with db.transaction() as conn:
            conn.executemany("INSERT INTO bulk_probe (n) VALUES (?)", [(i,) for i in range(20000)])
        self.assertLess(time.perf_counter() - start, 3.0)

    def test_a_bulk_write_gets_a_page_cache_its_index_fits_in(self):
        """With the default 2 MB, a 100,000-row threat list indexed on its
        hashes took 10 seconds under the lock; with 64 MB, 1.5."""
        import db
        with db.transaction() as conn:
            self.assertLessEqual(conn.execute("PRAGMA cache_size").fetchone()[0], -65536)

    def test_it_takes_the_global_write_lock(self):
        import db
        with db.transaction():
            self.assertTrue(db._lock.locked())
        self.assertFalse(db._lock.locked())


class CveStoreTests(unittest.TestCase):
    def setUp(self):
        _clear()
        _load_php()
        _all_synced()

    def test_a_store_that_fails_half_way_keeps_the_cves_that_were_there(self):
        before = cve_feed.stored_cves("php")
        self.assertTrue(before)
        record = _cve("CVE-2026-50001", [_match("php:php", version="8.1.5")])["cve"]
        good = (record, cve_feed.ranges_for(record, "php:php"))
        broken = ({"id": "CVE-2026-50002", "vulnStatus": "Analyzed"}, [("too", "short")])
        with self.assertRaises(Exception):
            cve_feed._store("php", [good, broken], full=True)
        self.assertEqual(before, cve_feed.stored_cves("php"))


class OverviewCacheTests(unittest.TestCase):
    """Tools -> Versions read all 30,000 ranges on every visit (0.6 s),
    though they change only when a sync stores new data."""

    def setUp(self):
        _clear()
        _load_php()
        _all_synced()

    def test_a_second_visit_does_not_read_the_ranges_again(self):
        cve_feed.overview()
        with mock.patch.object(cve_feed, "_ranges", wraps=cve_feed._ranges) as ranges:
            again = cve_feed.overview()
        ranges.assert_not_called()
        self.assertEqual("php", again[0]["key"])

    def test_new_data_is_shown_after_a_sync(self):
        before = next(r for r in cve_feed.overview() if r["key"] == "php")["cves"]
        record = _cve("CVE-2026-50003", [_match("php:php", versionStartIncluding="8.4.0",
                                                versionEndExcluding="8.4.99")], score=5.0)
        with _enabled():
            cve_feed.sync_nvd([PHP], get=mock.Mock(return_value=_page([record])), sleep=mock.Mock(), now=NOW)
        after = next(r for r in cve_feed.overview() if r["key"] == "php")["cves"]
        self.assertEqual(before + 1, after)

    def test_changing_a_returned_row_does_not_change_the_next_one(self):
        cve_feed.overview()[0]["cves"] = -1
        self.assertNotEqual(-1, cve_feed.overview()[0]["cves"])


if __name__ == "__main__":
    unittest.main()
