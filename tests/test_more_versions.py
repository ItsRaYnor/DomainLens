"""More versions read from what a site already sends.

OpenSSL stood in many Server headers ("Apache/2.4.41 (Ubuntu)
OpenSSL/1.1.1f") and was never compared with its CVEs. A WordPress site that
removed its generator tag was "version not shown" while its own core files
carried the release in their address (?ver=6.8.1). And "WordPress 6.8",
which is the 6.8.0 release, was treated as a version without its patch.
"""

import os
import tempfile
import unittest
from datetime import timedelta
from unittest import mock

import cve_feed
import software_advisories as sa
from test_cve_feed import NOW, PHP, _all_synced, _clear, _cve, _enabled, _load_php, _match, _page

_tempdir = None
OPENSSL = next((p for p in cve_feed.PRODUCTS if p["key"] == "openssl"), None)
WORDPRESS = next(p for p in cve_feed.PRODUCTS if p["key"] == "wordpress")

OPENSSL_RECORDS = [
    # 1.1.1 up to 1.1.1w, exploited.
    _cve("CVE-2026-30001", [_match("openssl:openssl", versionStartIncluding="1.1.1", versionEndExcluding="1.1.1w"),
                            _match("openssl:openssl", versionStartIncluding="3.0.0", versionEndExcluding="3.0.14")],
         score=7.5, kev="2026-05-01"),
    # One lettered release only.
    _cve("CVE-2026-30002", [_match("openssl:openssl", version="1.0.2k")], score=5.9),
]
WORDPRESS_RECORDS = [
    _cve("CVE-2026-40001", [_match("wordpress:wordpress", versionStartIncluding="6.8",
                                   versionEndExcluding="6.8.2")], score=6.1),
]


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "more-versions.db")
    import db
    db.init_db()


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


def _load(product, records):
    with _enabled():
        cve_feed.sync_nvd([product], get=mock.Mock(return_value=_page(records)), sleep=mock.Mock(), now=NOW)


def _assess(headers, generator=None, page=None, url="https://example.org/"):
    with _enabled(), mock.patch.object(cve_feed, "_now", return_value=NOW):
        found = cve_feed.assess(headers, generator, "", url, page)
    return {a["key"]: a for a in found or []}


class OpenSslTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(OPENSSL, "OpenSSL is not a followed product")
        _clear()
        _load(OPENSSL, OPENSSL_RECORDS)
        _all_synced()

    def test_openssl_in_the_server_header_is_compared_with_its_cves(self):
        found = _assess({"server": "Apache/2.4.62 OpenSSL/3.0.13"})["openssl"]
        self.assertEqual("vulnerable", found["state"])
        self.assertEqual(["CVE-2026-30001"], [c["cve"] for c in found["cves"]])
        self.assertEqual("3.0.14", found["fixed_in"])

    def test_a_patch_letter_is_a_release_not_a_distribution_build(self):
        """1.1.1f is the sixth patch of 1.1.1: read as a vendor suffix, every
        OpenSSL 1.x would have been "cannot tell"."""
        found = _assess({"server": "nginx OpenSSL/1.1.1f"})["openssl"]
        self.assertEqual("vulnerable", found["state"])
        self.assertEqual("1.1.1w", found["fixed_in"])
        self.assertEqual("no_known_cves", _assess({"server": "nginx OpenSSL/1.1.1w"})["openssl"]["state"])

    def test_a_lettered_version_in_the_nvd_data_is_compared(self):
        """Read as numbers only, "1.0.2k" had no version to compare with."""
        found = _assess({"server": "nginx OpenSSL/1.0.2k"})["openssl"]
        self.assertEqual(["CVE-2026-30002"], [c["cve"] for c in found["cves"]])
        self.assertEqual("no_known_cves", _assess({"server": "nginx OpenSSL/1.0.2j"})["openssl"]["state"])

    def test_openssl_beside_a_distribution_build_cannot_be_told(self):
        """In "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f" the OpenSSL is Ubuntu's
        package, which carries fixes without a new letter."""
        found = _assess({"server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"})["openssl"]
        self.assertEqual("cannot_tell", found["state"])
        self.assertIn("(Ubuntu)", found["reason"])
        self.assertTrue(found["distribution"])

    def test_a_fips_build_cannot_be_told(self):
        found = _assess({"server": "Apache OpenSSL/1.0.2k-fips"})["openssl"]
        self.assertEqual("cannot_tell", found["state"])

    def test_other_products_keep_reading_numbers_only(self):
        self.assertIsNone(cve_feed._version("8.1.5a"))
        self.assertEqual((1, 1, 1, 23), cve_feed._version("1.1.1w", letters=True))
        self.assertEqual("1.1.1w", cve_feed._fmt((1, 1, 1, 23), letters=True))
        self.assertEqual("2.4.0.1", cve_feed._fmt((2, 4, 0, 1)))


class WordPressCoreFileTests(unittest.TestCase):
    def setUp(self):
        _clear()
        _load(WORDPRESS, WORDPRESS_RECORDS)
        _all_synced()

    def test_the_core_files_give_the_version_the_generator_tag_no_longer_shows(self):
        page = ('<link rel="stylesheet" href="https://example.org/wp-includes/css/dist/block-library/'
                'style.min.css?ver=6.8.1" media="all">')
        found = _assess({}, page=page)["wordpress"]
        self.assertEqual(("vulnerable", "WordPress 6.8.1"), (found["state"], found["version"]))
        self.assertIn("Read from its own core file /wp-includes/css/dist/block-library/style.min.css?ver=6.8.1",
                      found["reason"])

    def test_the_emoji_script_in_its_json_block_counts_too(self):
        page = '<script>window._wpemojiSettings = {"concatemoji":"https:\\/\\/www.example.org\\/wp-includes' \
               '\\/js\\/wp-emoji-release.min.js?ver=6.8.1"};</script>'
        self.assertEqual("WordPress 6.8.1", _assess({}, page=page)["wordpress"]["version"])

    def test_jquery_and_plugins_do_not_give_their_number_as_the_wordpress_release(self):
        page = ('<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
                '<link href="/wp-content/plugins/forms/style.css?ver=6.8.1">')
        found = _assess({}, page=page)["wordpress"]
        self.assertIsNone(found["version"])
        self.assertIn("its version is not shown", found["reason"])

    def test_another_sites_core_files_are_that_sites(self):
        page = '<link href="https://cdn.example.net/wp-includes/css/dist/block-library/style.min.css?ver=6.8.1">'
        self.assertNotIn("wordpress", _assess({}, page=page))

    def test_the_generator_tag_still_comes_first(self):
        page = '<link href="/wp-includes/css/dist/block-library/style.min.css?ver=6.8.1">'
        found = _assess({}, generator="WordPress 6.8.2", page=page)["wordpress"]
        self.assertEqual(("no_known_cves", "WordPress 6.8.2"), (found["state"], found["version"]))
        self.assertNotIn("core file", found["reason"])

    def test_a_rule_reads_the_core_files_as_well(self):
        rule = sa.compile_rule({"id": "wp-x", "name": "WP flaw", "product": "WordPress", "token": "WordPress",
                                "severity": "high", "summary": "A flaw.", "cves": ["CVE-2026-40001"],
                                "sources": ["meta:generator"], "fixed": ["6.8.2"]})
        page = '<link href="/wp-includes/css/dist/block-library/style.css?ver=6.8.1">'
        found = sa.match({}, url="https://example.org/", rules=[rule], page=page)
        self.assertEqual([("vulnerable", "WordPress 6.8.1")], [(a["verdict"], a["version"]) for a in found])

    def test_wordpress_6_8_is_a_release_not_a_version_without_its_patch(self):
        """WordPress calls 6.8.0 "6.8"; that was "cannot tell" before."""
        found = _assess({}, generator="WordPress 6.8")["wordpress"]
        self.assertEqual("vulnerable", found["state"])
        rule = sa.compile_rule({"id": "wp-y", "name": "WP flaw", "product": "WordPress", "token": "WordPress",
                                "severity": "high", "summary": "A flaw.", "cves": ["CVE-2026-40001"],
                                "sources": ["meta:generator"], "fixed": ["6.8.2"]})
        self.assertEqual("vulnerable", sa.match({}, generator="WordPress 6.8", rules=[rule])[0]["verdict"])


class NewProductTests(unittest.TestCase):
    """A product added in an update has never been fetched."""

    def setUp(self):
        _clear()
        _load_php()
        _all_synced()

    def test_a_product_not_fetched_yet_does_not_hold_up_the_others(self):
        import db
        with db._lock, db._connect() as conn:
            conn.execute("DELETE FROM cve_feed_state WHERE source = 'nvd:openssl'")
        found = _assess({"x-powered-by": "PHP/8.1.5", "server": "nginx OpenSSL/3.0.13"})
        self.assertEqual("vulnerable", found["php"]["state"])
        self.assertEqual("unmeasured", found["openssl"]["state"])
        self.assertIn("has not been fetched yet", found["openssl"]["reason"])

    def test_it_is_fetched_at_the_next_turn_allowed_not_a_day_later(self):
        import db
        with db._lock, db._connect() as conn:
            conn.execute("DELETE FROM cve_feed_state WHERE source = 'nvd:openssl'")
        with _enabled(), mock.patch.object(cve_feed, "_now", return_value=NOW + timedelta(hours=3)), \
                mock.patch.object(cve_feed, "sync", return_value={"started": True}) as sync:
            cve_feed.maybe_sync()
        sync.assert_called_once()
        _all_synced()
        with _enabled(), mock.patch.object(cve_feed, "_now", return_value=NOW + timedelta(hours=3)), \
                mock.patch.object(cve_feed, "sync") as sync:
            cve_feed.maybe_sync()
        sync.assert_not_called()


if __name__ == "__main__":
    unittest.main()
