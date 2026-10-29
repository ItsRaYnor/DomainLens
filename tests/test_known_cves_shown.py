"""The known-CVE comparison is visible wherever a version check is shown.

With the CVE data switched on, a WordPress site that hid its version came back
on the Versions page with only the PHP rule in it: the comparison of a hidden
version was filtered out, the page listed only the rules under "Checked for",
and the scan result showed CVEs only as findings. It looked as if the check
did not exist. A hidden version is "cannot tell", as it is for a rule, and a
comparison that is switched off says so.
"""

import json
import pathlib
import shutil
import subprocess
import unittest
from unittest import mock

import cve_feed
import software_advisories as sa
from enterprise_harness import EnterpriseAppTestCase
from test_software_advisories import _DOM_STUB, _VERSIONS_JS

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP_JS = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")

HIDDEN = {"product": "WordPress", "key": "wordpress", "state": "unmeasured", "version": None, "cves": [],
          "reason": "WordPress is in use but its version is not shown."}


def _settings(enabled):
    return mock.patch.object(cve_feed, "settings",
                             return_value={"enabled": enabled, "ncsc": False, "max_age_days": 3})


class HiddenVersionTests(unittest.TestCase):
    def test_a_hidden_version_says_so_even_before_the_data_is_synced(self):
        """Without a version nothing can be compared; "the CVE data has not
        been fetched yet" blamed the data for what the site hides."""
        product = next(p for p in cve_feed.PRODUCTS if p["key"] == "wordpress")
        found = cve_feed.assess_product(product, None, fresh={"state": "never", "max_age_days": 3})
        self.assertEqual("WordPress is in use but its version is not shown.", found["reason"])

    def test_php_in_use_from_its_cookie_is_in_the_cve_comparison_too(self):
        """The PHP2Shell rule said "PHP in use" from a PHPSESSID cookie; the
        CVE data, not knowing that cookie, left PHP out of the same result."""
        never = {"state": "never", "synced_at": None, "max_age_days": 3}
        with _settings(True), mock.patch.object(cve_feed, "freshness", return_value=never):
            found = cve_feed.assess({}, None, "PHPSESSID=abc", "https://example.org/")
        self.assertEqual(["php"], [a["key"] for a in found])
        self.assertEqual("PHP is in use but its version is not shown.", found[0]["reason"])

    def test_a_major_version_alone_is_named_not_called_hidden(self):
        """"Drupal 11 (https://www.drupal.org)" stood in the result column
        while the reason said the version was not shown."""
        never = {"state": "never", "synced_at": None, "max_age_days": 3}
        with _settings(True), mock.patch.object(cve_feed, "freshness", return_value=never):
            found = cve_feed.assess({"server": "Apache"}, "Drupal 11 (https://www.drupal.org)", "",
                                    "https://example.org/")
        by_key = {a["key"]: a for a in found}
        self.assertEqual(("cannot_tell", "Drupal 11"), (by_key["drupal"]["state"], by_key["drupal"]["version"]))
        self.assertIn("shows only its major version", by_key["drupal"]["reason"])
        self.assertIn("its version is not shown", by_key["apache-httpd"]["reason"], "a bare Apache shows none")

    def test_a_rule_says_the_same_about_a_major_version(self):
        rule = sa.compile_rule({"id": "drupal-x", "name": "Drupal flaw", "product": "Drupal", "token": "Drupal",
                                "severity": "high", "summary": "A flaw.", "cves": ["CVE-2026-11111"],
                                "sources": ["meta:generator"], "fixed": ["11.2.5"]})
        found = sa.match({}, generator="Drupal 11 (https://www.drupal.org)", rules=[rule])
        self.assertEqual([("cannot_tell", "Drupal 11")], [(a["verdict"], a["version"]) for a in found])
        self.assertIn("cannot be compared with the fix", found[0]["reason"])
        self.assertEqual("Drupal/11.2.4", sa.parse_version(rule, ["Drupal/11.2.4"])["raw"])

    def test_the_csv_calls_a_hidden_version_cannot_tell(self):
        rows = sa._csv_rows("example.org", "2026-10-29", {"advisories": [], "cves": [HIDDEN]})
        self.assertEqual(["cannot_tell"], [r["result"] for r in rows])


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class VersionsTableTests(unittest.TestCase):
    def _run(self, scenario):
        script = _DOM_STUB + _VERSIONS_JS.read_text(encoding="utf-8") + "\n" + scenario
        done = subprocess.run(["node", "-"], input=script, capture_output=True, text=True, encoding="utf-8",
                              timeout=30)
        self.assertEqual(0, done.returncode, done.stderr)
        return json.loads(done.stdout.strip().splitlines()[-1])

    def test_a_hidden_version_is_cannot_tell_and_named_under_why(self):
        out = self._run("""
            const side = { advisories: [], cves: [%s] };
            console.log(JSON.stringify({ verdict: vcVerdict(side)[0], why: vcWhy(side) }));
        """ % json.dumps(HIDDEN))
        self.assertEqual("Cannot tell from outside", out["verdict"])
        self.assertIn("WordPress is in use but its version is not shown.", out["why"])


class VersionsPageTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.login_as("user")

    def test_checked_for_lists_the_known_cve_comparison(self):
        with _settings(True):
            page = self.client.get("/tools/versions").get_data(as_text=True)
        self.assertIn("Known CVEs (NVD)", page)
        self.assertIn("Every known CVE of these products is compared", page)

    def test_checked_for_shows_what_the_data_holds(self):
        """Only the heading was shown: not what is kept, nor which releases
        have none of the known CVEs."""
        row = {"key": "php", "product": "PHP", "cves": 738, "exploited": 5, "not_versioned": 1,
               "clean_from": ["8.5.12", "8.4.27"], "newest": {"cve": "CVE-2026-109619", "published": "2026-10-21",
                                                              "score": 8.1, "kev": True}}
        with _settings(True), mock.patch.object(cve_feed, "overview", return_value=[row]):
            page = self.client.get("/tools/versions").get_data(as_text=True)
        for text in ("No known CVE from", "8.5.12 · 8.4.27", "CVE-2026-109619", "Exploited (KEV)", "738"):
            self.assertIn(text, page)

    def test_it_says_that_monitored_versions_are_compared_after_each_sync(self):
        """Without it, nobody knows a new CVE for a monitored site is sent
        as an event, nor when that last happened."""
        import cve_alerts
        with _settings(True), mock.patch.object(cve_alerts, "last_run",
                                                return_value={"at": "2026-10-29T03:00:00+00:00", "events": 2}):
            page = self.client.get("/tools/versions").get_data(as_text=True)
        self.assertIn("are compared again", page)
        self.assertIn("2026-10-29", page)

    def test_switched_off_it_says_so(self):
        with _settings(False):
            page = self.client.get("/tools/versions").get_data(as_text=True)
        self.assertIn("Known CVEs (NVD)", page)
        self.assertIn("Not compared: switch it on", page)


class PhoneLayoutTests(unittest.TestCase):
    def test_the_site_list_does_not_push_the_page_sideways(self):
        """A grid item is as wide as its longest option: "All domains in the
        portfolio with a website" made the page 37 pixels too wide on a phone."""
        css = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".vc-form label, .vc-form select { min-width: 0; }", css)


class ScanCardTests(unittest.TestCase):
    def test_the_scan_card_shows_the_version_checks_not_only_the_findings(self):
        self.assertIn("html += knownVulnerabilitiesHtml(info);", APP_JS)
        self.assertIn("const state = a.state === 'unmeasured' && !a.version ? 'cannot_tell' : a.state;", APP_JS)
        self.assertIn("Known CVEs (NVD): switched off, so not compared.", APP_JS)


if __name__ == "__main__":
    unittest.main()
