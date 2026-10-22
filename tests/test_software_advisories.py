"""Known vulnerable software versions, matched against what a server shows.

PHP2Shell (CVE-2026-109618, CVE-2026-109619) was fixed in 8.5.12, 8.4.27,
8.3.36 and 8.2.35 and exploited the same day. A scan saw "X-Powered-By:
PHP/8.2.7" and called it only a version leak; there was no way to see
across the organisation which sites still ran an unfixed PHP. Now the
version shown is compared with the fix -- vulnerable, has the fix, or
cannot tell (hidden, or a distribution build whose package may carry the
fix) -- in every scan, and for the whole portfolio on one page. Nothing is
sent but an ordinary request for the home page.
"""

import unittest
from unittest import mock

import security_checks
import software_advisories as sa
from enterprise_harness import EnterpriseAppTestCase

PHP2SHELL = sa.ADVISORIES[0]


def _verdict(raw):
    return sa.verdict(PHP2SHELL, sa.parse_php([raw]))[0]


class VerdictTests(unittest.TestCase):
    def test_versions_against_the_fix(self):
        cases = {
            "PHP/8.2.7": "vulnerable", "PHP/8.4.26": "vulnerable", "PHP/8.5.11": "vulnerable",
            "PHP/8.2.35": "fixed", "PHP/8.3.36": "fixed", "PHP/8.4.30": "fixed", "PHP/8.5.12": "fixed",
            "PHP/7.4.33": "vulnerable",  # a branch that gets no fixes at all
            "PHP/8.1.2-1ubuntu2.18": "cannot_tell",  # the distribution may have put the fix in
            "PHP/8.2.7-1~deb12u1": "cannot_tell",
            "PHP/8.3": "cannot_tell",  # no patch release shown
        }
        for raw, expected in cases.items():
            self.assertEqual(expected, _verdict(raw), raw)

    def test_the_version_is_read_from_the_server_header_too(self):
        found = sa.match({"server": "Apache/2.4.57 (Unix) PHP/8.3.10"})
        self.assertEqual(("vulnerable", "PHP/8.3.10"), (found[0]["verdict"], found[0]["version"]))

    def test_php_without_a_version_cannot_be_told_and_no_php_is_not_applicable(self):
        self.assertEqual("cannot_tell", sa.match({"server": "nginx"}, "PHPSESSID=x; path=/")[0]["verdict"])
        self.assertEqual([], sa.match({"server": "nginx"}, ""))


class ScanTests(unittest.TestCase):
    def _info(self, headers):
        resp = mock.Mock(headers=headers, text="<html></html>", history=[], url="https://example.org/")
        with mock.patch.object(security_checks, "_safe_host", return_value=True), \
             mock.patch.object(security_checks, "_get", return_value=resp):
            return security_checks.check_info_disclosure("example.org")

    def test_a_vulnerable_version_is_a_critical_finding(self):
        info = self._info({"X-Powered-By": "PHP/8.2.7"})
        findings = security_checks.audit_findings({"info_disclosure": info})
        hit = [f for f in findings if "PHP2Shell" in f["title"]]
        self.assertEqual("critical", hit[0]["severity"])
        self.assertIn("CVE-2026-109618", hit[0]["title"])

    def test_a_hidden_version_is_information_not_a_defect(self):
        info = self._info({"Server": "nginx", "Set-Cookie": "PHPSESSID=abc"})
        findings = security_checks.audit_findings({"info_disclosure": info})
        hit = [f for f in findings if "PHP2Shell" in f["title"]]
        self.assertEqual("info", hit[0]["severity"])

    def test_a_fixed_version_says_nothing(self):
        info = self._info({"X-Powered-By": "PHP/8.4.27"})
        findings = security_checks.audit_findings({"info_disclosure": info})
        self.assertFalse([f for f in findings if "PHP2Shell" in f["title"]])


class FleetTests(unittest.TestCase):
    def test_a_redirect_into_the_own_network_is_not_followed(self):
        """The server asks on someone's behalf; a redirect to 127.0.0.1 or
        a private address would aim it at its own network."""
        first = mock.Mock(status_code=302, headers={"location": "http://127.0.0.1/admin", "X-Powered-By": "PHP/8.2.7"})
        with mock.patch("requests.get", return_value=first) as get:
            result = sa.check_host("example.org", safe=lambda host: host not in ("127.0.0.1",))
        self.assertEqual(1, get.call_count)
        self.assertEqual("vulnerable", result["advisories"][0]["verdict"])

    def test_no_answer_is_unmeasured(self):
        with mock.patch("requests.get", side_effect=OSError("down")):
            result = sa.check_host("example.org", safe=lambda host: True)
        self.assertEqual("unmeasured", result["state"])

    def test_only_the_home_page_is_asked_for(self):
        resp = mock.Mock(status_code=200, headers={"X-Powered-By": "PHP/8.5.12"})
        with mock.patch("requests.get", return_value=resp) as get:
            sa.check_host("example.org", safe=lambda host: True)
        self.assertEqual("https://example.org/", get.call_args[0][0])
        self.assertFalse(get.call_args[1]["allow_redirects"])


class CsvTests(unittest.TestCase):
    """The check's table went nowhere: leaving the page lost it, while the
    teams that patch need the list. Its cells come from servers that are not
    ours, so a Server header written as a formula must not run in Excel."""

    def test_one_row_per_domain_and_outcome(self):
        import csv
        import io
        results = [
            {"domain": "a.example.org", "state": "measured", "powered_by": "PHP/8.2.7", "server": "Apache",
             "url": "https://a.example.org/", "advisories": sa.match({"x-powered-by": "PHP/8.2.7"})},
            {"domain": "b.example.org", "state": "measured", "server": "nginx", "advisories": []},
            {"domain": "c.example.org", "state": "unmeasured", "error": "No response", "advisories": []},
        ]
        rows = list(csv.DictReader(io.StringIO(sa.to_csv(results))))
        self.assertEqual(["vulnerable", "no_php", "no_response"], [r["result"] for r in rows])
        self.assertEqual("CVE-2026-109618 CVE-2026-109619", rows[0]["cves"])

    def test_a_header_written_as_a_formula_is_defused(self):
        out = sa.to_csv([{"domain": "a.example.org", "state": "measured", "server": '=HYPERLINK("http://x")',
                          "advisories": []}])
        self.assertIn("'=HYPERLINK", out)


class ExportPageTests(EnterpriseAppTestCase):
    def test_the_export_answers_with_a_csv_file(self):
        self.login_as("user")
        resp = self.client.post("/api/advisories/csv", json={"results": [
            {"domain": "a.example.org", "state": "measured", "advisories": []}]})
        self.assertEqual("text/csv", resp.mimetype)
        self.assertIn("domainlens-versions-", resp.headers["Content-Disposition"])
        self.assertIn("a.example.org,no_php", resp.get_data(as_text=True))

    def test_the_page_lists_the_advisory_and_the_endpoint_takes_ten_at_a_time(self):
        self.login_as("user")
        html = self.client.get("/tools/versions").get_data(as_text=True)
        self.assertIn("CVE-2026-109618", html)
        self.assertIn('href="/tools/versions"', html)
        seen = []
        with mock.patch.object(security_checks, "_safe_host", return_value=True), \
             mock.patch.object(sa, "check_host", side_effect=lambda d: seen.append(d) or {"domain": d}):
            self.client.post("/api/advisories/check", json={"domains": [f"site{n}.example.org" for n in range(15)]})
        self.assertEqual(10, len(seen))

    def test_a_domain_that_points_inside_is_not_checked(self):
        self.login_as("user")
        with mock.patch.object(security_checks, "_safe_host", return_value=False), \
             mock.patch.object(sa, "check_host") as check:
            self.client.post("/api/advisories/check", json={"domains": ["intranet.example.org"]})
        check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
