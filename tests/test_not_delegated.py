"""A name that is not in DNS is not scanned as if it were empty.

A domain in SIDN's quarantine ("pending delete") has no name servers. Every
check found nothing and each "nothing" became a finding -- no SPF, no DMARC,
no HTTPS, sixteen in all, with a wall of red tiles -- for a domain that has
no mail, web or DNS to judge. Only an NXDOMAIN counts as "not in DNS": a
timeout says nothing about the name, and the scan then runs as usual.
"""

from unittest import mock

import dns.resolver

from enterprise_harness import EnterpriseAppTestCase

_QUARANTINE_WHOIS = {"success": True, "data": {},
                     "rdap": {"success": True, "status": ["pending delete"]}}


class NameExistenceTests(EnterpriseAppTestCase):
    def _exists(self, side_effect):
        with mock.patch.object(self.app_module.dns.resolver, "resolve", side_effect=side_effect):
            return self.app_module._name_exists("gone.example")

    def test_nxdomain_means_the_name_does_not_exist(self):
        self.assertIs(False, self._exists(dns.resolver.NXDOMAIN()))

    def test_an_empty_answer_means_it_does(self):
        self.assertIs(True, self._exists(dns.resolver.NoAnswer()))

    def test_a_timeout_says_nothing_about_the_name(self):
        self.assertIsNone(self._exists(dns.resolver.LifetimeTimeout()))


class NotDelegatedScanTests(EnterpriseAppTestCase):
    def test_only_the_registration_is_looked_up(self):
        app = self.app_module
        with mock.patch.object(app, "_name_exists", return_value=False), \
             mock.patch.object(app, "lookup_whois", return_value=_QUARANTINE_WHOIS), \
             mock.patch.object(app, "_run_checks") as run_checks:
            results = app.run_selected_checks("gone.example", ["all"])
        run_checks.assert_not_called()
        self.assertEqual("registry_status", results["not_delegated"]["reason"])
        self.assertEqual(["pending delete"], results["not_delegated"]["registry_status"])
        self.assertEqual({"apex_domain", "whois", "not_delegated"}, set(results))

    def test_an_unanswered_lookup_still_scans(self):
        app = self.app_module
        with mock.patch.object(app, "_name_exists", return_value=None), \
             mock.patch.object(app, "_run_checks") as run_checks, \
             mock.patch.object(app, "_get_apex_domain", return_value="example.com"):
            app.run_selected_checks("example.com", ["spf"])
        run_checks.assert_called_once()

    def test_one_finding_says_why_instead_of_sixteen(self):
        import recommendations
        recs = recommendations.generate({
            "domain": "gone.example.nl",
            "not_delegated": {"name": "gone.example.nl", "reason": "registry_status",
                              "registry_status": ["pending delete"]}})
        self.assertEqual(["Domain is not in DNS"], [r["title"] for r in recs])
        self.assertEqual("info", recs[0]["severity"])
        self.assertIn("quarantine", recs[0]["problem"])

    def test_the_quarantine_note_is_only_for_nl(self):
        import recommendations
        recs = recommendations.generate({
            "domain": "gone.example",
            "not_delegated": {"name": "gone.example", "reason": "registry_status",
                              "registry_status": ["pending delete"]}})
        self.assertNotIn("SIDN", recs[0]["problem"])

    def test_the_scan_api_returns_no_overview_verdicts(self):
        app = self.app_module
        self.login_as("user")
        with mock.patch.object(app, "_name_exists", return_value=False), \
             mock.patch.object(app, "lookup_whois", return_value=_QUARANTINE_WHOIS):
            data = self.client.post("/api/scan", json={"domain": "gone.example"}).get_json()
        self.assertEqual(1, len(data["recommendations"]))
        self.assertEqual({"weak_auth": None, "blacklist": None, "ipv6_mail": None}, data["overview"])
