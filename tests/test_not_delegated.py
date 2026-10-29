"""A name that is not in DNS is not scanned as if it were empty.

A domain in SIDN's quarantine ("pending delete") has no name servers. Every
check found nothing and each "nothing" became a finding -- no SPF, no DMARC,
no HTTPS, sixteen in all, with a wall of red tiles -- for a domain that has
no mail, web or DNS to judge. Only an NXDOMAIN counts as "not in DNS": a
timeout says nothing about the name. The scan then runs as usual once DNS
answers again (test_monitor_schedule_dns covers when it does not).
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

    def test_an_unanswered_lookup_still_scans_when_dns_answers_again(self):
        app = self.app_module
        with mock.patch.object(app, "_name_exists", return_value=None), \
             mock.patch.object(app.dns_health, "check", return_value={"state": "ok", "error": None}), \
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
        self.assertEqual({"weak_auth": None, "blacklist": None, "ipv6_mail": None,
                          "dkim": None, "mta_sts": None, "tlsrpt": None}, data["overview"])


def _chain_nxdomain(name, target):
    """The NXDOMAIN a resolver raises for a CNAME whose target is gone."""
    import dns.message, dns.name, dns.rcode, dns.rdata, dns.rdataclass, dns.rdatatype
    qname = dns.name.from_text(name)
    response = dns.message.make_response(dns.message.make_query(qname, "A"))
    rrset = response.find_rrset(response.answer, qname, dns.rdataclass.IN, dns.rdatatype.CNAME,
                                create=True)
    rrset.add(dns.rdata.from_text("IN", "CNAME", target + "."), 300)
    response.set_rcode(dns.rcode.NXDOMAIN)
    return dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: response})


_TAKEOVER = {"kind": "takeover", "subdomain": "app.example.org", "cname": "gone.example.net",
             "service": "Example Cloud", "target_resolves": False, "fingerprint_match": False,
             "http_status": None, "confidence": "medium"}


class DanglingCnameTests(EnterpriseAppTestCase):
    """A name that is a CNAME to a target that no longer exists was reported
    as "does not exist in DNS (NXDOMAIN)" with advice to fix the delegation:
    the resolver's NXDOMAIN belongs to the end of the chain, and the dangling
    record -- where a subdomain takeover starts -- went unmentioned."""

    def test_an_nxdomain_at_the_end_of_a_cname_is_not_the_names_own(self):
        app = self.app_module
        with mock.patch.object(app.dns.resolver, "resolve",
                               side_effect=_chain_nxdomain("app.example.org", "gone.example.net")):
            self.assertEqual(app._DANGLING, app._name_exists("app.example.org"))

    def test_a_dangling_cname_is_reported_as_one_not_as_missing_delegation(self):
        import recommendations
        app = self.app_module
        with mock.patch.object(app, "_name_exists", return_value=app._DANGLING), \
             mock.patch.object(app.security_checks, "_check_one_takeover", return_value=dict(_TAKEOVER)), \
             mock.patch.object(app, "lookup_whois", return_value={"success": True, "rdap": {"success": True}}), \
             mock.patch.object(app, "_run_checks") as run_checks:
            results = app.run_selected_checks("app.example.org", ["all"])
        run_checks.assert_not_called()
        self.assertEqual(("dangling_cname", "gone.example.net"),
                         (results["not_delegated"]["reason"], results["not_delegated"]["cname"]))
        recs = recommendations.generate(results)
        self.assertEqual(["Possible subdomain takeover: app.example.org"], [r["title"] for r in recs])
        self.assertEqual("medium", recs[0]["severity"])
        self.assertNotIn("delegation", recs[0]["fix"])

    def test_a_target_that_resolves_again_is_scanned_as_usual(self):
        app = self.app_module
        with mock.patch.object(app, "_name_exists", return_value=app._DANGLING), \
             mock.patch.object(app.security_checks, "_check_one_takeover", return_value=None), \
             mock.patch.object(app, "_run_checks") as run_checks, \
             mock.patch.object(app, "_get_apex_domain", return_value="example.org"):
            app.run_selected_checks("app.example.org", ["spf"])
        run_checks.assert_called_once()
