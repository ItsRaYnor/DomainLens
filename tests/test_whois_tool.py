"""Registration data through RDAP, and a WHOIS tool that needs no scan.

The port-43 parse missed most of a .nl record -- reseller, DNSSEC,
registrar address -- and the only way to see registration data was to run
a scan. RDAP gives the same structured record for every registry. What the
registry withholds is said to be withheld, with where to look, never shown
as empty.
"""

import unittest
from unittest import mock

import rdap
from enterprise_harness import EnterpriseAppTestCase

# The shape SIDN returns, with invented parties.
_SIDN_LIKE = {
    "ldhName": "example.nl",
    "status": ["active"],
    "secureDNS": {"delegationSigned": True},
    "events": [{"eventAction": "registration", "eventDate": "1999-01-02T23:00:00Z"},
               {"eventAction": "last changed", "eventDate": "2024-02-06T13:10:05Z"}],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}, {"ldhName": "ns2.example.net"}],
    "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]},
        {"roles": ["administrative"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]},
        {"roles": ["registrar"], "vcardArray": ["vcard", [
            ["fn", {}, "text", "Example Registrar"],
            ["adr", {}, "text", ["", "", "Hoofdstraat 1", "Zwolle", "", "8000AA", ""]]]]},
        {"roles": ["reseller"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Hosting"]]]},
    ],
}


class RdapParseTests(unittest.TestCase):
    def setUp(self):
        self.r = rdap.parse(_SIDN_LIKE, "example.nl", server="https://rdap.example/")

    def test_the_fields_port_43_missed_are_there(self):
        self.assertTrue(self.r["dnssec"])
        self.assertEqual("Example Hosting", self.r["reseller"]["name"])
        self.assertEqual("Hoofdstraat 1, Zwolle, 8000AA", self.r["registrar"]["address"])
        self.assertEqual(["ns1.example.net", "ns2.example.net"], self.r["nameservers"])
        self.assertEqual(("1999-01-02", "2024-02-06"), (self.r["registered"], self.r["updated"]))

    def test_a_withheld_holder_is_withheld_not_empty(self):
        """Blank would read as "no holder"; the registry chose not to say."""
        self.assertEqual({"withheld": True}, self.r["registrant"])
        self.assertEqual({"withheld": True}, self.r["administrative"])

    def test_a_contact_the_registry_leaves_out_is_withheld_too(self):
        self.assertEqual({"withheld": True}, self.r["technical"])

    def test_it_points_to_the_registrys_own_lookup(self):
        self.assertEqual("SIDN", self.r["registry_lookup"]["name"])
        self.assertIn("example.nl", self.r["registry_lookup"]["url"])


class RdapLookupStatesTests(unittest.TestCase):
    """Three states kept apart: measured, could not be measured, not applicable."""

    def _resp(self, status, body=None):
        resp = mock.Mock(status_code=status)
        resp.json.return_value = body or {}
        return resp

    def test_an_unregistered_domain_is_a_measured_answer(self):
        with mock.patch.object(rdap, "server_for", return_value="https://rdap.example/"), \
             mock.patch.object(rdap.requests, "get", return_value=self._resp(404)):
            result = rdap.lookup("free.example.nl")
        self.assertEqual(("measured", False), (result["state"], result["registered"]))

    def test_an_unreachable_registry_is_not_measured(self):
        with mock.patch.object(rdap, "server_for", return_value="https://rdap.example/"), \
             mock.patch.object(rdap.requests, "get", side_effect=rdap.requests.ConnectionError()):
            self.assertEqual("unmeasured", rdap.lookup("example.nl")["state"])

    def test_a_tld_without_rdap_is_not_applicable(self):
        with mock.patch.object(rdap, "server_for", return_value=None):
            self.assertEqual("not_applicable", rdap.lookup("example.zz")["state"])


class WhoisToolTests(EnterpriseAppTestCase):
    def test_rdap_rescues_a_failed_port_43_lookup(self):
        app = self.app_module
        with mock.patch.object(app, "_lookup_whois_text",
                               return_value={"success": False, "error": "timeout"}), \
             mock.patch.object(app.rdap, "lookup", return_value={"success": True}):
            self.assertTrue(app.lookup_whois("example.nl")["success"])

    def test_the_tool_is_in_the_tools_menu_and_open_to_viewers(self):
        self.login_as("viewer")
        resp = self.client.get("/tools/whois")
        self.assertEqual(200, resp.status_code)
        self.assertIn('href="/tools/whois"', resp.get_data(as_text=True))

    def test_a_subdomain_is_looked_up_at_its_registered_domain(self):
        self.login_as("viewer")
        app = self.app_module
        with mock.patch.object(app, "_get_apex_domain", return_value="example.nl"), \
             mock.patch.object(app, "lookup_whois", return_value={"success": True}) as lookup:
            data = self.client.get("/api/whois?domain=www.example.nl").get_json()
        lookup.assert_called_once_with("example.nl")
        self.assertEqual("example.nl", data["apex_domain"])

    def test_a_cnamed_host_is_not_mistaken_for_the_apex(self):
        """The SOA query follows a CNAME: www pointing at a hosting provider
        answered with the provider's SOA, so www became its own apex and
        email and WHOIS were checked on www -- "no registration found"."""
        app = self.app_module
        answer = mock.Mock()
        answer.rrset.name.to_text.return_value = "cname.hosting.example."
        with mock.patch.object(app.dns.resolver, "resolve", return_value=answer):
            self.assertEqual("example.nl", app._get_apex_domain("www.example.nl"))

    def test_an_invalid_name_is_refused(self):
        self.login_as("viewer")
        self.assertEqual(400, self.client.get("/api/whois?domain=not a domain").status_code)


if __name__ == "__main__":
    unittest.main()
