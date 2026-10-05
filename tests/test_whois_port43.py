"""Registries without RDAP are read over port 43, not left unmeasured.

.be, .eu, .de and .at are not in IANA's RDAP bootstrap. Every domain there
ended as "this registry does not offer RDAP" -- in the portfolio for good,
never measured -- and the WHOIS page fell back on a general parser that
found no registrar, took "NOT AVAILABLE" (registered, at DNS Belgium) for a
status, glued addresses to name servers and raised an error for a domain
that is simply free. The answers below follow each registry's layout, with
placeholder names.
"""

import unittest
from unittest import mock

import whois_batch
import whois_port43

BE = """% .be Whois Server 6.1
%
Domain:\t example.be
Status:\tNOT AVAILABLE
Registered:\tWed Jun 13 2012

Registrant:
\tNot shown, please visit www.dnsbelgium.be for webbased whois.

Registrar:
\tName:\tExample Registrar BV
\tWebsite:\thttps://registrar.example

Nameservers:
\tns1.example.net (192.0.2.1)
\tns1.example.net (2001:db8:0:0:0:0:0:1)
\tns2.example.net (192.0.2.2)

Keys:
\tkeyTag:1 flags:KSK protocol:3 algorithm:ECDSAP256SHA256 pubKey:AAAA

Flags:
\tclientTransferProhibited

Please visit www.dnsbelgium.be for more info.
"""

BE_FREE = """% .be Whois Server 6.1
Domain:\t example-free.be
Status:\tAVAILABLE
"""

EU = """% The WHOIS service offered by EURid
Domain: example.eu
Script: LATIN

Registrant:
        NOT DISCLOSED!

Registrar:
        Name: Example Registrar BV
        Website: https://registrar.example

Name servers:
        ns1.example.net (192.0.2.1)
        ns2.example.net

Keys:

Please visit www.eurid.eu for more info.
"""

DE = """% Restricted rights.
Domain: example.de
Nserver: ns1.example.net 192.0.2.1 2001:db8::1
Nserver: ns2.example.net
Dnskey: 257 3 8 AAAA
Status: connect
Changed: 2024-12-19T13:33:43+01:00
"""

DE_FREE = "Domain: example-free.de\nStatus: free\n"

AT = """% Copyright (c)2026 by NIC.AT (1)
domain:            example.at
registrar:
nserver:           ns1.example.net
remarks:           192.0.2.1
nserver:           ns2.example.net
changed:           20200427 16:03:40
registered:        20000825 20:16:35
DNSSEC:            Unsigned
source:            AT-DOM
"""

AT_FREE = "% Copyright (c)2026 by NIC.AT (1)\n%\n% nothing found\n"

IT = """Domain:             example.it
Status:             ok
Signed:             no
Created:            1997-08-27 00:00:00
Expire Date:        2026-12-31

Registrar
  Organization:     Example Registrar S.r.l.
  Name:             EXAMPLE-REG

Nameservers
  ns1.example.net
  ns2.example.net
"""


def _parse(text, domain):
    return whois_port43.parse(text, domain)


class ParseTests(unittest.TestCase):
    def test_dns_belgium_not_available_means_registered(self):
        r = _parse(BE, "example.be")
        self.assertEqual(("registered", "Example Registrar BV", "2012-06-13", True),
                         (r["lifecycle"]["phase"], r["registrar"]["name"], r["registered"], r["dnssec"]))
        # One entry per server, without the addresses after it.
        self.assertEqual(["ns1.example.net", "ns2.example.net"], r["nameservers"])
        self.assertIn("clientTransferProhibited", r["status"])

    def test_a_free_name_is_not_registered_rather_than_an_error(self):
        for text, domain in ((BE_FREE, "example-free.be"), (DE_FREE, "example-free.de"),
                             (AT_FREE, "example-free.at")):
            r = _parse(text, domain)
            self.assertEqual((False, "measured", False), (r["success"], r["state"], r["registered"]), domain)

    def test_eurid_registrar_and_name_servers(self):
        r = _parse(EU, "example.eu")
        self.assertEqual("Example Registrar BV", r["registrar"]["name"])
        self.assertEqual(["ns1.example.net", "ns2.example.net"], r["nameservers"])

    def test_denic_publishes_no_registrar_and_that_is_left_empty(self):
        r = _parse(DE, "example.de")
        self.assertEqual(("registered", None, True), (r["lifecycle"]["phase"], r["registrar"], r["dnssec"]))
        self.assertEqual(["ns1.example.net", "ns2.example.net"], r["nameservers"])

    def test_nic_at_dates_and_an_unsigned_zone(self):
        r = _parse(AT, "example.at")
        self.assertEqual(("2000-08-25", False, None), (r["registered"], r["dnssec"], r["registrar"]))

    def test_headings_without_a_colon(self):
        r = _parse(IT, "example.it")
        self.assertEqual(("Example Registrar S.r.l.", "2026-12-31", False),
                         (r["registrar"]["name"], r["expires"], r["dnssec"]))
        self.assertEqual(["ns1.example.net", "ns2.example.net"], r["nameservers"])

    def test_quarantine_and_redemption_are_phases(self):
        self.assertEqual("quarantine", _parse("Domain:\t example.be\nStatus:\tQUARANTINE\n",
                                              "example.be")["lifecycle"]["phase"])
        self.assertEqual("redemption", _parse("Domain: example.de\nStatus: redemptionPeriod\n",
                                              "example.de")["lifecycle"]["phase"])

    def test_a_rate_limit_is_not_measured_and_not_free(self):
        r = _parse("% Error: 55000000002 Connection refused; access control limit reached.\n", "example.de")
        self.assertEqual((False, "unmeasured"), (r["success"], r["state"]))

    def test_a_dnssec_answer_that_says_nothing_stays_unknown(self):
        """No keys and no DNSSEC line: unknown, not "no"."""
        r = _parse("Domain: example.de\nNserver: ns1.example.net\nStatus: connect\n", "example.de")
        self.assertIsNone(r["dnssec"])


class LookupTests(unittest.TestCase):
    def test_the_registry_server_is_asked_in_its_own_terms(self):
        asked = []
        whois_port43.lookup("example.de", ask=lambda server, q: asked.append((server, q)) or DE)
        self.assertEqual([("whois.denic.de", "-T dn,ace example.de")], asked)

    def test_a_network_failure_is_not_measured(self):
        def fail(server, q):
            raise OSError("timeout")
        r = whois_port43.lookup("example.be", ask=fail)
        self.assertEqual((False, "unmeasured"), (r["success"], r["state"]))


class FallbackTests(unittest.TestCase):
    class _Pacer:
        def wait(self, server):
            pass

        def hold(self, server, seconds):
            pass

    def test_a_registry_without_rdap_is_read_over_port_43(self):
        """Before, the portfolio and the batch got "does not offer RDAP" and
        nothing else for every domain there."""
        answer = whois_port43.parse(BE, "example.be")
        with mock.patch.object(whois_batch.rdap, "server_for", return_value=None), \
                mock.patch.object(whois_batch.rdap, "lookup",
                                  return_value={"success": False, "state": "not_applicable"}), \
                mock.patch.object(whois_port43, "lookup", return_value=answer) as port43:
            result = whois_batch.lookup_paced("example.be", pacer=self._Pacer())
        port43.assert_called_once_with("example.be")
        self.assertEqual(("whois", "Example Registrar BV"), (result.get("source", "whois"),
                                                             result["registrar"]["name"]))

    def test_a_free_name_over_port_43_is_an_answer(self):
        free = whois_port43.parse(BE_FREE, "example-free.be")
        with mock.patch.object(whois_batch.rdap, "server_for", return_value=None), \
                mock.patch.object(whois_batch.rdap, "lookup",
                                  return_value={"success": False, "state": "not_applicable"}), \
                mock.patch.object(whois_port43, "lookup", return_value=free):
            result = whois_batch.lookup_paced("example-free.be", pacer=self._Pacer())
        self.assertIs(False, result["registered"])

    def test_the_portfolio_says_not_published_for_these_registries(self):
        import domain_portfolio
        state, _ = domain_portfolio.expiry_state({"domain": "example.be", "phase": "registered"})
        self.assertEqual("not_published", state)


if __name__ == "__main__":
    unittest.main()
