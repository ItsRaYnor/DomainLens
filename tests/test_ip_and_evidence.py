import os
import tempfile
import unittest
from unittest import mock

import evidence
import ip_intel


class AddressClassificationTests(unittest.TestCase):
    """Private and loopback addresses are refused rather than sent to a
    registry: no registry has an answer for them, and asking would hand a
    detail of the operator's internal network to a third party.
    """

    def test_a_public_address_is_looked_up(self):
        address, refusal = ip_intel.classify("8.8.8.8")
        self.assertIsNotNone(address)
        self.assertIsNone(refusal)

    def test_private_ranges_are_refused(self):
        for value in ("192.168.1.1", "10.0.0.5", "172.16.3.9", "fd00::1"):
            _address, refusal = ip_intel.classify(value)
            self.assertIsNotNone(refusal, value)

    def test_loopback_is_refused(self):
        self.assertIsNotNone(ip_intel.classify("127.0.0.1")[1])
        self.assertIsNotNone(ip_intel.classify("::1")[1])

    def test_link_local_is_refused(self):
        self.assertIsNotNone(ip_intel.classify("169.254.1.1")[1])

    def test_a_non_address_is_distinguished_from_a_refusal(self):
        # "not an address" and "an address nobody registered" are different
        # answers and must not render the same.
        address, refusal = ip_intel.classify("example.com")
        self.assertIsNone(address)
        self.assertEqual(refusal, "Not a valid IP address")

    def test_ipv6_is_accepted(self):
        address, refusal = ip_intel.classify("2001:4860:4860::8888")
        self.assertIsNotNone(address)
        self.assertIsNone(refusal)

    def test_is_ip_separates_names_from_addresses(self):
        self.assertTrue(ip_intel.is_ip("1.2.3.4"))
        self.assertTrue(ip_intel.is_ip("::1"))
        self.assertFalse(ip_intel.is_ip("example.com"))
        self.assertFalse(ip_intel.is_ip(""))


class RdapParsingTests(unittest.TestCase):
    """The abuse contact is the field a notice depends on, and registries
    nest it inside the network's org entity rather than at the top level."""

    def _response(self, payload, status=200):
        resp = mock.Mock(status_code=status)
        resp.json.return_value = payload
        resp.raise_for_status.return_value = None
        return resp

    def _payload(self):
        return {
            "handle": "NET-8-8-8-0-1",
            "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
            "name": "GOGL", "type": "DIRECT ALLOCATION", "country": "US",
            "events": [{"eventAction": "registration", "eventDate": "2023-01-01T00:00:00Z"}],
            "entities": [{
                "handle": "GOGL",
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
                "entities": [{
                    "handle": "ABUSE5250-ARIN",
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Abuse"],
                        ["email", {}, "text", "network-abuse@google.com"],
                    ]],
                }],
            }],
        }

    def test_a_nested_abuse_contact_is_found(self):
        session = mock.Mock()
        session.get.return_value = self._response(self._payload())
        result = ip_intel.rdap("8.8.8.8", session=session)
        self.assertTrue(result["success"])
        self.assertEqual(result["abuse"]["email"], "network-abuse@google.com")

    def test_the_range_and_holder_are_reported(self):
        session = mock.Mock()
        session.get.return_value = self._response(self._payload())
        result = ip_intel.rdap("8.8.8.8", session=session)
        self.assertEqual(result["range"], "8.8.8.0 – 8.8.8.255")
        self.assertEqual(result["country"], "US")
        self.assertEqual(result["registrant"]["name"], "Google LLC")

    def test_a_missing_record_is_not_an_error(self):
        session = mock.Mock()
        session.get.return_value = self._response({}, status=404)
        result = ip_intel.rdap("192.0.2.1", session=session)
        self.assertFalse(result["success"])
        self.assertIn("No registry record", result["error"])

    def test_a_network_failure_reports_rather_than_raises(self):
        session = mock.Mock()
        session.get.side_effect = RuntimeError("boom")
        result = ip_intel.rdap("8.8.8.8", session=session)
        self.assertFalse(result["success"])
        self.assertIsNotNone(result["error"])

    def test_an_entity_without_contact_details_is_dropped(self):
        payload = {"entities": [{"handle": "X", "roles": ["abuse"], "vcardArray": ["vcard", []]}]}
        session = mock.Mock()
        session.get.return_value = self._response(payload)
        self.assertIsNone(ip_intel.rdap("8.8.8.8", session=session)["abuse"])


class SimilarityTests(unittest.TestCase):
    """Similarity is measured and described, never judged: whether a name
    infringes is a legal question about a mark and its use, not something an
    edit distance settles."""

    def test_a_tld_swap_is_identified_as_such(self):
        result = evidence.confusable_score("example.org", "example.com")
        self.assertTrue(result["tld_swap_only"])
        self.assertTrue(result["same_label"])
        self.assertEqual(result["edit_distance"], 0)

    def test_a_typo_is_measured(self):
        result = evidence.confusable_score("examp1e.com", "example.com")
        self.assertEqual(result["edit_distance"], 1)
        self.assertFalse(result["tld_swap_only"])

    def test_a_prefixed_name_is_flagged_as_containing(self):
        result = evidence.confusable_score("mijn-example.com", "example.com")
        self.assertTrue(result["contains_protected"])

    def test_an_identical_name_does_not_claim_containment(self):
        result = evidence.confusable_score("example.com", "example.com")
        self.assertFalse(result["contains_protected"])
        self.assertTrue(result["same_label"])

    def test_no_protected_domain_yields_nothing(self):
        self.assertIsNone(evidence.confusable_score("a.nl", ""))
        self.assertIsNone(evidence.confusable_score("", "a.nl"))

    def test_no_verdict_field_exists(self):
        # If this ever grows an "infringing" boolean, that is the tool making
        # a legal assertion on the operator's behalf.
        result = evidence.confusable_score("example.org", "example.com")
        for forbidden in ("infringing", "verdict", "malicious", "illegal"):
            self.assertNotIn(forbidden, result)


class DossierTests(unittest.TestCase):

    def _dossier(self, **kwargs):
        base = dict(
            domain="example.org",
            protected_domain="example.com",
            whois_result={"data": {
                "registrar": "Example Registrar",
                "registrar_abuse_contact_email": "abuse@registrar.example",
                "registrar_iana_id": "1234",
            }},
            ip_report={"ip": "203.0.113.5", "rdap": {
                "name": "EXAMPLE-NET", "range": "203.0.113.0 – 203.0.113.255",
                "abuse": {"email": "abuse@host.example"},
            }},
        )
        base.update(kwargs)
        return evidence.build(**base)

    def test_both_abuse_routes_are_listed(self):
        # They can do different things: one suspends the name, the other
        # removes the content. A notice to the wrong one goes nowhere.
        report = self._dossier()["where_to_report"]
        self.assertEqual(report["registrar"]["abuse_email"], "abuse@registrar.example")
        self.assertEqual(report["hosting_network"]["abuse_email"], "abuse@host.example")
        self.assertIn("suspend", report["registrar"]["can"])
        self.assertIn("content", report["hosting_network"]["can"])

    def test_a_missing_registrar_contact_is_called_out(self):
        # An absent contact is the one thing that stops a notice being sent.
        dossier = self._dossier(whois_result={"data": {"registrar": "Example"}})
        self.assertTrue(any("registrar abuse address" in gap for gap in dossier["gaps"]))

    def test_a_missing_network_contact_is_called_out(self):
        dossier = self._dossier(ip_report={"ip": "203.0.113.5", "rdap": {}})
        self.assertTrue(any("abuse contact in the registry" in gap for gap in dossier["gaps"]))

    def test_without_a_protected_domain_no_similarity_is_claimed(self):
        dossier = self._dossier(protected_domain=None)
        self.assertIsNone(dossier["similarity"])
        self.assertTrue(any("No protected domain" in gap for gap in dossier["gaps"]))

    def test_the_moment_of_observation_is_recorded(self):
        # A registrar will ask when you saw it, and the page may have changed.
        self.assertIn("T", self._dossier()["generated_at"])

    def test_the_body_hash_is_recomputable(self):
        dossier = self._dossier(body_text="hello")
        self.assertEqual(
            dossier["body"]["sha256"],
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

    def test_no_body_means_no_hash_rather_than_an_empty_one(self):
        self.assertIsNone(self._dossier()["body"])


class EvidenceEndpointTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "ev.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        importlib.reload(db_module).init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_an_invalid_domain_is_refused(self):
        resp = self.client.post("/api/evidence", json={"domain": "not a domain"})
        self.assertEqual(resp.status_code, 400)

    def test_an_invalid_protected_domain_is_refused(self):
        resp = self.client.post("/api/evidence",
                                json={"domain": "example.com", "protected_domain": "!!"})
        self.assertEqual(resp.status_code, 400)

    def test_a_dossier_is_returned(self):
        with mock.patch.object(self.app_module, "lookup_whois", return_value={"data": {}}), \
             mock.patch.object(self.app_module, "lookup_dns", return_value={}), \
             mock.patch.object(self.app_module, "check_http_deep", return_value={}), \
             mock.patch.object(self.app_module, "check_ssl", return_value={}), \
             mock.patch.object(self.app_module, "_safe_resolve_ip", return_value="203.0.113.5"), \
             mock.patch.object(self.app_module, "_ip_report", return_value={"ip": "203.0.113.5"}):
            resp = self.client.post("/api/evidence", json={
                "domain": "example.org", "protected_domain": "example.com"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["subject"]["domain"], "example.org")
        self.assertTrue(body["similarity"]["tld_swap_only"])

    def test_a_private_address_lookup_is_answered_not_refused(self):
        resp = self.client.get("/api/ip/192.168.1.1")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("not_applicable", resp.get_json())

    def test_a_non_address_lookup_is_a_400(self):
        self.assertEqual(self.client.get("/api/ip/example.com").status_code, 400)


if __name__ == "__main__":
    unittest.main()
