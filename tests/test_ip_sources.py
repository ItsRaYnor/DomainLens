"""IP and ASN data from the most reliable sources, and a dead list is not clean.

The network (ASN) and location both came from ip-api.com's free endpoint:
plain HTTP, non-commercial use only, every address sent to a third party.
Hosting and proxy showed "No" when nothing had been asked. And two SORBS
blocklists that no longer exist answered NXDOMAIN to everything, which was
counted as "not listed" -- as was a timeout, and a list's error code.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import dns.resolver

import geoip
import ip_asn
import osint
from enterprise_harness import EnterpriseAppTestCase


def _json(data):
    resp = mock.Mock(status_code=200)
    resp.json.return_value = {"status": "ok", "data": data}
    resp.raise_for_status = mock.Mock()
    return resp


class AsnTests(unittest.TestCase):
    def test_the_registry_answers_first(self):
        overview = {"resource": "192.0.2.0/24", "announced": True,
                    "asns": [{"asn": 64500, "holder": "EXAMPLE-AS Example Network"}],
                    "block": {"desc": "RIPE NCC (Status: ALLOCATED)"}}
        country = {"located_resources": [{"resource": "192.0.2.0/24", "location": "NL"}]}
        with mock.patch.object(ip_asn.requests, "get", side_effect=[_json(overview), _json(country)]):
            result = ip_asn.lookup("192.0.2.10")
        self.assertEqual(("measured", 64500, "RIPEstat", "NL", "192.0.2.0/24"),
                         (result["state"], result["asn"], result["source"], result["country"], result["prefix"]))
        self.assertEqual("AS64500 EXAMPLE-AS Example Network", ip_asn.label(result))

    def test_team_cymru_when_the_registry_cannot_be_reached(self):
        def txt(name):
            if name.endswith("origin.asn.cymru.com"):
                return ["64500 | 192.0.2.0/24 | NL | ripencc | 2001-01-01"]
            return ["64500 | NL | ripencc | 2001-01-01 | EXAMPLE-AS Example Network, NL"]
        with mock.patch.object(ip_asn.requests, "get", side_effect=ip_asn.requests.ConnectionError("down")), \
             mock.patch.object(ip_asn, "_txt", side_effect=txt):
            result = ip_asn.lookup("192.0.2.10")
        self.assertEqual(("measured", 64500, "Team Cymru"), (result["state"], result["asn"], result["source"]))

    def test_neither_reached_is_not_measured(self):
        with mock.patch.object(ip_asn.requests, "get", side_effect=ip_asn.requests.ConnectionError("down")), \
             mock.patch.object(ip_asn, "_txt", side_effect=dns.resolver.LifetimeTimeout()):
            result = ip_asn.lookup("192.0.2.10")
        self.assertEqual(("unmeasured", None), (result["state"], result["asn"]))
        self.assertTrue(result["error"])


class _Reader:
    def __init__(self, built, record):
        self._built, self._record = built, record

    def metadata(self):
        return mock.Mock(build_epoch=int(self._built.timestamp()))

    def get(self, ip):
        return self._record


class GeoTests(unittest.TestCase):
    RECORD = {"country": {"iso_code": "NL", "names": {"en": "Netherlands"}},
              "city": {"names": {"en": "Amsterdam"}}, "subdivisions": [{"names": {"en": "North Holland"}}]}

    def _lookup(self, built, record=RECORD, configured=True):
        with mock.patch.object(geoip, "configured", return_value=configured), \
             mock.patch.object(geoip, "_db", return_value=_Reader(built, record)):
            return geoip.lookup("192.0.2.10")

    def test_without_an_account_it_is_not_configured_not_guessed(self):
        self.assertEqual("not_configured", self._lookup(datetime.now(timezone.utc), configured=False)["state"])

    def test_a_current_database_gives_the_place_and_the_credit(self):
        result = self._lookup(datetime.now(timezone.utc) - timedelta(days=3))
        self.assertEqual(("measured", "Amsterdam", "NL"), (result["state"], result["city"], result["country_code"]))
        self.assertIn("GeoLite Data created by MaxMind", result["attribution"])

    def test_a_database_past_its_licence_is_not_used(self):
        """The EULA: no old version 30 days after a newer one is out."""
        result = self._lookup(datetime.now(timezone.utc) - timedelta(days=40))
        self.assertEqual("unmeasured", result["state"])
        self.assertIn("40 days old", result["error"])

    def test_an_address_not_in_the_database(self):
        self.assertEqual("not_in_database", self._lookup(datetime.now(timezone.utc), record=None)["state"])


class ContextTests(unittest.TestCase):
    def _context(self, ip_api):
        network = {"state": "measured", "asn": 64500, "holder": "EXAMPLE-AS", "prefix": "192.0.2.0/24",
                   "country": "NL", "source": "RIPEstat", "error": None}
        session = mock.Mock()
        with mock.patch.object(osint.socket, "gethostbyname", return_value="192.0.2.10"), \
             mock.patch.object(osint.ip_asn, "lookup", return_value=network), \
             mock.patch.object(osint.geoip, "lookup", return_value={"state": "not_configured"}), \
             mock.patch.object(osint, "_ip_api_enabled", return_value=ip_api), \
             mock.patch.object(osint, "_session", return_value=session):
            return osint.ip_context("example.org"), session

    def test_no_address_goes_to_ip_api_unless_switched_on(self):
        result, session = self._context(ip_api=False)
        session.get.assert_not_called()
        self.assertEqual("AS64500 EXAMPLE-AS", result["geo"]["asn"])
        self.assertIsNone(result["geo"]["hosting"])
        self.assertIsNone(result["geo"]["proxy"])
        self.assertIsNone(result["geo"]["country"])
        self.assertEqual("NL", result["geo"]["registered_country"])

    def test_switched_on_it_is_asked(self):
        _, session = self._context(ip_api=True)
        session.get.assert_called_once()
        self.assertTrue(session.get.call_args[0][0].startswith("http://ip-api.com/json/"))


class BlocklistTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.app_module._dnsbl_alive_cache.clear()

    def _check(self, answer):
        with mock.patch.object(self.app_module, "_spamhaus_dqs_key", return_value=""), \
             mock.patch.object(self.app_module, "_safe_resolve_ip", return_value="192.0.2.10"), \
             mock.patch("dns.resolver.resolve", side_effect=answer):
            return self.app_module.check_blacklist("example.org")

    def test_sorbs_is_gone(self):
        hosts = [h for h, _k, _l in self.app_module._build_dnsbl_list()]
        self.assertFalse([h for h in hosts if "sorbs" in h])

    def test_a_list_that_does_not_answer_its_test_address_is_not_clean(self):
        result = self._check(dns.resolver.NXDOMAIN())
        self.assertEqual([], result["clean"])
        self.assertEqual(0, result["measured"])
        self.assertTrue(result["unmeasured"])
        import overview
        self.assertEqual("not_tested", overview.blacklist({"blacklist": result})["state"])

    def test_a_timeout_is_not_clean(self):
        def answer(name, rdtype):
            if name.startswith("2.0.0.127."):
                return [mock.Mock(to_text=mock.Mock(return_value="127.0.0.2"))]
            raise dns.resolver.LifetimeTimeout()
        result = self._check(answer)
        self.assertEqual([], result["clean"])
        self.assertEqual(len(self.app_module._DNSBL_OPEN), len(result["unmeasured"]))

    def test_a_working_list_that_does_not_list_the_address_is_clean(self):
        def answer(name, rdtype):
            if name.startswith("2.0.0.127."):
                return [mock.Mock(to_text=mock.Mock(return_value="127.0.0.2"))]
            raise dns.resolver.NXDOMAIN()
        result = self._check(answer)
        self.assertEqual(len(self.app_module._DNSBL_OPEN), len(result["clean"]))
        self.assertEqual([], result["unmeasured"])


class SettingsTests(unittest.TestCase):
    def test_ip_api_is_off_and_maxmind_has_its_keys(self):
        from settings import defaults
        self.assertEqual({"ip_api": False}, defaults.DEFAULTS["ip_context"])
        envs = {item["env"] for item in defaults.OPTIONAL_INTEGRATIONS}
        self.assertTrue({"MAXMIND_ACCOUNT_ID", "MAXMIND_LICENSE_KEY"} <= envs)


if __name__ == "__main__":
    unittest.main()
