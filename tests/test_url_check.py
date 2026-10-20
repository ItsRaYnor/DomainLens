"""Links judged on their own, without the message -- and without opening them.

A suspicious link often arrives alone: forwarded, in a chat, from a
screenshot. DomainLens could check links only inside a whole message. Now
links can be pasted on their own and are judged by what they are, whether
they imitate the organisation's domains, the threat lists, VirusTotal by
hash, the age of their domain and the reputation of their address. Nothing
fetches the link: one request can tell a phisher the link was seen.
"""

import pathlib
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import url_check
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


class FakeLookups(url_check.Lookups):
    def __init__(self, own=("example.com",), registered_days=4000, addresses=("192.0.2.10",), feeds=None):
        self.own, self.days, self.addresses, self._feeds = set(own), registered_days, list(addresses), feeds
        self.asked = []

    def own_domains(self):
        return self.own

    def feeds(self, urls):
        return self._feeds

    def virustotal(self, urls):
        return "off", {}

    def resolve(self, host):
        self.asked.append(("dns", host))
        return ("measured", self.addresses) if self.addresses else ("nxdomain", [])

    def registration(self, domain):
        self.asked.append(("rdap", domain))
        if self.days is None:
            return {"success": False, "state": "measured", "registered": False}
        when = datetime.now(timezone.utc) - timedelta(days=self.days)
        return {"success": True, "registered": when.isoformat(), "registrar": {"name": "Example Registrar"}}

    def reputation(self, ip):
        return {"is_listed": False, "listed": [], "measured": 5, "ip_lists": {"lists": []}}


def _titles(link):
    return {f["title"]: f["severity"] for f in link["findings"]}


class ReadingTests(unittest.TestCase):
    def test_defanged_and_bare_links_are_read(self):
        urls, skipped = url_check.extract("see hxxps://login.example[.]net/a and\nwww.example.org/x\nexample.net/reset")
        self.assertEqual(["https://login.example.net/a", "https://www.example.org/x", "https://example.net/reset"], urls)
        self.assertEqual(0, skipped)

    def test_at_most_ten_at_a_time(self):
        urls, skipped = url_check.extract("\n".join(f"https://h{n}.example.net/" for n in range(13)))
        self.assertEqual((10, 3), (len(urls), skipped))


class WhatTheLinkIsTests(unittest.TestCase):
    def test_a_destination_hidden_behind_an_at(self):
        link = url_check.inspect("https://bank.example.com@evil.example.net/login")
        self.assertEqual("evil.example.net", link["host"])
        self.assertEqual("high", _titles(link)["The link hides its real destination behind an @"])

    def test_look_alike_letters(self):
        link = url_check.inspect("https://exаmple.com/")  # a Cyrillic a
        self.assertEqual("high", _titles(link)["The link uses look-alike characters"])
        self.assertTrue(link["host"].startswith("xn--"))

    def test_an_ip_written_as_one_number(self):
        link = url_check.inspect("http://3232235777/")
        self.assertEqual("192.168.1.1", link["ip"])
        self.assertIn("The link points to a private address", _titles(link))

    def test_another_domains_name_in_front_of_the_real_one(self):
        link = url_check.inspect("https://example.com.secure-login.example.net/")
        self.assertEqual("example.net", link["registrable"])
        self.assertIn("Another domain's name is put in front of the real one", _titles(link))

    def test_a_script_link(self):
        self.assertIn("The link runs code or opens a local file", _titles(url_check.inspect("javascript:alert(1)")))

    def test_an_ordinary_link_has_nothing_to_say(self):
        self.assertEqual([], url_check.inspect("https://www.example.org/news")["findings"])


class KnownTests(unittest.TestCase):
    def test_a_lookalike_of_an_own_domain_registered_days_ago(self):
        result = url_check.check("https://examp1e.com/reset", FakeLookups(registered_days=3))
        found = _titles(result["links"][0])
        self.assertEqual("high", found["The link goes to a lookalike of your domain"])
        self.assertEqual("high", found["The domain was registered days ago"])

    def test_an_unregistered_domain(self):
        result = url_check.check("https://nobody-registered-this.example/", FakeLookups(registered_days=None, addresses=()))
        link = result["links"][0]
        self.assertEqual("not_registered", link["checks"]["registration"]["state"])
        self.assertIn("The domain is not registered", _titles(link))

    def test_a_listed_link(self):
        url = "https://bad.example.net/x"
        found = _titles(url_check.check(url, FakeLookups(feeds={url: "listed"}))["links"][0])
        self.assertEqual("high", found["The link is on a threat list"])

    def test_no_threat_lists_is_said_as_such(self):
        result = url_check.check("https://www.example.org/", FakeLookups(feeds=None))
        self.assertEqual("not_configured", result["feeds"])
        self.assertEqual("not_configured", result["links"][0]["checks"]["feeds"]["state"])


class NeverOpenedTests(unittest.TestCase):
    def test_nothing_fetches_the_link(self):
        """A request to the link tells a phisher it was seen; only the
        registry (RDAP) and DNS are asked, about the domain."""
        source = (ROOT / "url_check.py").read_text(encoding="utf-8")
        self.assertNotIn("requests.", source)
        self.assertNotIn("urlopen", source)
        lookups = FakeLookups()
        with mock.patch("requests.get") as get, mock.patch("requests.head") as head:
            url_check.check("https://login.example.net/token/abc123", lookups)
        get.assert_not_called()
        head.assert_not_called()
        self.assertEqual([("rdap", "example.net"), ("dns", "login.example.net")], lookups.asked)

    def test_the_host_is_looked_up_through_dns4eu(self):
        import dns_tools
        resolver = mock.Mock()
        resolver.resolve.return_value = [mock.Mock(to_text=mock.Mock(return_value="192.0.2.1"))]
        with mock.patch("dns.resolver.Resolver", return_value=resolver):
            url_check.Lookups().resolve("login.example.net")
        self.assertEqual(dns_tools.RESOLVERS["dns4eu-unfiltered"], resolver.nameservers)


class PageTests(EnterpriseAppTestCase):
    def test_the_page_has_both_tabs_and_the_endpoint_answers(self):
        self.login_as("user")
        html = self.client.get("/tools/mail").get_data(as_text=True)
        self.assertIn('data-mt-tab="links"', html)
        self.assertIn('id="linkCheckInput"', html)
        with mock.patch.object(self.app_module, "_LinkLookups", return_value=FakeLookups()):
            data = self.client.post("/api/linkcheck", json={"text": "https://examp1e.com/"}).get_json()
        self.assertEqual("examp1e.com", data["links"][0]["host"])

    def test_text_without_a_link_is_refused_in_words(self):
        self.login_as("user")
        resp = self.client.post("/api/linkcheck", json={"text": "no link here"})
        self.assertEqual(400, resp.status_code)


if __name__ == "__main__":
    unittest.main()
