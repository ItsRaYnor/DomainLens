"""IP threat lists fetched from their maintainers and searched locally.

The DNS blocklists ask their operator about every address, and the Spamhaus
zones say nothing through a public resolver without a key. These lists are
downloaded whole from the maintainer's own site and searched on the server,
so no checked address leaves it. These tests pin the official sources and
their formats, that a private address is "not public" rather than listed
(the bogon ranges some lists carry would otherwise flag every 10.x address),
and that a broken download never wipes a good list.

Documentation addresses (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32) stand
in for public ones: _public is patched to accept them.
"""

import ipaddress
import unittest
from unittest import mock

import ip_lists
from enterprise_harness import EnterpriseAppTestCase

_DOC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32")]


def _public(address):
    return address.is_global or any(address in n for n in _DOC)


SPAMHAUS_V4 = ('{"cidr":"192.0.2.0/25","sblid":"SBL000001","rir":"ripencc"}\n'
               '{"type":"metadata","timestamp":1791402242,"size":100,"records":1,'
               '"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}\n')
SPAMHAUS_V6 = '{"cidr":"2001:db8:1::/48","sblid":"SBL000002","rir":null}\n'
DSHIELD = ("# comment\n#\n"
           "198.51.100.0\t198.51.100.255\t24\t310\tEXAMPLE-NET\tNL\tabuse@example.net\n")


class _Resp:
    def __init__(self, text, status=200):
        self.status_code, self._body = status, text.encode()

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, size):
        yield self._body


def _get(pages):
    return lambda url: _Resp(pages[url]) if url in pages else _Resp("", 404)


OFFICIAL = {
    "https://www.spamhaus.org/drop/drop_v4.json": SPAMHAUS_V4,
    "https://www.spamhaus.org/drop/drop_v6.json": SPAMHAUS_V6,
    "https://feeds.dshield.org/block.txt": DSHIELD,
}


class SourceTests(unittest.TestCase):
    def test_the_lists_come_from_their_maintainers(self):
        self.assertEqual(["https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"],
                         ip_lists.BUILT_IN[ip_lists.SPAMHAUS][2])
        self.assertEqual(["https://feeds.dshield.org/block.txt"], ip_lists.BUILT_IN[ip_lists.DSHIELD][2])

    def test_spamhaus_is_on_and_dshield_off_by_default(self):
        """DShield's file carries a non-commercial licence: an admin decides."""
        with mock.patch.object(ip_lists, "_settings", return_value={}):
            self.assertEqual([ip_lists.SPAMHAUS], [n for n, _, _ in ip_lists.configured_sources()])

    def test_each_format_is_read(self):
        self.assertEqual([("192.0.2.0/25", "SBL000001")],
                         [(str(n), d) for n, d in ip_lists.parse("spamhaus", SPAMHAUS_V4)])
        self.assertEqual([("198.51.100.0/24", "EXAMPLE-NET NL")],
                         [(str(n), d) for n, d in ip_lists.parse("dshield", DSHIELD)])
        plain = "# c\n192.0.2.7\n198.51.100.0/28 ; note\nnot an address\n"
        self.assertEqual(["192.0.2.7/32", "198.51.100.0/28"], [str(n) for n, _ in ip_lists.parse("plain", plain)])


@mock.patch.object(ip_lists, "_public", _public)
class CheckTests(EnterpriseAppTestCase):
    def _load(self, settings=None):
        with mock.patch.object(ip_lists, "_settings", return_value=settings or {"dshield": True}):
            return ip_lists.refresh(get=_get(OFFICIAL))

    def test_before_any_list_is_loaded_nothing_is_checked(self):
        self.assertEqual("not_checked", ip_lists.check("192.0.2.10")["state"])

    def test_listed_ipv4_ipv6_and_not_listed(self):
        self._load()
        found = ip_lists.check("192.0.2.10")
        self.assertEqual(("listed", ip_lists.SPAMHAUS, "SBL000001"),
                         (found["state"], found["lists"][0]["source"], found["lists"][0]["detail"]))
        self.assertIn("Spamhaus", found["lists"][0]["credit"])
        self.assertEqual("listed", ip_lists.check("2001:db8:1::5")["state"])
        self.assertEqual(ip_lists.DSHIELD, ip_lists.check("198.51.100.20")["lists"][0]["source"])
        self.assertEqual("not_listed", ip_lists.check("192.0.2.200")["state"])

    def test_a_private_address_is_not_public_not_listed(self):
        self._load()
        for address in ("10.1.2.3", "192.168.1.1", "127.0.0.1"):
            self.assertEqual("not_public", ip_lists.check(address)["state"], address)

    def test_a_broken_download_keeps_the_good_list(self):
        self._load()
        with mock.patch.object(ip_lists, "_settings", return_value={"dshield": True}):
            report = ip_lists.refresh(get=_get({}))
            status = ip_lists.status()
        self.assertTrue(all(str(v).startswith("error") for v in report.values()))
        self.assertEqual("listed", ip_lists.check("192.0.2.10")["state"])
        self.assertTrue(all(s["error"] for s in status))

    def test_an_empty_list_does_not_replace_a_full_one(self):
        self._load()
        empty = {url: "" for url in OFFICIAL}
        with mock.patch.object(ip_lists, "_settings", return_value={"dshield": True}):
            ip_lists.refresh(get=_get(empty))
        self.assertEqual("listed", ip_lists.check("192.0.2.10")["state"])

    def test_only_https_lists_are_fetched(self):
        with mock.patch.object(ip_lists, "_settings", return_value={"spamhaus_drop": False,
                                                                     "custom_lists": ["http://lists.example.com/ips.txt"]}):
            report = ip_lists.refresh(get=lambda url: self.fail("fetched"))
        self.assertIn("https", report["http://lists.example.com/ips.txt"])


@mock.patch.object(ip_lists, "_public", _public)
class FindingTests(EnterpriseAppTestCase):
    def test_a_server_on_spamhaus_drop_is_a_high_finding(self):
        import recommendations
        results = {"blacklist": {"ip": "192.0.2.10", "listed": [], "clean": ["a"], "is_listed": False,
                                 "ip_lists": {"state": "listed", "lists": [{"source": ip_lists.SPAMHAUS,
                                                                            "detail": "SBL000001", "credit": ""}]}}}
        found = [r for r in recommendations._blacklist(results) if "Spamhaus DROP" in r["title"]]
        self.assertEqual(["high"], [r["severity"] for r in found])

    def test_check_blacklist_carries_the_ip_lists(self):
        with mock.patch.object(ip_lists, "_settings", return_value={"dshield": True}):
            ip_lists.refresh(get=_get(OFFICIAL))
        with mock.patch.object(self.app_module, "_build_dnsbl_list", return_value=[]):
            result = self.app_module.check_blacklist("192.0.2.10")
        self.assertEqual("listed", result["ip_lists"]["state"])

    def test_the_mail_analysis_names_a_sender_on_a_list(self):
        import mail_test

        class Lookups(mail_test.Lookups):
            def txt(self, name): return []
            def spf(self, ip, mail_from, helo): return ("pass", "")
            def ptr(self, ip): return []
            def addresses(self, host): return []
            def blocklist(self, ip):
                return {"listed": [], "spamhaus_dqs": False,
                        "ip_lists": {"state": "listed", "lists": [{"source": ip_lists.SPAMHAUS, "detail": "", "credit": ""}]}}

        raw = ("Received: from mail.example.org ([192.0.2.10]) by mx.example.net with ESMTPS; Mon, 5 Oct 2026\r\n"
               "From: a@example.org\r\nTo: b@example.net\r\nSubject: s\r\nDate: Mon, 5 Oct 2026 10:00:00 +0000\r\n"
               "Message-ID: <1@example.org>\r\n\r\nhi\r\n").encode()
        with mock.patch.object(mail_test, "_public", _public):
            result = mail_test.analyse(raw, lookups=Lookups())
        self.assertIn("The sending address is on an IP threat list", [f["title"] for f in result["findings"]])


class RouteTests(EnterpriseAppTestCase):
    def test_status_and_refresh(self):
        self.login_as("user")
        self.assertEqual([ip_lists.SPAMHAUS], [l["source"] for l in self.client.get("/api/iplists").get_json()["lists"]])
        self.assertEqual(403, self.client.post("/api/iplists/refresh").status_code)


if __name__ == "__main__":
    unittest.main()
