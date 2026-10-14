"""Checking your own public address, without passing someone else's off as it.

Tools -> IP address had no way to look up the address you are using. The
request's own address is that only when it is public: from the server's own
network, or through a proxy that is not trusted, it is a private address,
and the public one shown then is the server's -- said so, never as yours.
The server's address comes from RIPEstat, by host name over HTTPS: no
resolver address built into the code, and a registry in the EU.
"""

import pathlib
import unittest
from unittest import mock

import requests

import my_ip
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _documentation_is_public(ip):
    # The documentation ranges stand in for public addresses here; Python
    # counts them as private, and a real address does not belong in a test.
    return ip.startswith(("203.0.113.", "198.51.100."))


def _ripestat(ip):
    resp = mock.Mock(status_code=200)
    resp.json.return_value = {"status": "ok", "data_call_name": "whats-my-ip", "data": {"ip": ip}}
    resp.raise_for_status = mock.Mock()
    return resp


class MineTests(unittest.TestCase):
    def setUp(self):
        my_ip._cache.update(at=0.0, ip=None)
        patcher = mock.patch.object(my_ip, "is_public", _documentation_is_public)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_public_connection_is_the_answer_and_nothing_is_asked(self):
        with mock.patch.object(my_ip.requests, "get") as get:
            result = my_ip.mine("203.0.113.9")
        get.assert_not_called()
        self.assertEqual(("measured", "203.0.113.9", "connection"),
                         (result["state"], result["ip"], result["seen_as"]))

    def test_from_the_same_network_the_servers_address_is_shown_as_the_servers(self):
        with mock.patch.object(my_ip.requests, "get", return_value=_ripestat("198.51.100.20")) as get:
            result = my_ip.mine("192.168.1.15")
        self.assertEqual(("measured", "198.51.100.20", "server", "private", "192.168.1.15"),
                         (result["state"], result["ip"], result["seen_as"], result["reason"], result["client"]))
        self.assertTrue(get.call_args[0][0].startswith("https://stat.ripe.net/data/whats-my-ip/"))

    def test_an_untrusted_proxy_is_named_as_the_reason(self):
        with mock.patch.object(my_ip.requests, "get", return_value=_ripestat("198.51.100.20")):
            result = my_ip.mine("172.17.0.1", forwarded=True, proxy_trusted=False)
        self.assertEqual("proxy_untrusted", result["reason"])

    def test_ripestat_unreachable_is_not_measured_not_the_private_address(self):
        with mock.patch.object(my_ip.requests, "get", side_effect=requests.ConnectionError("down")):
            result = my_ip.mine("10.0.0.5")
        self.assertEqual(("unmeasured", None), (result["state"], result["ip"]))
        self.assertTrue(result["error"])

    def test_a_private_answer_is_not_taken_for_public(self):
        with mock.patch.object(my_ip.requests, "get", return_value=_ripestat("10.0.0.1")):
            self.assertEqual("unmeasured", my_ip.mine("10.0.0.5")["state"])

    def test_no_resolver_address_is_built_in(self):
        """OpenDNS and Cloudflare were asked at fixed addresses: US services,
        and an address in the code that breaks when the operator moves it."""
        source = (ROOT / "my_ip.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"[\"']\d{1,3}(\.\d{1,3}){3}[\"']")
        self.assertNotIn("opendns", source.lower())
        self.assertNotIn("cloudflare", source.lower())


class PageTests(EnterpriseAppTestCase):
    def test_the_ip_page_has_the_button_and_the_endpoint_answers(self):
        self.login_as("user")
        html = self.client.get("/tools/ip").get_data(as_text=True)
        self.assertIn('id="ipMineBtn"', html)
        with mock.patch.object(my_ip, "server_public_ip", return_value=("198.51.100.20", None)):
            data = self.client.get("/api/myip").get_json()
        # The test client connects from 127.0.0.1: the server's address, said so.
        self.assertEqual(("198.51.100.20", "server"), (data["ip"], data["seen_as"]))


if __name__ == "__main__":
    unittest.main()
