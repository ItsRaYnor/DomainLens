import http.server
import os
import threading
import unittest
from unittest import mock

import requests

import net_guard


class AddressRangeTests(unittest.TestCase):
    """Four copies of the "is this private" check each let through 0.0.0.0
    (localhost on Linux), carrier-grade NAT, multicast and IPv4 written as
    IPv6 -- so ::ffff:127.0.0.1 passed as a public address."""

    def test_addresses_that_reach_the_servers_own_network_are_not_public(self):
        for ip in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
                   "0.0.0.0", "100.64.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
                   "::1", "::", "fe80::1", "fd00::1", "ff02::1",
                   "::ffff:127.0.0.1", "::ffff:10.0.0.1", "2002:7f00:1::1",
                   "fe80::1%eth0", "not-an-ip", ""):
            with self.subTest(ip=ip):
                self.assertFalse(net_guard.is_public(ip))

    def test_public_addresses_are_public(self):
        for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"):
            with self.subTest(ip=ip):
                self.assertTrue(net_guard.is_public(ip))

    def test_one_internal_address_among_public_ones_is_refused(self):
        # A client may connect to any of them; only the first was checked.
        self.assertFalse(net_guard.safe_host("mixed.example.com", ["93.184.215.14", "10.0.0.5"]))
        self.assertTrue(net_guard.safe_host("ok.example.com", ["93.184.215.14", "2606:2800::1"]))

    def test_a_name_without_addresses_is_not_safe(self):
        self.assertFalse(net_guard.safe_host("nothing.example.com", []))


class _Handler(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Handler.hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"console.log('internal');")

    def log_message(self, *args):
        pass


class ConnectTimeTests(unittest.TestCase):
    """A name can pass the check and resolve to 127.0.0.1 a moment later when
    the request resolves it again, and a redirect or a script the page links
    was never checked at all. What counts is the address the socket reached.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Handler.hits.clear()
        self._env = mock.patch.dict(os.environ, {"NO_PROXY": "*", "no_proxy": "*"})
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def _refused(self):
        # urllib3 reports it as an aborted connection, carrying the reason.
        return self.assertRaisesRegex(requests.exceptions.ConnectionError, "not a public address")

    def test_a_request_to_an_internal_address_is_never_sent(self):
        with self._refused():
            net_guard.get(f"http://127.0.0.1:{self.port}/admin", timeout=5)
        self.assertEqual(_Handler.hits, [])

    def test_a_name_that_resolves_internally_is_caught_at_connect(self):
        # No check beforehand: as after DNS rebinding, only the socket knows.
        with self._refused():
            net_guard.get(f"http://localhost:{self.port}/", timeout=5)
        self.assertEqual(_Handler.hits, [])

    def test_the_js_scanner_does_not_fetch_a_script_on_an_internal_address(self):
        import js_scan
        self.assertIsNone(js_scan._fetch_script(f"http://127.0.0.1:{self.port}/app.js"))
        self.assertIsNone(js_scan._fetch_map(f"http://127.0.0.1:{self.port}/app.js.map"))
        self.assertEqual(_Handler.hits, [])

    def test_security_checks_requests_are_guarded(self):
        import security_checks
        with self._refused():
            security_checks._get(f"http://127.0.0.1:{self.port}/", timeout=5)
        self.assertEqual(_Handler.hits, [])

    def test_the_active_scanner_does_not_probe_an_internal_address(self):
        import active_scan
        with self._refused():
            active_scan._get(f"http://127.0.0.1:{self.port}/?q=<script>", timeout=5)
        self.assertEqual(_Handler.hits, [])


if __name__ == "__main__":
    unittest.main()
