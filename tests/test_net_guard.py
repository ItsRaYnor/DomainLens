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

    def test_the_http_checks_in_app_do_not_fetch_an_internal_address(self):
        # The header, redirect and MTA-STS checks and the infrastructure
        # check still used plain requests after 0.1.22.
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import app
        with self._refused():
            app._http_request(f"http://127.0.0.1:{self.port}/", allow_redirects=True)
        result = app.check_http_deep(f"127.0.0.1:{self.port}")
        self.assertFalse(result.get("success"))
        self.assertEqual(_Handler.hits, [])

    def test_the_default_credentials_test_does_not_probe_an_internal_address(self):
        import weak_auth
        self.assertIsNone(weak_auth._probe_url(f"http://127.0.0.1:{self.port}/", 5))
        self.assertIsNone(weak_auth._try_basic(f"http://127.0.0.1:{self.port}/", "admin", "admin", 5))
        self.assertEqual(_Handler.hits, [])

    def test_the_version_check_does_not_fetch_an_internal_address(self):
        import software_advisories
        with self._refused():
            software_advisories._fetch(f"http://127.0.0.1:{self.port}/", lambda host: True)
        self.assertEqual(_Handler.hits, [])

    def test_an_operator_who_scans_internal_hosts_can_allow_it(self):
        with mock.patch.dict(os.environ, {"DOMAINLENS_ALLOW_PRIVATE_TARGETS": "true"}):
            resp = net_guard.get(f"http://127.0.0.1:{self.port}/", timeout=5)
            self.assertTrue(net_guard.safe_host("intranet.example.com", ["10.0.0.5"]))
            self.assertTrue(net_guard.safe_host("127.0.0.1"))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(net_guard.safe_host("intranet.example.com", ["10.0.0.5"]))


class RefusalReportingTests(unittest.TestCase):
    """A refused fetch read "Could not connect ... try again later" -- as if
    the host were down, and as if trying again could help."""

    def test_a_refusal_is_not_measured_and_says_why(self):
        import net_errors
        exc = requests.exceptions.ConnectionError(
            net_guard.BlockedAddress("intranet.example.com connected to 10.0.0.5, which is not a "
                                     "public address; the request was not sent"))
        kind, message = net_errors.classify(exc, "intranet.example.com")
        self.assertEqual(kind, net_errors.NOT_PUBLIC)
        self.assertIn("own network", message)
        self.assertIn("Not measured", message)
        self.assertNotIn("try again", message.lower())

    def test_a_refused_redirect_check_is_not_reported_as_a_missing_redirect(self):
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import app
        import recommendations
        refused = requests.exceptions.ConnectionError(
            "x connected to 10.0.0.5, which is not a public address; the request was not sent")
        with mock.patch.object(app, "_http_request", side_effect=refused):
            result = app.check_https_redirect("intranet.example.com")
        self.assertIsNone(result["pass"])
        self.assertEqual(result["state"], "not_measured")
        titles = [r["title"] for r in recommendations._https_redirect({"https_redirect": result})]
        self.assertNotIn("HTTP does not redirect to HTTPS", titles)

    def test_the_page_does_not_raise_a_high_finding_for_an_unverified_redirect(self):
        js = (os.path.dirname(__file__) + "/../static/js/app.js")
        with open(js, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("data.https_redirect.pass === false", text)
        self.assertNotIn("data.https_redirect && !data.https_redirect.pass", text)


if __name__ == "__main__":
    unittest.main()
