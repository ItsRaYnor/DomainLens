import os
import socket
import tempfile
import unittest
from unittest import mock


class PortCheckTests(unittest.TestCase):
    """`_check_port` was deleted in a refactor while its call site stayed, so
    every scan's Open Ports check raised NameError. The surrounding try/except
    swallowed it into a generic error string, which is why it went unnoticed:
    the check reported "failed" rather than crashing.
    """

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        cls.app = app

    def test_open_port_is_detected(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        try:
            port = server.getsockname()[1]
            self.assertTrue(self.app._check_port("127.0.0.1", port, timeout=2))
        finally:
            server.close()

    def test_closed_port_is_not_reported_open(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.close()
        self.assertFalse(self.app._check_port("127.0.0.1", port, timeout=2))

    def test_unreachable_host_does_not_raise(self):
        # 198.51.100.0/24 is TEST-NET-2: reserved and never routed.
        self.assertFalse(self.app._check_port("198.51.100.1", 9, timeout=0.2))


class CheckPortsTests(unittest.TestCase):
    """End-to-end: the check that was broken must now produce a result rather
    than an error string."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        cls.app = app

    def test_scan_produces_open_and_closed_lists(self):
        with mock.patch.object(self.app, "_safe_resolve_ip", return_value="93.184.216.34"), \
             mock.patch.object(self.app, "_check_port", side_effect=lambda ip, p: p == 443), \
             mock.patch.object(self.app, "_scan_ports_map",
                               return_value={80: "HTTP", 443: "HTTPS", 22: "SSH"}):
            result = self.app.check_ports("example.com")

        self.assertNotIn("error", result)
        self.assertEqual([p["port"] for p in result["open"]], [443])
        self.assertEqual([p["port"] for p in result["closed"]], [22, 80])

    def test_results_are_sorted_by_port(self):
        with mock.patch.object(self.app, "_safe_resolve_ip", return_value="93.184.216.34"), \
             mock.patch.object(self.app, "_check_port", return_value=True), \
             mock.patch.object(self.app, "_scan_ports_map",
                               return_value={443: "HTTPS", 22: "SSH", 80: "HTTP"}):
            result = self.app.check_ports("example.com")
        self.assertEqual([p["port"] for p in result["open"]], [22, 80, 443])

    def test_private_address_is_refused(self):
        # The SSRF guard must keep working; a scan of an internal host is not
        # something this tool should perform on request.
        result = self.app.check_ports("localhost")
        self.assertIn("error", result)

    def test_a_check_that_raises_is_reported_not_swallowed_silently(self):
        with mock.patch.object(self.app, "_safe_resolve_ip", return_value="93.184.216.34"), \
             mock.patch.object(self.app, "_scan_ports_map", side_effect=RuntimeError("boom")):
            result = self.app.check_ports("example.com")
        self.assertIn("error", result)
        self.assertIn("boom", result["error"])


if __name__ == "__main__":
    unittest.main()
