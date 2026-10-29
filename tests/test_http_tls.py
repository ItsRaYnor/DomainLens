"""The CA bundle is loaded once, not for every new HTTPS connection.

requests passed urllib3 the path of certifi's bundle, and urllib3 built a
fresh SSL context for each new connection and loaded the file into it:
about 70 ms of CPU per connection in the production image and 1.3 to 1.8
seconds on Windows, for well over a hundred connections in a full scan.
The shared context must not loosen anything: the same bundle, certificates
still required, and requests that ask for something else left alone.
"""

import socket
import ssl
import threading
import unittest
from unittest import mock

import requests
from requests.adapters import HTTPAdapter

import http_tls

http_tls.install()


class _ClosingServer:
    """Accepts TCP connections on localhost and closes them at once, so every
    request opens a new connection and fails during the TLS handshake."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            conn.close()

    def close(self):
        self._stop = True
        self.sock.close()


def _pool(url, verify=True, cert=None):
    adapter = HTTPAdapter()
    request = requests.Request("GET", url).prepare()
    pool = adapter.get_connection_with_tls_context(request, verify, cert=cert)
    adapter.cert_verify(pool, url, verify, cert)
    return pool


class SharedContextTests(unittest.TestCase):
    def test_new_connections_do_not_load_the_bundle_again(self):
        http_tls.shared_context()  # loaded once, up front
        server = _ClosingServer()
        loads = []
        original = ssl.SSLContext.load_verify_locations

        def counting(self, *args, **kwargs):
            loads.append(args or kwargs)
            return original(self, *args, **kwargs)

        try:
            with mock.patch.object(ssl.SSLContext, "load_verify_locations", counting):
                for _ in range(3):
                    with requests.Session() as session:
                        with self.assertRaises(requests.exceptions.RequestException):
                            session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
        finally:
            server.close()
        self.assertEqual([], loads)

    def test_hosts_share_one_context_that_still_requires_a_trusted_certificate(self):
        a = _pool("https://a.example.org/")
        b = _pool("https://b.example.org/")
        self.assertTrue(http_tls.uses_shared_context(a))
        self.assertTrue(http_tls.uses_shared_context(b))
        self.assertIsNone(a.ca_certs)
        self.assertEqual("CERT_REQUIRED", a.cert_reqs)
        ctx = http_tls.shared_context()
        self.assertEqual(ssl.CERT_REQUIRED, ctx.verify_mode)
        self.assertGreater(ctx.cert_store_stats()["x509_ca"], 0)

    def test_verify_false_is_left_alone(self):
        pool = _pool("https://a.example.org/", verify=False)
        self.assertFalse(http_tls.uses_shared_context(pool))
        self.assertEqual("CERT_NONE", pool.cert_reqs)

    def test_a_bundle_of_its_own_is_still_used(self):
        """REQUESTS_CA_BUNDLE and verify=<path> arrive here as a path; the
        shared context would quietly swap it for certifi's bundle."""
        from requests.utils import DEFAULT_CA_BUNDLE_PATH
        pool = _pool("https://a.example.org/", verify=DEFAULT_CA_BUNDLE_PATH)
        self.assertFalse(http_tls.uses_shared_context(pool))
        self.assertEqual(DEFAULT_CA_BUNDLE_PATH, pool.ca_certs)

    def test_installing_twice_does_not_wrap_twice(self):
        before = HTTPAdapter.cert_verify
        http_tls.install()
        self.assertIs(before, HTTPAdapter.cert_verify)

    def test_the_app_installs_it(self):
        import inspect
        import os
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        self.assertIn("http_tls.install()", inspect.getsource(app))


if __name__ == "__main__":
    unittest.main()
