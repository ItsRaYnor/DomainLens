import importlib
import os
import tempfile
import unittest


class TrustedProxyTests(unittest.TestCase):
    """Behind a reverse proxy every request arrives from the proxy's address.
    The rate limiter then treats all users as one client, so one person
    hitting the limit locks everyone out, and request.is_secure is false, so
    the session cookie never gets its Secure flag.

    Trusting X-Forwarded-* unconditionally is the other half of the trap: with
    nothing in front, any client can claim any address and walk past the rate
    limiter. So it is off unless the operator says how many proxies are real.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "proxy.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "DOMAINLENS_TRUSTED_PROXY_HOPS"):
            os.environ.pop(key, None)

    def _app(self, hops=None):
        if hops is None:
            os.environ.pop("DOMAINLENS_TRUSTED_PROXY_HOPS", None)
        else:
            os.environ["DOMAINLENS_TRUSTED_PROXY_HOPS"] = str(hops)
        import db as db_module
        import app as app_module
        importlib.reload(db_module).init_db()
        return importlib.reload(app_module)

    def _seen(self, module, **headers):
        seen = {}

        @module.app.route("/__probe")
        def probe():
            from flask import request
            seen["ip"] = request.remote_addr
            seen["secure"] = request.is_secure
            return "ok"

        module.app.test_client().get("/__probe", headers=headers)
        return seen

    def test_it_is_off_by_default(self):
        module = self._app(hops=None)
        self.assertFalse(module._trusting_proxy)

    def test_a_spoofed_header_is_ignored_when_off(self):
        # The whole point: without a proxy, this header is attacker-controlled.
        module = self._app(hops=None)
        seen = self._seen(module, **{"X-Forwarded-For": "203.0.113.9"})
        self.assertNotEqual(seen["ip"], "203.0.113.9")

    def test_the_real_client_is_used_when_a_proxy_is_declared(self):
        module = self._app(hops=1)
        seen = self._seen(module, **{"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(seen["ip"], "203.0.113.9")

    def test_the_scheme_is_taken_from_the_proxy(self):
        # Without this the app thinks it is on plain HTTP and the session
        # cookie never gets marked Secure.
        module = self._app(hops=1)
        seen = self._seen(module, **{"X-Forwarded-Proto": "https"})
        self.assertTrue(seen["secure"])

    def test_zero_hops_is_the_same_as_unset(self):
        module = self._app(hops=0)
        self.assertFalse(module._trusting_proxy)

    def test_a_nonsense_value_does_not_enable_it(self):
        # Failing open here would silently trust forged headers.
        module = self._app(hops="yes")
        self.assertFalse(module._trusting_proxy)

    def test_a_negative_value_does_not_enable_it(self):
        module = self._app(hops=-1)
        self.assertFalse(module._trusting_proxy)

    def test_only_the_declared_number_of_hops_is_trusted(self):
        # With one proxy declared, only the last entry is the proxy's own
        # view; earlier entries are whatever the client sent.
        module = self._app(hops=1)
        seen = self._seen(module, **{"X-Forwarded-For": "198.51.100.7, 203.0.113.9"})
        self.assertEqual(seen["ip"], "203.0.113.9")


if __name__ == "__main__":
    unittest.main()
