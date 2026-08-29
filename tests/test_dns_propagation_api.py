"""The propagation endpoint inherits the query endpoint's contract: resolvers
are named, never addressed.

That rule is not decoration. This app commonly runs without authentication on
a LAN, so an endpoint that took an address would be a way to aim UDP/53 at any
host the server can reach. Adding a second endpoint is exactly where that
guarantee gets dropped by accident, so it is pinned here.
"""

import os
import tempfile
import unittest
from unittest import mock


class PropagationEndpointTests(unittest.TestCase):
    def setUp(self):
        # ignore_cleanup_errors: sqlite3's `with conn` commits but does not
        # close, so Windows still holds the file when the dir is removed.
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "prop.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        import importlib
        import db
        import app
        from settings.store import get_store
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    def test_an_address_is_refused_as_a_resolver(self):
        """The guarantee this file exists for."""
        resp = self.client.get("/api/dns/propagation?name=example.com&resolver=10.0.0.5")
        self.assertEqual(400, resp.status_code)

    def test_an_unknown_resolver_name_is_refused(self):
        resp = self.client.get("/api/dns/propagation?name=example.com&resolver=nope")
        self.assertEqual(400, resp.status_code)

    def test_repeated_resolver_parameters_are_all_used(self):
        """The UI sends one parameter per ticked box; collapsing them to the
        last one would quietly compare a single resolver against itself."""
        seen = {}

        def fake(name, rtype, resolvers, custom=None):
            seen["resolvers"] = resolvers
            return {"name": name, "type": rtype, "verdict": "propagated",
                    "results": [], "answered": 2, "unreachable": [], "groups": []}

        with mock.patch.object(self.app_module.dns_tools, "propagation", fake):
            resp = self.client.get(
                "/api/dns/propagation?name=example.com&resolver=google&resolver=quad9")
        self.assertEqual(200, resp.status_code)
        self.assertEqual(["google", "quad9"], seen["resolvers"])

    def test_a_comma_separated_list_also_works(self):
        seen = {}

        def fake(name, rtype, resolvers, custom=None):
            seen["resolvers"] = resolvers
            return {"name": name, "type": rtype, "verdict": "propagated",
                    "results": [], "answered": 2, "unreachable": [], "groups": []}

        with mock.patch.object(self.app_module.dns_tools, "propagation", fake):
            self.client.get("/api/dns/propagation?name=example.com&resolvers=google,quad9")
        self.assertEqual(["google", "quad9"], seen["resolvers"])

    def test_the_verdict_reaches_the_caller(self):
        with mock.patch.object(self.app_module.dns_tools, "propagation",
                               return_value={"verdict": "inconsistent", "results": [],
                                             "answered": 2, "unreachable": [],
                                             "groups": [], "name": "example.com",
                                             "type": "A"}):
            body = self.client.get(
                "/api/dns/propagation?name=example.com&resolver=google").get_json()
        self.assertEqual("inconsistent", body["verdict"])

    def test_it_shares_the_dns_lookup_rate_limit(self):
        """Otherwise the cheap endpoint caps lookups while this one, which
        makes several queries per call, runs unmetered."""
        with mock.patch.object(self.app_module, "_check_rate_limit",
                               return_value=False) as limiter:
            resp = self.client.get(
                "/api/dns/propagation?name=example.com&resolver=google")
        self.assertEqual(429, resp.status_code)
        self.assertEqual("dns_lookup", limiter.call_args.kwargs["bucket"])

    def test_configured_custom_resolvers_are_offered_by_the_options_endpoint(self):
        """The checkboxes are built from this list, so a resolver an admin
        configured has to appear here or it can never be ticked."""
        with mock.patch.object(self.app_module, "_scan_config",
                               return_value={"custom_resolvers": ["Office = 10.0.0.1"]}):
            body = self.client.get("/api/dns/options").get_json()
        self.assertIn("office", body["resolvers"])
        self.assertIn("office", body["custom_resolvers"])

    def test_a_broken_custom_resolver_setting_does_not_break_the_page(self):
        """One malformed line in settings must not take DNS lookups down."""
        with mock.patch.object(self.app_module, "_scan_config",
                               side_effect=RuntimeError("settings exploded")):
            resp = self.client.get("/api/dns/options")
        self.assertEqual(200, resp.status_code)


if __name__ == "__main__":
    unittest.main()
