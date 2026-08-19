import os
import pathlib
import tempfile
import unittest
from unittest import mock

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

import dns_tools


class RequestValidationTests(unittest.TestCase):
    """A lookup tool on an app that commonly runs without authentication is a
    request-forgery primitive if it accepts a free-form resolver, and a
    command-injection one if it shells out to dig. Neither is offered.
    """

    def test_a_zone_transfer_is_refused(self):
        for rtype in ("AXFR", "IXFR"):
            with self.assertRaises(dns_tools.LookupError_) as ctx:
                dns_tools.query("example.com", rtype)
            self.assertIn("not a supported record type", str(ctx.exception))

    def test_any_is_refused(self):
        # Answered inconsistently by resolvers and mostly used for
        # amplification, so it is not a lookup worth offering.
        with self.assertRaises(dns_tools.LookupError_):
            dns_tools.query("example.com", "ANY")

    def test_an_address_is_not_an_acceptable_resolver(self):
        # This is the one that matters: an address here would let anyone on
        # the LAN probe port 53 on any host this server can reach.
        for value in ("10.0.0.1", "127.0.0.1", "192.168.1.1", "8.8.8.8"):
            with self.assertRaises(dns_tools.LookupError_) as ctx:
                dns_tools.query("example.com", "A", value)
            self.assertIn("Unknown resolver", str(ctx.exception))

    def test_named_resolvers_are_accepted(self):
        for name in dns_tools.RESOLVERS:
            # Validation only; no query is made.
            self.assertEqual(dns_tools._validate("example.com", "A", name)[2], name)

    def test_an_empty_name_is_refused(self):
        with self.assertRaises(dns_tools.LookupError_):
            dns_tools.query("", "A")

    def test_an_overlong_name_is_refused(self):
        with self.assertRaises(dns_tools.LookupError_):
            dns_tools.query("a" * 254, "A")

    def test_a_malformed_name_is_refused(self):
        with self.assertRaises(dns_tools.LookupError_):
            dns_tools.query("a" * 100 + "." + "b" * 100 + "." + "c" * 100, "A")

    def test_a_trailing_dot_is_accepted(self):
        self.assertEqual(dns_tools._validate("example.com.", "A", "system")[0], "example.com")

    def test_the_type_is_case_insensitive(self):
        self.assertEqual(dns_tools._validate("example.com", "txt", "system")[1], "TXT")


class NeverShellsOutTests(unittest.TestCase):

    def test_the_module_does_not_import_subprocess(self):
        source = (pathlib.Path(__file__).resolve().parent.parent
                  / "dns_tools.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "os.system", "popen", "shell=True"):
            self.assertNotIn(forbidden, source, forbidden)


class ResultShapeTests(unittest.TestCase):

    def _response(self, name, rtype, records, ttl=300, ad=True,
                  rcode=dns.rcode.NOERROR):
        query = dns.message.make_query(name, rtype)
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        if ad:
            response.flags |= dns.flags.AD
        if records:
            rrset = dns.rrset.from_text_list(
                name, ttl, "IN", rtype, records)
            response.answer.append(rrset)
        return response

    def test_txt_strings_are_joined_not_escaped(self):
        # to_text() re-quotes and escapes; the record's actual content is what
        # you are checking when you look up an SPF or DKIM value.
        response = self._response("example.com.", "TXT", ['"v=spf1 -all"'])
        with mock.patch("dns.query.udp", return_value=response):
            result = dns_tools.query("example.com", "TXT", "cloudflare")
        self.assertEqual(result["records"], ["v=spf1 -all"])

    def test_ttl_and_timing_are_reported(self):
        response = self._response("example.com.", "A", ["192.0.2.1"], ttl=42)
        with mock.patch("dns.query.udp", return_value=response):
            result = dns_tools.query("example.com", "A", "google")
        self.assertEqual(result["ttl"], 42)
        self.assertIsInstance(result["elapsed_ms"], int)

    def test_dnssec_validation_is_reported(self):
        response = self._response("example.com.", "A", ["192.0.2.1"], ad=True)
        with mock.patch("dns.query.udp", return_value=response):
            self.assertTrue(dns_tools.query("example.com", "A", "quad9")["authenticated"])

    def test_an_unvalidated_answer_is_reported_as_such(self):
        response = self._response("example.com.", "A", ["192.0.2.1"], ad=False)
        with mock.patch("dns.query.udp", return_value=response):
            self.assertFalse(dns_tools.query("example.com", "A", "quad9")["authenticated"])

    def test_nxdomain_is_distinct_from_an_empty_answer(self):
        nx = self._response("nope.example.com.", "A", [], rcode=dns.rcode.NXDOMAIN)
        with mock.patch("dns.query.udp", return_value=nx):
            result = dns_tools.query("nope.example.com", "A", "google")
        self.assertEqual(result["rcode"], "NXDOMAIN")
        self.assertEqual(result["records"], [])

        empty = self._response("example.com.", "AAAA", [])
        with mock.patch("dns.query.udp", return_value=empty):
            result = dns_tools.query("example.com", "AAAA", "google")
        self.assertEqual(result["rcode"], "NOERROR")
        self.assertEqual(result["records"], [])

    def test_a_network_failure_is_an_error_not_an_empty_answer(self):
        with mock.patch("dns.query.udp", side_effect=dns.exception.Timeout()):
            result = dns_tools.query("example.com", "A", "google")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["records"], [])

    def test_the_authoritative_lookup_reports_who_answered(self):
        response = self._response("example.com.", "A", ["192.0.2.1"])
        with mock.patch.object(dns_tools, "_authoritative_addresses",
                               return_value=("example.com", ["192.0.2.53"])), \
             mock.patch("dns.query.udp", return_value=response):
            result = dns_tools.query("example.com", "A", "authoritative")
        self.assertEqual(result["authoritative_zone"], "example.com")
        self.assertEqual(result["nameservers"], ["192.0.2.53"])
        # An authoritative server signs but does not validate, so claiming a
        # validation result from its AD bit would be inventing one.
        self.assertIsNone(result["authenticated"])


class EndpointTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "dns.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        importlib.reload(db_module).init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_a_refused_request_is_a_400_not_a_500(self):
        resp = self.client.get("/api/dns/query?name=example.com&type=AXFR")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("not a supported record type", resp.get_json()["error"])

    def test_an_address_resolver_is_refused_by_the_endpoint(self):
        resp = self.client.get("/api/dns/query?name=example.com&resolver=127.0.0.1")
        self.assertEqual(resp.status_code, 400)

    def test_a_successful_lookup_is_returned(self):
        with mock.patch.object(dns_tools, "query", return_value={"records": ["ok"]}):
            resp = self.client.get("/api/dns/query?name=example.com&type=A")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["records"], ["ok"])

    def test_an_upstream_failure_is_a_502(self):
        with mock.patch.object(dns_tools, "query", side_effect=RuntimeError("boom")):
            resp = self.client.get("/api/dns/query?name=example.com")
        self.assertEqual(resp.status_code, 502)

    def test_the_options_endpoint_lists_what_is_allowed(self):
        data = self.client.get("/api/dns/options").get_json()
        self.assertIn("TXT", data["types"])
        self.assertNotIn("AXFR", data["types"])
        self.assertNotIn("ANY", data["types"])
        self.assertIn("authoritative", data["resolvers"])

    def test_it_is_rate_limited(self):
        with mock.patch.object(self.app_module, "_check_rate_limit", return_value=False):
            resp = self.client.get("/api/dns/query?name=example.com")
        self.assertEqual(resp.status_code, 429)


if __name__ == "__main__":
    unittest.main()


class RateLimitBucketTests(unittest.TestCase):
    """The lookup shared the scan budget: ten per minute, sized for scans that
    run for tens of seconds. A handful of lookups then used up the scan
    allowance, so checking a few records left you unable to start a scan.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "rl.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        importlib.reload(db_module).init_db()
        self.app_module = importlib.reload(app_module)
        self.app_module._rate_store.clear()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_lookups_get_a_larger_budget_than_scans(self):
        scan = self.app_module._rate_limit_settings("scan")
        dns = self.app_module._rate_limit_settings("dns_lookup")
        self.assertGreater(dns["requests"], scan["requests"])

    def test_exhausting_lookups_does_not_block_scanning(self):
        # This is the bug: the two budgets must not be the same pot.
        for _ in range(self.app_module._rate_limit_settings("dns_lookup")["requests"]):
            self.app_module._check_rate_limit("1.2.3.4", bucket="dns_lookup")
        self.assertFalse(self.app_module._check_rate_limit("1.2.3.4", bucket="dns_lookup"))
        self.assertTrue(self.app_module._check_rate_limit("1.2.3.4", bucket="scan"))

    def test_exhausting_scans_does_not_block_lookups(self):
        for _ in range(self.app_module._rate_limit_settings("scan")["requests"]):
            self.app_module._check_rate_limit("1.2.3.4", bucket="scan")
        self.assertFalse(self.app_module._check_rate_limit("1.2.3.4", bucket="scan"))
        self.assertTrue(self.app_module._check_rate_limit("1.2.3.4", bucket="dns_lookup"))

    def test_clients_do_not_share_a_budget(self):
        for _ in range(self.app_module._rate_limit_settings("dns_lookup")["requests"]):
            self.app_module._check_rate_limit("1.2.3.4", bucket="dns_lookup")
        self.assertTrue(self.app_module._check_rate_limit("5.6.7.8", bucket="dns_lookup"))

    def test_the_default_bucket_is_still_the_scan_one(self):
        for _ in range(self.app_module._rate_limit_settings("scan")["requests"]):
            self.app_module._check_rate_limit("9.9.9.9")
        self.assertFalse(self.app_module._check_rate_limit("9.9.9.9"))

    def test_a_dozen_lookups_in_a_row_are_allowed(self):
        client = self.app_module.app.test_client()
        with mock.patch.object(dns_tools, "query", return_value={"records": []}):
            codes = [client.get("/api/dns/query?name=example.com&type=TXT").status_code
                     for _ in range(12)]
        self.assertEqual(set(codes), {200})
