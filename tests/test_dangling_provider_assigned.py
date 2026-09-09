import os
import tempfile
import unittest
from unittest import mock

import security_checks


class ProviderAssignedClassificationTests(unittest.TestCase):
    """A dangling CNAME to an AWS ELB or CloudFront name was reported as
    possibly claimable, which turned a stale-record cleanup into a false
    takeover report: the provider-assigned suffix cannot be re-registered by a
    third party, so "claimable" was never true for these targets.
    """

    def test_elb_name_is_provider_assigned(self):
        entry = security_checks.provider_assigned(
            "k8s-default-appingress-a1b2c3d4e5-1234567890.eu-central-1.elb.amazonaws.com")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["provider"], "AWS Elastic Load Balancing")

    def test_cloudfront_name_is_provider_assigned(self):
        self.assertIsNotNone(security_checks.provider_assigned("d111111abcdef8.cloudfront.net."))

    def test_unknown_provider_is_not_ruled_out(self):
        # None means "claimability untested", not "ruled out" — the two must
        # not be conflated, so an unrecognised host returns None rather than a
        # falsy entry that would read as provider-assigned.
        self.assertIsNone(security_checks.provider_assigned("app.example.net"))


class DanglingCheckClassifiesTargetTests(unittest.TestCase):
    def _run(self, cname):
        with mock.patch.object(security_checks, "_resolve", return_value=[cname]), \
             mock.patch.object(security_checks, "_is_nxdomain", return_value=True):
            return security_checks._check_one_takeover("chat.example.com")

    def test_provider_assigned_dangling_is_not_registrable(self):
        result = self._run("k8s-x-1234567890.eu-central-1.elb.amazonaws.com")
        self.assertEqual(result["kind"], "dangling")
        self.assertFalse(result["registrable"])
        self.assertEqual(result["provider"], "AWS Elastic Load Balancing")
        self.assertEqual(result["confidence"], "low")

    def test_unknown_provider_dangling_stays_untested(self):
        result = self._run("gone.some-obscure-host.example")
        self.assertEqual(result["kind"], "dangling")
        self.assertIsNone(result["registrable"])
        self.assertIsNone(result["provider"])
        self.assertEqual(result["confidence"], "medium")


class DanglingFindingWordingTests(unittest.TestCase):
    def _finding_for(self, dangling):
        findings = security_checks.audit_findings({"subdomains": {"dangling": [dangling]}})
        self.assertEqual(len(findings), 1)
        return findings[0]

    def test_provider_assigned_finding_does_not_claim_it_is_claimable(self):
        finding = self._finding_for({
            "subdomain": "chat.example.com",
            "cname": "k8s-x-1234567890.eu-central-1.elb.amazonaws.com",
            "registrable": False,
            "provider": "AWS Elastic Load Balancing",
            "provider_note": "the ELB DNS name carries an AWS-allocated suffix that cannot be requested",
        })
        self.assertEqual(finding["severity"], "low")
        self.assertIn("not a claimable takeover", finding["detail"])
        self.assertNotIn("may be claimable", finding["detail"])

    def test_unknown_provider_finding_keeps_the_claimable_caveat(self):
        finding = self._finding_for({
            "subdomain": "chat.example.com",
            "cname": "gone.some-obscure-host.example",
            "registrable": None,
            "provider": None,
        })
        self.assertEqual(finding["severity"], "medium")
        self.assertIn("may be claimable", finding["detail"])


class DnsOptionsExposesProviderAssignedTests(unittest.TestCase):
    """The lookup page labels a dangling CNAME as stale-not-claimable from the
    provider list, so the list must reach the client through /api/dns/options
    rather than being duplicated in JS where it would drift.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "opt.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["AUTH_REQUIRE_LOGIN"] = "0"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        import importlib
        import auth
        import db
        import app
        self.auth = importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "AUTH_REQUIRE_LOGIN", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    def test_options_lists_elb_as_provider_assigned(self):
        payload = self.client.get("/api/dns/options").get_json()
        suffixes = {p["suffix"]: p["provider"] for p in payload.get("provider_assigned", [])}
        self.assertIn(".elb.amazonaws.com", suffixes)
        self.assertEqual(suffixes[".elb.amazonaws.com"], "AWS Elastic Load Balancing")


if __name__ == "__main__":
    unittest.main()
