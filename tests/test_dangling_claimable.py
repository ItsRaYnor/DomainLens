"""Whether a dangling CNAME can really be claimed.

Every dangling CNAME to an azurewebsites.net name was reported as a
possible takeover, and the DNS lookup page said only that it "depends on
the provider". Two questions decide it, both documented by the providers:

- can someone else create the target name again? Not an App Service
  "secure unique default hostname" (<app>-<16-char hash>.<region>-NN...),
  a Front Door Standard/Premium endpoint, a hashed public IP label, an S3
  bucket in an account regional namespace, or an AWS-assigned id;
- would the provider then serve the name from it? Not App Service when the
  TXT record asuid.<name> holds the owner's domain verification ID; without
  it Microsoft accepts the CNAME alone.
"""

import unittest
from unittest import mock

import security_checks as s
from enterprise_harness import EnterpriseAppTestCase


class OnlyTheOwnerCanCreateTests(unittest.TestCase):
    def assertAssigned(self, host, provider):
        entry = s.provider_assigned(host)
        self.assertIsNotNone(entry, host)
        self.assertEqual(provider, entry["provider"])

    def test_names_with_a_hash_or_an_assigned_id(self):
        self.assertAssigned("app-a6gqaeashthkhkeu.westeurope-01.azurewebsites.net", "Azure App Service")
        self.assertAssigned("app-a6gqaeashthkhkeu.scm.westeurope-01.azurewebsites.net", "Azure App Service")
        self.assertAssigned("app-mdjf2jfgjf82mnzx.z01.azurefd.net", "Azure Front Door")
        self.assertAssigned("app.fjdng2acavhkevd8.westeurope.cloudapp.azure.com", "Azure public IP")
        self.assertAssigned("media-123456789012-eu-west-1-an.s3-website-eu-west-1.amazonaws.com", "AWS S3")
        self.assertAssigned("main.d1m7bkiki6tdw1.amplifyapp.com", "AWS Amplify")
        self.assertAssigned("a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com", "AWS API Gateway")
        self.assertAssigned("abcdefgh12.eu-west-1.awsapprunner.com", "AWS App Runner")

    def test_names_the_customer_chooses_are_not(self):
        for host in ("app.azurewebsites.net", "app.azurefd.net", "app.westeurope.cloudapp.azure.com",
                     "media.s3-website-eu-west-1.amazonaws.com", "app.eu-west-1.elasticbeanstalk.com"):
            self.assertIsNone(s.provider_assigned(host), host)


class ClassifyTests(unittest.TestCase):
    def _classify(self, cname, asuid):
        def resolve(name, rdtype):
            if rdtype == "TXT" and name.startswith("asuid."):
                return asuid
            return []
        with mock.patch.object(s, "_resolve", side_effect=resolve):
            return s.classify_dangling("app.example.org", cname)

    def test_app_service_with_its_verification_record_is_stale_not_claimable(self):
        verdict = self._classify("gone-app.azurewebsites.net", s._DnsRecords(['"5F3A0C9E2B7D41A8C6E9F0B2D4A61C8E3F5B7D9A1C2E4F6A8B0D2C4E6F8A0B1C"']))
        self.assertEqual(("dangling", False, "low"), (verdict["kind"], verdict["registrable"], verdict["confidence"]))
        self.assertIn("asuid.app.example.org", verdict["provider_note"])

    def test_app_service_without_it_is_a_takeover(self):
        verdict = self._classify("gone-app.azurewebsites.net", s._DnsRecords())
        self.assertEqual(("takeover", "Azure App Service", "medium"),
                         (verdict["kind"], verdict["service"], verdict["confidence"]))
        self.assertIn("no domain verification ID in TXT asuid.app.example.org", verdict["note"])

    def test_an_unchecked_verification_record_is_said_so(self):
        verdict = self._classify("gone-app.azurewebsites.net", s._DnsRecords(state="unmeasured"))
        self.assertEqual("takeover", verdict["kind"])
        self.assertIn("could not be checked", verdict["note"])

    def test_a_wildcard_txt_record_is_not_a_verification_id(self):
        """A zone with "*  TXT v=spf1 -all" answers for asuid.<name> too."""
        verdict = self._classify("gone-app.azurewebsites.net", s._DnsRecords(['"v=spf1 -all"']))
        self.assertEqual("takeover", verdict["kind"])

    def test_a_unique_default_hostname_is_stale_whatever_the_record(self):
        verdict = self._classify("gone-app-a6gqaeashthkhkeu.westeurope-01.azurewebsites.net", s._DnsRecords())
        self.assertEqual(("dangling", False), (verdict["kind"], verdict["registrable"]))

    def test_a_released_beanstalk_prefix_is_a_takeover(self):
        verdict = self._classify("gone-app.eu-west-1.elasticbeanstalk.com", s._DnsRecords())
        self.assertEqual(("takeover", "AWS Elastic Beanstalk"), (verdict["kind"], verdict["service"]))

    def test_the_finding_says_why(self):
        verdict = self._classify("gone-app.azurewebsites.net", s._DnsRecords())
        finding = s.audit_findings({"subdomains": {"takeovers": [verdict]}})[0]
        self.assertIn("no domain verification ID in TXT asuid.app.example.org", finding["detail"])


class LookupPageTests(EnterpriseAppTestCase):
    def test_the_lookup_page_gets_the_same_verdict(self):
        self.login_as("user")
        app = self.app_module
        resolve = lambda name, rdtype: (["gone-app.azurewebsites.net."] if rdtype == "CNAME"
                                        else s._DnsRecords())
        with mock.patch.object(app.security_checks, "_resolve", side_effect=resolve), \
             mock.patch.object(app.security_checks, "_is_nxdomain", return_value=True):
            data = self.client.get("/api/dns/dangling?name=app.example.org").get_json()
        self.assertTrue(data["dangling"])
        self.assertEqual("takeover", data["verdict"]["kind"])

    def test_the_page_asks_the_server(self):
        import pathlib
        js = (pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "lookup.js").read_text(encoding="utf-8")
        self.assertIn("fetch('/api/dns/dangling?name=' + encodeURIComponent(name))", js)
        self.assertNotIn("claimability depends on whether the provider", js)


if __name__ == "__main__":
    unittest.main()
