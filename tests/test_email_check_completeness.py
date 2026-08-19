import os
import unittest
from unittest import mock


class EmailCheckCompletenessTests(unittest.TestCase):
    """Regression tests for a completeness sweep of the email/DNS checks,
    triggered by the CAA bug (a check that only verified
    *presence* of a record, not whether it actually did anything). The same
    shallow pattern existed in SPF, DMARC, DKIM and MTA-STS: each treated
    "a record exists" as "this is configured correctly", missing several
    real RFC-defined failure modes.
    """

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        cls.app = app

    # --- SPF: multiple records is a PermError (RFC 7208 SS3.2) ---

    def test_spf_single_record_strict_passes(self):
        with mock.patch("app._resolve", return_value=['"v=spf1 include:_spf.example.com -all"']):
            result = self.app.check_spf("example.com")
        self.assertTrue(result["found"])
        self.assertTrue(result["pass"])
        self.assertFalse(result["multiple_records"])

    def test_spf_multiple_records_fails_even_if_individually_strict(self):
        with mock.patch("app._resolve", return_value=[
            '"v=spf1 -all"', '"v=spf1 include:_spf.example.com -all"',
        ]):
            result = self.app.check_spf("example.com")
        self.assertTrue(result["found"])
        self.assertTrue(result["multiple_records"])
        self.assertFalse(result["pass"])

    # --- DMARC: multiple records means DMARC is ignored (RFC 7489 SS6.6.3) ---

    def test_dmarc_single_reject_passes(self):
        with mock.patch("app._resolve", return_value=['"v=DMARC1; p=reject; rua=mailto:a@example.com"']):
            result = self.app.check_dmarc("example.com")
        self.assertTrue(result["pass"])
        self.assertFalse(result["multiple_records"])

    def test_dmarc_multiple_records_fails(self):
        with mock.patch("app._resolve", return_value=[
            '"v=DMARC1; p=reject"', '"v=DMARC1; p=reject; rua=mailto:a@example.com"',
        ]):
            result = self.app.check_dmarc("example.com")
        self.assertTrue(result["multiple_records"])
        self.assertFalse(result["pass"])

    # --- DKIM: revoked keys and non-DKIM TXT records at the selector name ---

    def test_dkim_active_key_passes(self):
        with mock.patch("app._resolve", return_value=['"v=DKIM1; k=rsa; p=MIIByourkey"']):
            result = self.app.check_dkim("example.com", selectors=["default"])
        self.assertTrue(result["found"])
        self.assertTrue(result["pass"])
        self.assertFalse(result["selectors"][0]["revoked"])

    def test_dkim_revoked_key_not_counted_as_passing(self):
        # RFC 6376 SS3.6.1: an empty p= tag means the key was revoked.
        with mock.patch("app._resolve", return_value=['"v=DKIM1; k=rsa; p="']):
            result = self.app.check_dkim("example.com", selectors=["default"])
        self.assertTrue(result["found"])  # a record exists...
        self.assertFalse(result["pass"])  # ...but it doesn't work
        self.assertTrue(result["selectors"][0]["revoked"])

    def test_dkim_unrelated_txt_record_not_counted(self):
        # Some other verification TXT record happens to live at this name —
        # it has no p= tag, so it isn't a DKIM key record at all.
        with mock.patch("app._resolve", return_value=['"some-other-verification-token=abc123"']):
            result = self.app.check_dkim("example.com", selectors=["default"])
        self.assertFalse(result["found"])
        self.assertFalse(result["pass"])
        self.assertEqual(result["selectors"], [])

    # --- MTA-STS: DNS record present is not the same as a reachable policy ---

    def _dns_record_response(self, status_code, text, headers=None):
        resp = mock.Mock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        return resp

    def test_mta_sts_no_dns_record(self):
        with mock.patch("app._resolve", return_value=[]):
            result = self.app.check_mta_sts("example.com")
        self.assertFalse(result["found"])
        self.assertFalse(result["pass"])

    def test_mta_sts_dns_ok_but_policy_unreachable(self):
        with mock.patch("app._resolve", return_value=['"v=STSv1; id=123"']), \
             mock.patch("app._http_request", side_effect=Exception("connection refused")):
            result = self.app.check_mta_sts("example.com")
        self.assertTrue(result["found"])
        self.assertFalse(result["policy_reachable"])
        self.assertFalse(result["pass"])

    def test_mta_sts_dns_ok_policy_reachable_and_valid(self):
        body = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"
        with mock.patch("app._resolve", return_value=['"v=STSv1; id=123"']), \
             mock.patch("app._http_request", return_value=self._dns_record_response(200, body)):
            result = self.app.check_mta_sts("example.com")
        self.assertTrue(result["policy_reachable"])
        self.assertTrue(result["policy_valid"])
        self.assertTrue(result["pass"])
        self.assertEqual(result["policy_mode"], "enforce")

    def test_mta_sts_dns_ok_policy_reachable_but_malformed(self):
        body = "not a real policy file"
        with mock.patch("app._resolve", return_value=['"v=STSv1; id=123"']), \
             mock.patch("app._http_request", return_value=self._dns_record_response(200, body)):
            result = self.app.check_mta_sts("example.com")
        self.assertTrue(result["policy_reachable"])
        self.assertFalse(result["policy_valid"])
        self.assertFalse(result["pass"])

    def test_mta_sts_dns_ok_policy_404(self):
        with mock.patch("app._resolve", return_value=['"v=STSv1; id=123"']), \
             mock.patch("app._http_request", return_value=self._dns_record_response(404, "not found")):
            result = self.app.check_mta_sts("example.com")
        self.assertFalse(result["policy_reachable"])
        self.assertFalse(result["pass"])

    # --- TLS-RPT: a record without rua= requests nothing (RFC 8460 SS3) ---

    def test_tlsrpt_with_rua_passes(self):
        with mock.patch("app._resolve", return_value=['"v=TLSRPTv1; rua=mailto:tls@example.com"']):
            result = self.app.check_tlsrpt("example.com")
        self.assertTrue(result["pass"])
        self.assertTrue(result["has_rua"])

    def test_tlsrpt_without_rua_fails(self):
        with mock.patch("app._resolve", return_value=['"v=TLSRPTv1"']):
            result = self.app.check_tlsrpt("example.com")
        self.assertTrue(result["found"])
        self.assertFalse(result["has_rua"])
        self.assertFalse(result["pass"])


if __name__ == "__main__":
    unittest.main()
