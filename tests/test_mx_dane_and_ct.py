"""DANE on the mail hosts, and certificates that CAA did not permit.

DANE on port 443 was the only TLSA lookup, and it was made on the domain
itself. That is the deployment nobody has: the record that matters lives at
_25._tcp on each mail exchanger, it is what internet.nl scores, and looking
it up on the domain reports every mail domain as missing it.

CAA says who *may* issue. It is consulted only at issuance, so it can look
correct while a certificate exists that nobody asked for. The CT logs answer
the other half, and they were already being fetched for subdomain
enumeration.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import cert_transparency as ct
import recommendations
import security_checks as s


NOW = datetime(2026, 9, 4, tzinfo=timezone.utc)
RECENT = (NOW - timedelta(days=3)).isoformat()
OLD = (NOW - timedelta(days=200)).isoformat()


def _fake_finding(severity, category, title, detail, evidence="", fix=""):
    return {"severity": severity, "category": category, "title": title}


def _cert(issuer, when=RECENT, serial="1"):
    return {"issuer_name": issuer, "not_before": when, "serial_number": serial}


class CaaParsingTests(unittest.TestCase):
    def test_issue_properties_are_collected(self):
        allowed = ct.caa_allowed_issuers([
            '0 issue "letsencrypt.org"', '0 issue "pki.goog"',
            '0 iodef "mailto:a@example.com"'])
        self.assertEqual({"letsencrypt.org", "pki.goog"}, allowed)

    def test_no_caa_means_any_authority_may_issue(self):
        """None, not an empty set: "no restriction" and "no CA at all" are
        opposite instructions and must not collapse into one value."""
        self.assertIsNone(ct.caa_allowed_issuers([]))
        self.assertIsNone(ct.caa_allowed_issuers(['0 iodef "mailto:a@example.com"']))

    def test_issue_semicolon_means_no_authority_may_issue(self):
        self.assertEqual(set(), ct.caa_allowed_issuers(['0 issue ";"']))

    def test_parameters_after_the_identifier_are_dropped(self):
        allowed = ct.caa_allowed_issuers(
            ['0 issue "letsencrypt.org; validationmethods=dns-01"'])
        self.assertEqual({"letsencrypt.org"}, allowed)


class UnexpectedIssuanceTests(unittest.TestCase):
    CAA = ['0 issue "letsencrypt.org"']

    def test_an_issuer_outside_caa_is_reported(self):
        result = ct.analyse([_cert("C=US, O=DigiCert Inc, CN=X")], self.CAA, now=NOW)
        self.assertEqual(1, len(result["unexpected"]))
        self.assertEqual("digicert.com", result["unexpected"][0]["caa_identifier"])

    def test_an_allowed_issuer_is_not_reported(self):
        result = ct.analyse([_cert("C=US, O=Let's Encrypt, CN=R11")], self.CAA, now=NOW)
        self.assertEqual([], result["unexpected"])

    def test_an_unknown_issuer_is_unrecognised_not_a_violation(self):
        """The second false alarm is the one that gets a check ignored. An
        issuer we cannot map is a gap in our table, not their problem."""
        result = ct.analyse([_cert("CN=Some Obscure CA Ltd")], self.CAA, now=NOW)
        self.assertEqual([], result["unexpected"])
        self.assertEqual(["CN=Some Obscure CA Ltd"], result["unrecognised_issuers"])

    def test_an_unrecognised_issuer_is_coverage_not_a_finding(self):
        """A missing local issuer mapping is not a defect of the domain."""
        result = ct.analyse([_cert("CN=Some Obscure CA Ltd")], self.CAA, now=NOW)
        self.assertEqual([], ct.findings(result, _fake_finding))
        self.assertEqual(["CN=Some Obscure CA Ltd"], result["unrecognised_issuers"])

    def test_certificates_outside_the_window_are_ignored(self):
        result = ct.analyse([_cert("C=US, O=DigiCert Inc", when=OLD)], self.CAA,
                            days=30, now=NOW)
        self.assertEqual([], result["recent"])
        self.assertEqual([], result["unexpected"])

    def test_without_caa_nothing_can_be_unexpected(self):
        """A domain that has made no restriction is not failing to keep one."""
        result = ct.analyse([_cert("C=US, O=DigiCert Inc")], [], now=NOW)
        self.assertEqual([], result["unexpected"])
        self.assertIn("any authority may issue", result["reason"])

    def test_duplicate_serials_are_counted_once(self):
        rows = [_cert("C=US, O=Let's Encrypt", serial="dup"),
                _cert("C=US, O=Let's Encrypt", serial="dup")]
        result = ct.analyse(rows, self.CAA, now=NOW)
        self.assertEqual(1, len(result["recent"]))

    def test_a_crtsh_outage_is_unmeasured_not_clean(self):
        """Reporting "no unexpected certificates" when the log could not be
        read is a clean bill of health nobody established."""
        result = ct.analyse(None, self.CAA, source_error="crt.sh outage")
        self.assertEqual("unmeasured", result["state"])
        self.assertEqual([], ct.findings(result, _fake_finding))


class MxDaneTests(unittest.TestCase):
    def test_a_host_with_tlsa_is_recorded_as_protected(self):
        def resolve(name, rdtype):
            if rdtype == "MX":
                return ["10 mx1.example.com."]
            if name == "_25._tcp.mx1.example.com":
                return ["3 1 1 abcdef"]
            return []
        with mock.patch.object(s, "_resolve", side_effect=resolve):
            result = s._check_mx_dane("example.com")
        self.assertEqual("measured", result["state"])
        self.assertEqual(1, result["with_dane"])
        self.assertEqual(0, result["without_dane"])

    def test_a_host_without_tlsa_is_recorded_as_missing(self):
        def resolve(name, rdtype):
            return ["10 mx1.example.com."] if rdtype == "MX" else []
        with mock.patch.object(s, "_resolve", side_effect=resolve):
            result = s._check_mx_dane("example.com")
        self.assertEqual(1, result["without_dane"])

    def test_the_record_is_looked_up_per_mail_host_not_on_the_domain(self):
        """The bug this replaces: _443._tcp on the domain reports every mail
        domain as missing DANE, because that is not where it lives."""
        seen = []

        def resolve(name, rdtype):
            seen.append((name, rdtype))
            return ["10 mx1.example.com."] if rdtype == "MX" else []
        with mock.patch.object(s, "_resolve", side_effect=resolve):
            s._check_mx_dane("example.com")
        self.assertIn(("_25._tcp.mx1.example.com", "TLSA"), seen)

    def test_no_mx_uses_the_rfc5321_implicit_mail_host(self):
        """Without MX, SMTP delivery falls back to the domain's A/AAAA."""
        seen = []

        def resolve(name, rdtype):
            seen.append((name, rdtype))
            return []

        with mock.patch.object(s, "_resolve", side_effect=resolve):
            result = s._check_mx_dane("example.com")
        self.assertEqual("measured", result["state"])
        self.assertTrue(result["implicit_mx"])
        self.assertIn(("_25._tcp.example.com", "TLSA"), seen)

    def test_a_null_mx_is_not_applicable_either(self):
        def resolve(name, rdtype):
            return ["0 ."] if rdtype == "MX" else []
        with mock.patch.object(s, "_resolve", side_effect=resolve):
            result = s._check_mx_dane("example.com")
        self.assertEqual("not_applicable", result["state"])
        self.assertIn("receives no mail", result["reason"])

    def test_partial_coverage_is_reported_as_its_own_case(self):
        """A sender reaching the unprotected host gets no verification, which
        is the same as having none -- but the fix reads differently."""
        dm = {"success": True, "caa": {"has_issue_tag": True}, "mx_dane": {
            "state": "measured", "with_dane": 1, "without_dane": 1,
            "hosts": [{"host": "mx1", "present": True},
                      {"host": "mx2", "present": False}]}}
        titles = [f["title"] for f in s.audit_findings({"dns_mail": dm})]
        self.assertTrue(any("some mail hosts" in t for t in titles), titles)

    def test_full_coverage_produces_no_finding(self):
        dm = {"success": True, "caa": {"has_issue_tag": True}, "mx_dane": {
            "state": "measured", "with_dane": 2, "without_dane": 0,
            "hosts": [{"host": "mx1", "present": True},
                      {"host": "mx2", "present": True}]}}
        titles = [f["title"] for f in s.audit_findings({"dns_mail": dm})]
        self.assertFalse(any("DANE" in t for t in titles), titles)

    def test_hosted_mx_without_tlsa_is_informational(self):
        """Only Zoho can publish below zoho.eu; telling its customer to add
        that TLSA record would turn a provider gap into an impossible fix."""
        dm = {"success": True, "caa": {"has_issue_tag": True}, "mx_dane": {
            "state": "measured", "with_dane": 0, "without_dane": 3,
            "domain": "example.com",
            "hosts": [
                {"host": "mx.zoho.eu", "present": False, "in_zone": False},
                {"host": "mx2.zoho.eu", "present": False, "in_zone": False},
                {"host": "mx3.zoho.eu", "present": False, "in_zone": False},
            ]}}
        dane = [f for f in s.audit_findings({"dns_mail": dm})
                if "DANE" in f["title"] or "TLSA" in f["title"]]
        self.assertEqual(1, len(dane), dane)
        self.assertEqual("info", dane[0]["severity"])
        self.assertNotIn("Publish a TLSA", dane[0].get("fix", ""))

        advice = recommendations._mx_dane_advice({
            "domain": "example.com",
            "security": {"dns_mail": dm},
        })
        self.assertEqual("info", advice[0]["severity"])
        self.assertNotIn("Publish a TLSA", advice[0]["fix"])

    def test_in_zone_mx_without_tlsa_remains_actionable(self):
        dm = {"success": True, "caa": {"has_issue_tag": True}, "mx_dane": {
            "state": "measured", "with_dane": 0, "without_dane": 1,
            "domain": "example.com",
            "hosts": [
                {"host": "mail.example.com", "present": False, "in_zone": True},
            ]}}
        dane = [f for f in s.audit_findings({"dns_mail": dm})
                if "DANE" in f["title"]]
        self.assertEqual("medium", dane[0]["severity"])
        self.assertIn("Publish a TLSA", dane[0]["fix"])

    def test_measurement_records_zone_ownership(self):
        def resolve(name, rdtype):
            if rdtype == "MX":
                return ["10 mail.example.com.", "20 mx.zoho.eu."]
            return []

        with mock.patch.object(s, "_resolve", side_effect=resolve):
            result = s._check_mx_dane("example.com")

        ownership = {h["host"]: h["in_zone"] for h in result["hosts"]}
        self.assertTrue(ownership["mail.example.com"])
        self.assertFalse(ownership["mx.zoho.eu"])

    def test_tlsa_timeout_is_unmeasured_not_missing(self):
        """A resolver failure must never become an actionable no-DANE verdict."""
        def resolve(name, rdtype):
            if rdtype == "MX":
                return ["10 mail.example.com."]
            return s._DnsRecords(state="unmeasured", error="timeout")

        with mock.patch.object(s, "_resolve", side_effect=resolve):
            result = s._check_mx_dane("example.com")

        self.assertEqual("unmeasured", result["state"])
        findings = s.audit_findings({"dns_mail": {
            "success": True,
            "caa": {"state": "measured", "has_issue_tag": True},
            "mx_dane": result,
        }})
        self.assertFalse(any("DANE" in f["title"] for f in findings), findings)

    def test_generate_emits_dane_only_once(self):
        dm = {"success": True, "caa": {"has_issue_tag": True}, "mx_dane": {
            "state": "measured", "with_dane": 0, "without_dane": 1,
            "domain": "example.com",
            "hosts": [{"host": "mail.example.com", "present": False, "in_zone": True}],
        }}
        audit_findings = s.audit_findings({"dns_mail": dm})
        findings = recommendations.generate({
            "domain": "example.com",
            "security": {"dns_mail": dm, "findings": audit_findings},
        })
        self.assertEqual(1, sum("DANE" in f["title"] for f in findings), findings)


if __name__ == "__main__":
    unittest.main()
