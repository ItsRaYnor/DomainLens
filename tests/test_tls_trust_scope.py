"""A certificate the scanner could not verify is not graded T for the site.

Seen from a container behind TLS inspection: every site scanned got TLS grade
T, "Poor TLS grade" as a critical finding and a red SSL Valid tile. The
certificate that answered was the inspection device's, chained to a root the
container does not have. The verification failure was recorded only as "not
trusted", its reason dropped, and the error text itself said "Not measured".

OpenSSL says why verification failed. Expired, not yet valid, self-signed
and issued for another name are faults of the certificate wherever the
scanner stands; those stay T, with the reason. A chain that could not be
built to a trusted root is what inspection, a scanner without CA
certificates and a server without its intermediate all produce: not
measured, with the issuer of what answered named so the operator can tell.
"""

import pathlib
import ssl
import unittest
from unittest import mock

import recommendations
from enterprise_harness import EnterpriseAppTestCase

JS = (pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "app.js").read_text(encoding="utf-8")

INSPECTED = {"issuer": "Example Inspection CA", "subject": "example.com", "san": ["example.com"]}


def _verify_error(code, message):
    exc = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message}")
    exc.verify_code = code
    exc.verify_message = message
    return exc


class _AppTests(EnterpriseAppTestCase):
    def failure(self, code, message):
        with mock.patch.object(self.app_module, "_presented_certificate", return_value=INSPECTED):
            return self.app_module._cert_verify_failure(_verify_error(code, message), "example.com")


class WhoseFaultTests(_AppTests):
    def test_a_chain_to_an_unknown_root_is_not_measured_and_names_the_issuer(self):
        cert = self.failure(19, "self-signed certificate in certificate chain")
        self.assertIsNone(cert["trusted"])
        self.assertEqual("unverified", cert["trust_scope"])
        self.assertIn("Example Inspection CA", cert["error"])
        self.assertIn("Not measured", cert["error"])

    def test_a_missing_local_issuer_is_not_measured_either(self):
        self.assertEqual("unverified", self.failure(20, "unable to get local issuer certificate")["trust_scope"])

    def test_faults_of_the_certificate_itself_stay_untrusted(self):
        for code, message in ((10, "certificate has expired"), (18, "self-signed certificate"),
                              (62, "Hostname mismatch")):
            cert = self.failure(code, message)
            self.assertIs(False, cert["trusted"], message)
            self.assertIn(message, cert["error"])


class GradeTests(_AppTests):
    def test_an_unverifiable_chain_gets_no_grade_rather_than_t(self):
        cert = self.failure(20, "unable to get local issuer certificate")
        grade, warnings = self.app_module._calculate_tls_grade([], [], cert, False, False, None)
        self.assertIsNone(grade)
        self.assertEqual(["Certificate could not be verified from this scanner: "
                          "unable to get local issuer certificate"], warnings)

    def test_an_expired_certificate_is_still_t_and_says_why(self):
        cert = self.failure(10, "certificate has expired")
        grade, warnings = self.app_module._calculate_tls_grade([], [], cert, False, False, None)
        self.assertEqual("T", grade)
        self.assertEqual(["Certificate not trusted: certificate has expired"], warnings)

    def test_the_certificate_check_reports_the_reason_too(self):
        """check_ssl dropped the reason the same way, and SSL Valid went red."""
        context = mock.Mock()
        context.wrap_socket.side_effect = _verify_error(19, "self-signed certificate in certificate chain")
        with mock.patch.object(self.app_module.ssl, "create_default_context", return_value=context), \
             mock.patch.object(self.app_module, "_presented_certificate", return_value=INSPECTED):
            result = self.app_module.check_ssl("example.com")
        self.assertEqual("unverified", result["trust_scope"])
        self.assertEqual(INSPECTED, result["presented"])


class AdviceTests(unittest.TestCase):
    def _scan(self, certificate, grade):
        return {"domain": "example.com",
                "tls_deep": {"success": True, "grade": grade, "certificate": certificate, "protocols": [
                    {"name": "TLS 1.2", "supported": True}, {"name": "TLS 1.3", "supported": True}]}}

    def test_no_critical_finding_for_a_certificate_the_scanner_could_not_verify(self):
        certificate = {"success": False, "trusted": None, "trust_scope": "unverified",
                       "verify_reason": "unable to get local issuer certificate",
                       "presented": INSPECTED, "error": "could not be verified from this scanner"}
        recs = recommendations.generate(self._scan(certificate, None))
        titles = [r["title"] for r in recs]
        self.assertFalse([t for t in titles if "Poor TLS grade" in t], titles)
        item = next(r for r in recs if r["title"] == "Certificate could not be verified from this scanner")
        self.assertEqual("info", item["severity"])
        self.assertIn("Presented certificate issued by: Example Inspection CA", item["evidence"])

    def test_a_t_grade_names_the_reason_in_what_was_measured(self):
        certificate = {"success": False, "trusted": False, "trust_scope": "certificate",
                       "verify_reason": "certificate has expired", "presented": INSPECTED}
        recs = recommendations.generate(self._scan(certificate, "T"))
        poor = next(r for r in recs if "Poor TLS grade" in r["title"])
        self.assertIn("Verification: certificate has expired", poor["evidence"])


class TileTests(unittest.TestCase):
    def test_no_grade_and_no_connection_are_not_shown_as_fail(self):
        self.assertIn("state: data.tls_deep && !data.tls_deep.grade ? 'not_tested' : undefined", JS)
        self.assertIn("state: data.ssl && !data.ssl.success && data.ssl.trusted !== false ? 'not_tested' : undefined", JS)

    def test_the_certificate_card_shows_what_answered(self):
        self.assertIn("const cls = data && data.trusted === false ? 'status-fail' : 'status-warn';", JS)
        self.assertIn("<tr><th>Presented by</th>", JS)


if __name__ == "__main__":
    unittest.main()
