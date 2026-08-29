"""The security.txt check answered one question -- is the file there -- and
threw the body away. RFC 9116's Encryption: field points at the PGP key a
researcher needs to send an encrypted report, and nothing looked at it: a
field pointing at a 404, at an HTML page, or at a private key all scored the
same as a working one.

These cover the parsing, the three reporting states, and the SSRF guard on a
URL that comes out of the scanned site's own file.
"""

import unittest
from unittest import mock

import security_checks as s
import security_checks as s_module


PUBLIC_KEY = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
    "mQINBGabcdefBEADdummyarmoureddata\n"
    "-----END PGP PUBLIC KEY BLOCK-----\n"
)

PRIVATE_KEY = (
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n"
    "lQOYBGabcdefBEADdummyarmoureddata\n"
    "-----END PGP PRIVATE KEY BLOCK-----\n"
)


def _resp(body, status=200):
    return mock.Mock(status_code=status, text=body, content=body.encode())


class SecurityTxtParsingTests(unittest.TestCase):
    """RFC 9116 is a flat "Field: value" format, but the details bite: field
    names are case-insensitive, several fields repeat, and a signed file
    wraps the whole thing in a PGP signature.
    """

    def test_fields_are_read_case_insensitively(self):
        parsed = s.parse_security_txt("CONTACT: mailto:a@example.com\n"
                                      "encryption: https://example.com/k.asc\n")
        self.assertEqual(["mailto:a@example.com"], parsed["contact"])
        self.assertEqual(["https://example.com/k.asc"], parsed["encryption"])

    def test_a_repeated_field_keeps_every_value(self):
        """Several Contact: lines are normal and ordered by preference; last
        one winning would silently drop the operator's first choice."""
        parsed = s.parse_security_txt("Contact: mailto:a@example.com\n"
                                      "Contact: tel:+31000000000\n")
        self.assertEqual(["mailto:a@example.com", "tel:+31000000000"],
                         parsed["contact"])

    def test_comments_and_blank_lines_are_ignored(self):
        parsed = s.parse_security_txt("# Contact: mailto:decoy@example.com\n"
                                      "\n"
                                      "Contact: mailto:real@example.com\n")
        self.assertEqual(["mailto:real@example.com"], parsed["contact"])

    def test_a_signed_file_does_not_leak_its_signature_as_fields(self):
        """Signed files are common, and the armour carries "Version:" and
        "Hash:" lines that parse as fields if the wrapper is not skipped."""
        body = ("Contact: mailto:a@example.com\n"
                "-----BEGIN PGP SIGNATURE-----\n"
                "Version: GnuPG v2\n"
                "-----END PGP SIGNATURE-----\n")
        parsed = s.parse_security_txt(body)
        self.assertIn("contact", parsed)
        self.assertNotIn("version", parsed)

    def test_an_empty_body_parses_to_nothing(self):
        for body in (None, "", "   \n\n"):
            with self.subTest(body=body):
                self.assertEqual({}, s.parse_security_txt(body))


class EncryptionKeyStateTests(unittest.TestCase):
    """Measured, could not be measured, and not applicable stay apart. Only
    the first belongs in the findings list: the second is our limitation and
    the third is a choice the RFC allows.
    """

    def test_no_encryption_field_is_not_applicable(self):
        """Encryption: is OPTIONAL. Reporting its absence as a fault would be
        advice the operator has already declined."""
        result = s.check_security_txt_key("Contact: mailto:a@example.com\n")
        self.assertEqual("not_applicable", result["state"])
        self.assertIsNone(result["url"])

    def test_a_served_public_key_is_measured_and_clean(self):
        body = "Contact: mailto:a@example.com\nEncryption: https://example.com/k.asc\n"
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", return_value=_resp(PUBLIC_KEY)):
            result = s.check_security_txt_key(body)
        self.assertEqual("measured", result["state"])
        self.assertTrue(result["armored"])
        self.assertFalse(result["private_key_published"])

    def test_a_key_url_returning_404_is_measured_as_broken(self):
        """A researcher following the field gets nothing. That is a fact
        about the site, not about our ability to look."""
        body = "Encryption: https://example.com/gone.asc\n"
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", return_value=_resp("Not Found", status=404)):
            result = s.check_security_txt_key(body)
        self.assertEqual("measured", result["state"])
        self.assertFalse(result["armored"])
        self.assertIn("404", result["reason"])

    def test_an_html_page_instead_of_a_key_is_not_a_key(self):
        body = "Encryption: https://example.com/k.asc\n"
        page = "<!DOCTYPE html><html><body>Our PGP key page</body></html>"
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", return_value=_resp(page)):
            result = s.check_security_txt_key(body)
        self.assertEqual("measured", result["state"])
        self.assertFalse(result["armored"])

    def test_a_published_private_key_is_recognised_as_such(self):
        """Exporting the wrong half is a real and repeated mistake, and it
        must not read as "a key is present, all good"."""
        body = "Encryption: https://example.com/k.asc\n"
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", return_value=_resp(PRIVATE_KEY)):
            result = s.check_security_txt_key(body)
        self.assertEqual("measured", result["state"])
        self.assertTrue(result["private_key_published"])
        self.assertFalse(result["armored"])

    def test_an_unreachable_key_is_unmeasured_not_a_defect(self):
        """A timeout on our side says nothing about the site. Calling it
        broken would put our own outage into their report."""
        body = "Encryption: https://example.com/k.asc\n"
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=OSError("boom")):
            result = s.check_security_txt_key(body)
        self.assertEqual("unmeasured", result["state"])
        self.assertFalse(result["armored"])

    def test_a_non_http_uri_is_reported_as_not_followed(self):
        """dns: and openpgp4fpr: URIs are legal in RFC 9116. We cannot follow
        them, which is ours to admit, not their failure."""
        body = "Encryption: openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f\n"
        result = s.check_security_txt_key(body)
        self.assertEqual("unmeasured", result["state"])
        self.assertIn("not followed", result["reason"])


class EncryptionUrlSsrfTests(unittest.TestCase):
    """The Encryption: URL is written by whoever controls the scanned site.
    Following it unchecked turns the scanner into a proxy into its own
    network, with cloud metadata endpoints the obvious target.
    """

    def test_a_private_address_is_never_fetched(self):
        body = "Encryption: http://169.254.169.254/latest/meta-data/iam/\n"
        with mock.patch.object(s, "_safe_host", return_value=False) as safe, \
             mock.patch.object(s, "_get") as get:
            result = s.check_security_txt_key(body)
        self.assertTrue(safe.called, "the host was never checked")
        get.assert_not_called()
        self.assertEqual("unmeasured", result["state"])

    def test_the_guard_runs_before_any_request(self):
        """Ordering is the whole protection: checking after the fetch would
        already have made the request."""
        body = "Encryption: http://internal.example/key.asc\n"
        calls = []
        with mock.patch.object(s, "_safe_host",
                               side_effect=lambda h: calls.append("safe") or False), \
             mock.patch.object(s, "_get",
                               side_effect=lambda *a, **k: calls.append("get")):
            s.check_security_txt_key(body)
        self.assertEqual(["safe"], calls)


class FindingsFromTheKeyTests(unittest.TestCase):
    """What actually reaches the operator's list. The states above only
    matter if the findings builder honours them."""

    def _findings(self, key_state):
        audit = {"web_exposure": {
            "success": True, "security_txt": True, "security_txt_key": key_state,
            "cookies": [], "admin_endpoints": [], "sensitive_files": [],
            "cors": {}, "methods": {},
        }}
        return s_module.audit_findings(audit)

    def _key_findings(self, findings):
        return [f for f in findings if "Encryption:" in f["title"]]

    def test_a_published_private_key_is_reported_critical(self):
        findings = self._findings({
            "state": "measured", "private_key_published": True, "armored": False,
            "url": "https://example.com/k.asc", "reason": "private", "encryption_urls": [],
        })
        hits = [f for f in findings if "PRIVATE key" in f["title"]]
        self.assertEqual(1, len(hits), "publishing a private key was not reported")
        self.assertEqual("critical", hits[0]["severity"])

    def test_a_url_that_serves_no_key_is_reported(self):
        findings = self._findings({
            "state": "measured", "private_key_published": False, "armored": False,
            "url": "https://example.com/k.asc", "reason": "Key URL returned HTTP 404",
            "encryption_urls": [],
        })
        self.assertEqual(1, len(self._key_findings(findings)))

    def test_an_unmeasured_key_produces_no_finding(self):
        """Our own failure to reach the URL must never appear as their
        defect -- this is the rule the whole three-state split exists for."""
        findings = self._findings({
            "state": "unmeasured", "private_key_published": False, "armored": False,
            "url": "https://example.com/k.asc", "reason": "Could not fetch the key",
            "encryption_urls": [],
        })
        self.assertEqual([], self._key_findings(findings))

    def test_no_encryption_field_produces_no_finding(self):
        """Encryption: is optional, so its absence is not advice to give."""
        findings = self._findings({
            "state": "not_applicable", "private_key_published": False,
            "armored": False, "url": None, "reason": "No Encryption: field",
            "encryption_urls": [],
        })
        self.assertEqual([], self._key_findings(findings))

    def test_a_working_key_produces_no_finding(self):
        findings = self._findings({
            "state": "measured", "private_key_published": False, "armored": True,
            "url": "https://example.com/k.asc", "reason": "ok", "encryption_urls": [],
        })
        self.assertEqual([], self._key_findings(findings))


if __name__ == "__main__":
    unittest.main()
