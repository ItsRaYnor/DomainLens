import unittest
from unittest import mock

import security_checks as s


class CaaCaseSensitivityTests(unittest.TestCase):
    """Regression tests for a real finding in production: a DNS provider's UI
    published CAA tags as "Issue"/"Iodef" (capitalised) instead of lowercase.
    RFC 8659 says tag matching is case-insensitive, but internet.nl (and
    presumably some real CAs) rejected it as missing the required "issue"
    property. DomainLens's old check only looked at whether *any* CAA record
    existed, so it reported "OK" and missed this entirely.
    """

    def _caa_result(self, records):
        with mock.patch("security_checks._resolve") as resolve:
            resolve.return_value = records
            result = {}
            caa = records
            caa_tags = []
            for rec in caa:
                parts = rec.split(None, 2)
                if len(parts) >= 2:
                    caa_tags.append(parts[1])
            result["caa"] = {
                "present": bool(caa),
                "records": caa,
                "has_issue_tag": any(t.lower() == "issue" for t in caa_tags),
                "non_lowercase_tags": sorted({t for t in caa_tags if t != t.lower()}),
            }
            return result["caa"]

    def test_lowercase_issue_tag_recognized(self):
        caa = self._caa_result(['0 issue "letsencrypt.org"'])
        self.assertTrue(caa["has_issue_tag"])
        self.assertEqual(caa["non_lowercase_tags"], [])

    def test_capitalised_issue_tag_flagged_as_non_lowercase(self):
        caa = self._caa_result(['0 Issue "letsencrypt.org"', '0 Iodef "mailto:security@example.com"'])
        # RFC-wise this still counts as a valid issue tag...
        self.assertTrue(caa["has_issue_tag"])
        # ...but we must flag the casing, since real-world validators reject it.
        self.assertEqual(caa["non_lowercase_tags"], ["Iodef", "Issue"])

    def test_no_caa_records_at_all(self):
        caa = self._caa_result([])
        self.assertFalse(caa["present"])
        self.assertFalse(caa["has_issue_tag"])

    def test_caa_present_but_no_issue_tag(self):
        caa = self._caa_result(['0 iodef "mailto:security@example.com"'])
        self.assertTrue(caa["present"])
        self.assertFalse(caa["has_issue_tag"])

    def test_finding_for_missing_caa(self):
        audit = {"dns_mail": {"success": True, "caa": {"present": False, "has_issue_tag": False}}}
        findings = s.audit_findings(audit)
        titles = [f["title"] for f in findings]
        self.assertIn("No CAA record", titles)

    def test_finding_for_caa_present_without_issue_tag(self):
        audit = {"dns_mail": {"success": True, "caa": {
            "present": True, "has_issue_tag": False,
            "records": ['0 iodef "mailto:security@example.com"'],
        }}}
        findings = s.audit_findings(audit)
        titles = [f["title"] for f in findings]
        self.assertIn("CAA record present but missing 'issue' property", titles)

    def test_finding_for_non_lowercase_tags(self):
        audit = {"dns_mail": {"success": True, "caa": {
            "present": True, "has_issue_tag": True,
            "non_lowercase_tags": ["Issue"],
        }}}
        findings = s.audit_findings(audit)
        titles = [f["title"] for f in findings]
        self.assertIn("CAA property tag is not lowercase", titles)

    def test_no_finding_when_caa_correct(self):
        audit = {"dns_mail": {"success": True, "caa": {
            "present": True, "has_issue_tag": True, "non_lowercase_tags": [],
        }}}
        findings = s.audit_findings(audit)
        titles = [f["title"] for f in findings]
        self.assertNotIn("No CAA record", titles)
        self.assertNotIn("CAA record present but missing 'issue' property", titles)
        self.assertNotIn("CAA property tag is not lowercase", titles)


if __name__ == "__main__":
    unittest.main()
