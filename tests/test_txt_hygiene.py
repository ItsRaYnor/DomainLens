import unittest
from unittest import mock

import security_checks as s


def _txt(*values):
    """Build fake TXT rdata objects the way dnspython exposes them."""
    out = []
    for v in values:
        rd = mock.Mock()
        rd.strings = (v.encode("utf-8"),)
        out.append(rd)
    return out


def _chunked_txt(value, size=255):
    """A long TXT record, split into 255-byte strings as DNS requires."""
    raw = value.encode("utf-8")
    rd = mock.Mock()
    rd.strings = tuple(raw[i:i + size] for i in range(0, len(raw), size))
    return [rd]


class TxtHygieneTests(unittest.TestCase):
    """Found on a live domain: both the DMARC and TLS-RPT records ended with
    a literal newline, picked up when the value was pasted into the DNS
    editor. Nothing shows it — the DNS panel renders the record normally and
    dig prints the byte escaped as \\010 — but strict parsers reject the
    record, so the policy silently stops applying. uriports simply showed a
    cross with no explanation.
    """

    def _hygiene(self, values_by_name):
        def fake_resolve(name, rdtype):
            raise AssertionError("should use _resolve_txt_raw")

        def fake_txt(name):
            return values_by_name.get(name, [])

        with mock.patch("security_checks._resolve_txt_raw", side_effect=fake_txt):
            return s.check_txt_hygiene("example.com")

    # --- the reported defect ---

    def test_trailing_newline_is_detected(self):
        result = self._hygiene({
            "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:a@b.com\n"],
        })
        self.assertEqual(len(result["defects"]), 1)
        defect = result["defects"][0]
        self.assertEqual(defect["record"], "DMARC")
        self.assertIn("newline (at the end)", defect["problems"][0])

    def test_every_policy_record_is_covered(self):
        result = self._hygiene({
            "example.com": ["v=spf1 -all\n"],
            "_dmarc.example.com": ["v=DMARC1; p=none\n"],
            "_mta-sts.example.com": ["v=STSv1; id=1\n"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:a@b.com\n"],
        })
        self.assertEqual(
            {d["record"] for d in result["defects"]},
            {"SPF", "DMARC", "MTA-STS", "TLS-RPT"},
        )

    def test_carriage_return_and_tab_are_detected(self):
        result = self._hygiene({
            "_dmarc.example.com": ["v=DMARC1;\tp=reject\r\n"],
        })
        problems = result["defects"][0]["problems"][0]
        self.assertIn("tab", problems)
        self.assertIn("carriage return", problems)
        self.assertIn("newline", problems)

    def test_control_char_in_the_middle_is_located_as_such(self):
        result = self._hygiene({
            "_dmarc.example.com": ["v=DMARC1;\np=reject"],
        })
        self.assertIn("inside the value", result["defects"][0]["problems"][0])

    def test_trailing_whitespace_is_reported_separately(self):
        result = self._hygiene({
            "_dmarc.example.com": ["v=DMARC1; p=reject  "],
        })
        self.assertIn("whitespace", result["defects"][0]["problems"][0])

    # --- no false positives ---

    def test_clean_records_produce_no_defects(self):
        result = self._hygiene({
            "example.com": ["v=spf1 include:_spf.example.net -all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:a@b.com"],
            "_mta-sts.example.com": ["v=STSv1; id=20260812"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:a@b.com"],
        })
        self.assertEqual(result["defects"], [])

    def test_unrelated_apex_txt_records_are_ignored(self):
        # Verification tokens live alongside SPF on the apex and are none of
        # this check's business.
        result = self._hygiene({
            "example.com": [
                "google-site-verification=abc\n",
                "zoho-verification=xyz\n",
                "v=spf1 -all",
            ],
        })
        self.assertEqual(result["defects"], [])

    def test_missing_records_are_not_an_error(self):
        result = self._hygiene({})
        self.assertEqual(result["defects"], [])
        self.assertEqual(result["checked"], [])

    # --- raw fetch behaviour ---

    def test_raw_fetch_exposes_the_byte_that_to_text_would_escape(self):
        with mock.patch.object(s._RESOLVER, "resolve",
                               return_value=_txt("v=DMARC1; p=none\n")):
            values = s._resolve_txt_raw("_dmarc.example.com")
        self.assertTrue(values[0].endswith("\n"))
        self.assertNotIn("\\010", values[0])

    def test_chunked_record_is_joined_before_inspection(self):
        long_value = "v=DMARC1; p=reject; rua=mailto:" + ("a" * 300) + "@b.com"
        with mock.patch.object(s._RESOLVER, "resolve",
                               return_value=_chunked_txt(long_value)):
            values = s._resolve_txt_raw("_dmarc.example.com")
        self.assertEqual(values, [long_value])

    def test_resolution_failure_is_silent(self):
        with mock.patch.object(s._RESOLVER, "resolve", side_effect=Exception("nope")):
            self.assertEqual(s._resolve_txt_raw("_dmarc.example.com"), [])

    # --- findings ---

    def test_finding_explains_the_invisible_failure(self):
        audit = {"dns_mail": {"success": True, "txt_hygiene": {"defects": [{
            "record": "DMARC", "name": "_dmarc.example.com",
            "problems": ["contains newline (at the end)"], "preview": "'...com\\n'",
        }]}}}
        findings = s.audit_findings(audit)
        match = [f for f in findings if "Malformed DMARC" in f["title"]]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0]["severity"], "medium")
        self.assertIn("line break", match[0]["fix"])

    def test_no_finding_when_records_are_clean(self):
        audit = {"dns_mail": {"success": True, "txt_hygiene": {"defects": []}}}
        titles = [f["title"] for f in s.audit_findings(audit)]
        self.assertFalse(any("Malformed" in t for t in titles))


if __name__ == "__main__":
    unittest.main()
