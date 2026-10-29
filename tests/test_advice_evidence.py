"""Each advice item carries what the scan measured, not only what to change.

"Weak cipher suites accepted" said to restrict the cipher list and that the
weak ones "include RC4, 3DES, DES, NULL or EXPORT" -- while the suites the
scan had found were CBC suites with SHA-1, none of those. The operator had
no way to check the claim from the advice, or to hand the server team a
list, without going through two tables on another tab that disagreed with
each other. Every item now names the result it came from and the measured
lines it rests on.
"""

import unittest

import recommendations
from enterprise_harness import EnterpriseAppTestCase


def _cipher(name, protocol, strength, fs):
    return {"name": name, "protocol": protocol, "bits": 128, "strength": strength, "forward_secrecy": fs}


def _ncsc_cipher(name, level, label, **parts):
    return {"name": name, "level": level, "label": label, "protocol": "TLSv1.2",
            "components": {k: {"name": v[0], "level": v[1]} for k, v in parts.items()}}


TLS = {
    "success": True, "grade": "B",
    "protocols": [{"name": "TLS 1.2", "supported": True}, {"name": "TLS 1.3", "supported": True}],
    "ciphers": [
        _cipher("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", "strong", True),
        _cipher("ECDHE-RSA-AES128-SHA", "TLSv1.0", "weak", True),
        _cipher("AES128-SHA256", "TLSv1.2", "acceptable", False),
    ],
    "cipher_summary": {"total": 3, "strong": 1, "acceptable": 1, "weak": 1, "insecure": 0, "forward_secrecy": 2},
    "hsts": {"enabled": False, "blocked": False, "checked_url": "https://example.com/", "status_code": 200, "value": ""},
}
NCSC = {
    "success": True,
    "ciphers": [
        _ncsc_cipher("ECDHE-RSA-AES128-GCM-SHA256", "sufficient", "Sufficient"),
        _ncsc_cipher("ECDHE-RSA-AES128-SHA", "insufficient", "Insufficient", hash=("SHA-1", "insufficient")),
        _ncsc_cipher("AES128-SHA256", "insufficient", "Insufficient",
                     key_exchange=("RSA", "insufficient"), bulk_encryption=("AES-128-CBC", "phased_out")),
        _ncsc_cipher("ECDHE-RSA-AES128-SHA256", "phased_out", "To be phased out",
                     bulk_encryption=("AES-128-CBC", "phased_out")),
    ],
    "findings": [
        {"id": "cipher-insufficient", "severity": "high", "title": "2 insufficient cipher suite(s)",
         "problem": "Insufficient suites accepted.", "fix": "Remove them."},
        {"id": "cipher-phased-out", "severity": "medium", "title": "1 cipher suite(s) to be phased out",
         "problem": "Phase-out suites accepted.", "fix": "Plan their removal."},
    ],
}


def _scan(**extra):
    base = {"domain": "example.com", "tls_deep": TLS, "ncsc_tls": NCSC}
    base.update(extra)
    return base


def _item(recs, words):
    return next(r for r in recs if words in r["title"].lower())


class WhereEachItemComesFromTests(unittest.TestCase):
    def test_every_item_names_the_result_it_was_drawn_from(self):
        """Without it the page cannot lead from an item to its measurement."""
        results = _scan(mta_sts={"state": "measured", "found": False})
        for rec in recommendations.generate(results):
            self.assertTrue(rec.get("sources"), rec["title"])
            for source in rec["sources"]:
                self.assertIn(source, results, rec["title"])

    def test_an_item_two_checks_agree_on_names_both(self):
        """The TLS scan and the NCSC assessment both flag the weak suites;
        they are one item, and either one's output is evidence for it."""
        weak = _item(recommendations.generate(_scan()), "weak cipher")
        self.assertEqual(["tls_deep", "ncsc_tls"], weak["sources"])
        self.assertEqual("cipher-insufficient", weak["check"])


class WhatTheScanMeasuredTests(unittest.TestCase):
    def test_the_weak_suites_are_named_with_both_verdicts(self):
        """Including AES128-SHA256: "acceptable" to the TLS scan but
        Insufficient to the NCSC for its RSA key exchange, which the
        advice follows."""
        lines = _item(recommendations.generate(_scan()), "weak cipher")["evidence"]
        self.assertEqual(2, len(lines))
        self.assertIn("ECDHE-RSA-AES128-SHA", lines[0])
        self.assertIn("SHA-1 hash", lines[0])
        self.assertIn("AES128-SHA256", lines[1])
        self.assertIn("acceptable", lines[1])
        self.assertIn("RSA key exchange", lines[1])

    def test_the_weak_suite_advice_no_longer_names_ciphers_that_were_not_found(self):
        problem = _item(recommendations.generate(_scan()), "weak cipher")["problem"]
        self.assertNotIn("These include RC4", problem)
        self.assertIn("SHA-1", problem)

    def test_suites_to_phase_out_are_named(self):
        lines = _item(recommendations.generate(_scan()), "phased out")["evidence"]
        self.assertEqual(1, len(lines))
        self.assertIn("ECDHE-RSA-AES128-SHA256", lines[0])

    def test_suites_without_forward_secrecy_are_named(self):
        lines = _item(recommendations.generate(_scan()), "forward secrecy")["evidence"]
        self.assertEqual(["AES128-SHA256 · TLSv1.2 · no forward secrecy"], lines)

    def test_a_missing_hsts_header_says_where_it_was_looked_for(self):
        lines = _item(recommendations.generate(_scan()), "hsts")["evidence"]
        self.assertEqual(["Checked https://example.com/ (HTTP 200)",
                          "Strict-Transport-Security: not sent"], lines)

    def test_the_header_item_lists_the_headers_it_counts(self):
        """"8 security headers missing" listed 10: CSP and HSTS have items
        of their own and are not in the count."""
        headers = {"success": True, "final_url": "https://example.com/", "status_code": 200,
                   "headers_found": {}, "headers_missing": [
                       "Strict-Transport-Security", "Content-Security-Policy",
                       "X-Content-Type-Options", "Referrer-Policy"]}
        recs = recommendations.generate({"domain": "example.com", "http_headers": headers})
        item = _item(recs, "security headers missing")
        self.assertTrue(item["title"].startswith("2 "))
        self.assertIn("Not sent: X-Content-Type-Options, Referrer-Policy", item["evidence"])

    def test_a_missing_record_names_where_it_was_looked_up(self):
        recs = recommendations.generate({"domain": "example.com",
                                         "dns": {"MX": ["10 mx.example.com."]},
                                         "mta_sts": {"state": "measured", "found": False}})
        self.assertEqual(["No MTA-STS record at _mta-sts.example.com"],
                         _item(recs, "mta-sts")["evidence"])

    def test_nothing_measured_gives_no_line_rather_than_an_invented_none(self):
        """A TLS scan that failed has no suites to name. The item, if any,
        must not read as though the scan found an empty list."""
        recs = recommendations.generate({"domain": "example.com", "tls_deep": {"success": False},
                                         "ncsc_tls": NCSC})
        weak = _item(recs, "insufficient cipher")
        self.assertTrue(all("ECDHE" in l or "AES" in l for l in weak["evidence"]))
        for rec in recs:
            for line in rec.get("evidence") or []:
                self.assertNotIn(": none", line)


class StoredScansTests(EnterpriseAppTestCase):
    def test_a_scan_saved_before_this_shows_the_measurement_when_opened(self):
        """The stored list had no sources or evidence; it is drawn again on
        reading, as the posture already was."""
        self.login_as("viewer")
        results = _scan()
        results["recommendations"] = [{"severity": "high", "category": "TLS",
                                       "title": "Weak cipher suites accepted",
                                       "problem": "old", "fix": "old", "retest": "old"}]
        scan_id = self.db.save_scan("example.com", results)
        data = self.client.get(f"/api/history/{scan_id}").get_json()["data"]
        weak = _item(data["recommendations"], "weak cipher")
        self.assertEqual(["tls_deep", "ncsc_tls"], weak["sources"])
        self.assertTrue(weak["evidence"])


if __name__ == "__main__":
    unittest.main()
