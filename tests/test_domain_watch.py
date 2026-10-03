"""Knowing the moment a wanted domain comes free, and never guessing it.

A .nl domain in SIDN's quarantine showed as "pending delete" with no word on
when it would be released. These tests cover reading that from the registry
answer; following a wanted domain until it comes free is the portfolio's
job now (test_wanted_in_portfolio).
"""

import pathlib
import unittest

import rdap
import whois_batch

ROOT = pathlib.Path(__file__).resolve().parent.parent
_RELEASE = "2026-10-11T00:05:24Z"


class LifecycleTests(unittest.TestCase):
    def test_a_nl_domain_in_quarantine_says_when_it_is_released(self):
        lc = rdap.lifecycle("gone.example.nl", ["pending delete"],
                            {"deletion": "2026-09-01T00:05:24Z", "expiration": _RELEASE})
        self.assertEqual(("quarantine", _RELEASE, 60),
                         (lc["phase"], lc["released_from"], lc["release_window_minutes"]))

    def test_quarantine_is_still_quarantine_when_the_answer_lacks_the_date(self):
        """SIDN's RDAP sometimes answers without the events."""
        lc = rdap.lifecycle("gone.example.nl", ["pending delete"], {})
        self.assertEqual("quarantine", lc["phase"])
        self.assertIsNone(lc["released_from"])

    def test_a_gtld_expiration_is_the_end_of_the_paid_term(self):
        lc = rdap.lifecycle("example.com", ["active"], {"expiration": "2027-08-13T04:00:00Z"})
        self.assertEqual(("registered", "2027-08-13"), (lc["phase"], lc["expires"]))

    def test_a_nl_release_moment_is_not_shown_as_an_expiry_date(self):
        r = rdap.parse({"ldhName": "gone.example.nl", "status": ["pending delete"],
                        "events": [{"eventAction": "expiration", "eventDate": _RELEASE}]},
                       "gone.example.nl")
        self.assertIsNone(r["expires"])
        self.assertEqual(_RELEASE, r["lifecycle"]["released_from"])

    def test_statuses_are_said_in_words(self):
        r = rdap.parse({"ldhName": "gone.example.nl", "status": ["pending delete"]}, "gone.example.nl")
        self.assertEqual(["Being deleted"], r["status_text"])

    def test_the_batch_csv_carries_the_phase_and_release(self):
        row = whois_batch._row("gone.example.nl", {
            "success": True, "status": ["pending delete"],
            "lifecycle": {"phase": "quarantine", "released_from": _RELEASE}})
        self.assertEqual(("quarantine", _RELEASE), (row["phase"], row["released_from"]))


class WhoisViewTests(unittest.TestCase):
    def test_the_view_names_the_abuse_contact_and_the_quarantine(self):
        js = ROOT.joinpath("static", "js", "whois_view.js").read_text(encoding="utf-8")
        self.assertIn("row('Abuse contact', abuse)", js)
        self.assertIn("lifecycleBlock(r) +", js)


if __name__ == "__main__":
    unittest.main()
