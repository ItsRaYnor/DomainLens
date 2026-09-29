"""Knowing the moment a wanted domain comes free, and never guessing it.

A .nl domain in SIDN's quarantine showed as "pending delete" with no word on
when it would be released, and the only way to catch the release was to
look by hand at 02:05. The watchlist looks for you, tighter as the release
comes closer, and tells you once per change. A failed lookup never becomes
"available": that mistake would send someone to buy a domain still taken.
"""

import pathlib
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import rdap
import whois_batch
from enterprise_harness import EnterpriseAppTestCase

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


class WatchTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        import domain_watch
        self.watch = domain_watch
        self.watch.add(["gone.example.nl"])
        self.notified = []

    def _entry(self):
        return self.watch.list_all()[0]

    def _check(self, answer):
        return self.watch.check(self._entry(), fetch=lambda d: answer,
                                notify=lambda *a: self.notified.append(a))

    def _quarantine(self):
        return {"success": True, "status": ["pending delete"], "registered": "1999-08-24",
                "lifecycle": {"phase": "quarantine", "released_from": _RELEASE}}

    def test_the_first_answer_is_a_baseline_not_news(self):
        self._check(self._quarantine())
        self.assertEqual("quarantine", self._entry()["phase"])
        self.assertEqual([], self.notified)

    def test_coming_free_is_told_once(self):
        self._check(self._quarantine())
        self._check({"success": False, "state": "measured", "registered": False})
        self._check({"success": False, "state": "measured", "registered": False})
        self.assertEqual(["available"], [n[1] for n in self.notified])
        self.assertIn("available to register now", self.notified[0][2])

    def test_a_failed_lookup_is_never_available(self):
        self._check(self._quarantine())
        self._check({"success": False, "state": "unmeasured", "error": "timeout"})
        entry = self._entry()
        self.assertEqual(("quarantine", "timeout"), (entry["phase"], entry["last_error"]))
        self.assertEqual([], self.notified)

    def test_a_new_registration_after_release_is_someone_else(self):
        self._check(self._quarantine())
        self._check({"success": True, "status": ["active"], "registered": "2026-10-11",
                     "lifecycle": {"phase": "registered"}})
        self.assertIn("by someone else", self.notified[0][2])

    def test_looked_up_every_minute_in_the_release_hour_only(self):
        entry = dict(self._entry(), phase="quarantine", released_from=_RELEASE)
        release = datetime(2026, 10, 11, 0, 5, 24, tzinfo=timezone.utc)
        entry["last_checked_at"] = (release + timedelta(minutes=9)).isoformat()
        self.assertTrue(self.watch.is_due(entry, release + timedelta(minutes=10)))
        entry["last_checked_at"] = (release - timedelta(days=2, minutes=1)).isoformat()
        self.assertFalse(self.watch.is_due(entry, release - timedelta(days=2)))

    def test_an_analyst_adds_and_removes_a_domain(self):
        self.login_as("user")
        resp = self.client.post("/api/watchlist", json={"text": "free.example.nl\nfree.example.nl"})
        self.assertEqual(["free.example.nl"], resp.get_json()["added"])
        entry = next(w for w in self.watch.list_all() if w["domain"] == "free.example.nl")
        self.assertEqual(200, self.client.delete(f"/api/watchlist/{entry['id']}").status_code)

    def test_a_viewer_can_look_but_not_change_it(self):
        self.login_as("viewer")
        self.assertEqual(200, self.client.get("/api/watchlist").status_code)
        self.assertEqual(403, self.client.post("/api/watchlist", json={"text": "x.example.nl"}).status_code)


if __name__ == "__main__":
    unittest.main()
