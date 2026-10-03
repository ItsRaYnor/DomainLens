"""Wanted domains are portfolio domains with the decision "request or claim".

They were a list of their own next to a portfolio that already had that
decision: two places for the same domains, the wanted ones without units,
contacts or the import. Merged, a wanted domain keeps what the list did
well -- a look every minute around a .nl release, one report when it comes
free, and telling a new holder from the old one restoring it -- and the
list's rows move over once, history and all.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import domain_portfolio
from enterprise_harness import EnterpriseAppTestCase

_RELEASE = "2026-10-11T00:05:24Z"
_NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _quarantine():
    return {"success": True, "source": "rdap", "status": ["pending delete"], "registered": "1999-08-24",
            "registrar": {"name": "Example Registrar"},
            "lifecycle": {"phase": "quarantine", "released_from": _RELEASE}}


def _registered(on):
    return {"success": True, "source": "rdap", "status": ["active"], "registered": on,
            "registrar": {"name": "Example Registrar"}, "lifecycle": {"phase": "registered"}}


_FREE = {"success": False, "state": "measured", "registered": False}


class WantedTestCase(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.added, _ = domain_portfolio.add_wanted(["gone.example.nl"])
        self.notified = []

    def row(self):
        return next(d for d in domain_portfolio.list_all() if d["domain"] == "example.nl")

    def look_up(self, answer):
        domain_portfolio.check(domain_portfolio.raw(self.row()["id"]), fetch=lambda d: answer,
                               notify=lambda *a: self.notified.append(a), now=_NOW)


class BehaviourTests(WantedTestCase):
    def test_a_wanted_domain_is_a_portfolio_domain_to_claim(self):
        self.assertEqual(["example.nl"], self.added)
        self.assertEqual("claim", self.row()["lifecycle"])
        self.assertIn("wanted", self.row()["flags"])

    def test_a_held_domain_is_never_turned_into_a_wanted_one(self):
        entries, _, _ = domain_portfolio.parse_import("example.com")
        domain_portfolio.import_domains(entries)
        added, already = domain_portfolio.add_wanted(["example.com"])
        self.assertEqual(([], ["example.com"]), (added, already))
        self.assertEqual("keep", next(d for d in domain_portfolio.list_all()
                                      if d["domain"] == "example.com")["lifecycle"])

    def test_the_first_answer_is_a_baseline_not_news(self):
        self.look_up(_quarantine())
        self.assertEqual(("quarantine", []), (self.row()["phase"], self.notified))

    def test_coming_free_is_told_once(self):
        self.look_up(_quarantine())
        self.look_up(_FREE)
        self.look_up(_FREE)
        self.assertEqual(1, len(self.notified))
        self.assertIn("can be requested now", self.notified[0][2])
        self.assertIn("claimable", self.row()["flags"])

    def test_a_failed_lookup_is_never_free(self):
        self.look_up(_quarantine())
        self.look_up({"success": False, "state": "unmeasured", "error": "timeout"})
        row = self.row()
        self.assertEqual(("quarantine", "timeout"), (row["phase"], row["last_error"]))
        self.assertNotIn("claimable", row["flags"])
        self.assertEqual([], self.notified)

    def test_registered_after_the_release_is_a_new_holder(self):
        self.look_up(_quarantine())
        self.look_up(_registered("2026-10-11"))
        self.assertIn("by a new holder", self.notified[0][2])
        self.assertEqual("high", self.notified[0][1])

    def test_registered_before_the_release_is_the_holder_restoring_it(self):
        self.look_up(_quarantine())
        self.look_up(_registered("1999-08-24"))
        self.assertIn("restored by the holder", self.notified[0][2])

    def test_looked_up_every_minute_around_the_release_only(self):
        row = dict(domain_portfolio.raw(self.row()["id"]), phase="quarantine", released_from=_RELEASE)
        release = datetime(2026, 10, 11, 0, 5, 24, tzinfo=timezone.utc)
        row["last_checked_at"] = (release + timedelta(minutes=9)).isoformat()
        self.assertTrue(domain_portfolio.is_due(row, release + timedelta(minutes=10)))
        row["last_checked_at"] = (release - timedelta(days=2, minutes=1)).isoformat()
        self.assertFalse(domain_portfolio.is_due(row, release - timedelta(days=2)))
        # A domain you hold in quarantine is not raced for: hourly is enough.
        held = dict(row, lifecycle="keep", last_checked_at=(release + timedelta(minutes=9)).isoformat())
        self.assertFalse(domain_portfolio.is_due(held, release + timedelta(minutes=10)))

    def test_someone_elses_domain_is_not_probed_for_use(self):
        probe = mock.Mock(return_value={"mail": True, "web": True})
        domain_portfolio.check(domain_portfolio.raw(self.row()["id"]), fetch=lambda d: _registered("2001-01-01"),
                               notify=lambda *a: None, now=_NOW, probe=probe)
        # check() drops the probe for a domain to claim, whoever passes one.
        probe.assert_not_called()


class AdoptionTests(EnterpriseAppTestCase):
    """The old list's rows move into the portfolio once."""

    def old_list(self, *rows, events=()):
        with self.db._connect() as conn:
            for domain, phase, released in rows:
                conn.execute("INSERT INTO watched_domains (domain, note, created_at, phase, released_from, "
                             "last_checked_at) VALUES (?, 'wanted for the brand', ?, ?, ?, ?)",
                             (domain, _NOW.isoformat(), phase, released, _NOW.isoformat()))
            for domain, detail in events:
                conn.execute("INSERT INTO watched_domain_events (domain, at, new_phase, detail) "
                             "VALUES (?, ?, 'quarantine', ?)", (domain, _NOW.isoformat(), detail))

    def adopt(self):
        with self.db._connect() as conn:
            domain_portfolio._adopt_watchlist(conn)

    def test_rows_move_with_their_answer_note_and_history(self):
        self.old_list(("example.nl", "quarantine", _RELEASE), ("example.org", "available", None),
                      events=[("example.nl", "example.nl went into quarantine.")])
        self.adopt()
        rows = {d["domain"]: d for d in domain_portfolio.list_all()}
        self.assertEqual(("claim", "quarantine", _RELEASE, "wanted for the brand"),
                         (rows["example.nl"]["lifecycle"], rows["example.nl"]["phase"],
                          rows["example.nl"]["released_from"], rows["example.nl"]["note"]))
        self.assertEqual("not_registered", rows["example.org"]["phase"])
        self.assertIn("claimable", rows["example.org"]["flags"])
        self.assertIn("example.nl went into quarantine.", [e["detail"] for e in domain_portfolio.events()])

    def test_a_removed_domain_is_not_brought_back(self):
        self.old_list(("example.nl", "quarantine", None))
        self.adopt()
        domain_portfolio.remove([next(d["id"] for d in domain_portfolio.list_all())])
        self.adopt()
        self.assertEqual([], domain_portfolio.list_all())

    def test_a_domain_already_held_keeps_its_decision(self):
        entries, _, _ = domain_portfolio.parse_import("example.nl")
        domain_portfolio.import_domains(entries)
        self.old_list(("example.nl", "registered", None))
        self.adopt()
        self.assertEqual(["keep"], [d["lifecycle"] for d in domain_portfolio.list_all()])

    def test_the_old_rows_stay_as_they_were(self):
        """Nothing is deleted: the move is marked, so it can be looked back on."""
        self.old_list(("example.nl", "quarantine", None))
        self.adopt()
        with self.db._connect() as conn:
            row = conn.execute("SELECT * FROM watched_domains").fetchone()
        self.assertEqual("example.nl", row["domain"])
        self.assertIsNotNone(row["moved_to_portfolio_at"])


class ApiTests(EnterpriseAppTestCase):
    def test_the_former_api_adds_lists_and_removes_wanted_domains(self):
        self.login_as("user")
        resp = self.client.post("/api/watchlist", json={"text": "free.example.nl\nfree.example.nl"})
        self.assertEqual((201, ["example.nl"]), (resp.status_code, resp.get_json()["added"]))
        listed = self.client.get("/api/watchlist").get_json()["domains"]
        self.assertEqual(["example.nl"], [d["domain"] for d in listed])
        self.assertEqual(200, self.client.delete(f"/api/watchlist/{listed[0]['id']}").status_code)
        self.assertEqual([], domain_portfolio.list_all())

    def test_a_held_domain_cannot_be_removed_through_the_former_api(self):
        entries, _, _ = domain_portfolio.parse_import("example.com")
        domain_portfolio.import_domains(entries)
        self.login_as("user")
        held = domain_portfolio.list_all()[0]["id"]
        self.assertEqual(404, self.client.delete(f"/api/watchlist/{held}").status_code)

    def test_a_viewer_can_look_but_not_change(self):
        self.login_as("viewer")
        self.assertEqual(200, self.client.get("/api/watchlist").status_code)
        self.assertEqual(403, self.client.post("/api/watchlist", json={"text": "example.nl"}).status_code)

    def test_the_import_can_add_domains_as_wanted(self):
        self.login_as("user")
        resp = self.client.post("/api/portfolio/import", json={"text": "example.nl", "lifecycle": "claim"})
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual("claim", domain_portfolio.list_all()[0]["lifecycle"])
        bad = self.client.post("/api/portfolio/import", json={"text": "example.org", "lifecycle": "sell"})
        self.assertEqual(400, bad.status_code)


class PageTests(EnterpriseAppTestCase):
    def test_the_old_page_opens_the_portfolio_on_its_wanted_domains(self):
        self.login_as("user")
        resp = self.client.get("/monitoring/wanted")
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers["Location"].endswith("/monitoring/domains?flag=wanted"))
        html = self.client.get("/monitoring/domains").get_data(as_text=True)
        self.assertIn('<option value="wanted">', html)
        self.assertIn('id="pfImportLifecycle"', html)
        self.assertNotIn('href="/monitoring/wanted"', self.client.get("/monitoring").get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
