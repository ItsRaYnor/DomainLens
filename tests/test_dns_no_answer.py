"""A domain whose name servers do not answer says so, instead of "not measured".

Dozens of registered domains stood on "use not measured" with no reason
given. Every DNS question for them ended in SERVFAIL: the name servers the
registry delegates them to did not answer at all, so the domains resolved
nowhere -- no web, no mail -- and if those name servers' own domain ever
lapsed, someone else could take over their DNS. That is a finding about the
domain, not a gap in the measurement, and it is now reported as one; a
failure on our side (the delegation itself unreadable) still is not.
"""

import unittest
from datetime import datetime, timezone
from unittest import mock

import domain_portfolio
from enterprise_harness import EnterpriseAppTestCase

_NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def _servfail(name, rtype):
    return {"records": [], "rcode": "SERVFAIL", "error": None}


def _answer(name, rtype):
    return {"records": ["192.0.2.1"] if rtype == "A" else [], "rcode": "NOERROR", "error": None}


class ProbeTests(unittest.TestCase):
    def test_no_answer_anywhere_and_a_silent_delegation_is_a_finding(self):
        found = domain_portfolio.probe_usage("example.nl", _servfail, delegation=lambda d: False)
        self.assertEqual({"mail": None, "web": None, "dns": "no_answer"}, found)

    def test_no_answer_from_the_resolver_but_one_from_the_name_servers_stays_unknown(self):
        """Then the failure was ours (or DNSSEC), not the domain's."""
        found = domain_portfolio.probe_usage("example.nl", _servfail, delegation=lambda d: True)
        self.assertIsNone(found["dns"])

    def test_an_unreadable_delegation_stays_unknown(self):
        found = domain_portfolio.probe_usage("example.nl", _servfail, delegation=lambda d: None)
        self.assertIsNone(found["dns"])

    def test_the_delegation_is_only_checked_when_nothing_answered(self):
        delegation = mock.Mock()
        found = domain_portfolio.probe_usage("example.nl", _answer, delegation=delegation)
        delegation.assert_not_called()
        self.assertEqual(("ok", True), (found["dns"], found["web"]))


def _registered():
    return {"success": True, "source": "rdap", "status": ["active"],
            "registrar": {"name": "Example Registrar"}, "lifecycle": {"phase": "registered"}}


class PortfolioTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        entries, _, _ = domain_portfolio.parse_import("example.nl")
        domain_portfolio.import_domains(entries)
        self.notified = []

    def row(self):
        return domain_portfolio.list_all()[0]

    def look_up(self, dns):
        domain_portfolio.check(domain_portfolio.raw(self.row()["id"]), fetch=lambda d: _registered(),
                               notify=lambda *a: self.notified.append(a), now=_NOW,
                               probe=lambda d: {"mail": None, "web": None, "dns": dns}
                               if dns == "no_answer" else {"mail": False, "web": True, "dns": dns})

    def test_the_finding_is_stored_flagged_and_not_counted_as_use_unknown(self):
        self.look_up("no_answer")
        row = self.row()
        self.assertEqual("no_answer", row["dns_state"])
        self.assertIn("dns_dead", row["flags"])
        self.assertNotIn("use_unmeasured", row["flags"])
        totals = domain_portfolio.summary(domain_portfolio.list_all(), domain_portfolio.list_groups())["total"]
        self.assertEqual((1, 0), (totals["dns_dead"], totals["use_unmeasured"]))

    def test_name_servers_going_silent_is_reported_once_and_coming_back_too(self):
        self.look_up("ok")                  # baseline
        self.look_up("no_answer")
        self.look_up("no_answer")
        self.look_up("ok")
        self.assertEqual(["high", "medium"], [n[1] for n in self.notified])
        self.assertIn("do not answer", self.notified[0][2])
        self.assertIn("answer again", self.notified[1][2])

    def test_the_first_measurement_is_a_baseline(self):
        self.look_up("no_answer")
        self.assertEqual([], self.notified)

    def test_a_domain_being_cancelled_raises_no_alarm_about_it(self):
        self.look_up("ok")
        domain_portfolio.set_lifecycle([self.row()["id"]], "cancel")
        self.look_up("no_answer")
        self.assertEqual([], self.notified)
        self.assertNotIn("dns_dead", self.row()["flags"])

    def test_the_csv_says_it(self):
        self.look_up("no_answer")
        lines = domain_portfolio.to_csv(domain_portfolio.list_all()).splitlines()
        values = dict(zip(lines[0].split(","), lines[1].split(",")))
        self.assertEqual("no_answer", values["dns"])


if __name__ == "__main__":
    unittest.main()
