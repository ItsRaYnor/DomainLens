"""Scans put off while DNS does not answer, and a time of day per monitor.

When DNS was down the scanner still ran: every check found nothing, each
"nothing" became a finding, and the domain was rated F for an outage --
of the scanner's own resolver, or of the domain's name servers -- rather
than for anything it had configured. And a monitor ran one interval after
its last run, so a daily scan drifted with every late or manual run and
could not be put at night.
"""

import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from zoneinfo import ZoneInfo

import dns.resolver

import dns_health
import scheduler
from enterprise_harness import EnterpriseAppTestCase

AMS = ZoneInfo("Europe/Amsterdam")


def _ams(*args):
    return datetime(*args, tzinfo=AMS)


class DnsHealthTests(unittest.TestCase):
    def setUp(self):
        dns_health.reset()

    def _check(self, answers):
        def query(name, rdtype):
            if answers(name):
                return True
            raise dns.resolver.LifetimeTimeout()
        with mock.patch.object(dns_health, "_query", side_effect=query):
            return dns_health.check("example.org")["state"]

    def test_a_name_that_answers_on_the_second_try_is_scanned(self):
        self.assertEqual(dns_health.OK, self._check(lambda name: True))

    def test_no_answer_anywhere_is_the_scanners_own_resolver(self):
        self.assertEqual(dns_health.RESOLVER_DOWN, self._check(lambda name: False))

    def test_only_the_domain_silent_is_the_domains_name_servers(self):
        self.assertEqual(dns_health.DOMAIN_DOWN, self._check(lambda name: name != "example.org"))

    def test_nxdomain_is_an_answer(self):
        with mock.patch.object(dns_health.dns.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            self.assertTrue(dns_health._query("example.org", "SOA"))


class ScanRefusedTests(EnterpriseAppTestCase):
    def test_a_scan_without_dns_is_not_run(self):
        app = self.app_module
        with mock.patch.object(app, "_name_exists", return_value=None), \
             mock.patch.object(app.dns_health, "check",
                               return_value={"state": dns_health.RESOLVER_DOWN, "error": "timeout"}), \
             mock.patch.object(app, "_run_checks") as run_checks:
            with self.assertRaises(dns_health.DnsUnavailable):
                app.run_selected_checks("example.org", ["all"])
        run_checks.assert_not_called()

    def test_the_scan_api_says_why_and_stores_no_f(self):
        app = self.app_module
        self.login_as("user")
        with mock.patch.object(app, "_name_exists", return_value=None), \
             mock.patch.object(app.dns_health, "check",
                               return_value={"state": dns_health.DOMAIN_DOWN, "error": "SERVFAIL"}):
            resp = self.client.post("/api/scan", json={"domain": "example.org"})
        self.assertEqual(503, resp.status_code)
        self.assertIn("name servers of example.org do not answer", resp.get_json()["error"])
        self.assertFalse(self.db.latest_scans_by_domain(["example.org"]))


class SchedulerDnsTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        # The scheduler's state is process-wide; other tests read it.
        saved = scheduler.state_snapshot()
        self.addCleanup(lambda: (scheduler._state.clear(), scheduler._state.update(saved)))
        scheduler._note_dns_up()
        self.monitor_id = self.db.create_monitor(name="t", domain="example.org", target="example.org",
                                                 record_type="A", schedule_minutes=1440, checks=["dns"])

    def _run(self, scan, resolver=(True, None)):
        return scheduler.process_due_monitors(
            db=self.db, scan_monitor_fn=scan, notify_fn=lambda *a, **k: None,
            safe_error_fn=str, run_lock=threading.Lock(), resolver_check_fn=lambda: resolver)

    def _due(self):
        self.db.update_monitor(self.monitor_id, next_scan_at=datetime.now(timezone.utc).isoformat())

    def _events(self):
        return [e for e in self.db.list_monitor_events(monitor_id=self.monitor_id, limit=50)]

    def test_with_the_resolver_down_every_scan_waits(self):
        calls = []
        outcome = self._run(lambda m: calls.append(m["id"]), resolver=(False, "timeout"))
        self.assertEqual([], calls)
        self.assertEqual(1, outcome["postponed_dns"])
        monitor = self.db.get_monitor(self.monitor_id)
        self.assertLessEqual(datetime.fromisoformat(monitor["next_scan_at"]), datetime.now(timezone.utc))
        self.assertNotIn("consecutive_failures", (monitor["metadata"].get("scheduler") or {}))
        self.assertEqual([], self._events())
        self.assertIsNotNone(scheduler.state_snapshot()["dns_down_since"])

        self._run(lambda m: {"scan_id": None, "event": {"event_type": "scan_unchanged"}})
        self.assertIsNone(scheduler.state_snapshot()["dns_down_since"])

    def test_a_silent_domain_is_retried_then_reported_once_without_a_scan(self):
        def silent(m):
            raise dns_health.DnsUnavailable(dns_health.DOMAIN_DOWN, m["target"], "SERVFAIL")

        before = datetime.now(timezone.utc)
        self._run(silent)
        monitor = self.db.get_monitor(self.monitor_id)
        retry = datetime.fromisoformat(monitor["next_scan_at"]) - before
        self.assertTrue(timedelta(minutes=14) < retry < timedelta(minutes=16))
        self.assertEqual([], self._events())

        for _ in range(3):
            self._due()
            self._run(silent)
        events = self._events()
        self.assertEqual(["dns_unanswered"], [e["event_type"] for e in events])
        self.assertEqual("medium", events[0]["severity"])
        monitor = self.db.get_monitor(self.monitor_id)
        self.assertGreater(datetime.fromisoformat(monitor["next_scan_at"]) - before, timedelta(hours=23))
        sched = monitor["metadata"].get("scheduler") or {}
        self.assertNotIn("dns_retries", sched)
        self.assertFalse(sched.get("consecutive_failures"))
        self.assertIsNone(monitor["last_scan_id"])


class NextRunTests(unittest.TestCase):
    def _next(self, now, minutes=1440, at="03:00", first=False):
        return scheduler.next_run(minutes, scan_time=at, scan_tz="Europe/Amsterdam",
                                  now=now.astimezone(timezone.utc), first=first).astimezone(AMS)

    def test_without_a_time_it_is_one_interval_on(self):
        now = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)
        self.assertEqual(now + timedelta(minutes=1440), scheduler.next_run(1440, now=now))

    def test_a_daily_scan_stays_at_its_time(self):
        self.assertEqual(_ams(2026, 10, 13, 3, 0), self._next(_ams(2026, 10, 12, 3, 5)))

    def test_a_late_or_manual_run_does_not_move_it(self):
        self.assertEqual(_ams(2026, 10, 13, 3, 0), self._next(_ams(2026, 10, 12, 16, 0)))

    def test_a_new_time_runs_at_its_next_occurrence(self):
        self.assertEqual(_ams(2026, 10, 12, 3, 0), self._next(_ams(2026, 10, 12, 1, 0), first=True))
        self.assertEqual(_ams(2026, 10, 13, 3, 0), self._next(_ams(2026, 10, 12, 16, 0), first=True))

    def test_the_hour_holds_across_the_clock_change(self):
        """Winter time starts on 25 October 2026: 03:00 stays 03:00 local."""
        self.assertEqual(_ams(2026, 10, 25, 3, 0), self._next(_ams(2026, 10, 24, 3, 5)))
        self.assertEqual(_ams(2026, 10, 26, 3, 0), self._next(_ams(2026, 10, 25, 3, 5)))

    def test_weekly_is_a_week_on_at_the_time(self):
        self.assertEqual(_ams(2026, 10, 19, 3, 0), self._next(_ams(2026, 10, 12, 3, 5), minutes=10080))

    def test_shorter_intervals_count_from_the_time(self):
        self.assertEqual(_ams(2026, 10, 12, 14, 0), self._next(_ams(2026, 10, 12, 9, 0), minutes=360, at="02:00"))
        self.assertEqual(_ams(2026, 10, 12, 2, 0), self._next(_ams(2026, 10, 12, 0, 30), minutes=360, at="02:00"))


class MonitorTimeApiTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.login_as("user")
        self.monitor_id = self.db.create_monitor(name="t", domain="example.org", target="example.org",
                                                 record_type="A", schedule_minutes=1440, checks=["dns"])

    def _patch(self, body):
        return self.client.patch(f"/api/monitors/{self.monitor_id}", json=body)

    def test_a_time_moves_the_next_scan_there(self):
        resp = self._patch({"scan_time": "03:00", "scan_tz": "Europe/Amsterdam"})
        self.assertEqual(200, resp.status_code)
        monitor = resp.get_json()["monitor"]
        self.assertEqual(("03:00", "Europe/Amsterdam"), (monitor["scan_time"], monitor["scan_tz"]))
        local = datetime.fromisoformat(monitor["next_scan_at"]).astimezone(AMS)
        self.assertEqual((3, 0), (local.hour, local.minute))
        self.assertLess(datetime.fromisoformat(monitor["next_scan_at"]) - datetime.now(timezone.utc),
                        timedelta(hours=24, minutes=1))

    def test_a_wrong_time_or_zone_is_refused(self):
        self.assertEqual(400, self._patch({"scan_time": "25:00", "scan_tz": "Europe/Amsterdam"}).status_code)
        self.assertEqual(400, self._patch({"scan_time": "03:00", "scan_tz": "Mars/Base"}).status_code)

    def test_an_empty_time_drops_it(self):
        self._patch({"scan_time": "03:00", "scan_tz": "Europe/Amsterdam"})
        monitor = self._patch({"scan_time": ""}).get_json()["monitor"]
        self.assertIsNone(monitor["scan_time"])

    def test_a_new_monitor_with_a_time_takes_its_baseline_then(self):
        resp = self.client.post("/api/monitors", json={"domain": "example.info", "schedule_minutes": 1440,
                                                       "scan_time": "02:30", "scan_tz": "Europe/Amsterdam"})
        self.assertEqual(201, resp.status_code)
        local = datetime.fromisoformat(resp.get_json()["monitor"]["next_scan_at"]).astimezone(AMS)
        self.assertEqual((2, 30), (local.hour, local.minute))

    def test_a_scan_keeps_the_monitor_on_its_time(self):
        app = self.app_module
        self._patch({"scan_time": "03:00", "scan_tz": "Europe/Amsterdam"})
        with mock.patch.object(app, "run_selected_checks", return_value={"dns": {}}):
            app._scan_monitor(self.db.get_monitor(self.monitor_id))
        local = datetime.fromisoformat(self.db.get_monitor(self.monitor_id)["next_scan_at"]).astimezone(AMS)
        self.assertEqual((3, 0), (local.hour, local.minute))


class PlanSlotTests(unittest.TestCase):
    def test_slots_follow_each_other_round_the_clock(self):
        self.assertEqual(["10:00", "10:02", "10:04"], [scheduler.plan_slot("10:00", 2, i) for i in range(3)])
        self.assertEqual("00:01", scheduler.plan_slot("23:59", 2, 1))

    def test_a_later_monitor_takes_the_first_free_time(self):
        self.assertEqual("10:02", scheduler.free_plan_slot("10:00", 2, {"10:00", "10:04"}))


class ScanPlanTests(EnterpriseAppTestCase):
    """Every monitor started at the moment it was made, or all at the hour
    chosen for them; a hundred domains then ran at once. A plan gives each
    its own time, a set number of minutes apart."""

    def setUp(self):
        super().setUp()
        self.login_as("user")
        for name in ("example.org", "example.net", "example.info"):
            self.db.create_monitor(name=name, domain=name, target=name, record_type="A",
                                   schedule_minutes=1440, checks=["all"])

    def _plan(self, start="10:00", spacing=2):
        return self.client.post("/api/monitors/plan", json={
            "start": start, "spacing_minutes": spacing, "scan_tz": "Europe/Amsterdam"})

    def _times(self):
        return {m["target"]: m.get("scan_time") for m in self.db.list_monitors(limit=100)}

    def test_each_monitor_gets_its_own_time(self):
        resp = self._plan()
        self.assertEqual(200, resp.status_code)
        times = self._times()
        self.assertEqual(len(times), len(set(times.values())))
        # Domains alphabetical; the harness's own example.com monitor first.
        self.assertEqual(["10:00", "10:02", "10:04", "10:06"],
                         [times[d] for d in ("example.com", "example.info", "example.net", "example.org")])
        for monitor in self.db.list_monitors(limit=100):
            if monitor["enabled"]:
                local = datetime.fromisoformat(monitor["next_scan_at"]).astimezone(AMS)
                self.assertEqual(monitor["scan_time"], local.strftime("%H:%M"))
            else:
                self.assertIsNone(monitor["next_scan_at"])

    def test_a_monitor_added_later_takes_the_next_free_time(self):
        self._plan()
        taken = set(self._times().values())
        monitor = self.client.post("/api/monitors", json={"domain": "example.edu"}).get_json()["monitor"]
        self.assertNotIn(monitor["scan_time"], taken)
        self.assertEqual(scheduler.free_plan_slot("10:00", 2, taken), monitor["scan_time"])

    def test_a_monitor_from_the_portfolio_takes_one_too(self):
        self._plan()
        self.app_module._set_monitoring(["example.edu"], 1440)
        self.assertIsNotNone(self._times()["example.edu"])

    def test_the_plan_and_its_times_can_be_removed(self):
        self._plan()
        self.assertEqual(200, self.client.delete("/api/monitors/plan").status_code)
        self.assertEqual({None}, set(self._times().values()))
        monitor = self.client.post("/api/monitors", json={"domain": "example.edu"}).get_json()["monitor"]
        self.assertIsNone(monitor["scan_time"])

    def test_the_list_says_how_it_is_planned(self):
        self._plan(spacing=5)
        plan = self.client.get("/api/monitors").get_json()["plan"]
        self.assertEqual(("10:00", 5), (plan["start"], plan["spacing"]))
        self.assertEqual(plan["monitors"], len(self._times()))

    def test_a_wrong_start_is_refused(self):
        self.assertEqual(400, self._plan(start="10").status_code)


class ScreenTests(EnterpriseAppTestCase):
    def test_the_monitor_page_offers_a_time_and_says_when_dns_is_down(self):
        self.login_as("user")
        html = self.client.get("/monitoring").get_data(as_text=True)
        self.assertIn('id="monitorTimeInput"', html)
        self.assertIn('id="planApplyBtn"', html)
        import pathlib
        js = (pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("scheduleBtn.textContent = 'Schedule…';", js)
        self.assertIn("const dnsDown = (scheduler.state || {}).dns_down_since;", js)


if __name__ == "__main__":
    unittest.main()
