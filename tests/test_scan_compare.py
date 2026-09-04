"""Naming what changed between two scans, not just that something did.

Monitoring hashes a set of tracked sections and raises an event when the hash
moves. Unless the change is one of a handful it names outright, the event
reads "Observed changes for example.com" -- which sends an operator off to
diff two reports by eye. SPF going from -all to ~all landed in exactly that
bucket: the record still exists, still parses, still passes a presence check.

The hard part is not comparing, it is deciding what counts. A deep diff of
two payloads reports something every time -- TTLs count down, certificates
lose a day, elapsed_ms never repeats -- and a report full of that is one
nobody reads.
"""

import os
import tempfile
import unittest

import scan_diff


class SpfWeakeningTests(unittest.TestCase):
    """The change this was asked for."""

    def test_hard_fail_to_soft_fail_is_named_and_judged(self):
        before = {"spf": {"found": True, "record": "v=spf1 mx -all", "strict": True}}
        after = {"spf": {"found": True, "record": "v=spf1 mx ~all", "strict": False}}
        result = scan_diff.compare(before, after)
        qualifier = [c for c in result["changes"] if c["key"] == "all"][0]
        self.assertEqual("-all (hard fail)", qualifier["before"])
        self.assertEqual("~all (soft fail)", qualifier["after"])
        self.assertEqual(scan_diff.WORSE, qualifier["direction"])

    def test_soft_fail_to_hard_fail_is_an_improvement(self):
        before = {"spf": {"found": True, "record": "v=spf1 mx ~all"}}
        after = {"spf": {"found": True, "record": "v=spf1 mx -all"}}
        qualifier = [c for c in scan_diff.compare(before, after)["changes"]
                     if c["key"] == "all"][0]
        self.assertEqual(scan_diff.BETTER, qualifier["direction"])

    def test_plus_all_is_named_for_what_it_does(self):
        """+all accepts any sender; an operator reading "changed" would not
        know that is the worst possible value."""
        before = {"spf": {"found": True, "record": "v=spf1 mx -all"}}
        after = {"spf": {"found": True, "record": "v=spf1 mx +all"}}
        qualifier = [c for c in scan_diff.compare(before, after)["changes"]
                     if c["key"] == "all"][0]
        self.assertIn("accepts any sender", qualifier["after"])
        self.assertEqual(scan_diff.WORSE, qualifier["direction"])

    def test_a_record_edit_that_keeps_the_qualifier_is_not_an_spf_weakening(self):
        """Adding an include is a change to the record, but the all mechanism
        is what decides how a receiver treats a forgery."""
        before = {"spf": {"found": True, "record": "v=spf1 mx -all"}}
        after = {"spf": {"found": True, "record": "v=spf1 mx include:_spf.example.com -all"}}
        keys = [c["key"] for c in scan_diff.compare(before, after)["changes"]]
        self.assertNotIn("all", keys)


class DirectionTests(unittest.TestCase):
    """A verdict is only claimed where one value is genuinely preferable."""

    def test_dmarc_policy_is_ordered_by_what_it_asks_receivers_to_do(self):
        worse = scan_diff.compare({"dmarc": {"policy": "reject"}},
                                  {"dmarc": {"policy": "none"}})["changes"][0]
        self.assertEqual(scan_diff.WORSE, worse["direction"])
        better = scan_diff.compare({"dmarc": {"policy": "none"}},
                                   {"dmarc": {"policy": "quarantine"}})["changes"][0]
        self.assertEqual(scan_diff.BETTER, better["direction"])

    def test_tls_grade_regression_is_judged(self):
        change = scan_diff.compare({"tls_deep": {"grade": "A+"}},
                                   {"tls_deep": {"grade": "C"}})["changes"][0]
        self.assertEqual(scan_diff.WORSE, change["direction"])

    def test_an_unknown_grade_gets_no_verdict_rather_than_a_wrong_one(self):
        change = scan_diff.compare({"tls_deep": {"grade": "A"}},
                                   {"tls_deep": {"grade": "??"}})["changes"][0]
        self.assertEqual(scan_diff.NEUTRAL, change["direction"])

    def test_losing_dnssec_is_worse_and_gaining_it_is_better(self):
        self.assertEqual(scan_diff.WORSE, scan_diff.compare(
            {"dnssec": {"signed": True}}, {"dnssec": {"signed": False}}
        )["changes"][0]["direction"])
        self.assertEqual(scan_diff.BETTER, scan_diff.compare(
            {"dnssec": {"signed": False}}, {"dnssec": {"signed": True}}
        )["changes"][0]["direction"])

    def test_a_blacklist_listing_is_worse(self):
        change = scan_diff.compare({"blacklist": {"is_listed": False}},
                                   {"blacklist": {"is_listed": True}})["changes"][0]
        self.assertEqual(scan_diff.WORSE, change["direction"])


class NoiseTests(unittest.TestCase):
    """What must NOT show up. A comparison that reports something after every
    scan is one people stop opening."""

    def test_a_ticking_certificate_clock_is_not_a_change(self):
        """days_until_expiry moves every day without anything happening. The
        expiry date itself is what changes when a certificate is renewed."""
        before = {"ssl": {"not_after": "2027-01-05T23:59:59+00:00", "days_until_expiry": 130}}
        after = {"ssl": {"not_after": "2027-01-05T23:59:59+00:00", "days_until_expiry": 129}}
        self.assertEqual([], scan_diff.compare(before, after)["changes"])

    def test_a_renewed_certificate_is_a_change(self):
        before = {"ssl": {"not_after": "2027-01-05T23:59:59+00:00"}}
        after = {"ssl": {"not_after": "2028-01-05T23:59:59+00:00"}}
        self.assertEqual(1, len(scan_diff.compare(before, after)["changes"]))

    def test_identical_payloads_report_nothing(self):
        payload = {"spf": {"found": True, "record": "v=spf1 -all", "strict": True},
                   "dmarc": {"found": True, "policy": "reject"},
                   "tls_deep": {"grade": "A", "protocols": []}}
        result = scan_diff.compare(payload, dict(payload))
        self.assertFalse(result["changed"])
        self.assertEqual([], result["changes"])

    def test_untracked_fields_are_ignored(self):
        """elapsed_ms and friends differ on every scan and mean nothing here."""
        before = {"spf": {"found": True, "elapsed_ms": 12, "record": "v=spf1 -all"}}
        after = {"spf": {"found": True, "elapsed_ms": 340, "record": "v=spf1 -all"}}
        self.assertEqual([], scan_diff.compare(before, after)["changes"])

    def test_header_order_is_not_a_change(self):
        """The set of missing headers matters; the order the scan happened to
        list them in does not."""
        before = {"http_headers": {"headers_missing": ["CSP", "Permissions-Policy"]}}
        after = {"http_headers": {"headers_missing": ["Permissions-Policy", "CSP"]}}
        self.assertEqual([], scan_diff.compare(before, after)["changes"])


class UnmeasuredTests(unittest.TestCase):
    """A check that did not run is not a value that changed. The two look
    identical in the data and mean opposite things to whoever reads it."""

    def test_a_check_absent_from_one_side_is_unmeasured_not_a_change(self):
        before = {"spf": {"found": True, "record": "v=spf1 -all"}}
        after = {}
        result = scan_diff.compare(before, after)
        self.assertEqual([], result["changes"])
        self.assertTrue(result["unmeasured"])
        self.assertIn("later scan", result["unmeasured"][0]["reason"])

    def test_a_check_added_later_is_unmeasured_too(self):
        result = scan_diff.compare({}, {"dnssec": {"signed": True}})
        self.assertEqual([], result["changes"])
        self.assertIn("earlier scan", result["unmeasured"][0]["reason"])

    def test_a_check_missing_from_both_sides_is_silent(self):
        """Nothing to say about a check neither scan ran."""
        result = scan_diff.compare({"spf": {"found": True}}, {"spf": {"found": True}})
        self.assertEqual([], result["unmeasured"])

    def test_a_broken_section_does_not_invent_a_difference(self):
        """A section that is not a dict cannot be read; reporting it as a
        change from a value to nothing would be a fault of ours."""
        result = scan_diff.compare({"ssl": "not a dict"}, {"ssl": "still not a dict"})
        self.assertEqual([], result["changes"])


class SummaryTests(unittest.TestCase):
    def test_the_summary_counts_each_direction(self):
        before = {"spf": {"found": True, "record": "v=spf1 -all", "strict": True},
                  "dnssec": {"signed": False}}
        after = {"spf": {"found": True, "record": "v=spf1 ~all", "strict": False},
                 "dnssec": {"signed": True}}
        summary = scan_diff.compare(before, after)["summary"]
        self.assertEqual(3, summary["total"])
        self.assertEqual(2, summary["worse"])
        self.assertEqual(1, summary["better"])

    def test_the_catalogue_lists_the_fields_the_ui_can_filter_on(self):
        catalogue = scan_diff.field_catalogue()
        ids = {f["id"] for f in catalogue}
        self.assertIn("spf.all", ids)
        self.assertIn("dmarc.policy", ids)
        for field in catalogue:
            self.assertTrue(field["label"], f"{field['id']} has no readable label")


class ComparePeriodEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "cmp.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        import importlib
        import db
        import app
        from settings.store import get_store
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)
        self.tempdir.cleanup()

    def _add(self, domain, created_at, payload):
        import json
        with self.db._lock, self.db._connect() as conn:
            conn.execute(
                "INSERT INTO scans (domain, created_at, grade, score, issues_count, data)"
                " VALUES (?,?,?,?,?,?)",
                (domain, created_at, "A", 80, 0, json.dumps(payload)))

    def _compare(self, domain="example.com"):
        return self.client.get(
            f"/api/reporting/compare?domain={domain}"
            "&a_from=2026-05-01&a_to=2026-05-31"
            "&b_from=2026-08-01&b_to=2026-08-31").get_json()

    def test_each_period_resolves_to_its_most_recent_scan(self):
        """"How did it look in May" means how it was left, so a change made
        mid-period shows in the period it happened."""
        self._add("example.com", "2026-05-02T10:00:00+00:00", {"dmarc": {"policy": "none"}})
        self._add("example.com", "2026-05-28T10:00:00+00:00", {"dmarc": {"policy": "reject"}})
        self._add("example.com", "2026-08-15T10:00:00+00:00", {"dmarc": {"policy": "none"}})
        body = self._compare()
        self.assertEqual("2026-05-28T10:00:00+00:00", body["a"]["created_at"])
        change = body["changes"][0]
        self.assertEqual("reject", change["before"])
        self.assertEqual("none", change["after"])

    def test_a_scan_late_on_the_final_day_is_still_inside_the_period(self):
        """Comparing against the bare date would exclude everything run after
        midnight on the day the user picked."""
        self._add("example.com", "2026-05-31T23:30:00+00:00", {"dmarc": {"policy": "reject"}})
        self._add("example.com", "2026-08-15T10:00:00+00:00", {"dmarc": {"policy": "none"}})
        body = self._compare()
        self.assertIsNotNone(body["a"]["scan_id"])
        self.assertTrue(body["changed"])

    def test_an_empty_period_is_refused_not_reported_as_unchanged(self):
        """Reporting a period nobody scanned as one where everything held
        steady is the worst answer available."""
        self._add("example.com", "2026-08-15T10:00:00+00:00", {"dmarc": {"policy": "none"}})
        body = self._compare()
        self.assertFalse(body["changed"])
        self.assertIn("nothing to compare", body["error"])

    def test_both_periods_resolving_to_one_scan_is_refused(self):
        self._add("example.com", "2026-05-10T10:00:00+00:00", {"dmarc": {"policy": "none"}})
        body = self.client.get(
            "/api/reporting/compare?domain=example.com"
            "&a_from=2026-05-01&a_to=2026-05-31"
            "&b_from=2026-05-01&b_to=2026-05-31").get_json()
        self.assertIn("same scan", body["error"])

    def test_both_scans_are_named_in_the_response(self):
        """A comparison whose endpoints are invisible cannot be checked."""
        self._add("example.com", "2026-05-10T10:00:00+00:00", {"dmarc": {"policy": "reject"}})
        self._add("example.com", "2026-08-10T10:00:00+00:00", {"dmarc": {"policy": "none"}})
        body = self._compare()
        for side in ("a", "b"):
            self.assertIsNotNone(body[side]["scan_id"])
            self.assertIsNotNone(body[side]["created_at"])

    def test_an_invalid_domain_is_refused(self):
        resp = self.client.get(
            "/api/reporting/compare?domain=not a domain"
            "&a_from=2026-05-01&a_to=2026-05-31&b_from=2026-08-01&b_to=2026-08-31")
        self.assertEqual(400, resp.status_code)

    def test_a_missing_period_bound_is_refused(self):
        resp = self.client.get(
            "/api/reporting/compare?domain=example.com&a_from=2026-05-01")
        self.assertEqual(400, resp.status_code)

    def test_a_period_that_ends_before_it_starts_is_refused(self):
        resp = self.client.get(
            "/api/reporting/compare?domain=example.com"
            "&a_from=2026-05-31&a_to=2026-05-01"
            "&b_from=2026-08-01&b_to=2026-08-31")
        self.assertEqual(400, resp.status_code)
        self.assertIn("ends before it starts", resp.get_json()["error"])

    def test_a_nonsense_date_is_refused(self):
        resp = self.client.get(
            "/api/reporting/compare?domain=example.com"
            "&a_from=last-tuesday&a_to=2026-05-31"
            "&b_from=2026-08-01&b_to=2026-08-31")
        self.assertEqual(400, resp.status_code)

    def test_the_page_is_in_the_reports_subnav(self):
        body = self.client.get("/reports").get_data(as_text=True)
        self.assertIn('href="/reports/compare"', body)

    def test_the_page_renders(self):
        resp = self.client.get("/reports/compare")
        self.assertEqual(200, resp.status_code)
        self.assertIn("cmpRunBtn", resp.get_data(as_text=True))



class IssueDeltaTests(unittest.TestCase):
    """A count on its own cannot tell a domain that sat at 20 issues all
    month from one that went from 2 to 20, and only the second is why
    someone opens a rising trend line."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "delta.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        import importlib
        import db
        import app
        from settings.store import get_store
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER",
                    "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)
        self.tempdir.cleanup()

    def _metric(self, domain, day, issues, grade="A"):
        """scan_metrics is what the drill-downs read; a scan row backs it."""
        import json
        with self.db._lock, self.db._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (domain, created_at, grade, score, issues_count, data)"
                " VALUES (?,?,?,?,?,?)",
                (domain, f"{day}T10:00:00+00:00", grade, 80, issues, json.dumps({})))
            scan_id = cur.lastrowid
            conn.execute(
                "INSERT INTO scan_metrics (scan_id, domain, day, created_at, grade,"
                " grade_score, header_score, issues_count, blacklist_listed,"
                " dnssec_signed, https_redirect)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, domain, day, f"{day}T10:00:00+00:00", grade,
                 90, 80, issues, 0, 1, 1))
        return scan_id

    def _deltas(self):
        return self.client.get("/api/reporting/deltas?days=365").get_json()["domains"]

    def test_a_domain_that_got_worse_reports_a_positive_delta(self):
        today = __import__("datetime").date.today()
        earlier = (today - __import__("datetime").timedelta(days=20)).isoformat()
        self._metric("worse.example", earlier, 2)
        self._metric("worse.example", today.isoformat(), 20)
        row = [r for r in self._deltas() if r["domain"] == "worse.example"][0]
        self.assertEqual(2, row["first_issues"])
        self.assertEqual(20, row["last_issues"])
        self.assertEqual(18, row["delta"])

    def test_a_domain_that_improved_reports_a_negative_delta(self):
        today = __import__("datetime").date.today()
        earlier = (today - __import__("datetime").timedelta(days=20)).isoformat()
        self._metric("better.example", earlier, 20)
        self._metric("better.example", today.isoformat(), 5)
        row = [r for r in self._deltas() if r["domain"] == "better.example"][0]
        self.assertEqual(-15, row["delta"])

    def test_a_steady_domain_is_distinguishable_from_a_worsening_one(self):
        """The whole point: both end at 20."""
        today = __import__("datetime").date.today()
        earlier = (today - __import__("datetime").timedelta(days=20)).isoformat()
        self._metric("steady.example", earlier, 20)
        self._metric("steady.example", today.isoformat(), 20)
        self._metric("spiked.example", earlier, 2)
        self._metric("spiked.example", today.isoformat(), 20)
        rows = {r["domain"]: r for r in self._deltas()}
        self.assertEqual(0, rows["steady.example"]["delta"])
        self.assertEqual(18, rows["spiked.example"]["delta"])
        self.assertEqual(rows["steady.example"]["last_issues"],
                         rows["spiked.example"]["last_issues"])

    def test_one_scan_means_the_change_was_never_observed(self):
        """None, not zero: a single scan has nothing to compare against, and
        0 would read as "we looked and it held steady"."""
        self._metric("once.example", __import__("datetime").date.today().isoformat(), 7)
        row = [r for r in self._deltas() if r["domain"] == "once.example"][0]
        self.assertIsNone(row["delta"])
        self.assertTrue(row["single_scan"])

    def test_the_worst_deterioration_comes_first(self):
        today = __import__("datetime").date.today()
        earlier = (today - __import__("datetime").timedelta(days=20)).isoformat()
        for name, first, last in (("small.example", 1, 3), ("big.example", 1, 30),
                                  ("fixed.example", 10, 1)):
            self._metric(name, earlier, first)
            self._metric(name, today.isoformat(), last)
        order = [r["domain"] for r in self._deltas()]
        self.assertEqual("big.example", order[0])
        self.assertLess(order.index("small.example"), order.index("fixed.example"))

    def test_both_scan_ids_are_returned_so_the_ui_can_link_to_a_comparison(self):
        today = __import__("datetime").date.today()
        earlier = (today - __import__("datetime").timedelta(days=20)).isoformat()
        first = self._metric("link.example", earlier, 2)
        last = self._metric("link.example", today.isoformat(), 9)
        row = [r for r in self._deltas() if r["domain"] == "link.example"][0]
        self.assertEqual(first, row["first_scan_id"])
        self.assertEqual(last, row["last_scan_id"])

    def test_an_invalid_domain_filter_is_refused(self):
        resp = self.client.get("/api/reporting/deltas?domain=not a domain")
        self.assertEqual(400, resp.status_code)


class TrendsDrilldownWiringTests(unittest.TestCase):
    """The issues drill-down is where a rising line gets explained."""

    def _read(self, *parts):
        import pathlib
        return (pathlib.Path(__file__).resolve().parent.parent
                .joinpath(*parts).read_text(encoding="utf-8"))

    def test_the_issues_drilldown_renders_the_delta(self):
        js = self._read("static", "js", "trends.js")
        self.assertIn("if (kind === 'issues') await renderDeltaDrill(body)", js)

    def test_a_single_scan_is_shown_as_not_measured(self):
        js = self._read("static", "js", "trends.js")
        block = js[js.index("function deltaCell"):][:600]
        self.assertIn("not measured", block)

    def test_each_row_links_through_to_the_field_level_comparison(self):
        js = self._read("static", "js", "trends.js")
        block = js[js.index("function compareLink"):][:800]
        self.assertIn("/reports/compare?", block)
        for param in ("domain", "a_from", "a_to", "b_from", "b_to"):
            self.assertIn(param, block)

    def test_the_domain_picker_is_a_dropdown_not_a_free_text_box(self):
        """A native datalist rendered as a stray suggestion box under the
        field, and typing a domain that has never been scanned only produces
        an empty comparison."""
        html = self._read("templates", "reports_compare.html")
        self.assertIn('<select id="cmpDomain">', html)
        self.assertNotIn("datalist", html)

    def test_the_dropdown_lists_each_scanned_domain_once(self):
        js = self._read("static", "js", "compare.js")
        block = js[js.index("async function fillDomains"):][:1400]
        self.assertIn("new Set()", block)
        self.assertIn("/api/reporting/domains", block)

    def test_a_domain_from_the_url_survives_being_absent_from_the_list(self):
        """Arriving from the trends drill-down for a domain the list does not
        carry would otherwise reset the selection to the placeholder."""
        js = self._read("static", "js", "compare.js")
        block = js[js.index("async function fillDomains"):][:1400]
        self.assertIn("if (preferred) found.add(preferred)", block)

    def test_an_empty_database_says_so_rather_than_offering_nothing(self):
        js = self._read("static", "js", "compare.js")
        self.assertIn("No scanned domains yet", js)

    def test_the_compare_page_runs_a_prefilled_comparison_on_arrival(self):
        """Otherwise the click through from trends drops the reader on a form
        holding exactly what they just clicked, asking them to press go."""
        js = self._read("static", "js", "compare.js")
        self.assertIn("prefilled.length === 5", js)

if __name__ == "__main__":
    unittest.main()
