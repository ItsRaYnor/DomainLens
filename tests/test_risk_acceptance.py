"""A finding the organisation has decided to live with, for a stated time.

Known and deliberately-left findings came back in every scan and report,
burying the new ones, and nothing recorded that the decision had been made,
by whom, or until when.
"""

from datetime import date, timedelta

from enterprise_harness import EnterpriseAppTestCase

# A scan that yields "SPF record missing" and nothing clever.
_RESULTS = {"domain": "example.com", "apex_domain": "example.com",
            "spf": {"success": True, "found": False, "measured": True}}


class AcceptanceTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        import recommendations
        self.rec = recommendations
        self.spf = next(r for r in recommendations.generate(dict(_RESULTS))
                        if r["title"] == "SPF record missing")

    def _accept(self, days=30, domain="example.com", **kwargs):
        import risk_acceptance
        return risk_acceptance.create(
            domain=domain, finding_key=self.spf["finding_key"], title=self.spf["title"],
            severity=self.spf["severity"], reason=kwargs.get("reason", "legacy relay until Q3"),
            owner=kwargs.get("owner", "CISO"),
            expires_on=(date.today() + timedelta(days=days)).isoformat(),
            created_by="admin@example.com")

    def _spf_now(self, results=None):
        return next(r for r in self.rec.generate(dict(results or _RESULTS))
                    if r["title"] == "SPF record missing")

    def test_an_accepted_finding_is_still_reported(self):
        """It is measured and still true; hiding it would claim otherwise."""
        self._accept()
        self.assertIn("accepted", self._spf_now())

    def test_an_accepted_finding_leaves_the_severity_counts(self):
        self._accept()
        counts = self.rec.summarize_counts(self.rec.generate(dict(_RESULTS)))
        self.assertEqual(0, counts[self.spf["severity"]])
        self.assertEqual(1, counts["accepted"])

    def test_an_expired_acceptance_counts_again(self):
        """A decision is revisited, not forgotten."""
        exception_id = self._accept()
        with self.db._connect() as conn:
            conn.execute("UPDATE finding_exceptions SET expires_on=? WHERE id=?",
                         ((date.today() - timedelta(days=1)).isoformat(), exception_id))
        self.assertNotIn("accepted", self._spf_now())

    def test_an_acceptance_on_another_domain_does_not_apply(self):
        self._accept(domain="other.example")
        self.assertNotIn("accepted", self._spf_now())

    def test_an_apex_acceptance_covers_the_apex_finding_on_a_subdomain_scan(self):
        """SPF lives at the apex; scanning www must not bring it back."""
        self._accept()
        self.assertIn("accepted", self._spf_now({**_RESULTS, "domain": "www.example.com"}))

    def test_no_longer_than_a_year(self):
        with self.assertRaises(ValueError):
            self._accept(days=400)

    def test_a_reason_and_an_owner_are_required(self):
        with self.assertRaises(ValueError):
            self._accept(reason=" ")
        with self.assertRaises(ValueError):
            self._accept(owner="")

    def test_trend_metrics_leave_accepted_findings_out(self):
        self._accept()
        scan_id = self.db.save_scan("example.com", dict(_RESULTS))
        with self.db._connect() as conn:
            count = conn.execute("SELECT recommendation_count FROM scan_metrics WHERE scan_id=?",
                                 (scan_id,)).fetchone()[0]
        self.assertEqual(0, count)


class AcceptanceRoutesTests(EnterpriseAppTestCase):
    def _scan(self):
        return self.db.save_scan("example.com", dict(_RESULTS))

    def _key(self):
        import recommendations
        return next(r for r in recommendations.generate(dict(_RESULTS))
                    if r["title"] == "SPF record missing")["finding_key"]

    def _form(self, **overrides):
        form = {"domain": "example.com", "finding_key": self._key(), "reason": "known",
                "owner": "CISO", "expires_on": (date.today() + timedelta(days=30)).isoformat()}
        form.update(overrides)
        return form

    def test_an_admin_accepts_a_finding_from_the_latest_scan(self):
        import audit_log
        import risk_acceptance
        self._scan()
        self.login_as("admin")
        self.client.post("/admin/risks", data=self._form())
        self.assertEqual(1, len(risk_acceptance.list_all("example.com")))
        entry = audit_log.list_entries(action="risk.accept")["entries"][0]
        self.assertEqual("CISO", entry["details"]["owner"])

    def test_an_analyst_cannot_accept_risk(self):
        """It takes a finding out of everyone's counts; that is an admin call."""
        import risk_acceptance
        self._scan()
        self.login_as("user")
        self.client.post("/admin/risks", data=self._form())
        self.assertEqual([], risk_acceptance.list_all())

    def test_a_finding_not_in_the_latest_scan_cannot_be_accepted(self):
        import risk_acceptance
        self._scan()
        self.login_as("admin")
        self.client.post("/admin/risks", data=self._form(finding_key="made:up"))
        self.assertEqual([], risk_acceptance.list_all())

    def test_a_viewer_can_see_what_was_accepted(self):
        self._scan()
        self.login_as("admin")
        self.client.post("/admin/risks", data=self._form())
        self.login_as("viewer")
        resp = self.client.get("/admin/risks")
        self.assertEqual(200, resp.status_code)
        self.assertIn(b"SPF record missing", resp.data)

    def test_the_printed_report_marks_it(self):
        scan_id = self._scan()
        self.login_as("admin")
        self.client.post("/admin/risks", data=self._form())
        self.assertIn(b"rec-is-accepted", self.client.get(f"/report/{scan_id}").data)
