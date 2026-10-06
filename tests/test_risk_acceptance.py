"""A finding the organisation has decided to live with, for a stated time.

Known and deliberately-left findings came back in every scan and report,
burying the new ones, and nothing recorded that the decision had been made,
by whom, or until when.
"""

from datetime import datetime, timedelta, timezone

from enterprise_harness import EnterpriseAppTestCase

# A scan that yields "SPF record missing" and nothing clever.
_RESULTS = {"domain": "example.com", "apex_domain": "example.com",
            "spf": {"success": True, "found": False, "measured": True}}


def _utc_today():
    """The date the application judges expiry by. date.today() is local:
    between midnight and the UTC date change "yesterday" was still today."""
    return datetime.now(timezone.utc).date()


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
            expires_on=(_utc_today() + timedelta(days=days)).isoformat(),
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
                         ((_utc_today() - timedelta(days=1)).isoformat(), exception_id))
        self.assertNotIn("accepted", self._spf_now())

    def test_an_acceptance_on_another_domain_does_not_apply(self):
        self._accept(domain="other.example")
        self.assertNotIn("accepted", self._spf_now())

    def test_an_apex_acceptance_covers_the_apex_finding_on_a_subdomain_scan(self):
        """SPF lives at the apex; scanning www must not bring it back."""
        self._accept()
        self.assertIn("accepted", self._spf_now({**_RESULTS, "domain": "www.example.com"}))

    def test_an_apex_acceptance_does_not_hide_a_web_finding_on_a_subdomain(self):
        """Finding keys name no host. Accepting a missing HSTS header on the
        apex silenced it on every subdomain scanned, so a new shop host
        without HSTS never counted and never failed the CI gate."""
        import risk_acceptance
        web = {"severity": "high", "category": "Web", "title": "HSTS missing"}
        key = self.rec._condition_key(web)
        risk_acceptance.create(
            domain="example.com", finding_key=key, title=web["title"], severity="high",
            reason="legacy apex host", owner="CISO", created_by="admin@example.com",
            expires_on=(_utc_today() + timedelta(days=30)).isoformat())
        on_sub = risk_acceptance.apply(
            {"domain": "shop.example.com", "apex_domain": "example.com"}, [dict(web)],
            self.rec._condition_key)
        on_apex = risk_acceptance.apply(
            {"domain": "example.com", "apex_domain": "example.com"}, [dict(web)],
            self.rec._condition_key)
        self.assertNotIn("accepted", on_sub[0])
        self.assertIn("accepted", on_apex[0])

    def test_findings_for_many_scans_read_the_acceptances_once(self):
        """Report and trend pages generate findings for every scan in a list,
        and each generation opened the database for the acceptances."""
        from unittest import mock
        import risk_acceptance
        self._accept()
        self._spf_now()
        with mock.patch.object(risk_acceptance.db, "_connect",
                               wraps=risk_acceptance.db._connect) as connect:
            for _ in range(5):
                self.assertIn("accepted", self._spf_now())
        self.assertEqual(0, connect.call_count)

    def test_a_revoked_acceptance_stops_counting_at_once(self):
        """The cache is only safe if a revocation empties it."""
        import risk_acceptance
        exception_id = self._accept()
        self.assertIn("accepted", self._spf_now())
        risk_acceptance.revoke(exception_id)
        self.assertNotIn("accepted", self._spf_now())

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
                "owner": "CISO", "expires_on": (_utc_today() + timedelta(days=30)).isoformat()}
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


class AcceptFromTheReportTests(EnterpriseAppTestCase):
    """The report showed a finding as accepted, but gave no way to accept
    one: the only route was a form under Admin that nothing pointed to."""

    _scan = AcceptanceRoutesTests._scan
    _key = AcceptanceRoutesTests._key
    _form = AcceptanceRoutesTests._form

    def _link(self):
        from urllib.parse import quote
        return f"/admin/risks?domain=example.com&amp;finding={quote(self._key(), safe='')}#finding"

    def test_an_admin_gets_a_link_per_finding(self):
        scan_id = self._scan()
        self.login_as("admin")
        self.assertIn(self._link().encode(), self.client.get(f"/report/{scan_id}").data)

    def test_others_do_not(self):
        scan_id = self._scan()
        self.login_as("user")
        self.assertNotIn(b"/admin/risks?domain=", self.client.get(f"/report/{scan_id}").data)

    def test_an_accepted_finding_offers_no_second_acceptance(self):
        scan_id = self._scan()
        self.login_as("admin")
        self.client.post("/admin/risks", data=self._form())
        self.assertNotIn(self._link().encode(), self.client.get(f"/report/{scan_id}").data)

    def test_the_link_lands_on_that_finding_ready_to_fill_in(self):
        from urllib.parse import quote
        self._scan()
        self.login_as("admin")
        page = self.client.get(f"/admin/risks?domain=example.com&finding={quote(self._key(), safe='')}").data
        self.assertIn(b'rec-focus" id="finding"', page)
        self.assertIn(b"required autofocus", page)

    def test_a_finding_the_latest_scan_no_longer_has_is_said(self):
        """A report of an older scan can name one; landing on a page without
        it, and without a word why, looked like the link was broken."""
        self._scan()
        self.login_as("admin")
        page = self.client.get("/admin/risks?domain=example.com&finding=gone:away").data
        self.assertIn(b"not in the latest scan", page)

    def test_the_scan_result_offers_it_too(self):
        import pathlib
        self.login_as("admin")
        self.assertIn(b'data-can-accept="1"', self.client.get("/").data)
        js = (pathlib.Path(__file__).resolve().parent.parent / "static/js/app.js").read_text(encoding="utf-8")
        self.assertIn("el.dataset.canAccept === '1'", js)
        self.login_as("user")
        self.assertNotIn(b'data-can-accept="1"', self.client.get("/").data)


class RiskOwnerTests(EnterpriseAppTestCase):
    """The risk owner was a free-text field: "CISO", "J. Example", "jan" --
    nothing tied it to the people the organisation already keeps as contacts,
    and nobody could see which risks one person carries. The owner is now a
    contact: the domain's (or its unit's) is offered first, or any other
    contact or account, or someone new."""

    _scan = AcceptanceRoutesTests._scan
    _key = AcceptanceRoutesTests._key

    def _form(self, **overrides):
        form = {"domain": "example.com", "finding_key": self._key(), "reason": "known",
                "expires_on": (_utc_today() + timedelta(days=30)).isoformat()}
        form.update(overrides)
        return form

    def _unit_with_contact(self):
        import contacts
        import domain_portfolio
        person = contacts.create(name="Sam Example", email="sam@example.com")
        unit = domain_portfolio.ensure_group("Marketing")
        domain_portfolio.update_group(unit, contact_id=person["id"])
        domain_portfolio.assign("example.com", unit)
        return person

    def test_the_units_contact_is_offered_first_and_chosen(self):
        person = self._unit_with_contact()
        self._scan()
        self.login_as("admin")
        page = self.client.get("/admin/risks?domain=example.com").data.decode()
        self.assertIn(f'<option value="c{person["id"]}" selected>Sam Example (sam@example.com)', page)
        self.assertIn("contact of Marketing", page)

    def test_a_chosen_contact_is_stored_with_the_name_it_had(self):
        import risk_acceptance
        person = self._unit_with_contact()
        self._scan()
        self.login_as("admin")
        self.client.post("/admin/risks", data=self._form(owner_contact=f"c{person['id']}"))
        entry = risk_acceptance.list_all("example.com")[0]
        self.assertEqual(("Sam Example (sam@example.com)", person["id"]),
                         (entry["owner"], entry["owner_contact_id"]))

    def test_someone_new_becomes_a_contact(self):
        import contacts
        import risk_acceptance
        self._scan()
        self.login_as("admin")
        self.client.post("/admin/risks", data=self._form(owner_contact="new", owner_name="Alex Example",
                                                         owner_email="alex@example.com"))
        made = [c for c in contacts.list_contacts() if c["name"] == "Alex Example"]
        self.assertEqual(1, len(made))
        self.assertEqual(made[0]["id"], risk_acceptance.list_all("example.com")[0]["owner_contact_id"])

    def test_an_account_becomes_a_contact(self):
        import risk_acceptance
        self._scan()
        self.login_as("admin")
        self.client.post("/admin/risks", data=self._form(owner_contact=f"u{self.users['user']}"))
        entry = risk_acceptance.list_all("example.com")[0]
        self.assertIn("user@example.com", entry["owner"])
        self.assertIsNotNone(entry["owner_contact_id"])

    def test_a_form_that_fails_makes_no_contact(self):
        """A missing reason sent the form back -- after the new owner had
        already been added to the contacts."""
        import contacts
        self._scan()
        self.login_as("admin")
        self.client.post("/admin/risks", data=self._form(reason="", owner_contact="new", owner_name="Alex Example"))
        self.assertEqual([], [c for c in contacts.list_contacts() if c["name"] == "Alex Example"])

    def test_without_a_contact_for_the_domain_nobody_is_chosen_for_you(self):
        self._scan()
        self.login_as("admin")
        page = self.client.get("/admin/risks?domain=example.com").data.decode()
        owner = page[page.index('name="owner_contact"'):page.index("</select>", page.index('name="owner_contact"'))]
        self.assertNotIn("selected", owner)
        self.assertIn('<option value="new">Someone else (new contact)</option>', owner)
