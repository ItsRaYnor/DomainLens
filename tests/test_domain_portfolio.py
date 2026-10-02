"""Keeping track of the domains an organisation holds, per company or department.

Hundreds of domains over several registrars were checked one batch at a
time, with nothing remembered in between: no warning when one expired or
went into quarantine, and no way to see which still had to move to the
registrar the business unit had agreed on. The portfolio keeps them, looks
them up on a schedule, and tells you once per change. A failed lookup never
erases what was known, and a missing .nl expiry is "not published", not a
gap in the data.
"""

import pathlib
import unittest
from datetime import date, datetime, timedelta, timezone
from unittest import mock

import domain_portfolio
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent
_NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _answer(registrar="Example Registrar", reseller=None, expires=None, phase="registered",
            nameservers=("ns1.example.net", "ns2.example.net"), **extra):
    return {"success": True, "source": "rdap", "status": ["active"],
            "registrar": {"name": registrar}, "reseller": {"name": reseller} if reseller else None,
            "expires": expires, "nameservers": list(nameservers),
            "lifecycle": {"phase": phase, **extra}}


class ParseImportTests(unittest.TestCase):
    def test_a_group_column_is_read_and_a_list_on_one_line_is_not_a_group(self):
        """"example.com, example.org" is two domains, not a domain in group "example.org"."""
        entries, rejected, _ = domain_portfolio.parse_import("\n".join([
            "domain;group",
            "example.nl;Sales",
            "example.com, example.org",
            "https://www.example.net/x\tHolding B.V.",
            "bad..example",
            "a.example b.example",
        ]))
        self.assertEqual([("example.nl", "Sales"), ("example.com", None), ("example.org", None),
                          ("example.net", "Holding B.V."), ("a.example", None), ("b.example", None)],
                         entries)
        self.assertEqual(["bad..example"], rejected)


class ImportConversionTests(unittest.TestCase):
    def test_a_subdomain_is_added_as_its_registered_domain_and_reported(self):
        """RDAP has no record of a subdomain: it would show as "not registered",
        a critical alert for a domain that is fine."""
        entries, _, converted = domain_portfolio.parse_import(
            "\n".join(["shop.example.nl;Sales", "https://mail.example.co.uk/login", "example.nl"]))
        self.assertEqual([("example.nl", "Sales"), ("example.co.uk", None)], entries)
        self.assertEqual({"shop.example.nl": "example.nl", "mail.example.co.uk": "example.co.uk"},
                         converted)

    def test_a_header_row_decides_which_columns_are_read(self):
        """A notes column before the company column was taken for the group."""
        entries, _, _ = domain_portfolio.parse_import(
            "\n".join(["Notities;Domein;Bedrijf", "see mail;example.nl;Sales", ";example.com;"]))
        self.assertEqual([("example.nl", "Sales"), ("example.com", None)], entries)


class PortfolioDbTestCase(EnterpriseAppTestCase):
    def add(self, text, group=None):
        entries, _, _ = domain_portfolio.parse_import(text)
        return domain_portfolio.import_domains(entries, default_group=group)

    def row(self, domain):
        return next(d for d in domain_portfolio.list_all(today=_NOW.date()) if d["domain"] == domain)

    def raw(self, domain):
        return domain_portfolio.raw(self.row(domain)["id"])


class ImportTests(PortfolioDbTestCase):
    def test_reimporting_moves_a_domain_to_the_group_it_names(self):
        self.add("example.nl;Sales")
        result = self.add("example.nl;Holding\nexample.com")
        self.assertEqual((["example.com"], ["example.nl"]), (result["added"], result["moved"]))
        self.assertEqual("Holding", self.row("example.nl")["group"])

    def test_an_import_without_a_group_does_not_ungroup_a_domain(self):
        self.add("example.nl;Sales")
        self.add("example.nl")
        self.assertEqual("Sales", self.row("example.nl")["group"])

    def test_more_than_the_cap_is_refused_not_truncated(self):
        with mock.patch.object(domain_portfolio, "MAX_DOMAINS", 2):
            with self.assertRaises(ValueError):
                self.add("a.example\nb.example\nc.example")
        self.assertEqual([], domain_portfolio.list_all())

    def test_deleting_a_group_keeps_its_domains(self):
        self.add("example.nl;Sales")
        domain_portfolio.delete_group(domain_portfolio.list_groups()[0]["id"])
        self.assertIsNone(self.row("example.nl")["group"])


class StateTests(unittest.TestCase):
    def test_the_reseller_counts_as_being_at_the_expected_registrar(self):
        """For .nl the name a customer knows is often the reseller."""
        domain = {"phase": "registered", "registrar": "Big Registrar B.V.", "reseller": "Example Hosting"}
        self.assertEqual("ok", domain_portfolio.transfer_state(domain, {"expected_registrar": "example hosting"}))
        self.assertEqual("move", domain_portfolio.transfer_state(domain, {"expected_registrar": "Other"}))

    def test_an_unknown_registrar_is_not_marked_to_move(self):
        domain = {"phase": "unmeasured", "registrar": None}
        self.assertEqual("unmeasured", domain_portfolio.transfer_state(domain, {"expected_registrar": "X"}))
        self.assertEqual("not_applicable", domain_portfolio.transfer_state(domain, {}))

    def test_a_nl_domain_without_expiry_is_not_published_not_unknown(self):
        self.assertEqual(("not_published", None), domain_portfolio.expiry_state(
            {"domain": "example.nl", "phase": "registered", "expires": None}))
        self.assertEqual(("unmeasured", None), domain_portfolio.expiry_state(
            {"domain": "example.com", "phase": "registered", "expires": None}))
        self.assertEqual(("unmeasured", None), domain_portfolio.expiry_state(
            {"domain": "example.nl", "phase": "unmeasured", "expires": None}))

    def test_the_schedule_tightens_near_expiry_and_in_quarantine(self):
        last = (_NOW - timedelta(hours=7)).isoformat()
        far = (_NOW + timedelta(days=200)).date().isoformat()
        soon = (_NOW + timedelta(days=10)).date().isoformat()
        self.assertFalse(domain_portfolio.is_due({"last_checked_at": last, "phase": "registered",
                                                  "expires": far}, _NOW))
        self.assertTrue(domain_portfolio.is_due({"last_checked_at": last, "phase": "registered",
                                                 "expires": soon}, _NOW))
        self.assertTrue(domain_portfolio.is_due({"last_checked_at": last, "phase": "quarantine"}, _NOW))


class CheckTests(PortfolioDbTestCase):
    def test_the_first_answer_is_a_baseline_not_news(self):
        self.add("example.com")
        notify = mock.Mock()
        domain_portfolio.check(self.raw("example.com"), fetch=lambda d: _answer(), notify=notify, now=_NOW)
        notify.assert_not_called()
        self.assertEqual("Example Registrar", self.row("example.com")["registrar"])

    def test_a_failed_lookup_keeps_the_last_answer_and_says_so(self):
        self.add("example.com")
        domain_portfolio.check(self.raw("example.com"), fetch=lambda d: _answer(), now=_NOW)
        notify = mock.Mock()
        domain_portfolio.check(self.raw("example.com"), notify=notify, now=_NOW,
                               fetch=lambda d: {"success": False, "state": "unmeasured", "error": "timeout"})
        row = self.row("example.com")
        notify.assert_not_called()
        self.assertEqual(("registered", "Example Registrar", True),
                         (row["phase"], row["registrar"], row["stale"]))
        self.assertIn("unmeasured", row["flags"])

    def test_a_registrar_or_name_server_change_is_reported_once(self):
        """An unexpected registrar or name server change can be a hijack."""
        self.add("example.com")
        domain_portfolio.check(self.raw("example.com"), fetch=lambda d: _answer(), now=_NOW)
        notify = mock.Mock()
        changed = _answer(registrar="Other Registrar", nameservers=("ns.example.org",))
        domain_portfolio.check(self.raw("example.com"), fetch=lambda d: changed, notify=notify, now=_NOW)
        domain_portfolio.check(self.raw("example.com"), fetch=lambda d: changed, notify=notify, now=_NOW)
        kinds = [c.args[2] for c in notify.call_args_list]
        self.assertEqual(2, len(kinds))
        self.assertIn("Other Registrar", kinds[0])
        self.assertIn("ns.example.org", kinds[1])

    def test_quarantine_is_critical(self):
        self.add("example.nl")
        domain_portfolio.check(self.raw("example.nl"), fetch=lambda d: _answer(), now=_NOW)
        notify = mock.Mock()
        domain_portfolio.check(self.raw("example.nl"), notify=notify, now=_NOW,
                               fetch=lambda d: _answer(phase="quarantine"))
        self.assertEqual("critical", notify.call_args.args[1])
        self.assertIn("attention", self.row("example.nl")["flags"])

    def test_expiry_warns_once_per_threshold_and_again_after_renewal(self):
        self.add("example.com")
        domain_portfolio.check(self.raw("example.com"), fetch=lambda d: _answer(), now=_NOW)
        notify = mock.Mock()
        soon = (_NOW + timedelta(days=20)).date().isoformat()
        for _ in range(2):
            domain_portfolio.check(self.raw("example.com"), notify=notify, now=_NOW,
                                   fetch=lambda d: _answer(expires=soon))
        self.assertEqual(1, notify.call_count)
        later = _NOW + timedelta(days=15)
        domain_portfolio.check(self.raw("example.com"), notify=notify, now=later,
                               fetch=lambda d: _answer(expires=soon))
        self.assertEqual(2, notify.call_count)
        # Renewed: a new term, so the thresholds count again for it.
        renewed = (later + timedelta(days=25)).date().isoformat()
        domain_portfolio.check(self.raw("example.com"), notify=notify, now=later,
                               fetch=lambda d: _answer(expires=renewed))
        self.assertEqual(3, notify.call_count)

    def test_a_round_looks_up_the_longest_unchecked_first_and_stops_at_its_cap(self):
        self.add("\n".join(f"d{i}.example" for i in range(5)))
        seen = []
        with mock.patch.object(domain_portfolio, "_PER_RUN", 3):
            domain_portfolio.maybe_run(_NOW, fetch=lambda d: seen.append(d) or _answer())
            domain_portfolio.maybe_run(_NOW, fetch=lambda d: seen.append(d) or _answer())
        self.assertEqual(5, len(set(seen)))


class ApiTests(PortfolioDbTestCase):
    def test_an_analyst_imports_groups_and_exports(self):
        self.login_as("user")
        resp = self.client.post("/api/portfolio/import",
                                json={"text": "example.nl;Sales\nexample.com", "group": "Holding"})
        self.assertEqual(201, resp.status_code)
        data = self.client.get("/api/portfolio").get_json()
        self.assertEqual({"Sales", "Holding"}, {g["name"] for g in data["groups"]})
        self.assertEqual(2, data["summary"]["total"]["total"])
        csv_body = self.client.get("/api/portfolio/csv").get_data(as_text=True)
        self.assertIn("example.nl,Sales", csv_body)

    def test_an_excel_sheet_is_imported_by_its_header(self):
        import io
        import openpyxl
        book = openpyxl.Workbook()
        sheet = book.active
        sheet.append(["Domain", "Company", "Notes"])
        sheet.append(["www.example.nl", "Sales", "x"])
        sheet.append(["example.com", None, None])
        buf = io.BytesIO()
        book.save(buf)
        self.login_as("user")
        resp = self.client.post("/api/portfolio/import", content_type="multipart/form-data",
                                data={"file": (io.BytesIO(buf.getvalue()), "domains.xlsx"),
                                      "group": "Holding"})
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        domains = {d["domain"]: d["group"] for d in self.client.get("/api/portfolio").get_json()["domains"]}
        self.assertEqual({"example.nl": "Sales", "example.com": "Holding"}, domains)

    def test_a_file_that_is_not_a_workbook_is_refused(self):
        import io
        self.login_as("user")
        resp = self.client.post("/api/portfolio/import", content_type="multipart/form-data",
                                data={"file": (io.BytesIO(b"not a zip"), "domains.xlsx")})
        self.assertEqual(400, resp.status_code)

    def test_bulk_move_and_remove(self):
        self.login_as("user")
        self.client.post("/api/portfolio/import", json={"text": "example.nl\nexample.com"})
        group = self.client.post("/api/portfolio/groups",
                                 json={"name": "Sales", "expected_registrar": "Example"}).get_json()
        ids = [d["id"] for d in self.client.get("/api/portfolio").get_json()["domains"]]
        self.client.post("/api/portfolio/domains", json={"action": "move", "ids": ids[:1],
                                                         "group_id": group["id"]})
        self.client.post("/api/portfolio/domains", json={"action": "remove", "ids": ids[1:]})
        domains = self.client.get("/api/portfolio").get_json()["domains"]
        self.assertEqual([("Sales", "unmeasured")], [(d["group"], d["transfer"]) for d in domains])

    def test_a_viewer_can_look_but_not_change(self):
        self.login_as("viewer")
        self.assertEqual(200, self.client.get("/api/portfolio").status_code)
        self.assertEqual(403, self.client.post("/api/portfolio/import",
                                               json={"text": "example.nl"}).status_code)

    def test_the_page_is_under_monitoring_with_its_own_tab(self):
        self.login_as("user")
        page = self.client.get("/monitoring/domains").get_data(as_text=True)
        self.assertIn('href="/monitoring/domains"', page)
        self.assertIn("portfolio.js", page)
        self.assertIn('href="/monitoring/domains"', self.client.get("/monitoring").get_data(as_text=True))


class ViewTests(unittest.TestCase):
    def test_the_page_says_not_published_and_keeps_stale_answers_visible(self):
        js = ROOT.joinpath("static", "js", "portfolio.js").read_text(encoding="utf-8")
        self.assertIn("'not_published'", js)
        self.assertIn("Last lookup failed", js)


if __name__ == "__main__":
    unittest.main()
