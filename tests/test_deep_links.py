import os
import pathlib
import tempfile
import unittest


class ScanDeepLinkTests(unittest.TestCase):
    """/remediate/domain/<d> has always linked to /?domain=…&tab=advies, and
    nothing on the scan page read either parameter. The button labelled
    "Scan & open Advies" opened an empty search box, and every ServiceNow
    deep link landed the same way.
    """

    def _app_js(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "js" / "app.js").read_text(encoding="utf-8")

    def test_the_query_is_read_on_load(self):
        block = self._app_js()
        block = block[block.index("document.addEventListener('DOMContentLoaded'"):][:600]
        self.assertIn("openFromQuery()", block)

    def test_the_domain_is_filled_in_and_scanned(self):
        block = self._app_js()
        block = block[block.index("function openFromQuery"):][:1200]
        self.assertIn("params.get('domain')", block)
        self.assertIn("startScan()", block)

    def test_advies_maps_to_the_real_tab_name(self):
        # The links say "advies"; the tab is data-tab="recommendations".
        # Assuming they match is why this silently did nothing.
        block = self._app_js()
        block = block[block.index("QUERY_TAB_ALIASES"):][:600]
        self.assertIn("advies: 'recommendations'", block)

    def test_a_running_scan_is_not_duplicated(self):
        # resumeScanIfRunning() is already re-attaching; starting again would
        # race two scans of one domain into the history.
        block = self._app_js()
        block = block[block.index("function openFromQuery"):][:1200]
        self.assertIn("if (readJob()) return;", block)

    def test_the_tab_is_selected_after_the_render(self):
        # Before it, there is nothing for the tab to show.
        block = self._app_js()
        block = block[block.index("function renderResults"):][:500]
        self.assertIn("pendingTab", block)

    def test_a_hidden_group_is_not_opened(self):
        # ?tab=hubspot on a site with no HubSpot would otherwise reveal a tab
        # the scan deliberately hid.
        block = self._app_js()
        block = block[block.index("function selectTab"):][:400]
        self.assertIn("tab-group.hidden", block)


class RemediationLinkTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "deep.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        importlib.reload(db_module).init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_the_remediation_page_links_with_both_parameters(self):
        body = self.client.get("/remediate/domain/example.com").data.decode()
        self.assertIn("domain=example.com", body)
        self.assertIn("tab=advies", body)

    def test_the_scan_page_accepts_those_parameters(self):
        self.assertEqual(
            self.client.get("/?domain=example.com&tab=advies").status_code, 200)

    def test_an_invalid_domain_is_still_refused(self):
        self.assertEqual(self.client.get("/remediate/domain/not a domain").status_code, 404)


if __name__ == "__main__":
    unittest.main()


class StoredScanTests(unittest.TestCase):
    """History moved to its own page, where there is nothing to render a scan
    into — Load simply did nothing. And re-scanning to read advice already on
    disk costs a minute of waiting plus another round of traffic at the domain.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "stored.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db as db_module
        import app as app_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        self.app_module = importlib.reload(app_module)
        self.client = self.app_module.app.test_client()
        self.scan_id = self.db.save_scan("example.com", {"domain": "example.com"})

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _app_js(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "js" / "app.js").read_text(encoding="utf-8")

    def test_load_hands_off_when_there_is_nowhere_to_render(self):
        block = self._app_js()
        block = block[block.index("async function loadScan"):][:600]
        self.assertIn("if (!$('domainInput'))", block)
        self.assertIn("'/?scan='", block)

    def test_the_scan_page_opens_a_stored_scan(self):
        block = self._app_js()
        block = block[block.index("function openFromQuery"):][:900]
        self.assertIn("params.get('scan')", block)
        self.assertIn("loadScan(stored)", block)

    def test_a_stored_scan_does_not_trigger_a_new_one(self):
        # The whole point is not re-running it.
        block = self._app_js()
        block = block[block.index("function openFromQuery"):][:900]
        stored = block.index("loadScan(stored)")
        start = block.index("startScan()")
        self.assertLess(stored, start)

    def test_the_remediation_page_offers_the_stored_scan_first(self):
        body = self.client.get("/remediate/domain/example.com").data.decode()
        self.assertIn(f"/?scan={self.scan_id}", body)
        self.assertIn("Open last scan", body)
        self.assertIn("Run a new scan", body)

    def test_the_stored_scan_carries_its_date(self):
        # "Open last scan" without a date is an invitation to read something
        # stale without knowing it.
        body = self.client.get("/remediate/domain/example.com").data.decode()
        self.assertIn("btn-sub", body)
        self.assertIn("UTC", body)

    def test_a_domain_without_a_scan_says_so(self):
        body = self.client.get("/remediate/domain/nothing.example").data.decode()
        self.assertIn("No stored scan for this domain yet", body)
        self.assertNotIn("Open last scan", body)

    def test_nothing_is_labelled_advies_any_more(self):
        # Internal word for the recommendations tab; meant nothing on a page
        # a registrar or a colleague might read.
        body = self.client.get("/remediate/domain/example.com").data.decode()
        self.assertNotIn("Advies", body)
