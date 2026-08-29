import os
import pathlib
import tempfile
import unittest


class SectionRouteTests(unittest.TestCase):
    """Monitoring and History were buttons that slid a drawer over the scan
    page: no address to link to, no way back, no sign of where you were.
    Every section is a page now, so the back button, bookmarks and sharing
    all work.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "nav.db")
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

    def test_every_section_has_its_own_address(self):
        for path in ("/", "/tools/ip", "/tools/dns", "/tools/impersonation",
                     "/tools/disclosure", "/monitoring", "/reports", "/trends",
                     "/remediate"):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_the_current_section_is_marked(self):
        body = self.client.get("/monitoring").data.decode()
        self.assertIn('href="/monitoring" class="nav-item current"', body)
        self.assertIn('aria-current="page"', body)

    def test_only_one_section_is_current(self):
        body = self.client.get("/reports").data.decode()
        self.assertEqual(body.count('aria-current="page"'), 2)  # section + subnav

    def test_tool_pages_share_the_tools_section(self):
        for path in ("/tools/ip", "/tools/dns", "/tools/impersonation",
                     "/tools/disclosure"):
            body = self.client.get(path).data.decode()
            self.assertIn('href="/tools/ip" class="nav-item current"', body, path)

    def test_the_subnav_shares_the_content_width(self):
        """It centred on a 1200px track while the header and main use 960px,
        so the row of tools sat 120px left of everything under it."""
        import pathlib
        css = (pathlib.Path(__file__).resolve().parent.parent
               / "static" / "css" / "style.css").read_text(encoding="utf-8")
        block = css[css.index(".subnav {"):][:400]
        self.assertIn("max-width: 960px", block)
        self.assertNotIn("max-width: 1200px", block)

    def test_the_old_lookup_addresses_still_resolve(self):
        """They were linked and bookmarked before the tools grouping; a dead
        link is a worse outcome than an extra redirect."""
        for old, new in (("/lookup/ip", "/tools/ip"),
                         ("/lookup/dns", "/tools/dns"),
                         ("/lookup/impersonation", "/tools/impersonation"),
                         ("/lookup/pgp", "/tools/disclosure")):
            with self.subTest(old=old):
                resp = self.client.get(old)
                self.assertEqual(301, resp.status_code)
                self.assertTrue(resp.headers["Location"].endswith(new),
                                resp.headers["Location"])

    def test_the_scan_page_no_longer_carries_its_own_dns_lookup(self):
        """It is a tool and lives under Tools; a second copy on the scan page
        was a duplicate implementation drifting from the real one."""
        body = self.client.get("/").data.decode()
        self.assertNotIn("dnsLookupCard", body)
        self.assertNotIn('id="dnsLookupName"', body)

    def test_reports_and_trends_share_a_subnav(self):
        for path in ("/reports", "/trends"):
            body = self.client.get(path).data.decode()
            self.assertIn('class="subnav"', body, path)
            self.assertIn('href="/trends"', body, path)
            self.assertIn('href="/reports"', body, path)

    def test_remediation_is_reachable_from_the_menu(self):
        # /remediate/domain/<d> existed as a ServiceNow deep link only, so
        # the page could not be reached from the app at all.
        body = self.client.get("/").data.decode()
        self.assertIn('href="/remediate"', body)

    def test_the_monitoring_panel_renders_as_a_page_not_a_drawer(self):
        body = self.client.get("/monitoring").data.decode()
        self.assertIn('id="monitorsDrawer" class="page-panel"', body)
        self.assertNotIn('id="monitorsDrawer" class="drawer hidden"', body)

    def test_the_scan_page_no_longer_carries_the_drawers(self):
        body = self.client.get("/").data.decode()
        self.assertNotIn('id="monitorsDrawer"', body)
        self.assertNotIn('id="historyDrawer"', body)

    def test_there_is_a_skip_link(self):
        body = self.client.get("/").data.decode()
        self.assertIn('class="skip-link"', body)
        self.assertIn('id="main"', body)


class TabGroupingTests(unittest.TestCase):
    """Ten flat tabs implied ten equally important views. Findings is the one
    you almost always want; HubSpot is one almost nobody wants."""

    def _index(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "templates" / "index.html").read_text(encoding="utf-8")

    def test_tabs_are_grouped(self):
        body = self._index()
        for key in ("tabs.findings", "tabs.registration", "tabs.transport",
                    "tabs.signals", "tabs.platform"):
            self.assertIn(key, body, key)

    def test_findings_is_first_and_open(self):
        body = self._index()
        findings = body.index("tabs.findings")
        registration = body.index("tabs.registration")
        self.assertLess(findings, registration)
        self.assertIn('class="tab active" data-tab="recommendations"', body)

    def test_the_platform_group_starts_hidden(self):
        # An always-empty tab reads as "we looked and found nothing wrong"
        # rather than "this does not apply here".
        self.assertIn('class="tab-group hidden" id="tabGroupPlatform"', self._index())

    def test_every_original_tab_survives(self):
        body = self._index()
        for tab in ("recommendations", "whois", "dns", "email", "ssl", "web",
                    "network", "osint", "hubspot", "rapid7", "security"):
            self.assertIn(f'data-tab="{tab}"', body, tab)


class PlatformVisibilityTests(unittest.TestCase):
    """The Platform group only means something on a specific stack."""

    def _app_js(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "js" / "app.js").read_text(encoding="utf-8")

    def test_detection_covers_hubspot_cloudflare_and_the_cdn(self):
        block = self._app_js()
        block = block[block.index("function platformDetected"):][:800]
        self.assertIn("hubspot", block)
        self.assertIn("cloudflare", block)
        self.assertIn("cdn", block)

    def test_a_generic_cdn_does_not_count_as_a_platform(self):
        block = self._app_js()
        block = block[block.index("function platformDetected"):][:800]
        self.assertIn("'generic'", block)

    def test_hiding_the_group_moves_the_reader_somewhere_real(self):
        # Leaving the reader on a tab that just disappeared shows an empty
        # results pane with no explanation.
        block = self._app_js()
        block = block[block.index("function syncPlatformGroup"):][:600]
        self.assertIn('data-tab="recommendations"', block)

    def test_it_runs_on_every_render(self):
        block = self._app_js()
        block = block[block.index("function renderResults"):][:300]
        self.assertIn("syncPlatformGroup(data)", block)


class SharedNavTests(unittest.TestCase):
    """One navigation, so a new section is added once rather than in every
    page's own hand-rolled header."""

    def _templates(self):
        root = pathlib.Path(__file__).resolve().parent.parent / "templates"
        return {p.name: p.read_text(encoding="utf-8") for p in root.glob("*.html")}

    def test_the_main_pages_use_the_shared_partial(self):
        for name in ("index.html", "trends.html", "monitoring.html", "reports.html",
                     "lookup_ip.html", "lookup_dns.html", "lookup_impersonation.html",
                     "remediate_index.html"):
            self.assertIn('include "partials/nav.html"', self._templates()[name], name)

    def test_no_page_still_hand_rolls_a_header(self):
        for name, body in self._templates().items():
            if name in ("login.html", "mfa.html", "report.html"):
                continue  # standalone pages, deliberately without the app chrome
            self.assertNotIn("<header>\n", body, name)



class IpInTheSearchBoxTests(unittest.TestCase):
    """The scan pipeline rejects an address with "Invalid domain name", so
    typing one in the search box - a reasonable thing to do when the tool
    also looks up addresses - produced an error instead of an answer.
    """

    def _app_js(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "js" / "app.js").read_text(encoding="utf-8")

    def _lookup_js(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "js" / "lookup.js").read_text(encoding="utf-8")

    def test_an_address_is_handed_to_the_lookup(self):
        block = self._app_js()
        block = block[block.index("async function startScan"):][:900]
        self.assertIn("looksLikeIp(domain)", block)
        self.assertIn("/tools/ip?ip=", block)

    def test_the_check_runs_before_the_scan_starts(self):
        # After the request would be too late: the API has already refused it.
        block = self._app_js()
        start = block.index("async function startScan")
        scan_call = block.index("/api/scan/start", start)
        redirect = block.index("/tools/ip?ip=", start)
        self.assertLess(redirect, scan_call)

    def test_ipv4_and_ipv6_are_both_recognised(self):
        block = self._app_js()
        block = block[block.index("function looksLikeIp"):][:600]
        self.assertIn("255", block)          # octet bound
        self.assertIn("includes(':')", block)  # v6

    def test_the_lookup_page_runs_what_it_was_handed(self):
        block = self._lookup_js()
        block = block[block.index("const ipBtn"):][:700]
        self.assertIn("URLSearchParams", block)
        self.assertIn("ipLookup()", block)


if __name__ == "__main__":
    unittest.main()
