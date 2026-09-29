"""New hosts the scans already saw, surfaced as monitors to add.

Every scan reads Certificate Transparency and lists the names certificates
were issued for, then that list was shown once and forgotten. A host stood up
last month stayed unmonitored until someone compared the lists by eye.
"""

from enterprise_harness import EnterpriseAppTestCase


def _scan_with_ct(hosts):
    return {"domain": "example.com",
            "osint": {"certificate_transparency": {"subdomains": hosts}},
            "security": {"subdomains": {"subdomains": ["example.com"]}}}


class DiscoveryTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.db.create_monitor(
            name="apex", domain="example.com", target="example.com", record_type="A",
            record_value=None, source_type="manual", source_label="m", provider="manual",
            schedule_minutes=1440, checks=["all"], enabled=True, metadata={})

    def _suggested(self):
        import discovery
        return [s["host"] for s in discovery.suggestions(self.db)]

    def test_a_saved_scan_is_read_once_not_on_every_page_load(self):
        """The Monitoring page parsed the full latest scan of every monitored
        zone on each load; a saved scan never changes, so once is enough."""
        from unittest import mock
        self.db.save_scan("example.com", _scan_with_ct(["new-portal.example.com"]))
        with mock.patch.object(self.db, "get_scan", wraps=self.db.get_scan) as get_scan:
            for _ in range(3):
                self.assertEqual(["new-portal.example.com"], self._suggested())
        self.assertEqual(1, get_scan.call_count)

    def test_a_newer_scan_is_picked_up(self):
        self.db.save_scan("example.com", _scan_with_ct(["one.example.com"]))
        self.assertEqual(["one.example.com"], self._suggested())
        self.db.save_scan("example.com", _scan_with_ct(["two.example.com"]))
        self.assertEqual(["two.example.com"], self._suggested())

    def test_an_unmonitored_ct_name_is_suggested(self):
        self.db.save_scan("example.com", _scan_with_ct(["new-portal.example.com"]))
        self.assertEqual(["new-portal.example.com"], self._suggested())

    def test_a_monitored_name_is_not(self):
        self.db.save_scan("example.com", _scan_with_ct(["example.com"]))
        self.assertEqual([], self._suggested())

    def test_a_lookalike_outside_the_zone_is_not(self):
        """crt.sh matches by suffix; badexample.com is not our zone."""
        self.db.save_scan("example.com", _scan_with_ct(["badexample.com", "x.badexample.com"]))
        self.assertEqual([], self._suggested())

    def test_a_wildcard_is_reduced_to_its_base_name(self):
        self.db.save_scan("example.com", _scan_with_ct(["*.shop.example.com"]))
        self.assertEqual(["shop.example.com"], self._suggested())

    def test_an_analyst_adds_it_as_a_monitor(self):
        self.db.save_scan("example.com", _scan_with_ct(["new-portal.example.com"]))
        self.login_as("user")
        self.client.post("/monitoring/discovered",
                         data={"host": "new-portal.example.com", "zone": "example.com"})
        targets = [m["target"] for m in self.db.list_monitors()]
        self.assertIn("new-portal.example.com", targets)
        self.assertEqual([], self._suggested())

    def test_a_name_that_was_never_seen_cannot_be_added_this_way(self):
        """The form must not become a way to monitor arbitrary domains
        that skips the normal monitor form's checks."""
        self.login_as("user")
        self.client.post("/monitoring/discovered",
                         data={"host": "stranger.example", "zone": "example.com"})
        self.assertNotIn("stranger.example", [m["target"] for m in self.db.list_monitors()])

    def test_the_monitoring_page_lists_them(self):
        self.db.save_scan("example.com", _scan_with_ct(["new-portal.example.com"]))
        self.login_as("viewer")
        page = self.client.get("/monitoring").get_data(as_text=True)
        self.assertIn("new-portal.example.com", page)
        self.assertNotIn('action="/monitoring/discovered"', page,
                         "a viewer is shown a button that can only fail")
