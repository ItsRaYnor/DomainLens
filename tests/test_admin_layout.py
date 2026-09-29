"""Where things sit on the admin pages.

The organisation features added pages and settings faster than the layout
kept up: the settings an admin came for started ~3000px down the page,
notification credentials sat 2000px away from their own switch, a dead
"Retention (days)" field contradicted the real retention setting, and the
header repeated the admin sub-navigation with the wrong entry lit up.
"""

from enterprise_harness import EnterpriseAppTestCase


class SettingsPageTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.login_as("admin")
        self.html = self.client.get("/admin/settings").get_data(as_text=True)

    def test_the_settings_come_before_the_credential_cards(self):
        """The tabs were rendered under API keys, credentials, version and
        backup, so the page opened on none of the settings themselves."""
        self.assertLess(self.html.index('id="settingsNav"'),
                        self.html.index('data-section="api_keys"'))

    def test_every_credential_group_has_a_settings_tab_to_live_in(self):
        """A group without a tab stays behind in the separate card, far from
        the switch it serves -- the split this layout exists to end."""
        from settings import api_keys
        schema = self.app_module._settings_store.admin_form_schema()
        for group in api_keys.credential_status(db=self.db):
            with self.subTest(group=group["group"]):
                self.assertIn(group["section"], schema["sections"])
                self.assertIn(f'data-section="{group["section"]}"', self.html)

    def test_the_page_no_longer_claims_secrets_are_environment_only(self):
        """It said so at the top of a page whose next card stores them."""
        self.assertNotIn("remain in environment variables only", self.html)
        self.assertNotIn("stay environment-only by design", self.html)

    def test_every_loose_block_has_a_tab_to_move_into(self):
        """API keys, version and backup sat as cards under the tabs, so the
        page had a second, unlabelled menu below the first. Each is now
        tagged for a tab; a tag naming no tab would drop it from the page."""
        import re
        from settings.registry import SETTING_CATEGORIES
        tabs = {s for c in SETTING_CATEGORIES for s in c["sections"]}
        tagged = re.findall(r'class="[^"]*settings-panel-extra[^"]*"[^>]*data-section="([a-z_]+)"',
                            " ".join(self.html.split()))
        self.assertTrue({"api_keys", "updates", "retention"} <= set(tagged), tagged)
        self.assertEqual(sorted(set(tagged) - tabs), [])

    def test_the_api_keys_are_a_tab_under_integrations(self):
        from settings.registry import SETTING_CATEGORIES
        integrations = next(c for c in SETTING_CATEGORIES
                            if c["key"] == "settings.categories.integrations")
        self.assertIn("api_keys", integrations["sections"])

    def test_the_ownership_tab_links_to_the_verified_domains_page(self):
        self.assertIn('<a href="/admin/domains">', self.html)


class DeadRetentionSettingTests(EnterpriseAppTestCase):
    def test_reporting_offers_no_retention_field_that_does_nothing(self):
        """reporting.retention_days showed 365 beside the real Retention tab,
        which keeps everything by default: an admin read it as data being
        removed after a year while nothing was ever removed."""
        schema = self.app_module._settings_store.admin_form_schema()
        self.assertNotIn("retention_days", schema["sections"]["reporting"]["fields"])
        self.assertIn("scan_days", schema["sections"]["retention"]["fields"])


class HeaderTests(EnterpriseAppTestCase):
    def test_the_header_has_one_admin_entry_not_a_copy_of_the_subnav(self):
        """Settings and Users buttons repeated the sub-navigation below them,
        and Settings looked selected on the Users and Audit log pages too."""
        self.login_as("admin")
        html = self.client.get("/admin/audit").get_data(as_text=True)
        header = html[:html.index('class="subnav-wrap"')]
        self.assertEqual(1, header.count('href="/admin/'))
        self.assertIn('href="/admin/settings"', header)


class PageOrderTests(EnterpriseAppTestCase):
    def test_accepting_a_risk_comes_before_the_list(self):
        """The form sat under an empty table with nothing saying it was how
        a risk gets accepted."""
        self.login_as("admin")
        html = self.client.get("/admin/risks").get_data(as_text=True)
        self.assertLess(html.index('action="/admin/risks"'), html.index('class="users-table"'))

    def test_the_user_list_comes_before_the_create_form(self):
        self.login_as("admin")
        html = self.client.get("/admin/users").get_data(as_text=True)
        self.assertLess(html.index('data-i18n="admin.existing_users"'),
                        html.index('data-i18n="admin.create_user"'))

    def test_verified_domains_tells_an_admin_where_the_expiry_is_set(self):
        self.login_as("admin")
        html = self.client.get("/admin/domains").get_data(as_text=True)
        self.assertIn('href="/admin/settings#ownership"', html)
