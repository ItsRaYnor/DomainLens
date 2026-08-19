import os
import pathlib
import tempfile
import unittest


class ResponsiveLayoutTests(unittest.TestCase):
    """Five section links plus admin plus a user chip cannot sit on one line
    of a phone. They wrapped into a stack of loose buttons above the menu,
    which read as chrome rather than navigation.
    """

    def _css(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "static" / "css" / "style.css").read_text(encoding="utf-8")

    def _nav(self):
        return (pathlib.Path(__file__).resolve().parent.parent
                / "templates" / "partials" / "nav.html").read_text(encoding="utf-8")

    def test_there_is_a_narrow_layout(self):
        self.assertIn("@media (max-width: 860px)", self._css())

    def test_the_menu_collapses_behind_a_toggle(self):
        css = self._css()
        self.assertIn(".nav-toggle-input:checked ~ .main-nav", css)
        self.assertIn(".nav-toggle-input:checked ~ .header-actions", css)

    def test_the_toggle_needs_no_javascript(self):
        # The menu is how you leave a page that is misbehaving; it must not
        # depend on a script having loaded.
        nav = self._nav()
        self.assertIn('type="checkbox"', nav)
        self.assertIn('for="navToggle"', nav)
        self.assertNotIn("onclick", nav)

    def test_the_toggle_is_reachable_by_keyboard(self):
        # The `hidden` attribute took it out of the tab order, which left the
        # menu openable by pointer only.
        self.assertNotIn('class="nav-toggle-input" hidden', self._nav())
        self.assertIn(".nav-toggle-input:focus-visible ~ .nav-toggle", self._css())

    def test_the_menu_reopens_on_a_wide_screen(self):
        # Otherwise a rotate leaves the navigation collapsed with no toggle.
        css = self._css()
        self.assertIn("@media (min-width: 861px)", css)

    def test_admin_links_travel_with_the_sections(self):
        # They used to sit above the menu as loose buttons on a phone.
        css = self._css()
        block = css[css.index("@media (max-width: 860px)"):][:2000]
        self.assertIn(".app-header .header-actions", block)

    def test_wide_tables_scroll_inside_their_own_box(self):
        css = self._css()
        block = css[css.index("@media (max-width: 860px)"):]
        self.assertIn("overflow-x: auto", block)

    def test_touch_targets_are_large_enough(self):
        css = self._css()
        self.assertIn("@media (pointer: coarse)", css)
        self.assertIn("min-height: 44px", css)

    def test_inputs_do_not_trigger_ios_zoom(self):
        # Anything under 16px makes Safari zoom the page on focus.
        css = self._css()
        block = css[css.index("@media (pointer: coarse)"):]
        self.assertIn("font-size: 16px", block)


class LoginPagePrivacyTests(unittest.TestCase):
    """The sign-in page answered questions nobody signing in has to ask: how
    long a password must be, which character classes it needs, whether MFA is
    required, whether a local account exists beside the SSO, and which tenant
    the directory belongs to.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ.update({
            "DOMAINLENS_DB": os.path.join(self.tempdir.name, "priv.db"),
            "DOMAINLENS_DISABLE_SCHEDULER": "1",
            "AUTH_LOCAL_ENABLED": "1",
            "AUTH_REQUIRE_LOGIN": "0",
            "DOMAINLENS_SECRET_KEY": "test-secret",
            "LOCAL_ADMIN_EMAIL": "admin@example.com",
            "LOCAL_ADMIN_PASSWORD": "Valid-Passw0rd!",
        })
        import importlib
        import auth
        import db
        import app
        from settings.store import get_store
        importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "AUTH_LOCAL_ENABLED",
                    "AUTH_REQUIRE_LOGIN", "DOMAINLENS_SECRET_KEY",
                    "LOCAL_ADMIN_EMAIL", "LOCAL_ADMIN_PASSWORD"):
            os.environ.pop(key, None)

    def test_the_password_policy_is_not_published(self):
        # It only helps the reader building a wordlist; someone signing in
        # already has a password.
        body = self.client.get("/login").data
        self.assertNotIn(b"Password policy", body)
        self.assertNotIn(b"min 12 chars", body)

    def test_whether_mfa_is_required_is_not_published(self):
        # It answers "is a stolen password enough on its own".
        body = self.client.get("/login").data
        self.assertNotIn(b"MFA required", body)
        self.assertNotIn(b"MFA available", body)

    def test_the_diagnostics_block_is_gone(self):
        body = self.client.get("/login").data
        for leak in (b"Local backup accounts", b"OAuth callback", b"SCIM:"):
            self.assertNotIn(leak, body, leak)

    def test_the_api_does_not_answer_it_either(self):
        # Removing it from the HTML alone would have been cosmetic.
        payload = self.client.get("/api/auth/me").get_json()
        self.assertFalse(payload["authenticated"])
        for private in ("password_policy", "mfa", "azure", "scim", "auth_methods"):
            self.assertNotIn(private, payload, private)

    def test_an_admin_still_gets_the_full_picture(self):
        self.client.post("/auth/local/login", data={
            "email": "admin@example.com", "password": "Valid-Passw0rd!"})
        payload = self.client.get("/api/auth/me").get_json()
        self.assertTrue(payload["authenticated"])
        self.assertIn("password_policy", payload)
        self.assertIn("mfa", payload)

    def test_the_sign_in_buttons_still_work(self):
        # Scoping the payload must not blank the page it feeds.
        body = self.client.get("/login").data
        self.assertIn(b"Sign in with local account", body)
        self.assertIn(b'name="password"', body)

    def test_the_policy_is_still_shown_where_it_is_needed(self):
        # On the change-password form, where the reader is choosing one.
        account = (pathlib.Path(__file__).resolve().parent.parent
                   / "templates" / "account.html").read_text(encoding="utf-8")
        self.assertIn("password_policy.min_length", account)


if __name__ == "__main__":
    unittest.main()
