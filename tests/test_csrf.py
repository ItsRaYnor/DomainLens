import importlib
import os
import tempfile
import unittest


class CrossSiteWriteTests(unittest.TestCase):
    """Any web page a DomainLens user opened could make their browser post to
    DomainLens: add monitors, change settings, revoke tokens. SameSite=Lax
    does not cover a sibling subdomain, older browsers, or an installation
    with login switched off, where there is no cookie at all and the request
    simply works. A write has to show that it came from DomainLens's own page.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "csrf.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import db as db_module
        import app as app_module
        importlib.reload(db_module).init_db()
        self.module = importlib.reload(app_module)
        self.reached = []

        @self.module.app.route("/__write", methods=["GET", "POST", "DELETE"])
        def write():
            self.reached.append(True)
            return "ok"

        @self.module.app.route("/auth/saml/__acs_probe", methods=["POST"])
        def not_exempt():
            self.reached.append(True)
            return "ok"

        self.client = self.module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def _post(self, path="/__write", method="post", **headers):
        return getattr(self.client, method)(path, headers=headers, base_url="http://lens.example.com")

    def test_a_post_another_site_made_the_browser_send_is_refused(self):
        resp = self._post(**{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.net"})
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(self.reached, [], "the view ran despite the refusal")

    def test_a_sibling_subdomain_is_refused_although_samesite_lets_its_cookie_through(self):
        resp = self._post(**{"Sec-Fetch-Site": "same-site", "Origin": "https://blog.example.com"})
        self.assertEqual(resp.status_code, 403)

    def test_delete_is_guarded_like_post(self):
        resp = self._post(method="delete", **{"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(resp.status_code, 403)

    def test_without_sec_fetch_a_foreign_origin_is_refused(self):
        # Browsers that predate Sec-Fetch-* still send Origin on a POST.
        resp = self._post(Origin="https://evil.example.net")
        self.assertEqual(resp.status_code, 403)

    def test_an_opaque_null_origin_is_refused(self):
        # A sandboxed iframe or a data: page reports Origin: null.
        resp = self._post(Origin="null")
        self.assertEqual(resp.status_code, 403)

    def test_without_origin_a_foreign_referer_is_refused(self):
        resp = self._post(Referer="https://evil.example.net/page")
        self.assertEqual(resp.status_code, 403)

    def test_domainlens_own_pages_can_still_write(self):
        for headers in ({"Sec-Fetch-Site": "same-origin", "Origin": "http://lens.example.com"},
                        {"Origin": "http://lens.example.com"},
                        {"Referer": "http://lens.example.com/monitoring"}):
            with self.subTest(headers=headers):
                self.assertEqual(self._post(**headers).status_code, 200)

    def test_https_at_the_proxy_does_not_lock_out_the_app_behind_it(self):
        # TLS ends at the proxy: the app sees http, the browser reports https.
        resp = self._post(Origin="https://lens.example.com")
        self.assertEqual(resp.status_code, 200)

    def test_the_configured_public_url_counts_as_own_origin(self):
        # A proxy that rewrites Host: the app sees an internal name.
        import csrf
        with self.module.app.test_request_context(
                "/__write", method="POST", base_url="http://domainlens:5000",
                headers={"Origin": "https://lens.example.com"}):
            self.assertIsNotNone(csrf.check(""))
            self.assertIsNone(csrf.check("https://lens.example.com/"))

    def test_reads_are_not_affected(self):
        resp = self.client.get("/__write", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(resp.status_code, 200)

    def test_api_clients_with_their_own_credential_are_not_refused(self):
        # A browser never adds Authorization to a cross-site request itself.
        resp = self._post(Authorization="Bearer something", Origin="https://ci.example.net")
        self.assertNotEqual(resp.status_code, 403)

    def test_scripts_without_browser_headers_are_not_refused(self):
        self.assertEqual(self._post().status_code, 200)

    def test_the_identity_provider_can_still_post_the_saml_assertion(self):
        import csrf
        with self.module.app.test_request_context(
                "/auth/saml/acs", method="POST",
                headers={"Sec-Fetch-Site": "cross-site", "Origin": "https://idp.example.net"}):
            self.assertIsNone(csrf.check(""))

    def test_the_saml_exemption_is_that_one_path_not_everything_under_auth(self):
        resp = self._post("/auth/saml/__acs_probe", **{"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(resp.status_code, 403)

    def test_a_cross_site_login_post_is_refused(self):
        # Login CSRF: signing the victim in to the attacker's account.
        resp = self._post("/auth/local/login", **{"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
