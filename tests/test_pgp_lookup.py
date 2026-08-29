"""The manual counterpart to the scan's security.txt check.

Checking a key used to be possible only by running a full domain scan and
reading the findings. This is the same parsing and the same three key states,
aimed at one domain on demand -- which is how you check your own after
publishing it.
"""

import os
import tempfile
import unittest
from unittest import mock

import security_checks as s


PUBLIC_KEY = ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBGa\n"
              "-----END PGP PUBLIC KEY BLOCK-----\n")

SECURITY_TXT = ("Contact: mailto:security@example.com\n"
                "Expires: 2027-01-01T00:00:00Z\n"
                "Encryption: https://example.com/key.asc\n")

SOFT_404 = "<!DOCTYPE html><html><body>Not found</body></html>"


def _resp(body, status=200):
    return mock.Mock(status_code=status, text=body, content=body.encode())


class InspectSecurityTxtTests(unittest.TestCase):
    def test_a_published_file_is_parsed_and_its_key_followed(self):
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=[_resp(SECURITY_TXT),
                                                       _resp(PUBLIC_KEY)]):
            result = s.inspect_security_txt("example.com")
        self.assertTrue(result["found"])
        self.assertEqual(["mailto:security@example.com"], result["fields"]["contact"])
        self.assertEqual("measured", result["key"]["state"])
        self.assertTrue(result["key"]["armored"])

    def test_https_is_tried_before_http(self):
        """A security.txt fetched over plain http can be rewritten in transit,
        and the contact address is the thing an attacker would change."""
        calls = []

        def record(url, **kwargs):
            calls.append(url)
            return _resp(SECURITY_TXT)

        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=record):
            s.inspect_security_txt("example.com")
        self.assertTrue(calls[0].startswith("https://"), calls)

    def test_a_soft_404_html_page_is_not_a_security_txt(self):
        """A 200 that returns the site's HTML error page would otherwise be
        reported as a published policy that does not exist."""
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", return_value=_resp(SOFT_404)):
            result = s.inspect_security_txt("example.com")
        self.assertFalse(result["found"])

    def test_a_file_without_a_contact_field_is_not_accepted(self):
        """Contact is mandatory in RFC 9116; without it there is nothing to
        act on, and calling it "found" overstates what is published."""
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", return_value=_resp("Expires: 2027-01-01T00:00:00Z\n")):
            result = s.inspect_security_txt("example.com")
        self.assertFalse(result["found"])

    def test_a_404_is_reported_as_absent_not_as_an_error(self):
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", return_value=_resp("nope", status=404)):
            result = s.inspect_security_txt("example.com")
        self.assertFalse(result["found"])
        self.assertIsNone(result["error"])
        self.assertEqual(404, result["status"])

    def test_an_unreachable_host_is_an_error_not_an_absent_file(self):
        """"They publish nothing" and "we could not look" are different
        answers, and only one of them is about the domain."""
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=OSError("boom")):
            result = s.inspect_security_txt("example.com")
        self.assertFalse(result["found"])
        self.assertIn("Could not reach", result["error"])

    def test_a_private_address_is_never_fetched(self):
        with mock.patch.object(s, "_safe_host", return_value=False), \
             mock.patch.object(s, "_get") as get:
            result = s.inspect_security_txt("internal.example")
        get.assert_not_called()
        self.assertIn("public address", result["error"])


class PgpInspectEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "pgp.db")
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

    def test_an_invalid_domain_is_refused(self):
        resp = self.client.get("/api/pgp/inspect?domain=not a domain")
        self.assertEqual(400, resp.status_code)

    def test_a_result_reaches_the_caller(self):
        with mock.patch.object(self.app_module.security_checks, "inspect_security_txt",
                               return_value={"found": True, "domain": "example.com"}):
            body = self.client.get("/api/pgp/inspect?domain=example.com").get_json()
        self.assertTrue(body["found"])

    def test_it_shares_the_dns_lookup_rate_limit(self):
        """It makes outbound requests for whoever can reach the page, so it
        cannot be the one endpoint that runs unmetered."""
        with mock.patch.object(self.app_module, "_check_rate_limit",
                               return_value=False) as limiter:
            resp = self.client.get("/api/pgp/inspect?domain=example.com")
        self.assertEqual(429, resp.status_code)
        self.assertEqual("dns_lookup", limiter.call_args.kwargs["bucket"])

    def test_the_page_is_in_the_lookup_subnav(self):
        """A tool nothing links to is a tool nobody finds."""
        body = self.client.get("/tools/dns").get_data(as_text=True)
        self.assertIn('href="/tools/disclosure"', body)

    def test_the_page_renders(self):
        resp = self.client.get("/tools/disclosure")
        self.assertEqual(200, resp.status_code)
        self.assertIn("security.txt", resp.get_data(as_text=True))



class DisclosureUiPlacementTests(unittest.TestCase):
    """Where the two halves of this feature live.

    Generation and the security.txt settings are one feature. Split across a
    settings tab and a card floating at the bottom of the page, they read as
    two, and the card showed under every unrelated tab.
    """

    def _read(self, *parts):
        import pathlib
        return (pathlib.Path(__file__).resolve().parent.parent
                .joinpath(*parts).read_text(encoding="utf-8"))

    def test_the_key_block_is_moved_into_the_disclosure_panel(self):
        js = self._read("static", "js", "admin_settings.js")
        self.assertIn("panel-disclosure", js)
        self.assertIn("disclosurePanel.appendChild(keyCard)", js)

    def test_the_settings_section_is_registered_for_the_admin_form(self):
        from settings.registry import ADMIN_SECTIONS, FIELD_META
        self.assertIn("disclosure", ADMIN_SECTIONS)
        self.assertIn("disclosure", FIELD_META)

    def test_the_key_fields_are_not_free_text_editable(self):
        """A public key comes from generation or an explicit paste, never
        from a settings textarea, and the fingerprint must keep describing
        the key it belongs to."""
        from settings.registry import FIELD_META
        for key in ("pgp_public_key", "pgp_fingerprint", "pgp_uid"):
            self.assertNotIn(key, FIELD_META["disclosure"])

    def test_the_section_and_nav_labels_are_translated(self):
        import json
        for locale in ("en", "nl"):
            with self.subTest(locale=locale):
                data = json.loads(self._read("i18n", "locales", f"{locale}.json"))
                self.assertIn("disclosure", data["settings"]["sections"])
                self.assertIn("lookup_pgp", data["nav"])
                self.assertIn("disclosure", data["settings"])

    def test_every_disclosure_field_has_a_label_in_both_locales(self):
        import json
        from settings.registry import FIELD_META
        for locale in ("en", "nl"):
            data = json.loads(self._read("i18n", "locales", f"{locale}.json"))
            labels = data["settings"]["disclosure"]
            for key in FIELD_META["disclosure"]:
                with self.subTest(locale=locale, key=key):
                    self.assertIn(key, labels)


class SettingsFieldOrderTests(unittest.TestCase):
    """The schema is serialised with sorted keys, so the form rendered every
    section alphabetically: the mandatory contact field landed third and the
    on/off switch fourth. The registry's order is the designed one."""

    def _read(self, *parts):
        import pathlib
        return (pathlib.Path(__file__).resolve().parent.parent
                .joinpath(*parts).read_text(encoding="utf-8"))

    def test_the_schema_carries_an_explicit_order(self):
        self.assertIn('"order": list((FIELD_META.get(section) or {}).keys())',
                      self._read("settings", "store.py"))

    def test_the_form_renders_in_that_order(self):
        js = self._read("static", "js", "admin_settings.js")
        self.assertIn("sec.order", js)

    def test_a_field_missing_from_the_order_is_still_rendered(self):
        """Falling back matters: a new field added to FIELD_META but not to
        the order must not vanish from the page."""
        js = self._read("static", "js", "admin_settings.js")
        self.assertIn("if (!keys.includes(k)) keys.push(k)", js)

    def test_disclosure_starts_with_the_switch_then_the_mandatory_field(self):
        from settings.registry import FIELD_META
        order = list(FIELD_META["disclosure"].keys())
        self.assertEqual(["enabled", "contact"], order[:2])


class ToolEndpointTests(unittest.TestCase):
    """The tools operate on what you paste. Nothing is fetched, nothing is
    stored, and the generator here keeps neither half -- that is what makes
    it a tool rather than a configuration step."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "tools.db")
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

    def test_a_valid_security_txt_validates(self):
        body = "Contact: mailto:a@example.com\nExpires: 2099-01-01T00:00:00Z\n"
        result = self.client.post("/api/pgp/validate-securitytxt",
                                  json={"body": body}).get_json()
        self.assertTrue(result["valid"], result["errors"])

    def test_an_invalid_security_txt_reports_why(self):
        result = self.client.post("/api/pgp/validate-securitytxt",
                                  json={"body": "nothing useful"}).get_json()
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])

    def test_an_absurdly_large_paste_is_refused(self):
        resp = self.client.post("/api/pgp/validate-securitytxt",
                                json={"body": "x" * 200_000})
        self.assertEqual(400, resp.status_code)

    def test_the_key_validator_reports_a_private_key(self):
        private = ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nx\n"
                   "-----END PGP PRIVATE KEY BLOCK-----\n")
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=True), \
             mock.patch.object(self.app_module.pgp_keys, "inspect_key",
                               return_value={"valid": True, "is_private": True,
                                             "keys": [], "error": None}) as inspect:
            body = self.client.post("/api/pgp/validate-key",
                                    json={"key": private}).get_json()
        self.assertTrue(inspect.called)
        self.assertTrue(body["is_private"])

    def test_the_key_validator_answers_without_gpg_where_it_can(self):
        """It used to refuse with a 503 before looking at the input, so
        someone who had pasted a signature was told gpg was missing and went
        after the wrong problem. Telling a signature from a key needs no gpg."""
        sig = "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n"
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=False):
            resp = self.client.post("/api/pgp/validate-key", json={"key": sig})
        self.assertEqual(200, resp.status_code)
        body = resp.get_json()
        self.assertFalse(body["valid"])
        self.assertIn("signature", body["error"])

    def test_a_real_key_without_gpg_reports_the_missing_tool(self):
        key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n"
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=False):
            body = self.client.post("/api/pgp/validate-key", json={"key": key}).get_json()
        self.assertFalse(body["valid"])
        self.assertIn("gpg is not installed", body["error"])

    def test_the_generator_still_needs_gpg_and_says_how_to_get_it(self):
        """Generation genuinely cannot proceed, so this one keeps its 503 --
        but names the package rather than just the absence."""
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=False):
            resp = self.client.post("/api/pgp/generate",
                                    json={"name": "T", "email": "t@example.com"})
        self.assertEqual(503, resp.status_code)
        error = resp.get_json()["error"]
        self.assertIn("GnuPG", error)
        self.assertIn("Docker image", error)

    def test_the_tool_generator_stores_nothing(self):
        """The distinction from the settings generator: this one is for a
        domain that is not this installation, so nothing is persisted."""
        fake = {"fingerprint": "A" * 40, "uid": "T <t@example.com>",
                "public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
                "private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n",
                "expiry": "2y", "protected": False}
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=True), \
             mock.patch.object(self.app_module.pgp_keys, "generate", return_value=fake):
            resp = self.client.post("/api/pgp/generate",
                                    json={"name": "T", "email": "t@example.com"})
        self.assertEqual(201, resp.status_code)
        section = self.app_module._settings_store.section("disclosure", force_reload=True)
        self.assertEqual("", section["pgp_public_key"])
        self.assertEqual("", section["pgp_fingerprint"])

    def test_the_tool_generator_returns_both_halves(self):
        fake = {"fingerprint": "A" * 40, "uid": "T <t@example.com>",
                "public_key": "PUB", "private_key": "PRIV",
                "expiry": "2y", "protected": False}
        with mock.patch.object(self.app_module.pgp_keys, "available", return_value=True), \
             mock.patch.object(self.app_module.pgp_keys, "generate", return_value=fake):
            body = self.client.post("/api/pgp/generate",
                                    json={"name": "T", "email": "t@example.com"}).get_json()
        self.assertEqual("PUB", body["public_key"])
        self.assertEqual("PRIV", body["private_key"])
        self.assertIn("is stored", body["warning"])

    def test_the_tool_generator_is_rate_limited(self):
        """Key generation costs CPU, and this endpoint needs no admin role."""
        with mock.patch.object(self.app_module, "_check_rate_limit",
                               return_value=False) as limiter:
            resp = self.client.post("/api/pgp/generate", json={"name": "T", "email": "t@e.co"})
        self.assertEqual(429, resp.status_code)
        self.assertEqual("dns_lookup", limiter.call_args.kwargs["bucket"])

    def test_all_four_tools_are_on_the_page(self):
        body = self.client.get("/tools/disclosure").get_data(as_text=True)
        for element in ("pgpLookupBtn", "stxtValidateBtn", "pgpKeyValidateBtn", "genBtn"):
            with self.subTest(element=element):
                self.assertIn(element, body)

if __name__ == "__main__":
    unittest.main()
