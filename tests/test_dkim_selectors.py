import os
import unittest
from unittest import mock


class DkimSelectorValidationTests(unittest.TestCase):
    """Regression tests for user-supplied custom DKIM selectors: the
    A production case showed the tool's default selector list missed the
    domain's real selectors (Zoho's "zmail", Resend's "resend"), so a user
    needs a way to add their own without an admin-settings change.
    """

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        cls.app = app

    def test_accepts_valid_selectors(self):
        result = self.app._prepare_dkim_selectors(["zmail", "resend", "my-selector.01"])
        self.assertEqual(result, ["zmail", "resend", "my-selector.01"])

    def test_rejects_invalid_characters(self):
        result = self.app._prepare_dkim_selectors(["zmail; rm -rf /", "ok_one", "has space"])
        self.assertEqual(result, ["ok_one"])

    def test_deduplicates(self):
        result = self.app._prepare_dkim_selectors(["zmail", "zmail", "resend"])
        self.assertEqual(result, ["zmail", "resend"])

    def test_caps_at_ten(self):
        result = self.app._prepare_dkim_selectors([f"sel{i}" for i in range(20)])
        self.assertEqual(len(result), 10)

    def test_rejects_overlong_selector(self):
        result = self.app._prepare_dkim_selectors(["a" * 64, "ok"])
        self.assertEqual(result, ["ok"])

    def test_non_list_input_returns_empty(self):
        self.assertEqual(self.app._prepare_dkim_selectors("not-a-list"), [])
        self.assertEqual(self.app._prepare_dkim_selectors(None), [])

    def test_non_string_items_are_dropped(self):
        result = self.app._prepare_dkim_selectors(["zmail", 123, None, {"a": 1}])
        self.assertEqual(result, ["zmail"])

    def test_check_dkim_extra_selectors_merge_not_replace(self):
        def fake_resolve(name, rtype):
            if name.startswith("zmail.") or name.startswith("default."):
                return ['"v=DKIM1; k=rsa; p=xxx"']
            return []

        with mock.patch("app._resolve", side_effect=fake_resolve), \
             mock.patch("app._dkim_selectors_list", return_value=["default", "google"]):
            result = self.app.check_dkim("example.com", extra_selectors=["zmail", "resend"])

        matched = sorted(s["selector"] for s in result["selectors"])
        self.assertEqual(matched, ["default", "zmail"])
        self.assertTrue(result["found"])

    def test_check_dkim_extra_selectors_deduplicated_against_base(self):
        calls = []

        def fake_resolve(name, rtype):
            calls.append(name)
            return []

        with mock.patch("app._resolve", side_effect=fake_resolve), \
             mock.patch("app._dkim_selectors_list", return_value=["default", "zmail"]):
            self.app.check_dkim("example.com", extra_selectors=["zmail", "resend"])

        # "zmail" should only be queried once even though it's in both the
        # base list and the extra selectors.
        zmail_calls = [c for c in calls if c.startswith("zmail.")]
        self.assertEqual(len(zmail_calls), 1)


class BuiltInSelectorTests(unittest.TestCase):
    """A domain on OVHcloud's hosted mail signs with ovhmo-selector-1/-2.
    None of the probed names matched, so a signed domain was reported as
    having no DKIM at all -- a defect the domain did not have.
    """

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        cls.app = app

    def _signed_by_ovh(self, name, rtype):
        if name.startswith("ovhmo-selector-1.") or name.startswith("ovhmo-selector-2."):
            return ['"v=DKIM1; k=rsa; p=MIIBIjANBgkq"']
        return []

    def test_an_ovh_signed_domain_is_found_without_any_configuration(self):
        with mock.patch("app._resolve", side_effect=self._signed_by_ovh), \
             mock.patch("app._scan_config", return_value={}):
            result = self.app.check_dkim("example.com")

        self.assertTrue(result["found"])
        self.assertEqual(sorted(s["selector"] for s in result["selectors"]),
                         ["ovhmo-selector-1", "ovhmo-selector-2"])

    def test_a_saved_scan_section_does_not_freeze_out_new_built_in_selectors(self):
        # Saving any scan setting stores the selector list of that moment.
        # Such an installation must still probe selectors added afterwards.
        saved = {"dkim_selectors": ["default", "google", "selector1"]}
        with mock.patch("app._resolve", side_effect=self._signed_by_ovh), \
             mock.patch("app._scan_config", return_value=saved):
            result = self.app.check_dkim("example.com")

        self.assertTrue(result["found"])

    def test_configured_selectors_are_still_probed_and_not_repeated(self):
        with mock.patch("app._scan_config",
                        return_value={"dkim_selectors": ["default", " corp2024 ", "corp2024"]}):
            selectors = self.app._dkim_selectors_list()

        self.assertIn("corp2024", selectors)
        self.assertEqual(selectors.count("corp2024"), 1)
        self.assertEqual(selectors.count("default"), 1)


if __name__ == "__main__":
    unittest.main()
