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


if __name__ == "__main__":
    unittest.main()
