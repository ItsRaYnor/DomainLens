import unittest
from unittest import mock

import auth


class OtpauthQrTests(unittest.TestCase):
    """Enrolling meant copying a long otpauth:// string into a phone by hand.
    People get that wrong once and then stop bothering with MFA, which is the
    worst possible outcome for a feature that exists to be used.
    """

    def _uri(self):
        return auth.otpauth_uri("JBSWY3DPEHPK3PXP", "someone@example.com")

    def test_a_qr_is_produced(self):
        svg = auth.otpauth_qr_svg(self._uri())
        self.assertIsNotNone(svg)
        self.assertIn("<svg", svg)
        self.assertIn("<path", svg)

    def test_it_embeds_in_html(self):
        # An XML declaration mid-document is not valid HTML and browsers
        # render it as text.
        svg = auth.otpauth_qr_svg(self._uri())
        self.assertFalse(svg.lstrip().startswith("<?xml"))

    def test_the_colours_are_fixed_not_theme_dependent(self):
        # A dark QR on a dark background does not scan, and a code that
        # renders but cannot be read is worse than no code.
        svg = auth.otpauth_qr_svg(self._uri())
        self.assertIn('fill="#ffffff"', svg)
        self.assertIn('fill="#000000"', svg)

    def test_the_secret_is_actually_encoded(self):
        # Two different secrets must not produce the same image.
        first = auth.otpauth_qr_svg(auth.otpauth_uri("JBSWY3DPEHPK3PXP", "a@example.com"))
        second = auth.otpauth_qr_svg(auth.otpauth_uri("KRSXG5CTMVRXEZLU", "a@example.com"))
        self.assertNotEqual(first, second)

    def test_a_missing_library_degrades_to_no_qr(self):
        # The manual secret is always shown as well, so losing the QR must not
        # break enrolment.
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "qrcode" or name.startswith("qrcode."):
                raise ImportError("no qrcode")
            return real_import(name, *args, **kwargs)

        with mock.patch.object(builtins, "__import__", side_effect=fake_import):
            self.assertIsNone(auth.otpauth_qr_svg(self._uri()))

    def test_a_rendering_failure_is_swallowed(self):
        with mock.patch("qrcode.QRCode", side_effect=RuntimeError("boom")):
            self.assertIsNone(auth.otpauth_qr_svg(self._uri()))

    def test_the_uri_still_matches_what_the_qr_encodes(self):
        uri = self._uri()
        self.assertIn("otpauth://totp/", uri)
        self.assertIn("secret=JBSWY3DPEHPK3PXP", uri)


class AccountPageTests(unittest.TestCase):
    """The QR has to reach the page, and the manual fallback has to survive."""

    def _template(self):
        import pathlib
        return (pathlib.Path(__file__).resolve().parent.parent
                / "templates" / "account.html").read_text(encoding="utf-8")

    def test_the_page_renders_the_qr(self):
        self.assertIn("mfa_setup.qr_svg", self._template())

    def test_the_svg_is_inlined_not_an_image_source(self):
        # A data: URI would need a CSP img-src exception; inline SVG needs none.
        template = self._template()
        self.assertIn('class="mfa-qr"', template)
        self.assertNotIn("data:image/svg", template)

    def test_manual_entry_is_still_offered(self):
        template = self._template()
        self.assertIn("mfa_setup.secret", template)
        self.assertIn("mfa_setup.uri", template)


if __name__ == "__main__":
    unittest.main()
