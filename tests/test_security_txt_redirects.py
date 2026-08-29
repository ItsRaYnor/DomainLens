"""A security.txt behind a redirect is still a published security.txt.

The scan probe sent allow_redirects=False and discarded anything that was not
a 200, so a site serving its file from www (apex -> www is the ordinary
setup) was reported as having none. cloudflare.com, ncsc.nl and google.com
all redirect, and all three were being blamed for it.

The manual tool followed redirects, which is why the same domain could be
fine on the Tools page and flagged in a scan.

Redirects are followed hop by hop rather than handed to requests, because a
302 is written by the site being scanned: unfollowed checking would let it
point this scanner at 127.0.0.1 or a cloud metadata address.
"""

import unittest
from unittest import mock

import security_checks as s


SECURITY_TXT = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n"


def _resp(status, body="", location=None):
    headers = {"Location": location} if location else {}
    return mock.Mock(status_code=status, text=body, content=body.encode(),
                     headers=headers)


class SafeRedirectFetchTests(unittest.TestCase):
    def test_a_redirect_is_followed_to_the_final_document(self):
        responses = [_resp(302, location="https://www.example.com/x"),
                     _resp(200, "final")]
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=responses):
            resp, final, hops = s._get_following_safe_redirects("https://example.com/x")
        self.assertEqual(200, resp.status_code)
        self.assertEqual("https://www.example.com/x", final)
        self.assertEqual(["https://example.com/x"], hops)

    def test_a_relative_location_is_resolved_against_the_current_url(self):
        responses = [_resp(301, location="/elsewhere/security.txt"), _resp(200, "final")]
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=responses):
            _resp_out, final, _hops = s._get_following_safe_redirects(
                "https://example.com/.well-known/security.txt")
        self.assertEqual("https://example.com/elsewhere/security.txt", final)

    def test_every_hop_is_checked_not_just_the_first(self):
        """The point of doing this by hand: requests would follow a 302 into
        the network this scanner runs in, on the say-so of the scanned site."""
        checked = []

        def safe(host):
            checked.append(host)
            return host != "169.254.169.254"

        with mock.patch.object(s, "_safe_host", side_effect=safe), \
             mock.patch.object(s, "_get",
                               return_value=_resp(302, location="http://169.254.169.254/")):
            resp, final, detail = s._get_following_safe_redirects("https://example.com/x")
        self.assertIsNone(resp)
        self.assertIn("public address", detail)
        self.assertIn("169.254.169.254", checked)

    def test_the_metadata_address_is_never_fetched(self):
        calls = []

        def fake_get(url, **kwargs):
            calls.append(url)
            return _resp(302, location="http://169.254.169.254/latest/meta-data/")

        with mock.patch.object(s, "_safe_host",
                               side_effect=lambda h: h != "169.254.169.254"), \
             mock.patch.object(s, "_get", side_effect=fake_get):
            s._get_following_safe_redirects("https://example.com/x")
        self.assertNotIn("http://169.254.169.254/latest/meta-data/", calls)

    def test_a_redirect_chain_is_bounded(self):
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get",
                               side_effect=lambda u, **k: _resp(302, location=u + "/a")):
            resp, _final, detail = s._get_following_safe_redirects(
                "https://example.com/x", max_hops=3)
        self.assertIsNone(resp)
        self.assertIn("redirects", detail)

    def test_a_redirect_without_a_location_is_not_followed_forever(self):
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", return_value=_resp(302)):
            resp, _final, _detail = s._get_following_safe_redirects("https://example.com/x")
        self.assertEqual(302, resp.status_code)

    def test_a_connection_failure_is_reported_not_raised(self):
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=OSError("boom")):
            resp, _final, detail = s._get_following_safe_redirects("https://example.com/x")
        self.assertIsNone(resp)
        self.assertEqual("OSError", detail)


class SecurityTxtBehindARedirectTests(unittest.TestCase):
    PATH = "/.well-known/security.txt"
    SIGS = ["Contact:", "contact:"]

    def test_the_scan_finds_a_file_served_from_www(self):
        """The reported bug: apex redirects to www, and the scan said the
        site had no security.txt at all."""
        responses = [_resp(302, location="https://www.example.com" + self.PATH),
                     _resp(200, SECURITY_TXT)]
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=responses):
            result = s._probe_path("https://example.com", self.PATH, self.SIGS, False)
        self.assertIsNotNone(result)
        self.assertTrue(result["positive"])
        self.assertEqual("https://www.example.com" + self.PATH, result["url"])

    def test_a_redirect_to_a_soft_404_is_still_not_a_security_txt(self):
        """Following the redirect must not lower the bar: the thing at the
        end still has to be a real file with a Contact field."""
        html = "<!DOCTYPE html><html><body>Not found</body></html>"
        responses = [_resp(302, location="https://www.example.com/404"), _resp(200, html)]
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=responses):
            result = s._probe_path("https://example.com", self.PATH, self.SIGS, False)
        self.assertIsNone(result)

    def test_a_redirect_that_ends_in_404_is_not_a_find(self):
        responses = [_resp(302, location="https://www.example.com/gone"), _resp(404, "")]
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=responses):
            result = s._probe_path("https://example.com", self.PATH, self.SIGS, False)
        self.assertIsNone(result)

    def test_other_sensitive_paths_still_refuse_to_follow_redirects(self):
        """Deliberate and worth keeping: a /.env that redirects to a login
        page has exposed nothing, and following it would invent a finding."""
        with mock.patch.object(s, "_get") as get:
            get.return_value = _resp(302, location="https://example.com/login")
            result = s._probe_path("https://example.com", "/.env", None, False)
        self.assertIsNone(result)
        self.assertFalse(get.call_args.kwargs.get("allow_redirects", True))

    def test_the_tool_reports_where_the_file_actually_came_from(self):
        """A file served from another address is normal, but the operator
        should be able to see that it moved."""
        responses = [_resp(302, location="https://www.example.com" + self.PATH),
                     _resp(200, SECURITY_TXT)]
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", side_effect=responses), \
             mock.patch.object(s, "check_security_txt_key", return_value={}):
            result = s.inspect_security_txt("example.com")
        self.assertTrue(result["found"])
        self.assertEqual("https://www.example.com" + self.PATH, result["url"])
        self.assertEqual("https://example.com" + self.PATH, result["redirected_from"])

    def test_a_file_served_without_a_redirect_records_no_redirect(self):
        with mock.patch.object(s, "_safe_host", return_value=True), \
             mock.patch.object(s, "_get", return_value=_resp(200, SECURITY_TXT)), \
             mock.patch.object(s, "check_security_txt_key", return_value={}):
            result = s.inspect_security_txt("example.com")
        self.assertTrue(result["found"])
        self.assertIsNone(result["redirected_from"])


if __name__ == "__main__":
    unittest.main()
