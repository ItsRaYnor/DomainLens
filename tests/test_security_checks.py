import unittest
from unittest import mock

import security_checks as s


def _resp(body, status=200):
    return mock.Mock(status_code=status, text=body, content=body.encode())


class SensitivePathFalsePositiveTests(unittest.TestCase):
    """Regression tests for a real false positive reported from production:
    a CDN (Bunny) returned HTTP 200 with a generic HTML "not found" page for
    /.env, and the old signature list (which included a bare "=") matched any
    such page, since virtually all HTML contains an "=" somewhere (e.g.
    attr="value"). Fixed by (1) requiring real KEY=VALUE env-file lines for
    .env-style paths, and (2) rejecting HTML soft-404 pages outright for
    every path that should never legitimately be HTML.
    """

    SOFT_404_HTML = (
        '<!DOCTYPE html><html lang="nl"><head><title>Not Found</title></head>'
        '<body><p class="error">Pagina niet gevonden</p></body></html>'
    )

    def test_env_not_flagged_on_html_soft_404(self):
        with mock.patch("security_checks._get", return_value=_resp(self.SOFT_404_HTML)):
            result = s._probe_path("https://example.com", "/.env", None, False)
        self.assertIsNone(result)

    def test_all_sensitive_paths_reject_html_soft_404(self):
        for path, sigs, expects_html in s._SENSITIVE_PATHS:
            with mock.patch("security_checks._get", return_value=_resp(self.SOFT_404_HTML)):
                result = s._probe_path("https://example.com", path, sigs, expects_html)
            if not expects_html:
                self.assertIsNone(result, f"{path} false-positived on an HTML soft-404 page")

    def test_real_env_leak_still_detected(self):
        body = "APP_ENV=production\nDB_PASSWORD=SuperSecret123!\nSECRET_KEY=abcxyz\n"
        with mock.patch("security_checks._get", return_value=_resp(body)):
            result = s._probe_path("https://example.com", "/.env", None, False)
        self.assertIsNotNone(result)
        self.assertFalse(result["positive"])
        self.assertEqual(result["path"], "/.env")

    def test_env_with_bare_equals_only_not_flagged(self):
        """A single stray '=' (not a KEY=VALUE line) must not trigger a hit —
        this is exactly the pattern that caused the original false positive.
        """
        body = "Some page content with a = somewhere in the text."
        with mock.patch("security_checks._get", return_value=_resp(body)):
            result = s._probe_path("https://example.com", "/.env", None, False)
        self.assertIsNone(result)

    def test_security_txt_requires_real_contact_field(self):
        # A soft-404 HTML page must NOT be reported as "security.txt present".
        with mock.patch("security_checks._get", return_value=_resp(self.SOFT_404_HTML)):
            result = s._probe_path(
                "https://example.com", "/.well-known/security.txt",
                ["Contact:", "contact:"], False,
            )
        self.assertIsNone(result)

    def test_security_txt_detected_when_genuinely_present(self):
        body = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n"
        with mock.patch("security_checks._get", return_value=_resp(body)):
            result = s._probe_path(
                "https://example.com", "/.well-known/security.txt",
                ["Contact:", "contact:"], False,
            )
        self.assertIsNotNone(result)
        self.assertTrue(result["positive"])

    def test_phpinfo_html_still_detected(self):
        # phpinfo.php is the one path where a genuine hit IS an HTML page.
        body = "<html><body><h1>phpinfo()</h1><table>PHP Version 8.2.1</table></body></html>"
        with mock.patch("security_checks._get", return_value=_resp(body)):
            result = s._probe_path(
                "https://example.com", "/phpinfo.php",
                ["phpinfo()", "PHP Version"], True,
            )
        self.assertIsNotNone(result)
        self.assertFalse(result["positive"])

    def test_non_200_status_never_flagged(self):
        with mock.patch("security_checks._get", return_value=_resp("APP_ENV=x", status=404)):
            result = s._probe_path("https://example.com", "/.env", None, False)
        self.assertIsNone(result)


class AdminEndpointSoftFourOhFourTests(unittest.TestCase):
    """Regression tests for a second false-positive class reported on
    admin/debug paths like /phpmyadmin/ were flagged as
    "reachable" purely because the host (behind a CDN) returns HTTP 200 for
    every path instead of a real 404. _probe_admin now requires the response
    to differ from a definitely-nonexistent baseline path before flagging.
    """

    SOFT_404_BODY = "<!DOCTYPE html><html><head></head><body>Page not found</body></html>"

    def _soft_404_get(self, url, timeout=6, allow_redirects=False, params=None, headers=None, method="GET"):
        return _resp(self.SOFT_404_BODY)

    def test_all_admin_paths_suppressed_on_soft_404_host(self):
        with mock.patch("security_checks._get", side_effect=self._soft_404_get):
            baseline = s._get_soft_404_baseline("https://example.com")
            for path in s._ADMIN_PATHS:
                result = s._probe_admin("https://example.com", path, baseline)
                self.assertIsNone(result, f"{path} false-positived on a soft-404 host")

    def test_genuine_admin_endpoint_still_detected(self):
        def fake_get(url, timeout=6, allow_redirects=False, params=None, headers=None, method="GET"):
            if "domainlens-baseline" in url:
                return _resp("Not Found", status=404)
            if url.endswith("/wp-admin/"):
                return _resp("<html><body><form id='loginform'>" + ("x" * 2000) + "</form></body></html>")
            return _resp("Not Found", status=404)

        with mock.patch("security_checks._get", side_effect=fake_get):
            baseline = s._get_soft_404_baseline("https://example.com")
            hit = s._probe_admin("https://example.com", "/wp-admin/", baseline)
            miss = s._probe_admin("https://example.com", "/phpmyadmin/", baseline)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["status"], 200)
        self.assertIsNone(miss)

    def test_no_baseline_falls_back_to_status_only(self):
        # If the baseline probe itself fails (network error), behavior
        # degrades to the original status-code check rather than crashing.
        with mock.patch("security_checks._get", return_value=_resp("<html>admin</html>")):
            result = s._probe_admin("https://example.com", "/admin", (None, None))
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
