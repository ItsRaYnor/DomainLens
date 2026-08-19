import unittest
from unittest import mock

import update_check


def _resp(status, payload=None, headers=None):
    r = mock.Mock(status_code=status)
    r.json.return_value = payload if payload is not None else []
    r.headers = headers or {}
    return r


class UpdateCheckDiagnosticsTests(unittest.TestCase):
    """"Could not reach GitHub releases (network or rate limit)" was returned
    for every failure, including the common case of a repository that simply
    has no releases or tags yet. That sends people hunting for a connectivity
    problem that does not exist.
    """

    def setUp(self):
        update_check.clear_cache()

    def tearDown(self):
        update_check.clear_cache()

    def test_no_releases_or_tags_says_so(self):
        # /releases/latest -> 404 (none published), /tags -> 200 but empty.
        responses = [_resp(404), _resp(200, [])]
        with mock.patch("update_check.requests.get", side_effect=responses):
            release, error = update_check._fetch_latest_release("owner/repo")
        self.assertIsNone(release)
        self.assertIn("No releases or tags published", error)
        self.assertNotIn("network", error.lower())

    def test_network_failure_still_reports_a_network_problem(self):
        import requests as real_requests
        with mock.patch("update_check.requests.get",
                        side_effect=real_requests.RequestException("boom")):
            release, error = update_check._fetch_latest_release("owner/repo")
        self.assertIsNone(release)
        self.assertIn("network", error.lower())

    def test_rate_limit_is_named_explicitly(self):
        limited = _resp(403, {}, {"X-RateLimit-Remaining": "0"})
        with mock.patch("update_check.requests.get", return_value=limited):
            release, error = update_check._fetch_latest_release("owner/repo")
        self.assertIsNone(release)
        self.assertIn("rate limit", error.lower())
        self.assertIn("GITHUB_TOKEN", error)

    def test_missing_repository_is_named_explicitly(self):
        responses = [_resp(404), _resp(404)]
        with mock.patch("update_check.requests.get", side_effect=responses):
            release, error = update_check._fetch_latest_release("owner/nope")
        self.assertIsNone(release)
        self.assertIn("not found", error)

    def test_bad_token_is_named_explicitly(self):
        with mock.patch("update_check.requests.get", return_value=_resp(401)):
            release, error = update_check._fetch_latest_release("owner/repo")
        self.assertIsNone(release)
        self.assertIn("token", error.lower())

    def test_release_found_returns_no_error(self):
        payload = {"tag_name": "v2.0.0", "html_url": "https://example/r", "name": "2.0.0"}
        with mock.patch("update_check.requests.get", return_value=_resp(200, payload)):
            release, error = update_check._fetch_latest_release("owner/repo")
        self.assertIsNone(error)
        self.assertEqual(release["tag_name"], "v2.0.0")

    def test_falls_back_to_tags_when_no_release_published(self):
        responses = [_resp(404), _resp(200, [{"name": "v1.4.0"}])]
        with mock.patch("update_check.requests.get", side_effect=responses):
            release, error = update_check._fetch_latest_release("owner/repo")
        self.assertIsNone(error)
        self.assertEqual(release["tag_name"], "v1.4.0")

    def test_check_for_updates_surfaces_the_specific_reason(self):
        with mock.patch("update_check._fetch_latest_release",
                        return_value=(None, "No releases or tags published in owner/repo yet")):
            result = update_check.check_for_updates(force=True)
        self.assertFalse(result["update_available"])
        self.assertIn("No releases or tags", result["error"])


if __name__ == "__main__":
    unittest.main()
