import os
import tempfile
import unittest
from unittest import mock

import weak_auth


class WeakAuthTests(unittest.TestCase):
    def test_disabled_by_default(self):
        result = weak_auth.scan("example.com", {"enabled": False})
        self.assertTrue(result["skipped"])
        self.assertFalse(result.get("weak_credentials_found"))

    def test_build_credential_list_respects_max(self):
        settings = {
            "usernames": ["a", "b", "c"],
            "passwords": ["1", "2", "3"],
            "max_attempts_per_scan": 4,
        }
        pairs = weak_auth.build_credential_list(settings)
        self.assertEqual(len(pairs), 4)

    def test_detects_basic_auth_weak_password(self):
        challenge = mock.Mock()
        challenge.status_code = 401
        challenge.headers = {"WWW-Authenticate": "Basic realm=\"test\""}

        success = mock.Mock()
        success.status_code = 200
        success.headers = {}

        def fake_get(url, **kwargs):
            if kwargs.get("auth"):
                user, password = kwargs["auth"]
                if user == "admin" and password == "admin":
                    return success
            return challenge

        with mock.patch("weak_auth.requests.get", side_effect=fake_get):
            result = weak_auth.scan(
                "example.com",
                {
                    "enabled": True,
                    "paths": ["/"],
                    "usernames": ["admin"],
                    "passwords": ["admin", "wrong"],
                    "max_attempts_per_scan": 5,
                    "delay_seconds": 0,
                    "timeout_seconds": 3,
                    "include_http": False,
                },
            )

        self.assertTrue(result["weak_credentials_found"])
        self.assertEqual(result["findings"][0]["username"], "admin")

    def test_no_protected_endpoints(self):
        ok = mock.Mock()
        ok.status_code = 200
        ok.headers = {}
        with mock.patch("weak_auth.requests.get", return_value=ok):
            result = weak_auth.scan(
                "example.com",
                {
                    "enabled": True,
                    "paths": ["/"],
                    "usernames": ["admin"],
                    "passwords": ["admin"],
                    "delay_seconds": 0,
                },
            )
        self.assertFalse(result["weak_credentials_found"])
        self.assertEqual(result["protected_endpoints"], [])


if __name__ == "__main__":
    unittest.main()
