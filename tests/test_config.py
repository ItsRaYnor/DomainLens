import json
import os
import tempfile
import unittest


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.tempdir.name, "domainlens.json")
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "scheduler": {"poll_seconds": 120, "concurrency": 3},
                    "weak_auth": {"enabled": True, "max_attempts_per_scan": 10},
                    "scan": {"rate_limit": {"requests": 5, "window_seconds": 30}},
                },
                handle,
            )
        os.environ["DOMAINLENS_CONFIG"] = self.config_path
        os.environ["DOMAINLENS_MONITOR_POLL_SECONDS"] = "45"
        import importlib
        import config

        self.config = importlib.reload(config)
        self.config.load_settings(force_reload=True)

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_CONFIG", "DOMAINLENS_MONITOR_POLL_SECONDS", "DOMAINLENS_DB"):
            os.environ.pop(key, None)

    def test_file_values_load(self):
        settings = self.config.load_settings(force_reload=True)
        sched = settings.scheduler()
        self.assertEqual(sched["concurrency"], 3)
        self.assertTrue(settings.weak_auth()["enabled"])
        self.assertEqual(settings.scan()["rate_limit"]["requests"], 5)

    def test_env_overrides_file(self):
        settings = self.config.load_settings(force_reload=True)
        self.assertEqual(settings.scheduler()["poll_seconds"], 45)

    def test_public_snapshot_excludes_secrets(self):
        settings = self.config.load_settings(force_reload=True)
        snap = settings.public_snapshot()
        self.assertIn("scheduler", snap)
        self.assertIn("weak_auth", snap)
        meta = json.dumps(snap.get("meta") or {})
        secrets = (snap.get("meta") or {}).get("secrets_configured") or {}
        self.assertIn("OAUTH_CLIENT_SECRET", secrets)
        self.assertFalse(secrets.get("OAUTH_CLIENT_SECRET"))
        self.assertNotIn("supersecret", meta.lower())


if __name__ == "__main__":
    unittest.main()
