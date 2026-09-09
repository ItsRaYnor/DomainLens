import os
import unittest


class OptionalIntegrationStatusTests(unittest.TestCase):
    """The OSINT/blacklist API keys are environment-only by design, but the
    admin UI gave no sign they existed — the only hint was a bare env var name
    inside a scan result ("Set ABUSECH_AUTH_KEY for ThreatFox lookups") with
    no indication of where that variable should go.
    """

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        cls.app = app

    def tearDown(self):
        for key in ("ABUSECH_AUTH_KEY", "OTX_API_KEY", "SPAMHAUS_DQS_KEY",
                    "VIRUSTOTAL_API_KEY"):
            os.environ.pop(key, None)

    def test_catalogue_covers_the_optional_keys(self):
        envs = {item["env"] for item in self.app._optional_integration_status()}
        self.assertEqual(envs, {"SPAMHAUS_DQS_KEY", "ABUSECH_AUTH_KEY", "OTX_API_KEY",
                                "VIRUSTOTAL_API_KEY"})

    def test_every_entry_explains_itself(self):
        for item in self.app._optional_integration_status():
            for field in ("name", "enables", "without", "signup"):
                self.assertTrue(item.get(field), f"{item['env']} is missing {field}")

    def test_unset_key_reports_not_configured(self):
        status = {i["env"]: i["configured"] for i in self.app._optional_integration_status()}
        self.assertFalse(status["ABUSECH_AUTH_KEY"])

    def test_set_key_reports_configured(self):
        os.environ["ABUSECH_AUTH_KEY"] = "abc123"
        status = {i["env"]: i["configured"] for i in self.app._optional_integration_status()}
        self.assertTrue(status["ABUSECH_AUTH_KEY"])

    def test_whitespace_only_key_is_not_configured(self):
        os.environ["OTX_API_KEY"] = "   "
        status = {i["env"]: i["configured"] for i in self.app._optional_integration_status()}
        self.assertFalse(status["OTX_API_KEY"])


if __name__ == "__main__":
    unittest.main()
