import os
import tempfile
import unittest
from unittest.mock import patch

import reporting_export
import update_check
import version


class VersionTests(unittest.TestCase):
    def test_reads_version_file(self):
        version.clear_cache()
        self.assertRegex(version.get_version(), r"^\d+\.\d+\.\d+")

    def test_env_override(self):
        version.clear_cache()
        with patch.dict(os.environ, {"DOMAINLENS_VERSION": "9.9.9"}):
            version.clear_cache()
            self.assertEqual(version.get_version(), "9.9.9")
        version.clear_cache()

    def test_semver_compare(self):
        self.assertTrue(version.is_newer("1.4.0", "1.3.0"))
        self.assertFalse(version.is_newer("1.3.0", "1.3.0"))
        self.assertFalse(version.is_newer("1.2.9", "1.3.0"))

    def test_info_payload(self):
        info = version.info()
        self.assertEqual(info["name"], "DomainLens")
        self.assertIn("version", info)
        self.assertIn("docker", info)


class ReportingExportTests(unittest.TestCase):
    def test_markdown_and_csv(self):
        scan = {
            "id": 42,
            "domain": "example.com",
            "created_at": "2026-01-01T00:00:00Z",
            "grade": "B",
            "score": 70,
            "data": {
                "ncsc_tls": {
                    "overall_level": "insufficient",
                    "overall_label": "Insufficient",
                    "pass": False,
                    "findings": [
                        {
                            "id": "signature-hash-insufficient",
                            "severity": "critical",
                            "title": "SHA-1",
                            "problem": "SHA1 accepted",
                        }
                    ],
                },
                "cdn": {"name": "BunnyCDN"},
            },
        }
        recs = [
            {
                "severity": "critical",
                "category": "NCSC TLS",
                "title": "Disable SHA-1",
                "problem": "SHA1",
                "fix": "Restrict SignatureAlgorithms",
                "retest": "Re-scan",
                "reference": "https://example.com",
            }
        ]
        counts = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
        bundle = reporting_export.build_report_bundle(scan, recs, counts)
        md = reporting_export.to_markdown(bundle)
        self.assertIn("example.com", md)
        self.assertIn("SHA-1", md)
        self.assertIn("BunnyCDN", md)
        csv_text = reporting_export.to_csv_advies(recs)
        self.assertIn("Disable SHA-1", csv_text)
        self.assertIn("severity", csv_text.splitlines()[0])


class UpdateCheckTests(unittest.TestCase):
    def test_docker_commands(self):
        cmds = update_check.docker_update_commands({
            "docker_image": "domainlens",
            "compose_file": "docker-compose.yml",
        })
        self.assertTrue(any("docker compose" in c for c in cmds))
        self.assertTrue(any("docker-update.sh" in c for c in cmds))

    def test_check_uses_mock_release(self):
        update_check.clear_cache()
        fake = {
            "tag_name": "v99.0.0",
            "html_url": "https://github.com/ItsRaYnor/DomainLens/releases/tag/v99.0.0",
            "name": "v99.0.0",
            "published_at": "2026-01-01T00:00:00Z",
            "prerelease": False,
        }
        # _fetch_latest_release now returns (release, error).
        with patch.object(update_check, "_fetch_latest_release", return_value=(fake, None)):
            with patch.object(update_check, "_updates_config", return_value={
                "enabled": True,
                "github_repo": "ItsRaYnor/DomainLens",
                "include_prereleases": False,
                "docker_image": "domainlens",
                "compose_file": "docker-compose.yml",
            }):
                result = update_check.check_for_updates(force=True)
        self.assertTrue(result["update_available"])
        self.assertEqual(result["latest_version"], "99.0.0")


class VersionApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(cls.tempdir.name, "v.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import app as app_module

        cls.app_module = importlib.reload(app_module)
        cls.client = cls.app_module.app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_health_includes_version(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertIn("version", data["version"])

    def test_api_version(self):
        resp = self.client.get("/api/version")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["name"], "DomainLens")

    def test_report_export_json(self):
        # Create a minimal scan row
        scan_id = self.app_module.db.save_scan(
            "example.com",
            {"domain": "example.com", "tls_deep": {"success": True, "grade": "A"}},
        )
        resp = self.client.get(f"/api/reports/{scan_id}/export?format=markdown")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"example.com", resp.data)
        resp_csv = self.client.get(f"/api/reports/{scan_id}/export?format=csv")
        self.assertEqual(resp_csv.status_code, 200)
        self.assertIn(b"severity", resp_csv.data)


if __name__ == "__main__":
    unittest.main()
