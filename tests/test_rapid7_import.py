import io
import os
import tempfile
import unittest

import rapid7_import


SAMPLE_CSV = """IP Address,Host Name,Vulnerability Title,Vulnerability CVE IDs,Vulnerability Severity Level,Vulnerability CVSS Score,Vulnerability Solution,Vulnerability Description,Service Port
203.0.113.10,www.example.com,SSL/TLS Server Supports Weak Cipher Suites,CVE-2016-2183,Severe,7.5,Disable weak ciphers.,Weak CBC ciphers.,443
203.0.113.10,mail.example.com,OpenSSH Username Enumeration,,Medium,5.0,Upgrade OpenSSH.,Timing side channel.,22
198.51.100.5,other.org,Unrelated Host Issue,,Low,2.0,N/A,Other domain.,80
"""


class Rapid7ImportParserTests(unittest.TestCase):
    def test_parse_csv_and_correlate_domain(self):
        parsed = rapid7_import.parse_export(SAMPLE_CSV.encode("utf-8"), filename="export.csv")
        self.assertEqual(parsed["source_format"], "csv")
        self.assertEqual(parsed["summary"]["findings"], 3)
        self.assertEqual(parsed["summary"]["by_severity"]["high"], 1)
        matched = rapid7_import.findings_for_domain(parsed["findings"], "example.com")
        self.assertEqual(len(matched), 2)
        self.assertTrue(all("example.com" in (f.get("domain") or "") for f in matched))

    def test_severity_aliases(self):
        self.assertEqual(rapid7_import.normalize_severity("Severe"), "high")
        self.assertEqual(rapid7_import.normalize_severity("", 9.1), "critical")
        self.assertEqual(rapid7_import.severity_from_cvss(4.5), "medium")

    def test_advies_item(self):
        parsed = rapid7_import.parse_export(SAMPLE_CSV.encode("utf-8"), filename="x.csv")
        item = rapid7_import.finding_to_advies(parsed["findings"][0], domain="example.com")
        self.assertEqual(item["category"], "rapid7")
        self.assertIn("CVE-2016-2183", item["title"])
        self.assertTrue(item["fix"])
        self.assertTrue(item["retest"])

    def test_parse_xlsx(self):
        from openpyxl import Workbook

        wb = Workbook()
        ws = wb.active
        ws.append([
            "Asset IP Address", "Asset Names", "Vulnerability Title",
            "Vulnerability CVE IDs", "Vulnerability Severity Level",
            "Vulnerability CVSS Score", "Vulnerability Solution",
        ])
        ws.append([
            "10.0.0.1", "app.acme.test", "Outdated OpenSSL",
            "CVE-2022-0778", "Critical", "9.8", "Upgrade OpenSSL",
        ])
        buf = io.BytesIO()
        wb.save(buf)
        parsed = rapid7_import.parse_export(buf.getvalue(), filename="vulns.xlsx")
        self.assertEqual(parsed["source_format"], "xlsx")
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertEqual(parsed["findings"][0]["severity"], "critical")
        self.assertEqual(parsed["findings"][0]["domain"], "app.acme.test")


class Rapid7ImportApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "r7.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ.pop("OAUTH_ENABLED", None)
        os.environ.pop("AUTH_LOCAL_ENABLED", None)
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"

        import importlib
        import auth
        import db
        import app
        from settings.store import get_store

        self.auth = importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    def test_upload_and_correlate_on_scan(self):
        resp = self.client.post(
            "/api/vuln-imports",
            data={"file": (io.BytesIO(SAMPLE_CSV.encode("utf-8")), "insightvm.csv")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 201, resp.get_data(as_text=True))
        payload = resp.get_json()
        # Lean filter drops Low by default (file_min_severity=medium)
        self.assertEqual(payload["summary"]["findings"], 2)
        self.assertTrue(payload["summary"].get("lean_filtered"))

        listed = self.client.get("/api/vuln-findings?domain=example.com").get_json()
        self.assertEqual(listed["count"], 2)

        # Attach path used by scans
        results = {"domain": "example.com"}
        self.app_module._attach_rapid7_findings(results, "example.com")
        self.assertTrue(results["rapid7"]["success"])
        self.assertEqual(results["rapid7"]["finding_count"], 2)

        import recommendations
        recs = recommendations.generate(results)
        rapid7_recs = [r for r in recs if r.get("category") == "rapid7"]
        self.assertGreaterEqual(len(rapid7_recs), 1)

    def test_list_imports(self):
        self.client.post(
            "/api/vuln-imports",
            data={"file": (io.BytesIO(SAMPLE_CSV.encode("utf-8")), "a.csv")},
            content_type="multipart/form-data",
        )
        resp = self.client.get("/api/vuln-imports")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.get_json()["imports"]), 1)


if __name__ == "__main__":
    unittest.main()
