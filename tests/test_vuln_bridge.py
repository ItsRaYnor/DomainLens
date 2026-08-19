import io
import os
import tempfile
import unittest
from unittest import mock

import insightvm
import rapid7_import
import servicenow_cmdb
import vuln_bridge


class LeanFilterTests(unittest.TestCase):
    def test_strips_description_and_filters_severity(self):
        findings = [
            {
                "title": "Crit",
                "severity": "critical",
                "description": "huge " * 100,
                "solution": "patch",
                "hostname": "a.example.com",
                "asset_ip": "1.2.3.4",
                "cves": ["CVE-2024-1"],
                "raw": {"proof": "blob", "keep": "x"},
            },
            {
                "title": "Low",
                "severity": "low",
                "description": "n",
                "hostname": "b.example.com",
                "cves": [],
                "raw": {},
            },
        ]
        cfg = {
            "min_severity": "high",
            "include_description": False,
            "include_proof": False,
            "include_solution": True,
            "max_rows": 100,
        }
        out = insightvm.lean_filter_findings(findings, cfg)
        self.assertEqual(len(out), 1)
        self.assertIsNone(out[0]["description"])
        self.assertNotIn("proof", out[0]["raw"])
        self.assertEqual(out[0]["solution"], "patch")


class ConsoleSyncMockTests(unittest.TestCase):
    def test_sync_from_console_api_builds_findings(self):
        cfg = {
            "enabled": True,
            "source_mode": "console_api",
            "api_base_url": "https://nexpose.test:3780",
            "username": "u",
            "password": "p",
            "console_configured": True,
            "cloud_configured": False,
            "verify_ssl": True,
            "min_severity": "high",
            "site_ids": [],
            "asset_hostname_contains": "",
            "max_assets": 10,
            "max_findings_per_asset": 10,
            "page_size": 50,
            "include_solution": True,
            "include_description": False,
            "include_proof": False,
            "max_rows": 100,
        }

        class FakeClient:
            def __init__(self, _cfg):
                pass

            def search_assets(self):
                return [{"id": 11, "hostName": "www.example.com", "ip": "203.0.113.10"}]

            def asset_vulnerabilities(self, asset_id):
                return [{"id": "ssl-weak-ciphers", "status": "vulnerable"}]

            def get_vulnerability(self, vuln_id):
                return {
                    "id": vuln_id,
                    "title": "Weak ciphers",
                    "severity": "Severe",
                    "cvss": {"v3": {"score": 7.5}},
                    "cves": ["CVE-2016-2183"],
                    "solution": {"summary": "Disable CBC"},
                }

        with mock.patch.object(insightvm, "InsightVMClient", FakeClient):
            result = insightvm.sync_from_console_api(cfg)

        self.assertEqual(result["source_format"], "console_api")
        self.assertEqual(result["summary"]["findings"], 1)
        f = result["findings"][0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["domain"], "www.example.com")
        self.assertIn("CVE-2016-2183", f["cves"])


class ServiceNowCmdbTests(unittest.TestCase):
    def test_lookup_ci_builds_or_query(self):
        cfg = {
            "configured": True,
            "instance": "https://example.service-now.com",
            "user": "u",
            "password": "p",
            "ci_table": "cmdb_ci",
            "ci_match_fields": ["name", "fqdn", "ip_address"],
            "cmdb_enabled": True,
            "create_vulnerable_items": False,
            "vuln_item_table": "sn_vul_vulnerable_item",
            "vuln_table": "sn_vul_vulnerability",
            "update_existing_vi": True,
            "vi_source": "DomainLens",
        }
        with mock.patch.object(
            servicenow_cmdb,
            "sn_get",
            return_value=[{"sys_id": "abc", "name": "www.example.com", "ip_address": "1.2.3.4"}],
        ) as get:
            ci = servicenow_cmdb.lookup_ci("www.example.com", "1.2.3.4", cfg=cfg)
        self.assertEqual(ci["sys_id"], "abc")
        args, kwargs = get.call_args
        self.assertIn("name=www.example.com", kwargs["query"])
        self.assertIn("ip_address=1.2.3.4", kwargs["query"])

    def test_link_finding_unmatched(self):
        cfg = {
            "configured": True,
            "cmdb_enabled": True,
            "create_vulnerable_items": False,
            "ci_table": "cmdb_ci",
            "ci_match_fields": ["name"],
            "vuln_item_table": "sn_vul_vulnerable_item",
            "vuln_table": "sn_vul_vulnerability",
            "instance": "https://example.service-now.com",
            "user": "u",
            "password": "p",
            "update_existing_vi": True,
            "vi_source": "DomainLens",
        }
        with mock.patch.object(servicenow_cmdb, "lookup_ci", return_value=None):
            result = servicenow_cmdb.link_finding_to_cmdb(
                {"hostname": "missing.example.com", "title": "x", "severity": "high"},
                cfg=cfg,
            )
        self.assertEqual(result["action"], "unmatched_ci")

    def test_upsert_creates_vi_with_cmdb_ci(self):
        cfg = {
            "configured": True,
            "cmdb_enabled": True,
            "create_vulnerable_items": True,
            "update_existing_vi": True,
            "ci_table": "cmdb_ci",
            "vuln_item_table": "sn_vul_vulnerable_item",
            "vuln_table": "sn_vul_vulnerability",
            "instance": "https://example.service-now.com",
            "user": "u",
            "password": "p",
            "vi_source": "DomainLens InsightVM",
            "ci_match_fields": ["name"],
        }
        ci = {"sys_id": "ci1", "name": "web01"}
        finding = {
            "id": 42,
            "title": "Weak ciphers",
            "severity": "high",
            "vuln_id": "ssl-weak",
            "cves": ["CVE-2016-2183"],
            "asset_ip": "10.0.0.1",
            "hostname": "web01.example.com",
            "domain": "example.com",
            "solution": "Fix TLS",
        }
        os.environ["DOMAINLENS_PUBLIC_URL"] = "https://domainlens.example.com"
        with mock.patch.object(servicenow_cmdb, "find_vulnerable_item", return_value=None), \
             mock.patch.object(servicenow_cmdb, "sn_post", return_value={"sys_id": "vi1", "number": "VUL0001"}) as post:
            result = servicenow_cmdb.upsert_vulnerable_item(finding, ci, {"sys_id": "vuln1"}, cfg=cfg)
        os.environ.pop("DOMAINLENS_PUBLIC_URL", None)
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "created")
        self.assertEqual(result["domainlens_url"], "https://domainlens.example.com/remediate/vuln/42")
        payload = post.call_args[0][2]
        self.assertEqual(payload["cmdb_ci"], "ci1")
        self.assertEqual(payload["vulnerability"], "vuln1")
        self.assertIn("https://domainlens.example.com/remediate/vuln/42", payload["work_notes"])
        self.assertIn("https://domainlens.example.com/remediate/vuln/42", payload["remediation"])
        self.assertIn("Fix TLS", payload["remediation"])


class VulnBridgeFileTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "bridge.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import db
        from settings.store import get_store

        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)

    def tearDown(self):
        self.tempdir.cleanup()
        os.environ.pop("DOMAINLENS_DB", None)
        os.environ.pop("DOMAINLENS_DISABLE_SCHEDULER", None)

    def test_ingest_file_applies_lean_filter(self):
        csv_data = (
            "IP Address,Host Name,Vulnerability Title,Vulnerability Severity Level,Vulnerability Description\n"
            "1.1.1.1,www.example.com,Crit finding,Critical,LONGDESC\n"
            "1.1.1.1,www.example.com,Low finding,Low,noise\n"
        ).encode()
        with mock.patch.object(insightvm, "config", return_value={
            "enabled": True,
            "min_severity": "high",
            "file_min_severity": "high",
            "include_description": False,
            "include_proof": False,
            "include_solution": True,
            "max_rows": 1000,
            "sync_to_servicenow_cmdb": False,
        }):
            result = vuln_bridge.ingest_file_bytes(csv_data, filename="lean.csv", push_cmdb=False)
        self.assertTrue(result["ok"])
        self.assertEqual(result["findings_stored"], 1)
        self.assertTrue(result["summary"]["lean_filtered"])


if __name__ == "__main__":
    unittest.main()
