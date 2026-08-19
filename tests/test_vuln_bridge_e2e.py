"""
End-to-end HTTP simulation: InsightVM Console API → DomainLens store → ServiceNow CMDB VI.

Uses mocked HTTP backends (no live credentials). Proves the wiring works.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from unittest import mock


class EndToEndVulnBridgeHttpTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "e2e.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["DOMAINLENS_SECRET_KEY"] = "e2e-secret"
        os.environ["RAPID7_CONSOLE_URL"] = "https://nexpose.test:3780"
        os.environ["RAPID7_USERNAME"] = "api"
        os.environ["RAPID7_PASSWORD"] = "secret"
        os.environ["SERVICENOW_INSTANCE"] = "https://example.service-now.com"
        os.environ["SERVICENOW_USER"] = "snuser"
        os.environ["SERVICENOW_PASSWORD"] = "snpass"
        os.environ.pop("OAUTH_ENABLED", None)
        os.environ.pop("AUTH_LOCAL_ENABLED", None)

        import importlib
        import auth
        import db
        import app
        import insightvm
        from settings.store import get_store

        self.auth = importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        store = get_store(db_module=self.db, force_new=True)
        # Persist runtime settings for API mode + CMDB
        store.update_section(
            "rapid7",
            {
                "enabled": True,
                "source_mode": "console_api",
                "api_base_url": "https://nexpose.test:3780",
                "api_min_severity": "high",
                "file_min_severity": "medium",
                "max_assets": 50,
                "max_findings_per_asset": 20,
                "include_description": False,
                "include_proof": False,
                "sync_to_servicenow_cmdb": True,
            },
        )
        store.update_section(
            "servicenow",
            {
                "enabled": True,
                "instance": "https://example.service-now.com",
                "cmdb_enabled": True,
                "create_vulnerable_items": True,
                "update_existing_vi": True,
                "ci_table": "cmdb_ci",
                "vuln_item_table": "sn_vul_vulnerable_item",
                "vuln_table": "sn_vul_vulnerability",
            },
        )
        self.app_module = importlib.reload(app)
        self.insightvm = importlib.reload(insightvm)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in (
            "DOMAINLENS_DB",
            "DOMAINLENS_DISABLE_SCHEDULER",
            "DOMAINLENS_SECRET_KEY",
            "RAPID7_CONSOLE_URL",
            "RAPID7_USERNAME",
            "RAPID7_PASSWORD",
            "SERVICENOW_INSTANCE",
            "SERVICENOW_USER",
            "SERVICENOW_PASSWORD",
        ):
            os.environ.pop(key, None)

    def test_status_endpoints_report_configured(self):
        ivm = self.client.get("/api/integrations/insightvm").get_json()
        self.assertTrue(ivm["console_configured"])
        self.assertEqual(ivm["source_mode"], "console_api")

        sn = self.client.get("/api/integrations/servicenow/cmdb").get_json()
        self.assertTrue(sn["configured"])
        self.assertTrue(sn["cmdb_enabled"])
        self.assertEqual(sn["vuln_item_table"], "sn_vul_vulnerable_item")

    def test_full_console_sync_then_cmdb_push_and_domain_correlate(self):
        """Mock InsightVM + ServiceNow HTTP; drive real DomainLens routes."""

        class FakeConsole:
            def __init__(self, cfg):
                self.cfg = cfg

            def search_assets(self):
                return [
                    {"id": 42, "hostName": "www.example.com", "ip": "203.0.113.10"},
                    {"id": 43, "hostName": "db.example.com", "ip": "203.0.113.11"},
                ]

            def asset_vulnerabilities(self, asset_id):
                return [
                    {"id": "ssl-cve-2016-2183", "status": "vulnerable"},
                    {"id": "ssh-weak", "status": "vulnerable"},
                ]

            def get_vulnerability(self, vuln_id):
                catalog = {
                    "ssl-cve-2016-2183": {
                        "id": vuln_id,
                        "title": "SSL/TLS SWEET32",
                        "severity": "Severe",
                        "cvss": {"v3": {"score": 7.5}},
                        "cves": ["CVE-2016-2183"],
                        "solution": {"summary": "Disable 3DES / weak CBC"},
                    },
                    "ssh-weak": {
                        "id": vuln_id,
                        "title": "OpenSSH weak algorithms",
                        "severity": "Moderate",
                        "cvss": {"v3": {"score": 5.3}},
                        "cves": [],
                        "solution": {"summary": "Harden sshd_config"},
                    },
                }
                return catalog.get(vuln_id, {"id": vuln_id, "title": vuln_id, "severity": "Low"})

        # ServiceNow Table API mock
        sn_state = {"ci_queries": [], "posts": [], "patches": []}

        def fake_sn_get(cfg, table, *, query=None, fields=None, limit=10):
            sn_state["ci_queries"].append({"table": table, "query": query})
            if table == "cmdb_ci":
                if query and "www.example.com" in (query or ""):
                    return [{
                        "sys_id": "ci-www",
                        "name": "www.example.com",
                        "ip_address": "203.0.113.10",
                        "fqdn": "www.example.com",
                        "sys_class_name": "cmdb_ci_server",
                    }]
                if query and "db.example.com" in (query or ""):
                    return [{
                        "sys_id": "ci-db",
                        "name": "db.example.com",
                        "ip_address": "203.0.113.11",
                        "fqdn": "db.example.com",
                        "sys_class_name": "cmdb_ci_server",
                    }]
                return []
            if table == "sn_vul_vulnerability":
                return []  # force create
            if table == "sn_vul_vulnerable_item":
                return []  # force create
            return []

        def fake_sn_post(cfg, table, payload):
            sn_state["posts"].append({"table": table, "payload": payload})
            if table == "sn_vul_vulnerability":
                return {"sys_id": f"vuln-{payload.get('id')}", "id": payload.get("id")}
            if table == "sn_vul_vulnerable_item":
                self.assertIn("cmdb_ci", payload)
                self.assertTrue(payload["cmdb_ci"].startswith("ci-"))
                return {"sys_id": f"vi-{len(sn_state['posts'])}", "number": f"VUL{len(sn_state['posts']):04d}"}
            return {"sys_id": "x"}

        with mock.patch.object(self.insightvm, "InsightVMClient", FakeConsole), \
             mock.patch("servicenow_cmdb.sn_get", side_effect=fake_sn_get), \
             mock.patch("servicenow_cmdb.sn_post", side_effect=fake_sn_post), \
             mock.patch("servicenow_cmdb.sn_patch", return_value={}):
            # 1) API sync with CMDB push
            resp = self.client.post(
                "/api/vuln-imports/sync",
                json={"push_cmdb": True},
            )
            self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
            body = resp.get_json()
            self.assertTrue(body["ok"])
            self.assertEqual(body["mode"], "console_api")
            # high filter keeps Severe; Moderate (medium) dropped by api_min_severity=high
            self.assertGreaterEqual(body["findings_stored"], 2)
            self.assertTrue(body["cmdb"]["ok"])
            self.assertGreaterEqual(body["cmdb"]["stats"]["created"], 1)

            import_id = body["import"]["id"]

            # 2) Findings for domain
            listed = self.client.get("/api/vuln-findings?domain=example.com").get_json()
            self.assertGreaterEqual(listed["count"], 2)

            # 3) CI lookup API
            lookup = self.client.post(
                "/api/integrations/servicenow/cmdb/lookup",
                json={"hostname": "www.example.com", "ip": "203.0.113.10"},
            )
            self.assertEqual(lookup.status_code, 200)
            self.assertTrue(lookup.get_json()["matched"])
            self.assertEqual(lookup.get_json()["ci"]["sys_id"], "ci-www")

            # 4) Domain scan attaches Rapid7 + Advies
            results = {"domain": "example.com"}
            self.app_module._attach_rapid7_findings(results, "example.com")
            self.assertTrue(results["rapid7"]["success"])
            self.assertGreaterEqual(results["rapid7"]["finding_count"], 2)

            import recommendations
            recs = recommendations.generate(results)
            rapid7_recs = [r for r in recs if r.get("category") == "rapid7"]
            self.assertGreaterEqual(len(rapid7_recs), 1)
            self.assertTrue(all(r.get("fix") and r.get("retest") for r in rapid7_recs))

            # 5) Re-push existing import
            push = self.client.post(f"/api/vuln-imports/{import_id}/push-cmdb")
            self.assertEqual(push.status_code, 200)
            self.assertTrue(push.get_json()["ok"])

        # VI payloads must bind cmdb_ci
        vi_posts = [p for p in sn_state["posts"] if p["table"] == "sn_vul_vulnerable_item"]
        self.assertGreaterEqual(len(vi_posts), 1)
        for post in vi_posts:
            self.assertIn(post["payload"]["cmdb_ci"], {"ci-www", "ci-db"})

    def test_file_upload_rejects_giant_payload_hint(self):
        # 51 MB should be rejected with lean-sync guidance
        big = b"x" * (51 * 1024 * 1024)
        resp = self.client.post(
            "/api/vuln-imports",
            data={"file": (io.BytesIO(big), "huge.csv")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)
        err = resp.get_json()["error"]
        self.assertIn("50 MB", err)
        self.assertIn("API", err)


if __name__ == "__main__":
    unittest.main()
