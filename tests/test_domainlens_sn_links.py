"""ServiceNow → DomainLens deep-link helpers and remediation pages."""

from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from unittest import mock


class DomainLensLinksUnitTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("DOMAINLENS_PUBLIC_URL", None)
        os.environ.pop("DOMAINLENS_BASE_URL", None)

    def test_vuln_and_domain_urls(self):
        os.environ["DOMAINLENS_PUBLIC_URL"] = "https://domainlens.example.com/"
        import domainlens_links

        importlib.reload(domainlens_links)
        self.assertEqual(
            domainlens_links.vuln_remediation_url(7),
            "https://domainlens.example.com/remediate/vuln/7",
        )
        self.assertEqual(
            domainlens_links.domain_remediation_url("Example.COM"),
            "https://domainlens.example.com/remediate/domain/example.com",
        )

    def test_finding_link_block_includes_urls(self):
        os.environ["DOMAINLENS_PUBLIC_URL"] = "https://np.test"
        import domainlens_links

        importlib.reload(domainlens_links)
        block = domainlens_links.finding_link_block(
            {"id": 9, "domain": "acme.com", "title": "TLS", "severity": "high"}
        )
        self.assertEqual(block["domainlens_url"], "https://np.test/remediate/vuln/9")
        self.assertIn("/remediate/vuln/9", block["text"])
        self.assertIn("Ownership and assignment stay in ServiceNow", block["text"])


class RemediatePageTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "remediate.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["DOMAINLENS_PUBLIC_URL"] = "https://domainlens.example.com"
        os.environ.pop("OAUTH_ENABLED", None)
        os.environ.pop("AUTH_LOCAL_ENABLED", None)

        import auth
        import db
        import app
        from settings.store import get_store

        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)
        importlib.reload(auth)
        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

        record = self.db.save_vuln_import(
            filename="t.csv",
            source_format="csv",
            findings=[
                {
                    "title": "Outdated OpenSSL",
                    "severity": "high",
                    "hostname": "web.acme.com",
                    "domain": "acme.com",
                    "solution": "Upgrade OpenSSL",
                    "description": "Old library",
                    "cves": ["CVE-2023-0001"],
                    "asset_ip": "10.1.1.1",
                }
            ],
            summary={},
            warnings=[],
            header_map={},
            row_count=1,
        )
        findings = self.db.list_vuln_findings(import_id=record["id"], limit=5)
        self.finding_id = findings[0]["id"]

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "DOMAINLENS_PUBLIC_URL"):
            os.environ.pop(key, None)

    def test_remediate_vuln_page(self):
        resp = self.client.get(f"/remediate/vuln/{self.finding_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Outdated OpenSSL", resp.data)
        self.assertIn(b"Ownership and assignment stay in ServiceNow", resp.data)
        self.assertIn(b"tab=advies", resp.data)

    def test_remediate_domain_page(self):
        resp = self.client.get("/remediate/domain/acme.com")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"acme.com", resp.data)
        # Assert the way onward exists, not its exact wording — the label has
        # changed once already and the link is what ServiceNow users need.
        self.assertIn(b"/?domain=acme.com", resp.data)

    def test_incident_includes_domainlens_links(self):
        import servicenow

        importlib.reload(servicenow)
        with mock.patch.object(servicenow, "should_notify", return_value=True), \
             mock.patch.object(servicenow, "config", return_value={
                 "enabled": True,
                 "instance": "https://example.service-now.com",
                 "user": "u",
                 "password": "p",
                 "min_severity": "high",
                 "assignment_group": None,
                 "caller_id": None,
                 "category": "Network",
                 "subcategory": "DNS",
             }), \
             mock.patch("servicenow.requests.post") as post:
            post.return_value.status_code = 201
            post.return_value.raise_for_status = lambda: None
            post.return_value.json.return_value = {"result": {"sys_id": "i1", "number": "INC1"}}
            servicenow.create_incident(
                summary="DNS change",
                severity="high",
                details={"scan_id": 5, "domain": "acme.com", "recommendation_count": 2},
                monitor={"id": 3, "domain": "acme.com", "target": "acme.com", "record_type": "A"},
            )
        payload = post.call_args.kwargs["json"]
        self.assertIn("https://domainlens.example.com/report/5", payload["description"])
        self.assertIn("https://domainlens.example.com/remediate/domain/acme.com", payload["work_notes"])


if __name__ == "__main__":
    unittest.main()
