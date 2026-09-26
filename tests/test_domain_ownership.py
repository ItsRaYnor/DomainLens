"""Active tests only against domains proven to be yours.

Weak-auth (login attempts with default passwords) and the active scan
(XSS/SQLi/open-redirect probes) were gated by one switch each. Once an
operator enabled one for their own site, any signed-in user could aim it at
any domain -- an intrusion attempt against a stranger, sent from the
organisation's own address.
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from enterprise_harness import EnterpriseAppTestCase


def _fresh_db():
    import importlib
    tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(tempdir.name, "own.db")
    import db
    importlib.reload(db).init_db()
    return tempdir


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get("DOMAINLENS_DB")
        self.tempdir = _fresh_db()
        import domain_ownership
        self.own = domain_ownership

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("DOMAINLENS_DB", None)
        else:
            os.environ["DOMAINLENS_DB"] = self._saved
        self.tempdir.cleanup()

    def test_a_pending_request_is_not_verification(self):
        self.own.request_verification("example.com")
        self.assertFalse(self.own.is_verified("example.com"))

    def test_the_dns_record_with_the_token_verifies(self):
        entry = self.own.request_verification("example.com")
        record = f"domainlens-verification={entry['token']}"
        with mock.patch.object(self.own, "_txt_values", return_value=([record], None)):
            result = self.own.check("example.com")
        self.assertEqual("dns", result["method"])
        self.assertTrue(self.own.is_verified("example.com"))

    def test_someone_elses_token_does_not(self):
        """A TXT record left by another DomainLens instance proves nothing
        about this one's request."""
        self.own.request_verification("example.com")
        with mock.patch.object(self.own, "_txt_values",
                               return_value=(["domainlens-verification=not-ours"], None)), \
             mock.patch.object(self.own, "_check_http", return_value=(False, "404")):
            self.own.check("example.com")
        self.assertFalse(self.own.is_verified("example.com"))

    def test_the_https_file_is_not_fetched_from_a_private_address(self):
        """A name pointed at 127.0.0.1 would turn the check into a request
        into the server's own network."""
        with mock.patch.object(self.own.socket, "getaddrinfo",
                               return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]), \
             mock.patch.object(self.own.requests, "get") as get:
            ok, _ = self.own._check_http("example.com", "tok")
        self.assertFalse(ok)
        get.assert_not_called()

    def test_verifying_the_zone_covers_its_subdomains(self):
        self.own.attest("example.com", "admin@example.com", "our zone")
        self.assertTrue(self.own.is_verified("shop.eu.example.com"))

    def test_verifying_a_subdomain_does_not_cover_its_parent(self):
        self.own.attest("shop.example.com", "admin@example.com", "our shop")
        self.assertFalse(self.own.is_verified("example.com"))

    def test_a_lookalike_suffix_is_not_a_subdomain(self):
        self.own.attest("example.com", "admin@example.com", "our zone")
        self.assertFalse(self.own.is_verified("badexample.com"))

    def test_an_attestation_needs_a_reason(self):
        with self.assertRaises(ValueError):
            self.own.attest("example.com", "admin@example.com", "  ")

    def test_an_old_proof_expires(self):
        """Domains are sold. A proof from years ago proves nothing now."""
        entry = self.own.request_verification("example.com")
        with mock.patch.object(self.own, "_txt_values",
                               return_value=([f"domainlens-verification={entry['token']}"], None)):
            self.own.check("example.com")
        old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        import db
        with db._connect() as conn:
            conn.execute("UPDATE verified_domains SET verified_at=?", (old,))
        self.assertFalse(self.own.is_verified("example.com"))

    def test_a_failed_recheck_does_not_revoke_a_valid_proof(self):
        """One DNS timeout must not switch off a customer's weekly scan."""
        self.own.attest("example.com", "admin@example.com", "ours")
        with mock.patch.object(self.own, "_txt_values", return_value=([], "Timeout")), \
             mock.patch.object(self.own, "_check_http", return_value=(False, "timeout")):
            self.own.check("example.com")
        self.assertTrue(self.own.is_verified("example.com"))


class GateTests(EnterpriseAppTestCase):
    def _enable(self, section):
        from settings.store import get_store
        get_store().update_section(section, {"enabled": True})
        self.app_module._reload_settings()

    def test_weak_auth_sends_nothing_to_an_unverified_domain(self):
        self._enable("weak_auth")
        with mock.patch.object(self.app_module.weak_auth, "scan") as scan:
            result = self.app_module.check_weak_auth("stranger.example")
        scan.assert_not_called()
        self.assertTrue(result["skipped"])
        self.assertEqual("not_applicable", result["state"])

    def test_the_active_scan_sends_nothing_to_an_unverified_domain(self):
        self._enable("active_scan")
        with mock.patch.object(self.app_module.active_scan, "scan") as scan:
            self.app_module.check_active_scan("stranger.example")
        scan.assert_not_called()

    def test_a_verified_domain_is_scanned(self):
        import domain_ownership
        self._enable("active_scan")
        domain_ownership.attest("mine.example", "admin@example.com", "ours")
        with mock.patch.object(self.app_module.active_scan, "scan",
                               return_value={"success": True, "enabled": True}) as scan:
            self.app_module.check_active_scan("www.mine.example")
        scan.assert_called_once()

    def test_a_full_scan_leaves_active_checks_out_for_an_unverified_domain(self):
        self._enable("weak_auth")
        self._enable("active_scan")
        ran = []
        with mock.patch.object(self.app_module, "_run_checks",
                               side_effect=lambda cmap, names, results, cb=None: ran.extend(names)), \
             mock.patch.object(self.app_module, "_attach_ncsc_tls", side_effect=lambda r, d: r):
            self.app_module.full_scan("stranger.example")
        self.assertNotIn("weak_auth", ran)
        self.assertNotIn("active_scan", ran)

    def test_skipped_is_not_reported_as_a_clean_result_or_a_finding(self):
        """Not measured is its own state: neither 'no weak credentials'
        nor something wrong with the scanned domain."""
        import recommendations
        self._enable("weak_auth")
        result = self.app_module.check_weak_auth("stranger.example")
        self.assertNotIn("weak_credentials_found", result)
        recs = recommendations.generate({"domain": "stranger.example", "weak_auth": result})
        self.assertFalse([r for r in recs if r["category"] == "Authentication"])


class OwnershipRoutesTests(EnterpriseAppTestCase):
    def test_an_analyst_can_start_a_verification(self):
        self.login_as("user")
        resp = self.client.post("/api/ownership", json={"domain": "example.com"})
        self.assertEqual(201, resp.status_code)
        self.assertIn("_domainlens-challenge.example.com", resp.get_json()["instructions"]["dns"]["name"])

    def test_an_analyst_cannot_attest_without_proof(self):
        self.login_as("user")
        self.client.post("/admin/domains/example.com/attest", data={"note": "trust me"})
        import domain_ownership
        self.assertFalse(domain_ownership.is_verified("example.com"))

    def test_an_admin_attestation_is_audited_with_its_reason(self):
        import audit_log
        self.login_as("admin")
        self.client.post("/admin/domains/intranet.example/attest", data={"note": "internal"})
        entry = audit_log.list_entries(action="ownership.attest")["entries"][0]
        self.assertEqual("internal", entry["details"]["note"])
        self.assertEqual("admin@example.com", entry["actor_email"])

    def test_the_page_renders(self):
        self.login_as("admin")
        self.client.post("/admin/domains", data={"domain": "example.com"})
        resp = self.client.get("/admin/domains")
        self.assertEqual(200, resp.status_code)
        self.assertIn(b"_domainlens-challenge.example.com", resp.data)


if __name__ == "__main__":
    unittest.main()
