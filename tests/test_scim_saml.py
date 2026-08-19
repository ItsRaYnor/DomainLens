"""SCIM OAuth-preferred provisioning, SAML legacy SSO, and local backup tests."""

from __future__ import annotations

import base64
import importlib
import os
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse


def _reload_app(env: dict):
    for key, value in env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    import auth
    import db
    import app
    import scim
    import scim_oauth
    import saml_sp
    from settings.store import get_store

    auth = importlib.reload(auth)
    db = importlib.reload(db)
    scim_oauth = importlib.reload(scim_oauth)
    scim = importlib.reload(scim)
    saml_sp = importlib.reload(saml_sp)
    db.init_db()
    get_store(db_module=db, force_new=True)
    app_module = importlib.reload(app)
    return auth, db, app_module, scim, scim_oauth, saml_sp


class ScimOAuthPreferredTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.env = {
            "DOMAINLENS_DB": os.path.join(self.tempdir.name, "scim.db"),
            "DOMAINLENS_DISABLE_SCHEDULER": "1",
            "DOMAINLENS_SECRET_KEY": "scim-test-secret-key",
            "SCIM_ENABLED": "1",
            "SCIM_AUTH_MODE": "oauth",
            "SCIM_CLIENT_ID": "scim-client",
            "SCIM_CLIENT_SECRET": "scim-secret",
            "OAUTH_ENABLED": "0",
            "AUTH_LOCAL_ENABLED": "1",
            "AUTH_REQUIRE_LOGIN": "0",
            "LOCAL_ADMIN_EMAIL": "admin@example.com",
            "LOCAL_ADMIN_PASSWORD": "Valid-Passw0rd!",
            "SAML_ENABLED": None,
            "SCIM_BEARER_TOKEN": None,
        }
        self.auth, self.db, self.app_module, self.scim, self.scim_oauth, self.saml = _reload_app(
            self.env
        )
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in list(self.env):
            os.environ.pop(key, None)

    def _token(self):
        resp = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "scim-client",
                "client_secret": "scim-secret",
                "scope": "scim",
            },
        )
        self.assertEqual(resp.status_code, 200, resp.data)
        return resp.get_json()["access_token"]

    def test_oauth_token_endpoint_preferred(self):
        token = self._token()
        self.assertTrue(token)
        ok, _ = self.scim_oauth.verify_access_token(token)
        self.assertTrue(ok)

    def test_scim_rejects_missing_bearer(self):
        resp = self.client.get("/scim/v2/Users")
        self.assertEqual(resp.status_code, 401)

    def test_scim_rejects_legacy_when_oauth_only(self):
        os.environ["SCIM_BEARER_TOKEN"] = "legacy-static"
        # auth_mode remains oauth — legacy must not work
        resp = self.client.get(
            "/scim/v2/Users",
            headers={"Authorization": "Bearer legacy-static"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_scim_user_lifecycle_with_oauth(self):
        token = self._token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/scim+json",
        }
        create = self.client.post(
            "/scim/v2/Users",
            headers=headers,
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "ada@contoso.com",
                "externalId": "entra-oid-ada",
                "displayName": "Ada Lovelace",
                "active": True,
                "emails": [{"primary": True, "type": "work", "value": "ada@contoso.com"}],
            },
        )
        self.assertEqual(create.status_code, 201, create.data)
        body = create.get_json()
        self.assertEqual(body["userName"], "ada@contoso.com")
        self.assertTrue(body["active"])
        user_id = body["id"]

        row = self.db.get_user(int(user_id), include_secrets=True)
        self.assertEqual(row["provider"], "scim")
        self.assertEqual(row["external_id"], "entra-oid-ada")
        self.assertFalse(row.get("password_hash"))

        listed = self.client.get(
            '/scim/v2/Users?filter=userName eq "ada@contoso.com"',
            headers=headers,
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.get_json()["totalResults"], 1)

        patched = self.client.patch(
            f"/scim/v2/Users/{user_id}",
            headers=headers,
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "Replace", "path": "active", "value": False}],
            },
        )
        self.assertEqual(patched.status_code, 200)
        self.assertFalse(patched.get_json()["active"])
        self.assertFalse(self.db.get_user(int(user_id))["enabled"])

    def test_both_mode_accepts_legacy_bearer(self):
        os.environ["SCIM_AUTH_MODE"] = "both"
        os.environ["SCIM_BEARER_TOKEN"] = "legacy-static-token"
        self.auth, self.db, self.app_module, self.scim, self.scim_oauth, self.saml = _reload_app(
            {**self.env, "SCIM_AUTH_MODE": "both", "SCIM_BEARER_TOKEN": "legacy-static-token"}
        )
        self.client = self.app_module.app.test_client()
        resp = self.client.get(
            "/scim/v2/ServiceProviderConfig",
            headers={"Authorization": "Bearer legacy-static-token"},
        )
        self.assertEqual(resp.status_code, 200)
        schemes = resp.get_json()["authenticationSchemes"]
        self.assertTrue(schemes[0]["primary"])

    def test_auth_status_reports_scim_oauth_preferred(self):
        # The SCIM block is configuration, not something a sign-in screen
        # needs, so it is only answered to an authenticated admin now.
        self.client.post("/auth/local/login", data={
            "email": "admin@example.com", "password": "Valid-Passw0rd!"})
        payload = self.client.get("/api/auth/me").get_json()
        self.assertTrue(payload["scim"]["enabled"])
        self.assertEqual(payload["scim"]["auth_mode"], "oauth")
        self.assertTrue(payload["scim"]["prefer_oauth"])
        self.assertTrue(payload["local_backup"] or payload["local_enabled"])

    def test_scim_configuration_is_not_answered_before_login(self):
        payload = self.client.get("/api/auth/me").get_json()
        self.assertFalse(payload["authenticated"])
        for private in ("scim", "password_policy", "mfa", "azure"):
            self.assertNotIn(private, payload, private)


class ScimFederatedLoginTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        env = {
            "DOMAINLENS_DB": os.path.join(self.tempdir.name, "fed.db"),
            "DOMAINLENS_DISABLE_SCHEDULER": "1",
            "DOMAINLENS_SECRET_KEY": "fed-secret",
            "SCIM_ENABLED": "1",
            "SCIM_AUTH_MODE": "oauth",
            "SCIM_CLIENT_ID": "scim-client",
            "SCIM_CLIENT_SECRET": "scim-secret",
            "AUTH_LOCAL_ENABLED": "1",
            "AUTH_REQUIRE_LOGIN": "0",
            "LOCAL_ADMIN_EMAIL": "admin@example.com",
            "LOCAL_ADMIN_PASSWORD": "Valid-Passw0rd!",
            "OAUTH_ENABLED": "0",
        }
        self.auth, self.db, self.app_module, *_ = _reload_app(env)
        # Provision an admin via SCIM helper
        self.uid = self.db.create_user(
            email="prov@contoso.com",
            password_hash=None,
            name="Provisioned",
            role="admin",
            enabled=True,
            provider="scim",
            external_id="oid-prov",
            user_name="prov@contoso.com",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_oauth_profile_inherits_scim_role(self):
        profile = self.auth.resolve_federated_user(
            {
                "email": "prov@contoso.com",
                "name": "From IdP",
                "provider": "azure",
                "sub": "oid-prov",
            }
        )
        self.assertEqual(profile["role"], "admin")
        self.assertTrue(profile["db_user"])
        self.assertEqual(profile["id"], self.uid)

    def test_disabled_scim_user_denied(self):
        self.db.update_user(self.uid, enabled=False)
        with self.assertRaises(PermissionError):
            self.auth.resolve_federated_user(
                {"email": "prov@contoso.com", "provider": "azure", "sub": "oid-prov"}
            )

    def test_scim_user_without_password_cannot_local_login(self):
        user, err, _ = self.auth.attempt_local_login("prov@contoso.com", "anything")
        self.assertIsNone(user)
        self.assertIn("no local password", err.lower())

    def test_local_backup_still_works(self):
        user, err, needs_mfa = self.auth.attempt_local_login(
            "admin@example.com", "Valid-Passw0rd!"
        )
        self.assertIsNone(err)
        self.assertFalse(needs_mfa)
        self.assertEqual(user["email"], "admin@example.com")
        self.assertEqual(user["role"], "admin")


def _make_idp_keypair():
    """Generate a throwaway self-signed IdP cert + key for SAML signing tests."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as _dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


class SamlLegacyTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.idp_cert, self.idp_key = _make_idp_keypair()
        env = {
            "DOMAINLENS_DB": os.path.join(self.tempdir.name, "saml.db"),
            "DOMAINLENS_DISABLE_SCHEDULER": "1",
            "DOMAINLENS_SECRET_KEY": "saml-secret",
            "SAML_ENABLED": "1",
            "SAML_IDP_SSO_URL": "https://login.microsoftonline.com/tenant/saml2",
            "SAML_ENTITY_ID": "https://domainlens.example/auth/saml/metadata",
            "SAML_IDP_CERT": self.idp_cert,
            "OAUTH_ENABLED": "1",
            "OAUTH_PROVIDER": "azure",
            "AZURE_TENANT_ID": "11111111-2222-3333-4444-555555555555",
            "AZURE_CLIENT_ID": "azure-client",
            "AZURE_CLIENT_SECRET": "azure-secret",
            "AUTH_LOCAL_ENABLED": "1",
            "AUTH_REQUIRE_LOGIN": "0",
            "LOCAL_ADMIN_EMAIL": "admin@example.com",
            "LOCAL_ADMIN_PASSWORD": "Valid-Passw0rd!",
            "SCIM_ENABLED": "0",
        }
        self.auth, self.db, self.app_module, _, _, self.saml = _reload_app(env)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_oauth_is_preferred_over_saml_on_login_page(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode()
        oauth_pos = html.find("Preferred:")
        saml_pos = html.find("legacy SAML")
        local_pos = html.find("local backup")
        self.assertGreater(oauth_pos, 0)
        self.assertGreater(saml_pos, oauth_pos)
        self.assertGreater(local_pos, saml_pos)
        self.assertIn("Continue with Microsoft Entra ID", html)
        # preferred_sso stays public: the login page needs it to decide which
        # button leads. The rest of the SAML block does not, so it is checked
        # as an admin.
        status = self.client.get("/api/auth/me").get_json()
        self.assertEqual(status["preferred_sso"], "oauth")
        self.assertNotIn("sso_preference", status)

        self.client.post("/auth/local/login", data={
            "email": "admin@example.com", "password": "Valid-Passw0rd!"})
        status = self.client.get("/api/auth/me").get_json()
        self.assertEqual(status["sso_preference"][0], "oauth")
        self.assertTrue(status["saml"]["legacy"])
        self.assertFalse(status["saml"]["preferred"])

    def test_saml_metadata_and_authn_redirect(self):
        meta = self.client.get("/auth/saml/metadata")
        self.assertEqual(meta.status_code, 200)
        self.assertIn(b"EntityDescriptor", meta.data)
        self.assertIn(b"AssertionConsumerService", meta.data)

        start = self.client.get("/auth/saml/login", follow_redirects=False)
        self.assertEqual(start.status_code, 302)
        loc = start.headers["Location"]
        self.assertIn("login.microsoftonline.com", loc)
        qs = parse_qs(urlparse(loc).query)
        self.assertIn("SAMLRequest", qs)

    _UNSIGNED_ASSERTION = """<?xml version="1.0"?>
        <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
          <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
          <saml2:Assertion>
            <saml2:Subject>
              <saml2:NameID>sam.user@contoso.com</saml2:NameID>
            </saml2:Subject>
            <saml2:AttributeStatement>
              <saml2:Attribute Name="http://schemas.microsoft.com/identity/claims/displayname">
                <saml2:AttributeValue>Sam User</saml2:AttributeValue>
              </saml2:Attribute>
            </saml2:AttributeStatement>
          </saml2:Assertion>
        </saml2p:Response>
        """

    def test_saml_rejects_unsigned_assertion(self):
        """Security: unsigned assertions must be rejected (they are forgeable)."""
        encoded = base64.b64encode(self._UNSIGNED_ASSERTION.encode()).decode()
        with self.assertRaises(Exception):
            self.saml.parse_saml_response(encoded)

        resp = self.client.post("/auth/saml/acs", data={"SAMLResponse": encoded})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=saml_failed", resp.headers["Location"])
        me = self.client.get("/api/auth/me").get_json()
        self.assertFalse(me["authenticated"])

    def test_saml_accepts_valid_signed_assertion(self):
        """A properly signed assertion verified against idp_cert is accepted."""
        from lxml import etree
        from signxml import XMLSigner

        cert_pem, key_pem = self.idp_cert, self.idp_key

        unsigned = (
            '<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" '
            'IssueInstant="2026-01-01T00:00:00Z">'
            '<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>'
            '<saml2:Assertion ID="_a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            '<saml2:Issuer>test-idp</saml2:Issuer>'
            '<saml2:Subject><saml2:NameID>sam.user@contoso.com</saml2:NameID></saml2:Subject>'
            '<saml2:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>'
            '</saml2:Assertion></saml2p:Response>'
        )
        root = etree.fromstring(unsigned.encode())
        signed = XMLSigner(
            signature_algorithm="rsa-sha256", digest_algorithm="sha256"
        ).sign(root, key=key_pem.encode(), cert=cert_pem.encode())
        encoded = base64.b64encode(etree.tostring(signed)).decode()

        cfg = self.saml.saml_config()
        cfg["idp_cert"] = cert_pem
        cfg["allow_unsigned"] = False
        profile = self.saml.parse_saml_response(encoded, cfg)
        self.assertEqual(profile["email"], "sam.user@contoso.com")
        self.assertEqual(profile["provider"], "saml")

        # Tampering after signing must be rejected.
        tampered = etree.tostring(signed).replace(b"sam.user@contoso.com", b"attacker@evil.com")
        with self.assertRaises(Exception):
            self.saml.parse_saml_response(base64.b64encode(tampered).decode(), cfg)


class LocalBackupOutageTests(unittest.TestCase):
    """Local accounts remain usable when OAuth/Entra path fails."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        env = {
            "DOMAINLENS_DB": os.path.join(self.tempdir.name, "backup.db"),
            "DOMAINLENS_DISABLE_SCHEDULER": "1",
            "DOMAINLENS_SECRET_KEY": "backup-secret",
            "OAUTH_ENABLED": "1",
            "OAUTH_REQUIRE_LOGIN": "1",
            "OAUTH_PROVIDER": "azure",
            "AZURE_TENANT_ID": "11111111-2222-3333-4444-555555555555",
            "AZURE_CLIENT_ID": "azure-client",
            "AZURE_CLIENT_SECRET": "azure-secret",
            "AUTH_LOCAL_ENABLED": "1",
            "AUTH_REQUIRE_LOGIN": "1",
            "LOCAL_ADMIN_EMAIL": "break-glass@example.com",
            "LOCAL_ADMIN_PASSWORD": "Valid-Passw0rd!",
            "SCIM_ENABLED": "0",
            "SAML_ENABLED": "0",
        }
        self.auth, self.db, self.app_module, *_ = _reload_app(env)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_login_page_offers_local_backup_under_oauth(self):
        resp = self.client.get("/login")
        html = resp.data.decode()
        self.assertIn("Preferred:", html)
        self.assertIn("local backup", html)
        self.assertIn("Sign in with local account", html)

    def test_local_login_works_when_oauth_exchange_would_fail(self):
        # Simulate Entra outage for token exchange; local path independent
        with mock.patch("auth.exchange_code", side_effect=RuntimeError("entra down")):
            resp = self.client.post(
                "/auth/local/login",
                data={
                    "email": "break-glass@example.com",
                    "password": "Valid-Passw0rd!",
                    "next": "/",
                },
                follow_redirects=False,
            )
        self.assertEqual(resp.status_code, 302)
        me = self.client.get("/api/auth/me").get_json()
        self.assertTrue(me["authenticated"])
        self.assertEqual(me["user"]["email"], "break-glass@example.com")
        self.assertEqual(me["user"]["provider"], "local")


class ScimOrgLogicalAttributeTests(unittest.TestCase):
    """Department, CompanyName, manager, and default logical attrs."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        env = {
            "DOMAINLENS_DB": os.path.join(self.tempdir.name, "scim-org.db"),
            "DOMAINLENS_DISABLE_SCHEDULER": "1",
            "DOMAINLENS_SECRET_KEY": "scim-org-secret",
            "SCIM_ENABLED": "1",
            "SCIM_AUTH_MODE": "oauth",
            "SCIM_CLIENT_ID": "scim-client",
            "SCIM_CLIENT_SECRET": "scim-secret",
            "AUTH_LOCAL_ENABLED": "0",
            "OAUTH_ENABLED": "0",
        }
        self.auth, self.db, self.app_module, self.scim, self.scim_oauth, _ = _reload_app(env)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def _token(self):
        resp = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "scim-client",
                "client_secret": "scim-secret",
                "scope": "scim",
            },
        )
        self.assertEqual(resp.status_code, 200)
        return resp.get_json()["access_token"]

    def test_create_with_department_company_manager(self):
        token = self._token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/scim+json",
        }
        enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        domainlens = "urn:ietf:params:scim:schemas:extension:domainlens:2.0:User"
        create = self.client.post(
            "/scim/v2/Users",
            headers=headers,
            json={
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User",
                    enterprise,
                    domainlens,
                ],
                "userName": "ada@contoso.com",
                "externalId": "oid-ada",
                "displayName": "Ada Lovelace",
                "title": "Engineer",
                "active": True,
                "emails": [{"primary": True, "type": "work", "value": "ada@contoso.com"}],
                "phoneNumbers": [{"type": "work", "value": "+31 20 123"}],
                "companyName": "Contoso NL",
                enterprise: {
                    "department": "Platform Engineering",
                    "organization": "Contoso NL",
                    "employeeNumber": "E-1042",
                    "costCenter": "CC-9",
                    "division": "Digital",
                    "manager": {
                        "value": "oid-manager-grace",
                        "displayName": "Grace Hopper",
                    },
                },
                domainlens: {
                    "companyName": "Contoso NL",
                    "officeLocation": "Amsterdam",
                    "costCodeLogical": "LOGIC-1",
                },
            },
        )
        self.assertEqual(create.status_code, 201, create.data)
        body = create.get_json()
        self.assertEqual(body["department"], "Platform Engineering")
        self.assertEqual(body["companyName"], "Contoso NL")
        self.assertEqual(body["title"], "Engineer")
        self.assertEqual(body[enterprise]["department"], "Platform Engineering")
        self.assertEqual(body[enterprise]["manager"]["value"], "oid-manager-grace")
        self.assertEqual(body[enterprise]["manager"]["displayName"], "Grace Hopper")
        self.assertEqual(body[domainlens]["officeLocation"], "Amsterdam")
        self.assertEqual(body[domainlens]["costCodeLogical"], "LOGIC-1")

        row = self.db.get_user(int(body["id"]))
        self.assertEqual(row["department"], "Platform Engineering")
        self.assertEqual(row["company_name"], "Contoso NL")
        self.assertEqual(row["organization"], "Contoso NL")
        self.assertEqual(row["job_title"], "Engineer")
        self.assertEqual(row["employee_number"], "E-1042")
        self.assertEqual(row["cost_center"], "CC-9")
        self.assertEqual(row["division"], "Digital")
        self.assertEqual(row["manager_external_id"], "oid-manager-grace")
        self.assertEqual(row["manager_display_name"], "Grace Hopper")
        self.assertEqual(row["office_location"], "Amsterdam")
        self.assertEqual(row["phone_number"], "+31 20 123")
        self.assertEqual((row.get("scim_profile") or {}).get("costCodeLogical"), "LOGIC-1")

    def test_patch_department_and_manager(self):
        token = self._token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/scim+json",
        }
        create = self.client.post(
            "/scim/v2/Users",
            headers=headers,
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "sam@contoso.com",
                "externalId": "oid-sam",
                "emails": [{"primary": True, "value": "sam@contoso.com", "type": "work"}],
                "active": True,
            },
        )
        uid = create.get_json()["id"]
        enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        patched = self.client.patch(
            f"/scim/v2/Users/{uid}",
            headers=headers,
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "Replace", "path": "department", "value": "Security"},
                    {"op": "Add", "path": "companyName", "value": "Contoso Corp"},
                    {
                        "op": "Replace",
                        "path": f"{enterprise}:manager",
                        "value": {"value": "oid-boss", "displayName": "Boss"},
                    },
                ],
            },
        )
        self.assertEqual(patched.status_code, 200, patched.data)
        body = patched.get_json()
        self.assertEqual(body["department"], "Security")
        self.assertEqual(body["companyName"], "Contoso Corp")
        self.assertEqual(body[enterprise]["manager"]["value"], "oid-boss")
        row = self.db.get_user(int(uid))
        self.assertEqual(row["department"], "Security")
        self.assertEqual(row["company_name"], "Contoso Corp")
        self.assertEqual(row["manager_external_id"], "oid-boss")

    def test_profile_from_payload_unit(self):
        profile = self.scim.profile_from_scim_payload(
            {
                "companyName": "Acme",
                "department": "Ops",
                "title": "SRE",
                "manager": "oid-mgr",
                "addresses": [
                    {
                        "primary": True,
                        "streetAddress": "1 Main",
                        "locality": "Utrecht",
                        "region": "UT",
                        "postalCode": "3500",
                        "country": "NL",
                    }
                ],
            }
        )
        self.assertEqual(profile["company_name"], "Acme")
        self.assertEqual(profile["organization"], "Acme")
        self.assertEqual(profile["department"], "Ops")
        self.assertEqual(profile["job_title"], "SRE")
        self.assertEqual(profile["manager_external_id"], "oid-mgr")
        self.assertEqual(profile["city"], "Utrecht")
        self.assertEqual(profile["country"], "NL")


if __name__ == "__main__":
    unittest.main()
