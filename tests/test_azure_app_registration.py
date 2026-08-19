"""Tests for Azure App Registration / Microsoft Entra ID OAuth support."""

from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse


class AzureEndpointTests(unittest.TestCase):
    def test_public_tenant_endpoints(self):
        import auth

        ep = auth.azure_endpoint_urls("contoso-tenant-id", "public")
        self.assertEqual(
            ep["authorize_url"],
            "https://login.microsoftonline.com/contoso-tenant-id/oauth2/v2.0/authorize",
        )
        self.assertEqual(
            ep["token_url"],
            "https://login.microsoftonline.com/contoso-tenant-id/oauth2/v2.0/token",
        )
        self.assertEqual(ep["userinfo_url"], "https://graph.microsoft.com/v1.0/me")
        self.assertEqual(ep["issuer"], "https://login.microsoftonline.com/contoso-tenant-id/v2.0")
        self.assertEqual(ep["graph_scope_default"], "https://graph.microsoft.com/.default")

    def test_usgov_cloud_hosts(self):
        import auth

        ep = auth.azure_endpoint_urls("gov-tenant", "usgov")
        self.assertIn("login.microsoftonline.us", ep["authorize_url"])
        self.assertEqual(ep["userinfo_url"], "https://graph.microsoft.us/v1.0/me")
        self.assertEqual(ep["graph_scope_default"], "https://graph.microsoft.us/.default")

    def test_default_tenant_is_organizations(self):
        import auth

        ep = auth.azure_endpoint_urls(None, "public")
        self.assertIn("/organizations/oauth2/v2.0/authorize", ep["authorize_url"])


class AzureOAuthConfigTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "azure-auth.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["OAUTH_ENABLED"] = "1"
        os.environ["OAUTH_REQUIRE_LOGIN"] = "1"
        os.environ["OAUTH_PROVIDER"] = "azure"
        os.environ["AZURE_TENANT_ID"] = "11111111-2222-3333-4444-555555555555"
        os.environ["AZURE_CLIENT_ID"] = "azure-app-client-id"
        os.environ["AZURE_CLIENT_SECRET"] = "azure-app-secret"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret-azure"
        os.environ.pop("OAUTH_CLIENT_ID", None)
        os.environ.pop("OAUTH_CLIENT_SECRET", None)
        os.environ.pop("AUTH_LOCAL_ENABLED", None)
        os.environ.pop("OAUTH_AUTHORIZE_URL", None)
        os.environ.pop("OAUTH_TOKEN_URL", None)
        os.environ.pop("OAUTH_USERINFO_URL", None)

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
        for key in (
            "DOMAINLENS_DB",
            "DOMAINLENS_DISABLE_SCHEDULER",
            "OAUTH_ENABLED",
            "OAUTH_REQUIRE_LOGIN",
            "OAUTH_PROVIDER",
            "AZURE_TENANT_ID",
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_CLOUD",
            "AZURE_SCOPES",
            "AZURE_REDIRECT_URI",
            "OAUTH_CLIENT_ID",
            "OAUTH_CLIENT_SECRET",
            "OAUTH_TENANT_ID",
            "DOMAINLENS_SECRET_KEY",
            "OAUTH_ALLOWED_DOMAINS",
            "AUTH_LOCAL_ENABLED",
        ):
            os.environ.pop(key, None)

    def test_oauth_config_resolves_app_registration(self):
        cfg = self.auth.oauth_config()
        self.assertTrue(cfg["configured"])
        self.assertEqual(cfg["provider"], "azure")
        self.assertEqual(cfg["display_name"], "Microsoft Entra ID")
        self.assertTrue(cfg["azure_app_registration"])
        self.assertTrue(cfg["azure_tenant_configured"])
        self.assertEqual(cfg["tenant_id"], "11111111-2222-3333-4444-555555555555")
        self.assertIn("11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize", cfg["authorize_url"])
        self.assertIn("11111111-2222-3333-4444-555555555555/oauth2/v2.0/token", cfg["token_url"])
        self.assertEqual(cfg["userinfo_url"], "https://graph.microsoft.com/v1.0/me")
        self.assertEqual(cfg["client_id"], "azure-app-client-id")
        self.assertIn("User.Read", cfg["scopes"])

    def test_provider_aliases_map_to_azure(self):
        for alias in ("entra", "aad", "azuread", "azure_ad"):
            os.environ["OAUTH_PROVIDER"] = alias
            auth = importlib.reload(self.auth)
            cfg = auth.oauth_config()
            self.assertEqual(cfg["provider"], "azure", alias)
            self.assertTrue(cfg["azure_app_registration"], alias)

    def test_authorize_url_includes_azure_params(self):
        url = self.auth.build_authorize_url("state-xyz", "https://domainlens.example/auth/callback")
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        self.assertTrue(parsed.path.endswith("/oauth2/v2.0/authorize"))
        self.assertEqual(qs["client_id"], ["azure-app-client-id"])
        self.assertEqual(qs["response_type"], ["code"])
        self.assertEqual(qs["response_mode"], ["query"])
        self.assertEqual(qs["prompt"], ["select_account"])
        self.assertEqual(qs["state"], ["state-xyz"])
        self.assertIn("openid", qs["scope"][0])

    def test_login_page_shows_entra_label(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        # The button label stays: it is what the visitor presses, and naming
        # the provider is the whole point of the button.
        self.assertIn(b"Continue with Microsoft Entra ID", resp.data)

    def test_login_page_does_not_publish_the_auth_configuration(self):
        # It used to print the provider, the tenant id, the SCIM endpoint and
        # whether local accounts exist — to anyone who loaded the page. None
        # of it helps a person sign in; together it maps the authentication
        # surface for whoever is deciding where to push.
        body = self.client.get("/login").data
        for leak in (b"provider <code>azure</code>", b"tenant", b"SCIM",
                     b"OAuth callback", b"Local backup accounts",
                     b"Password policy", b"MFA required"):
            self.assertNotIn(leak, body, leak)

    def test_the_tenant_is_not_answered_before_login(self):
        # The tenant id and issuer URL identify the organisation and its
        # directory. An anonymous caller gets the button labels and nothing
        # more.
        payload = self.client.get("/api/auth/me").get_json()
        self.assertEqual(payload["provider"], "azure")
        self.assertEqual(payload["display_name"], "Microsoft Entra ID")
        self.assertNotIn("azure", payload)
        self.assertNotIn("password_policy", payload)
        self.assertNotIn("mfa", payload)

    def test_auth_status_includes_azure_block(self):
        with self.client.session_transaction() as sess:
            sess["user"] = {"id": 1, "email": "admin@example.com", "role": "admin"}
        resp = self.client.get("/api/auth/me")
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertEqual(payload["provider"], "azure")
        self.assertEqual(payload["display_name"], "Microsoft Entra ID")
        self.assertTrue(payload["azure"]["app_registration"])
        self.assertTrue(payload["azure"]["tenant_configured"])
        self.assertEqual(payload["azure"]["tenant_id"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(payload["azure"]["cloud"], "public")

    def test_exchange_code_normalizes_graph_profile(self):
        token_json = {"access_token": "atok"}
        graph_json = {
            "id": "oid-123",
            "displayName": "Ada Lovelace",
            "mail": None,
            "userPrincipalName": "ada@contoso.com",
        }

        class _Resp:
            def __init__(self, data):
                self._data = data

            def raise_for_status(self):
                return None

            def json(self):
                return self._data

            @property
            def ok(self):
                return True

        with mock.patch("auth.requests.post", return_value=_Resp(token_json)) as post:
            with mock.patch("auth.requests.get", return_value=_Resp(graph_json)) as get:
                profile = self.auth.exchange_code("auth-code", "https://domainlens.example/auth/callback")

        self.assertEqual(profile["email"], "ada@contoso.com")
        self.assertEqual(profile["name"], "Ada Lovelace")
        self.assertEqual(profile["sub"], "oid-123")
        self.assertEqual(profile["provider"], "azure")
        post.assert_called_once()
        get.assert_called_once()
        self.assertEqual(
            get.call_args[0][0],
            "https://graph.microsoft.com/v1.0/me",
        )

    def test_client_credentials_token(self):
        class _Resp:
            def raise_for_status(self):
                return None

            def json(self):
                return {"access_token": "app-token", "expires_in": 3600, "token_type": "Bearer"}

        with mock.patch("auth.requests.post", return_value=_Resp()) as post:
            token = self.auth.azure_client_credentials_token()

        self.assertEqual(token["access_token"], "app-token")
        args, kwargs = post.call_args
        self.assertIn("11111111-2222-3333-4444-555555555555/oauth2/v2.0/token", args[0])
        self.assertEqual(kwargs["data"]["grant_type"], "client_credentials")
        self.assertEqual(kwargs["data"]["scope"], "https://graph.microsoft.com/.default")
        self.assertEqual(kwargs["data"]["client_id"], "azure-app-client-id")


class AzureMicrosoftUpgradeTests(unittest.TestCase):
    """microsoft + tenant_id upgrades to tenant-scoped App Registration endpoints."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "ms-upgrade.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["OAUTH_ENABLED"] = "1"
        os.environ["OAUTH_PROVIDER"] = "microsoft"
        os.environ["AZURE_TENANT_ID"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        os.environ["OAUTH_CLIENT_ID"] = "ms-client"
        os.environ["OAUTH_CLIENT_SECRET"] = "ms-secret"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        os.environ.pop("AUTH_LOCAL_ENABLED", None)

        import auth
        import db
        from settings.store import get_store

        self.auth = importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)

    def tearDown(self):
        self.tempdir.cleanup()
        for key in (
            "DOMAINLENS_DB",
            "DOMAINLENS_DISABLE_SCHEDULER",
            "OAUTH_ENABLED",
            "OAUTH_PROVIDER",
            "AZURE_TENANT_ID",
            "OAUTH_CLIENT_ID",
            "OAUTH_CLIENT_SECRET",
            "DOMAINLENS_SECRET_KEY",
        ):
            os.environ.pop(key, None)

    def test_microsoft_with_tenant_becomes_azure_endpoints(self):
        cfg = self.auth.oauth_config()
        self.assertEqual(cfg["provider"], "azure")
        self.assertIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", cfg["authorize_url"])
        self.assertNotIn("/common/", cfg["authorize_url"])


class AzureClientCredentialsGuardTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(self.tempdir.name, "cc-guard.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        os.environ["OAUTH_ENABLED"] = "1"
        os.environ["OAUTH_PROVIDER"] = "microsoft"
        os.environ["OAUTH_CLIENT_ID"] = "ms-client"
        os.environ["OAUTH_CLIENT_SECRET"] = "ms-secret"
        os.environ["DOMAINLENS_SECRET_KEY"] = "test-secret"
        os.environ.pop("AZURE_TENANT_ID", None)
        os.environ.pop("OAUTH_TENANT_ID", None)

        import auth
        import db
        from settings.store import get_store

        self.auth = importlib.reload(auth)
        self.db = importlib.reload(db)
        self.db.init_db()
        get_store(db_module=self.db, force_new=True)

    def tearDown(self):
        self.tempdir.cleanup()
        for key in (
            "DOMAINLENS_DB",
            "DOMAINLENS_DISABLE_SCHEDULER",
            "OAUTH_ENABLED",
            "OAUTH_PROVIDER",
            "OAUTH_CLIENT_ID",
            "OAUTH_CLIENT_SECRET",
            "DOMAINLENS_SECRET_KEY",
            "AZURE_TENANT_ID",
        ):
            os.environ.pop(key, None)

    def test_client_credentials_requires_tenant(self):
        with self.assertRaises(RuntimeError) as ctx:
            self.auth.azure_client_credentials_token()
        self.assertIn("AZURE_TENANT_ID", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
