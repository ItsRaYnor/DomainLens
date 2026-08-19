# Azure App Registration (Microsoft Entra ID)

DomainLens can authenticate users through an **Azure App Registration** (Microsoft Entra ID / Azure AD). This is the recommended way to integrate DomainLens with Microsoft 365 / Entra tenants: one app registration, tenant-scoped OAuth2 v2 endpoints, and Microsoft Graph for the signed-in user profile.

## Why App Registration

| Approach | When to use |
| --- | --- |
| `OAUTH_PROVIDER=azure` + `AZURE_TENANT_ID` | **Preferred** — single-tenant (or multi-tenant) App Registration with Directory (tenant) ID |
| `OAUTH_PROVIDER=microsoft` | Multi-tenant `/common` endpoints; upgrade to `azure` + tenant ID when you register an app in your directory |
| Generic `oidc` | Non-Microsoft IdPs |

App Registration gives you:

- Client ID + client secret (or later certificate) bound to your tenant
- Redirect URI allow-list (`https://your-host/auth/callback`)
- Delegated permissions (`openid`, `profile`, `email`, `User.Read`) for interactive login
- Optional **application** permissions for daemon/client-credentials flows

## Entra portal setup

1. **Microsoft Entra admin center** → **App registrations** → **New registration**
2. Name: e.g. `DomainLens`
3. Supported account types: usually *Accounts in this organizational directory only* (single tenant)
4. Redirect URI (Web): `https://<your-domainlens-host>/auth/callback`
5. After create, copy:
   - **Application (client) ID** → `AZURE_CLIENT_ID` / `OAUTH_CLIENT_ID`
   - **Directory (tenant) ID** → `AZURE_TENANT_ID`
6. **Certificates & secrets** → New client secret → `AZURE_CLIENT_SECRET` / `OAUTH_CLIENT_SECRET`
7. **API permissions** → Microsoft Graph → Delegated:
   - `openid`, `profile`, `email`, `User.Read` (and `offline_access` if you want refresh tokens)
8. Grant **admin consent** if your tenant requires it

## DomainLens configuration

Environment (secrets stay env-only):

```bash
OAUTH_ENABLED=1
OAUTH_REQUIRE_LOGIN=1
OAUTH_PROVIDER=azure
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=your-client-secret
DOMAINLENS_SECRET_KEY=long-random-string
# Optional explicit redirect (otherwise DomainLens builds /auth/callback):
# AZURE_REDIRECT_URI=https://your-host/auth/callback
# Optional cloud: public | usgov | china | germany
# AZURE_CLOUD=public
# Optional scopes override:
# AZURE_SCOPES=openid email profile offline_access User.Read
# Optional allowlists:
# OAUTH_ALLOWED_DOMAINS=contoso.com
```

Aliases accepted for provider: `azure`, `entra`, `aad`, `azuread`, `azure_ad`.

Admin UI → **Settings** → **OAuth / OIDC**: set provider to `azure`, tenant ID, cloud, and optional scopes/prompt. Client ID/secret remain environment variables (shown as configured/masked).

## Flows DomainLens uses

### Interactive login (authorization code)

1. User opens `/login` → **Continue with Microsoft Entra ID**
2. Browser redirects to  
   `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`
3. Callback `/auth/callback` exchanges the code at  
   `…/oauth2/v2.0/token`
4. Profile is loaded from Microsoft Graph `GET /v1.0/me` (`mail` / `userPrincipalName` / `displayName`)

### App-only (client credentials)

For service-to-service calls (e.g. Graph application permissions), use `auth.azure_client_credentials_token()`. Requires a **directory tenant ID** (not `/common`) and Application permissions + admin consent. Default scope: `https://graph.microsoft.com/.default` (or sovereign Graph host for `AZURE_CLOUD`).

## Status API

`GET /api/auth/me` (and related auth status payloads) include:

```json
{
  "provider": "azure",
  "display_name": "Microsoft Entra ID",
  "azure": {
    "app_registration": true,
    "tenant_configured": true,
    "tenant_id": "…",
    "cloud": "public",
    "issuer": "https://login.microsoftonline.com/…/v2.0"
  }
}
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `oauth_not_configured` | Client ID, secret, and that provider resolves authorize/token/userinfo URLs |
| `AADSTS50011` redirect mismatch | Exact redirect URI in App Registration matches `AZURE_REDIRECT_URI` / external URL |
| `access_denied` in DomainLens | `OAUTH_ALLOWED_EMAILS` / `OAUTH_ALLOWED_DOMAINS` |
| Client credentials fails | Set `AZURE_TENANT_ID`; grant Application permissions + admin consent |
| Wrong cloud | Set `AZURE_CLOUD=usgov` (or `china` / `germany`) so login + Graph hosts match |

## Related: SCIM provisioning

After App Registration SSO works, enable Entra **Provisioning** against DomainLens SCIM (`/scim/v2`) using OAuth 2 client credentials to `/oauth/token` (preferred over a static bearer token).

**IDs to sync:** map Entra **Object ID → `externalId`**, **UPN → `userName`**, **mail/UPN → emails**; leave SCIM **`id`** as DomainLens-assigned. Full mapping table: [SCIM_AND_SSO.md](SCIM_AND_SSO.md#which-ids-to-sync-entra--domainlens).

Keep local admin accounts as outage backup.

