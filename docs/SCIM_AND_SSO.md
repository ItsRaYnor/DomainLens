# SCIM provisioning + SSO preference (OAuth over SAML)

DomainLens supports **SCIM 2.0 user provisioning** from Microsoft Entra ID, with **OAuth 2.0 client credentials** as the preferred way to authorize the provisioning client. Interactive sign-in prefers **OAuth 2 / OpenID Connect (Azure App Registration)**; **SAML** remains available as legacy SSO. **Local accounts** are the backup path when Entra ID or App Registration is down.

## Recommended stack

| Concern | Preferred | Legacy / backup |
| --- | --- | --- |
| User provisioning | SCIM 2.0 (`/scim/v2`) | Manual admin users |
| SCIM authentication | OAuth 2 client credentials (`POST /oauth/token`, scope `scim`) | Static `SCIM_BEARER_TOKEN` |
| Interactive SSO | OAuth 2 / OIDC (`OAUTH_PROVIDER=azure`) | SAML 2.0 (`/auth/saml/*`) |
| Outage / misconfig | Local email/password (`AUTH_LOCAL_ENABLED=1`) | — |

## SCIM 2.0

### Endpoints

| Method | Path |
| --- | --- |
| GET | `/scim/v2/ServiceProviderConfig` |
| GET | `/scim/v2/ResourceTypes` |
| GET | `/scim/v2/Schemas` |
| GET/POST | `/scim/v2/Users` |
| GET/PUT/PATCH/DELETE | `/scim/v2/Users/{id}` |

Tenant URL for Entra provisioning: `https://<domainlens-host>/scim/v2`

### Preferred: OAuth 2 client credentials

```bash
SCIM_ENABLED=1
SCIM_AUTH_MODE=oauth          # oauth | bearer | both
# Reuse Azure App Registration credentials (or dedicated SCIM_*):
SCIM_CLIENT_ID=<app client id>          # or AZURE_CLIENT_ID
SCIM_CLIENT_SECRET=<app client secret>  # or AZURE_CLIENT_SECRET
DOMAINLENS_SECRET_KEY=long-random-string  # signs SCIM access tokens
```

In Entra **Provisioning** → Admin credentials:

1. **Tenant URL:** `https://host/scim/v2`
2. **Authentication method:** OAuth 2.0 Client Credentials  
3. **Token endpoint:** `https://host/oauth/token`  
4. **Client ID / Secret:** same as above  
5. **Scope:** `scim`

Token request:

```bash
curl -s -X POST https://host/oauth/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=...' \
  -d 'client_secret=...' \
  -d 'scope=scim'
```

Use `Authorization: Bearer <access_token>` on SCIM calls.

### Legacy: static bearer

```bash
SCIM_AUTH_MODE=bearer   # or both
SCIM_BEARER_TOKEN=long-random-static-token
```

Prefer `oauth` or `both` during migration; `oauth` alone is recommended in production.

### Which IDs to sync (Entra → DomainLens)

DomainLens cares about **three** identifiers. Map them explicitly in Entra **Provisioning → Mappings → Provision Microsoft Entra ID Users**.

| SCIM attribute | Sync? | Source in Entra ID | Stored in DomainLens | Purpose |
| --- | --- | --- | --- | --- |
| **`externalId`** | **Required** | **Object ID** (`objectId` / `oid`) | `users.external_id` | Stable directory key. Used to match the same person on later SCIM updates and on OAuth/SAML login (`sub` / `oid`). |
| **`userName`** | **Required** | **User principal name** (`userPrincipalName`) | `users.user_name` (+ email if UPN is an email) | Login name Entra sends on create/filter (`userName eq "…"`). Prefer UPN. |
| **`emails[type eq "work"].value`** | **Required** | **Mail**, fallback **UPN** | `users.email` | Primary email for allowlists, UI, and OAuth matching when `externalId` is absent. |
| **`id`** | **Do not map from Entra** | *(assigned by DomainLens)* | `users.id` | DomainLens’s SCIM resource id. Entra must **keep** the `id` returned from `POST /Users` and call `/Users/{id}` afterward. Never overwrite with Entra Object ID. |
| **`displayName`** / `name.formatted` | Recommended | `displayName` | `users.name` | Display only. |
| **`active`** | Recommended | Account enabled (`Switch([IsSoftDeleted], …)` or equivalent) | `users.enabled` | Soft-disable on leave / unassign. |
| **`roles`** | Optional | App role / custom expression | `users.role` (`user` \| `admin`) | If a role value contains `admin`, DomainLens grants admin; otherwise default role from settings. |

#### Department, manager, CompanyName & default logical attributes

Map these Entra **default logical** / org attributes (Provisioning → Mappings). Prefer the **enterprise** extension paths where listed.

| Entra source (logical / directory) | SCIM target (preferred) | Also accepted | DomainLens column |
| --- | --- | --- | --- |
| **department** | `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department` | top-level `department` | `department` |
| **companyName** | `urn:ietf:params:scim:schemas:extension:domainlens:2.0:User:companyName` | top-level `companyName` / enterprise `organization` | `company_name` (+ mirrors `organization`) |
| **manager** | `…enterprise:2.0:User:manager` → `{ "value": "<Object ID>" }` | top-level `manager` | `manager_external_id` (+ optional `manager_display_name`) |
| **jobTitle** | core `title` | `jobTitle` | `job_title` |
| **employeeId** | enterprise `employeeNumber` | `employeeId` | `employee_number` |
| costCenter / division / organization | enterprise `costCenter` / `division` / `organization` | same top-level names | `cost_center` / `division` / `organization` |
| office / physicalDeliveryOfficeName | domainlens `officeLocation` | `officeLocation` | `office_location` |
| telephoneNumber / mobile | `phoneNumbers[type eq "work"\|"mobile"].value` | — | `phone_number` / `mobile_number` |
| streetAddress, city, state, postalCode, country | `addresses[type eq "work"].*` | — | `street_address`, `city`, `state`, `postal_code`, `country` |
| preferredLanguage | `preferredLanguage` | — | `preferred_language` |
| Other custom / extension attrs | domainlens extension extras | — | `scim_profile` (JSON bag) |

**Manager sync tip:** set `manager.value` to the manager’s Entra **Object ID** (same ID space as user `externalId`). Display name is optional.

##### Recommended Entra mapping (org + logical)

```
Entra department              →  enterprise:department
Entra companyName             →  companyName  (or enterprise:organization)
Entra manager                 →  enterprise:manager  (value = manager objectId)
Entra jobTitle                →  title
Entra employeeId              →  enterprise:employeeNumber
Entra physicalDeliveryOfficeName → officeLocation (custom/domainlens)
Entra telephoneNumber         →  phoneNumbers[type eq "work"].value
Entra mobile                  →  phoneNumbers[type eq "mobile"].value
Entra streetAddress / city / state / postalCode / country
                              →  addresses[type eq "work"].*
Entra preferredLanguage       →  preferredLanguage
```

#### Recommended Entra attribute mapping (identity)

```
Entra objectId          →  externalId          (Match objects using this attribute: Yes — or Match precedence with userName)
Entra userPrincipalName →  userName            (Matching attribute for lookups)
Entra mail (or UPN)     →  emails[type eq "work"].value
Entra displayName       →  displayName
Entra accountEnabled    →  active
```

**Matching rules (important):**

1. **Primary match key for correlation with SSO:** `externalId` = Entra **Object ID**.  
   After OAuth login, Graph/`oid`/`sub` is compared to `users.external_id`.
2. **SCIM filter Entra uses on create:** usually `userName eq "<UPN>"`. Keep `userName` = UPN so creates are idempotent.
3. **DomainLens `id`:** target-system only. Entra’s “Match objects using this attribute” for the **target** side should use the SCIM `id` DomainLens returns — not Object ID.

#### What not to sync as `id` / `externalId`

| Value | Use as `externalId`? | Use as SCIM `id`? |
| --- | --- | --- |
| Entra **Object ID** (GUID) | **Yes** (preferred) | No |
| Entra **App role assignment ID** | No | No |
| On-premises **SAMAccountName** / **SID** | No (unstable across clouds) | No |
| Email / UPN alone | Only if Object ID is unavailable (weaker SSO link) | No |
| DomainLens numeric user id | No | Yes (server-assigned only) |
| Manager Object ID | Use as **`manager.value`**, not as the user’s `externalId` | No |

#### Example SCIM create payload Entra should effectively send

```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
    "urn:ietf:params:scim:schemas:extension:domainlens:2.0:User"
  ],
  "externalId": "11111111-2222-3333-4444-555555555555",
  "userName": "ada@contoso.com",
  "displayName": "Ada Lovelace",
  "title": "Engineer",
  "active": true,
  "emails": [
    { "value": "ada@contoso.com", "type": "work", "primary": true }
  ],
  "phoneNumbers": [
    { "value": "+31 20 000 0000", "type": "work" }
  ],
  "companyName": "Contoso Netherlands",
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
    "department": "Platform Engineering",
    "organization": "Contoso Netherlands",
    "employeeNumber": "E-1042",
    "manager": {
      "value": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "displayName": "Grace Hopper"
    }
  },
  "urn:ietf:params:scim:schemas:extension:domainlens:2.0:User": {
    "companyName": "Contoso Netherlands",
    "officeLocation": "Amsterdam"
  }
}
```

DomainLens responds with a new `id` (e.g. `"42"`). Entra must store that for subsequent GET/PATCH/DELETE.

#### How login resolves a provisioned user

Order used by `resolve_federated_user`:

1. `external_id` == OAuth/SAML `sub` / `oid` / NameID (best — Object ID sync)  
2. Else `email` == profile email / UPN  

If neither matches, the session is allowlist-only (no DB role) unless you enable further JIT later.

### What SCIM writes

Creates/updates rows in `users` with:

- `provider=scim`
- `external_id` from Entra `externalId` (**Object ID**)
- `user_name` from `userName` (**UPN**)
- email / display name / `active` → `enabled`
- **Org / logical:** `department`, `company_name`, `job_title`, `manager_external_id`, `manager_display_name`, `employee_number`, address/phone fields, `scim_profile` extras
- **No password** (SSO or later local backup password)

Soft-delete (PATCH `active=false` or DELETE) disables the account.

## Interactive SSO

### Preferred — OAuth / Azure App Registration

See [AZURE_APP_REGISTRATION.md](AZURE_APP_REGISTRATION.md).

Provisioned users who later sign in with OAuth inherit **role** and **enabled** from the DB row (matched by email or `external_id` / `sub`).

### Legacy — SAML 2.0

```bash
SAML_ENABLED=1
SAML_IDP_SSO_URL=https://login.microsoftonline.com/<tenant>/saml2
# Optional:
# SAML_ENTITY_ID=https://host/auth/saml/metadata
# SAML_ACS_URL=https://host/auth/saml/acs
# SAML_IDP_ENTITY_ID=https://sts.windows.net/<tenant>/
```

- Metadata: `GET /auth/saml/metadata`
- Login: `GET /auth/saml/login`
- ACS: `POST /auth/saml/acs`

Login UI labels SAML as **legacy** and keeps OAuth as the primary button.

## Local backup (Entra outage)

Always keep at least one local admin when using cloud SSO:

```bash
AUTH_LOCAL_ENABLED=1
AUTH_REQUIRE_LOGIN=1
LOCAL_ADMIN_EMAIL=admin@example.com
LOCAL_ADMIN_PASSWORD='ChangeMe-Now-12!'
```

- Login page shows **local backup** under preferred OAuth (and optional SAML).
- SCIM users without a password cannot use local login until an admin sets one (Users admin → reset password).
- If OAuth token exchange fails (`token_exchange_failed`), use the local backup account.

## Settings UI

Admin → Settings:

- **OAuth / OIDC (preferred SSO)**
- **SAML (legacy SSO)**
- **SCIM provisioning** (`auth_mode`: oauth / bearer / both)
- **Local authentication** (backup)

## Status

`GET /api/auth/me` includes `preferred_sso`, `sso_preference`, `scim`, `saml`, and `local_backup`.
