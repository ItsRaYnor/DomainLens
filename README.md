# DomainLens

Domain Intelligence Toolkit — a local web tool for fast domain analysis, similar to MX Toolbox and internet.nl.

## Features

- **WHOIS Lookup** — Registrar, creation date, expiry date, nameservers, status
- **DNS Records** — A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA, PTR
- **DNSSEC Validation** — Checks DNSKEY and DS records
- **SPF Check** — Sender Policy Framework analysis with policy assessment
- **DMARC Check** — Domain-based Message Authentication, policy evaluation
- **DKIM Check** — Checks common DKIM selectors
- **MTA-STS** — Mail Transfer Agent Strict Transport Security detection
- **TLS-RPT** — TLS Reporting configuration check
- **SSL/TLS Certificate** — Certificate details, expiry date, cipher, SAN
- **NCSC TLS Guidelines 2025-05** — Assess protocols, cipher suites, compression, and cert key sizes against the latest Dutch NCSC TLS guideline
- **HTTP Security Headers** — Checks HSTS, CSP, X-Frame-Options, Referrer-Policy, etc.
- **HTTPS Redirect** — Checks whether HTTP correctly redirects to HTTPS
- **IPv6 Support** — AAAA records for web, mail, and nameservers
- **Blacklist Check (DNSBL)** — Checks 8 commonly used DNS blacklists
- **Port Scanner** — Scans 17 commonly used ports (FTP, SSH, SMTP, HTTP, etc.)
- **HTTP Analysis** — Detects hosting/CDN/WAF (Azure, Cloudflare, AWS, Fastly, Akamai) and diagnoses 4xx errors
- **Security Audit** — Finds security blind spots (passive/light-touch, no exploitation):
  - *Subdomain takeover* — dangling CNAMEs via Certificate Transparency (crt.sh)
  - *Web-app exposures* — exposed `.git`/`.env`/backups, CORS misconfiguration, TRACE/HTTP methods, cookie flags, admin/debug endpoints, security.txt
  - *DNS & mail gaps* — AXFR zone transfer, missing CAA, DANE/TLSA, SPF lookup limit (>10), weak DMARC subdomain policy, wildcard DNS
  - *Info disclosure* — version leakage and tech-stack fingerprinting
- **JS Dependency &amp; Secrets scan** — Passive, always safe: detects vulnerable JS libraries (CVE database), accidentally leaked API keys/secrets in client-side code, and missing Subresource Integrity (SRI) on third-party scripts
- **Active Vulnerability Scan** — Optional, off by default: sends live reflected-XSS, open-redirect, and error-based SQL injection test requests to your own site to confirm real vulnerabilities — only for domains you control yourself
- **Security Score Overview** — Visual overview of all checks with pass/fail status
- **Scan history** — Local SQLite database (no extra dependencies); view, reload, or delete previous scans
- **DNS Monitoring** — Manage recurring monitors for websites, subdomains, CNAMEs, MX/NS/TXT/SRV/CAA/PTR records
- **DNS Import** — Import monitor targets via zonefile/export or directly from the OVHcloud DNS API
- **Scheduled scans** — Save a scan frequency per monitor and run all due scans in batch
- **Continuous scheduler** — A built-in background worker automatically scans all due monitors
- **Monitor events** — Track baselines, changes, regressions, and scan failures per monitor
- **Open-source OSINT** — Certificate Transparency (crt.sh), Wayback history, IP/ASN context, optional ThreatFox/URLhaus/OTX
- **HubSpot / Cloudflare scan** — Detect HubSpot behind Cloudflare and remediate consent, headers, forms, and WAF issues
- **Advice** — Prioritized findings with *how to fix* and *how to re-verify* (via DomainLens / internet.nl); printable reports include the same checklist
- **OAuth2 / OIDC login** — Optional sign-in via Google, GitHub, Microsoft, or generic OIDC provider
- **Trends dashboard** — KPIs and time series for issues, TLS/header scores, scan volume, and event severity
- **Reporting metrics** — Optimized `scan_metrics` table for fast dashboards without JSON blobs
- **ServiceNow** — Automatically create incidents on high/critical monitor events
- **Recommendations** — Concrete fixes per finding with severity level (critical → info) and references
- **Printable report** — HTML report per scan (`/report/<id>`), printable or savable as PDF via the browser

## Documentation

- **[Usage](docs/USAGE.md)** — scans, monitors, scheduling, weak-auth, Advice
- **[Configuration](docs/CONFIGURATION.md)** — `config/domainlens.json`, scheduler, reporting, credentials
- **[Docker & updates](docs/DOCKER_AND_UPDATES.md)** — version, compose, `./scripts/docker-update.sh`, in-app update check

## Version

The app version is in [`VERSION`](VERSION) (currently **0.0.1**). Runtime: `GET /api/version` / `/health`.

## Requirements

- Python 3.10+
- pip

## Installation

```bash
# Clone the repository
git clone https://github.com/ItsRaYnor/DomainLens.git
cd DomainLens

# Create a virtual environment (recommended)
python -m venv venv

# Activate the virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Optional: copy and adjust configuration
cp config/domainlens.example.json config/domainlens.json
```

## Usage

```bash
python app.py
```

Runs on a real production WSGI server ([Waitress](https://docs.pylonsproject.org/projects/waitress/)), not Flask's built-in development server — both natively (Windows/Linux/macOS) and in Docker.

Then open your browser and go to: **http://127.0.0.1:5000**

Enter a domain name (e.g. `example.com`) and click **Scan**. You can choose which checks to run, or run everything at once.

### Docker / continuous monitoring

```bash
docker compose up --build -d
```

The app then runs on **http://127.0.0.1:5050** and stores the SQLite database in a Docker volume.

**Updating without data loss:**

```bash
./scripts/docker-update.sh
```

See [docs/DOCKER_AND_UPDATES.md](docs/DOCKER_AND_UPDATES.md). In the UI: footer version chip + **Settings → Updates**.

**Linux distro in the container:** Debian Bookworm (`python:3.12-slim-bookworm`).
This is the recommended choice for Synology + Portainer. Do **not use Alpine** for this app (whois/OpenSSL on musl is more fragile).

Important environment variables:

- `DOMAINLENS_DB` — path to the SQLite database
- `DOMAINLENS_MONITOR_AUTORUN` — `1`/`0`, background scheduler on/off
- `DOMAINLENS_MONITOR_POLL_SECONDS` — interval at which due monitors are picked up
- `DOMAINLENS_HOST` / `DOMAINLENS_PORT` — bind address and port
- `DOMAINLENS_WSGI_THREADS` — number of worker threads for the production server (default 8)
- `DOMAINLENS_ACTIVE_SCAN_ENABLED` — `1`/`0`, active XSS/redirect/SQLi probes on/off (default off)
- `DOMAINLENS_JS_SCAN_ENABLED` — `1`/`0`, passive JS dependency/secrets scan on/off (default on)
- `SERVICENOW_ENABLED` / `SERVICENOW_INSTANCE` / `SERVICENOW_USER` / `SERVICENOW_PASSWORD` — ServiceNow incident integration
- `ABUSECH_AUTH_KEY` — free abuse.ch Auth-Key for ThreatFox / URLhaus
- `OTX_API_KEY` — optional AlienVault OTX API key
- `SPAMHAUS_DQS_KEY` — free Spamhaus DQS key; without it the Spamhaus zones are skipped

  These three optional keys can also be set from the UI under
  **Settings → Optional API keys**, so you don't have to recreate the container to
  add one. An environment variable always takes precedence and locks the field.
  Values are stored encrypted when `DOMAINLENS_SECRET_KEY` is set; without it the
  encryption key falls back to a secret stored in the same database, which is
  obfuscation rather than real protection — the settings page states which applies.
  The ServiceNow, Rapid7, OAuth/Entra and SCIM credentials are managed the same
  way, under **Settings → Integration credentials**, so no integration secret has
  to sit in the compose file. `DOMAINLENS_SECRET_KEY` itself always stays an
  environment variable — it is the key that protects the rest.
- `OAUTH_ENABLED` / `OAUTH_PROVIDER` / `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` — OAuth2 login
- `DOMAINLENS_SECRET_KEY` — Flask session secret (set this in production)
- `OAUTH_REQUIRE_LOGIN` — require authentication for UI/API when OAuth is enabled
- `OAUTH_ALLOWED_EMAILS` / `OAUTH_ALLOWED_DOMAINS` — optional allowlists
- `AUTH_LOCAL_ENABLED` / `AUTH_REQUIRE_LOGIN` — local email/password users
- `LOCAL_ADMIN_EMAIL` / `LOCAL_ADMIN_PASSWORD` — bootstrap first admin when the users table is empty
- `AUTH_PASSWORD_MIN_LENGTH` / `AUTH_PASSWORD_REQUIRE_*` — password policy
- `AUTH_MFA_ENABLED` / `AUTH_MFA_REQUIRED` — TOTP MFA options (MFA verification is rate-limited via the account-lockout mechanism)
- `AUTH_MAX_FAILED_ATTEMPTS` / `AUTH_LOCKOUT_MINUTES` — lockout after failed logins
- `SAML_IDP_CERT` — **required for SAML**: the IdP's X.509 certificate. SAML assertions must be signed and are verified against it; unsigned assertions are rejected
- `SCIM_TOKEN_SIGNING_KEY` — signing key for SCIM OAuth tokens (falls back to `DOMAINLENS_SECRET_KEY`, then a persisted random secret — never a hardcoded default)

### Security notes

- **Bind address** defaults to `127.0.0.1` (localhost). The app ships with authentication **off**, so only expose it on `0.0.0.0` (via `DOMAINLENS_HOST`) after enabling authentication. Docker sets `DOMAINLENS_HOST=0.0.0.0` and should be run behind auth/a reverse proxy.
- **Session secret**: if `DOMAINLENS_SECRET_KEY` is unset, a cryptographically random secret is generated and persisted (never derived from public config). Set it explicitly for multi-instance deployments.
- **SAML** requires a configured IdP certificate and verifies assertion signatures (via `signxml`); XML is parsed with `defusedxml`. Unsigned assertions are refused unless an operator explicitly opts into the insecure `allow_unsigned` mode with no certificate configured.
- **Weak-auth** findings never persist the discovered password in plaintext — it is masked in the scan history, exports, and UI.
- `/health` exposes only `status` + `version` to unauthenticated callers; detailed config is admin-only when auth is enabled.

### OAuth2 / OIDC login

Enable sign-in (example: Google):

```bash
OAUTH_ENABLED=1
OAUTH_REQUIRE_LOGIN=1
OAUTH_PROVIDER=google
OAUTH_CLIENT_ID=...
OAUTH_CLIENT_SECRET=...
DOMAINLENS_SECRET_KEY=long-random-string
OAUTH_REDIRECT_URI=https://your-host/auth/callback
# Optional allowlists:
# OAUTH_ALLOWED_DOMAINS=yourcompany.com
```

Other providers:
- `OAUTH_PROVIDER=github`
- `OAUTH_PROVIDER=microsoft` — multi-tenant Microsoft login (`/common`)
- `OAUTH_PROVIDER=azure` — **Azure App Registration / Entra ID** (recommended for Microsoft 365 tenants); see [docs/AZURE_APP_REGISTRATION.md](docs/AZURE_APP_REGISTRATION.md)
- `OAUTH_PROVIDER=oidc` plus `OAUTH_AUTHORIZE_URL`, `OAUTH_TOKEN_URL`, `OAUTH_USERINFO_URL`

#### Azure App Registration (Entra ID)

```bash
OAUTH_ENABLED=1
OAUTH_REQUIRE_LOGIN=1
OAUTH_PROVIDER=azure
AZURE_TENANT_ID=<Directory (tenant) ID>
AZURE_CLIENT_ID=<Application (client) ID>
AZURE_CLIENT_SECRET=<client secret>
DOMAINLENS_SECRET_KEY=long-random-string
# AZURE_REDIRECT_URI=https://your-host/auth/callback
# AZURE_CLOUD=public
```

Register a Web app in Entra with redirect URI `/auth/callback`, Graph delegated permissions (`openid`, `profile`, `email`, `User.Read`), and admin consent as required. Full guide: [docs/AZURE_APP_REGISTRATION.md](docs/AZURE_APP_REGISTRATION.md).

#### SCIM provisioning + SSO preference

Prefer **SCIM** for user provisioning (OAuth 2 client credentials to `/oauth/token`) and **OAuth/OIDC** for interactive SSO. SAML remains available as legacy SSO; keep **local accounts** as an Entra outage backup.

```bash
SCIM_ENABLED=1
SCIM_AUTH_MODE=oauth
# SCIM_CLIENT_ID / SCIM_CLIENT_SECRET (or reuse AZURE_CLIENT_*)
AUTH_LOCAL_ENABLED=1
LOCAL_ADMIN_EMAIL=admin@example.com
LOCAL_ADMIN_PASSWORD='ChangeMe-Now-12!'
# Optional legacy SAML:
# SAML_ENABLED=1
# SAML_IDP_SSO_URL=https://login.microsoftonline.com/<tenant>/saml2
```

Details: [docs/SCIM_AND_SSO.md](docs/SCIM_AND_SSO.md).

### Local users, password policy, and MFA

```bash
AUTH_LOCAL_ENABLED=1
AUTH_REQUIRE_LOGIN=1
DOMAINLENS_SECRET_KEY=long-random-string
LOCAL_ADMIN_EMAIL=admin@example.com
LOCAL_ADMIN_PASSWORD='ChangeMe-Now-12!'
# Optional policy / MFA:
# AUTH_PASSWORD_MIN_LENGTH=12
# AUTH_PASSWORD_REQUIRE_UPPER=1
# AUTH_PASSWORD_REQUIRE_LOWER=1
# AUTH_PASSWORD_REQUIRE_DIGIT=1
# AUTH_PASSWORD_REQUIRE_SPECIAL=1
# AUTH_MFA_ENABLED=1
# AUTH_MFA_REQUIRED=0
# AUTH_MAX_FAILED_ATTEMPTS=5
# AUTH_LOCKOUT_MINUTES=15
```

Local accounts use PBKDF2-SHA256 password hashes. MFA uses TOTP (authenticator apps) plus one-time backup codes. Admins manage users at `/admin/users`; each local user can enroll MFA at `/account`.

OAuth and local login can be enabled together.

Routes:
- `GET /login`
- `POST /auth/local/login`
- `GET|POST /auth/mfa`
- `GET /auth/login` / `GET /auth/callback` (OAuth)
- `GET /account` — password change + MFA enrollment
- `GET /admin/users` — local user admin (role `admin`)
- `GET /logout`
- `GET /api/auth/me`

When login is required (`OAUTH_REQUIRE_LOGIN` and/or `AUTH_REQUIRE_LOGIN`), unauthenticated API calls return `401` and UI routes redirect to `/login`. `/health` stays public.

### Data storage (SQLite)

Everything is stored in a single SQLite file (`DOMAINLENS_DB`, default `domainlens.db` or `/data/domainlens.db` in Docker):

| Table | Purpose |
|---|---|
| `scans` | Full scan results as JSON + summary (`grade`, `score`, `issues_count`) |
| `users` | Local accounts (password hash, role, MFA secret / backup codes, lockout) |
| `scan_metrics` | Denormalized daily metrics for fast trends (no JSON needed) |
| `monitors` | Monitor configuration, schedule, last/next scan, state hash |
| `monitor_events` | Changes/regressions/failures + optional ServiceNow `sys_id`/`number` |

Trends are read mainly from `scan_metrics` and `monitor_events`, so reporting stays scalable while `scans.data` remains available for detailed reports.

### Synology + Portainer

1. Create a shared folder on the NAS: `/volume1/docker/domainlens`
2. Open Portainer → **Stacks** → **Add stack**
3. Paste the contents of `docker-compose.portainer.yml` (or choose Repository deploy from this Git repo)
4. Deploy the stack
5. Open `http://<nas-ip>:5050`

Notes for Synology:

- Host port is **5050** (Synology DSM already uses 5000/5001)
- Bind mount `/volume1/docker/domainlens:/data` keeps the SQLite DB outside the container (easy to back up)
- Healthcheck endpoint: `GET /health`
- Need a different host port? Only change the left-hand side, e.g. `"8080:5000"`
- The container starts as root, chowns `/data`, and then drops to user `domainlens` (UID 1000) — no `PUID`/`PGID` needed
- The image base is Debian Bookworm slim — this works most reliably on Synology DSM / Container Manager / Portainer

#### Alternative: ready-made image via Docker Hub

If building on the NAS is too slow (or you'd rather not clone the repo every time), use `docker-compose.dockerhub.yml`. This pulls a prebuilt image instead of building locally:

1. GitHub Actions (`.github/workflows/docker-publish.yml`) automatically builds and pushes to `itsraynor/domainlens` on Docker Hub on every push to `main` (multi-arch: `amd64` + `arm64`)
2. In Portainer: **Stacks → Add stack → Web editor**, paste the contents of `docker-compose.dockerhub.yml`, deploy
3. Updating: **Stacks → domainlens → Pull and redeploy**

Requires two GitHub repo secrets, set once (**Settings → Secrets and variables → Actions**):

- `DOCKERHUB_USERNAME` — your Docker Hub username
- `DOCKERHUB_TOKEN` — a Docker Hub **Access Token** (Docker Hub → Account Settings → Security → New Access Token; do not use a password)

## Project structure

```
DomainLens/
├── app.py                       # Flask backend + monitor scheduler + all checks
├── db.py                        # SQLite scans / monitors / events / metrics
├── security_checks.py           # Security-audit checks (takeover, exposures, DNS/mail gaps, info disclosure)
├── js_scan.py                   # Passive JS dependency CVE + secret scan
├── active_scan.py               # Opt-in active XSS/open-redirect/SQLi probes
├── weak_auth.py                 # Opt-in weak/default credential probe
├── servicenow.py                # ServiceNow Table API incident helper
├── osint.py                     # Open-source OSINT collectors
├── hubspot_cf.py                # HubSpot behind Cloudflare scanner
├── ncsc_tls.py                  # NCSC-NL TLS Guidelines 2025-05 assessment
├── auth.py                      # OAuth2 / OIDC / local users / MFA
├── saml_sp.py                   # SAML 2.0 SP (signature-validated)
├── scim.py / scim_oauth.py      # SCIM 2.0 provisioning + OAuth token issuer
├── recommendations.py           # Remediation recommendations
├── requirements.txt
├── Dockerfile                   # Debian Bookworm slim image
├── docker-compose.yml           # local compose stack
├── docker-compose.portainer.yml # Synology / Portainer stack (build on the NAS)
├── docker-compose.dockerhub.yml # Synology / Portainer stack (pull from Docker Hub)
├── docker-entrypoint.sh         # Synology bind-mount ownership fix
├── .github/workflows/
│   └── docker-publish.yml       # Builds + pushes image to Docker Hub on push to main
├── templates/
│   ├── index.html
│   ├── trends.html
│   └── report.html
└── static/
    ├── css/
    └── js/
```

## Screenshots

After starting the application you'll see a dark dashboard with:
- A search bar at the top to enter a domain
- Checkboxes to select specific checks
- Tabs for WHOIS, DNS, Email Security, SSL/TLS, Web Security, and Network
- A score overview with pass/fail badges per check

## API

The tool offers a REST API:

### POST `/api/scan`

```json
{
  "domain": "example.com",
  "checks": ["all"]
}
```

Available checks: `whois`, `dns`, `dnssec`, `spf`, `dmarc`, `dkim`, `mta_sts`, `tlsrpt`, `ssl`, `tls_deep`, `ncsc_tls`, `http_headers`, `https_redirect`, `http_deep`, `ipv6`, `blacklist`, `ports`, `osint`, `hubspot_cf`, `security`, `weak_auth`, `js_scan`, `active_scan`, `all`

> **Active Vulnerability Scan (`active_scan`)** sends live XSS/open-redirect/SQL-injection test requests to the target. Off by default (`active_scan.enabled=false`) and not included in an `all` scan unless explicitly enabled. Only use this on domains you control yourself or have explicit permission for — never on third-party domains.
>
> **JS Dependency &amp; Secrets (`js_scan`)** is fully passive (only ordinary GET requests to public assets) and therefore safe on any domain.

> **Security Audit (`security`)** only performs passive/light-touch checks: DNS queries, Certificate Transparency enumeration, and targeted HTTP requests to known sensitive paths. **No** exploitation or DoS is performed. Only use it on domains you're authorized to test.

See [docs/USAGE.md](docs/USAGE.md) and [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for scheduling, reporting, and weak-auth configuration.

### NCSC TLS Guidelines 2025-05

Full scans (and any scan that includes `tls_deep` / `ncsc_tls`) produce an `ncsc_tls` assessment against the latest Dutch NCSC TLS guideline:

- Protocol levels: TLS 1.3 = Good, TLS 1.2 = Sufficient, TLS 1.0/1.1/SSL = Insufficient
- Cipher suite components (key exchange, auth, bulk encryption, hash) rated Good / Sufficient / To be phased out / Insufficient
- Cipher suite **order** (internet.nl "Volgorde van cipher suites"): pairwise TLS 1.2 probes verify the server ranks Good/Sufficient AEAD suites above phase-out/insufficient ones (N/A when only Good/Sufficient are offered)
- TLS compression, certificate key size (RSA/ECDSA), and actionable findings with remediation
- Results appear in the SSL/TLS tab, score overview, recommendations, and printable report

Reference: https://www.ncsc.nl/en/transport-layer-security-tls/tls-security-guidelines

### POST `/api/osint`

```json
{
  "domain": "example.com"
}
```

Open-source OSINT enrichment:
- Certificate Transparency via crt.sh
- Wayback Machine snapshots
- IP/ASN/geo via ip-api.com
- Optional ThreatFox + URLhaus (`ABUSECH_AUTH_KEY`)
- Optional AlienVault OTX (`OTX_API_KEY`)

### POST `/api/reverse-dns`

```json
{
  "ip": "8.8.8.8"
}
```

### Scan history

- `GET /api/history?domain=<optional>&limit=100` — overview of stored scans + statistics
- `GET /api/history/<id>` — retrieve full scan results
- `DELETE /api/history/<id>` — delete a single scan
- `DELETE /api/history` — clear all history
- `GET /api/recommendations/<id>` — recommendations (JSON) for a stored scan

Scans are saved by default. Send `"save_history": false` in the body of `/api/scan` to skip this for a single scan.

### Monitoring

- `GET /api/monitors` — list of monitors + statistics
- `GET /api/monitor-events` — recent monitor events / changes
- `POST /api/monitors` — manually add a monitor
- `PATCH /api/monitors/<id>` — enable/disable a monitor or adjust interval/checks
- `DELETE /api/monitors/<id>` — delete a monitor
- `POST /api/monitors/<id>/scan` — scan a single monitor immediately
- `POST /api/monitors/run-due` — run all due monitors immediately
- `POST /api/monitors/import` — bulk import monitors from DNS records

Monitor events are automatically created for:

- first baseline scan
- detected changes between scans
- regressions (e.g. TLS grade drop)
- new blacklist listings
- scheduler/manual scan failures

Examples:

```json
{
  "domain": "app.example.com",
  "target": "app.example.com",
  "record_type": "CNAME",
  "schedule_minutes": 60,
  "checks": ["dns", "ssl", "http_headers", "https_redirect"]
}
```

```json
{
  "mode": "zone_file",
  "domain": "example.com",
  "schedule_minutes": 1440,
  "zone_text": "$ORIGIN example.com.\n@ 3600 IN A 203.0.113.10\nwww 3600 IN CNAME app.example.net.\nmail 3600 IN MX 10 mx1.mailhost.tld."
}
```

```json
{
  "mode": "ovhcloud",
  "zone_name": "example.com",
  "schedule_minutes": 1440,
  "app_key": "xxx",
  "app_secret": "xxx",
  "consumer_key": "xxx"
}
```

### Reporting & trends

- `GET /trends` — trends dashboard (KPIs + charts)
- `GET /api/reporting/overview?days=30` — KPI aggregates
- `GET /api/reporting/trends?days=30&domain=optional` — daily series
- `GET /report/<id>` — a full HTML report with findings, severity scores, and remediation advice

### ServiceNow

Set in Docker/Portainer:

```bash
SERVICENOW_ENABLED=1
SERVICENOW_INSTANCE=https://example.service-now.com
SERVICENOW_USER=integration.user
SERVICENOW_PASSWORD=***
SERVICENOW_MIN_SEVERITY=high
```

DomainLens then creates an incident via the Table API (`/api/now/table/incident`) for actionable monitor events (changes, regressions, blacklist, scan failures). Status: `GET /api/integrations/servicenow`.

## License

MIT License — see [LICENSE](LICENSE) for details.
