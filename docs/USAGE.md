# Usage guide

## Ad-hoc scan

1. Open the web UI (`http://127.0.0.1:5000` or Docker port `5050`).
2. Enter a domain (e.g. `example.com`).
3. Select checks, or leave **All Checks** enabled.
4. Click **Scan**.
5. Review tabs: **Advies** (fix + retest steps), DNS, E-mail, SSL/TLS, Web, Network, OSINT.

### API scan

```bash
curl -s -X POST http://127.0.0.1:5000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","checks":["dns","tls_deep","ncsc_tls","http_headers"]}'
```

Available checks: `whois`, `dns`, `dnssec`, `spf`, `dmarc`, `dkim`, `mta_sts`, `tlsrpt`, `ssl`, `tls_deep`, `ncsc_tls`, `http_headers`, `https_redirect`, `http_deep`, `ipv6`, `blacklist`, `ports`, `osint`, `hubspot_cf`, `weak_auth`, `all`.

### Printable report

After a saved scan: **Report** button or `GET /report/<scan_id>`.

---

## Advies (remediation)

The **Advies** tab lists every finding with:

- **Probleem** — what is wrong
- **Advies (oplossen)** — how to fix it
- **Hertesten** — how to verify (re-scan in DomainLens, internet.nl, dig, curl, …)

Prioritized items (critical / high / medium) appear at the top.

### Web security & CSP

The **HTTP Headers** check now also analyses:

- **CSP quality** — `'unsafe-inline'` / `'unsafe-eval'`, wildcards, missing `frame-ancestors` / `base-uri` / `form-action`
- **Cookies** — missing `Secure` / `HttpOnly` / `SameSite` on session-like cookies
- **CORS** — `Access-Control-Allow-Origin: *` (especially with credentials)
- **Clickjacking** — no CSP `frame-ancestors` and no `X-Frame-Options`
- **Info disclosure** — versioned `Server` / `X-Powered-By`

When CSP is missing or weak, Advies includes **step-by-step build guidance**: start with Report-Only, baseline `default-src 'self'`, add hosts, prefer nonces/hashes, then enforce.

---

## DNS monitoring & scheduling

### Create a monitor (UI)

1. Open **Monitors** drawer.
2. Enter domain, target, record type, schedule (minutes), and checks.
3. Save — first scan runs when due (immediately if enabled).

### Create via API

```bash
curl -s -X POST http://127.0.0.1:5000/api/monitors \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "example.com",
    "domain": "example.com",
    "target": "example.com",
    "record_type": "A",
    "schedule_minutes": 1440,
    "checks": ["all"]
  }'
```

### Scheduler

- Background thread polls every `scheduler.poll_seconds` (default 60s).
- Due monitors run with configurable **concurrency** (default 2).
- Manual batch: **Run due** in UI or `POST /api/monitors/run-due`.
- Status: `GET /health` or `GET /api/reporting/scheduler`.

### Zone / OVH import

Import many targets from a zone file or OVHcloud DNS API (see README).

### Rapid7 InsightVM / Nexpose

**Do not import a full ~1GB vulnerability dump.** Prefer API sync or a Critical/Severe-only export.

See **[INTEGRATIONS_RAPID7_SERVICENOW.md](INTEGRATIONS_RAPID7_SERVICENOW.md)** for Console/Cloud API setup and ServiceNow CMDB CI ↔ Vulnerable Item linking.

1. Settings → Rapid7 → `source_mode` = `console_api` or `cloud_api` (or upload a lean CSV).
2. Set API min severity to **high** (Critical + Severe).
3. Monitoring drawer → **Sync via InsightVM API**, or upload a filtered file.
4. Optional: enable ServiceNow CMDB bridge to match `cmdb_ci` and create `sn_vul_vulnerable_item`.
5. Set `DOMAINLENS_PUBLIC_URL` so each VI includes a link back to DomainLens Advies / retest (`/remediate/vuln/<id>`). Ownership stays in ServiceNow.
5. Scan a domain — matching hosts appear under **Rapid7** and in **Advies**.

```bash
# Lean API sync
curl -s -X POST http://127.0.0.1:5000/api/vuln-imports/sync \
  -H 'Content-Type: application/json' -d '{"push_cmdb":true}'

curl -s 'http://127.0.0.1:5000/api/vuln-findings?domain=example.com'
```

### Events & ServiceNow

Monitor scans create events: `baseline_created`, `scan_changed`, `scan_unchanged`, `scan_failed`.

Configure ServiceNow env vars to auto-create incidents for high/critical events.

---

## Weak authentication testing

**Legal / ethical use only** — test domains you own or have written permission to assess.

1. Enable in `config/domainlens.json`:

```json
"weak_auth": { "enabled": true }
```

2. Customize paths and credential lists (see [CONFIGURATION.md](CONFIGURATION.md)).
3. Run check `weak_auth` (alone or with other web checks).
4. If weak credentials are found, **Advies** shows critical remediation steps.
5. After fixing passwords, re-run the scan to confirm `weak_credentials_found: false`.

---

## Trends & reporting

- **Trends** page: `/trends` — KPIs and time series from `scan_metrics`.
- `GET /api/reporting/overview?days=30`
- `GET /api/reporting/trends?days=30&domain=example.com`

---

## Authentication (Azure App Registration)

For Microsoft Entra ID / Azure AD:

1. Create an **App Registration** (redirect URI `https://host/auth/callback`).
2. Set `OAUTH_PROVIDER=azure`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.
3. Users sign in via `/login` → **Continue with Microsoft Entra ID** (preferred OAuth).
4. Enable **SCIM** for directory provisioning (`SCIM_ENABLED=1`, OAuth token at `/oauth/token`).
5. Keep **local backup** accounts (`AUTH_LOCAL_ENABLED=1`) for Entra outages.
6. Optional legacy SAML: `SAML_ENABLED=1` + IdP SSO URL.

Details: [AZURE_APP_REGISTRATION.md](AZURE_APP_REGISTRATION.md), [SCIM_AND_SSO.md](SCIM_AND_SSO.md).

---

## Geo-blocked sites (NL/DE/BE)

Some CDN setups (e.g. BunnyCDN) return `403` outside Benelux. DomainLens marks HSTS / headers / redirects as **inconclusive**, not failed. TLS and NCSC checks still work. Re-verify HTTP findings from NL/DE/BE or [internet.nl](https://internet.nl/).

---

## internet.nl alignment

For Dutch HTTPS/TLS compliance:

- Run **NCSC TLS** + **TLS Scan** checks.
- Compare cipher suites and cipher order with internet.nl HTTPS results.
- DomainLens also probes **TLS 1.2 signature hashes** (NCSC §3.3.5 / RFC 9155): if the edge still accepts SHA-1 for key-exchange signatures, you get a `signature-hash-insufficient` finding — the same failure as internet.nl “Hashfuncties voor sleuteluitwisseling”. This is **not** the cipher-suite name ending in `-SHA`; it is OpenSSL `SignatureAlgorithms`.
- Use **Advies → Hertesten** links to re-test after changes.

### Reports & exports

- HTML report: `/report/<scan_id>` (print / Save as PDF)
- API exports: `/api/reports/<id>/export?format=json|markdown|csv`
- Scanner UI: **Export** menu (JSON / Markdown / CSV Advies)

### CDN hardening (Bunny / Cloudflare / OVHcloud)

When DomainLens detects BunnyCDN, Cloudflare, or OVHcloud, Advies includes edge-specific remediations:

| Finding | What to change |
|--------|----------------|
| SHA-1 signature hashes | Disable SHA-1/SHA-224 on the **CDN SSL profile** (and origin). Bunny: modern TLS preset + support ticket if SignatureAlgorithms is not exposed. Cloudflare: Minimum TLS 1.2+, modern cipher suites / support for sigalg profiles. OVH: Intermediate SSL Gateway profile or origin `SSLSignatureAlgorithms` / `ssl_conf_command SignatureAlgorithms`. Fix **both A and AAAA**. |
| Cipher order | Prefer AEAD (GCM/CCM/ChaCha) before CBC phase-out suites; enable server preference. |
| Geo-block + headers | Inject HSTS/CSP on **all** responses including CDN 403 pages (Bunny Edge Rules / Cloudflare Transform Rules / OVH gateway). |

Example (site behind BunnyCDN): TLS 1.2+1.3 work from any region, but HTTP may be geo-blocked (`cdn-requestcountrycode: US` → 403). internet.nl still fails SHA-1 on IPv4/IPv6 until the Bunny edge stops offering `ECDSA+SHA1` / `RSA+SHA1`.

---

## Configuration reference

See [CONFIGURATION.md](CONFIGURATION.md) for the full `domainlens.json` schema, env overrides, and bootstrap monitors.
