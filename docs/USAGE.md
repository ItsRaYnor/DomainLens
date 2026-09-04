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

## DNS propagation check

**Tools &rarr; DNS record** asks one resolver a question; the propagation panel below it
asks several the same question and compares the answers.

Tick the resolvers to compare and press **Check propagation**. The verdict is
one of three, and they are kept apart on purpose:

| Verdict | Meaning |
|---|---|
| propagated | Every resolver that answered returned the same records |
| inconsistent | They answered and the records differ &mdash; still rolling out |
| unknown | Fewer than two answered, so nothing was compared |

A resolver that times out is listed as **unreachable**, never as
disagreeing. That is our reach failing, not evidence about the zone, and
counting it as "not propagated yet" would send someone chasing a rollout that
already finished.

Record order is normalised before comparing: round-robin resolvers rotate an
RRset deliberately, and comparing raw order would report a difference on every
second lookup of a settled record.

Each row expands into **Query detail** &mdash; the answer, authority and
additional sections with TTLs, the response flags, and which address replied.
That is what tells you *why* two resolvers disagree rather than just *that*
they do.

### Custom resolvers

To compare your own recursors, add them in **Settings &rarr; Scan &rarr;
Custom resolvers**, one per line:

```
Office = 10.0.0.1, 10.0.0.2
DMZ = 192.0.2.53
```

They then appear as checkboxes alongside the built-in ones.

Addresses are configured there rather than typed on the lookup page for a
reason: DomainLens commonly runs without authentication on a LAN, and an
endpoint that accepted a resolver address would be a way to aim UDP/53 at any
host the server can reach. Only literal IP addresses are accepted, a label
cannot shadow a built-in resolver name, and a malformed line is skipped rather
than breaking the page.

## Responsible disclosure: your own security.txt and PGP key

DomainLens checks other people's `security.txt`. It can publish one of its own
too, with a contact key it generates for you.

Configure it under **Settings &rarr; Responsible disclosure**. `Contact` is the
only required field; with it set and the section enabled, the file appears at
`/.well-known/security.txt`. Both that file and the key below are reachable
without signing in, as RFC 9116 requires &mdash; a researcher who has to log in
to find out how to report a bug does not report it.

`Expires` is mandatory in RFC 9116 and is computed at request time from the
configured number of days, so the file cannot quietly go stale the way a
hand-written date does. Anything over a year is clamped to a year.

Checking any domain's published contact and key &mdash; including your own,
once you have published one &mdash; is **Tools &rarr; Responsible disclosure**.
The lookups live there too: they are tools, and the scan page no longer
carries its own copy of the DNS lookup.

**Tools &rarr; Responsible disclosure** carries four things, all of which work
on a domain that is not this one:

| Tool | What it does |
|---|---|
| Check a domain | Fetches its `security.txt` and follows `Encryption:` to the key |
| Validate a security.txt | Checks a **pasted** file against RFC 9116, before you publish it |
| Validate a PGP key | Reads a pasted armoured key: algorithm, fingerprint, identities, expiry |
| Generate a keypair | Makes a keypair and keeps **neither** half |

The validators fetch nothing and store nothing, which is what makes them
usable on a draft. A pasted key is read in a throwaway keyring with
`--import-options show-only`, so it is never imported or trusted anywhere. A
private key pasted into the validator is reported rather than refused:
someone checking "does my key work" with the wrong half needs to be told
which half they have.

The generator under Tools is for someone else's domain and keeps nothing. The
one in Settings, below, is for **this** installation and keeps the public half
so it can be published.

### Generating the key

**Settings &rarr; Responsible disclosure key &rarr; Generate keypair** creates an
OpenPGP keypair (ed25519 by default) and:

- keeps the **public** half, serving it at `/.well-known/pgp-key.asc` and
  referencing it from `security.txt` with an `Encryption:` field;
- shows you the **private** half exactly once, to download or copy.

**The private key is never stored.** It is generated in a throwaway keyring
that is deleted before the request returns, handed back in that one response,
and written to nothing &mdash; not the database, not the logs, not `/data`. It
cannot be shown again; generate a new key if you lose it.

That is a deliberate limit rather than an oversight. DomainLens commonly runs
without authentication on a LAN, and a copy of its database plus
`DOMAINLENS_SECRET_KEY` would otherwise hand someone the key that decrypts
every vulnerability report its owner ever received. Keep the private key in
your password manager or your own GnuPG keyring, and decrypt there.

Settings refuse a PGP **private** key block in any field, whichever route it
arrives by, and the key endpoint fails loudly rather than serving one.

### Requirements

Key generation shells out to `gpg`, which ships in the Docker image. On a
native install without GnuPG the button is disabled and says so; everything
else on the page keeps working, and you can still paste a public key you
generated elsewhere.

## Comparing two periods

**Reports &rarr; Compare** answers "what changed" for one domain between two
moments, field by field: SPF dropping from `-all` to `~all`, DMARC from
reject to none, a TLS grade slipping, a security header disappearing.

Monitoring already tells you *that* something changed. Unless the change is
one of the few it names outright, the event reads "Observed changes for
example.com" &mdash; and an SPF weakening lands exactly there, because the
record still exists and still parses. This names it instead.

Each period is represented by its **most recent** scan: "how did it look in
May" means how it was left, so a change made mid-period shows in the period
it happened. Both scans are named under the result, with their dates and ids,
so the comparison can be checked rather than taken on trust.

Two filters narrow a long result: **only what got worse**, and a single area
(SPF, DMARC, TLS, headers, and so on). They re-render what is already loaded
rather than re-running the comparison.

### From a trend line to the change behind it

The **issues** tile on Trends drills into the move rather than the standing.
A count on its own cannot tell a domain that sat at 20 issues all month from
one that went from 2 to 20, and the second is why anyone opens a rising line:

| Domain | Issues at start | Issues now | Change |
|---|---|---|---|
| spiked.example | 2 | 20 | +18 |
| steady.example | 20 | 20 | 0 |
| fixed.example | 15 | 3 | -12 |
| once.example | &mdash; | 8 | not measured |

A domain scanned once in the window is **not measured**, never `0`: one scan
has nothing to compare against, and a zero would read as "we looked and it
held steady".

Each row links to **what changed**, which opens the comparison above on
exactly those two scans and runs it &mdash; so a rising line leads to "SPF
went from -all to ~all" in two clicks.

### What counts as a change

Only fields an operator can act on. A raw diff of two scans reports something
every single time &mdash; TTLs count down, certificates lose a day of
validity, timings never repeat &mdash; and a report full of that is one
nobody opens. A certificate's expiry *date* changing is a renewal and is
reported; its days-remaining ticking down is not.

A direction is only claimed where one value is genuinely better: DMARC
policies, TLS grades and SPF qualifiers are ordered, so those moves are
labelled better or worse. Anything else is reported as changed, without a
verdict invented for it.

A check that ran in only one of the two scans is listed under **could not be
compared**, never folded into "nothing changed" &mdash; and a period with no
scan at all is refused outright, because reporting it as steady would be a
claim nobody measured.

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
