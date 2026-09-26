# Running DomainLens for an organisation

What changes when more than one person, team or system uses the instance:
who may do what, what is recorded, how active tests are kept to your own
domains, how scripts and alerting connect, and how the service is operated.

- [Roles](#roles)
- [Audit log](#audit-log)
- [Verified domains (active tests)](#verified-domains)
- [API tokens, OpenAPI and the CI gate](#api-tokens)
- [Notifications](#notifications)
- [Accepted risks](#accepted-risks)
- [Discovered hostnames](#discovered-hostnames)
- [Metrics](#metrics)
- [Retention](#retention)
- [Backup and restore](#backup-and-restore)

## Roles

| Role | Stored as | May |
|------|-----------|-----|
| Viewer | `viewer` | Read scans, reports, trends, monitors, accepted risks. Change only their own password, MFA, language and theme. |
| Analyst | `user` | Everything a viewer may, plus scan, manage monitors, import findings, start domain verification. |
| Admin | `admin` | Everything, plus settings, users, credentials, audit log, backups, attesting domains, accepting risks, clearing all history. |

Existing accounts keep their role: `user` is the Analyst. Change a role under
**Admin → Users**. SCIM maps a directory role containing `admin` to Admin, and
`viewer`, `read-only` or `readonly` to Viewer.

Viewers are read-only for every route, including routes added later: the rule
is enforced once, before any route runs, rather than per route.

A role change or a disabled account takes effect on the user's **next
request**. Sessions re-read the account on every request.

With authentication switched off there are no roles; the instance is treated
as a single trusted operator, as before.

## Audit log

**Admin → Audit log** (`/admin/audit`) lists, newest first:

- sign-ins (local, OAuth, SAML, MFA), including failed and refused ones with the attempted email;
- sign-outs, password and MFA changes;
- user creation, role changes, enabling, disabling, password resets, deletion;
- SCIM provisioning (actor `scim-directory`);
- settings changes (the **keys** changed, never the values) and credential set/clear (the credential **name**, never the value);
- every scan, with the active checks it asked for;
- scan and history deletion, monitor changes, imports;
- domain verification, attestation and revocation, token creation and revocation, risk acceptance, backups, retention purges;
- requests refused for the caller's role (`access.denied`).

Each entry carries the actor, their role, how they authenticated (`session`,
`token`, `scim`, `system`), their address and the outcome.

Filter by action prefix (`auth.`), actor, outcome and dates, and export CSV.
Cells that a spreadsheet would run as a formula are prefixed with `'`.

**Tamper evidence.** Every entry stores the hash of the entry before it. The
page checks the whole chain on each view and says where it breaks if a row was
edited or removed (`GET /api/admin/audit/verify` does the same). This makes a
quiet edit visible; it does not stop someone who holds the database file from
rebuilding every hash. For that, ship the log elsewhere (CSV export, or the
webhook channel).

## Verified domains

Weak-auth (login attempts with default passwords) and the active scan
(XSS, open-redirect and SQL-injection probes) run **only against verified
domains**. Enabling them in Settings is still required; verification decides
*where* they run.

Under **Admin → Verified domains** (`/admin/domains`, Analysts and Admins):

1. Enter the domain and press **Start verification**.
2. Publish **one** of:
   - DNS: `TXT` record at `_domainlens-challenge.<domain>` with value `domainlens-verification=<token>`
   - HTTPS: `https://<domain>/.well-known/domainlens-verification.txt` containing the token
3. Press **Check now**.

Verifying a zone covers its subdomains (`example.com` covers `www.example.com`),
never its parent. A lookalike such as `badexample.com` is not covered.

Where neither record is possible (an internal name, a zone run elsewhere), an
admin can **attest** the domain with a reason. Attestations are recorded under
the admin's name in the audit log and do not expire.

DNS and HTTPS proofs expire after **Settings → Domain ownership →
max_age_days** (default 365; `0` = never). A failed re-check does not revoke a
proof that is still within its age, so one DNS timeout does not switch off a
scheduled scan.

A scan of an unverified domain reports the two checks as *not applicable* with
the reason. It is not reported as clean, and not as a finding.

The open relay and open resolver tests keep their own allowlist under
**Own infrastructure tests**.

## API tokens

Create tokens under **Account → API tokens**. Each token:

- is sent as `Authorization: Bearer dlk_…` to `/api/…` endpoints and `/metrics`;
- has a name, a role at or below yours, and an expiry of 1–365 days;
- is shown **once**; only its SHA-256 hash is stored;
- never holds more than your account currently does: demote or disable the account and every token follows;
- cannot render pages, change passwords or MFA, or create further tokens.

Admins see and revoke every token under **Admin → Users**.

A token that is presented but invalid, expired or revoked is refused with
401, even from a browser that also has a signed-in session.

The API is described at **`/api/openapi.json`** (OpenAPI 3.1). Each operation
carries `x-minimum-role`.

### CI gate

```sh
export DOMAINLENS_URL=https://domainlens.example.com
export DOMAINLENS_TOKEN=dlk_...          # Analyst role is enough
python scripts/ci_gate.py www.example.com --fail-on high
```

| Exit | Meaning |
|------|---------|
| 0 | No open finding at or above `--fail-on` |
| 1 | Open findings at or above `--fail-on` (listed) |
| 2 | The scan could not be started or read |

Accepted risks never fail the gate. `--checks tls_deep,http_headers` limits the
scan. Standard library only.

## Notifications

**Settings → Notifications** sends monitor events at or above `min_severity`
(default `high`) to every configured channel. Unchanged scans and first
baselines never alert.

| Channel | Configure |
|---------|-----------|
| Webhook (JSON) | Credential `NOTIFY_WEBHOOK_URL` (https only); optional `NOTIFY_WEBHOOK_SECRET` signs the body: `X-DomainLens-Signature: sha256=<HMAC-SHA256 of the raw body>` |
| Slack | Credential `NOTIFY_SLACK_WEBHOOK_URL` (Incoming Webhooks) |
| Microsoft Teams | Credential `NOTIFY_TEAMS_WEBHOOK_URL`: a Teams Workflow "Post to a channel when a webhook request is received". Sent as an Adaptive Card. |
| Email | `smtp_host`, `smtp_port`, `smtp_security` (`starttls`, `ssl`, `none`), `smtp_from`, `email_to`; credentials `SMTP_USERNAME`, `SMTP_PASSWORD` |

The URLs and SMTP login are **integration credentials** (Settings →
Integration credentials), stored encrypted, because Slack and Teams URLs are
secrets in their own right. The **Notifications** group there has a test
button that sends a message labelled as a test to every configured channel.

Set **General → public_url** so alerts link to the report.

`send_digest` also delivers the periodic summary configured under Reporting.

Each channel fails on its own: a dead Slack URL is logged and counted in
`/metrics`, and Teams and email still go out.

Webhook payload:

```json
{
  "source": "domainlens",
  "event_type": "regression",
  "severity": "high",
  "summary": "…",
  "target": "www.example.com",
  "monitor": {"id": 3, "name": "www.example.com (A)"},
  "scan_id": 812,
  "url": "https://domainlens.example.com/report/812",
  "timestamp": "2026-09-26T03:00:12+00:00"
}
```

## Accepted risks

**Admin → Accepted risks** (`/admin/risks`). An admin picks a domain, sees the
findings of its latest saved scan, and accepts one with a **reason**, a **risk
owner** and an **expiry date** (at most a year).

While accepted, the finding:

- is still listed in the scan view and the printed report, marked accepted with owner, reason and date;
- is left out of severity counts, trend metrics, monitor-event counts, the remediation plan and the CI gate.

When it expires it counts again. Everyone can see the list; only admins accept
or revoke, and both are audited.

An acceptance on the apex also covers apex-level findings (SPF, DMARC, DNSSEC)
when a subdomain is scanned.

## Discovered hostnames

The **Monitoring** page lists hostnames from Certificate Transparency under
each monitored zone (from that zone's latest saved scan) that no monitor
watches yet. Analysts add one with **Monitor**. Nothing is contacted to build
the list; a CT entry shows a certificate was issued, not that the host is up.
Also at `GET /api/monitors/discovered`.

## Metrics

`GET /metrics` returns Prometheus text format. With authentication on, it
answers 401 without credentials; scrape it with an API token (Viewer is
enough):

```yaml
scrape_configs:
  - job_name: domainlens
    metrics_path: /metrics
    authorization:
      credentials: dlk_...
    static_configs:
      - targets: ["domainlens.example.com:443"]
    scheme: https
```

Includes monitors by state, stored scans and domains, running scans, monitor
events in the last 24 hours by severity, verified domains, active tokens,
scheduler run count/duration/errors/last run, scans started, and notification
deliveries by channel and result. No domain names are exposed.

## Retention

**Settings → Retention** deletes, once a day:

| Key | Deletes | Default |
|-----|---------|---------|
| `scan_days` | Scans older than N days, **except** each monitor's current baseline | `0` (keep) |
| `event_days` | Monitor events older than N days | `0` (keep) |
| `audit_days` | Audit entries older than N days | `0` (keep) |

All default to keep, so upgrading deletes nothing. Each purge is audited.
`reporting.retention_days` is unrelated and still only a documented target.

## Backup and restore

The database is a single SQLite file in WAL mode. Copying it while DomainLens
runs can capture a half-written state. Use one of:

- **Settings → Backup → Download backup** (admin; audited), or `GET /api/admin/backup`;
- from a shell or cron, inside the container:

  ```sh
  docker exec domainlens python maintenance.py backup /data/backup-$(date +%F).db
  ```

Both use SQLite's online backup API and produce a consistent file.

Stored credentials inside the backup are encrypted with
`DOMAINLENS_SECRET_KEY`. **Keep that key with the backup**; without the same
value, a restore comes back with every stored credential unreadable.

Restore:

```sh
docker compose stop domainlens
cp backup-2026-09-26.db /path/to/data/domainlens.db
rm -f /path/to/data/domainlens.db-wal /path/to/data/domainlens.db-shm
docker compose start domainlens
```

Remove the `-wal` and `-shm` files of the old database, or SQLite may replay
them on top of the restored file.
