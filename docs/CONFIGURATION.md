# Configuration

DomainLens uses a **JSON configuration file** with optional environment-variable overrides.

## Quick start

1. Copy the example file:

```bash
cp config/domainlens.example.json config/domainlens.json
```

2. Edit `config/domainlens.json` for your environment.

3. Point DomainLens at it (optional if using the default path):

```bash
export DOMAINLENS_CONFIG=/path/to/domainlens.json
python app.py
```

Docker Compose:

```yaml
environment:
  DOMAINLENS_CONFIG: /config/domainlens.json
volumes:
  - ./config/domainlens.json:/config/domainlens.json:ro
```

## Precedence

1. **Environment variables** (`DOMAINLENS_*`) — highest priority
2. **`config/domainlens.json`** (or `DOMAINLENS_CONFIG` path)
3. **Built-in defaults** in `config.py`

## Sections

### `server`

| Key | Default | Env override |
|-----|---------|--------------|
| `host` | `0.0.0.0` | `DOMAINLENS_HOST` |
| `port` | `5000` | `DOMAINLENS_PORT` / `PORT` |
| `log_level` | `INFO` | `DOMAINLENS_LOG_LEVEL` |

### `database`

| Key | Default | Env override |
|-----|---------|--------------|
| `path` | `./domainlens.db` | `DOMAINLENS_DB` |

### `scheduler`

Controls the background monitor worker.

| Key | Default | Env override |
|-----|---------|--------------|
| `enabled` | `true` | `DOMAINLENS_MONITOR_AUTORUN` |
| `poll_seconds` | `60` | `DOMAINLENS_MONITOR_POLL_SECONDS` |
| `max_monitors_per_run` | `200` | — |
| `concurrency` | `2` | — |
| `failure_backoff_minutes` | `15` | — |
| `max_consecutive_failures` | `8` | — |
| `defaults.schedule_minutes` | `1440` | — |
| `defaults.checks` | `["all"]` | — |

Disable the scheduler entirely (tests / dev):

```bash
export DOMAINLENS_DISABLE_SCHEDULER=1
```

After repeated scan failures, a monitor is **backed off** for `failure_backoff_minutes` (stored in monitor `metadata.scheduler`).

### `scan`

| Key | Default | Env override |
|-----|---------|--------------|
| `rate_limit.requests` | `10` | `DOMAINLENS_RATE_LIMIT` |
| `rate_limit.window_seconds` | `60` | `DOMAINLENS_RATE_WINDOW` |
| `thread_pool_workers` | `14` | — |

### `reporting`

| Key | Default | Description |
|-----|---------|-------------|
| `retention_days` | `365` | Documented retention target |
| `digest_enabled` | `false` | Periodic scheduler summary |
| `digest_interval_hours` | `24` | Digest interval |

Scheduler status: `GET /api/reporting/scheduler` and `GET /health`.

### `weak_auth` (credential testing)

**Disabled by default.** Only enable for systems you own or are explicitly authorized to test.

| Key | Default | Env override |
|-----|---------|--------------|
| `enabled` | `false` | `DOMAINLENS_WEAK_AUTH_ENABLED` |
| `max_attempts_per_scan` | `25` | — |
| `delay_seconds` | `0.35` | Pause between attempts |
| `timeout_seconds` | `8` | HTTP timeout |
| `paths` | `/`, `/admin`, … | URLs to probe |
| `usernames` / `passwords` | built-in lists | Inline wordlists |
| `credentials_file` | `weak_auth_credentials.json` | JSON `pairs` array |
| `wordlist_file` | `null` | One password per line |
| `usernames_file` | `null` | One username per line |

Example credential file (`config/weak_auth_credentials.json`):

```json
{
  "pairs": [
    ["admin", "admin"],
    ["root", "toor"]
  ]
}
```

Enable in config:

```json
"weak_auth": {
  "enabled": true,
  "paths": ["/", "/admin"],
  "credentials_file": "weak_auth_credentials.json"
}
```

Or temporarily:

```bash
export DOMAINLENS_WEAK_AUTH_ENABLED=1
```

Select check `weak_auth` in the UI or API:

```json
{ "domain": "example.com", "checks": ["weak_auth", "http_headers"] }
```

### `monitors` (declarative bootstrap)

On startup, monitors in config are **upserted** into the database (matched by domain + target + record type):

```json
"monitors": [
  {
    "name": "example.com website",
    "domain": "example.com",
    "target": "example.com",
    "record_type": "A",
    "schedule_minutes": 60,
    "checks": ["dns", "tls_deep", "ncsc_tls"],
    "enabled": true
  }
]
```

## API

| Endpoint | Description |
|----------|-------------|
| `GET /api/config` | Non-secret effective configuration |
| `GET /health` | Liveness + scheduler state |
| `GET /api/reporting/scheduler` | Scheduler + 7-day reporting snapshot |

## Integrations (environment only)

ServiceNow, OAuth / Azure App Registration, local auth, OSINT API keys, and OVH credentials remain **environment variables** (or Admin Settings for non-secret OAuth fields such as provider and tenant ID) — see `README.md`, [AZURE_APP_REGISTRATION.md](AZURE_APP_REGISTRATION.md), and `servicenow.py`.
