# Rapid7 InsightVM / Nexpose ↔ ServiceNow CMDB

## Problem

A full InsightVM/Nexpose vulnerability export is often **~1GB** and includes proof text, policy noise, and low-severity noise that DomainLens and ServiceNow do not need. This guide describes the **lean** path DomainLens implements and how it aligns with official Rapid7 and ServiceNow documentation.

## Recommended architecture

```
InsightVM / Nexpose
        │
        ├─ Console API v3  (filtered assets + findings)   ← preferred
        ├─ Cloud Integrations API v4 (Query Builder)      ← preferred (cloud)
        └─ Lean CSV/XLSX (Critical/Severe only)           ← fallback
                │
                ▼
           DomainLens (store + Advies)
                │
                ├─ Domain correlation (hostname / FQDN)
                └─ Optional: ServiceNow CMDB bridge
                        │
                        ├─ Lookup cmdb_ci (name / fqdn / IP)
                        └─ Upsert sn_vul_vulnerable_item (cmdb_ci = CI sys_id)
```

### Official ServiceNow path (enterprise scale)

ServiceNow documents the Store app **Rapid7 Integration for Security Operations**, which:

1. Imports assets and vulnerable items from InsightVM / data warehouse via scheduled jobs  
2. Creates **Discovered Items**  
3. Uses **CI Lookup Rules** to match hosts → `cmdb_ci`  
4. Creates **Vulnerable Items** (`sn_vul_vulnerable_item`) linked to those CIs  

Docs:

- [Understanding the Rapid7 Vulnerability Integration](https://www.servicenow.com/docs/r/security-management/vulnerability-response/r7-vuln-integration.html)
- [Install the Rapid7 Vulnerability Integration](https://www.servicenow.com/docs/r/security-management/vulnerability-response/install-and-configure-r7.html)
- [Create a Vulnerability Response CI lookup rule](https://www.servicenow.com/docs/r/security-management/vulnerability-response/create-ci-identifier-rules.html)

**Use the Store app** when you need continuous, high-volume VR. Use DomainLens’s bridge to:

- Validate CI matching with lean subsets  
- Enrich DomainLens Advies with InsightVM findings  
- Push filtered findings when the Store app is not available yet  

## Rapid7 APIs (official)

| Mode | Auth | Docs |
|------|------|------|
| `console_api` | Basic (`RAPID7_USERNAME` / `RAPID7_PASSWORD`) | [Security Console API v3](https://help.rapid7.com/insightvm/en-us/api/index.html) |
| `cloud_api` | `X-Api-Key` (`RAPID7_API_KEY`) | [Cloud Integrations API v4](https://help.rapid7.com/insightvm/en-us/api/integrations.html) |
| Overview | | [RESTful API overview](https://docs.rapid7.com/insightvm/restful-api/) |

### Console lean sync (what DomainLens does)

1. `POST /api/3/assets/search` with filters:
   - `vulnerability-severity` ∈ Critical / Severe (configurable)
   - optional `site-id`, `host-name contains`
2. Cap assets (`max_assets`, default 500)
3. Per asset: `GET /api/3/assets/{id}/vulnerabilities` (capped)
4. `GET /api/3/vulnerabilities/{id}` for title / CVSS / CVE (cached)
5. **Omit** proof and long descriptions by default

### Cloud lean sync

`POST /vm/v4/integration/assets` with Query Builder syntax:

```json
{
  "asset": "asset.name CONTAINS 'example.com'",
  "vulnerability": "severity IN ['Critical', 'Severe']"
}
```

Use `&&` for AND and `||` for OR (InsightVM Query Builder expert mode).

## ServiceNow CMDB linkage (DomainLens bridge)

Tables (Vulnerability Response plugin required for VI create):

| Table | Role |
|-------|------|
| `cmdb_ci` | Configuration Items already in your CMDB |
| `sn_vul_vulnerability` | Vulnerability definition (CVE / source id) |
| `sn_vul_vulnerable_item` | Links vulnerability ↔ CI via **`cmdb_ci`** |

VI query by CI (community / VR practice):

```http
GET /api/now/table/sn_vul_vulnerable_item?sysparm_query=cmdb_ci=<ci_sys_id>
```

DomainLens matching order (similar to CI Lookup Rules):

1. `cmdb_ci.name` / `fqdn` / `host_name` = InsightVM hostname or short name  
2. `cmdb_ci.ip_address` = asset IP  

Then upsert VI with `cmdb_ci=<sys_id>`.

## Configuration (web UI + env)

### Settings → Rapid7

- `source_mode`: `file` | `console_api` | `cloud_api`
- `api_min_severity`: start with **`high`** (Critical+Severe) — never “all”
- `site_ids`, `asset_hostname_contains`, `max_assets`
- `include_description` / `include_proof`: leave **off**
- `sync_to_servicenow_cmdb`: auto-push after sync

### Settings → ServiceNow

- `cmdb_enabled`: enable CI lookup / VI bridge  
- `create_vulnerable_items`: create rows in `sn_vul_vulnerable_item` (needs VR)  
- Without create: DomainLens still reports **matched CI** for validation  

### Secrets (env only)

```bash
# Console API
export RAPID7_CONSOLE_URL="https://nexpose.example.com:3780"
export RAPID7_USERNAME="api-user"
export RAPID7_PASSWORD="…"

# Cloud API
export RAPID7_API_KEY="…"
# optional: RAPID7_CLOUD_API_BASE=https://us.api.insight.rapid7.com

# ServiceNow
export SERVICENOW_INSTANCE="https://example.service-now.com"
export SERVICENOW_USER="…"
export SERVICENOW_PASSWORD="…"

# Public DomainLens URL — written onto VI / incident so POs open the tool from ServiceNow
export DOMAINLENS_PUBLIC_URL="https://domainlens.example.com"
# optional custom field on sn_vul_vulnerable_item:
# export SERVICENOW_DOMAINLENS_URL_FIELD="u_domainlens_url"
```

### ServiceNow → DomainLens deep links

Ownership and assignment stay in **ServiceNow**. DomainLens embeds links back to the tool on create/update:

| ServiceNow record | Where the link appears | Opens in DomainLens |
| --- | --- | --- |
| Vulnerable Item (`sn_vul_vulnerable_item`) | `description`, `remediation`, `work_notes` (+ optional `u_domainlens_url`) | `/remediate/vuln/<id>` — problem / fix / retest |
| Monitor incident | `description`, `work_notes` | `/report/<scan_id>` and `/remediate/domain/<domain>` |

Set **`DOMAINLENS_PUBLIC_URL`** (or Settings → General → Public URL) to your externally reachable DomainLens base URL.

Optional: add a URL field on the VI form (e.g. `u_domainlens_url`) and set `servicenow.domainlens_url_field` / `SERVICENOW_DOMAINLENS_URL_FIELD` so the link is a first-class clickable field for Product Owners.

## API hooks

```bash
# Status
curl -s localhost:5000/api/integrations/insightvm
curl -s localhost:5000/api/integrations/servicenow/cmdb

# Lean API sync (admin)
curl -s -X POST localhost:5000/api/vuln-imports/sync \
  -H 'Content-Type: application/json' -d '{"push_cmdb": true}'

# Lean file upload (still severity-filtered on ingest)
curl -s -X POST 'localhost:5000/api/vuln-imports?push_cmdb=1' \
  -F file=@critical-severe.csv

# Push an existing import to CMDB
curl -s -X POST localhost:5000/api/vuln-imports/1/push-cmdb

# CI lookup test
curl -s -X POST localhost:5000/api/integrations/servicenow/cmdb/lookup \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"web01.example.com","ip":"10.0.0.5"}'
```

## Operational checklist

1. In InsightVM, do **not** schedule a full vulnerability CSV for DomainLens.  
2. Set Rapid7 `source_mode` to `console_api` or `cloud_api`, severity ≥ high.  
3. Confirm CIs exist in ServiceNow (`name`/`fqdn`/`ip_address` match scanner hostnames).  
4. Tune ServiceNow **CI Lookup Rules** for the Store app; use DomainLens lookup to verify.  
5. Enable `cmdb_enabled`; enable `create_vulnerable_items` only after VR tables exist.  
6. Scan a domain in DomainLens — Rapid7 tab + Advies show correlated findings.

## Modules

| File | Purpose |
|------|---------|
| `insightvm.py` | Console/Cloud API clients + lean sync |
| `rapid7_import.py` | CSV/XLSX parser |
| `vuln_bridge.py` | Orchestration (API/file → DB → CMDB) |
| `servicenow_cmdb.py` | CI lookup + Vulnerable Item upsert |
| `servicenow.py` | Existing incident integration |
