"""OpenAPI 3.1 description of the automation-facing API.

Served at /api/openapi.json so a team can point Swagger UI, Postman or a
client generator at it instead of reading app.py. It covers the endpoints a
pipeline or integration uses -- scans, history, monitors, reporting,
ownership, tokens and audit -- not every UI helper. A test checks that each
path and method listed here is a real route, so the document cannot drift
into describing endpoints that no longer exist.
"""

from __future__ import annotations

import version as app_version

_JSON = "application/json"


def _ok(description, schema=None):
    content = {_JSON: {"schema": schema or {"type": "object"}}}
    return {"200": {"description": description, "content": content}}


def _body(schema, required=True):
    return {"required": required, "content": {_JSON: {"schema": schema}}}


def _param(name, where="query", schema=None, required=False, description=None):
    out = {"name": name, "in": where, "required": required or where == "path",
           "schema": schema or {"type": "string"}}
    if description:
        out["description"] = description
    return out


_DAYS = _param("days", schema={"type": "integer", "minimum": 1, "maximum": 365, "default": 30})
_DOMAIN_FILTER = _param("domain", description="Limit to one domain")
_ERRORS = {
    "401": {"description": "No valid session or API token"},
    "403": {"description": "Your role does not allow this"},
    "429": {"description": "Rate limit exceeded"},
}

_SCAN_REQUEST = {
    "type": "object",
    "required": ["domain"],
    "properties": {
        "domain": {"type": "string", "example": "example.com"},
        "checks": {"type": "array", "items": {"type": "string"}, "default": ["all"],
                   "description": "Check names from GET /api/checks, or [\"all\"]. "
                                  "weak_auth and active_scan run only on verified domains."},
        "dkim_selectors": {"type": "array", "items": {"type": "string"}},
        "save_history": {"type": "boolean", "default": True},
        "force_refresh": {"type": "boolean", "default": False},
    },
}


def _op(summary, tag, responses, *, params=None, body=None, role="viewer", description=None):
    op = {"summary": summary, "tags": [tag], "responses": {**responses, **_ERRORS},
          "x-minimum-role": role}
    if params:
        op["parameters"] = params
    if body:
        op["requestBody"] = body
    if description:
        op["description"] = description
    return op


def spec():
    paths = {
        "/api/version": {"get": _op("Application version", "System", _ok("Version info"))},
        "/api/checks": {"get": _op("Catalog of selectable checks", "Scans", _ok("Grouped checks"))},
        "/api/scan": {"post": _op(
            "Run a scan and wait for the result", "Scans", _ok("Full scan result"),
            body=_body(_SCAN_REQUEST), role="user",
            description="Synchronous; can take a minute. Prefer /api/scan/start in pipelines.")},
        "/api/scan/start": {"post": _op(
            "Start a scan in the background", "Scans",
            {"202": {"description": "Job accepted; poll /api/scan/status/{job_id}"},
             "409": {"description": "A scan for this domain is already running"}},
            body=_body(_SCAN_REQUEST), role="user")},
        "/api/scan/status/{job_id}": {"get": _op(
            "Poll a scan job", "Scans", _ok("Job state; includes the result when finished"),
            params=[_param("job_id", "path")])},
        "/api/scan/active": {"get": _op(
            "Running scan for a domain, if any", "Scans", _ok("Job or null"),
            params=[_param("domain", required=True)])},
        "/api/history": {
            "get": _op("List saved scans", "History", _ok("Scans and totals"),
                       params=[_DOMAIN_FILTER,
                               _param("limit", schema={"type": "integer", "maximum": 500}),
                               _param("days", schema={"type": "integer"})]),
            "delete": _op("Delete all saved scans", "History", _ok("Cleared"), role="admin"),
        },
        "/api/history/{scan_id}": {
            "get": _op("One saved scan with its full result", "History", _ok("Scan"),
                       params=[_param("scan_id", "path", {"type": "integer"})]),
            "delete": _op("Delete one saved scan", "History", _ok("Deleted"),
                          params=[_param("scan_id", "path", {"type": "integer"})], role="user"),
        },
        "/api/compare": {"get": _op(
            "What got worse, better or changed between two scans", "History", _ok("Diff"),
            params=[_param("a", schema={"type": "integer"}, required=True, description="Older scan id"),
                    _param("b", schema={"type": "integer"}, required=True, description="Newer scan id")])},
        "/api/recommendations/{scan_id}": {"get": _op(
            "Prioritised findings with fix and re-test steps", "History", _ok("Recommendations"),
            params=[_param("scan_id", "path", {"type": "integer"})])},
        "/api/monitors": {
            "get": _op("List monitors", "Monitoring", _ok("Monitors, stats and recent events")),
            "post": _op("Create a monitor", "Monitoring", {"201": {"description": "Created"}},
                        role="user", body=_body({
                            "type": "object", "required": ["domain"],
                            "properties": {
                                "domain": {"type": "string"}, "target": {"type": "string"},
                                "record_type": {"type": "string", "default": "A"},
                                "schedule_minutes": {"type": "integer", "default": 1440},
                                "checks": {"type": "array", "items": {"type": "string"}},
                                "enabled": {"type": "boolean", "default": True}}})),
        },
        "/api/monitors/{monitor_id}": {
            "patch": _op("Change a monitor", "Monitoring", _ok("Updated monitor"), role="user",
                         params=[_param("monitor_id", "path", {"type": "integer"})],
                         body=_body({"type": "object"})),
            "delete": _op("Delete a monitor", "Monitoring", _ok("Deleted"), role="user",
                          params=[_param("monitor_id", "path", {"type": "integer"})]),
        },
        "/api/monitors/{monitor_id}/scan/start": {"post": _op(
            "Run a monitor now, in the background", "Monitoring",
            {"202": {"description": "Job accepted"}}, role="user",
            params=[_param("monitor_id", "path", {"type": "integer"})])},
        "/api/monitors/discovered": {"get": _op(
            "Hostnames seen in Certificate Transparency that no monitor watches", "Monitoring",
            _ok("Suggestions from the latest saved scan of each monitored zone"))},
        "/api/monitor-events": {"get": _op(
            "Monitor events: baselines, changes, regressions", "Monitoring", _ok("Events"),
            params=[_param("monitor_id", schema={"type": "integer"}),
                    _param("limit", schema={"type": "integer", "maximum": 500})])},
        "/api/reporting/overview": {"get": _op("Portfolio KPIs", "Reporting", _ok("KPIs"),
                                               params=[_DAYS, _DOMAIN_FILTER])},
        "/api/reporting/domains": {"get": _op("Per-domain summary", "Reporting", _ok("Domains"),
                                              params=[_DAYS, _DOMAIN_FILTER])},
        "/api/reporting/deltas": {"get": _op("How each domain moved, worst first", "Reporting",
                                             _ok("Deltas"), params=[_DAYS, _DOMAIN_FILTER])},
        "/api/reporting/trends": {"get": _op("Time series", "Reporting", _ok("Trends"),
                                             params=[_DAYS, _DOMAIN_FILTER])},
        "/api/whois": {"get": _op(
            "Registration data (RDAP, then port-43 WHOIS) for one domain", "WHOIS",
            _ok("Registration data; a subdomain is looked up at its registered domain"),
            params=[_param("domain", required=True)])},
        "/api/whois/batch": {"post": _op(
            "Look up a list of domains in the background, paced per registry", "WHOIS",
            {"202": {"description": "Batch accepted; poll /api/whois/batch/{job_id}"}},
            role="user", body=_body({"type": "object", "required": ["text"], "properties": {
                "text": {"type": "string",
                         "description": "Domain names, one per line or as CSV; at most 500"}}}))},
        "/api/whois/batch/{job_id}": {
            "get": _op("Progress and rows of a batch", "WHOIS", _ok("Batch state"),
                       params=[_param("job_id", "path")]),
            "delete": _op("Stop a batch", "WHOIS", _ok("Batch state"), role="user",
                          params=[_param("job_id", "path")]),
        },
        "/api/whois/batch/{job_id}/csv": {"get": _op(
            "A batch as CSV", "WHOIS", {"200": {"description": "CSV file"}},
            params=[_param("job_id", "path")])},
        "/api/ownership": {
            "get": _op("Domains and their verification state", "Ownership", _ok("Domains"), role="user"),
            "post": _op("Start verifying a domain", "Ownership",
                        {"201": {"description": "Pending entry with DNS and HTTPS instructions"}},
                        role="user", body=_body({"type": "object", "required": ["domain"],
                                                 "properties": {"domain": {"type": "string"}}})),
        },
        "/api/ownership/{domain}/check": {"post": _op(
            "Check the DNS record or HTTPS file now", "Ownership", _ok("Updated entry"), role="user",
            params=[_param("domain", "path")])},
        "/api/tokens": {
            "get": _op("Your API tokens (never their values)", "Tokens", _ok("Tokens")),
            "post": _op("Create an API token (browser session only)", "Tokens",
                        {"201": {"description": "The token value, shown this once"}},
                        body=_body({"type": "object", "required": ["name"], "properties": {
                            "name": {"type": "string"},
                            "role": {"type": "string", "enum": ["viewer", "user", "admin"]},
                            "days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 90}}})),
        },
        "/api/tokens/{token_id}": {"delete": _op(
            "Revoke one of your tokens", "Tokens", _ok("Revoked"),
            params=[_param("token_id", "path", {"type": "integer"})])},
        "/api/admin/audit": {"get": _op(
            "Audit log entries, newest first", "Audit", _ok("Entries and total"), role="admin",
            params=[_param("action", description="Prefix, e.g. auth."),
                    _param("actor"), _param("outcome"),
                    _param("since", schema={"type": "string", "format": "date"}),
                    _param("until", schema={"type": "string", "format": "date"}),
                    _param("limit", schema={"type": "integer", "maximum": 500}),
                    _param("offset", schema={"type": "integer"})])},
        "/api/admin/audit/verify": {"get": _op(
            "Verify the audit log hash chain", "Audit", _ok("Intact, or where it breaks"), role="admin")},
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "DomainLens API",
            "version": app_version.get_version(),
            "description": (
                "Authenticate with `Authorization: Bearer dlk_…` (create one under "
                "Account → API tokens) or a signed-in session. `x-minimum-role` on "
                "each operation is the least role that may call it: viewer < user "
                "(Analyst) < admin."
            ),
        },
        "components": {"securitySchemes": {
            "apiToken": {"type": "http", "scheme": "bearer", "bearerFormat": "dlk_…"},
            "session": {"type": "apiKey", "in": "cookie", "name": "session"},
        }},
        "security": [{"apiToken": []}, {"session": []}],
        "paths": paths,
    }
