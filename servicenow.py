"""
ServiceNow incident integration for DomainLens monitor events.

Uses the Table API:
  POST /api/now/table/incident

Configure via environment variables:
  SERVICENOW_INSTANCE   e.g. https://example.service-now.com
  SERVICENOW_USER
  SERVICENOW_PASSWORD
  SERVICENOW_ENABLED=1
  SERVICENOW_MIN_SEVERITY=high          # critical|high|medium|low|info
  SERVICENOW_ASSIGNMENT_GROUP=          # optional sys_id or name
  SERVICENOW_CALLER_ID=                 # optional
  SERVICENOW_CATEGORY=Network
  SERVICENOW_SUBCATEGORY=DNS
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import requests

log = logging.getLogger("domainlens.servicenow")

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_URGENCY = {
    "critical": "1",
    "high": "2",
    "medium": "2",
    "low": "3",
    "info": "3",
}


def _managed_secret(*env_names):
    """Resolve a credential: environment first, then the encrypted store.

    Falls back to a plain environment read if the settings package is
    unavailable, so this can never be the reason an integration breaks.
    """
    try:
        from settings import api_keys
        return api_keys.resolve_first(*env_names)
    except Exception:
        for name in env_names:
            value = (os.environ.get(name) or "").strip()
            if value:
                return value
        return ""


def config():
    raw = {}
    try:
        from settings.store import get_store
        raw = dict(get_store().section("servicenow", force_reload=True))
    except Exception:
        pass
    instance = (raw.get("instance") or os.environ.get("SERVICENOW_INSTANCE") or "").strip().rstrip("/")
    user = _managed_secret("SERVICENOW_USER")
    password = _managed_secret("SERVICENOW_PASSWORD")
    enabled_flag = bool(raw.get("enabled", False))
    min_severity = (raw.get("min_severity") or os.environ.get("SERVICENOW_MIN_SEVERITY") or "high").strip().lower()
    if min_severity not in _SEVERITY_RANK:
        min_severity = "high"
    return {
        "enabled": enabled_flag and bool(instance and user and password),
        "configured": bool(instance and user and password),
        "instance": instance,
        "user": user,
        "password": password,
        "min_severity": min_severity,
        "assignment_group": (raw.get("assignment_group") or os.environ.get("SERVICENOW_ASSIGNMENT_GROUP") or "").strip() or None,
        "caller_id": (raw.get("caller_id") or os.environ.get("SERVICENOW_CALLER_ID") or "").strip() or None,
        "category": (raw.get("category") or os.environ.get("SERVICENOW_CATEGORY") or "Network").strip(),
        "subcategory": (raw.get("subcategory") or os.environ.get("SERVICENOW_SUBCATEGORY") or "DNS").strip(),
    }


def should_notify(severity: str) -> bool:
    cfg = config()
    if not cfg["enabled"]:
        return False
    return _SEVERITY_RANK.get(severity, 99) <= _SEVERITY_RANK[cfg["min_severity"]]


def create_incident(*, summary: str, severity: str, details: dict | None = None, monitor: dict | None = None):
    """Create a ServiceNow incident and return {sys_id, number} or None."""
    cfg = config()
    if not cfg["enabled"]:
        return None
    if not should_notify(severity):
        return None

    details = details or {}
    monitor = monitor or {}
    import domainlens_links

    scan_id = details.get("scan_id") or monitor.get("last_scan_id")
    domain = monitor.get("domain") or details.get("domain") or ""
    tool_lines = ["--- DomainLens ---"]
    if scan_id:
        tool_lines.append(f"Scan report: {domainlens_links.scan_report_url(scan_id)}")
    if domain:
        tool_lines.append(f"Domain Advies / retest: {domainlens_links.domain_remediation_url(domain)}")
    if monitor.get("id"):
        tool_lines.append(f"Monitors: {domainlens_links.monitor_url(monitor.get('id'))}")
    if len(tool_lines) == 1:
        base = domainlens_links.public_base_url()
        tool_lines.append(
            f"Open DomainLens: {base or '(set DOMAINLENS_PUBLIC_URL)'}"
        )

    description_lines = [
        f"DomainLens monitoring alert ({severity})",
        f"Summary: {summary}",
        f"Target: {monitor.get('target') or details.get('target') or '-'}",
        f"Domain: {monitor.get('domain') or '-'}",
        f"Record type: {monitor.get('record_type') or details.get('record_type') or '-'}",
        f"TLS grade: {details.get('tls_grade')}",
        f"Blacklist listed: {details.get('blacklist_listed')}",
        f"Recommendations: {details.get('recommendation_count')}",
        f"Detected at: {datetime.now(timezone.utc).isoformat()}",
        "",
        *tool_lines,
    ]
    work_notes = "Created automatically by DomainLens DNS monitoring.\n" + "\n".join(tool_lines)
    payload = {
        "short_description": summary[:160],
        "description": "\n".join(str(line) for line in description_lines),
        "urgency": _URGENCY.get(severity, "2"),
        "impact": _URGENCY.get(severity, "2"),
        "category": cfg["category"],
        "subcategory": cfg["subcategory"],
        "work_notes": work_notes,
    }
    if cfg["assignment_group"]:
        payload["assignment_group"] = cfg["assignment_group"]
    if cfg["caller_id"]:
        payload["caller_id"] = cfg["caller_id"]

    url = f"{cfg['instance']}/api/now/table/incident"
    try:
        response = requests.post(
            url,
            auth=(cfg["user"], cfg["password"]),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json=payload,
            timeout=20,
        )
        response.raise_for_status()
        result = (response.json() or {}).get("result") or {}
        return {
            "sys_id": result.get("sys_id"),
            "number": result.get("number"),
            "url": f"{cfg['instance']}/nav_to.do?uri=incident.do?sys_id={result.get('sys_id')}" if result.get("sys_id") else None,
        }
    except Exception as exc:
        log.warning("ServiceNow incident creation failed: %s", exc)
        return {"error": str(exc)[:300]}
