"""
ServiceNow CMDB + Vulnerability Response helpers for DomainLens.

Preferred enterprise path (documented by ServiceNow):
  Install Store app "Rapid7 Integration for Security Operations" which runs
  scheduled jobs into Vulnerability Response and uses CI Lookup Rules to match
  Discovered Items → cmdb_ci. See:
  https://www.servicenow.com/docs/r/security-management/vulnerability-response/r7-vuln-integration.html

DomainLens bridge (this module) supports orgs that need a lean API path:
  1) Lookup CI in CMDB by hostname / FQDN / IP (Table API on cmdb_ci)
  2) Ensure a vulnerability definition (sn_vul_vulnerability) when possible
  3) Upsert Vulnerable Item (sn_vul_vulnerable_item) with cmdb_ci reference

Tables (Vulnerability Response):
  - sn_vul_vulnerable_item  — links vulnerability ↔ CI (field: cmdb_ci)
  - sn_vul_vulnerability    — vulnerability definition / CVE metadata
  - cmdb_ci                 — Configuration Items

References:
  - CI Lookup Rules: https://www.servicenow.com/docs/r/security-management/vulnerability-response/create-ci-identifier-rules.html
  - VI query by CI: GET .../sn_vul_vulnerable_item?sysparm_query=cmdb_ci=<sys_id>
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests

log = logging.getLogger("domainlens.servicenow.cmdb")

_SEVERITY_TO_RISK = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "info": 5,
}


def cmdb_config(base_cfg: dict | None = None) -> dict:
    """Merge ServiceNow base config with CMDB/VR settings."""
    from servicenow import config as sn_config

    base = dict(base_cfg or sn_config())
    raw = {}
    try:
        from settings.store import get_store
        raw = dict(get_store().section("servicenow", force_reload=True))
    except Exception:
        pass

    return {
        **base,
        "cmdb_enabled": bool(raw.get("cmdb_enabled", False)),
        "create_vulnerable_items": bool(raw.get("create_vulnerable_items", False)),
        "update_existing_vi": bool(raw.get("update_existing_vi", True)),
        "ci_table": (raw.get("ci_table") or "cmdb_ci").strip(),
        "vuln_item_table": (raw.get("vuln_item_table") or "sn_vul_vulnerable_item").strip(),
        "vuln_table": (raw.get("vuln_table") or "sn_vul_vulnerability").strip(),
        "ci_match_fields": list(
            raw.get("ci_match_fields")
            or ["name", "fqdn", "host_name", "ip_address", "dns_domain"]
        ),
        "vi_source": (raw.get("vi_source") or "DomainLens InsightVM").strip(),
        "vi_state_open": (raw.get("vi_state_open") or "open").strip(),
        # Optional custom field on VI for the deep link (e.g. u_domainlens_url)
        "domainlens_url_field": (
            raw.get("domainlens_url_field")
            or os.environ.get("SERVICENOW_DOMAINLENS_URL_FIELD")
            or ""
        ).strip()
        or None,
    }


def _auth_headers(cfg: dict) -> tuple:
    return (cfg["user"], cfg["password"]), {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _table_url(cfg: dict, table: str) -> str:
    return f"{cfg['instance']}/api/now/table/{table}"


def sn_get(cfg: dict, table: str, *, query: str | None = None, fields: str | None = None, limit: int = 10) -> list[dict]:
    params = {"sysparm_limit": str(limit)}
    if query:
        params["sysparm_query"] = query
    if fields:
        params["sysparm_fields"] = fields
    auth, headers = _auth_headers(cfg)
    resp = requests.get(_table_url(cfg, table), auth=auth, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return list((resp.json() or {}).get("result") or [])


def sn_post(cfg: dict, table: str, payload: dict) -> dict:
    auth, headers = _auth_headers(cfg)
    resp = requests.post(_table_url(cfg, table), auth=auth, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    return (resp.json() or {}).get("result") or {}


def sn_patch(cfg: dict, table: str, sys_id: str, payload: dict) -> dict:
    auth, headers = _auth_headers(cfg)
    url = f"{_table_url(cfg, table)}/{sys_id}"
    resp = requests.patch(url, auth=auth, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    return (resp.json() or {}).get("result") or {}


def lookup_ci(
    hostname: str | None = None,
    ip: str | None = None,
    *,
    cfg: dict | None = None,
) -> dict | None:
    """
    Find a CMDB CI matching hostname/FQDN/IP.

    Mirrors ServiceNow CI Lookup Rule ideas (DNS name, IP) but via Table API.
    Returns {sys_id, name, ip_address, fqdn, sys_class_name} or None.
    """
    cfg = cfg or cmdb_config()
    if not cfg.get("configured"):
        return None

    hostname = (hostname or "").strip().lower().rstrip(".")
    ip = (ip or "").strip()
    clauses = []
    if hostname:
        # Exact name / fqdn / host_name; also short name before first dot
        short = hostname.split(".", 1)[0]
        for field in cfg.get("ci_match_fields") or []:
            field = str(field).strip()
            if not field or field == "ip_address":
                continue
            clauses.append(f"{field}={hostname}")
            if short and short != hostname:
                clauses.append(f"{field}={short}")
    if ip:
        clauses.append(f"ip_address={ip}")

    if not clauses:
        return None

    # OR join
    query = "^OR".join(clauses)
    fields = "sys_id,name,ip_address,fqdn,host_name,sys_class_name,operational_status"
    try:
        rows = sn_get(cfg, cfg["ci_table"], query=query, fields=fields, limit=5)
    except Exception as exc:
        log.warning("CMDB CI lookup failed: %s", exc)
        return None
    if not rows:
        return None
    row = rows[0]
    return {
        "sys_id": row.get("sys_id"),
        "name": row.get("name"),
        "ip_address": row.get("ip_address"),
        "fqdn": row.get("fqdn") or row.get("host_name"),
        "sys_class_name": row.get("sys_class_name"),
        "url": f"{cfg['instance']}/nav_to.do?uri={cfg['ci_table']}.do?sys_id={row.get('sys_id')}",
    }


def find_or_create_vulnerability_def(finding: dict, *, cfg: dict | None = None) -> dict | None:
    """
    Locate sn_vul_vulnerability by CVE or source id; create a minimal record if allowed.
    Returns {sys_id, id} or None when VR tables are unavailable.
    """
    cfg = cfg or cmdb_config()
    if not cfg.get("configured"):
        return None

    cves = finding.get("cves") or []
    vuln_id = finding.get("vuln_id") or ""
    queries = []
    if cves:
        queries.append(f"id={cves[0]}")
        queries.append(f"cve={cves[0]}")
    if vuln_id:
        queries.append(f"source_id={vuln_id}")
        queries.append(f"id={vuln_id}")

    for q in queries:
        try:
            rows = sn_get(
                cfg,
                cfg["vuln_table"],
                query=q,
                fields="sys_id,id,source_id,cve",
                limit=1,
            )
            if rows:
                return {"sys_id": rows[0].get("sys_id"), "id": rows[0].get("id") or cves[:1] or vuln_id}
        except Exception as exc:
            # Table may not exist without Vulnerability Response plugin
            log.info("Vulnerability table query skipped (%s): %s", q, exc)
            return None

    if not cfg.get("create_vulnerable_items"):
        return None

    payload = {
        "short_description": (finding.get("title") or "Imported vulnerability")[:160],
        "source": cfg.get("vi_source") or "DomainLens",
    }
    if cves:
        payload["id"] = cves[0]
        payload["cve"] = cves[0]
    elif vuln_id:
        payload["id"] = str(vuln_id)
        payload["source_id"] = str(vuln_id)
    if finding.get("cvss") is not None:
        payload["cvss_score"] = str(finding["cvss"])
    try:
        created = sn_post(cfg, cfg["vuln_table"], payload)
        return {"sys_id": created.get("sys_id"), "id": payload.get("id"), "created": True}
    except Exception as exc:
        log.warning("Create vulnerability definition failed: %s", exc)
        return None


def find_vulnerable_item(ci_sys_id: str, vulnerability_sys_id: str | None, finding: dict, *, cfg: dict | None = None) -> dict | None:
    cfg = cfg or cmdb_config()
    clauses = [f"cmdb_ci={ci_sys_id}"]
    if vulnerability_sys_id:
        clauses.append(f"vulnerability={vulnerability_sys_id}")
    elif finding.get("vuln_id"):
        clauses.append(f"source_id={finding['vuln_id']}")
    query = "^".join(clauses)
    try:
        rows = sn_get(
            cfg,
            cfg["vuln_item_table"],
            query=query,
            fields="sys_id,number,cmdb_ci,vulnerability,state,source_id",
            limit=1,
        )
        return rows[0] if rows else None
    except Exception as exc:
        log.warning("Vulnerable item lookup failed: %s", exc)
        return None


def upsert_vulnerable_item(finding: dict, ci: dict, vuln_def: dict | None = None, *, cfg: dict | None = None) -> dict:
    """
    Create or update sn_vul_vulnerable_item linked to cmdb_ci.

    Embeds a DomainLens remediation deep link so Product Owners can open the tool
    from ServiceNow (ownership stays in SN).
    """
    cfg = cfg or cmdb_config()
    if not cfg.get("configured"):
        return {"ok": False, "error": "ServiceNow not configured"}
    if not cfg.get("cmdb_enabled"):
        return {"ok": False, "error": "CMDB bridge disabled in settings"}
    if not ci or not ci.get("sys_id"):
        return {"ok": False, "error": "No CI matched"}

    import domainlens_links

    vuln_sys_id = (vuln_def or {}).get("sys_id")
    existing = find_vulnerable_item(ci["sys_id"], vuln_sys_id, finding, cfg=cfg)
    links = domainlens_links.finding_link_block(finding)

    short = finding.get("title") or "Vulnerability"
    if finding.get("cves"):
        short = f"{short} ({', '.join(finding['cves'][:2])})"
    short = short[:160]

    remediation_parts = []
    if finding.get("solution"):
        remediation_parts.append(str(finding["solution"])[:3500])
    remediation_parts.append(links["text"])
    remediation = "\n\n".join(remediation_parts)[:4000]

    description_parts = []
    if finding.get("description"):
        description_parts.append(str(finding["description"])[:3000])
    description_parts.append(links["text"])
    description = "\n\n".join(description_parts)[:4000]

    payload: dict[str, Any] = {
        "cmdb_ci": ci["sys_id"],
        "short_description": short,
        "source": cfg.get("vi_source") or "DomainLens InsightVM",
        "ip_address": finding.get("asset_ip") or "",
        "dns_name": finding.get("hostname") or "",
        "risk_score": str(_SEVERITY_TO_RISK.get(finding.get("severity") or "info", 5)),
        "remediation": remediation,
        "description": description,
        "work_notes": links["text"],
    }
    if vuln_sys_id:
        payload["vulnerability"] = vuln_sys_id
    if finding.get("vuln_id"):
        payload["source_id"] = str(finding["vuln_id"])
    # Optional custom field on the VI form for a clickable URL
    url_field = cfg.get("domainlens_url_field")
    if url_field and links.get("domainlens_url"):
        payload[url_field] = links["domainlens_url"]
    elif url_field and links.get("domain_url"):
        payload[url_field] = links["domain_url"]

    try:
        if existing and existing.get("sys_id"):
            if not cfg.get("update_existing_vi", True):
                return {
                    "ok": True,
                    "action": "skipped_existing",
                    "sys_id": existing.get("sys_id"),
                    "number": existing.get("number"),
                    "domainlens_url": links.get("domainlens_url"),
                }
            updated = sn_patch(cfg, cfg["vuln_item_table"], existing["sys_id"], payload)
            return {
                "ok": True,
                "action": "updated",
                "sys_id": updated.get("sys_id") or existing.get("sys_id"),
                "number": updated.get("number") or existing.get("number"),
                "ci_sys_id": ci["sys_id"],
                "url": f"{cfg['instance']}/nav_to.do?uri={cfg['vuln_item_table']}.do?sys_id={existing.get('sys_id')}",
                "domainlens_url": links.get("domainlens_url"),
                "domain_url": links.get("domain_url"),
            }

        if not cfg.get("create_vulnerable_items"):
            return {
                "ok": True,
                "action": "ci_matched_only",
                "ci_sys_id": ci["sys_id"],
                "ci_name": ci.get("name"),
                "ci_url": ci.get("url"),
                "domainlens_url": links.get("domainlens_url"),
            }

        created = sn_post(cfg, cfg["vuln_item_table"], payload)
        sys_id = created.get("sys_id")
        return {
            "ok": True,
            "action": "created",
            "sys_id": sys_id,
            "number": created.get("number"),
            "ci_sys_id": ci["sys_id"],
            "url": f"{cfg['instance']}/nav_to.do?uri={cfg['vuln_item_table']}.do?sys_id={sys_id}" if sys_id else None,
            "domainlens_url": links.get("domainlens_url"),
            "domain_url": links.get("domain_url"),
        }
    except Exception as exc:
        log.warning("Vulnerable item upsert failed: %s", exc)
        return {"ok": False, "error": str(exc)[:400], "ci_sys_id": ci.get("sys_id")}


def link_finding_to_cmdb(finding: dict, *, cfg: dict | None = None) -> dict:
    """Full hook: CI lookup → optional VR definition → VI upsert."""
    cfg = cfg or cmdb_config()
    ci = lookup_ci(finding.get("hostname"), finding.get("asset_ip"), cfg=cfg)
    if not ci:
        return {
            "ok": False,
            "action": "unmatched_ci",
            "hostname": finding.get("hostname"),
            "asset_ip": finding.get("asset_ip"),
            "hint": (
                "No CMDB CI matched. Tune CI Lookup Rules in ServiceNow "
                "(Security Operations > CMDB > CI Lookup Rules) or ensure "
                "cmdb_ci.name/fqdn/ip_address matches the InsightVM asset."
            ),
        }

    vuln_def = None
    if cfg.get("create_vulnerable_items"):
        vuln_def = find_or_create_vulnerability_def(finding, cfg=cfg)

    result = upsert_vulnerable_item(finding, ci, vuln_def, cfg=cfg)
    result["ci"] = ci
    result["vulnerability_def"] = vuln_def
    result["linked_at"] = datetime.now(timezone.utc).isoformat()
    return result


def list_vulnerable_items_for_ci(ci_sys_id: str, *, cfg: dict | None = None, limit: int = 50) -> list[dict]:
    """GET Vulnerable Items for a CI (sysparm_query=cmdb_ci=<sys_id>)."""
    cfg = cfg or cmdb_config()
    if not cfg.get("configured") or not ci_sys_id:
        return []
    try:
        return sn_get(
            cfg,
            cfg["vuln_item_table"],
            query=f"cmdb_ci={ci_sys_id}",
            fields="sys_id,number,short_description,state,risk_score,vulnerability,source_id",
            limit=limit,
        )
    except Exception as exc:
        log.warning("List VIs for CI failed: %s", exc)
        return []
