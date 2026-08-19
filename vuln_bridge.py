"""
Vulnerability bridge: InsightVM/Nexpose → DomainLens DB → ServiceNow CMDB.

Orchestrates lean sync (API or filtered file) and optional CI ↔ Vulnerable Item linking.
Avoids full 1GB CSV dumps by filtering severity/sites and omitting proof/description blobs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import db
import insightvm
import rapid7_import
import servicenow_cmdb

log = logging.getLogger("domainlens.vuln_bridge")


def run_api_sync(*, push_cmdb: bool | None = None, imported_by: int | None = None) -> dict:
    """
    Pull from InsightVM Console or Cloud API, store lean findings, optionally link CMDB.
    """
    cfg = insightvm.config()
    if not cfg.get("enabled"):
        return {"ok": False, "error": "Rapid7 integration disabled in settings"}

    mode = cfg.get("source_mode") or "file"
    if mode == "console_api":
        if not cfg.get("console_configured"):
            return {
                "ok": False,
                "error": "Console API not configured (RAPID7_CONSOLE_URL + RAPID7_USERNAME/PASSWORD)",
            }
        parsed = insightvm.sync_from_console_api(cfg)
    elif mode == "cloud_api":
        if not cfg.get("cloud_configured"):
            return {"ok": False, "error": "Cloud API not configured (RAPID7_API_KEY)"}
        parsed = insightvm.sync_from_cloud_api(cfg)
    else:
        return {
            "ok": False,
            "error": (
                "source_mode is 'file'. Upload a lean export via /api/vuln-imports "
                "or set Rapid7 source_mode to console_api / cloud_api."
            ),
        }

    findings = insightvm.lean_filter_findings(parsed.get("findings") or [], cfg)
    record = db.save_vuln_import(
        filename=f"api-sync-{mode}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        source_format=parsed.get("source_format") or mode,
        findings=findings,
        summary=parsed.get("summary"),
        warnings=parsed.get("warnings"),
        header_map=parsed.get("header_map"),
        row_count=parsed.get("row_count") or len(findings),
        imported_by=imported_by,
    )

    # Re-load from DB so findings carry DomainLens ids for ServiceNow deep links
    stored = db.list_vuln_findings(import_id=record["id"], limit=len(findings) + 10)

    cmdb_cfg = servicenow_cmdb.cmdb_config()
    do_push = push_cmdb if push_cmdb is not None else (
        cfg.get("sync_to_servicenow_cmdb") and cmdb_cfg.get("cmdb_enabled")
    )
    cmdb_result = None
    if do_push:
        cmdb_result = push_findings_to_cmdb(stored, cfg=cmdb_cfg)

    return {
        "ok": True,
        "mode": mode,
        "import": record,
        "summary": parsed.get("summary"),
        "warnings": parsed.get("warnings"),
        "findings_stored": len(findings),
        "cmdb": cmdb_result,
    }


def ingest_file_bytes(
    data: bytes,
    *,
    filename: str,
    content_type: str | None = None,
    imported_by: int | None = None,
    push_cmdb: bool | None = None,
) -> dict:
    """Parse CSV/XLSX export, lean-filter, store, optional CMDB push."""
    cfg = insightvm.config()
    parsed = rapid7_import.parse_export(
        data,
        filename=filename,
        content_type=content_type,
        max_rows=int(cfg.get("max_rows") or 50000),
    )
    findings = insightvm.lean_filter_findings(
        parsed.get("findings") or [],
        cfg,
        severity_key="file_min_severity",
    )
    # Recompute summary after lean filter
    by_sev: dict[str, int] = {}
    assets = set()
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        assets.add((f.get("hostname") or "") + "|" + (f.get("asset_ip") or ""))
    summary = {
        "by_severity": by_sev,
        "assets": len(assets),
        "findings": len(findings),
        "with_cve": sum(1 for f in findings if f.get("cves")),
        "lean_filtered": True,
        "original_rows": parsed.get("row_count"),
        "file_min_severity": cfg.get("file_min_severity"),
    }
    warnings = list(parsed.get("warnings") or [])
    if (parsed.get("row_count") or 0) > len(findings):
        warnings.append(
            f"Lean filter kept {len(findings)} of {parsed.get('row_count')} rows "
            f"(severity ≥ {cfg.get('file_min_severity')}, bulky fields stripped)."
        )

    record = db.save_vuln_import(
        filename=filename,
        source_format=parsed.get("source_format") or "csv",
        findings=findings,
        summary=summary,
        warnings=warnings,
        header_map=parsed.get("header_map"),
        row_count=len(findings),
        imported_by=imported_by,
    )

    stored = db.list_vuln_findings(import_id=record["id"], limit=len(findings) + 10)

    cmdb_cfg = servicenow_cmdb.cmdb_config()
    do_push = push_cmdb if push_cmdb is not None else (
        cfg.get("sync_to_servicenow_cmdb") and cmdb_cfg.get("cmdb_enabled")
    )
    cmdb_result = push_findings_to_cmdb(stored, cfg=cmdb_cfg) if do_push else None

    return {
        "ok": True,
        "mode": "file",
        "import": record,
        "summary": summary,
        "warnings": warnings,
        "header_map": parsed.get("header_map"),
        "findings_stored": len(findings),
        "cmdb": cmdb_result,
    }


def push_findings_to_cmdb(findings: list[dict], *, cfg: dict | None = None, limit: int | None = None) -> dict:
    """Link each finding to a ServiceNow CI / Vulnerable Item."""
    cfg = cfg or servicenow_cmdb.cmdb_config()
    if not cfg.get("configured"):
        return {"ok": False, "error": "ServiceNow not configured"}
    if not cfg.get("cmdb_enabled"):
        return {"ok": False, "error": "servicenow.cmdb_enabled is false"}

    max_n = limit or len(findings)
    stats = {
        "processed": 0,
        "created": 0,
        "updated": 0,
        "ci_matched_only": 0,
        "unmatched_ci": 0,
        "errors": 0,
        "skipped_existing": 0,
    }
    samples = []

    for finding in findings[:max_n]:
        stats["processed"] += 1
        result = servicenow_cmdb.link_finding_to_cmdb(finding, cfg=cfg)
        action = result.get("action") or ("error" if not result.get("ok") else "ok")
        if action in stats:
            stats[action] += 1
        elif not result.get("ok"):
            stats["errors"] += 1
            if result.get("action") == "unmatched_ci":
                stats["unmatched_ci"] += 1
        if len(samples) < 20:
            samples.append({
                "hostname": finding.get("hostname"),
                "title": (finding.get("title") or "")[:80],
                "action": action,
                "ci": (result.get("ci") or {}).get("name"),
                "number": result.get("number"),
                "error": result.get("error"),
            })

    return {
        "ok": True,
        "stats": stats,
        "samples": samples,
        "note": (
            "For production at scale, prefer the ServiceNow Store app "
            "'Rapid7 Integration for Security Operations' with CI Lookup Rules. "
            "DomainLens's bridge is for lean/filtered sync and validation."
        ),
    }


def push_import_to_cmdb(import_id: int, *, limit: int = 5000) -> dict:
    record = db.get_vuln_import(import_id)
    if not record:
        return {"ok": False, "error": "Import not found"}
    findings = db.list_vuln_findings(import_id=import_id, limit=limit)
    return {
        "ok": True,
        "import_id": import_id,
        "cmdb": push_findings_to_cmdb(findings),
    }
