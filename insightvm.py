"""
Rapid7 InsightVM / Nexpose API client (lean pulls — avoid full 1GB exports).

Supports:
  - Security Console API v3 (on-prem Nexpose / InsightVM console)
    Auth: HTTP Basic (RAPID7_USERNAME / RAPID7_PASSWORD)
    Docs: https://help.rapid7.com/insightvm/en-us/api/index.html
  - Cloud Integrations API v4 (Insight platform)
    Auth: X-Api-Key (RAPID7_API_KEY)
    Docs: https://help.rapid7.com/insightvm/en-us/api/integrations.html

Design goal: pull only filtered assets + vulnerability IDs/metadata needed for
CMDB linkage — not full proof text, scan history, or policy dumps.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urljoin

import requests

import rapid7_import

log = logging.getLogger("domainlens.insightvm")

# InsightVM severity labels used by Console filters
_SEVERITY_FILTER_VALUES = {
    "critical": ["Critical"],
    "high": ["Critical", "Severe"],
    "medium": ["Critical", "Severe", "Moderate"],
    "low": ["Critical", "Severe", "Moderate", "Low"],
    "info": ["Critical", "Severe", "Moderate", "Low"],
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


def config(settings: dict | None = None) -> dict:
    raw = dict(settings or {})
    if not raw:
        try:
            from settings.store import get_store
            raw = dict(get_store().section("rapid7", force_reload=True))
        except Exception:
            pass

    mode = (raw.get("source_mode") or "file").strip().lower()
    if mode not in {"file", "console_api", "cloud_api"}:
        mode = "file"

    base = (raw.get("api_base_url") or os.environ.get("RAPID7_CONSOLE_URL") or "").strip().rstrip("/")
    cloud_base = (
        raw.get("cloud_api_base_url")
        or os.environ.get("RAPID7_CLOUD_API_BASE")
        or "https://us.api.insight.rapid7.com"
    ).strip().rstrip("/")

    user = _managed_secret("RAPID7_USERNAME")
    password = _managed_secret("RAPID7_PASSWORD")
    api_key = _managed_secret("RAPID7_API_KEY")

    console_ok = bool(base and user and password)
    cloud_ok = bool(api_key)

    return {
        "enabled": bool(raw.get("enabled", True)),
        "source_mode": mode,
        "api_base_url": base,
        "cloud_api_base_url": cloud_base,
        "verify_ssl": bool(raw.get("api_verify_ssl", True)),
        "username": user,
        "password": password,
        "api_key": api_key,
        "console_configured": console_ok,
        "cloud_configured": cloud_ok,
        "min_severity": (raw.get("api_min_severity") or "high").lower(),
        "file_min_severity": (raw.get("file_min_severity") or raw.get("min_severity_for_advies") or "medium").lower(),
        "site_ids": [
            int(x) for x in (raw.get("site_ids") or [])
            if (isinstance(x, int) or str(x).strip().isdigit())
        ],
        "asset_hostname_contains": (raw.get("asset_hostname_contains") or "").strip(),
        "max_assets": int(raw.get("max_assets") or 500),
        "max_findings_per_asset": int(raw.get("max_findings_per_asset") or 100),
        "page_size": min(500, max(10, int(raw.get("page_size") or 100))),
        "include_solution": bool(raw.get("include_solution", True)),
        "include_description": bool(raw.get("include_description", False)),
        "include_proof": bool(raw.get("include_proof", False)),
        "sync_to_servicenow_cmdb": bool(raw.get("sync_to_servicenow_cmdb", False)),
        "max_rows": int(raw.get("max_rows") or 50000),
    }


class InsightVMClient:
    """Thin HTTP client for Console API v3."""

    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or config()
        if not self.cfg.get("console_configured"):
            raise RuntimeError(
                "InsightVM Console API not configured. Set RAPID7_CONSOLE_URL, "
                "RAPID7_USERNAME, RAPID7_PASSWORD (and Settings → Rapid7)."
            )
        self.session = requests.Session()
        self.session.auth = (self.cfg["username"], self.cfg["password"])
        self.session.verify = self.cfg.get("verify_ssl", True)
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    def _url(self, path: str) -> str:
        return urljoin(self.cfg["api_base_url"] + "/", path.lstrip("/"))

    def _get(self, path: str, params: dict | None = None) -> dict:
        resp = self.session.get(self._url(path), params=params or {}, timeout=60)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def _post(self, path: str, body: dict, params: dict | None = None) -> dict:
        resp = self.session.post(self._url(path), json=body, params=params or {}, timeout=90)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def ping(self) -> dict:
        data = self._get("/api/3/administration/info")
        return {"ok": True, "info": data}

    def search_assets(self) -> list[dict]:
        """POST /api/3/assets/search with lean filters (paged)."""
        filters = []
        sev = self.cfg.get("min_severity") or "high"
        values = _SEVERITY_FILTER_VALUES.get(sev, _SEVERITY_FILTER_VALUES["high"])
        filters.append({
            "field": "vulnerability-severity",
            "operator": "in",
            "values": values,
        })
        site_ids = self.cfg.get("site_ids") or []
        if site_ids:
            filters.append({
                "field": "site-id",
                "operator": "in",
                "values": site_ids,
            })
        host_contains = self.cfg.get("asset_hostname_contains") or ""
        if host_contains:
            filters.append({
                "field": "host-name",
                "operator": "contains",
                "value": host_contains,
            })

        body = {"match": "all", "filters": filters}
        page_size = self.cfg["page_size"]
        max_assets = self.cfg["max_assets"]
        page = 0
        assets: list[dict] = []
        while len(assets) < max_assets:
            data = self._post(
                "/api/3/assets/search",
                body,
                params={"page": page, "size": page_size},
            )
            resources = data.get("resources") or []
            if not resources:
                break
            assets.extend(resources)
            total_pages = ((data.get("page") or {}).get("totalPages")) or 1
            page += 1
            if page >= total_pages:
                break
        return assets[:max_assets]

    def asset_vulnerabilities(self, asset_id: int | str) -> list[dict]:
        """GET /api/3/assets/{id}/vulnerabilities — finding stubs only."""
        page_size = self.cfg["page_size"]
        max_findings = self.cfg["max_findings_per_asset"]
        page = 0
        findings: list[dict] = []
        while len(findings) < max_findings:
            data = self._get(
                f"/api/3/assets/{asset_id}/vulnerabilities",
                params={"page": page, "size": page_size},
            )
            resources = data.get("resources") or []
            if not resources:
                break
            findings.extend(resources)
            total_pages = ((data.get("page") or {}).get("totalPages")) or 1
            page += 1
            if page >= total_pages:
                break
        return findings[:max_findings]

    def get_vulnerability(self, vuln_id: str) -> dict:
        """GET /api/3/vulnerabilities/{id} — metadata (title, severity, CVSS, CVEs)."""
        return self._get(f"/api/3/vulnerabilities/{vuln_id}")


class InsightVMCloudClient:
    """Cloud Integrations API v4 — filtered asset search with vulnerability criteria."""

    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or config()
        if not self.cfg.get("cloud_configured"):
            raise RuntimeError(
                "InsightVM Cloud API not configured. Set RAPID7_API_KEY "
                "(optional RAPID7_CLOUD_API_BASE)."
            )
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Api-Key": self.cfg["api_key"],
        })
        self.session.verify = self.cfg.get("verify_ssl", True)

    def _url(self, path: str) -> str:
        return urljoin(self.cfg["cloud_api_base_url"] + "/", path.lstrip("/"))

    def search_assets_with_vulns(self) -> list[dict]:
        """
        POST /vm/v4/integration/assets
        Query Builder syntax: && / || ; severity IN ['Critical','Severe']
        """
        sev = self.cfg.get("min_severity") or "high"
        if sev == "critical":
            vuln_q = "severity IN ['Critical']"
        elif sev == "high":
            vuln_q = "severity IN ['Critical', 'Severe']"
        elif sev == "medium":
            vuln_q = "severity IN ['Critical', 'Severe', 'Moderate']"
        else:
            vuln_q = "severity IN ['Critical', 'Severe', 'Moderate', 'Low']"

        asset_parts = []
        host = self.cfg.get("asset_hostname_contains") or ""
        if host:
            asset_parts.append(f"asset.name CONTAINS '{host}'")
        asset_q = " && ".join(asset_parts) if asset_parts else None

        body: dict[str, Any] = {"vulnerability": vuln_q}
        if asset_q:
            body["asset"] = asset_q

        page_size = min(self.cfg["page_size"], 500)
        max_assets = self.cfg["max_assets"]
        assets: list[dict] = []
        cursor = None
        while len(assets) < max_assets:
            params = {"size": page_size}
            if cursor:
                params["cursor"] = cursor
            resp = self.session.post(
                self._url("/vm/v4/integration/assets"),
                json=body,
                params=params,
                timeout=90,
            )
            resp.raise_for_status()
            data = resp.json() if resp.content else {}
            batch = data.get("data") or data.get("resources") or []
            if not batch:
                break
            assets.extend(batch)
            cursor = (data.get("metadata") or {}).get("cursor") or data.get("cursor")
            if not cursor:
                break
        return assets[:max_assets]


def _asset_hostname(asset: dict) -> str:
    return (
        asset.get("hostName")
        or asset.get("host_name")
        or asset.get("hostname")
        or (asset.get("host_names") or [None])[0]
        or asset.get("unique_identifier")
        or ""
    )


def _asset_ip(asset: dict) -> str:
    return (
        asset.get("ip")
        or asset.get("ip_address")
        or ((asset.get("addresses") or [{}])[0] or {}).get("ip")
        or ""
    )


def _vuln_meta_to_finding(asset: dict, finding_stub: dict, meta: dict, cfg: dict) -> dict:
    vuln_id = (
        finding_stub.get("id")
        or finding_stub.get("vulnerability_id")
        or meta.get("id")
        or ""
    )
    title = meta.get("title") or meta.get("vulnerability_title") or str(vuln_id)
    severity_raw = meta.get("severity") or finding_stub.get("severity") or ""
    cvss = None
    scores = meta.get("cvss") or {}
    if isinstance(scores, dict):
        v3 = scores.get("v3") or scores.get("v3_score") or {}
        if isinstance(v3, dict):
            cvss = v3.get("score")
        if cvss is None:
            v2 = scores.get("v2") or {}
            if isinstance(v2, dict):
                cvss = v2.get("score")
    if cvss is None:
        cvss = meta.get("cvss_score") or meta.get("cvssV3") 

    cves = []
    for cve in meta.get("cves") or meta.get("cve_ids") or []:
        if isinstance(cve, str):
            cves.append(cve.upper())
        elif isinstance(cve, dict) and cve.get("id"):
            cves.append(str(cve["id"]).upper())

    hostname = _asset_hostname(asset)
    asset_ip = _asset_ip(asset)
    solution = None
    if cfg.get("include_solution"):
        sol = meta.get("solution") or meta.get("remediation") or {}
        if isinstance(sol, dict):
            solution = sol.get("summary") or sol.get("steps")
        else:
            solution = sol
    description = None
    if cfg.get("include_description"):
        description = meta.get("description")
        if isinstance(description, dict):
            description = description.get("text") or description.get("html")

    return {
        "asset_ip": asset_ip or None,
        "hostname": hostname or None,
        "domain": rapid7_import.extract_domain(hostname, asset_ip),
        "title": title,
        "severity": rapid7_import.normalize_severity(str(severity_raw), float(cvss) if cvss is not None else None),
        "cvss": float(cvss) if cvss is not None else None,
        "cves": sorted(set(cves)),
        "solution": (str(solution)[:2000] if solution else None),
        "description": (str(description)[:500] if description else None),
        "port": None,
        "protocol": None,
        "vuln_id": str(vuln_id) if vuln_id else None,
        "result_code": finding_stub.get("status") or finding_stub.get("resultCode"),
        "exploit": None,
        "asset_id": str(asset.get("id") or asset.get("asset_id") or ""),
        "raw": {
            "asset_id": asset.get("id"),
            "vuln_id": vuln_id,
            "source": "insightvm_console_api",
        },
    }


def sync_from_console_api(cfg: dict | None = None) -> dict:
    """Lean Console API sync: filtered assets → capped findings → normalized list."""
    cfg = cfg or config()
    client = InsightVMClient(cfg)
    assets = client.search_assets()
    findings: list[dict] = []
    vuln_cache: dict[str, dict] = {}
    errors: list[str] = []
    assets_processed = 0

    for asset in assets:
        assets_processed += 1
        asset_id = asset.get("id")
        if asset_id is None:
            continue
        try:
            stubs = client.asset_vulnerabilities(asset_id)
        except Exception as exc:
            errors.append(f"asset {asset_id}: {exc}")
            continue
        for stub in stubs:
            vid = stub.get("id") or stub.get("vulnerability_id")
            if not vid:
                continue
            # Skip exceptions / invulnerable if status present
            status = (stub.get("status") or "").lower()
            if status in {"exception", "invulnerable", "false-positive"}:
                continue
            if vid not in vuln_cache:
                try:
                    vuln_cache[vid] = client.get_vulnerability(vid)
                except Exception as exc:
                    errors.append(f"vuln {vid}: {exc}")
                    vuln_cache[vid] = {"id": vid, "title": str(vid)}
            meta = vuln_cache[vid]
            sev = rapid7_import.normalize_severity(
                str(meta.get("severity") or ""),
                None,
            )
            rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            min_sev = cfg.get("min_severity") or "high"
            if rank.get(sev, 99) > rank.get(min_sev, 1):
                continue
            findings.append(_vuln_meta_to_finding(asset, stub, meta, cfg))
            if len(findings) >= cfg.get("max_rows", 50000):
                break
        if len(findings) >= cfg.get("max_rows", 50000):
            break

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    return {
        "source_format": "console_api",
        "assets_matched": len(assets),
        "assets_processed": assets_processed,
        "findings": findings,
        "summary": {
            "by_severity": by_sev,
            "assets": len(assets),
            "findings": len(findings),
            "with_cve": sum(1 for f in findings if f.get("cves")),
            "vuln_definitions_fetched": len(vuln_cache),
        },
        "warnings": errors[:50],
        "header_map": {"source": "insightvm_console_api"},
        "row_count": len(findings),
    }


def sync_from_cloud_api(cfg: dict | None = None) -> dict:
    """Lean Cloud Integrations API sync."""
    cfg = cfg or config()
    client = InsightVMCloudClient(cfg)
    assets = client.search_assets_with_vulns()
    findings: list[dict] = []
    errors: list[str] = []

    for asset in assets:
        hostname = _asset_hostname(asset) or asset.get("host_name") or ""
        asset_ip = _asset_ip(asset)
        vulns = asset.get("same") or asset.get("new") or asset.get("vulnerabilities") or []
        if isinstance(vulns, dict):
            vulns = vulns.get("vulnerabilities") or vulns.get("list") or []
        count = 0
        for v in vulns:
            if count >= cfg["max_findings_per_asset"]:
                break
            if not isinstance(v, dict):
                continue
            title = v.get("title") or v.get("vulnerability_title") or v.get("id") or "Vulnerability"
            severity = rapid7_import.normalize_severity(str(v.get("severity") or ""), None)
            rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            if rank.get(severity, 99) > rank.get(cfg.get("min_severity") or "high", 1):
                continue
            cves = []
            for cve in v.get("cves") or []:
                if isinstance(cve, str):
                    cves.append(cve.upper())
            findings.append({
                "asset_ip": asset_ip or None,
                "hostname": hostname or None,
                "domain": rapid7_import.extract_domain(hostname, asset_ip),
                "title": title,
                "severity": severity,
                "cvss": v.get("cvss_v3_score") or v.get("cvss_score"),
                "cves": sorted(set(cves)),
                "solution": (str(v.get("solution") or "")[:2000] or None) if cfg.get("include_solution") else None,
                "description": None,
                "port": None,
                "protocol": None,
                "vuln_id": str(v.get("id") or v.get("vulnerability_id") or "") or None,
                "result_code": None,
                "exploit": None,
                "asset_id": str(asset.get("id") or ""),
                "raw": {"source": "insightvm_cloud_api", "asset_id": asset.get("id")},
            })
            count += 1
            if len(findings) >= cfg.get("max_rows", 50000):
                break
        if len(findings) >= cfg.get("max_rows", 50000):
            break

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    return {
        "source_format": "cloud_api",
        "assets_matched": len(assets),
        "assets_processed": len(assets),
        "findings": findings,
        "summary": {
            "by_severity": by_sev,
            "assets": len(assets),
            "findings": len(findings),
            "with_cve": sum(1 for f in findings if f.get("cves")),
        },
        "warnings": errors,
        "header_map": {"source": "insightvm_cloud_api"},
        "row_count": len(findings),
    }


def lean_filter_findings(findings: list[dict], cfg: dict | None = None, *, severity_key: str = "min_severity") -> list[dict]:
    """Strip bulky fields and apply severity floor (for file imports too)."""
    cfg = cfg or config()
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_sev = cfg.get(severity_key) or cfg.get("min_severity") or "high"
    threshold = rank.get(min_sev, 1)
    out = []
    for f in findings:
        if rank.get(f.get("severity"), 99) > threshold:
            continue
        item = dict(f)
        if not cfg.get("include_description"):
            item["description"] = None
        if not cfg.get("include_proof") and isinstance(item.get("raw"), dict):
            item["raw"] = {
                k: v for k, v in item["raw"].items()
                if k.lower() not in {"proof", "vulnerability proof", "details", "scan_data"}
            }
        if not cfg.get("include_solution"):
            item["solution"] = None
        elif item.get("solution"):
            item["solution"] = str(item["solution"])[:2000]
        out.append(item)
        if len(out) >= int(cfg.get("max_rows") or 50000):
            break
    return out
