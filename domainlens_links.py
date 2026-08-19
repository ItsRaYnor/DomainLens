"""Build public DomainLens URLs for ServiceNow → tool deep links."""

from __future__ import annotations

import os
from urllib.parse import quote


def public_base_url() -> str:
    """
    Absolute base URL of this DomainLens instance.

    Prefer DOMAINLENS_PUBLIC_URL (e.g. https://domainlens.example.com).
    Falls back to settings general.public_url.
    """
    env = (os.environ.get("DOMAINLENS_PUBLIC_URL") or os.environ.get("DOMAINLENS_BASE_URL") or "").strip().rstrip("/")
    if env:
        return env
    try:
        from settings.store import get_store
        raw = get_store().section("general", force_reload=True)
        configured = (raw.get("public_url") or "").strip().rstrip("/")
        if configured:
            return configured
    except Exception:
        pass
    return ""


def _join(base: str, path: str) -> str:
    base = (base or "").rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    if not base:
        return path
    return f"{base}{path}"


def vuln_remediation_url(finding_id, *, base: str | None = None) -> str:
    """Deep link for a stored Rapid7/InsightVM finding (PO landing page)."""
    return _join(base if base is not None else public_base_url(), f"/remediate/vuln/{int(finding_id)}")


def domain_remediation_url(domain: str, *, base: str | None = None) -> str:
    """Deep link to run/open Advies for a domain."""
    d = (domain or "").strip().lower()
    return _join(base if base is not None else public_base_url(), f"/remediate/domain/{quote(d, safe='')}")


def scan_report_url(scan_id, *, base: str | None = None) -> str:
    return _join(base if base is not None else public_base_url(), f"/report/{int(scan_id)}")


def monitor_url(monitor_id=None, *, base: str | None = None) -> str:
    path = "/"
    if monitor_id:
        path = f"/?monitor={int(monitor_id)}"
    return _join(base if base is not None else public_base_url(), path)


def finding_link_block(finding: dict, *, base: str | None = None) -> dict:
    """
    URLs + short text block to embed on ServiceNow VI / incident.

    Returns keys: domainlens_url, domain_url, text (multiline for description/work_notes).
    """
    base = base if base is not None else public_base_url()
    finding_id = finding.get("id")
    domain = (finding.get("domain") or finding.get("hostname") or "").strip().lower()
    domainlens_url = vuln_remediation_url(finding_id, base=base) if finding_id else None
    domain_url = domain_remediation_url(domain, base=base) if domain else None

    lines = [
        "--- DomainLens remediation ---",
        "Ownership and assignment stay in ServiceNow; use DomainLens to see fix steps and retest.",
    ]
    if domainlens_url:
        lines.append(f"Open finding in DomainLens: {domainlens_url}")
    if domain_url and domain_url != domainlens_url:
        lines.append(f"Domain Advies / retest: {domain_url}")
    if not domainlens_url and not domain_url:
        lines.append(
            "Set DOMAINLENS_PUBLIC_URL (or Settings → General → Public URL) "
            "so ServiceNow records link back to DomainLens."
        )
    title = finding.get("title")
    if title:
        lines.append(f"Finding: {title}")
    sev = finding.get("severity")
    if sev:
        lines.append(f"Severity: {sev}")

    return {
        "domainlens_url": domainlens_url,
        "domain_url": domain_url,
        "text": "\n".join(lines),
        "public_base_configured": bool(base),
    }
