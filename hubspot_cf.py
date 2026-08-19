"""
HubSpot-behind-Cloudflare exposure and misconfiguration scanner.

Detects HubSpot CMS/tracking assets when Cloudflare sits in front, then
flags practical remediation items (consent, headers, forms, WAF friction).
"""

from __future__ import annotations

import re
import socket

import dns.resolver
import requests

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_HUBSPOT_HOST_RE = re.compile(
    r"(?:^|[./])("
    r"js\.hs-scripts\.com|"
    r"js\.hs-analytics\.net|"
    r"js\.hscollectedforms\.net|"
    r"js\.hsadspixel\.net|"
    r"js\.hs-banner\.com|"
    r"js\.hubspotfeedback\.com|"
    r"forms(?:-eu1)?\.hsforms\.com|"
    r"(?:api(?:-eu1)?\.)?hubapi\.com|"
    r"track\.hubspot\.com|"
    r"cta-redirect\.hubspot\.com|"
    r"[a-z0-9.-]*hs-sites(?:-eu1)?\.com|"
    r"[a-z0-9.-]*hubspotusercontent[a-z0-9.-]*\.net|"
    r"[a-z0-9.-]*hubspot\.com"
    r")(?:/|$)",
    re.I,
)

_PORTAL_RE = re.compile(r"js\.hs-scripts\.com/(\d+)\.js", re.I)
_HS_COOKIE_RE = re.compile(
    r"(?:^|;\s*)(__hstc|__hssc|__hssrc|hubspotutk|messagesUtk|_hs_opt_out|__hs_do_not_track)\s*=",
    re.I,
)
_CF_COOKIE_RE = re.compile(r"(?:^|;\s*)(__cf_bm|cf_clearance|__cfuvid|__cfruid)\s*=", re.I)

_CF_NET_HINTS = ("cf-ray", "cf-cache-status", "cf-ipcountry")


def _safe_error(exc):
    text = str(exc)
    return text[:300] if len(text) > 300 else text


def _cname_chain(domain):
    chain = []
    current = domain
    for _ in range(10):
        try:
            answers = dns.resolver.resolve(current, "CNAME")
            target = answers[0].to_text().rstrip(".")
            chain.append(target)
            current = target
        except Exception:
            break
    return chain


def _collect_cookies(resp):
    raw = []
    if hasattr(resp.headers, "getlist"):
        raw.extend(resp.headers.getlist("Set-Cookie") or [])
    single = resp.headers.get("Set-Cookie")
    if single:
        raw.append(single)
    joined = "; ".join(raw)
    return raw, joined


def _detect_cloudflare(headers_lc, cookie_blob, resolved_ip=None):
    evidence = []
    if "cf-ray" in headers_lc:
        evidence.append(f"cf-ray={headers_lc.get('cf-ray')}")
    if headers_lc.get("server", "").lower() == "cloudflare":
        evidence.append("server=cloudflare")
    for hint in _CF_NET_HINTS:
        if hint in headers_lc and hint != "cf-ray":
            evidence.append(f"{hint}={headers_lc.get(hint)}")
    if _CF_COOKIE_RE.search(cookie_blob or ""):
        evidence.append("cloudflare cookies present")
    return {
        "detected": bool(evidence),
        "confidence": "high" if ("cf-ray" in headers_lc or evidence) else "none",
        "evidence": evidence,
    }


def _detect_hubspot(headers_lc, cookie_blob, body, cname_chain):
    evidence = []
    assets = []
    portal_ids = set()

    for cname in cname_chain or []:
        if _HUBSPOT_HOST_RE.search(cname):
            evidence.append(f"cname={cname}")

    for match in _HUBSPOT_HOST_RE.finditer(body or ""):
        host = match.group(1).lower()
        assets.append(host)
        evidence.append(f"asset={host}")

    for match in _PORTAL_RE.finditer(body or ""):
        portal_ids.add(match.group(1))

    cookie_hits = _HS_COOKIE_RE.findall(cookie_blob or "")
    for name in cookie_hits:
        evidence.append(f"cookie={name}")

    # HubSpot HTML markers
    markers = (
        "hs-script-loader",
        "hs-cta-",
        "data-hs-",
        "HubSpotConversations",
        "hsConversationsSettings",
        "generator\" content=\"HubSpot",
    )
    for marker in markers:
        if marker.lower() in (body or "").lower():
            evidence.append(f"html={marker}")

    # Deduplicate while preserving order
    seen = set()
    uniq_evidence = []
    for item in evidence:
        if item not in seen:
            seen.add(item)
            uniq_evidence.append(item)

    return {
        "detected": bool(uniq_evidence),
        "confidence": "high" if (portal_ids or cookie_hits or assets) else ("medium" if uniq_evidence else "none"),
        "evidence": uniq_evidence[:40],
        "assets": sorted(set(assets))[:30],
        "portal_ids": sorted(portal_ids),
        "cookies": sorted(set(cookie_hits)),
        "consent_banner_script": "js.hs-banner.com" in (body or "").lower(),
        "forms_script": "hsforms.com" in (body or "").lower() or "hscollectedforms" in (body or "").lower(),
        "conversations": "HubSpotConversations".lower() in (body or "").lower(),
    }


def _probe_paths(domain, headers_lc):
    """Probe a few HubSpot/CF-sensitive paths for exposure signals."""
    findings = []
    paths = [
        "/_hcms/",
        "/hs/manage-cookies/",
        "/_hcms/performance",
    ]
    for path in paths:
        url = f"https://{domain}{path}"
        try:
            resp = requests.get(
                url,
                timeout=8,
                allow_redirects=True,
                headers={"User-Agent": _BROWSER_UA, "Accept": "text/html,*/*"},
            )
            body = (resp.text or "")[:2000].lower()
            item = {
                "path": path,
                "status": resp.status_code,
                "final_url": resp.url,
                "cloudflare": "cf-ray" in {k.lower() for k in resp.headers.keys()},
            }
            if path == "/_hcms/" and resp.status_code < 500:
                item["note"] = "HubSpot CMS path responded"
            if "captcha" in body or "cf-browser-verification" in body or "attention required" in body:
                item["challenge"] = True
            findings.append(item)
        except Exception as exc:
            findings.append({"path": path, "error": _safe_error(exc)})
    return findings


def _build_findings(cf, hs, headers_lc, path_probes, final_status):
    findings = []

    if hs["detected"] and cf["detected"]:
        findings.append({
            "id": "hubspot_behind_cloudflare",
            "severity": "info",
            "title": "HubSpot detected behind Cloudflare",
            "problem": "The site serves HubSpot assets/cookies while Cloudflare edge headers are present.",
            "fix": "Treat Cloudflare as the security edge and HubSpot as the app/CMS layer. Align WAF allowlists for HubSpot forms, webhooks, and tracking callbacks.",
            "reference": "https://knowledge.hubspot.com/domains-and-urls/ssl-and-domain-security-in-hubspot",
        })

    if hs["detected"] and not cf["detected"]:
        findings.append({
            "id": "hubspot_without_cloudflare",
            "severity": "medium",
            "title": "HubSpot present without Cloudflare edge signals",
            "problem": "HubSpot fingerprints were found, but Cloudflare edge markers were not. Origin exposure or incomplete CDN onboarding is possible.",
            "fix": "Confirm DNS is orange-clouded (proxied) in Cloudflare, or enable HubSpot/Cloudflare recommended SSL mode (Full/Strict) for the connected domain.",
            "reference": "https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/",
        })

    if hs["detected"] and hs["cookies"] and not hs["consent_banner_script"]:
        findings.append({
            "id": "hubspot_tracking_without_banner",
            "severity": "high",
            "title": "HubSpot tracking cookies without consent banner script",
            "problem": f"HubSpot cookies seen ({', '.join(hs['cookies'])}) but js.hs-banner.com was not loaded.",
            "fix": "Enable the HubSpot cookie consent banner (or your CMP) and block non-essential HubSpot cookies until consent is granted.",
            "reference": "https://knowledge.hubspot.com/privacy-and-consent/hubspot-cookie-security-and-privacy",
        })

    if hs["detected"] and not headers_lc.get("content-security-policy"):
        findings.append({
            "id": "hubspot_missing_csp",
            "severity": "medium",
            "title": "HubSpot site missing Content-Security-Policy",
            "problem": "HubSpot assets are loaded without a CSP. XSS impact is higher on marketing CMS pages with forms and chat widgets.",
            "fix": "In HubSpot domain security settings, enable CSP (or set it at Cloudflare) allowing only required HubSpot hosts such as *.hs-scripts.com and *.hsforms.com.",
            "reference": "https://knowledge.hubspot.com/domains-and-urls/ssl-and-domain-security-in-hubspot",
        })

    if hs["detected"] and not headers_lc.get("strict-transport-security"):
        findings.append({
            "id": "hubspot_missing_hsts",
            "severity": "medium",
            "title": "HubSpot domain missing HSTS",
            "problem": "No Strict-Transport-Security header on a HubSpot-powered domain.",
            "fix": "Enable HSTS in HubSpot domain security settings and/or Cloudflare edge rules (max-age >= 31536000).",
            "reference": "https://knowledge.hubspot.com/domains-and-urls/ssl-and-domain-security-in-hubspot",
        })

    if hs["portal_ids"]:
        findings.append({
            "id": "hubspot_portal_id_exposed",
            "severity": "info",
            "title": "HubSpot portal ID is public",
            "problem": f"Portal ID(s) visible in page scripts: {', '.join(hs['portal_ids'])}.",
            "fix": "Expected for HubSpot tracking, but lock down form submissions, CORS, and rate limits. Review public forms for spam/abuse.",
        })

    if hs["forms_script"] and cf["detected"]:
        findings.append({
            "id": "hubspot_forms_behind_cf",
            "severity": "low",
            "title": "HubSpot forms behind Cloudflare",
            "problem": "HubSpot forms/scripts are loaded through a Cloudflare-protected site.",
            "fix": "Allow HubSpot form/API endpoints in Cloudflare WAF and Bot Fight Mode exclusions if legitimate submissions are blocked (check Security → Events).",
            "reference": "https://developers.cloudflare.com/waf/",
        })

    challenged = [p for p in path_probes if p.get("challenge")]
    if challenged and hs["detected"]:
        findings.append({
            "id": "cloudflare_challenge_hubspot_paths",
            "severity": "medium",
            "title": "Cloudflare challenge on HubSpot-related paths",
            "problem": "Cloudflare browser/challenge pages were observed on HubSpot CMS or consent paths.",
            "fix": "Create Cloudflare WAF/skip rules for HubSpot operational paths (/_hcms/, cookie management, form callbacks) used by trusted automation and editors.",
        })

    hcms = next((p for p in path_probes if p.get("path") == "/_hcms/" and isinstance(p.get("status"), int)), None)
    if hcms and hcms.get("status") in (200, 301, 302, 401, 403):
        findings.append({
            "id": "hubspot_hcms_path_exposed",
            "severity": "low",
            "title": "HubSpot CMS management path responds publicly",
            "problem": f"/_hcms/ returned HTTP {hcms.get('status')}.",
            "fix": "Ensure only intended CMS routes are public. Restrict editor/admin surfaces with Cloudflare Access or HubSpot permissions.",
        })

    if final_status in (401, 403) and cf["detected"] and hs["detected"]:
        findings.append({
            "id": "cf_blocks_hubspot_origin",
            "severity": "high",
            "title": "Cloudflare returned access denial on HubSpot site",
            "problem": f"Final HTTP status {final_status} with both Cloudflare and HubSpot signals present.",
            "fix": "Inspect Cloudflare Security Events and HubSpot domain SSL mode. False-positive WAF rules commonly break HubSpot pages, chat, and forms.",
        })

    return findings


def scan_hubspot_cloudflare(domain):
    """Run HubSpot + Cloudflare detection and return remediation findings."""
    result = {
        "success": False,
        "domain": domain,
        "cloudflare": {"detected": False},
        "hubspot": {"detected": False},
        "behind_cloudflare": False,
        "findings": [],
        "path_probes": [],
        "final_status": None,
        "final_url": None,
    }

    cname_chain = _cname_chain(domain)
    result["cname_chain"] = cname_chain

    try:
        resolved_ip = socket.gethostbyname(domain)
        result["resolved_ip"] = resolved_ip
    except Exception:
        resolved_ip = None

    resp = None
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=12,
                allow_redirects=True,
                headers={
                    "User-Agent": _BROWSER_UA,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )
            break
        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue

    if resp is None:
        result["error"] = "Could not fetch site content"
        return result

    headers_lc = {k.lower(): v for k, v in resp.headers.items()}
    cookies_raw, cookie_blob = _collect_cookies(resp)
    try:
        body = resp.text[:120000]
    except Exception:
        body = ""

    cf = _detect_cloudflare(headers_lc, cookie_blob, resolved_ip)
    hs = _detect_hubspot(headers_lc, cookie_blob, body, cname_chain)
    path_probes = _probe_paths(domain, headers_lc) if (hs["detected"] or cf["detected"]) else []
    findings = _build_findings(cf, hs, headers_lc, path_probes, resp.status_code)

    result.update({
        "success": True,
        "cloudflare": cf,
        "hubspot": hs,
        "behind_cloudflare": bool(hs["detected"] and cf["detected"]),
        "findings": findings,
        "path_probes": path_probes,
        "final_status": resp.status_code,
        "final_url": resp.url,
        "cookies_seen": sorted(set(hs.get("cookies") or []) | set(_CF_COOKIE_RE.findall(cookie_blob or ""))),
        "pass": not any(f.get("severity") in ("critical", "high") for f in findings),
    })
    return result
