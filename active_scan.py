"""
DomainLens — Active web application vulnerability scan.

Unlike every other check in DomainLens, this one sends deliberately crafted
test input to the target application (reflected-XSS probes, open-redirect
probes, error-based SQL-injection probes). That is appropriate ONLY against
systems you own or are explicitly authorized to test — never a third party's
site just because you can resolve its domain.

Safety design (mirrors weak_auth.py):
  - Disabled by default (active_scan.enabled).
  - A single hard, scan-wide request ceiling (max_requests_per_scan) that
    bounds every request this module makes, not just per-parameter.
  - Crawl is same-origin only and capped to a handful of pages.
  - No actual script execution, no boolean/time-based SQLi (only the
    lowest-side-effect error-based check), no destructive payloads.
"""

import concurrent.futures
import ipaddress
import re
import secrets
import socket
import time
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

import requests

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 DomainLens-ActiveScan"
)

_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]

# Parameter names commonly used for client-controlled redirects — tested even
# if not observed on a discovered link, since they're frequently only present
# in server-side routes not linked from the homepage.
_COMMON_REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
    "returnurl", "return_url", "continue", "dest", "destination", "target",
    "out", "view", "r", "goto", "forward",
]

_SQL_ERROR_SIGNATURES = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysqli?_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"microsoft sql native client", re.I),
    re.compile(r"odbc sql server driver", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"postgresql.*syntax error", re.I),
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"sqlite3?\.(operationalerror|programmingerror)", re.I),
    re.compile(r"sqlite_error", re.I),
    re.compile(r'near ".*": syntax error', re.I),
    re.compile(r"syntax error at or near", re.I),
    re.compile(r"unterminated quoted string", re.I),
]


def _is_private_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


def _safe_host(host):
    try:
        ip = socket.gethostbyname(host)
        return not _is_private_ip(ip)
    except Exception:
        return False


def _get(url, timeout, allow_redirects=False, params=None):
    return requests.get(
        url, timeout=timeout, allow_redirects=allow_redirects,
        params=params, headers={"User-Agent": _UA, "Accept": "*/*"},
    )


# ---------------------------------------------------------------------------
# Target discovery — same-origin only, bounded
# ---------------------------------------------------------------------------

def _discover(base_url, html, origin_netloc, max_pages, timeout):
    """Crawl a handful of same-origin pages and collect URLs with query params."""
    visited = {base_url}
    to_visit = []
    targets = []  # list of {"url": ..., "param": ...}

    def _collect_params(page_url):
        parsed = urlparse(page_url)
        for name, _ in parse_qsl(parsed.query):
            targets.append({"url": page_url, "param": name})

    def _collect_links(page_html, page_url):
        found = []
        for m in re.finditer(r'href=["\']([^"\']+)["\']', page_html, re.I):
            href = m.group(1)
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            abs_url = urljoin(page_url, href)
            if urlparse(abs_url).netloc.lower() == origin_netloc:
                found.append(abs_url.split("#")[0])
        return found

    _collect_params(base_url)
    for link in _collect_links(html, base_url):
        if link not in visited and "?" in link:
            _collect_params(link)
            visited.add(link)
        elif link not in visited:
            to_visit.append(link)

    pages_fetched = 0
    for link in to_visit:
        if pages_fetched >= max_pages or link in visited:
            continue
        visited.add(link)
        try:
            resp = _get(link, timeout)
            pages_fetched += 1
            if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", ""):
                _collect_params(resp.url)
                for sub in _collect_links(resp.text, resp.url):
                    if sub not in visited and "?" in sub:
                        _collect_params(sub)
                        visited.add(sub)
        except Exception:
            continue

    # Dedupe (url, param)
    seen = set()
    deduped = []
    for t in targets:
        key = (t["url"], t["param"])
        if key not in seen:
            seen.add(key)
            deduped.append(t)
    return deduped


def _set_param(url, param, value):
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query))
    q[param] = value
    return urlunparse(parsed._replace(query=urlencode(q)))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_xss(url, param, timeout):
    token = secrets.token_hex(4)
    marker = f"<svg onload=npx{token}>"
    test_url = _set_param(url, param, f'"\'{marker}')
    try:
        resp = _get(test_url, timeout, allow_redirects=True)
    except Exception:
        return None
    if marker in (resp.text or ""):
        return {
            "type": "reflected_xss",
            "url": url,
            "param": param,
            "evidence": f"Unescaped marker `{marker}` reflected verbatim in the response body.",
        }
    return None


def _probe_open_redirect(url, param, timeout):
    test_target = "https://domainlens-redirect-check.invalid/landing"
    test_url = _set_param(url, param, test_target)
    try:
        resp = _get(test_url, timeout, allow_redirects=False)
    except Exception:
        return None
    location = resp.headers.get("Location", "")
    if resp.status_code in (301, 302, 303, 307, 308) and "domainlens-redirect-check.invalid" in location:
        return {
            "type": "open_redirect",
            "url": url,
            "param": param,
            "evidence": f"HTTP {resp.status_code} redirected to attacker-controlled "
                        f"value: {location}",
        }
    # Some apps redirect client-side via JS/meta-refresh instead of a Location header.
    body = (resp.text or "")[:4000]
    if "domainlens-redirect-check.invalid" in body and (
        "meta" in body.lower() and "refresh" in body.lower()
        or "location.href" in body or "location.replace" in body
    ):
        return {
            "type": "open_redirect",
            "url": url,
            "param": param,
            "evidence": "Attacker-controlled value reflected into a client-side "
                        "redirect (meta-refresh or location.href).",
        }
    return None


def _probe_sqli_error(url, param, timeout):
    test_url = _set_param(url, param, "domainlens'\"")
    try:
        resp = _get(test_url, timeout, allow_redirects=True)
    except Exception:
        return None
    body = resp.text or ""
    for sig in _SQL_ERROR_SIGNATURES:
        m = sig.search(body)
        if m:
            return {
                "type": "sqli_error_based",
                "url": url,
                "param": param,
                "evidence": f"Database error signature triggered by a single-quote "
                            f"probe: \"{m.group(0)[:120]}\"",
            }
    return None


_PROBES = (_probe_xss, _probe_open_redirect, _probe_sqli_error)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def scan(domain, settings):
    """Active vulnerability probe. Requires active_scan.enabled=true.

    settings keys: enabled, max_requests_per_scan, max_pages_crawled,
    delay_seconds, timeout_seconds, include_http, extra_params.
    """
    if not settings.get("enabled"):
        return {
            "success": True,
            "skipped": True,
            "enabled": False,
            "detail": (
                "Active scanning is disabled. Enable active_scan.enabled in "
                "config only for systems you own or are explicitly authorized "
                "to test — this check sends live XSS/redirect/SQLi probes."
            ),
        }

    if not _safe_host(domain):
        return {"success": False, "enabled": True, "error": "Host does not resolve to a public address"}

    timeout = int(settings.get("timeout_seconds", 8))
    delay = float(settings.get("delay_seconds", 0.25))
    max_requests = max(1, int(settings.get("max_requests_per_scan", 40)))
    max_pages = max(0, int(settings.get("max_pages_crawled", 5)))
    schemes = ["https"] + (["http"] if settings.get("include_http", True) else [])

    base_url = None
    html = ""
    for scheme in schemes:
        try:
            resp = _get(f"{scheme}://{domain}/", timeout, allow_redirects=True)
            base_url = resp.url
            html = resp.text or ""
            break
        except Exception:
            continue
    if not base_url:
        return {"success": False, "enabled": True, "error": "No HTTP response from target"}

    origin_netloc = urlparse(base_url).netloc.lower()
    targets = _discover(base_url, html, origin_netloc, max_pages, timeout)

    # Always also test common redirect-param names directly on the base URL,
    # even if none were observed on a crawled link (many apps only expose
    # these on routes that aren't linked from the homepage).
    extra_params = list(settings.get("extra_params") or []) or _COMMON_REDIRECT_PARAMS
    for p in extra_params:
        targets.append({"url": base_url, "param": p})

    # Dedupe again after adding extras
    seen = set()
    deduped_targets = []
    for t in targets:
        key = (t["url"], t["param"])
        if key not in seen:
            seen.add(key)
            deduped_targets.append(t)
    targets = deduped_targets

    findings = []
    attempts = 0
    capped = False
    pages_tested = set()

    for target in targets:
        if attempts >= max_requests:
            capped = True
            break
        pages_tested.add(target["url"])
        for probe in _PROBES:
            if attempts >= max_requests:
                capped = True
                break
            attempts += 1
            try:
                hit = probe(target["url"], target["param"], timeout)
            except Exception:
                hit = None
            if hit:
                findings.append(hit)
            if delay > 0:
                time.sleep(delay)

    detail = (
        f"Sent {attempts} test request(s) across {len(pages_tested)} URL(s) / "
        f"{len(targets)} parameter target(s)."
    )
    if capped:
        detail += f" Stopped at the max_requests_per_scan ceiling ({max_requests})."
    if not targets:
        detail = "No query-string parameters or forms discovered to test."

    return {
        "success": True,
        "enabled": True,
        "base_url": base_url,
        "targets_discovered": len(targets),
        "pages_crawled": len(pages_tested),
        "attempts": attempts,
        "max_requests": max_requests,
        "capped": capped,
        "findings": findings,
        "vulnerabilities_found": len(findings) > 0,
        "detail": detail,
    }


_SEVERITY_BY_TYPE = {
    # These probes find reflection/error signatures, not executable script
    # context or confirmed query manipulation. Escalate only after validation.
    "reflected_xss": "medium",
    "sqli_error_based": "medium",
    "open_redirect": "medium",
}

_TITLE_BY_TYPE = {
    "reflected_xss": "Reflected XSS in parameter '{param}'",
    "sqli_error_based": "Possible SQL injection in parameter '{param}'",
    "open_redirect": "Open redirect via parameter '{param}'",
}

_FIX_BY_TYPE = {
    "reflected_xss": (
        "Output-encode all user-controlled data before writing it into HTML "
        "(context-aware encoding), and set a strict Content-Security-Policy "
        "as defense in depth."
    ),
    "sqli_error_based": (
        "Use parameterized queries / prepared statements everywhere user input "
        "reaches SQL. Never build queries via string concatenation. Disable "
        "verbose DB error output in production."
    ),
    "open_redirect": (
        "Validate redirect targets against an allowlist of known-safe paths/"
        "hosts instead of redirecting to an arbitrary user-supplied URL."
    ),
}


def findings_from_scan(scan_result):
    """Turn a scan() result into severity-graded findings for Advies/reports."""
    out = []
    if not scan_result or not scan_result.get("success") or not scan_result.get("enabled"):
        return out
    for hit in scan_result.get("findings", []):
        t = hit["type"]
        out.append({
            "severity": _SEVERITY_BY_TYPE.get(t, "medium"),
            "category": "Active Vulnerability Scan",
            "title": _TITLE_BY_TYPE.get(t, "Vulnerability found").format(param=hit["param"]),
            "detail": hit["evidence"],
            "evidence": f"{hit['url']} (param: {hit['param']})",
            "fix": _FIX_BY_TYPE.get(t, "Review and remediate this finding."),
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda f: order.get(f["severity"], 9))
    return out
