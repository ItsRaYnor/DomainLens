"""
DomainLens — Client-side JavaScript security scan.

Passive, always-safe: fetches the page and its same-origin/CDN <script src>
files (no execution, no active probing) and checks for:
  1. Known-vulnerable JS library versions (small curated CVE database)
  2. Hardcoded secrets/API keys accidentally shipped in client-side bundles
  3. Missing Subresource Integrity (SRI) on third-party <script>/<link> tags

This never sends anything to the target beyond ordinary GET requests, so it
is safe to run against any domain — unlike the active_scan / weak_auth checks.
"""

import concurrent.futures
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import requests

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]

_MAX_SCRIPTS = 25
_MAX_SCRIPT_BYTES = 2_000_000  # 2 MB cap per file
_TIMEOUT = 8


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


# ---------------------------------------------------------------------------
# Known-vulnerable JS library signatures
# ---------------------------------------------------------------------------
# Small, hand-curated set of widely-deployed libraries with well-known CVEs.
# Not exhaustive (a full feed like Retire.js/OSV would need external data),
# but covers the versions most commonly still found in the wild.

def _ver_tuple(v):
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:4]) if parts else (0,)


def _ver_lt(a, b):
    return _ver_tuple(a) < _ver_tuple(b)


def _ver_lte(a, b):
    return _ver_tuple(a) <= _ver_tuple(b)


# Each rule: (name, filename/content regex to find version, max_vulnerable_version
# (inclusive), CVE ids, summary)
_VULN_LIBRARIES = [
    {
        "name": "jQuery",
        "match": re.compile(r"jquery[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "3.4.1",
        "cves": ["CVE-2020-11022", "CVE-2020-11023"],
        "summary": "jQuery <= 3.4.1 is vulnerable to XSS via html()/jQuery.htmlPrefilter() "
                   "with untrusted HTML containing <option> or <style> tags.",
    },
    {
        "name": "jQuery",
        "match": re.compile(r"jquery[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "1.12.4",
        "cves": ["CVE-2015-9251"],
        "summary": "jQuery <= 1.12.4 is vulnerable to XSS via cross-domain Ajax requests "
                   "when the response is executed as JS instead of parsed as JSON.",
    },
    {
        "name": "jQuery UI",
        "match": re.compile(r"jquery[\-.]ui[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "1.12.1",
        "cves": ["CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"],
        "summary": "jQuery UI <= 1.12.1 has multiple XSS issues in .datepicker(), "
                   ".resizable(), and altField options.",
    },
    {
        "name": "Bootstrap",
        "match": re.compile(r"bootstrap[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "3.4.1",
        "cves": ["CVE-2018-14040", "CVE-2018-14041", "CVE-2018-14042"],
        "summary": "Bootstrap 3.x/4.0.0 tooltip/affix/collapse data-attribute XSS.",
    },
    {
        "name": "Bootstrap",
        "match": re.compile(r"bootstrap[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "4.3.1",
        "cves": ["CVE-2019-8331"],
        "summary": "Bootstrap <= 4.3.1 tooltip/popover data-template XSS.",
    },
    {
        "name": "AngularJS",
        "match": re.compile(r"angular[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "1.8.2",
        "cves": ["CVE-2023-26118"],
        "summary": "AngularJS is end-of-life (no more security patches from Google since "
                   "Jan 2022) and has known sandbox-bypass XSS issues.",
    },
    {
        "name": "Lodash",
        "match": re.compile(r"lodash[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "4.17.20",
        "cves": ["CVE-2020-8203", "CVE-2020-28500"],
        "summary": "Lodash <= 4.17.20 is vulnerable to prototype pollution via "
                   "zipObjectDeep and ReDoS via trim/pad functions.",
    },
    {
        "name": "Moment.js",
        "match": re.compile(r"moment[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "2.29.3",
        "cves": ["CVE-2022-31129"],
        "summary": "Moment.js <= 2.29.3 has a ReDoS vulnerability in its "
                   "user-locale parsing.",
    },
    {
        "name": "Handlebars",
        "match": re.compile(r"handlebars[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "4.7.6",
        "cves": ["CVE-2021-23369", "CVE-2021-23383"],
        "summary": "Handlebars <= 4.7.6 allows prototype pollution / RCE via "
                   "crafted templates.",
    },
    {
        "name": "Underscore.js",
        "match": re.compile(r"underscore[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "1.12.0",
        "cves": ["CVE-2021-23358"],
        "summary": "Underscore.js <= 1.12.0 template() function allows arbitrary "
                   "JS execution via crafted input.",
    },
    {
        "name": "SweetAlert",
        "match": re.compile(r"sweetalert2?[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "8.0.0",
        "cves": ["CVE-2019-16759-related"],
        "summary": "Old SweetAlert versions have known XSS issues via unsanitized "
                   "HTML content options.",
    },
    {
        "name": "Prototype.js",
        "match": re.compile(r"prototype[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "1.7.3",
        "cves": ["CVE-2015-1836"],
        "summary": "Prototype.js <= 1.7.3 has a DoS vulnerability via crafted "
                   "regular expressions.",
    },
    {
        "name": "Socket.IO",
        "match": re.compile(r"socket\.io[.\-]?(\d+\.\d+\.\d+)", re.I),
        "max_vulnerable": "2.4.0",
        "cves": ["CVE-2020-36049"],
        "summary": "Socket.IO client <= 2.4.0 is affected by a ReDoS vulnerability.",
    },
]


def _identify_libraries(url, body):
    """Match a script URL/content against the known-vulnerable library list."""
    findings = []
    haystacks = [url]
    # Only scan the first few KB of content for a version banner comment to
    # keep this cheap; library version banners are always near the top.
    if body:
        haystacks.append(body[:2000])
    seen = set()
    for hay in haystacks:
        for rule in _VULN_LIBRARIES:
            m = rule["match"].search(hay)
            if not m:
                continue
            version = m.group(1)
            key = (rule["name"], version)
            if key in seen:
                continue
            if _ver_lte(version, rule["max_vulnerable"]):
                seen.add(key)
                findings.append({
                    "library": rule["name"],
                    "version": version,
                    "max_vulnerable": rule["max_vulnerable"],
                    "cves": rule["cves"],
                    "summary": rule["summary"],
                    "source": url,
                })
    return findings


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------
# Patterns for secrets that should never ship in client-side JS. Kept
# conservative (specific prefixes/formats) to minimise false positives.

_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth Client Secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b")),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe Live Publishable Key", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("Generic Bearer/API secret assignment", re.compile(
        r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|client[_-]?secret|secret[_-]?key)"
        r"['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_./+=]{16,}['\"]"
    )),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("JWT (looks like a live token, not a template)", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    )),
    ("Firebase URL with implicit database", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("Basic Auth in URL", re.compile(r"https?://[^/\s'\"]+:[^/\s'\"]+@[^/\s'\"]+")),
]

# Placeholder/example values that would otherwise false-positive.
_SECRET_ALLOWLIST_HINTS = (
    "xxxxxxxx", "your_api_key", "your-api-key", "example", "changeme",
    "insert_key_here", "replace_me", "0000000000", "1234567890abcdef",
    "test_key", "sk_test_", "pk_test_",
)


def _scan_secrets(url, body):
    findings = []
    if not body:
        return findings
    for label, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(body):
            snippet = m.group(0)
            low = snippet.lower()
            if any(hint in low for hint in _SECRET_ALLOWLIST_HINTS):
                continue
            # Mask the middle of the secret before it ever leaves this function.
            masked = snippet if len(snippet) <= 8 else f"{snippet[:4]}...{snippet[-4:]}"
            findings.append({
                "type": label,
                "masked_value": masked,
                "source": url,
            })
            break  # one hit per pattern per file is enough signal
    return findings


# ---------------------------------------------------------------------------
# Script discovery + fetch
# ---------------------------------------------------------------------------

def _extract_tags(base_url, html):
    """Return (script_urls, inline_script_bodies, unprotected_cross_origin_tags)."""
    script_urls = []
    inline_bodies = []
    unprotected = []

    origin = urlparse(base_url)
    origin_host = origin.netloc.lower()

    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.I | re.S):
        attrs, inline = m.group(1), m.group(2)
        src_m = re.search(r'src=["\']([^"\']+)["\']', attrs, re.I)
        if src_m:
            abs_url = urljoin(base_url, src_m.group(1))
            script_urls.append(abs_url)
            if not re.search(r'integrity=', attrs, re.I):
                script_host = urlparse(abs_url).netloc.lower()
                if script_host and script_host != origin_host:
                    unprotected.append({"tag": "script", "src": abs_url})
        elif inline.strip():
            inline_bodies.append(inline)

    for m in re.finditer(r"<link\b([^>]*)>", html, re.I):
        attrs = m.group(1)
        if not re.search(r'rel=["\']stylesheet["\']', attrs, re.I):
            continue
        href_m = re.search(r'href=["\']([^"\']+)["\']', attrs, re.I)
        if not href_m:
            continue
        abs_url = urljoin(base_url, href_m.group(1))
        if not re.search(r'integrity=', attrs, re.I):
            link_host = urlparse(abs_url).netloc.lower()
            if link_host and link_host != origin_host:
                unprotected.append({"tag": "link", "src": abs_url})

    # Dedupe & cap
    seen = set()
    deduped = []
    for u in script_urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped[:_MAX_SCRIPTS], inline_bodies[:_MAX_SCRIPTS], unprotected[:_MAX_SCRIPTS]


def _fetch_script(url):
    try:
        resp = requests.get(
            url, timeout=_TIMEOUT, headers={"User-Agent": _UA},
            stream=True, allow_redirects=True,
        )
        if resp.status_code != 200:
            return None
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > _MAX_SCRIPT_BYTES:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        return None


def scan(domain):
    """Fetch the homepage and its scripts; return library CVE + secret findings."""
    result = {
        "success": False,
        "base_url": None,
        "scripts_analyzed": 0,
        "vulnerable_libraries": [],
        "secrets_found": [],
        "missing_sri": [],
    }
    if not _safe_host(domain):
        result["error"] = "Host does not resolve to a public address"
        return result

    html = None
    base_url = None
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}", timeout=_TIMEOUT,
                headers={"User-Agent": _UA}, allow_redirects=True,
            )
            html = resp.text
            base_url = resp.url
            break
        except Exception:
            continue
    if html is None:
        result["error"] = "No HTTP response"
        return result

    result["base_url"] = base_url
    script_urls, inline_bodies, unprotected = _extract_tags(base_url, html)
    result["missing_sri"] = unprotected

    lib_findings = []
    secret_findings = []

    # Inline scripts: scan for secrets + library version banners, no fetch needed.
    for body in inline_bodies:
        secret_findings.extend(_scan_secrets(base_url, body))
        lib_findings.extend(_identify_libraries(base_url, body))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_fetch_script, u): u for u in script_urls}
        for fut in concurrent.futures.as_completed(futures):
            url = futures[fut]
            try:
                body = fut.result()
            except Exception:
                body = None
            result["scripts_analyzed"] += 1
            lib_findings.extend(_identify_libraries(url, body or ""))
            if body:
                secret_findings.extend(_scan_secrets(url, body))

    # Dedupe library findings by (name, version)
    seen_libs = set()
    deduped_libs = []
    for f in lib_findings:
        key = (f["library"], f["version"])
        if key not in seen_libs:
            seen_libs.add(key)
            deduped_libs.append(f)

    result["vulnerable_libraries"] = deduped_libs
    result["secrets_found"] = secret_findings
    result["success"] = True
    return result


def findings(scan_result):
    """Turn a scan() result into severity-graded findings for Advies/reports."""
    out = []
    if not scan_result or not scan_result.get("success"):
        return out

    for lib in scan_result.get("vulnerable_libraries", []):
        out.append({
            "severity": "high",
            "category": "Vulnerable JS Library",
            "title": f"{lib['library']} {lib['version']} has known vulnerabilities",
            "detail": lib["summary"],
            "evidence": f"{', '.join(lib['cves'])} · found in {lib['source']}",
            "fix": f"Upgrade {lib['library']} beyond {lib['max_vulnerable']} to a "
                   f"currently maintained release.",
        })

    for secret in scan_result.get("secrets_found", []):
        out.append({
            "severity": "critical",
            "category": "Exposed Secret",
            "title": f"Possible {secret['type']} exposed in client-side JS",
            "detail": f"A pattern matching {secret['type']} was found in JavaScript "
                      f"served to every visitor's browser.",
            "evidence": f"{secret['masked_value']} · found in {secret['source']}",
            "fix": "Rotate this credential immediately, remove it from client-side "
                   "code, and move the operation it enables behind a backend API.",
        })

    missing_sri = scan_result.get("missing_sri", [])
    if missing_sri:
        hosts = sorted({urlparse(m["src"]).netloc for m in missing_sri})
        out.append({
            "severity": "low",
            "category": "Subresource Integrity",
            "title": f"{len(missing_sri)} third-party script/style tag(s) without SRI",
            "detail": "Cross-origin <script>/<link> tags are loaded without an "
                      "integrity attribute, so a compromised CDN could silently "
                      "modify the delivered code.",
            "evidence": f"Hosts: {', '.join(hosts[:5])}",
            "fix": "Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" to "
                   "third-party <script>/<link> tags, or self-host the assets.",
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda f: order.get(f["severity"], 9))
    return out
