"""
DomainLens — Client-side JavaScript security scan.

Passive, always-safe: fetches the page and its same-origin/CDN <script src>
files (no execution, no active probing) and checks for:
  1. Known-vulnerable JS library versions (small curated CVE database)
  2. Hardcoded secrets/API keys accidentally shipped in client-side bundles
  3. Missing Subresource Integrity (SRI) on third-party <script>/<link> tags
  4. Public source maps, which hand out the original source

Only what the page itself loads is fetched: its scripts, the code chunks
those name literally (a Vite or Next.js bundle splits most of an app into
them), and the source maps they point to. No paths are guessed.

This never sends anything to the target beyond ordinary GET requests, so it
is safe to run against any domain — unlike the active_scan / weak_auth checks.
"""

import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import math
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
_MAX_CHUNKS = 15            # code chunks named in those scripts, on top
_MAX_SCRIPT_BYTES = 2_000_000  # 2 MB cap per file
_MAX_MAP_BYTES = 5_000_000     # source maps carry the whole source
_MAX_MAPS = 10
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
        r"['\"]?\s*[:=]\s*['\"](?P<v>[A-Za-z0-9\-_./+=]{16,})['\"]"
    )),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("JWT (looks like a live token, not a template)", re.compile(
        r"(?<![.\w])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    )),
    ("Firebase URL with implicit database", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("Basic Auth in URL", re.compile(r"https?://[^/\s'\"]+:[^/\s'\"]+@[^/\s'\"]+")),
    # Prefixed formats: the prefix makes a chance match next to impossible.
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}")),
    ("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("Mailchimp API Key", re.compile(r"\b[0-9a-f]{32}-us\d{1,2}\b")),
    ("Mailgun API Key", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("npm Token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Shopify Access Token", re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b")),
    ("Stripe Live Restricted Key", re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b")),
    ("Telegram Bot Token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b")),
    ("Discord Webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,}")),
    ("Microsoft Teams Webhook", re.compile(r"https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9@/_-]{40,}")),
    ("Azure Storage Connection String", re.compile(
        r"DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/]{86}==")),
    ("Azure SAS Token", re.compile(r"[?&]sv=20\d\d-\d\d-\d\d&[^\s'\"]*?sig=[A-Za-z0-9%+/=]{30,}")),
    ("Mapbox Secret Token", re.compile(r"\bsk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")),
]

# Placeholder/example values that would otherwise false-positive.
_SECRET_ALLOWLIST_HINTS = (
    "xxxxxxxx", "your_api_key", "your-api-key", "example", "changeme",
    "insert_key_here", "replace_me", "0000000000", "1234567890abcdef",
    "test_key", "sk_test_", "pk_test_",
)


def _entropy(value):
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _jwt_claims(token):
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return None


def _classify(label, match):
    """The type to report for a match, or None when it is not a secret.

    A generic `apiKey: "..."` with a low-entropy value (a word, a repeated
    character, a path) was reported as a possible secret. A JWT is decoded:
    a Supabase key says its role, and an anon key is meant for the browser
    while a service_role key bypasses every row-level security policy.
    """
    value = match.group(0)
    if label.startswith("Generic"):
        candidate = match.groupdict().get("v") or value
        if _entropy(candidate) < 3.5 or not re.search(r"\d", candidate) or not re.search(r"[A-Za-z]", candidate):
            return None
    if label.startswith("JWT"):
        claims = _jwt_claims(value) or {}
        role = claims.get("role") if isinstance(claims, dict) else None
        if role == "service_role":
            return "Supabase service_role key"
        if role == "anon":
            return "Supabase anon key"
    return label


def _scan_secrets(url, body):
    findings = {}
    if not body:
        return []
    for label, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(body):
            snippet = m.group(0)
            low = snippet.lower()
            if any(hint in low for hint in _SECRET_ALLOWLIST_HINTS):
                continue
            kind = _classify(label, m)
            if kind is None or kind in findings:
                continue  # one hit per type per file is enough signal
            findings[kind] = {
                "type": kind,
                # Mask the middle of the secret before it ever leaves this function.
                "masked_value": snippet if len(snippet) <= 8 else f"{snippet[:4]}...{snippet[-4:]}",
                "source": url,
                "severity": secret_severity(kind),
                # The same key in ten bundles is one finding, not ten; told
                # apart by a hash, so the value itself is never kept.
                "fingerprint": hashlib.sha256(snippet.encode()).hexdigest()[:16],
            }
    return list(findings.values())


# Meant for the browser: a finding only as a reminder to restrict them.
_PUBLIC_BY_DESIGN = {
    "Google API Key", "Stripe Live Publishable Key", "Firebase URL with implicit database",
    "Supabase anon key",
}
_CRITICAL = {"Supabase service_role key"}
_PRIVATE = {
    "AWS Secret Key", "Google OAuth Client Secret", "Stripe Live Secret Key", "GitHub Token",
    "Slack Token", "Slack Webhook", "Private Key Block", "Basic Auth in URL", "OpenAI API Key",
    "Anthropic API Key", "SendGrid API Key", "Mailchimp API Key", "GitLab Token", "npm Token",
    # Not Mailgun's key-<32 hex>: a cache key in a bundle has the same shape,
    # so it stays medium until someone looks.
    "Shopify Access Token", "Stripe Live Restricted Key", "Telegram Bot Token", "Discord Webhook",
    "Microsoft Teams Webhook", "Azure Storage Connection String", "Mapbox Secret Token",
}


def secret_severity(kind):
    if kind in _CRITICAL:
        return "critical"
    if kind in _PRIVATE:
        return "high"
    if kind in _PUBLIC_BY_DESIGN:
        return "info"
    return "medium"


# Code chunks named literally in a bundle: Vite's assets/<name>-<hash>.js,
# Next.js's /_next/static/chunks/..., webpack's <id>.<hash>.chunk.js.
_CHUNK_REF = re.compile(r"[\"'`]((?:\.{0,2}/)?[\w@./-]{1,200}?\.m?js)[\"'`]")
# A chunk, not any .js string: a chunk directory, or a content hash in the name.
_CHUNK_NAME = re.compile(r"chunk|_next/static/|assets/|static/js/|[.-][A-Za-z0-9_]{8,}\.m?js$")
_ROOTED = re.compile(r"(?:\.?/)?(?:_next/|assets/|static/)")
_SOURCE_MAP = re.compile(r"//[#@]\s*sourceMappingURL=(?!data:)(\S+)\s*$", re.M)


def _chunk_urls(script_url, body, page_url):
    """Same-origin chunk files a bundle names, resolved as the bundler does:
    from the site root for /_next, assets/ and static/, else beside the file."""
    origin = urlparse(page_url).netloc.lower()
    found = []
    for m in _CHUNK_REF.finditer(body or ""):
        path = m.group(1)
        if not _CHUNK_NAME.search(path):
            continue
        rooted = _ROOTED.match(path)
        url = urljoin(page_url, "/" + path.lstrip("./")) if rooted else urljoin(script_url, path)
        if urlparse(url).netloc.lower() == origin:
            found.append(url)
    return found


def _fetch_map(url):
    """A public source map's original sources, or None."""
    try:
        resp = requests.get(url, timeout=_TIMEOUT, headers={"User-Agent": _UA}, stream=True)
        if resp.status_code != 200:
            return None
        data, total = [], 0
        for chunk in resp.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > _MAX_MAP_BYTES:
                return None
            data.append(chunk)
        parsed = json.loads(b"".join(data).decode("utf-8", errors="ignore"))
    except Exception:
        return None
    if not isinstance(parsed, dict) or "sources" not in parsed:
        return None
    return parsed


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
    """Fetch the homepage and its scripts; return library CVE + secret findings.

    Coverage is counted, so "no secrets found" can be read against what was
    looked at: scripts that could not be fetched are not scripts that were
    clean.
    """
    result = {
        "success": False,
        "base_url": None,
        "scripts_analyzed": 0,
        "scripts_found": 0,
        "scripts_failed": 0,
        "inline_scripts": 0,
        "chunks_followed": 0,
        "source_maps": [],
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
    result["scripts_found"] = len(script_urls)
    result["inline_scripts"] = len(inline_bodies)

    lib_findings = []
    secret_findings = []

    # Inline scripts: scan for secrets + library version banners, no fetch needed.
    for body in inline_bodies:
        secret_findings.extend(_scan_secrets(base_url, body))
        lib_findings.extend(_identify_libraries(base_url, body))

    origin = urlparse(base_url).netloc.lower()
    fetched = {}

    def fetch_all(urls):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(_fetch_script, u): u for u in urls}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    fetched[futures[fut]] = fut.result()
                except Exception:
                    fetched[futures[fut]] = None

    fetch_all(script_urls)
    # The chunks the page's own bundles name: most of a modern app is in
    # them, not in the one file the HTML loads.
    chunks = []
    for url, body in list(fetched.items()):
        if body and urlparse(url).netloc.lower() == origin:
            for chunk in _chunk_urls(url, body, base_url):
                if chunk not in fetched and chunk not in chunks:
                    chunks.append(chunk)
    chunks = chunks[:_MAX_CHUNKS]
    fetch_all(chunks)
    result["chunks_followed"] = sum(1 for c in chunks if fetched.get(c))

    maps = []
    for url, body in fetched.items():
        if body:
            result["scripts_analyzed"] += 1
            lib_findings.extend(_identify_libraries(url, body))
            secret_findings.extend(_scan_secrets(url, body))
            for m in _SOURCE_MAP.finditer(body[-2000:]):
                map_url = urljoin(url, m.group(1))
                if urlparse(map_url).netloc.lower() == origin and map_url not in maps:
                    maps.append(map_url)
        else:
            result["scripts_failed"] += 1
            lib_findings.extend(_identify_libraries(url, ""))

    # A public source map is the original source, comments and all; what is
    # in it is scanned too.
    for map_url in maps[:_MAX_MAPS]:
        parsed = _fetch_map(map_url)
        if not parsed:
            continue
        result["source_maps"].append(map_url)
        contents = "\n".join(c for c in parsed.get("sourcesContent") or [] if isinstance(c, str))
        secret_findings.extend(_scan_secrets(map_url, contents))

    # Dedupe library findings by (name, version)
    seen_libs = set()
    deduped_libs = []
    for f in lib_findings:
        key = (f["library"], f["version"])
        if key not in seen_libs:
            seen_libs.add(key)
            deduped_libs.append(f)

    # One finding per secret, however many files carry it.
    by_value = {}
    for s in secret_findings:
        known = by_value.get(s["fingerprint"])
        if known:
            known["also_in"] = known.get("also_in", 0) + 1
        else:
            by_value[s["fingerprint"]] = s
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    result["vulnerable_libraries"] = deduped_libs
    result["secrets_found"] = sorted(by_value.values(), key=lambda s: order.get(s["severity"], 9))
    result["success"] = True
    return result


_SECRET_TEXT = {
    "critical": (
        "A {kind} was found in JavaScript served to every visitor's browser. It bypasses "
        "every row-level security policy: whoever reads it can read and change all data.",
        "Rotate the key in the Supabase dashboard now, remove it from client-side code, and "
        "use it only on a server. The browser gets the anon key, with row-level security on.",
    ),
    "high": (
        "A pattern strongly matching {kind} was found in JavaScript served to every visitor's browser.",
        "Validate and rotate this credential, remove it from client-side code, and move "
        "privileged operations behind a backend API.",
    ),
    "medium": (
        "A pattern possibly matching {kind} was found in public JavaScript, but validity and "
        "privilege were not established.",
        "Validate the match and its permissions. Rotate and remove it from client-side code if "
        "it is a live private credential.",
    ),
    "info": (
        "A client-visible identifier matching {kind} was found. This may be intentional; its "
        "server-side restrictions still need review.",
        "Confirm the identifier is intended to be public and restrict it by origin, API, quota, "
        "and least privilege where the provider supports that. For a Supabase anon key: make "
        "sure row-level security is on for every table.",
    ),
}


def findings(scan_result):
    """Turn a scan() result into severity-graded findings for Advies/reports."""
    out = []
    if not scan_result or not scan_result.get("success"):
        return out

    for lib in scan_result.get("vulnerable_libraries", []):
        out.append({
            "severity": "medium",
            "category": "Vulnerable JS Library",
            "title": f"{lib['library']} {lib['version']} has known vulnerabilities",
            "detail": lib["summary"],
            "evidence": f"{', '.join(lib['cves'])} · found in {lib['source']}",
            "fix": f"Upgrade {lib['library']} beyond {lib['max_vulnerable']} to a "
                   f"currently maintained release.",
        })

    for secret in scan_result.get("secrets_found", []):
        secret_type = secret["type"]
        severity = secret.get("severity") or secret_severity(secret_type)
        detail, fix = _SECRET_TEXT[severity]
        where = f"{secret['masked_value']} · found in {secret['source']}"
        if secret.get("also_in"):
            where += f" and {secret['also_in']} other file(s)"
        out.append({
            "severity": severity,
            "category": "Exposed Secret",
            "title": f"Possible {secret_type} exposed in client-side JS",
            "detail": detail.format(kind=secret_type),
            "evidence": where,
            "fix": fix,
        })

    maps = scan_result.get("source_maps") or []
    if maps:
        out.append({
            "severity": "low",
            "category": "Exposed Source Map",
            "title": f"{len(maps)} public source map(s)",
            "detail": "The site serves source maps: anyone can read the original, unminified "
                      "source, with its comments, internal paths and any value left in it.",
            "evidence": ", ".join(maps[:3]),
            "fix": "Do not deploy .map files to the public site (Vite: build.sourcemap false; "
                   "Create React App: GENERATE_SOURCEMAP=false; Next.js: "
                   "productionBrowserSourceMaps false), or upload them only to your error tracker.",
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
