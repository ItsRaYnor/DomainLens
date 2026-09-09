"""
DomainLens — Security audit checks.

Passive / light-touch security assessment: detects misconfigurations and
exposures without exploiting them. No brute-force, no exploit payloads, no DoS.

Covers four blindspot categories:
  1. Subdomain takeover (dangling CNAMEs via Certificate Transparency)
  2. Web-app exposures (cookies, CORS, HTTP methods, sensitive files, security.txt)
  3. DNS & mail gaps (AXFR, CAA, TLSA/DANE, SPF lookups, DMARC sp, wildcard)
  4. Info disclosure & tech fingerprinting
"""

import concurrent.futures
import ipaddress
import re
import secrets
import socket
import urllib.parse

import security_txt
import pgp_keys
import cert_transparency

import dns.resolver
import dns.query
import dns.zone
import requests


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

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


def _is_private_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


def _safe_host(host):
    """Return True if host resolves to a public IP (SSRF guard)."""
    ips = _resolve(host, "A")
    if not ips:
        return False
    return not _is_private_ip(ips[0])


# Bounded resolver so a broken/blocked DNS path can never hang a scan.
_RESOLVER = dns.resolver.Resolver()
_RESOLVER.timeout = 4
_RESOLVER.lifetime = 6


def _resolve(domain, rdtype):
    try:
        answers = _RESOLVER.resolve(domain, rdtype)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def _is_nxdomain(name):
    """True only when the name definitively does not exist.

    _resolve() collapses every failure mode to an empty list — NXDOMAIN,
    SERVFAIL, timeout, NoAnswer all look identical. Takeover detection then
    read "no records" as "the target is unclaimed", so a transient resolver
    hiccup during a scan produced a reported (medium-confidence) takeover on
    a perfectly healthy CNAME. Only NXDOMAIN actually means claimable.
    """
    try:
        _RESOLVER.resolve(name, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.resolver.NoAnswer:
        # The name exists, it just has no A record (e.g. AAAA/TXT only).
        return False
    except Exception:
        # SERVFAIL / timeout / no nameservers: genuinely unknown, so never
        # claim a takeover off the back of it.
        return False


def _get(url, timeout=8, allow_redirects=True, headers=None, method="GET"):
    hdrs = {"User-Agent": _UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    return requests.request(
        method, url, timeout=timeout, allow_redirects=allow_redirects,
        headers=hdrs, stream=False,
    )


def _iter_set_cookie(resp):
    """Yield individual Set-Cookie header values, preserving each cookie.

    requests folds multiple Set-Cookie headers into one comma-joined string,
    so prefer the raw urllib3 headers which expose them separately.
    """
    try:
        raw_headers = resp.raw.headers
        if hasattr(raw_headers, "get_all"):
            vals = raw_headers.get_all("Set-Cookie")
            if vals:
                for v in vals:
                    if v:
                        yield v
                return
    except Exception:
        pass
    combined = resp.headers.get("Set-Cookie", "")
    if combined:
        # Best-effort split: a new cookie starts after ", " followed by name=
        for part in re.split(r",(?=[^ ;]+=)", combined):
            part = part.strip()
            if part:
                yield part


def _finding(severity, category, title, detail, evidence="", fix=""):
    f = {"severity": severity, "category": category, "title": title,
         "detail": detail}
    if evidence:
        f["evidence"] = evidence
    if fix:
        f["fix"] = fix
    return f


# ---------------------------------------------------------------------------
# 1. Subdomain enumeration + takeover detection
# ---------------------------------------------------------------------------

# Providers that hand out the hostname themselves, with a portion no third
# party can choose. A dangling CNAME to one of these is a stale record worth
# removing, but it is NOT a claimable takeover: to re-point the name an
# attacker would have to make the provider re-issue that exact hostname, and
# the provider-assigned portion (an AWS-allocated ELB suffix, a random
# CloudFront distribution id) cannot be requested. Kept apart from the
# takeover signatures on purpose — conflating "stale" with "claimable" turns a
# cleanup task into a false vulnerability report.
#
# Contrast with classic per-tenant services (S3, GitHub Pages, Heroku): there
# the customer picks the whole subdomain, so anyone can re-register it. Those
# stay in _TAKEOVER_SIGNATURES.
_PROVIDER_ASSIGNED = [
    {"provider": "AWS Elastic Load Balancing",
     "cnames": [".elb.amazonaws.com"],
     "note": "the ELB DNS name carries an AWS-allocated suffix that cannot be requested"},
    {"provider": "AWS CloudFront",
     "cnames": [".cloudfront.net"],
     "note": "the CloudFront distribution domain is a random AWS-assigned id, and an "
             "alternate domain can only be added after ownership is proven"},
]


def provider_assigned(hostname):
    """Return the provider entry if `hostname` is a provider-assigned name.

    A provider-assigned name is one whose registrable portion the provider,
    not the customer, controls — so a dangling CNAME to it is stale but not
    claimable. Returns None when the host is not recognised, in which case
    claimability is genuinely unknown rather than ruled out.
    """
    host = (hostname or "").rstrip(".").lower()
    for entry in _PROVIDER_ASSIGNED:
        if any(c in host for c in entry["cnames"]):
            return entry
    return None


# Fingerprints for services vulnerable to subdomain takeover.
# Each entry: cname substrings that point at the service + body signatures that
# indicate the resource is unclaimed / dangling.
_TAKEOVER_SIGNATURES = [
    {"service": "AWS S3", "cnames": ["s3.amazonaws.com", "s3-website", ".s3."],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"service": "GitHub Pages", "cnames": ["github.io"],
     "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"]},
    {"service": "Heroku", "cnames": ["herokuapp.com", "herokudns.com"],
     "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"]},
    {"service": "Azure", "cnames": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azureedge.net", "azurefd.net", "azure-api.net"],
     "fingerprints": ["404 Web Site not found", "The specified blob does not exist", "Error 404 - Web app not found"]},
    {"service": "Fastly", "cnames": ["fastly.net"],
     "fingerprints": ["Fastly error: unknown domain", "Please check that this domain has been added to a service"]},
    {"service": "Shopify", "cnames": ["myshopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left!"]},
    {"service": "Zendesk", "cnames": ["zendesk.com"],
     "fingerprints": ["Help Center Closed", "this help center no longer exists"]},
    {"service": "Unbounce", "cnames": ["unbouncepages.com"],
     "fingerprints": ["The requested URL was not found on this server"]},
    {"service": "Surge.sh", "cnames": ["surge.sh"],
     "fingerprints": ["project not found"]},
    {"service": "Pantheon", "cnames": ["pantheonsite.io"],
     "fingerprints": ["The gods are wise", "404 error unknown site"]},
    {"service": "Netlify", "cnames": ["netlify.app", "netlify.com"],
     "fingerprints": ["Not Found - Request ID"]},
    {"service": "Cargo", "cnames": ["cargocollective.com"],
     "fingerprints": ["404 Not Found"]},
    {"service": "Tumblr", "cnames": ["domains.tumblr.com"],
     "fingerprints": ["Whatever you were looking for doesn't currently exist at this address"]},
    {"service": "WordPress.com", "cnames": ["wordpress.com"],
     "fingerprints": ["Do you want to register"]},
    {"service": "Ghost", "cnames": ["ghost.io"],
     "fingerprints": ["The thing you were looking for is no longer here"]},
    {"service": "Read the Docs", "cnames": ["readthedocs.io"],
     "fingerprints": ["unknown to Read the Docs"]},
    {"service": "Bitbucket", "cnames": ["bitbucket.io"],
     "fingerprints": ["Repository not found"]},
    {"service": "GitLab Pages", "cnames": ["gitlab.io"],
     "fingerprints": ["The page you're looking for could not be found"]},
    {"service": "Webflow", "cnames": ["proxy-ssl.webflow.com", "webflow.io"],
     "fingerprints": ["The page you are looking for doesn't exist or has been moved"]},
    {"service": "Help Scout", "cnames": ["helpscoutdocs.com"],
     "fingerprints": ["No settings were found for this company"]},
    {"service": "Campaign Monitor", "cnames": ["createsend.com"],
     "fingerprints": ["Trying to access your account?", "double-check the URL"]},
    {"service": "Acquia", "cnames": ["acquia-sites.com"],
     "fingerprints": ["The site you are looking for could not be found"]},
    {"service": "UserVoice", "cnames": ["uservoice.com"],
     "fingerprints": ["This UserVoice subdomain is currently available"]},
    {"service": "Tilda", "cnames": ["tilda.ws"],
     "fingerprints": ["Please renew your subscription"]},
    {"service": "Kajabi", "cnames": ["endpoint.mykajabi.com"],
     "fingerprints": ["The page you were looking for doesn't exist"]},
    {"service": "Launchrock", "cnames": ["launchrock.com"],
     "fingerprints": ["It looks like you may have taken a wrong turn somewhere"]},
    {"service": "Strikingly", "cnames": ["strikinglydns.com"],
     "fingerprints": ["But if you're looking to build your own website"]},
    {"service": "Intercom", "cnames": ["custom.intercom.help"],
     "fingerprints": ["This page is reserved for artistic dogs"]},
    {"service": "Freshdesk", "cnames": ["freshdesk.com"],
     "fingerprints": ["May be this is still fresh!"]},
    {"service": "Teamwork", "cnames": ["teamwork.com"],
     "fingerprints": ["Oops - We didn't find your site"]},
    {"service": "Agile CRM", "cnames": ["agilecrm.com"],
     "fingerprints": ["Sorry, this page is no longer available"]},
    {"service": "Smartling", "cnames": ["smartling.com"],
     "fingerprints": ["Domain is not configured"]},
    {"service": "GetResponse", "cnames": ["gr8.com"],
     "fingerprints": ["With GetResponse Landing Pages, lead generation has never been easier"]},
    {"service": "Vercel", "cnames": ["vercel-dns.com", "vercel.app"],
     "fingerprints": ["DEPLOYMENT_NOT_FOUND", "The deployment could not be found"]},
    {"service": "Firebase Hosting", "cnames": ["firebaseapp.com", "web.app"],
     "fingerprints": ["Site Not Found", "this file does not exist and there was no index"]},
    {"service": "Cloudflare Pages", "cnames": ["pages.dev"], "fingerprints": []},
    {"service": "Render", "cnames": ["onrender.com"], "fingerprints": []},
    {"service": "AWS Elastic Beanstalk", "cnames": ["elasticbeanstalk.com"], "fingerprints": []},
    {"service": "Bunny CDN", "cnames": ["b-cdn.net"], "fingerprints": []},
    {"service": "ngrok", "cnames": ["ngrok.io"],
     "fingerprints": ["Tunnel not found", "ngrok.io not found"]},
    {"service": "Short.io", "cnames": ["cname.short.io"],
     "fingerprints": ["Link does not exist"]},
]


_SUBDOMAIN_LIMIT = 60


def _fetch_crtsh(domain, timeout=20, attempts=3, force=False):
    """Fetch crt.sh JSON. See crtsh.fetch_detailed for retry/outage/cache handling."""
    import crtsh
    return crtsh.fetch_detailed(domain, timeout=timeout, attempts=attempts, force=force)


def enumerate_subdomains(domain, limit=_SUBDOMAIN_LIMIT, timeout=20, force=False):
    """Passive subdomain enumeration via crt.sh Certificate Transparency logs.

    Returns (subdomains, discovered_count, source_error, source_meta). A failed lookup used
    to be swallowed, leaving just the apex — so a takeover scan that had
    enumerated nothing still reported "no dangling subdomains detected",
    which reads as a clean bill of health rather than an absent one.
    """
    found = set()
    rows, source_error, meta = _fetch_crtsh(domain, timeout=timeout, force=force)
    for entry in rows or []:
        name = entry.get("name_value", "")
        for sub in str(name).split("\n"):
            sub = sub.strip().lower().lstrip("*.")
            if sub.endswith(domain) and _DOMAIN_OK.match(sub):
                found.add(sub)
    # Always include the apex
    found.add(domain)
    ordered = sorted(found, key=lambda s: (s.count("."), len(s)))
    return ordered[:limit], len(ordered), source_error, meta or {}


_DOMAIN_OK = re.compile(r"^[a-z0-9._-]+$")


def _check_one_takeover(sub):
    """Resolve a subdomain's CNAME and test for a dangling / unclaimed target.

    Two distinct outcomes are reported, because they need different responses:
      kind="takeover" — the CNAME points at a known takeover-able service and
        either its unclaimed-resource fingerprint matched, or the target is
        NXDOMAIN.
      kind="dangling" — the CNAME target is NXDOMAIN but the service isn't in
        our signature list. Still a real dangling record worth removing;
        previously these were dropped silently, so a dangling CNAME to any
        provider we hadn't enumerated was invisible.
    """
    cnames = _resolve(sub, "CNAME")
    if not cnames:
        return None
    cname = cnames[0].rstrip(".").lower()

    # Match against a known takeover-able service
    matched = None
    for sig in _TAKEOVER_SIGNATURES:
        if any(c in cname for c in sig["cnames"]):
            matched = sig
            break

    # NXDOMAIN on the target is the only DNS state that actually means
    # "unclaimed" — see _is_nxdomain for why "no records" is not enough.
    target_nxdomain = _is_nxdomain(cname)
    target_resolves = not target_nxdomain and bool(
        _resolve(cname, "A") or _resolve(cname, "AAAA")
    )

    if not matched:
        if target_nxdomain:
            assigned = provider_assigned(cname)
            return {
                "kind": "dangling",
                "subdomain": sub,
                "cname": cname,
                "service": None,
                "target_resolves": False,
                "fingerprint_match": False,
                "http_status": None,
                # registrable is False when the target is a provider-assigned
                # name (stale, but nobody can re-register it) and None when the
                # provider is simply unknown to us (claimability untested).
                "registrable": None if assigned is None else False,
                "provider": assigned["provider"] if assigned else None,
                "provider_note": assigned["note"] if assigned else None,
                "confidence": "low" if assigned else "medium",
            }
        return None

    body = ""
    status = None
    if _safe_host(sub):
        for scheme in ("https", "http"):
            try:
                r = _get(f"{scheme}://{sub}", timeout=8)
                status = r.status_code
                body = r.text[:4000]
                break
            except Exception:
                continue

    fp_hit = any(fp.lower() in body.lower() for fp in matched["fingerprints"])

    if fp_hit or target_nxdomain:
        confidence = "high" if fp_hit else "medium"
        return {
            "kind": "takeover",
            "subdomain": sub,
            "cname": cname,
            "service": matched["service"],
            "target_resolves": target_resolves,
            "fingerprint_match": fp_hit,
            "http_status": status,
            "confidence": confidence,
        }
    return None


def check_subdomain_takeover(domain, limit=_SUBDOMAIN_LIMIT, force=False):
    """Enumerate subdomains and flag ones vulnerable to takeover."""
    result = {
        "success": False, "subdomains": [], "takeovers": [], "dangling": [],
        "count": 0, "discovered_count": 0, "truncated": False, "limit": limit,
        "source_error": None,
    }
    try:
        subs, discovered, source_error, source_meta = enumerate_subdomains(
            domain, limit=limit, force=force)
        # Say when the certificate list is yesterday's, so an unchanged
        # subdomain count is not mistaken for a fresh confirmation.
        result["source_cached"] = bool(source_meta.get("cached"))
        result["source_cache_age_seconds"] = source_meta.get("cache_age_seconds")
        # A stale copy shown during an outage is a different claim from a
        # same-day reuse: it says "this is the last answer we know to be
        # real", and the outage that forced it has to travel with it.
        result["source_stale"] = bool(source_meta.get("stale"))
        result["source_cached_at"] = source_meta.get("cached_at")
        result["source_outage"] = source_meta.get("outage")
        result["subdomains"] = subs
        result["count"] = len(subs)
        result["source_error"] = source_error
        # Report coverage honestly: a capped list looks identical to a
        # complete one in the UI otherwise, so "no takeovers found" reads as
        # "all subdomains are clean" when most were never checked.
        result["discovered_count"] = discovered
        result["truncated"] = discovered > len(subs)

        takeovers = []
        dangling = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            futures = {ex.submit(_check_one_takeover, s): s for s in subs}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    r = fut.result()
                except Exception:
                    continue
                if not r:
                    continue
                if r.get("kind") == "dangling":
                    dangling.append(r)
                else:
                    takeovers.append(r)
        takeovers.sort(key=lambda x: x["subdomain"])
        dangling.sort(key=lambda x: x["subdomain"])
        result["takeovers"] = takeovers
        result["dangling"] = dangling
        result["success"] = True
    except Exception as exc:
        result["error"] = str(exc)[:200]
    return result


# ---------------------------------------------------------------------------
# 2. Web-app exposures
# ---------------------------------------------------------------------------

# Small, targeted wordlist — sensitive files/endpoints that should never be
# publicly readable. Each has a content signature to avoid catch-all 200 pages.
# A real leaked env/config/backup file is never a normal HTML page — many
# hosts and CDNs (incl. Bunny) return HTTP 200 with a generic "not found" or
# SPA-fallback HTML page instead of a real 404. That page virtually always
# contains a stray "=" somewhere (e.g. any attr="value"), so a loose
# substring match on "=" or a bare word like "SECRET" false-positives on any
# such fallback page. expects_html marks the rare entries where a genuine hit
# IS an HTML page (phpinfo.php); everything else is rejected outright if the
# response looks like an HTML document.
_SENSITIVE_PATHS = [
    ("/.git/config", ["[core]", "repositoryformatversion"], False),
    ("/.git/HEAD", ["ref: refs/"], False),
    ("/.env", None, False),
    ("/.env.local", None, False),
    ("/.env.production", None, False),
    ("/config.php.bak", ["<?php"], False),
    ("/wp-config.php.bak", ["DB_PASSWORD", "<?php"], False),
    ("/.DS_Store", ["Bud1", "\x00\x00\x00\x01"], False),
    ("/.svn/entries", ["dir", "svn"], False),
    ("/backup.zip", ["PK\x03\x04"], False),
    ("/backup.sql", ["INSERT INTO", "CREATE TABLE", "DROP TABLE"], False),
    ("/database.sql", ["INSERT INTO", "CREATE TABLE"], False),
    ("/dump.sql", ["INSERT INTO", "CREATE TABLE"], False),
    ("/phpinfo.php", ["phpinfo()", "PHP Version"], True),
    ("/server-status", ["Apache Server Status", "Server uptime"], False),
    ("/.well-known/security.txt", ["Contact:", "contact:"], False),
    ("/docker-compose.yml", ["services:", "image:"], False),
    ("/.aws/credentials", ["aws_access_key_id"], False),
    ("/id_rsa", ["PRIVATE KEY"], False),
    ("/.htpasswd", [":$"], False),
]

# Endpoints that are common admin/debug surfaces — presence alone is worth noting
_ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin/", "/.git/", "/actuator",
                "/actuator/health", "/debug", "/phpmyadmin/", "/manager/html"]

# .env files are KEY=VALUE lines (e.g. DB_PASSWORD=secret) — require that
# actual shape rather than a bare "=" or a common word appearing anywhere.
_ENV_LINE_RE = re.compile(r"(?m)^[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S+")


# --- RFC 9116 security.txt -------------------------------------------------
# The file is fetched anyway for the presence check; parsing it costs nothing
# extra and turns a bare yes/no into something a researcher can act on.


# A PGP public key block, as armoured by RFC 4880. The private counterpart is
# matched too: finding one published is a serious finding, not a valid key.
_PGP_PUBLIC_RE = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----")
_PGP_PRIVATE_RE = re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")


# The parser lives in security_txt: it is about the file format, not
# about scanning. Re-exported here because callers and tests reach for it
# by this name, and the move should not be their problem.
parse_security_txt = security_txt.parse_security_txt


def check_security_txt_key(body, base_url=None):
    """Resolve and inspect the PGP key an Encryption: field points at.

    Three outcomes are kept apart, because an operator acts on each
    differently: the key was fetched and read, the key could not be reached
    (ours to report as unmeasured, never as the site's defect), and there is
    no Encryption: field to follow at all.
    """
    result = {
        "state": "not_applicable",
        "encryption_urls": [],
        "url": None,
        "reason": None,
        "armored": False,
        "private_key_published": False,
        "key_details": None,
    }
    fields = parse_security_txt(body)
    urls = [u for u in fields.get("encryption", []) if u]
    result["encryption_urls"] = urls
    if not urls:
        # Encryption is OPTIONAL in RFC 9116. Absent is a deliberate choice,
        # not a failure to measure and not a defect.
        result["reason"] = "No Encryption: field in security.txt"
        return result

    url = urls[0]
    result["url"] = url
    # dns: and openpgp4fpr: URIs are legal but point at a key we would have
    # to look up elsewhere; say so rather than reporting a fetch failure.
    if not url.lower().startswith(("http://", "https://")):
        result["state"] = "unmeasured"
        result["reason"] = f"Encryption URI is not HTTP(S) and was not followed: {url}"
        return result

    host = urllib.parse.urlsplit(url).hostname
    # The URL comes out of the scanned site's own file, so it is attacker
    # controlled: without this, a hostile security.txt could point us at a
    # cloud metadata endpoint or an internal host and use the scanner as a
    # proxy to it.
    if not host or not _safe_host(host):
        result["state"] = "unmeasured"
        result["reason"] = "Encryption URL does not resolve to a public address"
        return result

    # Same reasoning as the file itself: a key URL may redirect, and every
    # hop is checked rather than trusted.
    r, _final, detail = _get_following_safe_redirects(url, timeout=8)
    if r is None:
        result["state"] = "unmeasured"
        result["reason"] = f"Could not fetch the key: {detail}"
        return result

    if r.status_code != 200:
        result["state"] = "measured"
        result["reason"] = f"Key URL returned HTTP {r.status_code}"
        return result

    text = r.text[:200000] if r.content else ""
    result["private_key_published"] = bool(_PGP_PRIVATE_RE.search(text))
    result["armored"] = bool(_PGP_PUBLIC_RE.search(text))
    result["state"] = "measured"
    if result["private_key_published"]:
        result["reason"] = "The URL serves a PGP PRIVATE key block"
    elif result["armored"]:
        result["reason"] = "Armoured PGP public key block served"
    else:
        result["reason"] = "The URL did not serve an armoured PGP public key block"

    # The key is already in hand, so read it here rather than making someone
    # copy it into the validator to learn the same things. "Armoured" only
    # says the wrapper is right: an expired key, or one whose only identity
    # is an address nobody reads, still passes that and still leaves a
    # researcher unable to reach anyone.
    if result["armored"] or result["private_key_published"]:
        try:
            result["key_details"] = pgp_keys.inspect_key(text)
        except Exception as exc:
            # Never fatal: the fetch succeeded, and failing to parse is our
            # limitation rather than a fault in what they published.
            result["key_details"] = {"valid": False, "keys": [],
                                     "error": f"Could not read the key: {type(exc).__name__}"}
    return result


def inspect_security_txt(domain, timeout=8):
    """Fetch one domain's security.txt and report what it says.

    The manual counterpart to the scan check: same parsing, same three key
    states, but aimed at a single domain on demand -- including your own,
    which is the usual reason to look.
    """
    result = {
        "domain": domain,
        "found": False,
        "url": None,
        "status": None,
        "fields": {},
        "raw": None,
        "key": None,
        "redirected_from": None,
        "error": None,
    }
    if not _safe_host(domain):
        result["error"] = "Host does not resolve to a public address"
        return result

    last_error = None
    for scheme in ("https", "http"):
        base = f"{scheme}://{domain}"
        url = base + "/.well-known/security.txt"
        response, final_url, detail = _get_following_safe_redirects(url, timeout=timeout)
        if response is None:
            last_error = detail
            continue
        result["url"] = final_url
        result["status"] = response.status_code
        # Worth showing: a file served from somewhere other than the address
        # asked for is normal, but the operator should see where it came from.
        if final_url != url:
            result["redirected_from"] = url
        if response.status_code != 200:
            continue
        body = response.text[:20000] if response.content else ""
        # Same guard as the scan: a 200 HTML fallback page is a soft 404, not
        # a security.txt, and reporting it as one invents a policy that does
        # not exist.
        if _looks_like_html(body) or "contact:" not in body.lower():
            continue
        result["found"] = True
        result["raw"] = body
        result["fields"] = parse_security_txt(body)
        result["key"] = check_security_txt_key(body, base)
        return result

    if not result["url"] and last_error:
        result["error"] = f"Could not reach {domain} ({last_error})"
    return result


def _check_mx_dane(domain, max_hosts=5):
    """TLSA records on each mail exchanger, per host.

    Returns the three states this codebase keeps apart. "No MX" is not a
    DANE failure: a domain that receives no mail has no mail hosts to
    secure, and reporting it as missing DANE would be advice about something
    that does not exist.
    """
    result = {"state": "not_applicable", "hosts": [], "reason": None,
              "with_dane": 0, "without_dane": 0}
    mx = _resolve(domain, "MX")
    if not mx:
        result["reason"] = "No MX records, so there are no mail hosts to secure"
        return result

    hosts = []
    for record in mx:
        parts = str(record).split()
        target = (parts[-1] if parts else "").rstrip(".")
        if target and target not in hosts:
            hosts.append(target)
    if hosts == [""] or not hosts:
        # A null MX (RFC 7505) is "this domain receives no mail", not a gap.
        result["reason"] = "Null MX: this domain receives no mail"
        return result

    result["state"] = "measured"
    for host in hosts[:max_hosts]:
        records = _resolve(f"_25._tcp.{host}", "TLSA")
        entry = {"host": host, "present": bool(records), "records": records}
        result["hosts"].append(entry)
        if records:
            result["with_dane"] += 1
        else:
            result["without_dane"] += 1
    if len(hosts) > max_hosts:
        result["truncated"] = len(hosts) - max_hosts
    return result


def _looks_like_html(body):
    stripped = body.lstrip()[:100].lower()
    return stripped.startswith("<!doctype") or stripped.startswith("<html") or "<head" in stripped


def _looks_like_env_file(body):
    return bool(_ENV_LINE_RE.search(body)) and not _looks_like_html(body)


def _get_following_safe_redirects(url, timeout=8, max_hops=5):
    """Fetch a URL, following redirects, checking the host at every hop.

    requests follows redirects on its own, but it does not care where they
    lead: a 302 to 127.0.0.1 or to a cloud metadata address would walk this
    scanner into the network it runs in, on the say-so of the site being
    scanned. Every hop is resolved and checked instead.

    Returns (response, final_url, hops) or (None, None, reason).
    """
    seen = []
    current = url
    for _ in range(max_hops + 1):
        host = urllib.parse.urlsplit(current).hostname
        if not host or not _safe_host(host):
            return None, None, f"{current} does not resolve to a public address"
        try:
            response = _get(current, timeout=timeout, allow_redirects=False)
        except Exception as exc:
            return None, None, type(exc).__name__
        if response.status_code not in (301, 302, 303, 307, 308):
            return response, current, seen
        location = response.headers.get("Location")
        if not location:
            return response, current, seen
        seen.append(current)
        current = urllib.parse.urljoin(current, location)
        if current in seen:
            return None, None, "redirect loop"
    return None, None, f"more than {max_hops} redirects"


def _probe_path(base, path, signatures, expects_html=False):
    # security.txt is the one path here where a redirect is a normal answer:
    # apex to www, or http to https, are both ordinary ways to serve it, and
    # RFC 9116 does not require it to be served without one. Reporting "no
    # security.txt" for a site that publishes one behind a 302 blames the
    # site for our own refusal to follow.
    #
    # Everywhere else the redirect stays unfollowed on purpose: a /.env that
    # redirects to a login page has not exposed anything, and following it
    # would turn that into a finding.
    if path.endswith("security.txt"):
        r, final_url, _hops = _get_following_safe_redirects(base + path, timeout=6)
        if r is None or r.status_code != 200:
            return None
    else:
        try:
            r = _get(base + path, timeout=6, allow_redirects=False)
        except Exception:
            return None
        if r.status_code != 200:
            return None
        final_url = base + path
    body = r.text[:6000] if r.content else ""
    # security.txt is a GOOD thing — track separately. Still requires a real
    # "Contact:" field (RFC 9116); otherwise a 200-status HTML fallback page
    # (soft 404) would be misreported as "security.txt present".
    if path.endswith("security.txt"):
        if signatures and any(sig in body for sig in signatures) and not _looks_like_html(body):
            # The body rides along so the RFC 9116 fields can be read without
            # a second request for a file we have already downloaded.
            return {"path": path, "status": r.status_code, "positive": True,
                    "body": body, "url": final_url}
        return None

    # Reject generic HTML fallback/soft-404 pages for paths that should never
    # legitimately be HTML — this is what caused false positives like /.env
    # matching on a stray "=" inside an unrelated HTML page.
    if not expects_html and _looks_like_html(body):
        return None

    if signatures is None:
        # .env-style paths: require real KEY=VALUE env-file lines.
        matched = _looks_like_env_file(body)
    else:
        matched = any(sig in body for sig in signatures)

    if matched:
        return {"path": path, "status": r.status_code,
                "size": len(r.content), "positive": False}
    return None


def _get_soft_404_baseline(base, timeout=6):
    """Probe a definitely-nonexistent path to detect soft-404 hosts.

    Many CDNs/hosts (e.g. Bunny) return HTTP 200 with a generic fallback page
    for ANY path instead of a real 404. Without this baseline, every entry in
    _ADMIN_PATHS would be reported as a "reachable admin endpoint" on such a
    host, since they'd all get the same 200 the baseline gets.
    """
    token = secrets.token_hex(8)
    try:
        r = _get(f"{base}/domainlens-baseline-{token}-probe", timeout=timeout, allow_redirects=False)
        body = r.text[:2000] if r.content else ""
        return r.status_code, len(body)
    except Exception:
        return None, None


def _probe_admin(base, path, baseline=(None, None)):
    baseline_status, baseline_size = baseline
    try:
        r = _get(base + path, timeout=6, allow_redirects=False)
        if r.status_code not in (200, 401, 403):
            return None
        body = r.text[:2000] if r.content else ""
        # Same status and near-identical body size as the nonexistent
        # baseline path means this host answers everything the same way —
        # not a real signal that this specific admin path exists.
        if (
            baseline_status is not None
            and r.status_code == baseline_status
            and baseline_size is not None
            and abs(len(body) - baseline_size) < 50
        ):
            return None
        return {"path": path, "status": r.status_code}
    except Exception:
        pass
    return None


def check_web_exposure(domain):
    result = {
        "success": False, "base_url": None,
        "cookies": [], "cors": {}, "methods": {},
        "sensitive_files": [], "admin_endpoints": [],
        "security_txt": False,
        "security_txt_key": None,
    }

    if not _safe_host(domain):
        result["error"] = "Host does not resolve to a public address"
        return result

    base = None
    resp = None
    for scheme in ("https", "http"):
        try:
            resp = _get(f"{scheme}://{domain}", timeout=8)
            base = f"{scheme}://{domain}"
            break
        except Exception:
            continue
    if not base:
        result["error"] = "No HTTP response"
        return result
    result["base_url"] = base

    # --- Cookie security flags ---
    for raw in _iter_set_cookie(resp):
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        result["cookies"].append({
            "name": name,
            "secure": "secure" in low,
            "httponly": "httponly" in low,
            "samesite": ("none" if "samesite=none" in low else
                         "lax" if "samesite=lax" in low else
                         "strict" if "samesite=strict" in low else None),
        })

    # --- CORS misconfiguration ---
    try:
        evil = "https://domainlens-cors-test.example"
        cr = _get(base, timeout=6, headers={"Origin": evil})
        acao = cr.headers.get("Access-Control-Allow-Origin", "")
        acac = cr.headers.get("Access-Control-Allow-Credentials", "")
        result["cors"] = {
            "allow_origin": acao,
            "allow_credentials": acac.lower() == "true",
            "reflects_origin": acao == evil,
            "wildcard": acao == "*",
        }
    except Exception:
        pass

    # --- Allowed HTTP methods ---
    try:
        opt = _get(base, timeout=6, method="OPTIONS")
        allow = opt.headers.get("Allow", "") or opt.headers.get("access-control-allow-methods", "")
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        result["methods"] = {
            "allow_header": allow,
            "methods": methods,
            "trace_enabled": "TRACE" in methods,
            "dangerous": [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")],
        }
    except Exception:
        pass

    # --- Sensitive files (light wordlist) ---
    security_txt_body = ""
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_probe_path, base, p, sigs, html): p
                   for p, sigs, html in _SENSITIVE_PATHS}
        for fut in concurrent.futures.as_completed(futures):
            try:
                r = fut.result()
                if r and r.get("positive") and r["path"].endswith("security.txt"):
                    result["security_txt"] = True
                    security_txt_body = r.get("body") or ""
                elif r and not r.get("positive"):
                    result["sensitive_files"].append(r)
            except Exception:
                continue

    # --- security.txt PGP key (RFC 9116 Encryption:) ---
    # Only when the file was actually found: with no security.txt there is no
    # field to follow, and a "key missing" line would be a second complaint
    # about the one thing already reported.
    if result["security_txt"]:
        try:
            result["security_txt_key"] = check_security_txt_key(security_txt_body, base)
        except Exception as exc:
            result["security_txt_key"] = {
                "state": "unmeasured",
                "reason": f"Key check failed: {type(exc).__name__}",
                "encryption_urls": [], "url": None,
                "armored": False, "private_key_published": False,
            }

    # --- Admin / debug endpoints ---
    baseline = _get_soft_404_baseline(base)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_probe_admin, base, p, baseline): p for p in _ADMIN_PATHS}
        for fut in concurrent.futures.as_completed(futures):
            try:
                r = fut.result()
                if r:
                    result["admin_endpoints"].append(r)
            except Exception:
                continue

    result["sensitive_files"].sort(key=lambda x: x["path"])
    result["admin_endpoints"].sort(key=lambda x: x["path"])
    result["success"] = True
    return result


# ---------------------------------------------------------------------------
# 3. DNS & mail gaps
# ---------------------------------------------------------------------------

def _spf_lookup_count(domain, seen=None, depth=0):
    """Count DNS-lookup-consuming SPF mechanisms (RFC 7208 limit = 10)."""
    if seen is None:
        seen = set()
    if depth > 10 or domain in seen:
        return 0
    seen.add(domain)
    txts = _resolve(domain, "TXT")
    spf = None
    for t in txts:
        c = t.strip('"')
        if c.lower().startswith("v=spf1"):
            spf = c
            break
    if not spf:
        return 0
    count = 0
    for mech in spf.split():
        m = mech.lower()
        if m.startswith(("include:", "a:", "mx:", "ptr:", "exists:")) or m in ("a", "mx", "ptr"):
            count += 1
            if m.startswith("include:"):
                target = mech.split(":", 1)[1]
                count += _spf_lookup_count(target, seen, depth + 1)
        elif m.startswith("redirect="):
            target = mech.split("=", 1)[1]
            count += 1 + _spf_lookup_count(target, seen, depth + 1)
    return count


# Control characters have no legitimate place in these policy records. A
# trailing newline is by far the most common: it rides along when the value
# is pasted into a DNS editor, and nothing shows it — the DNS UI renders the
# record as if it were fine, and dig prints it escaped as \010. The record is
# then silently invalid, so the policy it carries quietly stops working.
_TXT_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_CONTROL_NAMES = {
    0x09: "tab", 0x0a: "newline", 0x0d: "carriage return", 0x00: "null byte",
}

# (label, prefix) — prefix "" means the domain itself.
_POLICY_TXT_RECORDS = [
    ("SPF", ""),
    ("DMARC", "_dmarc"),
    ("MTA-STS", "_mta-sts"),
    ("TLS-RPT", "_smtp._tls"),
]


def _resolve_txt_raw(name):
    """TXT values as raw strings, not presentation format.

    _resolve() goes through to_text(), which escapes a stray newline to the
    literal characters \\010 — hiding the very defect this check looks for.
    """
    try:
        answers = _RESOLVER.resolve(name, "TXT")
    except Exception:
        return []
    values = []
    for rdata in answers:
        try:
            # A long TXT record is split into 255-byte chunks that are
            # concatenated by the consumer, so join before inspecting.
            values.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        except Exception:
            continue
    return values


def _describe_control_chars(value):
    found = []
    for ch in _TXT_CONTROL_RE.findall(value):
        code = ord(ch)
        name = _CONTROL_NAMES.get(code, f"0x{code:02x}")
        where = "at the end" if value.endswith(ch) else "inside the value"
        entry = f"{name} ({where})"
        if entry not in found:
            found.append(entry)
    return found


def check_txt_hygiene(domain, extra_names=None):
    """Flag control characters and stray whitespace in policy TXT records."""
    result = {"checked": [], "defects": []}
    targets = [(label, f"{prefix}.{domain}" if prefix else domain)
               for label, prefix in _POLICY_TXT_RECORDS]
    for label, name in (extra_names or []):
        targets.append((label, name))

    for label, name in targets:
        for value in _resolve_txt_raw(name):
            # Only inspect records that actually carry a policy, so unrelated
            # verification tokens on the apex are not dragged in.
            lowered = value.lower()
            if name == domain and not lowered.startswith("v=spf1"):
                continue
            result["checked"].append(name)
            problems = []
            controls = _describe_control_chars(value)
            if controls:
                problems.append("contains " + ", ".join(controls))
            elif value != value.strip():
                # Leading/trailing spaces are tolerated by most parsers but
                # still indicate a copy/paste accident worth knowing about.
                problems.append("has leading or trailing whitespace")
            if problems:
                result["defects"].append({
                    "record": label,
                    "name": name,
                    "problems": problems,
                    "preview": repr(value[-40:]),
                })
    return result


def check_dns_mail_gaps(domain):
    result = {"success": False}
    try:
        # AXFR zone transfer test — try each authoritative NS
        ns_list = [ns.rstrip(".") for ns in _resolve(domain, "NS")]
        axfr = {"tested": ns_list, "vulnerable": [], "records_leaked": 0}
        for ns in ns_list[:5]:
            try:
                ns_ips = _resolve(ns, "A")
                if not ns_ips:
                    continue
                ns_ip = ns_ips[0]
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5, lifetime=8))
                names = list(z.nodes.keys())
                axfr["vulnerable"].append({"nameserver": ns, "records": len(names)})
                axfr["records_leaked"] += len(names)
            except Exception:
                continue
        result["axfr"] = axfr

        # CAA records
        caa = _resolve(domain, "CAA")
        caa_tags = []
        for rec in caa:
            parts = rec.split(None, 2)
            if len(parts) >= 2:
                caa_tags.append(parts[1])
        result["caa"] = {
            "present": bool(caa),
            "records": caa,
            # RFC 8659 tag matching is case-insensitive, but real-world
            # validators (e.g. internet.nl) and some CAs treat tags
            # case-sensitively, so track both: whether an "issue" tag
            # exists at all, and whether any tag isn't lowercase as
            # published (a real case: a DNS provider's UI published
            # "Issue"/"Iodef" verbatim, which internet.nl rejected as
            # missing the required issue property).
            "has_issue_tag": any(t.lower() == "issue" for t in caa_tags),
            "non_lowercase_tags": sorted({t for t in caa_tags if t != t.lower()}),
        }

        # DANE / TLSA on 443
        tlsa = _resolve(f"_443._tcp.{domain}", "TLSA")
        result["tlsa"] = {"present": bool(tlsa), "records": tlsa}

        # Certificates actually issued, against the CAA record that says who
        # may. CAA is only consulted at issuance, so it can look correct
        # while a certificate exists that nobody asked for.
        rows, ct_error, _meta = _fetch_crtsh(domain)
        result["cert_transparency"] = cert_transparency.analyse(
            rows, caa, days=30, source_error=ct_error)

        # DANE on the mail hosts, which is the one that carries weight:
        # internet.nl scores it and the Dutch government requires it, while
        # DANE on 443 is barely deployed. The record lives on each MX host
        # at _25._tcp, not on the domain -- looking it up on the domain (as
        # the 443 check does) would report every mail domain as missing it.
        result["mx_dane"] = _check_mx_dane(domain)

        # SPF lookup count
        lookups = _spf_lookup_count(domain)
        result["spf_lookups"] = {
            "count": lookups,
            "over_limit": lookups > 10,
        }

        # DMARC subdomain policy
        dmarc_txt = _resolve(f"_dmarc.{domain}", "TXT")
        sp = None
        p = None
        for t in dmarc_txt:
            c = t.strip('"')
            if c.lower().startswith("v=dmarc1"):
                for part in c.split(";"):
                    part = part.strip().lower()
                    if part.startswith("sp="):
                        sp = part.split("=", 1)[1].strip()
                    elif part.startswith("p="):
                        p = part.split("=", 1)[1].strip()
        result["dmarc_subdomain"] = {
            "policy": p, "subdomain_policy": sp,
            # If sp is absent it inherits p; weak only when p is strong but sp explicitly none
            "weak_subdomain": sp == "none" and p in ("quarantine", "reject"),
        }

        # Wildcard DNS — a fixed unlikely label; if it resolves, a wildcard exists
        rand = "domainlens-wildcard-probe-zzq7x9"
        wildcard = bool(_resolve(f"{rand}.{domain}", "A"))
        result["wildcard_dns"] = wildcard

        # Stray control characters in the policy TXT records
        result["txt_hygiene"] = check_txt_hygiene(domain)

        result["success"] = True
    except Exception as exc:
        result["error"] = str(exc)[:200]
    return result


# ---------------------------------------------------------------------------
# 4. Info disclosure & tech fingerprinting
# ---------------------------------------------------------------------------

_TECH_HEADER_HINTS = {
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "ASP.NET version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-generator": "Generator",
    "x-drupal-cache": "Drupal",
    "x-magento-cache-debug": "Magento",
    "x-shopify-stage": "Shopify",
}

_TECH_COOKIE_HINTS = {
    "phpsessid": "PHP",
    "jsessionid": "Java (JSP/Servlet)",
    "asp.net_sessionid": "ASP.NET",
    "aspsessionid": "Classic ASP",
    "laravel_session": "Laravel (PHP)",
    "ci_session": "CodeIgniter (PHP)",
    "django": "Django (Python)",
    "csrftoken": "Django (Python)",
    "_rails": "Ruby on Rails",
    "connect.sid": "Node.js (Express)",
}

# Version-bearing Server strings worth flagging (leaks patch level)
_VERSION_RE = re.compile(r"\d+\.\d+")


def check_info_disclosure(domain):
    result = {"success": False, "technologies": [], "version_leaks": [],
              "disclosed_headers": {}}
    if not _safe_host(domain):
        result["error"] = "Host does not resolve to a public address"
        return result

    resp = None
    for scheme in ("https", "http"):
        try:
            resp = _get(f"{scheme}://{domain}", timeout=8)
            break
        except Exception:
            continue
    if resp is None:
        result["error"] = "No HTTP response"
        return result

    headers_lc = {k.lower(): v for k, v in resp.headers.items()}
    techs = set()

    # Header-based tech + version leaks
    server = headers_lc.get("server", "")
    if server:
        result["disclosed_headers"]["Server"] = server
        if _VERSION_RE.search(server):
            result["version_leaks"].append({"header": "Server", "value": server})
        techs.add(server.split("/")[0])

    for h, label in _TECH_HEADER_HINTS.items():
        if h in headers_lc:
            val = headers_lc[h]
            result["disclosed_headers"][label] = val
            techs.add(label)
            if _VERSION_RE.search(val):
                result["version_leaks"].append({"header": label, "value": val})

    # Cookie-based tech fingerprint
    cookie_hdr = ""
    try:
        cookie_hdr = " ".join(v for k, v in resp.headers.items() if k.lower() == "set-cookie")
    except Exception:
        pass
    cl = cookie_hdr.lower()
    for needle, label in _TECH_COOKIE_HINTS.items():
        if needle in cl:
            techs.add(label)

    # Generator meta tag in body
    try:
        body = resp.text[:20000]
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        if m:
            gen = m.group(1)
            techs.add(gen)
            result["disclosed_headers"]["Meta generator"] = gen
            if _VERSION_RE.search(gen):
                result["version_leaks"].append({"header": "Meta generator", "value": gen})
    except Exception:
        pass

    result["technologies"] = sorted(techs)
    result["success"] = True
    return result


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def run_security_audit(domain, force=False):
    """Run all four categories concurrently and return a combined dict."""
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {
            ex.submit(check_subdomain_takeover, domain, force=force): "subdomains",
            ex.submit(check_web_exposure, domain): "web_exposure",
            ex.submit(check_dns_mail_gaps, domain): "dns_mail",
            ex.submit(check_info_disclosure, domain): "info_disclosure",
        }
        for fut in concurrent.futures.as_completed(futures):
            key = futures[fut]
            try:
                out[key] = fut.result()
            except Exception as exc:
                out[key] = {"success": False, "error": str(exc)[:200]}
    return out


# ---------------------------------------------------------------------------
# Findings — turn raw audit results into severity-graded findings
# ---------------------------------------------------------------------------

def audit_findings(audit):
    """Return a list of severity-graded findings from a security audit dict."""
    findings = []

    # --- Subdomain takeover ---
    subs = audit.get("subdomains") or {}
    for t in subs.get("takeovers", []):
        sev = "critical" if t["confidence"] == "high" else "high"
        findings.append(_finding(
            sev, "Subdomain Takeover",
            f"Possible subdomain takeover: {t['subdomain']}",
            f"{t['subdomain']} has a dangling CNAME to {t['cname']} ({t['service']}). "
            + ("A takeover fingerprint was matched on the live response." if t["fingerprint_match"]
               else "The CNAME target returns NXDOMAIN, which is a strong takeover signal."),
            evidence=f"CNAME → {t['cname']} | target_resolves={t['target_resolves']} | http={t['http_status']}",
            fix=f"Remove the dangling DNS record for {t['subdomain']}, or re-claim the resource on {t['service']}.",
        ))
    for d in subs.get("dangling", []):
        if d.get("registrable") is False:
            # Provider-assigned name: measured as stale, and claimability is
            # not "unknown" but ruled out — kept apart so the operator reads a
            # cleanup task, not a takeover they need to race an attacker on.
            provider = d.get("provider") or "the hosting provider"
            note = d.get("provider_note") or "the provider controls the hostname"
            findings.append(_finding(
                "low", "Subdomain Takeover",
                f"Dangling CNAME: {d['subdomain']}",
                f"{d['subdomain']} is a CNAME to {d['cname']}, which returns NXDOMAIN — "
                f"the {provider} resource behind it is gone. This is a stale record to "
                f"clean up, not a claimable takeover: {note}, so a third party cannot "
                f"re-register the target.",
                evidence=f"CNAME → {d['cname']} (NXDOMAIN, provider-assigned)",
                fix=f"Remove the DNS record for {d['subdomain']}; the target is no longer in use.",
            ))
        else:
            findings.append(_finding(
                "medium", "Subdomain Takeover",
                f"Dangling CNAME: {d['subdomain']}",
                f"{d['subdomain']} is a CNAME to {d['cname']}, which returns NXDOMAIN. "
                "The provider is not in DomainLens's takeover-signature list, so this could "
                "not be confirmed as claimable, but a CNAME pointing at a non-existent "
                "target is a stale record and may be claimable by whoever can register it.",
                evidence=f"CNAME → {d['cname']} (NXDOMAIN)",
                fix=f"Remove the DNS record for {d['subdomain']} if the target is no longer in use.",
            ))
    # Scan-coverage limits (a truncated list, or an unreachable Certificate
    # Transparency source) are deliberately NOT findings. A finding is
    # something wrong with the scanned domain that the owner can act on;
    # crt.sh being down says nothing about their domain and cannot be fixed
    # by them, so listing it as an issue only pads the advice list. The
    # coverage caveat is reported alongside the subdomain result instead, so
    # "no takeovers found" is still never mistaken for a clean bill of health.

    # --- Web exposures ---
    web = audit.get("web_exposure") or {}
    for f in web.get("sensitive_files", []):
        findings.append(_finding(
            "critical", "Exposure",
            f"Sensitive file exposed: {f['path']}",
            f"The path {f['path']} is publicly readable and matched a known sensitive-content signature.",
            evidence=f"HTTP {f['status']}, {f.get('size', '?')} bytes",
            fix=f"Block public access to {f['path']} at the web server / deny dotfiles and backups.",
        ))
    cors = web.get("cors") or {}
    if cors.get("reflects_origin") and cors.get("allow_credentials"):
        findings.append(_finding(
            "high", "CORS",
            "CORS reflects arbitrary Origin with credentials",
            "The server reflects any Origin in Access-Control-Allow-Origin while allowing credentials — any site can read authenticated responses.",
            evidence=f"ACAO reflected, ACAC=true",
            fix="Never reflect arbitrary Origins with credentials. Use an explicit allowlist of trusted origins.",
        ))
    elif cors.get("wildcard") and cors.get("allow_credentials"):
        findings.append(_finding(
            "medium", "CORS",
            "CORS wildcard with credentials",
            "Access-Control-Allow-Origin is * together with credentials.",
            fix="Replace the wildcard with an explicit allowlist when credentials are needed.",
        ))
    methods = web.get("methods") or {}
    if methods.get("trace_enabled"):
        findings.append(_finding(
            "medium", "HTTP Methods",
            "HTTP TRACE enabled (Cross-Site Tracing)",
            "TRACE is enabled and can be abused for Cross-Site Tracing (XST) to steal headers/cookies.",
            evidence=methods.get("allow_header", ""),
            fix="Disable the TRACE method on the web server.",
        ))
    if methods.get("dangerous"):
        extra = [m for m in methods["dangerous"] if m != "TRACE"]
        if extra:
            findings.append(_finding(
                "low", "HTTP Methods",
                f"Potentially unsafe HTTP methods: {', '.join(extra)}",
                "Write/modify methods are advertised as allowed. Confirm they require authentication.",
                evidence=methods.get("allow_header", ""),
                fix="Restrict PUT/DELETE/PATCH to authenticated, authorized users only.",
            ))
    for c in web.get("cookies", []):
        problems = []
        if not c["secure"]:
            problems.append("no Secure")
        if not c["httponly"]:
            problems.append("no HttpOnly")
        if c["samesite"] is None:
            problems.append("no SameSite")
        if c["samesite"] == "none" and not c["secure"]:
            problems.append("SameSite=None without Secure")
        if problems:
            findings.append(_finding(
                "low", "Cookies",
                f"Cookie '{c['name']}' missing flags: {', '.join(problems)}",
                "Session cookies without Secure/HttpOnly/SameSite are exposed to interception and XSS theft.",
                fix="Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.",
            ))
    for a in web.get("admin_endpoints", []):
        if a["status"] == 200:
            findings.append(_finding(
                "medium", "Exposure",
                f"Admin/debug endpoint reachable: {a['path']}",
                f"{a['path']} returned HTTP 200 and may expose an administrative or debug interface.",
                fix=f"Restrict {a['path']} to trusted networks or require authentication.",
            ))
    if web.get("success") and not web.get("security_txt"):
        findings.append(_finding(
            "info", "Best Practice",
            "No security.txt published",
            "There is no /.well-known/security.txt, so researchers have no clear way to report vulnerabilities.",
            fix="Publish /.well-known/security.txt with a Contact field (RFC 9116).",
        ))

    # The PGP key behind Encryption:. Only states we actually established are
    # reported: "unmeasured" is our limitation, and putting it in the findings
    # list would read as a defect of the scanned site. "not_applicable" is the
    # operator's deliberate choice -- Encryption: is optional in RFC 9116, so
    # advising them to add one is advice they have already declined.
    key = web.get("security_txt_key") or {}
    if key.get("state") == "measured":
        if key.get("private_key_published"):
            findings.append(_finding(
                "critical", "Exposure",
                "security.txt Encryption: URL serves a PGP PRIVATE key",
                "The key published for encrypted reports is a private key. Anyone who "
                "fetched it can decrypt reports sent to this address and sign as its owner.",
                evidence=key.get("url"),
                fix="Remove the private key, revoke it, and publish only the exported public key.",
            ))
        elif not key.get("armored"):
            findings.append(_finding(
                "low", "Best Practice",
                "security.txt Encryption: URL does not serve a PGP public key",
                "The Encryption: field points at a URL that does not return an armoured "
                "PGP public key block, so a researcher following it cannot encrypt a report.",
                evidence=f"{key.get('url')} -- {key.get('reason')}",
                fix="Serve the armoured public key (-----BEGIN PGP PUBLIC KEY BLOCK-----) at that URL, or drop the Encryption: field.",
            ))

    # --- DNS & mail gaps ---
    dm = audit.get("dns_mail") or {}
    axfr = dm.get("axfr") or {}
    if axfr.get("vulnerable"):
        ns_names = ", ".join(v["nameserver"] for v in axfr["vulnerable"])
        findings.append(_finding(
            "critical", "DNS",
            "DNS zone transfer (AXFR) allowed",
            f"One or more nameservers allow unauthenticated zone transfers, leaking the full DNS zone ({axfr['records_leaked']} records).",
            evidence=f"Vulnerable NS: {ns_names}",
            fix="Restrict AXFR to authorized secondary nameservers only (allow-transfer ACL).",
        ))
    findings.extend(cert_transparency.findings(dm.get("cert_transparency"), _finding))

    # DANE on the mail hosts. Only reported when there are mail hosts: a
    # domain that receives no mail has nothing to secure here, and advice
    # about a mail server it does not run is advice it cannot act on.
    mx_dane = dm.get("mx_dane") or {}
    if mx_dane.get("state") == "measured":
        missing = [h["host"] for h in mx_dane.get("hosts", []) if not h.get("present")]
        if missing and not mx_dane.get("with_dane"):
            findings.append(_finding(
                "medium", "Email",
                "No DANE (TLSA) on the mail hosts",
                "None of this domain's mail exchangers publish a TLSA record, so a "
                "sending server cannot verify the certificate it is offered and "
                "STARTTLS can be stripped or spoofed without detection.",
                evidence="No _25._tcp TLSA on: " + ", ".join(missing),
                fix="Publish a TLSA record at _25._tcp.<mx-host> for each mail "
                    "exchanger, matching the certificate it serves. DNSSEC must be "
                    "signed for DANE to mean anything.",
            ))
        elif missing:
            findings.append(_finding(
                "medium", "Email",
                "DANE (TLSA) is missing on some mail hosts",
                "Some mail exchangers publish a TLSA record and some do not. A "
                "sender that reaches one of the unprotected hosts gets no "
                "verification, which is the same as having none at all.",
                evidence="Without TLSA: " + ", ".join(missing),
                fix="Publish a TLSA record at _25._tcp for every mail exchanger, "
                    "not only the primary.",
            ))

    caa = dm.get("caa") or {}
    if dm.get("success") and not caa.get("has_issue_tag"):
        if caa.get("present"):
            findings.append(_finding(
                "low", "DNS",
                "CAA record present but missing 'issue' property",
                "CAA records exist for this domain, but none of them define an 'issue' tag, so any Certificate Authority may still issue certificates for it.",
                evidence="; ".join(caa.get("records") or []),
                fix="Add a CAA record with the issue tag naming your allowed CA(s), e.g. 0 issue \"letsencrypt.org\".",
            ))
        else:
            findings.append(_finding(
                "low", "DNS",
                "No CAA record",
                "Without a CAA record, any Certificate Authority may issue certificates for this domain.",
                fix="Publish a CAA record naming your allowed CA(s), e.g. 0 issue \"letsencrypt.org\".",
            ))
    elif caa.get("non_lowercase_tags"):
        findings.append(_finding(
            "info", "DNS",
            "CAA property tag is not lowercase",
            "RFC 8659 defines CAA tag matching as case-insensitive, but some validators and Certificate Authorities treat tags case-sensitively in practice, so a capitalised tag (e.g. \"Issue\") may be ignored and treated as if no issue restriction exists.",
            evidence=", ".join(caa["non_lowercase_tags"]),
            fix="Republish the CAA record(s) with lowercase tags (issue, issuewild, iodef) for maximum compatibility.",
        ))
    spf = dm.get("spf_lookups") or {}
    if spf.get("over_limit"):
        findings.append(_finding(
            "high", "Email",
            f"SPF exceeds 10 DNS lookups ({spf['count']})",
            "SPF requires <=10 DNS lookups; over the limit yields a permerror and receivers ignore SPF entirely.",
            fix="Flatten includes or remove unused mechanisms to get under 10 lookups.",
        ))
    dmarc_sub = dm.get("dmarc_subdomain") or {}
    if dmarc_sub.get("weak_subdomain"):
        findings.append(_finding(
            "medium", "Email",
            "DMARC subdomain policy is weaker than domain policy",
            f"The main policy is p={dmarc_sub['policy']} but sp=none, so subdomains can still be spoofed.",
            fix="Set sp=reject (or remove sp so it inherits the strong p= policy).",
        ))
    if dm.get("wildcard_dns"):
        findings.append(_finding(
            "info", "DNS",
            "Wildcard DNS record present",
            "A wildcard (*) DNS record resolves arbitrary subdomains, which can mask takeovers and aid phishing.",
            fix="Remove the wildcard unless it is strictly required.",
        ))
    for defect in (dm.get("txt_hygiene") or {}).get("defects", []):
        findings.append(_finding(
            "medium", "DNS",
            f"Malformed {defect['record']} record: {'; '.join(defect['problems'])}",
            f"The TXT record at {defect['name']} {'; '.join(defect['problems'])}. "
            "Control characters usually arrive by pasting the value into a DNS "
            "editor along with a line break. Nothing displays them — the DNS "
            "panel shows the record as normal — but strict parsers reject the "
            "record, so the policy it carries silently stops applying.",
            evidence=f"ends with: {defect['preview']}",
            fix="Re-enter the record value without a trailing line break or stray whitespace.",
        ))

    # --- Info disclosure ---
    info = audit.get("info_disclosure") or {}
    for leak in info.get("version_leaks", []):
        findings.append(_finding(
            "low", "Info Disclosure",
            f"Version leaked in {leak['header']}",
            f"The server discloses a precise version ({leak['value']}), helping attackers match known CVEs.",
            fix=f"Strip or generalize the {leak['header']} header.",
        ))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings
