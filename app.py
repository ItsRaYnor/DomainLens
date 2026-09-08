"""
DomainLens - Domain Intelligence Toolkit
A comprehensive domain lookup and security analysis tool.
"""

import functools
import ipaddress
import hashlib
import json
import logging
import os
import re
import select
import socket
import time
import ssl
import concurrent.futures
import threading
from datetime import datetime, timezone
from urllib.parse import quote

import dns.resolver
import dns.reversename
import dns.dnssec
import dns.name
import dns.rdatatype
import dns.query
import dns.zone
import requests
import whois
from flask import Flask, render_template, request, jsonify, abort, redirect, url_for, session

import db
import recommendations
import scan_diff
import security_checks
import servicenow
import osint
import hubspot_cf
import ncsc_tls
import auth
import config as domainlens_config
import weak_auth
import js_scan
import active_scan
import scheduler as monitor_scheduler
import i18n as i18n_mod
import rapid7_import
import insightvm
import vuln_bridge
import servicenow_cmdb
import scim
import scim_oauth
import saml_sp
import web_security
import cdn_hardening
import version as app_version
import routes as route_modules
import dns_tools
import evidence
import ip_intel
import theming
import scan_cache
import scan_jobs
from settings.store import get_store
from settings.defaults import DEFAULT_SECURITY_HEADERS, DEFAULT_DKIM_SELECTORS, DEFAULT_SCAN_PORTS

log = logging.getLogger("domainlens")

app = Flask(__name__)


def _configure_trusted_proxies(flask_app):
    """Honour X-Forwarded-* only when explicitly told a proxy sits in front.

    Behind a reverse proxy every request otherwise arrives from the proxy's
    address, so the rate limiter treats all users as one client and one
    person hitting the limit locks everyone out. request.is_secure is false
    too, which keeps the session cookie from being marked Secure.

    This is off by default and counts hops rather than being a boolean,
    because trusting X-Forwarded-For when nothing sets it lets any client
    claim any address and walk straight past the rate limiter. Set it to the
    number of proxies you actually run (1 for a single Synology/nginx/Caddy
    in front).
    """
    try:
        hops = int(os.environ.get("DOMAINLENS_TRUSTED_PROXY_HOPS", "0"))
    except ValueError:
        hops = 0
    if hops <= 0:
        return False
    from werkzeug.middleware.proxy_fix import ProxyFix
    flask_app.wsgi_app = ProxyFix(
        flask_app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops, x_port=hops)
    log.info("Trusting X-Forwarded-* from %s proxy hop(s)", hops)
    return True


_trusting_proxy = _configure_trusted_proxies(app)
_settings = domainlens_config.load_settings()
domainlens_config.apply_database_env(_settings)
db.init_db()
auth.init_app(app)
scim.register_routes(app)
_settings_store = get_store(db_module=db)
logging.basicConfig(level=_settings.server()["log_level"])
try:
    _bootstrapped = domainlens_config.bootstrap_monitors(db)
    if _bootstrapped:
        log.info("Bootstrapped %s monitor(s) from config", _bootstrapped)
except Exception as exc:
    log.warning("Monitor bootstrap skipped: %s", exc)

_monitor_run_lock = threading.Lock()
_scheduler_started = False
_scheduler_stop = threading.Event()


def _reload_settings():
    global _settings
    _settings = domainlens_config.load_settings(force_reload=True, db_module=db)
    _settings_store.invalidate()
    return _settings


def _scan_config():
    return _reload_settings().scan()


def _scan_ports_map():
    ports = _scan_config().get("ports") or DEFAULT_SCAN_PORTS
    return {int(k): v for k, v in ports.items()}


def _security_headers_list():
    return list(_scan_config().get("security_headers") or DEFAULT_SECURITY_HEADERS)


def _dkim_selectors_list():
    return list(_scan_config().get("dkim_selectors") or DEFAULT_DKIM_SELECTORS)


def _monitor_import_types():
    types = _scan_config().get("monitor_import_types")
    if types:
        return set(types)
    return {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "PTR"}


def _benelux_geo_allow():
    codes = _scan_config().get("benelux_geo_allow") or ["NL", "DE", "BE"]
    return frozenset(codes)


@app.context_processor
def inject_i18n():
    from flask import has_request_context
    user = auth.current_user()
    general = _reload_settings().general()
    locale = i18n_mod.resolve_locale(request if has_request_context() else None, user, general)
    return {
        "t": lambda k, **kw: i18n_mod.t(k, locale, **kw),
        "locale": locale,
        "general": general,
        "supported_locales": i18n_mod.supported_locales(),
        "app_version": app_version.get_version(),
        "app_version_info": app_version.info(),
        "asset_token": _asset_token(),
        "update_repo": _update_repo(),
        **_inject_theme(user, general),
    }


def _inject_theme(user, general):
    """Theme attributes for <html>, resolved server-side.

    The CSP serves `script-src 'self'` with no `unsafe-inline`, so the usual
    inline bootstrap in <head> could never run — the page would paint light
    and then snap to dark. Rendering it here means there is nothing to flash.
    """
    from flask import has_request_context
    from markupsafe import Markup
    cookies = request.cookies if has_request_context() else {}
    resolved = theming.resolve(
        user=user,
        cookies=cookies,
        defaults=_reload_settings().appearance(),
    )
    return {
        "theme": resolved["theme"],
        "accent": resolved["accent"],
        # Marked safe only after theming.py has reduced it to a known theme
        # name and a six-digit hex colour; nothing else can reach it.
        "theme_attr": Markup(theming.html_attributes(resolved)),
    }


@functools.lru_cache(maxsize=1)
def _update_repo():
    """owner/repo used for commit links, from the same config as update checks."""
    try:
        import update_check
        return update_check._updates_config()["github_repo"]
    except Exception:
        return "ItsRaYnor/DomainLens"


@functools.lru_cache(maxsize=1)
def _asset_token():
    """Cache-busting token for static assets.

    The version string only changes on a release, so after a redeploy of the
    same version a browser would happily keep running the JS it cached from
    the previous image — the change is invisible until a hard refresh. The
    git revision changes on every build, so append it to static URLs.
    """
    return (app_version.get_git_revision() or app_version.get_version() or "dev")[:12]

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_valid_domain(domain):
    """Validate that input looks like a public domain name."""
    if not domain or len(domain) > 253:
        return False
    return _DOMAIN_RE.match(domain) is not None


def _is_private_ip(ip_str):
    """Return True if the IP is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


def _is_valid_ip(ip_str):
    """Validate that input is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _normalize_domain(domain):
    """Normalize a user-provided domain or hostname input."""
    if not isinstance(domain, str):
        return ""
    domain = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.rstrip("/")


def _safe_resolve_ip(domain):
    """Resolve domain to IP and reject private addresses."""
    ip = socket.gethostbyname(domain)
    if _is_private_ip(ip):
        raise ValueError("Target resolves to a private IP address")
    return ip


def _safe_error(exc):
    """Return a sanitised error message without leaking internals."""
    text = str(exc)
    for word in ("Traceback", "/home/", "/usr/", "File \""):
        if word in text:
            return "An internal error occurred"
    if len(text) > 300:
        text = text[:300]
    return text


def _parse_positive_int(value, default, minimum=1, maximum=525600):
    """Parse a bounded positive integer from user input."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(value):
    """Convert non-serializable types to strings."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _get_apex_domain(domain):
    """Return the zone apex by walking up labels until SOA is found.

    For 'shop.branch.example.com' this returns 'example.com'.
    Falls back to the last two labels if no SOA is found.
    """
    parts = domain.split(".")
    # No need to walk for a plain two-label domain
    if len(parts) <= 2:
        return domain
    for i in range(len(parts) - 2):
        candidate = ".".join(parts[i:])
        try:
            dns.resolver.resolve(candidate, "SOA")
            return candidate
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers):
            continue
        except Exception:
            break
    return ".".join(parts[-2:])


def _resolve(domain, rdtype):
    """Resolve DNS records, return list of strings."""
    try:
        answers = dns.resolver.resolve(domain, rdtype)
        return [r.to_text() for r in answers]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def lookup_whois(domain):
    """Return parsed WHOIS data."""
    try:
        w = whois.whois(domain)
        data = {}
        for key in (
            "domain_name", "registrar", "whois_server", "creation_date",
            "expiration_date", "updated_date", "name_servers", "status",
            "emails", "dnssec", "org", "address", "city", "state",
            "country", "registrant_postal_code",
            # The address a notice or takedown is actually sent to. ICANN
            # requires registrars to publish it, and without it a report has
            # nowhere to go.
            "registrar_abuse_contact_email", "registrar_abuse_contact_phone",
            "registrar_url", "registrar_iana_id", "reseller",
        ):
            val = getattr(w, key, None)
            if val is not None:
                data[key] = _clean(val)
        return {"success": True, "data": data}
    except Exception as exc:
        return {"success": False, "error": _safe_error(exc)}


# ---------------------------------------------------------------------------
# DNS Records
# ---------------------------------------------------------------------------

DNS_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR",
]

MONITOR_IMPORT_TYPES = _monitor_import_types()


def _record_owner_to_fqdn(name, origin):
    """Turn a zone owner name into a normalized fully-qualified domain."""
    origin = origin.rstrip(".")
    owner = str(name).rstrip(".")
    if not owner or owner == "@":
        return origin
    if owner.endswith(origin):
        return owner
    return f"{owner}.{origin}"


def _record_target_candidates(rdtype, text):
    """Extract hostnames from record content that could be monitored."""
    value = text.rstrip(".")
    if rdtype in {"CNAME", "NS", "PTR"}:
        return [value]
    if rdtype == "MX":
        parts = text.split()
        return [parts[-1].rstrip(".")] if parts else []
    if rdtype == "SRV":
        parts = text.split()
        return [parts[-1].rstrip(".")] if len(parts) >= 4 else []
    return []


def _zone_records_to_monitors(domain, zone_text):
    """Parse a DNS zone file and return monitor definitions."""
    origin = domain.rstrip(".")
    zone = dns.zone.from_text(zone_text, origin=origin, relativize=False, check_origin=False)
    monitors = []

    for name, node in zone.nodes.items():
        owner = _record_owner_to_fqdn(name, origin)
        for rdataset in node.rdatasets:
            rdtype = dns.rdatatype.to_text(rdataset.rdtype)
            if rdtype not in MONITOR_IMPORT_TYPES:
                continue
            for rdata in rdataset:
                raw_value = rdata.to_text()
                candidates = [owner]
                candidates.extend(_record_target_candidates(rdtype, raw_value))
                seen = set()
                for candidate in candidates:
                    normalized = _normalize_domain(candidate)
                    if normalized in seen or not _is_valid_domain(normalized):
                        continue
                    seen.add(normalized)
                    monitors.append(
                        {
                            "name": f"{normalized} ({rdtype})",
                            "domain": origin,
                            "target": normalized,
                            "record_type": rdtype,
                            "record_value": raw_value,
                            "source_type": "dns_import",
                            "source_label": f"Zone import: {origin}",
                            "provider": "zone_file",
                            "metadata": {
                                "record_name": owner,
                                "import_origin": origin,
                            },
                        }
                    )
    return monitors


def _ovh_signature(secret, payload):
    digest = hashlib.sha1(payload.encode("utf-8")).digest()
    return "$1$" + digest.hex()


def _ovh_request(method, path, *, endpoint, app_key, app_secret, consumer_key, body=None, timeout=20):
    """Perform an authenticated OVH API request."""
    endpoint = endpoint.rstrip("/")
    url = f"{endpoint}{path}"
    timestamp_resp = requests.get(f"{endpoint}/auth/time", timeout=timeout)
    timestamp_resp.raise_for_status()
    timestamp = str(timestamp_resp.json())
    body_text = "" if body is None else requests.models.complexjson.dumps(body, separators=(",", ":"))
    signature_payload = "+".join([app_secret, consumer_key, method.upper(), url, body_text, timestamp])
    headers = {
        "X-Ovh-Application": app_key,
        "X-Ovh-Consumer": consumer_key,
        "X-Ovh-Timestamp": timestamp,
        "X-Ovh-Signature": _ovh_signature(app_secret, signature_payload),
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    response = requests.request(method.upper(), url, headers=headers, data=body_text or None, timeout=timeout)
    response.raise_for_status()
    if response.content:
        return response.json()
    return None


def _ovh_records_to_monitors(zone_name, records):
    """Convert OVH record payloads into monitor definitions."""
    monitors = []
    for record in records:
        field_type = str(record.get("fieldType", "")).upper()
        if field_type not in MONITOR_IMPORT_TYPES:
            continue
        sub_domain = (record.get("subDomain") or "").strip()
        owner = zone_name if not sub_domain else f"{sub_domain}.{zone_name}"
        record_value = str(record.get("target") or record.get("fieldValue") or "").strip()
        candidates = [owner]
        candidates.extend(_record_target_candidates(field_type, record_value))
        seen = set()
        for candidate in candidates:
            normalized = _normalize_domain(candidate)
            if normalized in seen or not _is_valid_domain(normalized):
                continue
            seen.add(normalized)
            monitors.append(
                {
                    "name": f"{normalized} ({field_type})",
                    "domain": zone_name,
                    "target": normalized,
                    "record_type": field_type,
                    "record_value": record_value,
                    "source_type": "provider_api",
                    "source_label": f"OVHcloud API: {zone_name}",
                    "provider": "ovhcloud",
                    "metadata": {
                        "record_name": owner,
                        "ovh_record_id": record.get("id"),
                        "ttl": record.get("ttl"),
                    },
                }
            )
    return monitors

def lookup_dns(domain):
    """Return all common DNS records."""
    results = {}
    for rtype in DNS_RECORD_TYPES:
        records = _resolve(domain, rtype)
        if records:
            results[rtype] = records
    return results


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def lookup_reverse_dns(ip):
    """Return reverse DNS for an IP address."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        return [r.to_text() for r in answers]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# DNSSEC validation
# ---------------------------------------------------------------------------

def check_dnssec(domain):
    """Check if DNSSEC is enabled for the domain."""
    try:
        dns.name.from_text(domain)
        try:
            dns.resolver.resolve(domain, "DNSKEY")
            has_dnskey = True
        except Exception:
            has_dnskey = False

        try:
            dns.resolver.resolve(domain, "DS")
            has_ds = True
        except Exception:
            has_ds = False

        signed = has_dnskey and has_ds
        return {
            "signed": signed,
            "has_dnskey": has_dnskey,
            "has_ds": has_ds,
            "status": "DNSSEC enabled" if signed else "DNSSEC not fully configured",
        }
    except Exception as exc:
        return {"signed": False, "status": _safe_error(exc)}


# ---------------------------------------------------------------------------
# E-mail security: SPF, DMARC, DKIM, MTA-STS, TLSRPT
# ---------------------------------------------------------------------------

def check_spf(domain):
    """Check SPF record.

    RFC 7208 SS3.2: a domain must publish at most one SPF TXT record: two or
    more is a PermError and receivers ignore SPF entirely, regardless of how
    strong either individual record looks. Only reporting the first match
    (the old behaviour) hid this failure mode completely.
    """
    txts = _resolve(domain, "TXT")
    spf_records = [t.strip('"') for t in txts if t.strip('"').lower().startswith("v=spf1")]
    if not spf_records:
        return {"found": False, "pass": False}
    multiple = len(spf_records) > 1
    clean = spf_records[0]
    mechanisms = clean.split()
    has_all = any(m in ("-all", "~all", "?all") for m in mechanisms)
    strict = "-all" in mechanisms
    return {
        "found": True,
        "record": clean,
        "records": spf_records,
        "multiple_records": multiple,
        "has_all_mechanism": has_all,
        "strict": strict,
        "pass": has_all and not multiple,
    }


def check_dmarc(domain):
    """Check DMARC record.

    RFC 7489 SS6.6.3: if more than one _dmarc TXT record is found, receivers
    must ignore DMARC entirely for the domain — the policy silently doesn't
    apply even though a record "found" that looks fine on its own.
    """
    records = _resolve(f"_dmarc.{domain}", "TXT")
    dmarc_records = [r.strip('"') for r in records if r.strip('"').lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return {"found": False, "pass": False}
    multiple = len(dmarc_records) > 1
    clean = dmarc_records[0]
    policy = "none"
    for part in clean.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            policy = part.split("=", 1)[1].strip().lower()
    return {
        "found": True,
        "record": clean,
        "records": dmarc_records,
        "multiple_records": multiple,
        "policy": policy,
        "pass": policy in ("reject", "quarantine") and not multiple,
    }


def _parse_dkim_tags(record_text):
    tags = {}
    for part in record_text.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dkim(domain, selectors=None, extra_selectors=None):
    """Check common DKIM selectors, plus any caller-supplied extra ones.

    `selectors`, if given, fully replaces the built-in list (used internally/
    in tests). `extra_selectors` is checked IN ADDITION to the built-in list —
    this is how a user's saved custom selector (e.g. "zmail" for Zoho) gets
    checked without having to change the admin-wide default list.

    A selector name resolving to *any* TXT record used to count as "found",
    even if that record was unrelated (some other verification TXT squatting
    at the same name) or an explicitly revoked key (p= present but empty,
    per RFC 6376 SS3.6.1). Both now require an actual p= tag, and revoked
    keys are reported separately rather than counted as a working selector.
    """
    if selectors is None:
        selectors = _dkim_selectors_list()
    if extra_selectors:
        # Preserve order, drop duplicates.
        seen = set(selectors)
        selectors = list(selectors) + [s for s in extra_selectors if s not in seen and not seen.add(s)]
    found = []
    for sel in selectors:
        records = _resolve(f"{sel}._domainkey.{domain}", "TXT")
        if not records:
            continue
        record_text = records[0].strip('"')
        tags = _parse_dkim_tags(record_text)
        if "p" not in tags:
            # No p= tag: not a DKIM key record, just something else at this name.
            continue
        found.append({
            "selector": sel,
            "record": record_text,
            "revoked": tags["p"] == "",
        })
    active = [s for s in found if not s["revoked"]]
    return {"found": len(found) > 0, "selectors": found, "pass": len(active) > 0}


def check_mta_sts(domain):
    """Check the MTA-STS DNS record AND fetch the policy file it points to.

    A correct _mta-sts TXT record means nothing on its own — sending mail
    servers validate MTA-STS by fetching
    https://mta-sts.<domain>/.well-known/mta-sts.txt, and that host can be
    unreachable (wrong CNAME, no TLS, geo-blocked CDN Pull Zone, etc.) while
    the DNS record still looks perfectly valid. DNS-only checking reports
    "pass" in exactly that broken state. Note this only observes reachability
    from wherever DomainLens itself runs — a policy blocked for most of the
    world but reachable from DomainLens's own network would still misreport as
    OK, the same blind spot a single-vantage-point check always has.
    """
    records = _resolve(f"_mta-sts.{domain}", "TXT")
    dns_record = None
    for r in records:
        clean = r.strip('"')
        if "v=sts" in clean.lower() or "v=STSv1" in clean:
            dns_record = clean
            break
    if not dns_record:
        return {"found": False, "pass": False}

    result = {
        "found": True, "record": dns_record,
        "policy_reachable": False, "policy_valid": False, "pass": False,
    }
    try:
        resp = _http_request(
            f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
            allow_redirects=True, timeout=8,
        )
        result["policy_status_code"] = resp.status_code
        if resp.status_code == 200:
            result["policy_reachable"] = True
            body = resp.text[:4000]
            result["policy_content_type"] = resp.headers.get("Content-Type", "")
            directives = {}
            for line in body.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    directives[k.strip().lower()] = v.strip()
            has_version = directives.get("version", "").strip().upper() == "STSV1"
            has_mode = directives.get("mode", "").strip().lower() in ("enforce", "testing", "none")
            has_mx = "mx" in directives
            has_max_age = directives.get("max_age", "").strip().isdigit()
            result["policy_valid"] = has_version and has_mode and has_mx and has_max_age
            result["policy_mode"] = directives.get("mode")
    except Exception as exc:
        result["policy_error"] = _safe_error(exc)

    result["pass"] = result["policy_reachable"] and result["policy_valid"]
    return result


def check_tlsrpt(domain):
    """Check TLS-RPT DNS record, including whether it actually requests reports.

    RFC 8460 SS3: without an rua= target the record is syntactically present
    but requests nothing — no reports are ever generated or delivered.
    """
    records = _resolve(f"_smtp._tls.{domain}", "TXT")
    for r in records:
        clean = r.strip('"')
        if "v=tlsrpt" in clean.lower() or "v=TLSRPTv1" in clean:
            has_rua = "rua=" in clean.lower()
            return {"found": True, "record": clean, "has_rua": has_rua, "pass": has_rua}
    return {"found": False, "pass": False}


# ---------------------------------------------------------------------------
# SSL / TLS certificate
# ---------------------------------------------------------------------------

def check_ssl(domain, port=443):
    """Retrieve and analyse the SSL/TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            cert = s.getpeercert()
            cipher = s.cipher()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        san = []
        for _, value in cert.get("subjectAltName", ()):
            san.append(value)

        return {
            "success": True,
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_left,
            "expired": days_left < 0,
            "serial_number": cert.get("serialNumber"),
            "version": cert.get("version"),
            "san": san,
            "cipher": cipher[0] if cipher else None,
            "protocol": cipher[1] if cipher else None,
        }
    except Exception as exc:
        return {"success": False, "error": _safe_error(exc)}


# ---------------------------------------------------------------------------
# TLS Deep Scan (Qualys SSL Labs style)
# ---------------------------------------------------------------------------

# Map legacy protocol names to modern ssl.TLSVersion values.
# Entries are skipped silently if the version is disabled in the local OpenSSL build.
_TLS_VERSION_MAP = [
    ("TLS 1.0", "TLSv1"),
    ("TLS 1.1", "TLSv1_1"),
    ("TLS 1.2", "TLSv1_2"),
]
TLS_PROTOCOLS = [
    (name, getattr(ssl.TLSVersion, attr))
    for name, attr in _TLS_VERSION_MAP
    if hasattr(ssl.TLSVersion, attr)
]

WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"}


def _classify_cipher(cipher_name):
    upper = (cipher_name or "").upper()
    # Avoid matching the "DES" substring inside "ECDSA".
    if "NULL" in upper or "EXPORT" in upper or "ANON" in upper:
        return "insecure"
    if "RC4" in upper or "MD5" in upper or "3DES" in upper or "DES-CBC3" in upper:
        return "weak"
    if re.search(r"(?<![A-Z0-9])DES(?![A-Z0-9])", upper):
        return "weak"
    if "CCM8" in upper or "CCM-8" in upper or "CCM_8" in upper:
        return "weak"
    # OpenSSL "...-SHA" means SHA-1 (insufficient per NCSC).
    if re.search(r"(?<![A-Z0-9])SHA(?![A-Z0-9])", upper) and "SHA256" not in upper and "SHA384" not in upper and "SHA512" not in upper:
        return "weak"
    if "CHACHA" in upper:
        return "strong"
    if "AES" in upper and ("GCM" in upper or "CCM" in upper):
        return "strong"
    if "AES" in upper:
        return "acceptable"
    return "acceptable"


def _has_forward_secrecy(cipher_name):
    upper = (cipher_name or "").upper()
    if upper.startswith("TLS_AES_") or upper.startswith("TLS_CHACHA20"):
        return True  # TLS 1.3 suites always use ephemeral key exchange
    return "ECDHE" in upper or bool(re.search(r"(?<![E])DHE", upper))


def _test_protocol(domain, tls_version, port=443, timeout=5):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            s.connect((domain, port))
            cipher = s.cipher()
            return {
                "supported": True,
                "cipher": cipher[0] if cipher else None,
                "bits": cipher[2] if cipher else None,
                "protocol_version": cipher[1] if cipher else None,
            }
    except Exception:
        return {"supported": False}


def _test_tls13(domain, port=443, timeout=5):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            s.connect((domain, port))
            cipher = s.cipher()
            return {
                "supported": True,
                "cipher": cipher[0] if cipher else None,
                "bits": cipher[2] if cipher else None,
                "protocol_version": cipher[1] if cipher else None,
            }
    except Exception:
        return {"supported": False}


def _openssl_cipher_names():
    """Return OpenSSL cipher names, including weak suites disabled at default SECLEVEL."""
    names = set()
    for spec in ("ALL:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0", "ALL"):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.set_ciphers(spec)
            names.update(c["name"] for c in ctx.get_ciphers())
        except Exception:
            continue
    # Explicit suites commonly checked by internet.nl / NCSC Appendix B.
    names.update(
        [
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES128-CCM",
            "ECDHE-ECDSA-AES256-SHA384",
            "ECDHE-ECDSA-AES128-SHA256",
            "ECDHE-ECDSA-AES256-SHA",
            "ECDHE-ECDSA-AES128-SHA",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-SHA",
            "AES128-SHA",
            "DES-CBC3-SHA",
        ]
    )
    return sorted(names)


def _cipher_result(negotiated):
    if not negotiated:
        return None
    name, protocol, bits = negotiated[0], negotiated[1], negotiated[2]
    return {
        "name": name,
        "protocol": protocol,
        "bits": bits,
        "strength": _classify_cipher(name),
        "forward_secrecy": _has_forward_secrecy(name),
    }


def _enumerate_ciphers(domain, port=443, timeout=5):
    """
    Probe accepted cipher suites for TLS 1.2 and TLS 1.3 separately.

    Default OpenSSL clients often only negotiate one modern suite. internet.nl /
    NCSC compliance requires discovering outdated CBC/SHA suites as well, so we
    force TLS 1.2 + SECLEVEL=0 per candidate cipher.
    """
    accepted = []
    seen = set()

    def _add(result):
        if not result:
            return
        key = (result["name"], result.get("protocol"))
        if key in seen:
            return
        seen.add(key)
        accepted.append(result)

    def _try_tls12(name):
        try:
            tctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tctx.check_hostname = False
            tctx.verify_mode = ssl.CERT_NONE
            tctx.minimum_version = ssl.TLSVersion.TLSv1_2
            tctx.maximum_version = ssl.TLSVersion.TLSv1_2
            try:
                tctx.set_ciphers(f"{name}:@SECLEVEL=0")
            except ssl.SSLError:
                tctx.set_ciphers(name)
            with tctx.wrap_socket(
                socket.create_connection((domain, port), timeout=timeout),
                server_hostname=domain,
            ) as sock:
                negotiated = sock.cipher()
                # Only count if the server selected the cipher we offered alone.
                if negotiated and negotiated[0] == name:
                    return _cipher_result(negotiated)
                if negotiated:
                    return _cipher_result(negotiated)
        except Exception:
            return None
        return None

    def _try_tls13(name):
        try:
            tctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tctx.check_hostname = False
            tctx.verify_mode = ssl.CERT_NONE
            tctx.minimum_version = ssl.TLSVersion.TLSv1_3
            tctx.maximum_version = ssl.TLSVersion.TLSv1_3
            # TLS 1.3 cipher selection via set_ciphers is limited; probe by
            # connecting and recording the negotiated suite. Prefer offering one
            # suite when the OpenSSL build supports ciphersuites API.
            if hasattr(tctx, "set_ciphersuites"):
                try:
                    tctx.set_ciphersuites(name)
                except Exception:
                    pass
            with tctx.wrap_socket(
                socket.create_connection((domain, port), timeout=timeout),
                server_hostname=domain,
            ) as sock:
                return _cipher_result(sock.cipher())
        except Exception:
            return None

    tls12_names = [n for n in _openssl_cipher_names() if not n.startswith("TLS_")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        for result in executor.map(_try_tls12, tls12_names):
            _add(result)

    for suite in (
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_128_CCM_SHA256",
    ):
        _add(_try_tls13(suite))

    accepted.sort(key=lambda x: (-(x.get("bits") or 0), x["name"]))
    return accepted


def _is_tls13_suite(name, protocol=None):
    n = (name or "").upper()
    p = (protocol or "").upper()
    return (
        n.startswith("TLS_AES_")
        or n.startswith("TLS_CHACHA20")
        or n.startswith("TLS_AES")
        or "TLSV1.3" in p
        or p == "TLSV1.3"
    )


def _negotiate_tls12_ciphers(domain, port, openssl_cipher_list, timeout=5):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(openssl_cipher_list)
    except ssl.SSLError:
        ctx.set_ciphers(openssl_cipher_list.replace(":@SECLEVEL=0", ""))
    with ctx.wrap_socket(
        socket.create_connection((domain, port), timeout=timeout),
        server_hostname=domain,
    ) as sock:
        return sock.cipher()


# OpenSSL → IANA names for internet.nl-style reporting (common TLS 1.2 suites).
_OPENSSL_TO_IANA = {
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-CCM": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    "ECDHE-ECDSA-AES256-CCM": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "ECDHE-ECDSA-AES128-CCM8": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    "ECDHE-ECDSA-AES256-CCM8": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    "ECDHE-ECDSA-AES128-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-ECDSA-AES256-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES128-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-RSA-AES256-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "ECDHE-RSA-AES128-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-AES256-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "DHE-RSA-AES128-GCM-SHA256": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "DHE-RSA-AES256-GCM-SHA384": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "DHE-RSA-CHACHA20-POLY1305": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "DHE-RSA-AES128-CCM": "TLS_DHE_RSA_WITH_AES_128_CCM",
    "DHE-RSA-AES256-CCM": "TLS_DHE_RSA_WITH_AES_256_CCM",
    "AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "AES128-SHA256": "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "AES256-SHA256": "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
}


def openssl_to_iana(name):
    """Best-effort OpenSSL cipher name → IANA TLS_* name for reports."""
    if not name:
        return None
    if str(name).startswith("TLS_"):
        return name
    return _OPENSSL_TO_IANA.get(name, name)


def check_cipher_order(domain, port=443, accepted=None, timeout=5):
    """
    internet.nl / NCSC cipher-order check (TLS 1.2).

    The server must enforce a security-descending preference: Good/Sufficient
    before To-be-phased-out / Insufficient. Not applicable when only
    Good/Sufficient suites are offered.

    Method: pairwise negotiation of each (phase-out/insufficient, good/sufficient)
    pair. Offering the full suite list is insufficient — a server can put GCM
    first overall yet still rank CBC-SHA384 above AES-CCM (a common
    internet.nl cipher-order finding).
    """
    accepted = accepted or []
    tls12 = []
    for item in accepted:
        name = item.get("name") or ""
        if not name or _is_tls13_suite(name, item.get("protocol")):
            continue
        level = ncsc_tls.classify_cipher_suite(name)["level"]
        tls12.append({"name": name, "level": level})

    better = [
        c["name"]
        for c in tls12
        if c["level"] in {ncsc_tls.LEVEL_GOOD, ncsc_tls.LEVEL_SUFFICIENT}
    ]
    worse = [
        c["name"]
        for c in tls12
        if c["level"] in {ncsc_tls.LEVEL_PHASED_OUT, ncsc_tls.LEVEL_INSUFFICIENT}
    ]

    if not worse:
        return {
            "applicable": False,
            "pass": True,
            "reason": "only_good_or_sufficient",
            "detail": "Cipher order check is not applicable when only Good/Sufficient suites are offered.",
        }
    if not better:
        return {
            "applicable": False,
            "pass": False,
            "reason": "no_good_or_sufficient",
            "detail": "No Good/Sufficient TLS 1.2 suites available to prefer over phase-out/insufficient suites.",
            "worse_suites": worse,
        }

    # Prefer AEAD suites as the "expected" pick (matches internet.nl examples:
    # AES_128_CCM over CBC-SHA384). CCM before GCM/ChaCha for stable reporting.
    def _better_rank(name):
        u = name.upper()
        if "CCM" in u and "CCM8" not in u and "CCM_8" not in u:
            return (0, name)
        if "GCM" in u or "CHACHA" in u or "POLY1305" in u:
            return (1, name)
        if "CCM8" in u or "CCM_8" in u:
            return (2, name)
        return (3, name)

    better_sorted = sorted(better, key=_better_rank)
    # Phase-out before insufficient when scanning for the first deviation —
    # internet.nl reported CBC-SHA384 (phase out) vs CCM, not SHA1.
    worse_sorted = sorted(
        worse,
        key=lambda n: (
            0 if ncsc_tls.classify_cipher_suite(n)["level"] == ncsc_tls.LEVEL_PHASED_OUT else 1,
            n,
        ),
    )

    errors = []
    probes_ok = 0
    # Pairwise: for each weaker suite, see if the server ranks it above any
    # Good/Sufficient suite. Stop at the first deviation (internet.nl style).
    for weak_name in worse_sorted:
        for strong_name in better_sorted:
            # Offer strong first in the client list. If the server still picks
            # weak, it is enforcing a non-security-descending server order.
            cipher_list = f"{strong_name}:{weak_name}:@SECLEVEL=0"
            try:
                negotiated = _negotiate_tls12_ciphers(
                    domain, port, cipher_list, timeout=timeout
                )
            except Exception as exc:
                errors.append(_safe_error(exc))
                continue

            chosen = negotiated[0] if negotiated else None
            if not chosen:
                continue
            probes_ok += 1
            if chosen == weak_name:
                chosen_level = ncsc_tls.classify_cipher_suite(chosen)["level"]
                expected_level = ncsc_tls.classify_cipher_suite(strong_name)["level"]
                chosen_iana = openssl_to_iana(chosen)
                expected_iana = openssl_to_iana(strong_name)
                return {
                    "applicable": True,
                    "pass": False,
                    "reason": "prefers_weaker",
                    "server_preferred": chosen,
                    "server_preferred_iana": chosen_iana,
                    "server_preferred_level": chosen_level,
                    "expected_preferred": strong_name,
                    "expected_preferred_iana": expected_iana,
                    "expected_preferred_level": expected_level,
                    "better_suites": better_sorted,
                    "worse_suites": worse_sorted,
                    "detail": (
                        f"Server preferred {chosen_iana or chosen} "
                        f"({chosen_level.replace('_', ' ')}) over "
                        f"{expected_iana or strong_name} ({expected_level}). "
                        "The server is not enforcing a security-descending cipher suite order "
                        "(internet.nl / NCSC)."
                    ),
                }

    if probes_ok == 0:
        return {
            "applicable": True,
            "pass": None,
            "reason": "probe_failed",
            "error": errors[0] if errors else "No pairwise cipher negotiations succeeded",
            "better_suites": better_sorted,
            "worse_suites": worse_sorted,
        }

    # Optional confirmation: server picks a Good/Sufficient suite when the
    # client prefers all weak suites first.
    offered = worse_sorted + better_sorted
    cipher_list = ":".join(offered) + ":@SECLEVEL=0"
    chosen = None
    try:
        negotiated = _negotiate_tls12_ciphers(domain, port, cipher_list, timeout=timeout)
        chosen = negotiated[0] if negotiated else None
    except Exception as exc:
        if errors:
            return {
                "applicable": True,
                "pass": None,
                "reason": "probe_failed",
                "error": _safe_error(exc),
                "better_suites": better_sorted,
                "worse_suites": worse_sorted,
            }

    expected = better_sorted[0]
    chosen_level = ncsc_tls.classify_cipher_suite(chosen or "")["level"] if chosen else None
    return {
        "applicable": True,
        "pass": True,
        "reason": "prefers_stronger",
        "server_preferred": chosen,
        "server_preferred_iana": openssl_to_iana(chosen),
        "server_preferred_level": chosen_level,
        "expected_preferred": expected,
        "expected_preferred_iana": openssl_to_iana(expected),
        "expected_preferred_level": ncsc_tls.classify_cipher_suite(expected)["level"],
        "better_suites": better_sorted,
        "worse_suites": worse_sorted,
        "detail": "Server prefers Good/Sufficient cipher suites over phase-out/insufficient ones.",
    }


def _check_ocsp_stapling(domain, port=443, timeout=10):
    """Whether the server staples an OCSP response. None when undetermined.

    This used to probe a stdlib ssl.SSLContext for set_ocsp_client_callback,
    which is a pyOpenSSL method that stdlib ssl does not have. The guard was
    therefore never true and the function returned False without opening a
    connection — so every domain was reported as having stapling disabled,
    whether it did or not.

    Requesting a stapled response needs OpenSSL's status_request extension,
    which stdlib ssl does not expose at all, so this genuinely requires
    pyOpenSSL. Where that is unavailable the answer is None (unknown) rather
    than a confident False, because an unverifiable claim is worse than an
    absent one.
    """
    try:
        from OpenSSL import SSL
    except ImportError:
        return None

    staple = {"data": None}

    def _ocsp_cb(conn, ocsp_data, user_data):
        staple["data"] = ocsp_data
        return True

    sock = None
    try:
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_ocsp_client_callback(_ocsp_cb)
        sock = socket.create_connection((domain, port), timeout=timeout)
        conn = SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(domain.encode("idna"))
        conn.request_ocsp()
        conn.set_connect_state()

        # A socket with a timeout is in non-blocking mode as far as OpenSSL is
        # concerned, so the handshake reports WantRead instead of waiting.
        # Drive it with select until it completes or the deadline passes.
        deadline = time.monotonic() + timeout
        while True:
            try:
                conn.do_handshake()
                break
            except (SSL.WantReadError, SSL.WantWriteError) as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("TLS handshake timed out") from exc
                want_write = isinstance(exc, SSL.WantWriteError)
                select.select(
                    [] if want_write else [sock],
                    [sock] if want_write else [],
                    [], remaining,
                )
        try:
            conn.shutdown()
        except Exception:
            pass  # the peer may close first; the staple is already known
        return bool(staple["data"])
    except Exception:
        # A handshake failure says nothing about stapling support.
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _check_tls_compression(domain, port=443):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            return s.compression() is not None
    except Exception:
        return False


def _get_cert_details(domain, port=443):
    result = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        san = [v for _, v in cert.get("subjectAltName", ())]

        result = {
            "success": True,
            "subject": subject,
            "issuer": issuer,
            "common_name": subject.get("commonName", ""),
            "issuer_org": issuer.get("organizationName", issuer.get("commonName", "")),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_left,
            "expired": days_left < 0,
            "serial_number": cert.get("serialNumber", ""),
            "version": cert.get("version", ""),
            "san": san,
            "san_count": len(san),
            "wildcard": any(s.startswith("*.") for s in san),
            "self_signed": subject == issuer,
            # Authority Information Access. Let's Encrypt stopped issuing an
            # OCSP URI in 2025 and retired its responders, so many current
            # certificates cannot be stapled at all. Without this the scan
            # could not tell "stapling is off" from "there is nothing to
            # staple", and reported the second as the first.
            "ocsp_uris": list(cert.get("OCSP") or ()),
            "ca_issuer_uris": list(cert.get("caIssuers") or ()),
        }
        key_info = _peer_cert_key_info(domain, port)
        if key_info:
            result.update(key_info)
    except ssl.SSLCertVerificationError as exc:
        result = {"success": False, "trusted": False, "error": _safe_error(exc)}
        key_info = _peer_cert_key_info(domain, port)
        if key_info:
            result.update(key_info)
    except Exception as exc:
        result = {"success": False, "error": _safe_error(exc)}
    return result


def _peer_cert_key_info(domain, port=443):
    """Best-effort public key type/size for NCSC Table 3/4 checks."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(
            socket.create_connection((domain, port), timeout=10),
            server_hostname=domain,
        ) as sock:
            der = sock.getpeercert(binary_form=True)
        if not der:
            return {}
        try:
            import subprocess

            proc = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
                input=der,
                capture_output=True,
                timeout=5,
                check=False,
            )
            text = (proc.stdout or b"").decode("utf-8", errors="replace")
            info = {}
            if "Public Key Algorithm: rsaEncryption" in text:
                info["key_type"] = "RSA"
            elif "Public Key Algorithm: id-ecPublicKey" in text or "ASN1 OID" in text:
                info["key_type"] = "EC"
            m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
            if m:
                info["key_bits"] = int(m.group(1))
            return info
        except Exception:
            return {}
    except Exception:
        return {}


def _http_request(url, *, allow_redirects=False, method="GET", timeout=10):
    """Browser-like HTTP request used for header / redirect / HSTS checks."""
    headers = {
        "User-Agent": _BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,nl;q=0.8",
    }
    return requests.request(
        method,
        url,
        headers=headers,
        timeout=timeout,
        allow_redirects=allow_redirects,
    )


# Common Benelux / edge allowlists for geo-restricted sites (configurable).
_BENELUX_GEO_ALLOW = _benelux_geo_allow()


def _request_country_from_headers(headers):
    """Best-effort client country code reported by CDN/WAF edges."""
    if not headers:
        return None
    for key in ("CDN-RequestCountryCode", "CF-IPCountry", "CloudFront-Viewer-Country"):
        value = headers.get(key)
        if value and len(str(value).strip()) == 2:
            return str(value).strip().upper()
    return None


def _geo_block_note(country):
    """Human-readable note when the probe country is outside a Benelux allowlist."""
    if not country:
        return (
            "CDN/WAF blocked this probe; HSTS and security headers are inconclusive "
            "from this vantage point."
        )
    if country in _BENELUX_GEO_ALLOW:
        return (
            f"CDN/WAF returned a block from probe country {country}. "
            "Headers remain inconclusive."
        )
    return (
        f"CDN geo-blocked this probe (request country {country}; "
        "site may allow only NL/DE/BE). "
        "HSTS/headers are inconclusive here — verify from NL/DE/BE or internet.nl."
    )


def _response_access_blocked(resp):
    """
    Detect CDN/WAF geo or bot blocks where security headers are often omitted.

    BunnyCDN/Cloudflare can return 403 from blocked regions without HSTS, which
    must not be treated as 'HSTS missing'. Many Benelux sites allow only NL/DE/BE.
    """
    if resp is None:
        return True, "no_response", None
    status = resp.status_code
    server = (resp.headers.get("Server") or "").lower()
    pull_zone = resp.headers.get("CDN-PullZone") or resp.headers.get("CDN-RequestId")
    cf_ray = resp.headers.get("CF-Ray")
    country = _request_country_from_headers(resp.headers)
    if status in {401, 403, 429, 503} and (
        "bunnycdn" in server
        or "cloudflare" in server
        or pull_zone
        or cf_ray
    ):
        detail = f"cdn_blocked_{status}"
        if country:
            detail += f"_{country}"
            if country not in _BENELUX_GEO_ALLOW:
                detail += "_geo"
        return True, detail, country
    if status == 403:
        return True, "http_403", country
    return False, None, country


def _probe_hsts(domain):
    """
    Probe Strict-Transport-Security.

    internet.nl checks HSTS on first contact (before redirects). We try that
    first, then a redirected request. If the edge blocks us, return enabled=None.
    """
    result = {
        "enabled": None,
        "value": "",
        "preload": False,
        "include_subdomains": False,
        "max_age": None,
        "blocked": False,
        "block_reason": None,
        "block_detail": None,
        "request_country": None,
        "status_code": None,
        "checked_url": f"https://{domain}/",
    }
    responses = []
    for allow_redirects in (False, True):
        for method in ("HEAD", "GET"):
            try:
                resp = _http_request(
                    f"https://{domain}/",
                    allow_redirects=allow_redirects,
                    method=method,
                )
                responses.append(resp)
                hsts = resp.headers.get("Strict-Transport-Security") or ""
                if hsts:
                    result["enabled"] = True
                    result["value"] = hsts
                    result["preload"] = "preload" in hsts.lower()
                    result["include_subdomains"] = "includesubdomains" in hsts.lower()
                    m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
                    if m:
                        result["max_age"] = int(m.group(1))
                    result["status_code"] = resp.status_code
                    result["blocked"] = False
                    result["block_reason"] = None
                    result["request_country"] = _request_country_from_headers(resp.headers)
                    return result
            except Exception:
                continue

    # No HSTS observed — distinguish block vs truly missing.
    if responses:
        resp = responses[0]
        result["status_code"] = resp.status_code
        blocked, reason, country = _response_access_blocked(resp)
        result["request_country"] = country
        if blocked:
            result["enabled"] = None
            result["blocked"] = True
            result["block_reason"] = reason
            result["block_detail"] = _geo_block_note(country)
            return result
        result["enabled"] = False
        return result

    result["enabled"] = None
    result["blocked"] = True
    result["block_reason"] = "request_failed"
    result["block_detail"] = _geo_block_note(None)
    return result


def _calculate_tls_grade(protocols, ciphers, cert, has_ocsp, has_compression, has_hsts):
    score = 100
    warnings = []

    if not cert.get("success"):
        return "T", ["Certificate not trusted"]
    if cert.get("expired"):
        return "T", ["Certificate expired"]
    if cert.get("self_signed"):
        score -= 40
        warnings.append("Self-signed certificate")

    proto_map = {p["name"]: p["supported"] for p in protocols}
    if proto_map.get("TLS 1.0"):
        score -= 15
        warnings.append("TLS 1.0 supported (deprecated)")
    if proto_map.get("TLS 1.1"):
        score -= 10
        warnings.append("TLS 1.1 supported (deprecated)")
    if not proto_map.get("TLS 1.2") and not proto_map.get("TLS 1.3"):
        score -= 30
        warnings.append("Neither TLS 1.2 nor 1.3 supported")
    if not proto_map.get("TLS 1.3"):
        score -= 5
        warnings.append("TLS 1.3 not supported")

    has_weak = any(c["strength"] in ("weak", "insecure") for c in ciphers)
    has_fs = any(c["forward_secrecy"] for c in ciphers)
    all_fs = all(c["forward_secrecy"] for c in ciphers) if ciphers else False

    if has_weak:
        score -= 20
        warnings.append("Weak cipher suites accepted")
    if not has_fs:
        score -= 15
        warnings.append("No forward secrecy")

    if has_compression:
        score -= 15
        warnings.append("TLS compression enabled (CRIME vulnerable)")

    if not has_ocsp:
        score -= 5
        warnings.append("No OCSP stapling")

    # has_hsts may be None when a CDN/WAF blocked the HTTP probe.
    if has_hsts is False:
        score -= 5
        warnings.append("HSTS not set")
    elif has_hsts is None:
        warnings.append("HSTS could not be verified (HTTP probe blocked)")

    if score >= 95 and has_hsts and all_fs and not has_weak:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return grade, warnings


# NCSC §3.3.5 / internet.nl: TLS 1.2 signature hash for key-exchange (not cipher PRF).
# OpenSSL -sigalgs probes; classification per RFC 9155 / NCSC 2025-05.
_SIG_HASH_PROBES = (
    ("SHA1", "ECDSA+SHA1:RSA+SHA1", ncsc_tls.LEVEL_INSUFFICIENT),
    ("SHA224", "ECDSA+SHA224:RSA+SHA224", ncsc_tls.LEVEL_PHASED_OUT),
    ("SHA256", "ECDSA+SHA256:RSA+SHA256:RSA-PSS+SHA256", ncsc_tls.LEVEL_GOOD),
    ("SHA384", "ECDSA+SHA384:RSA+SHA384:RSA-PSS+SHA384", ncsc_tls.LEVEL_GOOD),
    ("SHA512", "ECDSA+SHA512:RSA+SHA512:RSA-PSS+SHA512", ncsc_tls.LEVEL_GOOD),
)


def _resolve_tls_endpoints(domain):
    """Return unique (family, address) targets for TLS probes (A + AAAA)."""
    endpoints = []
    seen = set()
    for rtype, family in (("A", "IPv4"), ("AAAA", "IPv6")):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rr in answers:
                addr = rr.to_text().strip()
                if addr and addr not in seen:
                    seen.add(addr)
                    endpoints.append({"family": family, "address": addr})
        except Exception:
            continue
    if not endpoints:
        endpoints.append({"family": "hostname", "address": domain})
    return endpoints


def _openssl_peer_signing_digest(domain, port, connect_host, sigalgs, timeout=8):
    """
    Run openssl s_client TLS 1.2 with a restricted SignatureAlgorithms list.
    Returns peer signing digest name (e.g. SHA1) or None on failure.
    """
    import subprocess

    connect = f"{connect_host}:{port}"
    # Bracket IPv6 literals for openssl -connect.
    if ":" in connect_host and not connect_host.startswith("["):
        connect = f"[{connect_host}]:{port}"
    cmd = [
        "openssl", "s_client",
        "-connect", connect,
        "-servername", domain,
        "-tls1_2",
        "-sigalgs", sigalgs,
        "-cipher", "DEFAULT:@SECLEVEL=0",
        "-brief",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    text = (proc.stdout or b"").decode("utf-8", errors="replace")
    text += "\n" + (proc.stderr or b"").decode("utf-8", errors="replace")
    if "Cipher is (NONE)" in text or "Cipher    : 0000" in text:
        return None
    m = re.search(r"Peer signing digest:\s*(\S+)", text, re.IGNORECASE)
    if not m:
        m = re.search(r"Hash used:\s*(\S+)", text, re.IGNORECASE)
    if not m:
        # Fallback: some builds only print under -msg; treat successful TLS 1.2
        # handshake with our restricted -sigalgs as acceptance of that hash family.
        if re.search(r"Protocol(?: version)?\s*:\s*TLSv1\.2", text, re.IGNORECASE) and "Cipher is (NONE)" not in text:
            # Infer from first offered hash token (ECDSA+SHA1 → SHA1)
            first = (sigalgs.split(":")[0] or "").upper()
            if "+" in first:
                return first.split("+", 1)[1]
        return None
    return m.group(1).upper().replace("-", "")


def check_tls_signature_hashes(domain, port=443, timeout=8, endpoints=None):
    """
    internet.nl / NCSC §3.3.5: hash functions for TLS 1.2 key-exchange signatures.

    Distinct from cipher-suite names ending in -SHA / -SHA256 (PRF/MAC). Probes
    OpenSSL SignatureAlgorithms (-sigalgs) per A/AAAA address.
    """
    result = {
        "applicable": True,
        "pass": True,
        "evaluated": False,
        "insufficient": [],
        "phased_out": [],
        "good": [],
        "by_address": [],
        "detail": None,
    }
    endpoints = endpoints or _resolve_tls_endpoints(domain)
    # Skip if TLS 1.2 is unavailable (check applies to TLS 1.2 only).
    try:
        tls12_ok = _test_protocol(domain, ssl.TLSVersion.TLSv1_2, port).get("supported")
    except Exception:
        tls12_ok = True
    if not tls12_ok:
        result["applicable"] = False
        result["pass"] = True
        result["detail"] = "Signature-hash check applies to TLS 1.2 only; TLS 1.2 not offered."
        return result

    insufficient = set()
    phased_out = set()
    good = set()
    by_address = []

    for ep in endpoints:
        addr = ep["address"]
        accepted = []
        probe_errors = 0
        for hash_name, sigalgs, level in _SIG_HASH_PROBES:
            digest = _openssl_peer_signing_digest(
                domain, port, addr, sigalgs, timeout=timeout
            )
            if not digest:
                probe_errors += 1
                continue
            # Normalize digest labels (SHA1, SHA256, …)
            label = digest.upper().replace("_", "")
            if label.startswith("SHA"):
                accepted.append({"hash": label, "level": level, "offered": hash_name})
                if level == ncsc_tls.LEVEL_INSUFFICIENT:
                    insufficient.add(label)
                elif level == ncsc_tls.LEVEL_PHASED_OUT:
                    phased_out.add(label)
                elif level == ncsc_tls.LEVEL_GOOD:
                    good.add(label)

        row = {
            "address": addr,
            "family": ep.get("family"),
            "accepted": accepted,
            "insufficient": sorted({a["hash"] for a in accepted if a["level"] == ncsc_tls.LEVEL_INSUFFICIENT}),
            "phased_out": sorted({a["hash"] for a in accepted if a["level"] == ncsc_tls.LEVEL_PHASED_OUT}),
            "good": sorted({a["hash"] for a in accepted if a["level"] == ncsc_tls.LEVEL_GOOD}),
        }
        if not accepted and probe_errors >= len(_SIG_HASH_PROBES):
            row["reachable"] = False
            row["note"] = "Endpoint unreachable or TLS 1.2 probe failed from this scanner"
        else:
            row["reachable"] = True
        by_address.append(row)

    result["evaluated"] = True
    result["by_address"] = by_address
    result["insufficient"] = sorted(insufficient)
    result["phased_out"] = sorted(phased_out)
    result["good"] = sorted(good)
    result["pass"] = not insufficient
    if insufficient:
        addrs = [
            row["address"]
            for row in by_address
            if row.get("insufficient")
        ]
        result["detail"] = (
            f"Server accepts insufficient signature hash(es) for TLS 1.2 key exchange: "
            f"{', '.join(sorted(insufficient))}"
            + (f" on {', '.join(addrs)}" if addrs else "")
            + ". NCSC §3.3.5 / RFC 9155 rate SHA-1 (and MD5) as Insufficient; "
            "allow only SHA-256/384/512 (SignatureAlgorithms)."
        )
    elif phased_out:
        result["detail"] = (
            f"Server still accepts phased-out signature hash(es): {', '.join(sorted(phased_out))}. "
            "Prefer SHA-256/384/512 only."
        )
    elif good:
        result["detail"] = (
            f"Only Good signature hashes observed for TLS 1.2 key exchange: "
            f"{', '.join(sorted(good))}."
        )
    else:
        result["evaluated"] = False
        result["detail"] = "Could not determine peer signing digests (openssl probe failed)."
    return result


def check_tls_deep(domain, port=443):
    results = {"success": False}

    try:
        protocols = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for name, const in TLS_PROTOCOLS:
                futures[executor.submit(_test_protocol, domain, const, port)] = name
            futures[executor.submit(_test_tls13, domain, port)] = "TLS 1.3"

            for future in concurrent.futures.as_completed(futures):
                pname = futures[future]
                res = future.result()
                res["name"] = pname
                protocols.append(res)

        protocols.sort(key=lambda x: x["name"])
        ciphers = _enumerate_ciphers(domain, port)
        cipher_order = check_cipher_order(domain, port, ciphers)
        signature_hashes = check_tls_signature_hashes(domain, port)
        cert = _get_cert_details(domain, port)
        has_ocsp = _check_ocsp_stapling(domain, port)
        has_compression = _check_tls_compression(domain, port)

        hsts = _probe_hsts(domain)
        has_hsts = hsts.get("enabled")

        grade, warnings = _calculate_tls_grade(
            protocols, ciphers, cert, has_ocsp, has_compression, has_hsts
        )
        if cipher_order.get("applicable") and cipher_order.get("pass") is False:
            warnings.append("Cipher suite order prefers phase-out/insufficient over Good/Sufficient")
        if signature_hashes.get("insufficient"):
            warnings.append(
                "TLS 1.2 key-exchange signature accepts insufficient hash(es): "
                + ", ".join(signature_hashes["insufficient"])
            )

        strong_count = sum(1 for c in ciphers if c["strength"] == "strong")
        acceptable_count = sum(1 for c in ciphers if c["strength"] == "acceptable")
        weak_count = sum(1 for c in ciphers if c["strength"] == "weak")
        insecure_count = sum(1 for c in ciphers if c["strength"] == "insecure")
        fs_count = sum(1 for c in ciphers if c["forward_secrecy"])

        results = {
            "success": True,
            "grade": grade,
            "warnings": warnings,
            "protocols": protocols,
            "ciphers": ciphers,
            "cipher_summary": {
                "total": len(ciphers),
                "strong": strong_count,
                "acceptable": acceptable_count,
                "weak": weak_count,
                "insecure": insecure_count,
                "forward_secrecy": fs_count,
            },
            "cipher_order": cipher_order,
            "signature_hashes": signature_hashes,
            "certificate": cert,
            "ocsp_stapling": has_ocsp,
            "tls_compression": has_compression,
            "hsts": hsts,
        }

    except Exception as exc:
        results = {"success": False, "error": _safe_error(exc)}

    return results


# ---------------------------------------------------------------------------
# HTTP Security Headers
# ---------------------------------------------------------------------------

SECURITY_HEADERS = _security_headers_list()


_COEP_HEADER = "Cross-Origin-Embedder-Policy"


def _resolve_coep_applicability(results, csp_analysis):
    """Decide whether COEP can honestly be recommended for this site.

    COEP was listed alongside HSTS and X-Content-Type-Options as a plain
    missing header. It is not comparable: `require-corp` blocks every
    cross-origin subresource that does not send CORP, so following that advice
    breaks any site embedding third-party images, fonts or scripts. Advice you
    cannot act on without breaking your site is worse than no advice.
    """
    blockers = web_security.coep_breaking_sources(csp_analysis)
    results["coep"] = {
        "applicable": not blockers,
        "blocking_sources": blockers[:12],
    }
    if not blockers:
        return
    # Not a defect of this site, so it leaves the missing list entirely and
    # stops costing header-presence score.
    if _COEP_HEADER in results.get("headers_missing", []):
        results["headers_missing"] = [
            h for h in results["headers_missing"] if h != _COEP_HEADER
        ]
        results["coep"]["excluded_from_score"] = True


def check_http_headers(domain):
    results = {
        "headers_found": {},
        "headers_missing": [],
        "score": 0,
        "web_security": None,
        "vuln_findings": [],
    }
    try:
        resp = None
        for method in ("GET", "HEAD"):
            try:
                resp = _http_request(
                    f"https://{domain}/",
                    allow_redirects=True,
                    method=method,
                )
                break
            except Exception:
                continue
        if resp is None:
            raise RuntimeError("HTTPS request failed")

        blocked, reason, country = _response_access_blocked(resp)
        results["status_code"] = resp.status_code
        results["final_url"] = getattr(resp, "url", f"https://{domain}/")
        results["server"] = resp.headers.get("Server", "")
        results["blocked"] = blocked
        results["block_reason"] = reason
        results["request_country"] = country
        results["success"] = True
        # CDN fingerprint headers (even on geo-block 403)
        results["notable_headers"] = {
            k: v for k, v in resp.headers.items()
            if k.lower() in {
                "server", "cdn-pullzone", "cdn-requestcountrycode", "cdn-requestid",
                "cf-ray", "cf-ipcountry", "cf-cache-status",
                "x-amz-cf-id", "x-azure-ref", "x-served-by",
            }
        }

        # Always capture HSTS if present, even on blocked responses.
        total = len(SECURITY_HEADERS)
        found = 0
        for hdr in SECURITY_HEADERS:
            val = resp.headers.get(hdr)
            if val:
                results["headers_found"][hdr] = val
                found += 1
            else:
                results["headers_missing"].append(hdr)

        # Additional vuln analysis: CSP quality, cookies, CORS, framing, disclosure
        if not blocked:
            analysis = web_security.analyze_response_security(resp.headers)
            results["web_security"] = analysis
            results["vuln_findings"] = analysis.get("issues") or []
            results["csp"] = analysis.get("csp")
            results["csp_report_only"] = analysis.get("csp_report_only")
            results["csp_delta"] = analysis.get("csp_delta")
            results["cookie_security"] = {
                "count": (analysis.get("cookies") or {}).get("count"),
                "issues": (analysis.get("cookies") or {}).get("issues") or [],
            }
            results["cors"] = analysis.get("cors")
            results["framing"] = analysis.get("framing")
            _resolve_coep_applicability(results, analysis.get("csp"))
            # Presence was the only thing checked, so a typo or a
            # valid-but-toothless value passed as protection.
            results["header_value_issues"] = web_security.check_header_values(
                results.get("headers_found"))
            results["permissions_policy"] = web_security.analyze_permissions_policy(
                (results.get("headers_found") or {}).get("Permissions-Policy"))

        if blocked and "Strict-Transport-Security" not in results["headers_found"]:
            # Do not score a geo/WAF block as "all headers missing".
            results["headers_missing"] = [
                h for h in results["headers_missing"] if h != "Strict-Transport-Security"
            ]
            results["inconclusive"] = ["Strict-Transport-Security"]
            results["score"] = None
            results["block_detail"] = _geo_block_note(country)
            results["note"] = results["block_detail"]
        else:
            # Soften score slightly when CSP/cookies have high issues
            penalty = 0
            for issue in results.get("vuln_findings") or []:
                if issue.get("severity") == "high":
                    penalty += 5
                elif issue.get("severity") == "medium":
                    penalty += 2
            # A header we decline to recommend must not count against the
            # score either, or the site is marked down for the right call.
            scored_total = total
            if (results.get("coep") or {}).get("excluded_from_score"):
                scored_total = max(1, total - 1)
            base = round((found / scored_total) * 100) if scored_total else 0
            results["score"] = max(0, min(100, base - min(penalty, 30)))
            results["header_presence_score"] = base
    except Exception as exc:
        results["success"] = False
        results["error"] = _safe_error(exc)
    return results


# ---------------------------------------------------------------------------
# HTTP Deep Analysis — infrastructure detection & 4xx diagnostics
# ---------------------------------------------------------------------------

_AZURE_CNAME_SUFFIXES = (
    ".azurewebsites.net", ".p.azurewebsites.net", ".scm.azurewebsites.net",
    ".azurefd.net", ".azureedge.net", ".trafficmanager.net",
    ".azure-api.net", ".azurestaticapps.net", ".azurecontainerapps.io",
    ".blob.core.windows.net", ".web.core.windows.net", ".azuremicroservices.io",
    ".service.signalr.net", ".webpubsub.azure.com",
)

_AZURE_IP_NETS = [
    ipaddress.ip_network(n) for n in (
        "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14",
        "20.0.0.0/8",
        "40.64.0.0/10", "40.124.0.0/16",
        "51.0.0.0/9", "51.128.0.0/9",
        "52.0.0.0/7",
        "65.52.0.0/14",
        "104.40.0.0/13", "104.146.0.0/15",
    )
]

_CF_NETS = [
    ipaddress.ip_network(n) for n in (
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14",
        "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
        "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20",
        "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
        "198.41.128.0/17",
    )
]


def _ip_cloud(ip_str):
    """Return cloud provider name if IP is in a known range, else None."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if any(addr in n for n in _AZURE_IP_NETS):
            return "Azure"
        if any(addr in n for n in _CF_NETS):
            return "Cloudflare"
    except ValueError:
        pass
    return None


def _get_cname_chain(domain):
    """Follow CNAME chain up to 10 hops; return list of targets."""
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


def _detect_infrastructure(headers_lc, cname_chain, resolved_ip):
    """Return list of infrastructure dicts from headers, CNAME and IP."""
    found = []

    def _add(name, kind, confidence, detail=""):
        if not any(d["name"] == name for d in found):
            found.append({"name": name, "type": kind,
                          "confidence": confidence, "detail": detail})

    # Azure Front Door (definitive header)
    if "x-azure-ref" in headers_lc or "x-msedge-ref" in headers_lc:
        _add("Azure Front Door", "cdn_waf", "high",
             headers_lc.get("x-azure-ref") or headers_lc.get("x-msedge-ref", ""))

    # Azure App Service — ARR affinity cookie
    cookie_hdr = headers_lc.get("set-cookie", "")
    if "arraaffinity" in cookie_hdr.lower() or "arraaffinity" in headers_lc:
        _add("Azure App Service", "paas", "high")

    # Azure via CNAME
    for cname in cname_chain:
        cl = cname.lower()
        for suffix in _AZURE_CNAME_SUFFIXES:
            if cl.endswith(suffix):
                label = suffix.lstrip(".").replace(".net", "").replace(".io", "")
                _add(f"Azure ({label})", "azure_cname", "high", cname)
                break

    # Azure via IP (when no header/CNAME found Azure yet)
    if resolved_ip and not any("Azure" in d["name"] for d in found):
        cloud = _ip_cloud(resolved_ip)
        if cloud == "Azure":
            _add("Azure (IP range)", "azure_ip", "medium", resolved_ip)

    # Cloudflare
    if "cf-ray" in headers_lc or headers_lc.get("server", "").lower() == "cloudflare":
        _add("Cloudflare", "cdn_waf", "high",
             headers_lc.get("cf-ray", ""))
    elif resolved_ip and _ip_cloud(resolved_ip) == "Cloudflare":
        _add("Cloudflare (IP range)", "cdn_waf", "medium", resolved_ip)

    # AWS CloudFront
    if "x-amz-cf-id" in headers_lc:
        _add("AWS CloudFront", "cdn", "high", headers_lc.get("x-amz-cf-id", ""))

    # AWS ALB
    if "awsalb" in cookie_hdr.lower():
        _add("AWS ALB", "load_balancer", "high")

    # Fastly
    xsb = headers_lc.get("x-served-by", "")
    if xsb and "cache-" in xsb.lower():
        _add("Fastly", "cdn", "high", xsb)

    # Akamai
    if "x-akamai-request-id" in headers_lc or "akamaiedge.net" in headers_lc.get("x-cache", ""):
        _add("Akamai", "cdn_waf", "high")

    # BunnyCDN
    server = headers_lc.get("server", "").lower()
    if "bunnycdn" in server or "cdn-pullzone" in headers_lc:
        _add(
            "BunnyCDN",
            "cdn",
            "high",
            headers_lc.get("cdn-pullzone") or headers_lc.get("server", ""),
        )

    # OVHcloud CDN / SSL Gateway hints
    if any("ovh" in (c or "").lower() for c in (cname_chain or [])) or "ovhcloud" in server:
        _add("OVHcloud", "cdn", "medium", headers_lc.get("server", ""))

    # Microsoft IIS (without Front Door)
    if "microsoft-iis" in server and not any("Azure" in d["name"] for d in found):
        _add("Microsoft IIS", "web_server", "medium", headers_lc.get("server", ""))

    # nginx / Apache
    if "nginx" in server:
        _add("nginx", "web_server", "medium", headers_lc.get("server", ""))
    elif "apache" in server:
        _add("Apache", "web_server", "medium", headers_lc.get("server", ""))

    return found


_HINTS_4XX = {
    401: [
        ("auth_required", "Authentication required (401)",
         "The resource requires credentials (HTTP Basic, Bearer token, API key, etc.).",
         "Check the WWW-Authenticate response header for the expected auth scheme and send the correct credentials."),
    ],
    405: [
        ("method_not_allowed", "Method not allowed (405)",
         "The HTTP method (GET/POST/…) is not accepted for this path.",
         "Check the Allow response header for accepted methods."),
    ],
    429: [
        ("rate_limited", "Rate limited (429)",
         "Too many requests. The server is throttling the client.",
         "Check the Retry-After header. Reduce request frequency or use exponential back-off."),
    ],
}


def _diagnose_4xx(status, headers_lc, body, cname_chain, infrastructure):
    hints = []

    def _add(htype, title, detail, action):
        hints.append({"type": htype, "title": title,
                      "detail": detail, "action": action})

    # Generic hints for non-403 codes
    for h in _HINTS_4XX.get(status, []):
        _add(*h)

    if status == 403:
        # Custom application-level deny header
        deny = headers_lc.get("x-deny-reason", "")
        if deny:
            _add("app_deny",
                 f"App-level block: {deny}",
                 f"The header x-deny-reason: {deny} indicates an explicit access policy at the application or gateway layer — NOT a WAF block.",
                 "Contact the application owner to add your host/IP to the allowlist, or verify you are sending the correct Host header and authentication credentials.")

        # Azure Front Door WAF
        body_lc = body.lower()
        if "x-azure-ref" in headers_lc:
            if "the request is blocked" in body_lc or "azure web application firewall" in body_lc:
                ref = headers_lc.get("x-azure-ref", "")
                _add("azure_waf",
                     "Azure WAF block (Front Door)",
                     f"Azure Front Door WAF rejected the request (Ref: {ref}). Body matches Azure WAF block page.",
                     "Open Azure Portal → Front Door → Security policies → WAF logs. Create an exclusion rule if the block is a false positive.")
            else:
                _add("azure_fd_403",
                     "Azure Front Door returned 403",
                     "Azure Front Door is in the path. The 403 may originate from WAF rules, geo-filtering, IP access rules, or a custom routing rule.",
                     "Check Azure Portal: Front Door → Security → WAF policy, and Networking → Access rules / Geo-filtering.")

        # Azure App Service access restriction
        if any("App Service" in d["name"] for d in infrastructure):
            _add("azure_app_svc",
                 "Azure App Service — possible Access Restriction",
                 "App Service IP-based access restrictions or EasyAuth may be blocking this request.",
                 "Azure Portal → App Service → Networking → Access Restrictions. Ensure your IP or subnet is in the allowlist.")

        # Cloudflare WAF
        if "cf-ray" in headers_lc:
            if "1020" in body or "error code: 1020" in body_lc:
                _add("cf_waf",
                     "Cloudflare Firewall Rule block (Error 1020)",
                     f"CF-Ray: {headers_lc.get('cf-ray', '')}. A Cloudflare Firewall Rule explicitly blocks this request.",
                     "Contact the site owner to whitelist your IP, or check Cloudflare dashboard → Security → Events.")
            else:
                _add("cf_403",
                     "Cloudflare returned 403",
                     f"CF-Ray: {headers_lc.get('cf-ray', '')}. Could be a WAF rule, Page Rule, or origin returning 403.",
                     "Check Cloudflare dashboard → Security → Events for blocked requests and their rule IDs.")

        # AppGW WAF default block page pattern
        if "403 - forbidden: access is denied" in body_lc:
            _add("azure_appgw_waf",
                 "Azure Application Gateway WAF block",
                 "Response body matches Azure Application Gateway WAF default block page.",
                 "Check Application Gateway WAF logs in Azure Portal. Consider adding a WAF exclusion for the blocked parameter or rule.")

        # Generic CORS / preflight
        if not hints:
            _add("generic_403",
                 "403 Forbidden — no specific infrastructure indicator",
                 "The server rejected the request without infrastructure-specific markers. Possible causes: IP/network blocklist, missing API key or Bearer token, CORS preflight failure, misconfigured ACL.",
                 "Try: adding standard headers (User-Agent, Accept, Authorization). Check if the endpoint requires HTTPS. Review server access logs.")

    # WWW-Authenticate hint for 401
    if status == 401 and "www-authenticate" in headers_lc:
        hints[0]["action"] += f" WWW-Authenticate: {headers_lc['www-authenticate']}"

    # Retry-After for 429
    if status == 429 and "retry-after" in headers_lc:
        if hints:
            hints[0]["action"] += f" Retry-After: {headers_lc['retry-after']} seconds."

    return hints


_INTERESTING_HEADERS = {
    "server", "x-powered-by", "via", "x-cache", "x-azure-ref", "x-msedge-ref",
    "x-amz-cf-id", "x-amz-cf-pop", "cf-ray", "cf-cache-status", "cf-ipcountry",
    "cdn-pullzone", "cdn-requestcountrycode", "cdn-requestid",
    "x-served-by", "x-akamai-request-id", "x-ms-request-id", "x-deny-reason",
    "arraaffinity", "arraaffinitysamsite", "strict-transport-security",
    "content-security-policy", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "retry-after", "www-authenticate",
    "location", "content-type",
}


def check_http_deep(domain):
    """Infrastructure detection, redirect chain, and 4xx diagnostics."""
    result = {
        "success": False,
        "cname_chain": [],
        "resolved_ip": None,
        "infrastructure": [],
        "redirect_chain": [],
        "final_status": None,
        "final_url": None,
        "notable_headers": {},
        "all_headers": {},
        "diagnostics": [],
    }

    # CNAME chain
    cname_chain = _get_cname_chain(domain)
    result["cname_chain"] = cname_chain

    # Resolved IP
    try:
        resolved_ip = socket.gethostbyname(domain)
        result["resolved_ip"] = resolved_ip
    except Exception:
        resolved_ip = None

    # HTTP request — try HTTPS first, fall back to HTTP
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={
                    "User-Agent": _BROWSER_UA,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "nl,en-US;q=0.7,en;q=0.3",
                },
            )
        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue

        # Redirect chain
        result["redirect_chain"] = [
            {"url": r.url, "status": r.status_code}
            for r in resp.history
        ] + [{"url": resp.url, "status": resp.status_code}]

        result["final_status"] = resp.status_code
        result["final_url"] = resp.url

        # Headers — highlight the curated/interesting subset, but also keep
        # the full raw response so nothing is hidden if detection misses a
        # non-standard header (e.g. a custom gateway deny header).
        headers_lc = {k.lower(): v for k, v in resp.headers.items()}
        result["notable_headers"] = {
            k: v for k, v in resp.headers.items()
            if k.lower() in _INTERESTING_HEADERS
        }
        result["all_headers"] = dict(resp.headers)

        # Body + cookies for SaaS fingerprinting (HubSpot, Cloudflare, etc.)
        try:
            body_snippet = resp.text[:20000]
        except Exception:
            body_snippet = ""
        cookie_header = resp.headers.get("Set-Cookie", "")
        result["body_fingerprint"] = {
            "length": len(body_snippet),
            "has_hubspot": "hs-scripts.com" in body_snippet.lower() or "hubspot" in body_snippet.lower(),
            "has_cloudflare_challenge": "cf-browser-verification" in body_snippet.lower(),
        }
        result["cookies_present"] = bool(cookie_header)

        # Additional cookie / CORS analysis (complements http_headers check)
        try:
            result["web_security"] = web_security.analyze_response_security(resp.headers)
        except Exception as exc:
            result["web_security_error"] = str(exc)[:200]

        # Infrastructure detection
        infra = _detect_infrastructure(headers_lc, cname_chain, resolved_ip)
        # HubSpot quick fingerprint in http_deep
        body_l = body_snippet.lower()
        if any(x in body_l for x in ("js.hs-scripts.com", "hs-script-loader", "hubspotutk", "__hstc")) or "hs-sites" in ".".join(cname_chain).lower():
            if not any(d.get("name", "").startswith("HubSpot") for d in infra):
                infra.append({
                    "name": "HubSpot",
                    "type": "marketing_cms",
                    "confidence": "high",
                    "detail": "script/cookie/cname fingerprint",
                })
        if cookie_header and ("__cf_bm=" in cookie_header or "cf_clearance=" in cookie_header):
            if not any("Cloudflare" in d.get("name", "") for d in infra):
                infra.append({
                    "name": "Cloudflare",
                    "type": "cdn_waf",
                    "confidence": "high",
                    "detail": "cloudflare cookie",
                })
        result["infrastructure"] = infra

        # 4xx diagnostics
        if resp.status_code in (400, 401, 403, 404, 405, 429):
            result["diagnostics"] = _diagnose_4xx(
                resp.status_code, headers_lc, body_snippet[:3000], cname_chain, infra
            )

        result["success"] = True
        break

    return result


# ---------------------------------------------------------------------------
# HTTPS redirect check
# ---------------------------------------------------------------------------

def check_https_redirect(domain):
    try:
        resp = _http_request(f"http://{domain}/", allow_redirects=False, method="GET")
        location = resp.headers.get("Location", "")
        redirects_to_https = (
            resp.status_code in (301, 302, 307, 308)
            and location.startswith("https://")
        )
        blocked, reason, country = _response_access_blocked(resp)
        if blocked and not redirects_to_https:
            if country and country not in _BENELUX_GEO_ALLOW:
                note = (
                    f"CDN geo-blocked this probe (request country {country}; "
                    "site may allow only NL/DE/BE). HTTPS redirect is inconclusive — "
                    "verify from NL/DE/BE or internet.nl."
                )
            else:
                note = (
                    "HTTP probe blocked by CDN/WAF; HTTPS redirect could not be verified."
                )
            return {
                "redirects": False,
                "status_code": resp.status_code,
                "location": location,
                "permanent": False,
                "pass": None,
                "blocked": True,
                "block_reason": reason,
                "block_detail": note,
                "request_country": country,
                "note": note,
            }
        return {
            "redirects": redirects_to_https,
            "status_code": resp.status_code,
            "location": location,
            "permanent": resp.status_code in (301, 308),
            "pass": redirects_to_https,
            "blocked": False,
        }
    except Exception as exc:
        return {"redirects": False, "pass": False, "error": _safe_error(exc)}


# ---------------------------------------------------------------------------
# IPv6 support
# ---------------------------------------------------------------------------

def check_ipv6(domain):
    aaaa = _resolve(domain, "AAAA")
    mx_records = _resolve(domain, "MX")
    mx_ipv6 = {}
    for mx in mx_records:
        mx_host = mx.split()[-1].rstrip(".")
        mx_aaaa = _resolve(mx_host, "AAAA")
        if mx_aaaa:
            mx_ipv6[mx_host] = mx_aaaa

    ns_records = _resolve(domain, "NS")
    ns_ipv6 = {}
    for ns in ns_records:
        ns_host = ns.rstrip(".")
        ns_aaaa = _resolve(ns_host, "AAAA")
        if ns_aaaa:
            ns_ipv6[ns_host] = ns_aaaa

    return {
        "has_ipv6": len(aaaa) > 0,
        "aaaa_records": aaaa,
        "mx_ipv6": mx_ipv6,
        "ns_ipv6": ns_ipv6,
        "web_pass": len(aaaa) > 0,
        "mail_pass": len(mx_ipv6) > 0,
        "ns_pass": len(ns_ipv6) > 0,
    }


# ---------------------------------------------------------------------------
# DNSBL / Blacklist Check
# ---------------------------------------------------------------------------

# Spamhaus stopped allowing free DNSBL access via public resolvers (8.8.8.8,
# 1.1.1.1) in 2022.  Set SPAMHAUS_DQS_KEY to a free DQS key from
# https://portal.spamhaus.com/dqs/ to re-enable Spamhaus checks.  Without a
# key, only the non-Spamhaus lists are queried.

def _spamhaus_dqs_key():
    """Resolved at call time, not import time.

    This used to be a module-level constant, so a key added after start-up
    (now possible from the admin UI) would not take effect until the process
    was restarted.
    """
    from settings import api_keys
    return api_keys.resolve("SPAMHAUS_DQS_KEY", db=db)


# Servers that work without a key. These are all IP-based: the query is the
# reversed IP prefixed to the zone.
_DNSBL_OPEN = [
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
]

# Spamhaus zones — used only when a DQS key is configured.
#
# zen is an IP blocklist; dbl (Domain Block List) and zrd (Zero Reputation
# Domains) are DOMAIN lists. Querying a domain list with a reversed IP is not
# just useless, it actively produces false positives: Spamhaus answers such a
# query with 127.0.1.255, "IP queries prohibited", which looks like an
# ordinary 127.0.x.y listing response. Every domain scanned this way was
# reported as "listed on dbl and zrd".
_DNSBL_SPAMHAUS_IP_ZONES = ["zen"]
_DNSBL_SPAMHAUS_DOMAIN_ZONES = ["dbl", "zrd"]


def _build_dnsbl_list():
    """Return [(zone_host, kind)] where kind is "ip" or "domain"."""
    servers = [(zone, "ip") for zone in _DNSBL_OPEN]
    key = _spamhaus_dqs_key()
    if key:
        for zone in _DNSBL_SPAMHAUS_IP_ZONES:
            servers.append((f"{key}.{zone}.dq.spamhaus.net", "ip"))
        for zone in _DNSBL_SPAMHAUS_DOMAIN_ZONES:
            servers.append((f"{key}.{zone}.dq.spamhaus.net", "domain"))
    return servers


def _dnsbl_is_real_hit(answers):
    """Return True only for genuine listing responses.

    DNSBLs answer in 127.0.0.0/8, but not every such answer is a listing:

      127.255.255.252-255  Spamhaus auth/quota errors (bad key, over limit)
      127.0.1.255          "IP queries prohibited" from the domain lists
      *.255                by convention, the .255 host is an error marker

    Treating any of these as a listing produces false positives, which is
    exactly what happened when the domain lists were queried with an IP.
    """
    for rdata in answers:
        txt = rdata.to_text()
        parts = txt.split(".")
        if len(parts) != 4 or parts[0] != "127":
            continue
        if parts[1] == "255":
            return False
        if parts[3] == "255":
            return False
        return True
    return False


def check_blacklist(domain):
    results = {
        "listed": [], "clean": [], "errors": [], "ip": None,
        "spamhaus_dqs": bool(_spamhaus_dqs_key()),
    }
    try:
        # A bare address has no hostname to offer a domain list, so those
        # zones are skipped rather than queried with something they cannot
        # answer — which is what produced the dbl/zrd false positive.
        querying_an_address = ip_intel.is_ip(domain)
        ip = domain if querying_an_address else _safe_resolve_ip(domain)
        results["ip"] = ip
        reversed_ip = ".".join(reversed(ip.split(".")))

        for bl, kind in _build_dnsbl_list():
            if querying_an_address and kind == "domain":
                continue
            # Domain lists take the hostname; IP lists take the reversed IP.
            prefix = domain if kind == "domain" else reversed_ip
            query = f"{prefix}.{bl}"
            try:
                answers = dns.resolver.resolve(query, "A")
                if _dnsbl_is_real_hit(answers):
                    results["listed"].append(bl)
                else:
                    results["errors"].append(bl)
                    results["clean"].append(bl)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                results["clean"].append(bl)
            except Exception:
                results["clean"].append(bl)

        results["is_listed"] = len(results["listed"]) > 0
    except Exception as exc:
        results["error"] = _safe_error(exc)
        results["is_listed"] = False
    return results


# ---------------------------------------------------------------------------
# Open Port Scanner (common ports)
# ---------------------------------------------------------------------------

def _check_port(ip, port, timeout=3):
    """True when a TCP connect succeeds.

    connect_ex returns an errno instead of raising, so a closed port is 0 vs
    non-zero rather than an exception — which keeps a filtered or refused port
    from costing a stack unwind per port.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False


def check_ports(domain):
    results = {"open": [], "closed": [], "ip": None}
    try:
        # Inside the try: a malformed ports setting should be reported as a
        # failed check, not raised out of it.
        port_map = _scan_ports_map()
        ip = _safe_resolve_ip(domain)
        results["ip"] = ip

        workers = min(len(port_map), 32)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {
                executor.submit(_check_port, ip, port): port
                for port in port_map
            }
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    results["open"].append({"port": port, "service": port_map[port]})
                else:
                    results["closed"].append({"port": port, "service": port_map[port]})

        results["open"].sort(key=lambda x: x["port"])
        results["closed"].sort(key=lambda x: x["port"])
    except Exception as exc:
        results["error"] = _safe_error(exc)
    return results


def _attach_rapid7_findings(results, domain):
    """Correlate imported InsightVM/Nexpose findings with the scanned domain."""
    cfg = domainlens_config.load_settings().rapid7()
    if not cfg.get("enabled", True) or not cfg.get("include_in_scan", True):
        results["rapid7"] = {
            "success": False,
            "disabled": True,
            "error": "Rapid7 correlation disabled in settings",
        }
        return results
    try:
        findings = db.vuln_findings_for_domain(
            domain,
            min_severity=None,
            limit=int(cfg.get("max_rows") or 50000),
        )
        section = rapid7_import.build_scan_section(findings, domain)
        section["min_severity_for_advies"] = cfg.get("min_severity_for_advies") or "medium"
        section["max_advies_items"] = int(cfg.get("max_advies_items") or 40)
        section["import_stats"] = db.vuln_import_stats()
        results["rapid7"] = section
    except Exception as exc:
        results["rapid7"] = {"success": False, "error": _safe_error(exc)}
    return results


def check_weak_auth(domain):
    """Optional weak/default credential probe (config weak_auth.enabled)."""
    settings = domainlens_config.load_settings().weak_auth()
    return weak_auth.scan(domain, settings)


def check_js_scan(domain):
    """Passive client-side JS scan: vulnerable libraries + exposed secrets."""
    try:
        result = js_scan.scan(domain)
        result["findings"] = js_scan.findings(result)
        return result
    except Exception as exc:
        return {"success": False, "error": _safe_error(exc)}


def check_active_scan(domain):
    """Optional active vulnerability probe (config active_scan.enabled)."""
    settings = domainlens_config.load_settings().active_scan()
    result = active_scan.scan(domain, settings)
    result["findings_graded"] = active_scan.findings_from_scan(result)
    return result


def _scan_thread_workers():
    return int(domainlens_config.load_settings().scan().get("thread_pool_workers", 14))


# ---------------------------------------------------------------------------
# Security Audit (subdomain takeover, exposures, DNS/mail gaps, info disclosure)
# ---------------------------------------------------------------------------

def check_security(domain, force=False):
    """Run the full security audit and attach severity-graded findings."""
    try:
        audit = security_checks.run_security_audit(domain, force=force)
        audit["findings"] = security_checks.audit_findings(audit)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in audit["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        audit["counts"] = counts
        audit["success"] = True
        return audit
    except Exception as exc:
        return {"success": False, "error": _safe_error(exc)}


# ---------------------------------------------------------------------------
# Full Scan (all checks combined)
# ---------------------------------------------------------------------------

# Single source of truth for every check: name -> zero-arg callable.
# Both full_scan and run_selected_checks build from this so a new check is
# added in exactly one place. Email/WHOIS/DNSSEC route to the zone apex.
def _build_check_map(domain, apex, extra_dkim_selectors=None, force_refresh=False):
    return {
        # Apex-domain checks (email security + WHOIS live at the root zone)
        "whois": lambda: lookup_whois(apex),
        "dnssec": lambda: check_dnssec(apex),
        "spf": lambda: check_spf(apex),
        "dmarc": lambda: check_dmarc(apex),
        "dkim": lambda: check_dkim(apex, extra_selectors=extra_dkim_selectors),
        "mta_sts": lambda: check_mta_sts(apex),
        "tlsrpt": lambda: check_tlsrpt(apex),
        # Subdomain / host-specific checks
        "dns": lambda: lookup_dns(domain),
        "ssl": lambda: check_ssl(domain),
        "tls_deep": lambda: check_tls_deep(domain),
        "http_headers": lambda: check_http_headers(domain),
        "https_redirect": lambda: check_https_redirect(domain),
        "http_deep": lambda: check_http_deep(domain),
        "ipv6": lambda: check_ipv6(domain),
        "blacklist": lambda: check_blacklist(domain),
        "ports": lambda: check_ports(domain),
        "osint": lambda: scan_cache.cached_call(
            scan_cache.KIND_OSINT, domain,
            lambda: osint.collect_osint(domain), force=force_refresh),
        "hubspot_cf": lambda: hubspot_cf.scan_hubspot_cloudflare(domain),
        "security": lambda: check_security(domain, force=force_refresh),
        "weak_auth": lambda: check_weak_auth(domain),
        "js_scan": lambda: check_js_scan(domain),
        "active_scan": lambda: check_active_scan(domain),
    }


# Checks that send active test traffic (login attempts, XSS/SQLi/redirect
# probes) — never run these in a full scan unless the operator has explicitly
# opted in via settings, regardless of which checkboxes are ticked.
_OPT_IN_ACTIVE_CHECKS = {"weak_auth", "active_scan"}


def _run_checks(check_map, names, results, progress_cb=None):
    """Execute checks concurrently, reporting completions as they land.

    progress_cb(done, total, name) is called after each check finishes, which
    is what lets a scan report a percentage instead of being an opaque wait.
    """
    total = len(names)
    done = 0
    if progress_cb:
        progress_cb(0, total, None)
    with concurrent.futures.ThreadPoolExecutor(max_workers=_scan_thread_workers()) as executor:
        futures = {executor.submit(check_map[n]): n for n in names}
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = {"error": _safe_error(exc)}
            done += 1
            if progress_cb:
                progress_cb(done, total, key)
    return results


def full_scan(domain, extra_dkim_selectors=None, progress_cb=None, force_refresh=False):
    apex = _get_apex_domain(domain)
    results = {"apex_domain": apex}
    check_map = _build_check_map(
        domain, apex, extra_dkim_selectors=extra_dkim_selectors,
        force_refresh=force_refresh)
    weak_enabled = domainlens_config.load_settings().weak_auth().get("enabled")
    active_enabled = domainlens_config.load_settings().active_scan().get("enabled")
    names = [
        n for n in check_map
        if n != "weak_auth" or weak_enabled
        if n != "active_scan" or active_enabled
    ]

    _run_checks(check_map, names, results, progress_cb)
    return _attach_ncsc_tls(results, domain)


def run_selected_checks(domain, checks, extra_dkim_selectors=None, progress_cb=None,
                        force_refresh=False):
    """Run a selected set of checks for a normalized domain."""
    if "all" in checks:
        return full_scan(
            domain, extra_dkim_selectors=extra_dkim_selectors, progress_cb=progress_cb,
            force_refresh=force_refresh)

    # Email security + WHOIS + DNSSEC live at the registered zone apex, so
    # route them there even when a subdomain was entered.
    apex = _get_apex_domain(domain)
    results = {"apex_domain": apex}
    selected = list(checks)
    # NCSC assessment needs tls_deep input; pull it in when only ncsc_tls is selected.
    if "ncsc_tls" in selected and "tls_deep" not in selected:
        selected.append("tls_deep")

    check_map = _build_check_map(
        domain, apex, extra_dkim_selectors=extra_dkim_selectors,
        force_refresh=force_refresh)
    names = [n for n in selected if n in check_map]
    _run_checks(check_map, names, results, progress_cb)

    if "ncsc_tls" in checks or "tls_deep" in results or "ncsc_tls" in selected:
        results = _attach_ncsc_tls(results, domain)
    return results


def _attach_ncsc_tls(results, domain=None):
    """Derive NCSC TLS 2025-05 assessment from tls_deep results."""
    deep = results.get("tls_deep")
    if not deep:
        results["ncsc_tls"] = {
            "success": False,
            "guideline": ncsc_tls.GUIDELINE,
            "guideline_url": ncsc_tls.GUIDELINE_URL,
            "error": "TLS deep scan required for NCSC assessment",
        }
        return results
    assessment = ncsc_tls.assess(deep)
    cdn = cdn_hardening.detect_cdn(
        http_deep=results.get("http_deep"),
        http_headers=results.get("http_headers"),
    )
    results["cdn"] = cdn
    # Enrich signature-hash / cipher-order findings with CDN-specific remediations.
    if assessment.get("success") and cdn.get("id") and cdn.get("id") != cdn_hardening.CDN_GENERIC:
        for item in assessment.get("findings") or []:
            if item.get("id") == "signature-hash-insufficient":
                adv = cdn_hardening.advice_for_signature_hashes(cdn=cdn)
                item["fix"] = adv["fix"]
                item["retest"] = adv["retest"]
                item["cdn"] = cdn.get("name")
            elif item.get("id") == "cipher-order":
                item["fix"] = (
                    (item.get("fix") or "")
                    + " "
                    + cdn_hardening.advice_for_cipher_order(cdn=cdn)
                ).strip()
                item["cdn"] = cdn.get("name")
    assessment["cdn"] = cdn
    assessment["cdn_optimizations"] = cdn_hardening.optimizations_summary(
        cdn,
        tls_deep=deep,
        http_headers=results.get("http_headers"),
    )
    results["ncsc_tls"] = assessment
    return results


# The set of checks a scan or a monitor can select, grouped for display. This
# is the single source of truth the monitor form renders from, so the monitor
# selector cannot drift from the checks the scanner actually runs. Keys must
# match _build_check_map (plus "ncsc_tls", derived from tls_deep).
CHECK_CATALOG = [
    {"group": "Domain & DNS", "checks": [
        {"key": "whois", "label": "WHOIS"},
        {"key": "dns", "label": "DNS"},
        {"key": "dnssec", "label": "DNSSEC"},
        {"key": "ipv6", "label": "IPv6"},
    ]},
    {"group": "Email Security", "checks": [
        {"key": "spf", "label": "SPF"},
        {"key": "dmarc", "label": "DMARC"},
        {"key": "dkim", "label": "DKIM"},
        {"key": "mta_sts", "label": "MTA-STS"},
        {"key": "tlsrpt", "label": "TLS-RPT"},
    ]},
    {"group": "SSL / TLS", "checks": [
        {"key": "ssl", "label": "SSL/TLS"},
        {"key": "tls_deep", "label": "TLS Scan"},
        {"key": "ncsc_tls", "label": "NCSC TLS"},
    ]},
    {"group": "Web", "checks": [
        {"key": "http_headers", "label": "Headers"},
        {"key": "https_redirect", "label": "HTTPS"},
        {"key": "http_deep", "label": "HTTP Analysis"},
        {"key": "hubspot_cf", "label": "HubSpot / CF"},
    ]},
    {"group": "Network", "checks": [
        {"key": "blacklist", "label": "Blacklist"},
        {"key": "ports", "label": "Ports"},
        {"key": "osint", "label": "OSINT"},
    ]},
    {"group": "Security", "checks": [
        {"key": "security", "label": "Security Audit"},
        {"key": "js_scan", "label": "JS Dependency & Secrets"},
    ]},
]

def _prepare_checks(payload_checks):
    """Normalize check selection input to a safe list.

    Kept permissive on purpose: opt-in active checks (weak_auth, active_scan)
    are requested by key here too, so this must not drop keys that are absent
    from CHECK_CATALOG (the display catalog for the scan/monitor UI).
    """
    if not isinstance(payload_checks, list):
        return ["all"]
    checks = [item for item in payload_checks if isinstance(item, str) and item]
    return checks or ["all"]


# DKIM selectors are DNS labels: letters, digits, hyphens, underscores, dots
# (some ESPs use dotted selector names). Reject anything else outright rather
# than silently dropping characters, and cap both the count and per-item
# length so a malicious/garbage payload can't turn into an oversized DNS
# lookup burst.
_DKIM_SELECTOR_RE = re.compile(r"^[A-Za-z0-9._-]{1,63}$")
_MAX_CUSTOM_DKIM_SELECTORS = 10


def _prepare_dkim_selectors(payload_selectors):
    """Validate and normalize user-supplied extra DKIM selectors."""
    if not isinstance(payload_selectors, list):
        return []
    cleaned = []
    seen = set()
    for item in payload_selectors:
        if not isinstance(item, str):
            continue
        sel = item.strip()
        if not sel or sel in seen or not _DKIM_SELECTOR_RE.match(sel):
            continue
        seen.add(sel)
        cleaned.append(sel)
        if len(cleaned) >= _MAX_CUSTOM_DKIM_SELECTORS:
            break
    return cleaned


def _serialize_monitor(monitor, latest_scan=None):
    """Return a monitor payload enriched with recommendation counts.

    Two different scans matter here and they are not the same thing:
    `last_scan` is the check this monitor itself ran, `latest_scan` is the
    newest scan of the domain from any source. Only the monitor path calls
    mark_monitor_scanned, so a manual rescan leaves `last_scan` behind and
    linking to it alone sends you to a stale report.
    """
    if not monitor:
        return None
    result = dict(monitor)
    if monitor.get("last_scan_id"):
        record = db.get_scan(monitor["last_scan_id"])
        if record:
            counts = recommendations.summarize_counts(recommendations.generate(record["data"]))
            result["last_scan"] = {
                "id": record["id"],
                "created_at": record["created_at"],
                "grade": record.get("grade"),
                "score": record.get("score"),
                "issues_count": record.get("issues_count"),
                "recommendation_counts": counts,
            }
    if latest_scan is None:
        rows = db.latest_scans_by_domain([monitor.get("domain")])
        latest_scan = rows.get(monitor.get("domain"))
    if latest_scan:
        result["latest_scan"] = dict(latest_scan)
    return result


def _save_monitor_definitions(monitor_defs, *, schedule_minutes, checks, enabled=True):
    """Persist monitor definitions and return stored monitors."""
    stored = []
    for item in monitor_defs:
        defaults = {
            "name": item["name"],
            "record_value": item.get("record_value"),
            "source_type": item.get("source_type", "manual"),
            "source_label": item.get("source_label"),
            "provider": item.get("provider"),
            "schedule_minutes": schedule_minutes,
            "checks": checks,
            "enabled": enabled,
            "metadata": item.get("metadata") or {},
        }
        stored_monitor = db.upsert_monitor(
            domain=item["domain"],
            target=item["target"],
            record_type=item["record_type"],
            defaults=defaults,
        )
        stored.append(_serialize_monitor(stored_monitor))
    return stored


def _resolve_monitored_record(target, record_type):
    """Resolve the one DNS record a monitor watches, for change detection.

    A monitor's record type used to be stored and displayed but never
    resolved, so "monitor the CNAME of chat.example.com" watched the same full
    scan as everything else and never noticed the record itself changing or
    going NXDOMAIN. This resolves exactly that record and returns it in the
    three states Reporting keeps apart:

      measured=True,  present=True   — the record resolved to one or more values
      measured=True,  present=False  — the name is NXDOMAIN (the dangling signal)
      measured=False                 — the lookup failed (SERVFAIL/timeout/network);
                                       never treated as a change, so a resolver
                                       hiccup cannot invent a "record disappeared".
    """
    rtype = (record_type or "A").upper()
    if rtype not in dns_tools.RECORD_TYPES:
        # Import sources may carry a type the lookup does not offer (e.g. SOA
        # on an apex); nothing to watch rather than an error.
        return {"type": rtype, "measured": False, "present": False,
                "records": [], "rcode": None, "authenticated": None,
                "error": f"{rtype} is not a resolvable record type here"}
    try:
        answer = dns_tools.query(target, rtype, resolver="system")
    except dns_tools.LookupError_ as exc:
        return {"type": rtype, "measured": False, "present": False,
                "records": [], "rcode": None, "authenticated": None,
                "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - any resolver failure is unmeasured
        return {"type": rtype, "measured": False, "present": False,
                "records": [], "rcode": None, "authenticated": None,
                "error": _safe_error(exc)}

    if answer.get("error"):
        return {"type": rtype, "measured": False, "present": False,
                "records": [], "rcode": answer.get("rcode"),
                "authenticated": answer.get("authenticated"),
                "error": answer["error"]}

    rcode = answer.get("rcode")
    records = sorted(answer.get("records") or [])
    # NXDOMAIN and NOERROR are both measured answers; only NXDOMAIN and an
    # empty NOERROR mean the watched record is absent.
    present = bool(records)
    return {"type": rtype, "measured": True, "present": present,
            "records": records, "rcode": rcode,
            "authenticated": answer.get("authenticated"), "error": None}


def _monitor_state_hash(results):
    """Create a stable fingerprint for change detection."""
    tracked = {
        "dns": results.get("dns"),
        "dnssec": results.get("dnssec"),
        "spf": results.get("spf"),
        "dmarc": results.get("dmarc"),
        "dkim": results.get("dkim"),
        "mta_sts": results.get("mta_sts"),
        "tlsrpt": results.get("tlsrpt"),
        "ssl": results.get("ssl"),
        "tls_deep": results.get("tls_deep"),
        "http_headers": results.get("http_headers"),
        "https_redirect": results.get("https_redirect"),
        "http_deep": results.get("http_deep"),
        "ipv6": results.get("ipv6"),
        "blacklist": results.get("blacklist"),
        "ports": results.get("ports"),
        "osint": (results.get("osint") or {}).get("summary"),
        "hubspot_cf": {
            "behind_cloudflare": (results.get("hubspot_cf") or {}).get("behind_cloudflare"),
            "findings": [
                f.get("id") for f in ((results.get("hubspot_cf") or {}).get("findings") or [])
            ],
        },
        "weak_auth": {
            "weak_credentials_found": (results.get("weak_auth") or {}).get("weak_credentials_found"),
            "findings_count": len((results.get("weak_auth") or {}).get("findings") or []),
        },
        "rapid7": {
            "finding_count": (results.get("rapid7") or {}).get("finding_count"),
            "by_severity": (results.get("rapid7") or {}).get("by_severity"),
        },
    }
    # The watched DNS record is deliberately NOT folded into this fingerprint.
    # A measured→unmeasured transition (a resolver hiccup) would otherwise flip
    # the hash and read as a change. Record changes are detected separately, by
    # comparing the two measured records in _watched_record_transition, which
    # ignores unmeasured scans entirely.
    payload = json.dumps(tracked, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _watched_record_transition(monitor, results, previous_results):
    """Describe a change in the monitor's watched DNS record, or None.

    Returns (severity, summary) when the specific record the monitor watches
    changed value or went NXDOMAIN between the previous scan and this one.
    Only fires when both scans measured the record: an unmeasured lookup on
    either side is "could not be measured", never a transition.
    """
    current = results.get("monitored_record") or {}
    previous = (previous_results or {}).get("monitored_record") or {}
    if not current.get("measured") or not previous.get("measured"):
        return None
    if current.get("records") == previous.get("records"):
        return None

    rtype = current.get("type") or monitor.get("record_type") or "record"
    target = monitor["target"]
    if previous.get("present") and not current.get("present"):
        # The value the CNAME/A/... pointed at is gone. This is the dangling
        # signal a takeover scan would otherwise only catch on a full re-enum.
        return "high", f"{rtype} record for {target} disappeared (now {current.get('rcode') or 'empty'})"
    if not previous.get("present") and current.get("present"):
        return "medium", f"{rtype} record for {target} reappeared"
    return "medium", f"{rtype} record for {target} changed value"


def _monitor_event_from_results(monitor, results, previous_record):
    """Derive a monitor event from scan results and the previous baseline."""
    current_hash = _monitor_state_hash(results)
    previous_hash = monitor.get("last_state_hash")
    warnings = len((results.get("tls_deep") or {}).get("warnings") or [])
    recommendation_count = len(recommendations.generate(results))
    blacklist_listed = bool((results.get("blacklist") or {}).get("is_listed"))
    tls_grade = (results.get("tls_deep") or {}).get("grade")
    watched = results.get("monitored_record") or {}
    details = {
        "target": monitor["target"],
        "record_type": monitor["record_type"],
        "tls_grade": tls_grade,
        "recommendation_count": recommendation_count,
        "blacklist_listed": blacklist_listed,
        "warnings": warnings,
        "record_measured": watched.get("measured"),
        "record_present": watched.get("present"),
        "record_values": watched.get("records"),
        "record_rcode": watched.get("rcode"),
    }

    if not previous_hash:
        return current_hash, {
            "event_type": "baseline_created",
            "severity": "info",
            "summary": f"Baseline created for {monitor['target']}",
            "details": details,
        }

    previous_results = (previous_record or {}).get("data") or {}
    record_transition = _watched_record_transition(monitor, results, previous_results)
    # A change is either a shift in the tracked fingerprint or a change in the
    # watched DNS record. The record is kept out of the fingerprint (see
    # _monitor_state_hash), so a pure record change is caught only here.
    if previous_hash != current_hash or record_transition:
        previous_grade = (previous_results.get("tls_deep") or {}).get("grade")
        previous_blacklist = bool((previous_results.get("blacklist") or {}).get("is_listed"))
        if not previous_record:
            # The previous report was deleted from the history, so the hash
            # proves something changed but there is nothing left to compare
            # against. An absent baseline reads as "everything was fine
            # before", which would invent a blacklist listing or a TLS
            # regression out of a missing row, so no transition is claimed.
            severity = "medium"
            summary = f"Observed changes for {monitor['target']}"
            details["baseline_missing"] = True
        elif blacklist_listed and not previous_blacklist:
            severity = "critical"
            summary = f"{monitor['target']} is now listed on a DNS blacklist"
        elif (results.get("weak_auth") or {}).get("weak_credentials_found") and not (
            (previous_results.get("weak_auth") or {}).get("weak_credentials_found")
        ):
            severity = "critical"
            summary = f"{monitor['target']} accepts weak/default credentials"
        elif previous_grade in {"A+", "A", "B"} and tls_grade in {"D", "F", "T"}:
            severity = "high"
            summary = f"{monitor['target']} TLS grade regressed from {previous_grade} to {tls_grade}"
        elif record_transition:
            severity, summary = record_transition
        else:
            severity = "medium"
            summary = f"Observed changes for {monitor['target']}"
        if previous_record:
            details["previous_tls_grade"] = previous_grade
            details["previous_blacklist_listed"] = previous_blacklist
            # The scan this change is measured against, so the event UI can
            # request a full old-vs-new diff (/api/compare) on demand.
            details["previous_scan_id"] = previous_record.get("id")
        return current_hash, {
            "event_type": "scan_changed",
            "severity": severity,
            "summary": summary,
            "details": details,
        }

    return current_hash, {
        "event_type": "scan_unchanged",
        "severity": "info",
        "summary": f"No changes detected for {monitor['target']}",
        "details": details,
    }


def _scan_monitor(monitor, progress_cb=None):
    """Run a monitor scan, save history, and advance its schedule."""
    target = _normalize_domain(monitor.get("target", ""))
    if not _is_valid_domain(target):
        raise ValueError("Monitor target is not a valid public domain")

    checks = monitor.get("checks") or ["all"]
    results = run_selected_checks(target, checks, progress_cb=progress_cb)
    results["domain"] = target
    results["timestamp"] = datetime.now(timezone.utc).isoformat()
    results["monitored_record"] = _resolve_monitored_record(target, monitor.get("record_type"))
    _attach_rapid7_findings(results, target)
    results["recommendations"] = recommendations.generate(results)
    results["recommendation_counts"] = recommendations.summarize_counts(results["recommendations"])
    results["monitor"] = {
        "id": monitor["id"],
        "name": monitor["name"],
        "domain": monitor["domain"],
        "target": target,
        "record_type": monitor["record_type"],
        "record_value": monitor.get("record_value"),
        "source_type": monitor.get("source_type"),
        "provider": monitor.get("provider"),
    }
    previous_record = db.get_scan(monitor["last_scan_id"]) if monitor.get("last_scan_id") else None
    current_hash, event = _monitor_event_from_results(monitor, results, previous_record)
    scan_id = db.save_scan(target, results)
    db.mark_monitor_scanned(monitor["id"], scan_id, monitor.get("schedule_minutes") or 1440)
    db.update_monitor(monitor["id"], last_state_hash=current_hash)
    event_id = db.create_monitor_event(
        monitor["id"],
        scan_id=scan_id,
        event_type=event["event_type"],
        severity=event["severity"],
        summary=event["summary"],
        details=event["details"],
    )
    sn_result = _notify_servicenow(event_id, event, monitor)
    if sn_result:
        event["servicenow"] = sn_result
    updated = db.get_monitor(monitor["id"])
    return {
        "monitor": _serialize_monitor(updated),
        "scan_id": scan_id,
        "results": results,
        "event": event,
    }



def _notify_servicenow(event_id, event, monitor):
    """Create a ServiceNow incident for actionable monitor events."""
    if not event_id:
        return None
    if event.get("event_type") in {"scan_unchanged", "baseline_created"}:
        return None
    result = servicenow.create_incident(
        summary=event.get("summary") or "DomainLens monitor alert",
        severity=event.get("severity") or "info",
        details=event.get("details") or {},
        monitor=monitor or {},
    )
    if not result:
        return None
    if result.get("sys_id"):
        db.update_monitor_event(
            event_id,
            servicenow_sys_id=result.get("sys_id"),
            servicenow_number=result.get("number"),
            notified_at=datetime.now(timezone.utc).isoformat(),
        )
    return result


def _process_due_monitors(limit=None):
    """Run all due monitors once (delegates to scheduler module)."""
    return monitor_scheduler.process_due_monitors(
        db=db,
        scan_monitor_fn=_scan_monitor,
        notify_fn=_notify_servicenow,
        safe_error_fn=_safe_error,
        run_lock=_monitor_run_lock,
        limit=limit,
    )


def _run_scheduler_digest():
    monitor_scheduler.maybe_run_reporting_digest(db)


def _scheduler_config():
    """Expose monitor scheduler configuration for the UI/API."""
    cfg = domainlens_config.load_settings().scheduler()
    state = monitor_scheduler.state_snapshot()
    return {**cfg, "state": state}


def _monitor_scheduler_loop():
    """Background loop that processes due monitors on a fixed interval."""
    monitor_scheduler.scheduler_loop(
        _scheduler_stop,
        lambda: _process_due_monitors(),
        _run_scheduler_digest,
    )


def _start_scheduler_once():
    """Start the monitoring scheduler only once per process."""
    global _scheduler_started
    if os.environ.get("DOMAINLENS_DISABLE_SCHEDULER", "").strip().lower() in {"1", "true", "yes"}:
        log.info("Monitor scheduler disabled by DOMAINLENS_DISABLE_SCHEDULER")
        return
    if _scheduler_started:
        return
    _scheduler_started = True
    cfg = _scheduler_config()
    log.info(
        "Monitor scheduler started (enabled=%s, poll=%ss, concurrency=%s)",
        cfg["enabled"],
        cfg["poll_seconds"],
        cfg["concurrency"],
    )
    thread = threading.Thread(
        target=_monitor_scheduler_loop,
        name="domainlens-monitor-scheduler",
        daemon=True,
    )
    thread.start()


# ---------------------------------------------------------------------------
# Security headers for our own responses
# ---------------------------------------------------------------------------


@app.before_request
def _require_oauth_login():
    return auth.enforce_login_before_request()


@app.context_processor
def _inject_auth():
    return {
        "auth_status": auth.status_payload(),
        "current_user": auth.current_user(),
    }

@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'"
    )
    return response


# ---------------------------------------------------------------------------
# Rate limiting (simple in-memory)
# ---------------------------------------------------------------------------

_rate_store = {}


def _rate_limit_settings(bucket="scan"):
    scan_settings = domainlens_config.load_settings().scan()
    if bucket == "dns_lookup":
        return scan_settings.get("dns_lookup_rate_limit") or {
            "requests": 60, "window_seconds": 60}
    return scan_settings["rate_limit"]


def _check_rate_limit(ip, bucket="scan"):
    """Rate-limit per client, per kind of work.

    Buckets are separate because the costs are not comparable: a scan runs for
    tens of seconds and hits dozens of third parties, a DNS lookup is one UDP
    round trip. Sharing one budget meant a handful of lookups used up the scan
    allowance, so checking a few records left you unable to start a scan — and
    made a normal burst of lookups look like abuse.
    """
    limits = _rate_limit_settings(bucket)
    window = int(limits.get("window_seconds", 60))
    maximum = int(limits.get("requests", 10))
    now = datetime.now(timezone.utc).timestamp()
    key = (bucket, ip)
    if key not in _rate_store:
        _rate_store[key] = []
    _rate_store[key] = [t for t in _rate_store[key] if now - t < window]
    if len(_rate_store[key]) >= maximum:
        return False
    _rate_store[key].append(now)
    return True


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

# Sub-navigation per section. Kept here rather than in each template so a
# new tool is added in one place and every page agrees on what exists.
_LOOKUP_SUBNAV = [
    ("nav.lookup_ip", "/lookup/ip"),
    ("nav.lookup_dns", "/lookup/dns"),
    ("nav.lookup_impersonation", "/lookup/impersonation"),
]
_REPORTS_SUBNAV = [
    ("nav.reports_history", "/reports"),
    ("nav.reports_trends", "/trends"),
]


def _subnav(items, current):
    return [{"key": key, "href": href, "active": href == current}
            for key, href in items]


@app.route("/")
def index():
    return render_template("index.html", section="scan")


@app.route("/lookup/ip")
def lookup_ip_view():
    return render_template(
        "lookup_ip.html", section="lookup",
        subnav=_subnav(_LOOKUP_SUBNAV, "/lookup/ip"))


@app.route("/lookup/dns")
def lookup_dns_view():
    return render_template(
        "lookup_dns.html", section="lookup",
        subnav=_subnav(_LOOKUP_SUBNAV, "/lookup/dns"))


@app.route("/lookup/impersonation")
def lookup_impersonation_view():
    return render_template(
        "lookup_impersonation.html", section="lookup",
        subnav=_subnav(_LOOKUP_SUBNAV, "/lookup/impersonation"))


@app.route("/monitoring")
def monitoring_view():
    return render_template("monitoring.html", section="monitoring")


@app.route("/reports")
def reports_view():
    return render_template(
        "reports.html", section="reports",
        subnav=_subnav(_REPORTS_SUBNAV, "/reports"))


@app.route("/remediate")
def remediate_index():
    """Landing for the remediation deep links, which had no way in.

    /remediate/domain/<domain> and /remediate/vuln/<id> existed as ServiceNow
    targets only, so the pages were unreachable from the app itself.
    """
    return render_template("remediate_index.html", section="remediation")


@app.route("/login")
def login_page():
    cfg = auth.config()
    next_url = request.args.get("next") or "/"
    if auth.current_user():
        return redirect(next_url)
    if auth.mfa_pending_user_id():
        return redirect(url_for("auth_mfa_page", next=next_url))
    error = request.args.get("error")
    message = request.args.get("message")
    return render_template(
        "login.html",
        # No password policy and no local_config here: the sign-in page has no
        # use for either, and handing them to an anonymous visitor is how they
        # ended up rendered on it.
        auth_cfg=cfg,
        next_url=next_url,
        error=error,
        message=message,
        providers=[cfg["provider"]] if cfg.get("oauth_configured") else [],
    )


@app.route("/auth/login")
def auth_login_start():
    cfg = auth.config()
    if not cfg.get("oauth_enabled"):
        return redirect(url_for("login_page", error="oauth_disabled"))
    if not cfg.get("oauth_configured"):
        return redirect(url_for("login_page", error="oauth_not_configured"))

    state = __import__("secrets").token_urlsafe(24)
    session["oauth_state"] = state
    session["oauth_next"] = request.args.get("next") or "/"
    redirect_uri = cfg["redirect_uri"] or url_for("auth_callback", _external=True)
    session["oauth_redirect_uri"] = redirect_uri
    return redirect(auth.build_authorize_url(state, redirect_uri))


@app.route("/auth/callback")
def auth_callback():
    cfg = auth.config()
    if not cfg.get("oauth_enabled"):
        return redirect(url_for("login_page", error="oauth_disabled"))

    error = request.args.get("error")
    if error:
        return redirect(url_for("login_page", error=error))

    state = request.args.get("state")
    code = request.args.get("code")
    if not code or not state or state != session.get("oauth_state"):
        return redirect(url_for("login_page", error="invalid_state"))

    redirect_uri = session.get("oauth_redirect_uri") or cfg["redirect_uri"] or url_for("auth_callback", _external=True)
    try:
        profile = auth.exchange_code(code, redirect_uri)
    except Exception as exc:
        log.warning("OAuth callback failed: %s", exc)
        return redirect(url_for("login_page", error="token_exchange_failed"))

    if not auth.user_allowed(profile):
        auth.logout_user()
        return redirect(url_for("login_page", error="access_denied"))

    try:
        profile = auth.resolve_federated_user(profile)
    except PermissionError:
        auth.logout_user()
        return redirect(url_for("login_page", error="access_denied"))

    next_url = session.pop("oauth_next", "/")
    auth.login_user(profile)
    if profile.get("db_user"):
        try:
            db.update_user(profile["id"], last_login_at=datetime.now(timezone.utc).isoformat())
        except Exception:
            pass
    if not isinstance(next_url, str) or not next_url.startswith("/"):
        next_url = "/"
    return redirect(next_url)


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    """OAuth 2.0 token endpoint — preferred auth for SCIM provisioning."""
    form = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    token, err = scim_oauth.authenticate_token_request(
        form,
        request.headers.get("Authorization"),
    )
    if err:
        status = 400
        if err == "invalid_client":
            status = 401
        elif err == "server_error":
            status = 503
        return jsonify({"error": err}), status
    return jsonify(token)


@app.route("/auth/saml/metadata")
def auth_saml_metadata():
    cfg = saml_sp.saml_config()
    entity_id = cfg.get("entity_id") or url_for("auth_saml_metadata", _external=True)
    acs_url = cfg.get("acs_url") or url_for("auth_saml_acs", _external=True)
    xml = saml_sp.build_sp_metadata(entity_id=entity_id, acs_url=acs_url)
    return app.response_class(xml, mimetype="application/samlmetadata+xml")


@app.route("/auth/saml/login")
def auth_saml_login():
    cfg = saml_sp.saml_config()
    if not cfg.get("enabled"):
        return redirect(url_for("login_page", error="saml_disabled"))
    if not cfg.get("configured"):
        return redirect(url_for("login_page", error="saml_not_configured"))
    entity_id = cfg.get("entity_id") or url_for("auth_saml_metadata", _external=True)
    acs_url = cfg.get("acs_url") or url_for("auth_saml_acs", _external=True)
    session["oauth_next"] = request.args.get("next") or "/"
    target = saml_sp.build_authn_request(
        entity_id=entity_id,
        acs_url=acs_url,
        idp_sso_url=cfg["idp_sso_url"],
    )
    return redirect(target)


@app.route("/auth/saml/acs", methods=["POST"])
def auth_saml_acs():
    cfg = saml_sp.saml_config()
    if not cfg.get("enabled"):
        return redirect(url_for("login_page", error="saml_disabled"))
    saml_response = request.form.get("SAMLResponse") or ""
    if not saml_response:
        return redirect(url_for("login_page", error="saml_failed"))
    try:
        profile = saml_sp.parse_saml_response(saml_response, cfg)
    except Exception as exc:
        log.warning("SAML ACS rejected: %s", exc)
        return redirect(url_for("login_page", error="saml_failed"))
    if not auth.user_allowed(profile):
        auth.logout_user()
        return redirect(url_for("login_page", error="access_denied"))
    try:
        profile = auth.resolve_federated_user(profile)
    except PermissionError:
        auth.logout_user()
        return redirect(url_for("login_page", error="access_denied"))
    next_url = session.pop("oauth_next", "/")
    auth.login_user(profile)
    if profile.get("db_user"):
        try:
            db.update_user(profile["id"], last_login_at=datetime.now(timezone.utc).isoformat())
        except Exception:
            pass
    if not isinstance(next_url, str) or not next_url.startswith("/"):
        next_url = "/"
    return redirect(next_url)


@app.route("/auth/local/login", methods=["POST"])
def auth_local_login():
    next_url = request.form.get("next") or request.args.get("next") or "/"
    if not isinstance(next_url, str) or not next_url.startswith("/"):
        next_url = "/"
    email = request.form.get("email") or ""
    password = request.form.get("password") or ""
    user, error, needs_mfa = auth.attempt_local_login(email, password)
    if error:
        return redirect(url_for("login_page", error=error, next=next_url))
    if needs_mfa:
        auth.set_mfa_pending(user["id"])
        session["oauth_next"] = next_url
        return redirect(url_for("auth_mfa_page", next=next_url))
    auth.login_local_user_record(user)
    local = auth.local_config()
    if local["mfa_required"] and local["mfa_available"] and not user.get("mfa_enabled"):
        return redirect(url_for("account_security", message="mfa_required"))
    return redirect(next_url)


@app.route("/auth/mfa", methods=["GET"])
def auth_mfa_page():
    if not auth.mfa_pending_user_id():
        return redirect(url_for("login_page"))
    next_url = request.args.get("next") or "/"
    return render_template(
        "mfa.html",
        next_url=next_url,
        error=request.args.get("error"),
    )


@app.route("/auth/mfa", methods=["POST"])
def auth_mfa_verify():
    uid = auth.mfa_pending_user_id()
    if not uid:
        return redirect(url_for("login_page", error="mfa_session_expired"))
    next_url = request.form.get("next") or "/"
    if not isinstance(next_url, str) or not next_url.startswith("/"):
        next_url = "/"
    code = (request.form.get("code") or "").strip()
    user = db.get_user(uid, include_secrets=True)
    if not user or not user.get("enabled"):
        auth.logout_user()
        return redirect(url_for("login_page", error="mfa_session_expired"))

    # Rate-limit the second factor: without this, TOTP codes could be guessed
    # without limit after a correct password. Reuse the account lockout used by
    # the password step.
    if auth.is_locked(user):
        auth.logout_user()
        return redirect(url_for("login_page", error="account_locked"))

    ok = False
    if auth.verify_totp(user.get("mfa_secret") or "", code):
        ok = True
    elif auth.consume_backup_code(user, code):
        ok = True
    if not ok:
        locked = auth.register_mfa_failure(user)
        if locked:
            auth.logout_user()
            return redirect(url_for("login_page", error="account_locked"))
        return redirect(url_for("auth_mfa_page", error="invalid_code", next=next_url))

    auth.clear_login_failures(user["id"])
    auth.login_local_user_record(user)
    return redirect(next_url)


@app.route("/logout")
def logout():
    auth.logout_user()
    return redirect(url_for("login_page") if auth.config()["enabled"] and auth.config()["require_login"] else "/")


@app.route("/account")
@app.route("/account/security")
def account_security():
    user = auth.current_user()
    if not user:
        return redirect(url_for("login_page", next="/account"))
    if user.get("provider") != "local":
        return render_template(
            "account.html",
        section="admin",
            user=user,
            local_only=False,
            message=request.args.get("message"),
            error=request.args.get("error"),
            password_policy=auth.password_policy(),
            local_cfg=auth.local_config(),
            mfa_setup=None,
            backup_codes=None,
        )
    db_user = db.get_user(user["id"], include_secrets=False)
    mfa_setup = None
    setup_secret = session.get(auth.SESSION_MFA_SETUP_SECRET)
    if setup_secret and db_user:
        setup_uri = auth.otpauth_uri(setup_secret, db_user["email"])
        mfa_setup = {
            "secret": setup_secret,
            "uri": setup_uri,
            "qr_svg": auth.otpauth_qr_svg(setup_uri),
        }
    return render_template(
        "account.html",
        section="admin",
        user=db_user or user,
        local_only=True,
        message=request.args.get("message"),
        error=request.args.get("error"),
        password_policy=auth.password_policy(),
        local_cfg=auth.local_config(),
        mfa_setup=mfa_setup,
        backup_codes=session.pop("mfa_backup_codes_once", None),
    )


@app.route("/account/password", methods=["POST"])
def account_change_password():
    user = auth.current_user()
    if not user or user.get("provider") != "local":
        return redirect(url_for("login_page"))
    current = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""
    row = db.get_user(user["id"], include_secrets=True)
    if not row or not auth.verify_password(current, row.get("password_hash") or ""):
        return redirect(url_for("account_security", error="Current password is incorrect."))
    if new_password != confirm:
        return redirect(url_for("account_security", error="New passwords do not match."))
    errors = auth.validate_password(new_password, row.get("email") or "")
    if errors:
        return redirect(url_for("account_security", error="; ".join(errors)))
    db.update_user(
        row["id"],
        password_hash=auth.hash_password(new_password),
        password_changed_at=datetime.now(timezone.utc).isoformat(),
    )
    return redirect(url_for("account_security", message="password_updated"))


@app.route("/account/mfa/start", methods=["POST"])
def account_mfa_start():
    user = auth.current_user()
    if not user or user.get("provider") != "local":
        return redirect(url_for("login_page"))
    if not auth.local_config()["mfa_available"]:
        return redirect(url_for("account_security", error="MFA is disabled on this instance."))
    session[auth.SESSION_MFA_SETUP_SECRET] = auth.generate_totp_secret()
    return redirect(url_for("account_security", message="mfa_scan"))


@app.route("/account/mfa/confirm", methods=["POST"])
def account_mfa_confirm():
    user = auth.current_user()
    if not user or user.get("provider") != "local":
        return redirect(url_for("login_page"))
    secret = session.get(auth.SESSION_MFA_SETUP_SECRET)
    code = (request.form.get("code") or "").strip()
    if not secret or not auth.verify_totp(secret, code):
        return redirect(url_for("account_security", error="Invalid MFA code. Try again."))
    backup = auth.generate_backup_codes()
    db.update_user(
        user["id"],
        mfa_enabled=True,
        mfa_secret=secret,
        mfa_backup_codes=auth.hash_backup_codes(backup),
    )
    session.pop(auth.SESSION_MFA_SETUP_SECRET, None)
    session["mfa_backup_codes_once"] = backup
    # refresh session flag
    sess = auth.current_user() or {}
    sess["mfa_enabled"] = True
    session[auth.SESSION_USER_KEY] = sess
    return redirect(url_for("account_security", message="mfa_enabled"))


@app.route("/account/mfa/disable", methods=["POST"])
def account_mfa_disable():
    user = auth.current_user()
    if not user or user.get("provider") != "local":
        return redirect(url_for("login_page"))
    if auth.local_config()["mfa_required"]:
        return redirect(url_for("account_security", error="MFA is required and cannot be disabled."))
    password = request.form.get("password") or ""
    code = (request.form.get("code") or "").strip()
    row = db.get_user(user["id"], include_secrets=True)
    if not row or not auth.verify_password(password, row.get("password_hash") or ""):
        return redirect(url_for("account_security", error="Password required to disable MFA."))
    if row.get("mfa_enabled") and not (
        auth.verify_totp(row.get("mfa_secret") or "", code) or auth.consume_backup_code(row, code)
    ):
        return redirect(url_for("account_security", error="Valid MFA code required to disable."))
    db.update_user(user["id"], mfa_enabled=False, mfa_secret=None, mfa_backup_codes=[])
    sess = auth.current_user() or {}
    sess["mfa_enabled"] = False
    session[auth.SESSION_USER_KEY] = sess
    return redirect(url_for("account_security", message="mfa_disabled"))


def _optional_integration_status():
    """Status of the optional API keys. Never includes the key values."""
    from settings import api_keys
    return api_keys.status(db=db)


@app.route("/admin/settings")
@auth.require_admin
def admin_settings_page():
    from settings import api_keys
    import connection_tests

    schema = _settings_store.admin_form_schema()
    return render_template(
        "admin_settings.html",
        section="admin",
        schema=schema,
        integrations=_optional_integration_status(),
        credential_groups=api_keys.credential_status(db=db),
        key_protection=api_keys.protection_state(db=db),
        testable_groups=list(connection_tests.GROUP_TESTS.keys()),
        message=request.args.get("message"),
        error=request.args.get("error"),
    )


@app.route("/api/admin/api-keys", methods=["GET"])
@auth.require_admin
def api_admin_api_keys():
    from settings import api_keys
    return jsonify({
        "keys": _optional_integration_status(),
        "credentials": api_keys.credential_status(db=db),
        "protection": api_keys.protection_state(db=db),
    })


@app.route("/api/admin/api-keys/<env_name>", methods=["PUT", "DELETE"])
@auth.require_admin
def api_admin_api_key_update(env_name):
    """Write-only endpoint: it accepts a key but never returns one."""
    from settings import api_keys

    if not api_keys.is_managed(env_name):
        return jsonify({"error": "Unknown API key"}), 404
    if api_keys.is_env_locked(env_name):
        return jsonify({
            "error": "This key is set via an environment variable and cannot be "
                     "changed here. Remove it from the environment first."
        }), 409

    user = auth.current_user() or {}
    user_id = int(user.get("id") or 0) or None

    try:
        if request.method == "DELETE":
            api_keys.clear_key(env_name, user_id=user_id, db=db)
        else:
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Invalid JSON body"}), 400
            api_keys.set_key(env_name, data.get("value"), user_id=user_id, db=db)
        _reload_settings()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        log.exception("Failed to update API key %s", env_name)
        return jsonify({"error": "Could not store the key"}), 500

    return jsonify({
        "keys": _optional_integration_status(),
        "credentials": api_keys.credential_status(db=db),
    })


@app.route("/api/admin/api-keys/<target>/test", methods=["POST"])
@auth.require_admin
def api_admin_api_key_test(target):
    """Live connection test — never returns or logs the credential value."""
    import connection_tests

    if target not in connection_tests.KEY_TESTS and target not in connection_tests.GROUP_TESTS:
        return jsonify({"error": "Unknown test target"}), 404
    return jsonify(connection_tests.run_test(target))


@app.route("/api/admin/settings/<section>", methods=["PATCH"])
@auth.require_admin
def api_admin_settings_patch(section):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON body"}), 400
    user = auth.current_user()
    user_id = int(user.get("id") or 0) if user else None
    try:
        updated = _settings_store.update_section(section, data, user_id=user_id)
        _reload_settings()
        return jsonify({"section": section, "values": updated})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503
    except Exception as exc:
        log.exception("Settings update failed for %s", section)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/i18n/<locale>.json")
def api_i18n_locale(locale):
    code = locale.split(".", 1)[0].strip().lower()
    if code not in i18n_mod.supported_locales():
        code = "en"
    return jsonify(i18n_mod.load_locale(code))


@app.route("/api/locale", methods=["POST"])
def api_set_locale():
    data = request.get_json(silent=True) or {}
    loc = (data.get("locale") or "").strip().lower()
    if loc not in i18n_mod.supported_locales():
        return jsonify({"error": "Unsupported locale"}), 400
    session["locale"] = loc
    return jsonify({"locale": loc})


@app.route("/admin/users")
@auth.require_admin
def admin_users_page():
    return render_template(
        "admin_users.html",
        section="admin",
        users=db.list_users(),
        password_policy=auth.password_policy(),
        message=request.args.get("message"),
        error=request.args.get("error"),
    )


@app.route("/admin/users", methods=["POST"])
@auth.require_admin
def admin_users_create():
    email = (request.form.get("email") or "").strip().lower()
    name = (request.form.get("name") or "").strip()
    role = (request.form.get("role") or "user").strip().lower()
    password = request.form.get("password") or ""
    if role not in {"user", "admin"}:
        role = "user"
    if not email:
        return redirect(url_for("admin_users_page", error="Email is required."))
    if db.get_user_by_email(email):
        return redirect(url_for("admin_users_page", error="A user with that email already exists."))
    errors = auth.validate_password(password, email)
    if errors:
        return redirect(url_for("admin_users_page", error="; ".join(errors)))
    db.create_user(
        email=email,
        password_hash=auth.hash_password(password),
        name=name or email.split("@")[0],
        role=role,
        enabled=True,
    )
    return redirect(url_for("admin_users_page", message="user_created"))


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@auth.require_admin
def admin_users_toggle(user_id):
    me = auth.current_user()
    if me and int(me.get("id") or 0) == user_id:
        return redirect(url_for("admin_users_page", error="You cannot disable your own account."))
    row = db.get_user(user_id)
    if not row:
        return redirect(url_for("admin_users_page", error="User not found."))
    db.update_user(user_id, enabled=not row.get("enabled"))
    return redirect(url_for("admin_users_page", message="user_updated"))


@app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@auth.require_admin
def admin_users_reset_password(user_id):
    password = request.form.get("password") or ""
    row = db.get_user(user_id)
    if not row:
        return redirect(url_for("admin_users_page", error="User not found."))
    errors = auth.validate_password(password, row.get("email") or "")
    if errors:
        return redirect(url_for("admin_users_page", error="; ".join(errors)))
    db.update_user(
        user_id,
        password_hash=auth.hash_password(password),
        password_changed_at=datetime.now(timezone.utc).isoformat(),
        failed_logins=0,
        locked_until=None,
    )
    return redirect(url_for("admin_users_page", message="password_reset"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@auth.require_admin
def admin_users_delete(user_id):
    me = auth.current_user()
    if me and int(me.get("id") or 0) == user_id:
        return redirect(url_for("admin_users_page", error="You cannot delete your own account."))
    db.delete_user(user_id)
    return redirect(url_for("admin_users_page", message="user_deleted"))


@app.route("/api/auth/me")
def api_auth_me():
    return jsonify(auth.status_payload())


@app.route("/api/preferences/appearance", methods=["POST"])
def api_preferences_appearance():
    """Store a display preference for whoever is asking.

    Written to the user record when there is one and to a cookie always. The
    cookie is not a fallback for anonymous visitors alone: running with
    authentication switched off is a supported configuration, and there is no
    record to write to in that case.
    """
    appearance = _reload_settings().appearance()
    if not appearance.get("allow_user_override", True):
        return jsonify({"error": "Appearance is set centrally on this instance"}), 403

    payload = request.get_json(silent=True) or {}
    theme = theming.normalize_theme(payload.get("theme"))
    accent = theming.normalize_accent(payload.get("accent"))
    if payload.get("theme") is not None and theme is None:
        return jsonify({"error": "Unknown theme"}), 400
    if payload.get("accent") is not None and accent is None:
        return jsonify({"error": "Accent must be a hex colour like #5b8def"}), 400
    if theme is None and accent is None:
        return jsonify({"error": "Nothing to set"}), 400

    user = auth.current_user()
    if user and user.get("id"):
        prefs = dict(db.get_user(user["id"]).get("prefs") or {})
        if theme:
            prefs["theme"] = theme
        if accent:
            prefs["accent"] = accent
        db.update_user(user["id"], prefs=prefs)

    response = jsonify({"theme": theme, "accent": accent})
    for name, value in ((theming.THEME_COOKIE, theme), (theming.ACCENT_COOKIE, accent)):
        if not value:
            continue
        response.set_cookie(
            name, value,
            max_age=theming.COOKIE_MAX_AGE,
            samesite="Lax",
            httponly=False,      # only ever read back as a display preference
            secure=request.is_secure,
        )
    return response


@app.route("/api/admin/users")
@auth.require_admin
def api_admin_users():
    return jsonify({"users": db.list_users()})


@app.route("/trends")
def trends_view():
    return render_template(
        "trends.html", section="reports",
        subnav=_subnav(_REPORTS_SUBNAV, "/trends"))


@app.route("/api/reporting/overview", methods=["GET"])
def api_reporting_overview():
    days = _parse_positive_int(request.args.get("days"), 30, minimum=1, maximum=365)
    domain = request.args.get("domain", "").strip().lower() or None
    if domain and not _is_valid_domain(domain):
        return jsonify({"error": "Invalid domain filter"}), 400
    return jsonify(db.reporting_overview(days=days, domain=domain))


@app.route("/api/reporting/domains", methods=["GET"])
def api_reporting_domains():
    days = _parse_positive_int(request.args.get("days"), 30, minimum=1, maximum=365)
    domain = request.args.get("domain", "").strip().lower() or None
    if domain and not _is_valid_domain(domain):
        return jsonify({"error": "Invalid domain filter"}), 400
    return jsonify(db.reporting_domains(days=days, domain=domain))


@app.route("/api/reporting/trends", methods=["GET"])
def api_reporting_trends():
    days = _parse_positive_int(request.args.get("days"), 30, minimum=1, maximum=365)
    domain = request.args.get("domain", "").strip().lower() or None
    if domain and not _is_valid_domain(domain):
        return jsonify({"error": "Invalid domain filter"}), 400
    return jsonify(db.reporting_trends(days=days, domain=domain))


@app.route("/api/reporting/scheduler", methods=["GET"])
def api_reporting_scheduler():
    days = _parse_positive_int(request.args.get("days"), 7, minimum=1, maximum=90)
    return jsonify({
        "scheduler": _scheduler_config(),
        "overview": db.reporting_overview(days=days),
        "monitors": db.monitor_stats(),
    })


@app.route("/api/config", methods=["GET"])
def api_config():
    snap = domainlens_config.load_settings().public_snapshot()
    snap["version"] = app_version.info()
    return jsonify(snap)


@app.route("/api/osint", methods=["POST"])
def api_osint():
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
    data = request.get_json(silent=True) or {}
    domain = _normalize_domain(data.get("domain", ""))
    if not _is_valid_domain(domain):
        return jsonify({"error": "Invalid domain name. Use format: example.com"}), 400
    return jsonify(osint.collect_osint(domain))


@app.route("/api/integrations/servicenow", methods=["GET"])
def api_servicenow_status():
    cfg = servicenow.config()
    return jsonify({
        "enabled": cfg["enabled"],
        "configured": cfg["configured"],
        "instance": cfg["instance"],
        "min_severity": cfg["min_severity"],
        "category": cfg["category"],
        "subcategory": cfg["subcategory"],
    })


@app.route("/api/vuln-imports", methods=["GET"])
def api_vuln_imports_list():
    return jsonify({
        "imports": db.list_vuln_imports(),
        "stats": db.vuln_import_stats(),
        "settings": domainlens_config.load_settings().rapid7(),
    })


@app.route("/api/vuln-imports", methods=["POST"])
def api_vuln_imports_create():
    """Upload InsightVM/Nexpose CSV or XLSX — lean-filtered (not full 1GB dumps)."""
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    cfg = domainlens_config.load_settings().rapid7()
    if not cfg.get("enabled", True):
        return jsonify({"error": "Rapid7 import is disabled in settings"}), 400

    upload = request.files.get("file") or request.files.get("export")
    if not upload or not upload.filename:
        return jsonify({"error": "Missing file field (file or export)"}), 400

    data = upload.read()
    if not data:
        return jsonify({"error": "Empty file"}), 400
    if len(data) > 50 * 1024 * 1024:
        return jsonify({
            "error": (
                "File too large (max 50 MB). Prefer InsightVM Console/Cloud API sync "
                "(Settings → Rapid7 → source_mode) or export only Critical/Severe."
            )
        }), 400

    user = auth.current_user()
    user_id = int(user.get("id") or 0) if user else None
    push = request.args.get("push_cmdb", "").lower() in {"1", "true", "yes"}
    try:
        result = vuln_bridge.ingest_file_bytes(
            data,
            filename=upload.filename,
            content_type=upload.content_type,
            imported_by=user_id,
            push_cmdb=push if push else None,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        log.exception("Rapid7 import parse failed")
        return jsonify({"error": _safe_error(exc)}), 500

    return jsonify({
        "import": result.get("import"),
        "summary": result.get("summary"),
        "warnings": result.get("warnings"),
        "header_map": result.get("header_map"),
        "cmdb": result.get("cmdb"),
        "stats": db.vuln_import_stats(),
    }), 201


@app.route("/api/vuln-imports/sync", methods=["POST"])
@auth.require_admin
def api_vuln_imports_sync():
    """Lean InsightVM API sync (Console v3 or Cloud v4) — avoids full exports."""
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
    body = request.get_json(silent=True) or {}
    push = body.get("push_cmdb")
    user = auth.current_user()
    user_id = int(user.get("id") or 0) if user else None
    try:
        result = vuln_bridge.run_api_sync(push_cmdb=push, imported_by=user_id)
    except Exception as exc:
        log.exception("InsightVM API sync failed")
        return jsonify({"error": _safe_error(exc)}), 500
    status = 200 if result.get("ok") else 400
    result["stats"] = db.vuln_import_stats()
    return jsonify(result), status


@app.route("/api/vuln-imports/<int:import_id>/push-cmdb", methods=["POST"])
@auth.require_admin
def api_vuln_import_push_cmdb(import_id):
    """Link stored findings to ServiceNow CMDB CIs / Vulnerable Items."""
    result = vuln_bridge.push_import_to_cmdb(import_id)
    status = 200 if result.get("ok") else 404 if result.get("error") == "Import not found" else 400
    return jsonify(result), status


@app.route("/api/integrations/insightvm", methods=["GET"])
def api_insightvm_status():
    cfg = insightvm.config()
    return jsonify({
        "enabled": cfg.get("enabled"),
        "source_mode": cfg.get("source_mode"),
        "console_configured": cfg.get("console_configured"),
        "cloud_configured": cfg.get("cloud_configured"),
        "api_base_url": cfg.get("api_base_url") or None,
        "min_severity": cfg.get("min_severity"),
        "max_assets": cfg.get("max_assets"),
        "include_description": cfg.get("include_description"),
        "include_proof": cfg.get("include_proof"),
        "sync_to_servicenow_cmdb": cfg.get("sync_to_servicenow_cmdb"),
    })


@app.route("/api/integrations/servicenow/cmdb", methods=["GET"])
def api_servicenow_cmdb_status():
    cfg = servicenow_cmdb.cmdb_config()
    return jsonify({
        "configured": cfg.get("configured"),
        "cmdb_enabled": cfg.get("cmdb_enabled"),
        "create_vulnerable_items": cfg.get("create_vulnerable_items"),
        "ci_table": cfg.get("ci_table"),
        "vuln_item_table": cfg.get("vuln_item_table"),
        "vuln_table": cfg.get("vuln_table"),
        "ci_match_fields": cfg.get("ci_match_fields"),
        "vi_source": cfg.get("vi_source"),
        "preferred_path": (
            "ServiceNow Store: Rapid7 Integration for Security Operations "
            "+ CI Lookup Rules (Discovered Items → cmdb_ci)"
        ),
    })


@app.route("/api/integrations/servicenow/cmdb/lookup", methods=["POST"])
@auth.require_admin
def api_servicenow_cmdb_lookup():
    body = request.get_json(silent=True) or {}
    ci = servicenow_cmdb.lookup_ci(body.get("hostname"), body.get("ip"))
    if not ci:
        return jsonify({"matched": False}), 404
    return jsonify({"matched": True, "ci": ci})


@app.route("/api/vuln-imports/<int:import_id>", methods=["GET"])
def api_vuln_import_detail(import_id):
    record = db.get_vuln_import(import_id)
    if not record:
        return jsonify({"error": "Import not found"}), 404
    findings = db.list_vuln_findings(import_id=import_id, limit=1000)
    return jsonify({"import": record, "findings": findings})


@app.route("/api/vuln-imports/<int:import_id>", methods=["DELETE"])
@auth.require_admin
def api_vuln_import_delete(import_id):
    if not db.delete_vuln_import(import_id):
        return jsonify({"error": "Import not found"}), 404
    return jsonify({"ok": True, "stats": db.vuln_import_stats()})


@app.route("/api/vuln-findings", methods=["GET"])
def api_vuln_findings():
    domain = request.args.get("domain", "").strip().lower() or None
    if domain and not _is_valid_domain(domain):
        return jsonify({"error": "Invalid domain filter"}), 400
    import_id = request.args.get("import_id")
    try:
        import_id = int(import_id) if import_id else None
    except ValueError:
        return jsonify({"error": "Invalid import_id"}), 400
    min_severity = request.args.get("min_severity") or None
    limit = _parse_positive_int(request.args.get("limit"), 200, minimum=1, maximum=2000)
    findings = db.list_vuln_findings(
        domain=domain,
        import_id=import_id,
        min_severity=min_severity,
        limit=limit,
    )
    return jsonify({
        "domain": domain,
        "count": len(findings),
        "findings": findings,
        "stats": db.vuln_import_stats(),
    })


def _perform_scan(domain, checks, extra_dkim_selectors, save_history=True, progress_cb=None,
                  force_refresh=False):
    """Run a scan and build the full result payload.

    Shared by the synchronous endpoint and the background job runner so both
    produce byte-for-byte the same result.
    """
    results = run_selected_checks(
        domain, checks, extra_dkim_selectors=extra_dkim_selectors, progress_cb=progress_cb,
        force_refresh=force_refresh)

    results["domain"] = domain
    results["timestamp"] = datetime.now(timezone.utc).isoformat()
    _attach_rapid7_findings(results, domain)

    recs = recommendations.generate(results)
    results["recommendations"] = recs
    results["recommendation_counts"] = recommendations.summarize_counts(recs)
    results["remediation_plan"] = [
        {
            "priority": idx + 1,
            "severity": rec["severity"],
            "category": rec["category"],
            "title": rec["title"],
            "action": rec["fix"],
            "retest": rec.get("retest"),
            "reference": rec.get("reference"),
        }
        for idx, rec in enumerate(recs)
        if rec.get("severity") in ("critical", "high", "medium")
    ][:25]

    if save_history:
        try:
            results["scan_id"] = db.save_scan(domain, results)
        except Exception as exc:
            log.warning("Failed to store scan history: %s", exc)

    return results


def _scan_request_params():
    """Validate a scan request body. Returns (params, error_response)."""
    data = request.get_json(silent=True)
    if not data:
        return None, (jsonify({"error": "Invalid request"}), 400)
    domain = _normalize_domain(data.get("domain", ""))
    if not _is_valid_domain(domain):
        return None, (jsonify({"error": "Invalid domain name. Use format: example.com"}), 400)
    return {
        "domain": domain,
        "checks": _prepare_checks(data.get("checks", ["all"])),
        "extra_dkim_selectors": _prepare_dkim_selectors(data.get("dkim_selectors")),
        "save_history": bool(data.get("save_history", True)),
        # Opt-in only: the point of the cache is that a repeat scan does not
        # ask crt.sh and the OSINT feeds again, so refreshing has to be asked
        # for rather than being the accidental default.
        "force_refresh": bool(data.get("force_refresh") or data.get("refresh")),
    }, None


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Synchronous scan, kept for API consumers and scripts."""
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
    params, error = _scan_request_params()
    if error:
        return error
    return jsonify(_perform_scan(
        params["domain"], params["checks"], params["extra_dkim_selectors"],
        save_history=params["save_history"], force_refresh=params["force_refresh"],
    ))


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    """Start a scan in the background and return a job to poll.

    A scan that is already running for the same domain is returned as-is
    rather than started again: duplicate scans of one domain waste the work,
    race each other into the history, and were easy to trigger by pressing
    Scan twice or reloading the page.
    """
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
    params, error = _scan_request_params()
    if error:
        return error

    existing = scan_jobs.find_active(params["domain"])
    if existing:
        return jsonify({**existing, "already_running": True}), 409

    def runner(progress_cb):
        return _perform_scan(
            params["domain"], params["checks"], params["extra_dkim_selectors"],
            save_history=params["save_history"], progress_cb=progress_cb,
            force_refresh=params["force_refresh"],
        )

    return jsonify(scan_jobs.start(params["domain"], runner)), 202


@app.route("/api/scan/status/<job_id>", methods=["GET"])
def api_scan_status(job_id):
    """Poll a scan job. The result is only included once it is finished."""
    job = scan_jobs.get(job_id, include_result=True)
    if not job:
        return jsonify({"error": "Unknown or expired scan job"}), 404
    return jsonify(job)


@app.route("/api/scan/active", methods=["GET"])
def api_scan_active():
    """Whether a scan is already running for a domain, so a page that was
    navigated away from can pick the job back up."""
    domain = _normalize_domain(request.args.get("domain", ""))
    if not _is_valid_domain(domain):
        return jsonify({"error": "Invalid domain name"}), 400
    return jsonify({"job": scan_jobs.find_active(domain)})


def _ip_report(ip):
    """Everything establishable about one address, gathered concurrently."""
    report = {"ip": ip, "rdap": None, "reverse_dns": None,
              "blacklist": None, "geo": None, "threat": None}

    tasks = {
        "rdap": lambda: ip_intel.rdap(ip),
        "reverse_dns": lambda: ip_intel.reverse_dns(ip),
        "blacklist": lambda: check_blacklist(ip),
        "geo": lambda: osint.ip_context(ip),
        "threat": lambda: osint.otx_lookup(ip),
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {executor.submit(fn): key for key, fn in tasks.items()}
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                report[key] = future.result()
            except Exception as exc:
                report[key] = {"success": False, "error": _safe_error(exc)}

    # The one field a notice or takedown actually needs, lifted to the top so
    # it is not buried in the registry object.
    abuse = ((report.get("rdap") or {}).get("abuse") or {})
    report["abuse_contact"] = abuse.get("email")
    return report


@app.route("/api/ip/<path:value>", methods=["GET"])
def api_ip_lookup(value):
    """WHOIS/RDAP, reverse DNS, reputation and geo for a single address."""
    if not _check_rate_limit(request.remote_addr, bucket="dns_lookup"):
        return jsonify({"error": "Too many lookups in a short time. Wait a moment."}), 429
    address, refusal = ip_intel.classify(value)
    if address is None:
        return jsonify({"error": refusal}), 400
    if refusal:
        # Not an error: a correct address that no registry has an answer for.
        return jsonify({"ip": str(address), "not_applicable": refusal})
    try:
        return jsonify(_ip_report(str(address)))
    except Exception as exc:
        return jsonify({"error": _safe_error(exc)}), 502


@app.route("/api/evidence", methods=["POST"])
def api_evidence():
    """Assemble a takedown dossier for a domain that impersonates another."""
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
    data = request.get_json(silent=True) or {}
    domain = _normalize_domain(data.get("domain", ""))
    if not _is_valid_domain(domain):
        return jsonify({"error": "Invalid domain name"}), 400
    protected = _normalize_domain(data.get("protected_domain", "")) or None
    if protected and not _is_valid_domain(protected):
        return jsonify({"error": "Invalid protected domain"}), 400

    try:
        whois_result = lookup_whois(domain)
        dns_result = lookup_dns(domain)
        http_result = check_http_deep(domain)
        tls_result = check_ssl(domain)
        try:
            ip_report = _ip_report(_safe_resolve_ip(domain))
        except Exception as exc:
            ip_report = {"error": _safe_error(exc)}
        dossier = evidence.build(
            domain=domain,
            protected_domain=protected,
            whois_result=whois_result,
            dns_result=dns_result,
            http_result=http_result,
            tls_result=tls_result,
            ip_report=ip_report,
            observed_from=(http_result or {}).get("request_country"),
            tool_version=app_version.get_version(),
        )
    except Exception as exc:
        return jsonify({"error": _safe_error(exc)}), 502
    return jsonify(dossier)


@app.route("/api/dns/query", methods=["GET"])
def api_dns_query():
    """A dig-style lookup for checking a record you just changed.

    The resolver is picked from a fixed list rather than accepted as an
    address: this app commonly runs without authentication on a LAN, and a
    free-form resolver would make it a way to probe port 53 on any host the
    server can reach.
    """
    if not _check_rate_limit(request.remote_addr, bucket="dns_lookup"):
        return jsonify({"error": "Too many lookups in a short time. Wait a moment."}), 429
    try:
        result = dns_tools.query(
            request.args.get("name", ""),
            request.args.get("type", "A"),
            request.args.get("resolver", "system"),
        )
    except dns_tools.LookupError_ as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": _safe_error(exc)}), 502
    return jsonify(result)


@app.route("/api/checks", methods=["GET"])
def api_checks_catalog():
    """The grouped catalog of selectable checks, for the monitor form to render
    the same "pick what to run" selection the scan form offers."""
    return jsonify({"catalog": CHECK_CATALOG})


@app.route("/api/dns/options", methods=["GET"])
def api_dns_options():
    return jsonify({
        "types": dns_tools.RECORD_TYPES,
        "resolvers": sorted(dns_tools.RESOLVERS),
        # Provider-assigned CNAME targets: a dangling CNAME to one of these is
        # stale but not claimable. Sent so the lookup page can label a
        # dead-target CNAME without duplicating the list in JS.
        "provider_assigned": [
            {"suffix": s, "provider": e["provider"], "note": e["note"]}
            for e in security_checks._PROVIDER_ASSIGNED for s in e["cnames"]
        ],
    })


@app.route("/api/history", methods=["GET"])
def api_history_list():
    domain_filter = request.args.get("domain", "").strip().lower() or None
    if domain_filter and not _is_valid_domain(domain_filter):
        return jsonify({"error": "Invalid domain filter"}), 400
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100
    limit = max(1, min(limit, 500))

    days_arg = request.args.get("days")
    days = _parse_positive_int(days_arg, 0, minimum=1, maximum=365) if days_arg else None

    scans = db.list_scans(domain=domain_filter, limit=limit, days=days)
    stats = db.history_stats()
    return jsonify({"scans": scans, "stats": stats})


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def api_history_get(scan_id):
    record = db.get_scan(scan_id)
    if not record:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(record)


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def api_history_delete(scan_id):
    # Collect this first: the delete clears the reference, so afterwards there
    # is no way to tell which monitors just lost their baseline.
    affected = db.monitors_using_scan(scan_id)
    if not db.delete_scan(scan_id):
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"deleted": True, "monitors_affected": affected})


@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    db.clear_history()
    return jsonify({"cleared": True})


def _scan_compare_meta(record):
    """Compact per-scan header for a comparison: what it is and where to read it."""
    return {
        "id": record["id"],
        "domain": record.get("domain"),
        "created_at": record.get("created_at"),
        "grade": record.get("grade"),
        "score": record.get("score"),
        "issues_count": record.get("issues_count"),
        "report_url": f"/report/{record['id']}",
    }


@app.route("/api/compare", methods=["GET"])
def api_compare_scans():
    """Structured worse/better/changed diff between two saved scans.

    `a` is the older (baseline) scan, `b` the newer one. Used by both the
    history compare view and a monitor event's "what changed" panel, so the
    two never diverge in how a regression is judged.
    """
    try:
        a_id = int(request.args.get("a", ""))
        b_id = int(request.args.get("b", ""))
    except (TypeError, ValueError):
        return jsonify({"error": "Pass two scan ids: a (older) and b (newer)"}), 400

    old = db.get_scan(a_id)
    new = db.get_scan(b_id)
    if not old or not new:
        return jsonify({"error": "One or both scans were not found"}), 404

    old_counts = recommendations.summarize_counts(recommendations.generate(old["data"]))
    new_counts = recommendations.summarize_counts(recommendations.generate(new["data"]))
    diff = scan_diff.compare(old["data"], new["data"],
                             old_severity=old_counts, new_severity=new_counts)
    return jsonify({
        "a": _scan_compare_meta(old),
        "b": _scan_compare_meta(new),
        "diff": diff,
    })


@app.route("/api/monitors", methods=["GET"])
def api_monitors_list():
    due_only = request.args.get("due_only", "").strip().lower() in {"1", "true", "yes"}
    enabled = request.args.get("enabled")
    enabled_filter = None
    if enabled is not None:
        enabled_filter = enabled.strip().lower() in {"1", "true", "yes"}

    rows = db.list_monitors(enabled=enabled_filter, due_only=due_only, limit=500)
    latest = db.latest_scans_by_domain([item.get("domain") for item in rows])
    monitors = [
        _serialize_monitor(item, latest_scan=latest.get(item.get("domain")))
        for item in rows
    ]
    return jsonify({
        "monitors": monitors,
        "stats": db.monitor_stats(),
        "scheduler": _scheduler_config(),
        "events": db.list_monitor_events(limit=20),
    })


@app.route("/api/monitors", methods=["POST"])
def api_monitors_create():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    domain = _normalize_domain(data.get("domain", ""))
    target = _normalize_domain(data.get("target") or domain)
    if not _is_valid_domain(domain) or not _is_valid_domain(target):
        return jsonify({"error": "Invalid domain or target"}), 400

    record_type = str(data.get("record_type") or "A").upper()
    name = (data.get("name") or f"{target} ({record_type})").strip()
    schedule_minutes = _parse_positive_int(data.get("schedule_minutes"), 1440)
    checks = _prepare_checks(data.get("checks", ["all"]))
    enabled = bool(data.get("enabled", True))

    monitor_id = db.create_monitor(
        name=name,
        domain=domain,
        target=target,
        record_type=record_type,
        record_value=data.get("record_value"),
        source_type="manual",
        source_label="Manual monitor",
        provider=(data.get("provider") or "manual"),
        schedule_minutes=schedule_minutes,
        checks=checks,
        enabled=enabled,
        metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
    )
    return jsonify({"monitor": _serialize_monitor(db.get_monitor(monitor_id))}), 201


@app.route("/api/monitors/import", methods=["POST"])
def api_monitors_import():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    mode = str(data.get("mode") or "").strip().lower()
    schedule_minutes = _parse_positive_int(data.get("schedule_minutes"), 1440)
    checks = _prepare_checks(data.get("checks", ["all"]))
    enabled = bool(data.get("enabled", True))

    try:
        if mode == "zone_file":
            domain = _normalize_domain(data.get("domain", ""))
            zone_text = data.get("zone_text", "")
            if not _is_valid_domain(domain) or not isinstance(zone_text, str) or not zone_text.strip():
                return jsonify({"error": "Provide a valid domain and zone_text"}), 400
            monitor_defs = _zone_records_to_monitors(domain, zone_text)
        elif mode == "ovhcloud":
            zone_name = _normalize_domain(data.get("zone_name") or data.get("domain") or "")
            if not _is_valid_domain(zone_name):
                return jsonify({"error": "Provide a valid OVH zone_name"}), 400
            endpoint = (data.get("endpoint") or os.environ.get("OVH_ENDPOINT") or "https://eu.api.ovh.com/1.0").strip()
            app_key = (data.get("app_key") or os.environ.get("OVH_APP_KEY") or "").strip()
            app_secret = (data.get("app_secret") or os.environ.get("OVH_APP_SECRET") or "").strip()
            consumer_key = (data.get("consumer_key") or os.environ.get("OVH_CONSUMER_KEY") or "").strip()
            if not all([endpoint, app_key, app_secret, consumer_key]):
                return jsonify({"error": "OVH credentials are required"}), 400

            encoded_zone = quote(zone_name, safe="")
            record_ids = _ovh_request(
                "GET",
                f"/domain/zone/{encoded_zone}/record",
                endpoint=endpoint,
                app_key=app_key,
                app_secret=app_secret,
                consumer_key=consumer_key,
            )
            records = []
            for record_id in record_ids or []:
                details = _ovh_request(
                    "GET",
                    f"/domain/zone/{encoded_zone}/record/{record_id}",
                    endpoint=endpoint,
                    app_key=app_key,
                    app_secret=app_secret,
                    consumer_key=consumer_key,
                )
                records.append(details)
            monitor_defs = _ovh_records_to_monitors(zone_name, records)
        else:
            return jsonify({"error": "Unsupported import mode"}), 400

        if not monitor_defs:
            return jsonify({"error": "No monitorable DNS records found"}), 400

        stored = _save_monitor_definitions(
            monitor_defs,
            schedule_minutes=schedule_minutes,
            checks=checks,
            enabled=enabled,
        )
        return jsonify({"imported": len(stored), "monitors": stored}), 201
    except Exception as exc:
        return jsonify({"error": _safe_error(exc)}), 400


@app.route("/api/monitors/run-due", methods=["POST"])
def api_monitors_run_due():
    return jsonify(_process_due_monitors())


@app.route("/api/monitor-events", methods=["GET"])
def api_monitor_events():
    limit = _parse_positive_int(request.args.get("limit"), 100, minimum=1, maximum=500)
    monitor_id = request.args.get("monitor_id")
    if monitor_id:
        try:
            monitor_id = int(monitor_id)
        except ValueError:
            return jsonify({"error": "Invalid monitor_id"}), 400
    else:
        monitor_id = None
    return jsonify({"events": db.list_monitor_events(monitor_id=monitor_id, limit=limit)})


@app.route("/api/monitors/<int:monitor_id>", methods=["PATCH"])
def api_monitors_update(monitor_id):
    monitor = db.get_monitor(monitor_id)
    if not monitor:
        return jsonify({"error": "Monitor not found"}), 404

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    updates = {}
    if "name" in data and isinstance(data["name"], str) and data["name"].strip():
        updates["name"] = data["name"].strip()
    if "schedule_minutes" in data:
        updates["schedule_minutes"] = _parse_positive_int(data["schedule_minutes"], monitor["schedule_minutes"])
    if "checks" in data:
        updates["checks"] = _prepare_checks(data["checks"])
    if "enabled" in data:
        updates["enabled"] = bool(data["enabled"])
        updates["next_scan_at"] = datetime.now(timezone.utc).isoformat() if updates["enabled"] else None

    updated = db.update_monitor(monitor_id, **updates)
    return jsonify({"monitor": _serialize_monitor(updated)})


@app.route("/api/monitors/<int:monitor_id>", methods=["DELETE"])
def api_monitors_delete(monitor_id):
    if not db.delete_monitor(monitor_id):
        return jsonify({"error": "Monitor not found"}), 404
    return jsonify({"deleted": True})


@app.route("/api/monitors/<int:monitor_id>/scan", methods=["POST"])
def api_monitors_scan(monitor_id):
    monitor = db.get_monitor(monitor_id)
    if not monitor:
        return jsonify({"error": "Monitor not found"}), 404
    try:
        outcome = _scan_monitor(monitor)
        return jsonify(outcome)
    except Exception as exc:
        return jsonify({"error": _safe_error(exc)}), 400


@app.route("/api/monitors/<int:monitor_id>/scan/start", methods=["POST"])
def api_monitors_scan_start(monitor_id):
    """Run a monitor scan as a background job, so "Run now" reports progress.

    It shares the job registry with manual scans on purpose: the two used to
    be able to run against the same domain at the same time, racing each
    other into the history.
    """
    monitor = db.get_monitor(monitor_id)
    if not monitor:
        return jsonify({"error": "Monitor not found"}), 404

    target = _normalize_domain(monitor.get("target", ""))
    if not _is_valid_domain(target):
        return jsonify({"error": "Monitor target is not a valid public domain"}), 400

    existing = scan_jobs.find_active(target)
    if existing:
        return jsonify({**existing, "already_running": True}), 409

    def runner(progress_cb):
        return _scan_monitor(monitor, progress_cb=progress_cb)

    return jsonify(scan_jobs.start(target, runner)), 202


@app.route("/api/recommendations/<int:scan_id>", methods=["GET"])
def api_recommendations(scan_id):
    record = db.get_scan(scan_id)
    if not record:
        return jsonify({"error": "Scan not found"}), 404
    recs = recommendations.generate(record["data"])
    counts = recommendations.summarize_counts(recs)
    return jsonify({
        "scan_id": scan_id,
        "domain": record["domain"],
        "created_at": record["created_at"],
        "recommendations": recs,
        "counts": counts,
    })


@app.route("/remediate/vuln/<int:finding_id>")
def remediate_vuln(finding_id):
    """
    Deep link target from ServiceNow Vulnerable Items.
    Ownership stays in ServiceNow; this page shows fix + retest guidance.
    """
    finding = db.get_vuln_finding(finding_id)
    if not finding:
        abort(404)
    domain = (finding.get("domain") or finding.get("hostname") or "").strip().lower()
    latest = (db.list_scans(domain=domain, limit=1) or [None])[0] if domain else None
    advies = None
    try:
        advies = rapid7_import.finding_to_advies(finding, domain or None)
    except Exception:
        advies = None
    scan_url = f"/?domain={quote(domain)}&tab=advies" if domain else "/"
    return render_template(
        "remediate.html",
        finding=finding,
        advies=advies,
        domain=domain or None,
        scan_url=scan_url,
        latest_scan=latest,
    )


@app.route("/remediate/domain/<path:domain>")
def remediate_domain(domain):
    """Deep link from ServiceNow to domain Advies / scan."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or not _is_valid_domain(domain):
        abort(404)
    # Rescanning to read yesterday's advice is a minute of waiting and another
    # round of traffic at the domain for an answer already on disk, so the
    # stored scan is offered first when there is one.
    latest = (db.list_scans(domain=domain, limit=1) or [None])[0]
    return render_template(
        "remediate.html",
        finding=None,
        advies=None,
        domain=domain,
        scan_url=f"/?domain={quote(domain)}&tab=advies",
        latest_scan=latest,
    )


@app.route("/api/reverse-dns", methods=["POST"])
def api_reverse_dns():
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    ip = data.get("ip", "")
    if not isinstance(ip, str):
        return jsonify({"error": "Invalid IP"}), 400
    ip = ip.strip()

    if not _is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address format"}), 400

    results = lookup_reverse_dns(ip)
    return jsonify({"ip": ip, "ptr_records": results})


# Modular route packages (health/version/updates + report exports)
route_modules.register_routes(
    app,
    db=db,
    auth=auth,
    recommendations=recommendations,
    servicenow=servicenow,
    domainlens_config=domainlens_config,
    scheduler_config_fn=_scheduler_config,
)

_start_scheduler_once()


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    server = domainlens_config.load_settings().server()
    # Env overrides win so Docker (which sets DOMAINLENS_HOST=0.0.0.0) stays
    # reachable, while the native default remains localhost-only.
    host = (os.environ.get("DOMAINLENS_HOST") or server.get("host") or "127.0.0.1").strip()
    port = int(os.environ.get("DOMAINLENS_PORT") or server.get("port") or 5000)
    if host == "0.0.0.0":
        auth_on = False
        try:
            auth_on = auth.config().get("enabled", False)
        except Exception:
            pass
        if not auth_on:
            log.warning(
                "Binding to 0.0.0.0 with authentication DISABLED — the admin UI "
                "and all APIs are reachable by anyone on the network. Enable auth "
                "or bind to 127.0.0.1."
            )

    # Flask's built-in app.run() is the Werkzeug development server — it
    # prints its own "do not use in production" warning for good reason: no
    # real concurrency handling (single-threaded by default) and none of the
    # hardening a real WSGI server provides. Waitress is a pure-Python
    # production-grade WSGI server that runs identically on Windows (native
    # install) and Linux (Docker), so both documented install paths get the
    # same real server instead of only the dev one.
    from waitress import serve

    threads = int(os.environ.get("DOMAINLENS_WSGI_THREADS", "8"))
    log.info("Starting production WSGI server (waitress) on %s:%s (%d threads)", host, port, threads)
    serve(app, host=host, port=port, threads=threads)
