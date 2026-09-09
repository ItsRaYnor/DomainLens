"""
Open-source OSINT enrichment for DomainLens.

Sources (no commercial APIs required):
- Certificate Transparency via crt.sh
- Wayback Machine CDX historical snapshots
- IP/ASN context via ip-api.com (non-commercial free endpoint)
- Optional abuse.ch ThreatFox / URLhaus when ABUSECH_AUTH_KEY is set
- Optional AlienVault OTX when OTX_API_KEY is set
- Optional VirusTotal multi-vendor reputation when VIRUSTOTAL_API_KEY is set

Every optional source reports skipped=True when its key is absent. That is a
"not measured" state, deliberately distinct from a clean verdict: nothing
downstream may turn an unconfigured lookup into "this domain is fine".
"""

from __future__ import annotations

import logging
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

log = logging.getLogger("domainlens.osint")

_UA = "DomainLens-OSINT/1.0 (+https://github.com/ItsRaYnor/DomainLens)"
_TIMEOUT = 12

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _session():
    s = requests.Session()
    s.headers.update({"User-Agent": _UA, "Accept": "application/json"})
    return s


def _safe_error(exc):
    text = str(exc)
    if len(text) > 300:
        text = text[:300]
    return text


def _normalize_host(value):
    if not value:
        return ""
    host = str(value).strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    return host


def _is_related(host, domain):
    host = _normalize_host(host)
    domain = _normalize_host(domain)
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def _api_key(env_name):
    """Resolve an optional API key: environment first, then the admin-set value.

    Read through settings.api_keys so a key added from the admin UI takes
    effect without an env var and without restarting the container.
    """
    try:
        from settings import api_keys
        return api_keys.resolve(env_name)
    except Exception:
        return (os.environ.get(env_name) or "").strip()


# Some upstreams are much slower than the shared _TIMEOUT allows, and were
# timing out on every scan as a result. OTX's passive_dns endpoint and the
# Wayback CDX API (which walks every capture of the whole domain because of
# the url=domain/* wildcard) are both routinely slow.
_OTX_TIMEOUT = 25
_WAYBACK_TIMEOUT = 30


def _fetch_json(session, url, *, label, timeout, headers=None, attempts=2, auth_message=None):
    """GET JSON with one retry on timeout. Returns (data, error).

    Only timeouts are retried — a rejected key or a bad request will not fix
    itself, and retrying just makes a failing scan slower.
    """
    last_error = None
    for _ in range(attempts):
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
            if auth_message and resp.status_code in (401, 403):
                return None, auth_message
            resp.raise_for_status()
            return resp.json(), None
        except requests.Timeout:
            last_error = f"{label} did not respond within {timeout}s"
        except Exception as exc:
            return None, _safe_error(exc)
    return None, last_error


def certificate_transparency(domain, limit=100):
    """Discover related hostnames from public CT logs (crt.sh)."""
    result = {
        "success": False,
        "source": "crt.sh",
        "subdomains": [],
        "issuers": [],
        "certificate_count": 0,
    }
    try:
        import crtsh
        rows, fetch_error = crtsh.fetch(domain, timeout=_TIMEOUT, session=_session())
        if rows is None:
            result["error"] = fetch_error
            return result

        hosts = set()
        issuers = set()
        for row in rows[: max(limit * 5, limit)]:
            name_value = row.get("name_value") or ""
            for part in str(name_value).split("\n"):
                host = _normalize_host(part)
                if _DOMAIN_RE.match(host) and _is_related(host, domain):
                    hosts.add(host)
            issuer = row.get("issuer_name")
            if issuer:
                issuers.add(str(issuer)[:180])

        subdomains = sorted(hosts)
        result.update({
            "success": True,
            "subdomains": subdomains[:limit],
            "subdomain_count": len(subdomains),
            "issuers": sorted(issuers)[:20],
            "certificate_count": len(rows),
            "truncated": len(subdomains) > limit,
        })
    except Exception as exc:
        result["error"] = _safe_error(exc)
    return result


def wayback_snapshots(domain, limit=15):
    """Fetch recent Wayback Machine snapshots for the domain."""
    result = {
        "success": False,
        "source": "web.archive.org",
        "snapshots": [],
        "first_seen": None,
        "last_seen": None,
    }
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={quote(domain)}/*&output=json&fl=timestamp,original,statuscode"
        f"&filter=statuscode:200&collapse=timestamp:8&limit={int(limit)}"
    )
    try:
        rows, error = _fetch_json(
            _session(), url, label="Wayback Machine", timeout=_WAYBACK_TIMEOUT)
        if rows is None:
            result["error"] = error
            return result
        if not isinstance(rows, list) or len(rows) < 2:
            # CDX returns just the header row (or nothing) when the domain has
            # never been archived — an empty history, not a failure.
            result["success"] = True
            result["snapshots"] = []
            result["count"] = 0
            return result

        snapshots = []
        for row in rows[1:]:
            if not isinstance(row, (list, tuple)) or len(row) < 3:
                continue
            ts, original, status = row[0], row[1], row[2]
            snapshots.append({
                "timestamp": ts,
                "url": original,
                "status": status,
                "archive_url": f"https://web.archive.org/web/{ts}/{original}",
            })
        timestamps = [s["timestamp"] for s in snapshots if s.get("timestamp")]
        result.update({
            "success": True,
            "snapshots": snapshots,
            "first_seen": min(timestamps) if timestamps else None,
            "last_seen": max(timestamps) if timestamps else None,
            "count": len(snapshots),
        })
    except Exception as exc:
        result["error"] = _safe_error(exc)
    return result


def ip_context(domain):
    """Resolve domain and enrich IP with open ASN/geo metadata."""
    result = {
        "success": False,
        "source": "ip-api.com",
        "ip": None,
        "geo": None,
    }
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
        resp = _session().get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,message,country,regionName,city,isp,org,as,asname,query,reverse,proxy,hosting",
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            result["error"] = data.get("message") or "IP lookup failed"
            return result
        result.update({
            "success": True,
            "geo": {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "asname": data.get("asname"),
                "reverse": data.get("reverse"),
                "proxy": bool(data.get("proxy")),
                "hosting": bool(data.get("hosting")),
            },
        })
    except Exception as exc:
        result["error"] = _safe_error(exc)
    return result


def threatfox_lookup(domain):
    """Optional ThreatFox IOC search (requires free abuse.ch Auth-Key)."""
    key = _api_key("ABUSECH_AUTH_KEY")
    result = {
        "success": False,
        "source": "threatfox.abuse.ch",
        "configured": bool(key),
        "hits": [],
    }
    if not key:
        result["success"] = True
        result["skipped"] = True
        result["message"] = "Set ABUSECH_AUTH_KEY for ThreatFox lookups"
        return result
    try:
        resp = _session().post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": key},
            json={"query": "search_ioc", "search_term": domain},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        hits = []
        if data.get("query_status") == "ok":
            for item in data.get("data") or []:
                hits.append({
                    "ioc": item.get("ioc"),
                    "threat_type": item.get("threat_type"),
                    "malware": item.get("malware"),
                    "confidence": item.get("confidence_level"),
                    "first_seen": item.get("first_seen"),
                    "reference": item.get("reference"),
                })
        result.update({
            "success": True,
            "hits": hits[:25],
            "hit_count": len(hits),
            "query_status": data.get("query_status"),
        })
    except Exception as exc:
        result["error"] = _safe_error(exc)
    return result


def urlhaus_lookup(domain):
    """Optional URLhaus host lookup (requires free abuse.ch Auth-Key)."""
    key = _api_key("ABUSECH_AUTH_KEY")
    result = {
        "success": False,
        "source": "urlhaus.abuse.ch",
        "configured": bool(key),
        "urls": [],
    }
    if not key:
        result["success"] = True
        result["skipped"] = True
        result["message"] = "Set ABUSECH_AUTH_KEY for URLhaus lookups"
        return result
    try:
        resp = _session().post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers={"Auth-Key": key},
            data={"host": domain},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        urls = []
        for item in data.get("urls") or []:
            urls.append({
                "url": item.get("url"),
                "threat": item.get("threat"),
                "tags": item.get("tags") or [],
                "url_status": item.get("url_status"),
                "date_added": item.get("date_added"),
            })
        result.update({
            "success": True,
            "query_status": data.get("query_status"),
            "urls": urls[:25],
            "url_count": len(urls),
        })
    except Exception as exc:
        result["error"] = _safe_error(exc)
    return result


def otx_lookup(domain):
    """Optional AlienVault OTX passive DNS / pulse summary."""
    key = _api_key("OTX_API_KEY")
    result = {
        "success": False,
        "source": "otx.alienvault.com",
        "configured": bool(key),
        "pulses": 0,
        "passive_dns": [],
    }
    if not key:
        result["success"] = True
        result["skipped"] = True
        result["message"] = "Set OTX_API_KEY for OTX lookups"
        return result

    session = _session()
    headers = {"X-OTX-API-KEY": key}
    base = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}"

    # The pulse count is the actual threat signal; passive DNS is context.
    general_data, error = _fetch_json(
        session, f"{base}/general", label="OTX", timeout=_OTX_TIMEOUT,
        headers=headers, auth_message="OTX rejected the API key")
    if general_data is None:
        result["error"] = error
        return result

    result.update({
        "success": True,
        "pulses": (general_data.get("pulse_info") or {}).get("count", 0),
        "alexa": general_data.get("alexa"),
        "whois": general_data.get("whois"),
    })

    # A slow passive_dns call must not discard the pulse count we already
    # have — previously one timeout here failed the whole lookup.
    pdns_data, pdns_error = _fetch_json(
        session, f"{base}/passive_dns", label="OTX passive DNS", timeout=_OTX_TIMEOUT,
        headers=headers, auth_message="OTX rejected the API key")
    if pdns_data is None:
        result["passive_dns_error"] = pdns_error
        return result

    result["passive_dns"] = [
        {
            "record": item.get("address") or item.get("hostname"),
            "type": item.get("record_type"),
            "first": item.get("first"),
            "last": item.get("last"),
        }
        for item in (pdns_data.get("passive_dns") or [])[:20]
    ]
    return result


def virustotal_lookup(domain):
    """Optional VirusTotal domain reputation (API v3).

    Adds a multi-vendor view that the abuse.ch/OTX feeds do not give: those
    answer "is this domain in a malware/C2 feed", VirusTotal answers "how many
    engines currently flag it", plus a community reputation score.

    Without a key this returns skipped=True rather than an error or a zero
    verdict: not configured is not the same as "clean", and nothing downstream
    may read it as one.
    """
    key = _api_key("VIRUSTOTAL_API_KEY")
    result = {
        "success": False,
        "source": "virustotal.com",
        "configured": bool(key),
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reputation": None,
        "flagged_by": [],
    }
    if not key:
        result["success"] = True
        result["skipped"] = True
        result["message"] = "Set VIRUSTOTAL_API_KEY for VirusTotal reputation lookups"
        return result

    session = _session()
    data, error = _fetch_json(
        session,
        f"https://www.virustotal.com/api/v3/domains/{quote(domain)}",
        label="VirusTotal", timeout=_TIMEOUT,
        headers={"x-apikey": key},
        auth_message="VirusTotal rejected the API key")
    if data is None:
        result["error"] = error
        return result

    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    # Name the engines that flag it: a bare count invites arguing with the
    # number, while the vendor list can actually be checked.
    flagged = [
        name for name, verdict in (attributes.get("last_analysis_results") or {}).items()
        if (verdict or {}).get("category") in {"malicious", "suspicious"}
    ]
    result.update({
        "success": True,
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "harmless": int(stats.get("harmless") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "reputation": attributes.get("reputation"),
        "flagged_by": sorted(flagged)[:20],
    })
    return result


def collect_osint(domain):
    """Run all OSINT collectors and return a combined payload."""
    collectors = {
        "certificate_transparency": lambda: certificate_transparency(domain),
        "wayback": lambda: wayback_snapshots(domain),
        "ip_context": lambda: ip_context(domain),
        "threatfox": lambda: threatfox_lookup(domain),
        "urlhaus": lambda: urlhaus_lookup(domain),
        "otx": lambda: otx_lookup(domain),
        "virustotal": lambda: virustotal_lookup(domain),
    }
    results = {}
    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = {executor.submit(fn): name for name, fn in collectors.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = {"success": False, "error": _safe_error(exc)}

    ct = results.get("certificate_transparency") or {}
    tf = results.get("threatfox") or {}
    uh = results.get("urlhaus") or {}
    otx = results.get("otx") or {}
    vt = results.get("virustotal") or {}
    threat_hits = int(tf.get("hit_count") or 0) + int(uh.get("url_count") or 0) + int(otx.get("pulses") or 0)
    # VirusTotal is reported alongside the feed hits rather than folded into
    # them: "N engines flag this" is a different claim from "it appears in a
    # malware feed", and merging the two would make either number unreadable.
    # measured is False when no key is set, so nothing can read a missing
    # lookup as a clean verdict.
    vt_measured = bool(vt.get("success")) and not vt.get("skipped")

    return {
        "success": True,
        "domain": domain,
        "sources": results,
        "summary": {
            "subdomain_count": ct.get("subdomain_count") or len(ct.get("subdomains") or []),
            "wayback_count": (results.get("wayback") or {}).get("count") or 0,
            "threat_hits": threat_hits,
            "ip": (results.get("ip_context") or {}).get("ip"),
            "asn": ((results.get("ip_context") or {}).get("geo") or {}).get("asn"),
            "country": ((results.get("ip_context") or {}).get("geo") or {}).get("country"),
            "listed_in_threat_feeds": threat_hits > 0,
            "virustotal_measured": vt_measured,
            "virustotal_malicious": int(vt.get("malicious") or 0) if vt_measured else None,
            "virustotal_suspicious": int(vt.get("suspicious") or 0) if vt_measured else None,
            "virustotal_reputation": vt.get("reputation") if vt_measured else None,
        },
    }
