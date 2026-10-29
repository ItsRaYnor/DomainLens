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
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

import geoip
import ip_asn
import net_errors
import rate_limits

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


def _safe_error(exc, host=None):
    # Readable words, not the exception: which source was not reached and
    # why, ending in "Not measured".
    return net_errors.describe(exc, host)


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
# timing out on every scan as a result. OTX's passive_dns endpoint is
# routinely slow. The Wayback CDX API was too while it was asked for every
# capture of the whole domain (url=domain/*); asked for the homepage only it
# answers in about a second, so its budget only matters during an outage.
_OTX_TIMEOUT = 25
_WAYBACK_TIMEOUT = 15


def _fetch_json(session, url, *, label, timeout, headers=None, attempts=2, auth_message=None,
                provider=None):
    """GET JSON with one retry on timeout. Returns (data, error).

    Only timeouts are retried — a rejected key or a bad request will not fix
    itself, and retrying just makes a failing scan slower.
    """
    last_error = None
    for _ in range(attempts):
        if provider:
            # Within the provider's free-tier budget, or not asked at all.
            allowed, reason = rate_limits.acquire(provider)
            if not allowed:
                return None, reason
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
            if auth_message and resp.status_code in (401, 403):
                return None, auth_message
            if provider and rate_limits.note_response(provider, resp):
                return None, net_errors.http_status(429, label)[1]
            resp.raise_for_status()
            return resp.json(), None
        except requests.Timeout:
            last_error = f"{label} did not respond within {timeout}s. {net_errors.AGAIN}"
        except Exception as exc:
            # A resolver that did not answer once often answers a second
            # later; a refused key or a missing name will not.
            if net_errors.is_temporary_dns(exc) and _ < attempts - 1:
                time.sleep(1)
                continue
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
        # crt.sh's own timeout, not the shorter one for the other feeds: the
        # security audit asks for the same list during the same scan, and a
        # lookup only stands in for a caller that would have waited as long.
        rows, fetch_error = crtsh.fetch(domain, session=_session())
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


def _wayback_url(domain, extra):
    # url=<domain> is the homepage, over http and https and with or without
    # www (CDX folds those together). The url=<domain>/* wildcard made the
    # archive walk every capture of every page, which took 5 to 60 seconds or
    # ended in a 503, and returned the same homepage rows first anyway: CDX
    # sorts by URL.
    return (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={quote(domain)}&output=json&fl=timestamp,original,statuscode"
        f"&filter=statuscode:200{extra}"
    )


def _wayback_rows(rows):
    snapshots = []
    for row in (rows or [])[1:]:
        if not isinstance(row, (list, tuple)) or len(row) < 3:
            continue
        ts, original, status = row[0], row[1], row[2]
        snapshots.append({
            "timestamp": ts,
            "url": original,
            "status": status,
            "archive_url": f"https://web.archive.org/web/{ts}/{original}",
        })
    return snapshots


def _wayback_fetch(url):
    # One try. A CDX query that did not answer within the budget is the
    # archive being overloaded, and asking again doubled the wait for the
    # whole scan without making an answer more likely.
    return _fetch_json(_session(), url, label="Wayback Machine", timeout=_WAYBACK_TIMEOUT,
                       attempts=1, provider="wayback")


def wayback_snapshots(domain, limit=15):
    """The most recent Wayback Machine snapshots of the homepage, one per day,
    and the date of the first one."""
    result = {
        "success": False,
        "source": "web.archive.org",
        "snapshots": [],
        "first_seen": None,
        "last_seen": None,
    }
    try:
        # A negative limit is "the last N": without it CDX returned the
        # oldest days, so "last seen" was the 15th capture ever made.
        rows, error = _wayback_fetch(_wayback_url(
            domain, f"&collapse=timestamp:8&limit=-{int(limit)}&fastLatest=true"))
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

        snapshots = _wayback_rows(rows)
        timestamps = [s["timestamp"] for s in snapshots if s.get("timestamp")]
        result.update({
            "success": True,
            "snapshots": snapshots,
            "last_seen": max(timestamps) if timestamps else None,
            "count": len(snapshots),
        })

        # The first capture needs its own question now that the snapshots
        # are the recent ones. If it goes unanswered, first_seen stays empty
        # and says why; the oldest recent snapshot is not the first one.
        first_rows, first_error = _wayback_fetch(_wayback_url(domain, "&limit=1"))
        first = _wayback_rows(first_rows) if isinstance(first_rows, list) else []
        if first:
            result["first_seen"] = first[0]["timestamp"]
        elif first_error:
            result["first_seen_error"] = first_error
    except Exception as exc:
        result["error"] = _safe_error(exc)
    return result


def _ip_api_enabled():
    try:
        import config as domainlens_config
        return bool((domainlens_config.load_settings().raw.get("ip_context") or {}).get("ip_api"))
    except Exception:
        return False


def _ip_api(ip):
    """Hosting and proxy flags from ip-api.com, only when switched on: plain
    HTTP, non-commercial use only, and the address goes to a third party."""
    allowed, reason = rate_limits.acquire("ip-api")
    if not allowed:
        return {"error": reason}
    try:
        resp = _session().get(f"http://ip-api.com/json/{ip}",
                              params={"fields": "status,message,isp,org,proxy,hosting"}, timeout=_TIMEOUT)
        if rate_limits.note_response("ip-api", resp):
            return {"error": net_errors.http_status(429, "ip-api.com")[1]}
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return {"error": data.get("message") or "ip-api.com did not answer for this address"}
        return {"proxy": bool(data.get("proxy")), "hosting": bool(data.get("hosting")),
                "isp": data.get("isp"), "error": None}
    except Exception as exc:
        return {"error": _safe_error(exc, "ip-api.com")}


def ip_context(domain):
    """The network an address is in, from the registry, and where it is, from
    GeoLite2 on this server.

    ASN, prefix and holder come from RIPEstat (falling back to Team Cymru);
    location from MaxMind GeoLite2 when an account is set; hosting and proxy
    flags only from ip-api.com, and only when an admin switches that on.
    Each part keeps its own state, so a missing location never hides the ASN.
    """
    result = {"success": False, "source": "RIPEstat / Team Cymru", "ip": None, "geo": None,
              "network": None, "location": None, "flags": None}
    try:
        ip = socket.gethostbyname(domain)
    except Exception as exc:
        result["error"] = _safe_error(exc, domain)
        return result
    result["ip"] = ip
    network = ip_asn.lookup(ip)
    location = geoip.lookup(ip)
    flags = _ip_api(ip) if _ip_api_enabled() else None
    result.update(network=network, location=location, flags=flags)
    if network.get("state") != "measured" and location.get("state") != "measured":
        result["error"] = network.get("error") or location.get("error") or "Network and location were not measured"
        return result
    measured_place = location.get("state") == "measured"
    good_flags = flags if flags and not flags.get("error") else {}
    result.update({
        "success": True,
        "source": network.get("source") or "GeoLite2",
        "geo": {
            "country": location.get("country") if measured_place else None,
            "region": location.get("region") if measured_place else None,
            "city": location.get("city") if measured_place else None,
            "registered_country": network.get("country"),
            "prefix": network.get("prefix"),
            "isp": good_flags.get("isp") or network.get("holder"),
            "org": network.get("holder"),
            "asn": ip_asn.label(network),
            "asname": network.get("holder"),
            "reverse": None,
            # None: not measured, which is what it is without ip-api.com.
            "proxy": good_flags.get("proxy"),
            "hosting": good_flags.get("hosting"),
        },
    })
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
        allowed, reason = rate_limits.acquire("abuse.ch")
        if not allowed:
            result["error"] = reason
            return result
        resp = _session().post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": key},
            json={"query": "search_ioc", "search_term": domain},
            timeout=_TIMEOUT,
        )
        rate_limits.note_response("abuse.ch", resp)
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
        allowed, reason = rate_limits.acquire("abuse.ch")
        if not allowed:
            result["error"] = reason
            return result
        resp = _session().post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers={"Auth-Key": key},
            data={"host": domain},
            timeout=_TIMEOUT,
        )
        rate_limits.note_response("abuse.ch", resp)
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
        headers=headers, auth_message="OTX rejected the API key", provider="otx")
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
        headers=headers, auth_message="OTX rejected the API key", provider="otx")
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
        label="VirusTotal", timeout=_TIMEOUT, provider="virustotal",
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


def cacheable(result):
    """Keep an OSINT result for a day only when no source failed for a
    reason that may pass: a DNS hiccup, a timeout or a rate limit replayed
    for 24 hours is the failure, not the answer."""
    if not isinstance(result, dict) or result.get("success") is False:
        return False
    for name, source in (result.get("sources") or {}).items():
        source = source or {}
        if net_errors.is_transient(source.get("error")) or net_errors.is_transient(source.get("passive_dns_error")):
            return False
        # A crt.sh failure is an outage at crt.sh, whatever its wording, and
        # crt.sh is often back within minutes. Kept for a day, the subdomain
        # list stayed "unavailable" on every scan until tomorrow.
        if name == "certificate_transparency" and source.get("success") is False:
            return False
    return True


def _source_cacheable(result):
    """One feed's answer is kept for a day only when it is an answer: not a
    failure, and not "no key configured" (which ends the day a key is set)."""
    return (isinstance(result, dict) and result.get("success") is True
            and not result.get("skipped") and not result.get("error")
            and not net_errors.is_transient(result.get("passive_dns_error")))


def _cached_source(name, producer, domain, force):
    import scan_cache
    kind = scan_cache.OSINT_SOURCE_KINDS.get(name)
    if kind is None:
        return producer()
    return scan_cache.cached_call(kind, domain, producer, force=force,
                                  should_store=_source_cacheable)


def collect_osint(domain, force=False):
    """Run all OSINT collectors and return a combined payload.

    Each feed's answer is reused for a day on its own. Before, the whole set
    was kept only when every feed had answered, so one feed that was down
    sent all of them out again on the next scan, the Wayback Machine's
    20 to 60 seconds included. `force` asks every feed again.
    """
    feeds = {
        "certificate_transparency": lambda: certificate_transparency(domain),
        "wayback": lambda: wayback_snapshots(domain),
        "ip_context": lambda: ip_context(domain),
        "threatfox": lambda: threatfox_lookup(domain),
        "urlhaus": lambda: urlhaus_lookup(domain),
        "otx": lambda: otx_lookup(domain),
        "virustotal": lambda: virustotal_lookup(domain),
    }
    collectors = {
        name: (lambda name=name, fn=fn: _cached_source(name, fn, domain, force))
        for name, fn in feeds.items()
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
    # A source that was not reached contributes no count: "0 hits" from three
    # feeds that all failed read as a clean bill of health.
    feeds_measured = [src for src in (tf, uh, otx) if src.get("success") and not src.get("skipped")]
    wayback = results.get("wayback") or {}
    # Several sources failing on DNS at once is this server's DNS, not theirs.
    dns_failures = sorted(name for name, src in results.items()
                          if str((src or {}).get("error") or "").startswith("This server could not"))

    return {
        "success": True,
        "domain": domain,
        "sources": results,
        "summary": {
            "subdomain_count": (ct.get("subdomain_count") or len(ct.get("subdomains") or [])
                                if ct.get("success") else None),
            "wayback_count": (wayback.get("count") or 0) if wayback.get("success") else None,
            "threat_hits": threat_hits if feeds_measured else None,
            "threat_feeds_measured": len(feeds_measured),
            "dns_failures": dns_failures,
            "ip": (results.get("ip_context") or {}).get("ip"),
            "asn": ((results.get("ip_context") or {}).get("geo") or {}).get("asn"),
            "country": ((results.get("ip_context") or {}).get("geo") or {}).get("country"),
            "listed_in_threat_feeds": threat_hits > 0 if feeds_measured else None,
            "virustotal_measured": vt_measured,
            "virustotal_malicious": int(vt.get("malicious") or 0) if vt_measured else None,
            "virustotal_suspicious": int(vt.get("suspicious") or 0) if vt_measured else None,
            "virustotal_reputation": vt.get("reputation") if vt_measured else None,
        },
    }
