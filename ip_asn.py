"""Which network an address belongs to: ASN, prefix, holder, registry country.

The ASN came from ip-api.com's free endpoint: plain HTTP, non-commercial use
only, and a single commercial geolocation source for what is a routing fact.
Routing is public record. RIPEstat (RIPE NCC, a regional internet registry)
answers it from its own BGP collectors over HTTPS; Team Cymru's IP-to-ASN
service, asked over DNS, is the fallback when RIPEstat cannot be reached.

The country here is where the address block is registered, from the
registry's own statistics -- not where the machine stands. Location is a
different claim and comes from geoip.py, or not at all.
"""

from __future__ import annotations

import ipaddress

import dns.resolver
import requests

import net_errors

_RIPESTAT = "https://stat.ripe.net/data/{call}/data.json"
_TIMEOUT = 10
_UA = "DomainLens (https://github.com/ItsRaYnor/DomainLens)"


def _ripestat(call, ip):
    resp = requests.get(_RIPESTAT.format(call=call),
                        params={"resource": ip, "sourceapp": "domainlens"},
                        headers={"User-Agent": _UA}, timeout=_TIMEOUT)
    resp.raise_for_status()
    body = resp.json()
    if body.get("status") not in (None, "ok"):
        raise ValueError(f"RIPEstat answered {body.get('status')}")
    return body.get("data") or {}


def _from_ripestat(ip):
    overview = _ripestat("prefix-overview", ip)
    asns = overview.get("asns") or []
    result = {"source": "RIPEstat", "prefix": overview.get("resource"),
              "announced": bool(overview.get("announced")), "asn": None, "holder": None,
              "country": None, "registry": None}
    if asns:
        result["asn"] = asns[0].get("asn")
        result["holder"] = asns[0].get("holder")
    try:
        located = _ripestat("rir-stats-country", ip).get("located_resources") or []
        result["country"] = (located[0] or {}).get("location") if located else None
    except Exception:
        pass  # the ASN stands without it
    desc = ((overview.get("block") or {}).get("desc") or "")
    result["registry"] = desc.split(" (")[0] or None
    return result


def _cymru_name(ip):
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = address.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _txt(name):
    answers = dns.resolver.resolve(name, "TXT", lifetime=_TIMEOUT)
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]


def _from_cymru(ip):
    result = {"source": "Team Cymru", "prefix": None, "announced": False, "asn": None,
              "holder": None, "country": None, "registry": None}
    try:
        rows = _txt(_cymru_name(ip))
    except dns.resolver.NXDOMAIN:
        return result  # not routed: measured, and nothing announces it
    fields = [f.strip() for f in rows[0].split("|")]
    if fields and fields[0]:
        result["asn"] = int(fields[0].split()[0])
        result["announced"] = True
    if len(fields) > 1:
        result["prefix"] = fields[1] or None
    if len(fields) > 2:
        result["country"] = fields[2] or None
    if len(fields) > 3:
        result["registry"] = fields[3] or None
    if result["asn"]:
        try:
            name = [f.strip() for f in _txt(f"AS{result['asn']}.asn.cymru.com")[0].split("|")]
            result["holder"] = name[-1] if name else None
        except Exception:
            pass
    return result


def lookup(ip):
    """{"state", "asn", "holder", "prefix", "country", "registry", "source", "error"}.

    state: "measured" (asn may still be None: an address no one announces)
    or "unmeasured" when neither source could be asked.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"state": "unmeasured", "error": "Not an IP address"}
    errors = []
    for source in (_from_ripestat, _from_cymru):
        try:
            return {"state": "measured", "error": None, **source(ip)}
        except Exception as exc:
            errors.append(net_errors.describe(exc))
    return {"state": "unmeasured", "asn": None, "holder": None, "prefix": None, "country": None,
            "registry": None, "source": None, "error": errors[0] if errors else None}


def label(result):
    """"AS3333 RIPE-NCC-AS ..." -- the form the rest of the app reads."""
    if not result or not result.get("asn"):
        return None
    return f"AS{result['asn']} {result.get('holder') or ''}".strip()
