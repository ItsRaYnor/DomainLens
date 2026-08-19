"""Everything DomainLens can establish about a single IP address.

Scanning was domain-shaped throughout: you typed a name, and an address only
ever appeared as a detail of that name. But the questions that start from an
address are real ones — who is responsible for this range, is it listed
anywhere, and who do I write to — and none of them could be asked here.

The field that does the most work is the abuse contact. A takedown or notice
goes to the party that can actually act, and for an address that is the
network's registered abuse mailbox, not the hosting company's sales form.

RDAP rather than port-43 WHOIS: the answer is structured, so the abuse
contact can be pulled out reliably instead of scraped from free text that
every registry formats differently.
"""

from __future__ import annotations

import ipaddress
import logging
import re

import requests

log = logging.getLogger("domainlens.ip_intel")

_UA = "DomainLens/1.0 (+https://github.com/ItsRaYnor/DomainLens)"
_TIMEOUT = 12

# rdap.org redirects to whichever RIR is authoritative for the address, so one
# URL covers RIPE, ARIN, APNIC, LACNIC and AFRINIC without hardcoding ranges.
_RDAP_IP_URL = "https://rdap.org/ip/{ip}"
_RDAP_AS_URL = "https://rdap.org/autnum/{asn}"


def is_ip(value):
    """True when the input is an IP address rather than a hostname."""
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def classify(value):
    """Describe an address, or explain why it is not one worth looking up.

    Private, loopback and link-local addresses are refused rather than sent
    to a registry: they are not globally routed, so no registry has an
    answer, and asking would leak a detail of the operator's internal network
    to a third party.
    """
    try:
        address = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None, "Not a valid IP address"
    if address.is_loopback:
        return address, "Loopback address — nothing to look up"
    if address.is_private:
        return address, "Private address (RFC 1918 / ULA) — not registered anywhere"
    if address.is_link_local:
        return address, "Link-local address — not registered anywhere"
    if address.is_multicast:
        return address, "Multicast address — not assigned to a network operator"
    if address.is_reserved or address.is_unspecified:
        return address, "Reserved address — not assigned to a network operator"
    return address, None


def _session():
    session = requests.Session()
    session.headers.update({"User-Agent": _UA, "Accept": "application/rdap+json"})
    return session


def _entity_contacts(entities, wanted_role):
    """Pull contacts with a given RDAP role out of a nested entity tree."""
    found = []
    for entity in entities or []:
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        if wanted_role in roles:
            found.append(_vcard(entity))
        # Registries nest the abuse contact inside the network's org entity,
        # so a flat scan of the top level misses it.
        found += _entity_contacts(entity.get("entities"), wanted_role)
    return [item for item in found if item]


def _vcard(entity):
    """Flatten an RDAP jCard into name/email/phone."""
    contact = {"handle": entity.get("handle"), "name": None, "email": None, "phone": None}
    vcard = (entity.get("vcardArray") or [None, []])[1]
    for field in vcard or []:
        if not isinstance(field, list) or len(field) < 4:
            continue
        key, value = str(field[0]).lower(), field[3]
        if key == "fn" and not contact["name"]:
            contact["name"] = value
        elif key == "email" and not contact["email"]:
            contact["email"] = value
        elif key == "tel" and not contact["phone"]:
            contact["phone"] = value
    return contact if any((contact["name"], contact["email"], contact["phone"])) else None


def _events(data):
    out = {}
    for event in data.get("events") or []:
        action = str(event.get("eventAction") or "").lower()
        if action:
            out[action] = event.get("eventDate")
    return out


def rdap(ip, session=None):
    """Registry data for an address: range, holder, country, abuse contact."""
    result = {
        "success": False, "source": "rdap.org", "ip": ip,
        "range": None, "name": None, "type": None, "country": None,
        "handle": None, "parent_handle": None,
        "abuse": None, "registrant": None, "events": {}, "remarks": [],
        "error": None,
    }
    http = session or _session()
    try:
        resp = http.get(_RDAP_IP_URL.format(ip=ip), timeout=_TIMEOUT)
        if resp.status_code == 404:
            result["error"] = "No registry record for this address"
            return result
        resp.raise_for_status()
        data = resp.json()
    except requests.Timeout:
        result["error"] = f"Registry did not respond within {_TIMEOUT}s"
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result

    start, end = data.get("startAddress"), data.get("endAddress")
    handle = data.get("handle")
    result.update({
        "success": True,
        "range": f"{start} – {end}" if start and end else handle,
        "name": data.get("name"),
        "type": data.get("type"),
        "country": data.get("country"),
        "handle": handle,
        "parent_handle": data.get("parentHandle"),
        "events": _events(data),
    })

    abuse = _entity_contacts(data.get("entities"), "abuse")
    result["abuse"] = abuse[0] if abuse else None
    holder = (_entity_contacts(data.get("entities"), "registrant")
              or _entity_contacts(data.get("entities"), "administrative"))
    result["registrant"] = holder[0] if holder else None
    for remark in data.get("remarks") or []:
        for line in remark.get("description") or []:
            if line:
                result["remarks"].append(str(line)[:300])
    return result


def reverse_dns(ip):
    """PTR record, which often names the hosting product in plain sight."""
    import dns.resolver
    import dns.reversename
    try:
        name = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(name, "PTR", lifetime=6)
        return {"success": True, "names": [str(r.target).rstrip(".") for r in answer]}
    except Exception as exc:
        return {"success": False, "names": [], "error": type(exc).__name__}


_ASN_RE = re.compile(r"AS(\d+)", re.I)


def asn_from_geo(geo):
    """Extract a bare AS number from ip-api's 'AS15169 Google LLC' string."""
    match = _ASN_RE.search(str((geo or {}).get("asn") or ""))
    return match.group(1) if match else None
