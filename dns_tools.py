"""A dig-style DNS lookup, for checking a record by hand.

Every DNS check in DomainLens answers a fixed question — is SPF present, does
DKIM parse, is DNSSEC signed. Verifying a record you just changed needed a
terminal, and "did my edit land?" is the most common question during a DNS
change.

Two deliberate limits, both about not handing anyone a weapon:

`dig` is never invoked. Queries go through dnspython, which is already a
dependency. Shelling out to a binary with a user-supplied name is a command
injection waiting to happen, and the parsed result is more useful than the
text output anyway.

The resolver cannot be an arbitrary address. It is chosen from a fixed set of
names, or `authoritative` to ask the zone's own nameservers. Accepting an IP
would turn an app that commonly runs without authentication on a LAN into a
way to probe port 53 on any host the server can reach, and to read internal
zones from an internal resolver.
"""

from __future__ import annotations

import time

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

# Types worth asking for. ANY is absent because resolvers answer it
# inconsistently and it is mostly used for amplification; AXFR and IXFR are
# absent because a zone transfer is not a lookup.
RECORD_TYPES = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA",
    "PTR", "DS", "DNSKEY", "TLSA", "NAPTR", "HTTPS", "SVCB",
]

RESOLVERS = {
    "system": None,
    "cloudflare": ["1.1.1.1", "1.0.0.1"],
    "google": ["8.8.8.8", "8.8.4.4"],
    "quad9": ["9.9.9.9", "149.112.112.112"],
    "authoritative": "auth",
}

_TIMEOUT = 8.0
_MAX_NAME_LENGTH = 253


class LookupError_(ValueError):
    """A request we refuse, as opposed to a lookup that failed."""


def _validate(name, rtype, resolver):
    name = (name or "").strip().rstrip(".")
    if not name or len(name) > _MAX_NAME_LENGTH:
        raise LookupError_("Enter a domain name of at most 253 characters")
    try:
        dns.name.from_text(name)
    except dns.exception.DNSException:
        raise LookupError_(f"{name!r} is not a valid DNS name")

    rtype = (rtype or "A").strip().upper()
    if rtype not in RECORD_TYPES:
        raise LookupError_(
            f"{rtype} is not a supported record type. "
            f"Zone transfers and ANY are deliberately not offered."
        )

    resolver = (resolver or "system").strip().lower()
    if resolver not in RESOLVERS:
        raise LookupError_(
            f"Unknown resolver {resolver!r}. Choose one of: "
            + ", ".join(sorted(RESOLVERS))
        )
    return name, rtype, resolver


def _authoritative_addresses(name):
    """Addresses of the nameservers for the closest zone containing `name`."""
    labels = name.split(".")
    for start in range(len(labels) - 1):
        zone = ".".join(labels[start:])
        try:
            answer = dns.resolver.resolve(zone, "NS", lifetime=_TIMEOUT)
        except dns.exception.DNSException:
            continue
        addresses = []
        for rdata in answer:
            host = str(rdata.target).rstrip(".")
            for family in ("A", "AAAA"):
                try:
                    addresses += [r.address for r in
                                  dns.resolver.resolve(host, family, lifetime=_TIMEOUT)]
                except dns.exception.DNSException:
                    continue
            if addresses:
                return zone, addresses
    raise LookupError_(f"No reachable nameservers found for {name}")


def _format(rdata, rtype):
    if rtype == "TXT":
        # to_text() escapes and re-quotes; the joined strings are what the
        # record actually contains, which is what you are checking.
        return b"".join(rdata.strings).decode("utf-8", "replace")
    return rdata.to_text()


def query(name, rtype="A", resolver="system"):
    """Resolve one name and return the answer with its metadata."""
    name, rtype, resolver_key = _validate(name, rtype, resolver)
    started = time.monotonic()

    result = {
        "name": name,
        "type": rtype,
        "resolver": resolver_key,
        "records": [],
        "ttl": None,
        "rcode": "NOERROR",
        "authenticated": None,
        "authoritative_zone": None,
        "nameservers": None,
        "error": None,
    }

    if resolver_key == "authoritative":
        zone, addresses = _authoritative_addresses(name)
        result["authoritative_zone"] = zone
        result["nameservers"] = addresses[:4]
        request = dns.message.make_query(
            dns.name.from_text(name), dns.rdatatype.from_text(rtype), want_dnssec=True)
        last = None
        for address in addresses[:4]:
            try:
                response = dns.query.udp(request, address, timeout=_TIMEOUT)
                break
            except dns.exception.DNSException as exc:
                last = exc
        else:
            result["error"] = f"No nameserver answered: {last}"
            result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
            return result
        result["rcode"] = dns.rcode.to_text(response.rcode())
        # An authoritative server signs but does not validate, so AD says
        # nothing here and is left unset rather than reported as False.
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                continue
            result["ttl"] = rrset.ttl
            result["records"] += [_format(rd, rtype) for rd in rrset]
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        return result

    request = dns.message.make_query(
        dns.name.from_text(name), dns.rdatatype.from_text(rtype), want_dnssec=True)
    # Ask for the AD bit explicitly: without it most resolvers never set it,
    # and a missing AD would read as "DNSSEC not validated" when it simply
    # was not asked about.
    request.flags |= dns.flags.AD

    addresses = RESOLVERS[resolver_key] or dns.resolver.get_default_resolver().nameservers
    last = None
    for address in list(addresses)[:3]:
        try:
            response = dns.query.udp(request, str(address), timeout=_TIMEOUT)
            break
        except dns.exception.DNSException as exc:
            last = exc
    else:
        result["error"] = f"Query failed: {last}"
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        return result

    result["rcode"] = dns.rcode.to_text(response.rcode())
    result["authenticated"] = bool(response.flags & dns.flags.AD)
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            continue
        result["ttl"] = rrset.ttl
        result["records"] += [_format(rd, rtype) for rd in rrset]
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result
