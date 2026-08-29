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

import concurrent.futures
import ipaddress
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


def _query_addresses(name, rtype, resolver_key, addresses, want_ad=True):
    """Send one question to the first of `addresses` that answers.

    Shared by the fixed resolvers, the authoritative path and the custom
    list, so all three report the same shape -- including the detail block,
    which is the only way to see *why* two resolvers disagree.
    """
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
        "answered_by": None,
        "detail": None,
        "error": None,
    }

    request = dns.message.make_query(
        dns.name.from_text(name), dns.rdatatype.from_text(rtype), want_dnssec=True)
    if want_ad:
        # Ask for the AD bit explicitly: without it most resolvers never set
        # it, and a missing AD would read as "DNSSEC not validated" when it
        # simply was not asked about.
        request.flags |= dns.flags.AD

    response = None
    last = None
    for address in list(addresses)[:4]:
        try:
            response = dns.query.udp(request, str(address), timeout=_TIMEOUT)
            result["answered_by"] = str(address)
            break
        except dns.exception.DNSException as exc:
            last = exc
    if response is None:
        result["error"] = f"Query failed: {last}"
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        return result

    result["rcode"] = dns.rcode.to_text(response.rcode())
    if want_ad:
        result["authenticated"] = bool(response.flags & dns.flags.AD)
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            continue
        result["ttl"] = rrset.ttl
        result["records"] += [_format(rd, rtype) for rd in rrset]
    result["detail"] = _response_detail(response, rtype)
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def query(name, rtype="A", resolver="system", custom=None):
    """Resolve one name and return the answer with its metadata."""
    custom = custom or {}
    if resolver and resolver.strip().lower() in custom:
        key = resolver.strip().lower()
        name, rtype, _ = _validate(name, rtype, "system")
        return _query_addresses(name, rtype, key, custom[key])

    name, rtype, resolver_key = _validate(name, rtype, resolver)

    if resolver_key == "authoritative":
        zone, addresses = _authoritative_addresses(name)
        # An authoritative server signs but does not validate, so AD says
        # nothing here and is left unset rather than reported as False.
        result = _query_addresses(name, rtype, resolver_key, addresses, want_ad=False)
        result["authoritative_zone"] = zone
        result["nameservers"] = addresses[:4]
        if result.get("error"):
            result["error"] = result["error"].replace("Query failed", "No nameserver answered")
        return result

    addresses = RESOLVERS[resolver_key] or dns.resolver.get_default_resolver().nameservers
    return _query_addresses(name, rtype, resolver_key, addresses)


# --- Custom resolvers ------------------------------------------------------
# Operators need to check their own recursors, but the query API is reachable
# without authentication on a LAN, so an address must never come straight off
# a request. These are configured once by an admin in settings and referred to
# by name afterwards -- the same contract RESOLVERS already has.

def parse_custom_resolvers(lines):
    """Read "label = addr[, addr]" lines from settings into resolver entries.

    A malformed line is skipped rather than raising: this runs on the way in
    to every lookup, and one typo in settings should not take the DNS page
    down with it.
    """
    resolvers = {}
    for raw in (lines or []):
        text = (raw or "").strip()
        if not text or text.startswith("#"):
            continue
        label, _, addresses = text.partition("=")
        if not addresses:
            # "1.1.1.1" alone is a reasonable thing to type; name it after
            # itself rather than rejecting it.
            label, addresses = text, text
        key = label.strip().lower()
        parsed = []
        for candidate in addresses.split(","):
            candidate = candidate.strip()
            if not candidate:
                continue
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            parsed.append(candidate)
        if key and parsed and key not in RESOLVERS:
            resolvers[key] = parsed
    return resolvers


def _response_detail(response, rtype):
    """The parts of the reply worth showing next to the records.

    Without this a lookup answers "what" but never "who said so and how" --
    which is exactly what you need when two resolvers disagree.
    """
    if response is None:
        return None
    detail = {
        "flags": dns.flags.to_text(response.flags).split(),
        "rcode": dns.rcode.to_text(response.rcode()),
        "answer": [], "authority": [], "additional": [],
    }
    for section, key in ((response.answer, "answer"),
                         (response.authority, "authority"),
                         (response.additional, "additional")):
        for rrset in section:
            for rdata in rrset:
                detail[key].append({
                    "name": str(rrset.name),
                    "ttl": rrset.ttl,
                    "type": dns.rdatatype.to_text(rrset.rdtype),
                    "value": rdata.to_text(),
                })
    return detail


def propagation(name, rtype="A", resolvers=None, custom=None):
    """Ask several resolvers the same question and compare their answers.

    The verdict keeps three things apart, because an operator acts on each
    differently:

      propagated    every resolver that answered returned the same records
      inconsistent  they answered, and the records differ -- still rolling out
      unknown       too few answered to compare anything

    A resolver that timed out is never counted as disagreeing. Treating our
    own failure to reach it as "not propagated yet" would send someone
    chasing a rollout that already finished.
    """
    name, rtype, _ = _validate(name, rtype, "system")
    custom = custom or {}
    # None means "use the usual set"; an explicitly empty list is a caller
    # asking to compare nothing, which is a mistake worth naming.
    if resolvers is None:
        keys = ["cloudflare", "google", "quad9", "authoritative"]
    else:
        keys = list(resolvers)

    known = {**{k: v for k, v in RESOLVERS.items()}, **custom}
    unknown_keys = [k for k in keys if k not in known]
    if unknown_keys:
        raise LookupError_("Unknown resolver(s): " + ", ".join(sorted(unknown_keys)))
    if not keys:
        raise LookupError_("Select at least one resolver to compare")

    def ask(key):
        try:
            if key in custom:
                return _query_addresses(name, rtype, key, custom[key])
            return query(name, rtype, key)
        except Exception as exc:
            return {"name": name, "type": rtype, "resolver": key, "records": [],
                    "ttl": None, "rcode": None, "error": f"{type(exc).__name__}: {exc}",
                    "detail": None, "elapsed_ms": None}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(keys))) as pool:
        for outcome in pool.map(ask, keys):
            results.append(outcome)
    # map() preserves input order; keep the caller's order so the report reads
    # the same way the checkboxes were ticked.
    answered = [r for r in results if not r.get("error")]
    unreachable = [r for r in results if r.get("error")]

    # Order within an RRset is not significant and round-robin resolvers
    # deliberately rotate it, so comparing unsorted lists would report a
    # difference on every second lookup.
    signatures = {}
    for r in answered:
        signature = (r.get("rcode"), tuple(sorted(r.get("records") or [])))
        signatures.setdefault(signature, []).append(r["resolver"])

    if len(answered) < 2:
        verdict = "unknown"
    elif len(signatures) == 1:
        verdict = "propagated"
    else:
        verdict = "inconsistent"

    return {
        "name": name,
        "type": rtype,
        "verdict": verdict,
        "results": results,
        "answered": len(answered),
        "unreachable": [r["resolver"] for r in unreachable],
        "groups": [
            {"records": list(sig[1]), "rcode": sig[0], "resolvers": who}
            for sig, who in signatures.items()
        ],
    }
