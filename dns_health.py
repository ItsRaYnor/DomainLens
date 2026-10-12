"""Whether DNS answers, asked before a scan is allowed to judge a domain.

A scan that cannot reach DNS still runs every check. Each check finds
nothing, each "nothing" becomes a finding -- no SPF, no DMARC, no HTTPS --
and the domain is rated F for an outage it may not even have. Two different
things can be down, and they are told apart:

- the scanner's own resolver (the container's network, or the resolver it
  points at): nothing can be measured for any domain, so every scan waits;
- the domain's own name servers: the resolver works, but this name gets no
  answer (SERVFAIL, timeout). That is an outage, or a path the scanner
  cannot reach -- not a set of missing controls.

Either way the scan is not run: "could not be measured" is not "measured
and bad".
"""

from __future__ import annotations

import threading
import time

import dns.exception
import dns.resolver

OK = "ok"
RESOLVER_DOWN = "resolver_down"
DOMAIN_DOWN = "domain_down"

# Names every working recursive resolver can answer. NXDOMAIN or an empty
# answer counts too: it is still an answer.
_PROBES = ((".", "NS"), ("example.com", "A"))
_LIFETIME = 6
_CACHE_SECONDS = 30

_lock = threading.Lock()
_cached = {"at": 0.0, "ok": None, "error": None}


class DnsUnavailable(Exception):
    """A scan was not run because DNS gave no answer."""

    def __init__(self, state, domain, error=None):
        self.state = state
        self.domain = domain
        self.error = error
        super().__init__(message(state, domain))


def message(state, domain):
    if state == RESOLVER_DOWN:
        return ("DNS does not answer on this server, so nothing can be measured; "
                f"the scan of {domain} was not run")
    return (f"The name servers of {domain} do not answer, so nothing can be measured; "
            "the scan was not run")


def _query(name, rdtype):
    """True when the resolver answered (NXDOMAIN and an empty answer count)."""
    try:
        dns.resolver.resolve(name, rdtype, lifetime=_LIFETIME)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return True


def resolver_ok(force=False):
    """(ok, error) for the scanner's own resolver, cached for half a minute
    so a batch of monitors asks once rather than once each."""
    now = time.monotonic()
    with _lock:
        if not force and _cached["ok"] is not None and now - _cached["at"] < _CACHE_SECONDS:
            return _cached["ok"], _cached["error"]
    ok, error = False, None
    for name, rdtype in _PROBES:
        try:
            ok = _query(name, rdtype)
            break
        except (dns.exception.DNSException, OSError) as exc:
            error = str(exc)[:200]
    with _lock:
        _cached.update(at=time.monotonic(), ok=ok, error=None if ok else error)
    return ok, None if ok else error


def check(domain):
    """{"state", "error"}: OK, RESOLVER_DOWN or DOMAIN_DOWN for one name.

    The name is asked once more first: the lookup that sent us here may have
    been a single lost packet."""
    domain_error = None
    for rdtype in ("SOA", "NS"):
        try:
            if _query(domain, rdtype):
                return {"state": OK, "error": None}
        except (dns.exception.DNSException, OSError) as exc:
            domain_error = str(exc)[:200]
    ok, error = resolver_ok(force=True)
    if not ok:
        return {"state": RESOLVER_DOWN, "error": error}
    return {"state": DOMAIN_DOWN, "error": domain_error}


def reset():
    """Forget the cached resolver answer. For tests."""
    with _lock:
        _cached.update(at=0.0, ok=None, error=None)
