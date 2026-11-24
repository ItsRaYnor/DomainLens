"""Keep the scanner from being pointed at the network it runs in.

DomainLens fetches what a scanned site tells it to: the page, its redirects,
the scripts and source maps it links. A site that redirects to
http://169.254.169.254/ or links a script on http://10.0.0.1/ would otherwise
have the server fetch the cloud metadata service or an admin panel on the LAN
on the site owner's behalf -- server-side request forgery.

Two layers, because each alone has a hole:

- `is_public` / `safe_host` decide before anything is asked. Four copies of
  this check existed, each missing the same ranges: 0.0.0.0 (which reaches
  localhost on Linux), carrier-grade NAT, multicast, and IPv4 written as IPv6
  (::ffff:127.0.0.1). They also looked at the first A record only.
- `get` / `session()` check the address a connection *actually* reached. A
  name can resolve to a public address when checked and to 127.0.0.1 a moment
  later when the request resolves it again (DNS rebinding); and a redirect or
  a linked script never passed the first check at all. Checking the peer of
  the open socket catches all of those, TLS included, with no change to
  certificate or SNI handling.

Through a configured HTTP(S) proxy the peer is the proxy, so only the first
layer applies there.

An installation that scans its own internal names on purpose sets
DOMAINLENS_ALLOW_PRIVATE_TARGETS=true: both layers then let internal
addresses through. `is_public` itself never changes -- it also tells a report
whether a host is public at all.
"""

from __future__ import annotations

import ipaddress
import os
import socket

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool


class BlockedAddress(requests.exceptions.ConnectionError):
    """A connection reached, or would reach, an address that is not public."""


def _unwrap(addr):
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        if addr.sixtofour is not None:
            return addr.sixtofour
        if addr.teredo is not None:
            return addr.teredo[1]
    return addr


def is_public(ip) -> bool:
    """True only for a globally routable unicast address. Garbage is not."""
    try:
        addr = _unwrap(ipaddress.ip_address(str(ip).split("%", 1)[0]))
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def is_blocked(ip) -> bool:
    return not is_public(ip)


def private_targets_allowed() -> bool:
    """True when the operator chose to let scans reach internal addresses."""
    raw = os.environ.get("DOMAINLENS_ALLOW_PRIVATE_TARGETS", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def addresses(host: str) -> list[str]:
    """Every address the system resolver gives for host, IPv4 and IPv6."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    seen = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


def safe_host(host: str, ips=None) -> bool:
    """True when host has at least one address and every one is public.

    All of them, not the first: a client may connect to any, so one internal
    address among public ones is a way in. `ips` lets a caller pass what its
    own resolver found instead of asking the system resolver.
    """
    if private_targets_allowed():
        if ips is None:
            ips = [host] if _is_literal(host) else addresses(host)
        return bool(list(ips or []))
    if ips is None:
        if is_public(host):
            return True
        ips = addresses(host)
    ips = list(ips or [])
    return bool(ips) and all(is_public(ip) for ip in ips)


def _is_literal(host) -> bool:
    try:
        ipaddress.ip_address(str(host).split("%", 1)[0])
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Connect-time check
# ---------------------------------------------------------------------------

def _check_peer(sock, host):
    try:
        peer = sock.getpeername()[0]
    except OSError:
        peer = None
    if peer is None or (not is_public(peer) and not private_targets_allowed()):
        sock.close()
        raise BlockedAddress(f"{host} connected to {peer or 'an unknown address'}, "
                             "which is not a public address; the request was not sent")


class _GuardedHTTPConnection(HTTPConnection):
    def _new_conn(self):
        sock = super()._new_conn()
        _check_peer(sock, self.host)
        return sock


class _GuardedHTTPSConnection(HTTPSConnection):
    def _new_conn(self):
        sock = super()._new_conn()
        _check_peer(sock, self.host)
        return sock


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class GuardedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _GuardedHTTPPool, "https": _GuardedHTTPSPool}


def session() -> requests.Session:
    s = requests.Session()
    adapter = GuardedAdapter()
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def get(url, **kwargs):
    """requests.get that refuses to talk to a non-public address."""
    with session() as s:
        return s.get(url, **kwargs)
