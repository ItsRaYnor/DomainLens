"""The public address the reader is using, for Tools -> IP address.

The address a request arrives from is the reader's public address only when
it is a public one. A private or loopback address means one of two things:
the browser is on the same network as this server, so they share one public
address, or a reverse proxy in front does not pass the reader's address on
(or passes it but is not trusted, DOMAINLENS_TRUSTED_PROXY_HOPS). Either way
the request's own address says nothing about the reader's public address, so
this server's public address is asked for instead -- and labelled as the
server's, never presented as the reader's own.

The server's address comes from RIPEstat's whats-my-ip call: the RIPE NCC, a
regional internet registry in the EU, already the source of the network data
(ip_asn.py). Asked by host name over HTTPS, so no resolver address is built
in here, and without a key. When it cannot be reached, the address is not
measured; no other service is tried in its place.
"""

from __future__ import annotations

import ipaddress
import threading
import time

import requests

import net_errors

_URL = "https://stat.ripe.net/data/whats-my-ip/data.json"
_TIMEOUT = 10
_UA = "DomainLens (https://github.com/ItsRaYnor/DomainLens)"
_CACHE_SECONDS = 300
_cache = {"at": 0.0, "ip": None}
_lock = threading.Lock()


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _from_ripestat():
    resp = requests.get(_URL, params={"sourceapp": "domainlens"}, headers={"User-Agent": _UA}, timeout=_TIMEOUT)
    resp.raise_for_status()
    body = resp.json()
    if body.get("status") not in (None, "ok"):
        raise ValueError(f"RIPEstat answered {body.get('status')}")
    return ((body.get("data") or {}).get("ip") or "").strip()


def server_public_ip():
    """(ip, error): this server's public address, as RIPEstat sees it."""
    with _lock:
        if _cache["ip"] and time.monotonic() - _cache["at"] < _CACHE_SECONDS:
            return _cache["ip"], None
    try:
        ip = _from_ripestat()
    except Exception as exc:
        return None, net_errors.describe(exc, "stat.ripe.net")
    if not is_public(ip):
        return None, f"RIPEstat gave an address that is not public ({ip or 'none'})"
    with _lock:
        _cache.update(at=time.monotonic(), ip=ip)
    return ip, None


def mine(client_ip, forwarded=False, proxy_trusted=False):
    """{"state", "ip", "seen_as", "client", "reason", "error"}.

    seen_as: "connection" -- the address the request came from, the reader's
    own; "server" -- the request came from a private address, so this is the
    server's public address, which is the reader's only when they share its
    connection. state "unmeasured" when that could not be asked either.
    """
    if is_public(client_ip):
        return {"state": "measured", "ip": client_ip, "seen_as": "connection",
                "client": client_ip, "reason": None, "error": None}
    # A forwarded address that is not trusted is not used: anyone can send
    # the header. Saying so tells the operator what to set.
    reason = "proxy_untrusted" if forwarded and not proxy_trusted else "private"
    ip, error = server_public_ip()
    if ip is None:
        return {"state": "unmeasured", "ip": None, "seen_as": None, "client": client_ip,
                "reason": reason, "error": error}
    return {"state": "measured", "ip": ip, "seen_as": "server", "client": client_ip,
            "reason": reason, "error": None}
