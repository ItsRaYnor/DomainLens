"""Hostnames the scans have already seen that no monitor is watching.

Every scan of a zone reads Certificate Transparency: the takeover audit and
the OSINT tab both list the names certificates were issued for. That list
was shown once and forgotten. A new host someone stood up last month --
with a certificate, so publicly listed -- stayed unmonitored until a person
happened to compare the two lists by eye.

This compares them. It reads only saved scans; it sends nothing anywhere.
A name in CT is evidence a certificate was issued, not that the host is
still up, and the suggestion says so rather than implying it is live.
"""

from __future__ import annotations

import re
import threading
from collections import OrderedDict

_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_LIMIT = 200

# Hostnames per saved scan. A saved scan never changes and its id is never
# reused (AUTOINCREMENT), so they are read from the stored JSON once, not on
# every Monitoring page load -- which parsed the full latest scan of every
# monitored zone each time.
_HOSTS_CACHE = OrderedDict()
_HOSTS_CACHE_SIZE = 1024
_hosts_lock = threading.Lock()


def _hosts_in(results):
    out = set()
    security = (results.get("security") or {}).get("subdomains") or {}
    ct = (results.get("osint") or {}).get("certificate_transparency") or {}
    for source in (security.get("subdomains") or [], ct.get("subdomains") or []):
        for host in source:
            host = str(host or "").strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if _HOST.match(host):
                out.add(host)
    return out


def _in_zone(host, zone):
    return host == zone or host.endswith("." + zone)


def _hosts_for_scan(db, scan_id):
    key = (getattr(db, "_db_path", lambda: None)(), scan_id)
    with _hosts_lock:
        if key in _HOSTS_CACHE:
            _HOSTS_CACHE.move_to_end(key)
            return _HOSTS_CACHE[key]
    record = db.get_scan(scan_id)
    hosts = sorted(_hosts_in((record or {}).get("data") or {})) if record else []
    with _hosts_lock:
        _HOSTS_CACHE[key] = hosts
        while len(_HOSTS_CACHE) > _HOSTS_CACHE_SIZE:
            _HOSTS_CACHE.popitem(last=False)
    return hosts


def suggestions(db, limit=_LIMIT):
    """[{host, zone, scan_id, scanned_at}] for CT names with no monitor."""
    monitors = db.list_monitors(limit=5000)
    watched = {str(m.get("target") or "").lower() for m in monitors}
    zones = sorted({str(m.get("domain") or "").lower() for m in monitors if m.get("domain")})
    found = []
    for zone in zones:
        latest = db.list_scans(domain=zone, limit=1)
        if not latest:
            continue
        scan = latest[0]
        for host in _hosts_for_scan(db, scan["id"]):
            if host in watched or not _in_zone(host, zone):
                continue
            found.append({"host": host, "zone": zone, "scan_id": scan["id"],
                          "scanned_at": scan.get("created_at")})
            if len(found) >= limit:
                return found
    return found
