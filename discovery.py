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

_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_LIMIT = 200


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
        record = db.get_scan(latest[0]["id"])
        for host in sorted(_hosts_in(record.get("data") or {})):
            if host in watched or not _in_zone(host, zone):
                continue
            found.append({"host": host, "zone": zone, "scan_id": record["id"],
                          "scanned_at": record.get("created_at")})
            if len(found) >= limit:
                return found
    return found
