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
# High enough that a zone with hundreds of CT names is not cut off silently;
# the page groups them per zone, so a long list stays readable.
_LIMIT = 5000

# Hidden names: app bookkeeping, underscore-prefixed like _app_secret.
HIDDEN_SECTION = "_discovery_hidden"

# Label words that mark a test, acceptance or development environment. Whole
# labels or dash-separated parts only ("acc-orm", "test.portal"), so "access"
# or "contest" do not count. A hint for sorting, not a verdict.
_NON_PRODUCTION = {
    "acc", "acceptatie", "acceptance", "accept", "test", "tst", "testing", "dev",
    "develop", "development", "ontw", "ontwikkel", "ontwikkeling", "stage", "staging",
    "stg", "uat", "qa", "demo", "sandbox", "preprod", "pre-prod", "preview", "beta",
}

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


def is_non_production(host, zone):
    """True when a label left of the zone names a test or acceptance setup."""
    left = host[: -len(zone) - 1] if host.endswith("." + zone) else host
    for label in left.split("."):
        parts = set(re.split(r"[-_]", label)) | {label}
        if parts & _NON_PRODUCTION or any(re.fullmatch(r"(acc|test|tst|dev|ont|o|t|a)\d+", p)
                                          for p in parts if len(p) > 1):
            return True
    return False


def hidden(db):
    """{zone: set(hosts)} the operator chose not to be shown again."""
    try:
        raw = db.get_setting_section(HIDDEN_SECTION) or {}
    except Exception:
        return {}
    return {zone: set(hosts or []) for zone, hosts in raw.items() if isinstance(hosts, list)}


def set_hidden(db, zone, hosts, hide=True, user_id=None):
    current = {z: set(h) for z, h in hidden(db).items()}
    names = current.setdefault(zone, set())
    names.update(hosts) if hide else names.difference_update(hosts)
    db.set_setting_section(HIDDEN_SECTION,
                           {z: sorted(h) for z, h in current.items() if h}, user_id=user_id)


def grouped(db, show_hidden=False):
    """Suggestions per zone, split into likely production and test names.

    A zone with hundreds of CT names was one flat list of "Monitor" buttons.
    Per zone, newest scan first: [{zone, scan_id, scanned_at, production,
    non_production, hidden_count}], hosts sorted within each part.
    """
    hidden_by_zone = hidden(db)
    zones = {}
    for s in suggestions(db):
        zone = zones.setdefault(s["zone"], {
            "zone": s["zone"], "scan_id": s["scan_id"], "scanned_at": s["scanned_at"],
            "production": [], "non_production": [], "hidden": [], "hidden_count": 0})
        if s["host"] in hidden_by_zone.get(s["zone"], set()):
            zone["hidden_count"] += 1
            if not show_hidden:
                continue
            zone["hidden"].append(s["host"])
            continue
        key = "non_production" if is_non_production(s["host"], s["zone"]) else "production"
        zone[key].append(s["host"])
    for zone in zones.values():
        zone["total"] = len(zone["production"]) + len(zone["non_production"])
    return sorted(zones.values(), key=lambda z: z["zone"])


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
