"""New known CVEs for the versions monitored domains showed, without a new scan.

A scan compares the version a site shows with the CVE data as it is that
day. A CVE published the day after, or one CISA adds to its list of
exploited flaws (KEV), was only seen at the next scan of that site, and
only by someone who opened the report and counted.

After every sync of the CVE data this compares again, for each active
monitor, the versions its last scan measured with the data as it now is,
and reports what was not there before as a monitor event -- which the
notification channels (webhook, Slack, Teams, e-mail, ServiceNow) pick up
like any other:

  * a CVE that now applies to the version and did not before (new, or one
    the NVD has since given versions);
  * a CVE that applied already and is now listed as exploited (KEV).

What a scan reported is the starting point: the scan of a monitor notes
the CVEs it found (note_scan), so the next comparison reports only what
came after. A monitor whose scan was not noted -- one from before this
existed, or one taken while the data had never been synced -- is taken
stock of silently at the first comparison.

Only measured versions count: a version that is not shown, a distribution
build, or one whose product data is not current is not compared, and
gives no event rather than a guess.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import db

log = logging.getLogger("domainlens.cve_alerts")

EVENT_TYPE = "known_cve_new"
_LISTED = 5
# What app.py hands its monitor events to (ServiceNow and the notification
# channels): notifier(event_id, event, monitor, scan_id=...). None in a
# process that has no app, such as a test: the event is still stored.
notifier = None


def init_schema(conn):
    # The CVEs already reported per monitor, product and version.
    conn.execute("CREATE TABLE IF NOT EXISTS cve_alert_known (monitor_id INTEGER NOT NULL, product TEXT NOT NULL, "
                 "version TEXT NOT NULL, cve_id TEXT NOT NULL, kev INTEGER NOT NULL DEFAULT 0, "
                 "PRIMARY KEY (monitor_id, product, version, cve_id))")
    # Which scan of each monitor the known CVEs belong to.
    conn.execute("CREATE TABLE IF NOT EXISTS cve_alert_scans (monitor_id INTEGER PRIMARY KEY, scan_id INTEGER, "
                 "noted_at TEXT)")


def _now():
    return datetime.now(timezone.utc)


def _measured(results):
    """[(product, shown)] for the versions a scan measured on the domain's
    own server: shown, upstream, comparable. A redirect's target is another
    site's server and is not this monitor's to hear about."""
    import cve_feed
    import software_advisories as engine
    info = ((results or {}).get("security") or {}).get("info_disclosure") or {}
    products = {p["key"]: p for p in cve_feed.PRODUCTS}
    out = []
    for assessment in info.get("cves") or []:
        product = products.get(assessment.get("key"))
        if not product or not assessment.get("version") or assessment.get("distribution"):
            continue
        reader = {**product, **engine.reader(product["token"], product["sources"])}
        shown = engine.parse_version(reader, [assessment["version"]])
        if shown and shown["patch_known"] and not shown["vendor"]:
            out.append((product, shown))
    return out


def _applicable(product, shown):
    import cve_feed
    applicable, _uncertain, _ = cve_feed._split(product["key"], shown)
    return {c["cve"]: c for c in applicable}


def _known(monitor_id, product_key, version):
    with db._connect() as conn:
        rows = conn.execute("SELECT cve_id, kev FROM cve_alert_known WHERE monitor_id = ? AND product = ? "
                            "AND version = ?", (monitor_id, product_key, version)).fetchall()
    return {r["cve_id"]: bool(r["kev"]) for r in rows}


def _remember(conn, monitor_id, product_key, version, cves):
    conn.executemany("INSERT OR REPLACE INTO cve_alert_known (monitor_id, product, version, cve_id, kev) "
                     "VALUES (?, ?, ?, ?, ?)",
                     [(monitor_id, product_key, version, c["cve"], 1 if c["kev"] else 0) for c in cves])


def _take_stock(monitor_id, scan_id, results):
    """What the data says now about the scan's versions, as already known."""
    found = [(product, shown, _applicable(product, shown)) for product, shown in _measured(results)]
    with db._lock, db._connect() as conn:
        conn.execute("DELETE FROM cve_alert_known WHERE monitor_id = ?", (monitor_id,))
        for product, shown, applicable in found:
            _remember(conn, monitor_id, product["key"], shown["raw"], applicable.values())
        conn.execute("INSERT OR REPLACE INTO cve_alert_scans (monitor_id, scan_id, noted_at) VALUES (?, ?, ?)",
                     (monitor_id, scan_id, _now().isoformat()))


def note_scan(monitor_id, scan_id, results):
    """Called when a monitor's scan is saved: what it found is known."""
    try:
        import cve_feed
        if not cve_feed.enabled() or cve_feed.freshness()["state"] == "never":
            # Nothing was compared; the first comparison takes stock.
            return
        _take_stock(monitor_id, scan_id, results)
    except Exception:
        log.warning("Known CVEs of monitor %s could not be noted", monitor_id, exc_info=True)


def _noted_scan(monitor_id):
    with db._connect() as conn:
        row = conn.execute("SELECT scan_id FROM cve_alert_scans WHERE monitor_id = ?", (monitor_id,)).fetchone()
    return row["scan_id"] if row else None


def _ids(cves):
    ids = [c["cve"] for c in cves[:_LISTED]]
    more = len(cves) - len(ids)
    return ", ".join(ids) + (f" and {more} more" if more > 0 else "")


def _severity(cves):
    import cve_feed
    scores = [c["score"] for c in cves if c.get("score") is not None]
    severity = cve_feed._severity_of(max(scores)) if scores else "medium"
    if any(c["kev"] for c in cves) and severity in ("medium", "low"):
        # Exploited in the wild outranks a modest score.
        severity = "high"
    return severity


def event_for(monitor, product, shown, new, exploited):
    """The monitor event for one product version, or None."""
    if not new and not exploited:
        return None
    import cve_feed
    target, raw = monitor["target"], shown["raw"]
    parts = []
    if new:
        parts.append(f"{len(new)} new known CVE(s) for {raw} on {target}: {_ids(new)}")
    if exploited:
        parts.append(f"Now exploited (CISA KEV) for {raw} on {target}: {_ids(exploited)}")
    row = lambda c: {k: c.get(k) for k in ("cve", "score", "severity", "kev", "kev_added", "published")}  # noqa: E731
    return {"event_type": EVENT_TYPE, "severity": _severity(new + exploited), "summary": " · ".join(parts),
            "details": {"target": target, "product": product["product"], "version": raw,
                        "new": [row(c) for c in new], "now_exploited": [row(c) for c in exploited],
                        "attribution": cve_feed.ATTRIBUTION}}


def recheck(now=None):
    """After a sync: compare each active monitor's measured versions with the
    data as it now is. {"monitors", "events"}, or None when switched off."""
    import cve_feed
    if not cve_feed.enabled():
        return None
    now = now or _now()
    with db._lock, db._connect() as conn:
        # Monitors deleted since: nothing left to tell about them.
        conn.execute("DELETE FROM cve_alert_known WHERE monitor_id NOT IN (SELECT id FROM monitors)")
        conn.execute("DELETE FROM cve_alert_scans WHERE monitor_id NOT IN (SELECT id FROM monitors)")
    current = {p["key"]: cve_feed.freshness(now, keys=[p["key"]])["state"] == "current" for p in cve_feed.PRODUCTS}
    compared = events = 0
    for monitor in db.list_monitors(enabled=True, limit=100000):
        scan_id = monitor.get("last_scan_id")
        record = db.get_scan(scan_id) if scan_id else None
        if not record:
            continue
        try:
            if _noted_scan(monitor["id"]) != scan_id:
                _take_stock(monitor["id"], scan_id, record["data"])
                continue
            compared += 1
            for product, shown in _measured(record["data"]):
                if not current.get(product["key"]):
                    continue
                applicable = _applicable(product, shown)
                known = _known(monitor["id"], product["key"], shown["raw"])
                new = [c for cve_id, c in applicable.items() if cve_id not in known]
                exploited = [c for cve_id, c in applicable.items() if c["kev"] and known.get(cve_id) is False]
                event = event_for(monitor, product, shown, sorted(new, key=cve_feed._rank),
                                  sorted(exploited, key=cve_feed._rank))
                if event:
                    _report(monitor, scan_id, event)
                    events += 1
                with db._lock, db._connect() as conn:
                    _remember(conn, monitor["id"], product["key"], shown["raw"], applicable.values())
        except Exception:
            log.warning("Known CVEs of monitor %s could not be compared", monitor["id"], exc_info=True)
    cve_feed._save_state("alerts", synced_at=now.isoformat(), items=events, error=None)
    return {"monitors": compared, "events": events}


def _report(monitor, scan_id, event):
    event_id = db.create_monitor_event(monitor["id"], scan_id=scan_id, event_type=event["event_type"],
                                       severity=event["severity"], summary=event["summary"],
                                       details=event["details"])
    if notifier:
        try:
            notifier(event_id, event, monitor, scan_id=scan_id)
        except Exception:
            log.warning("Notification of a new known CVE failed", exc_info=True)


def last_run():
    """{"at", "events"} of the last comparison, or None."""
    import cve_feed
    state = cve_feed._state("alerts")
    return {"at": state["synced_at"], "events": state["items"]} if state.get("synced_at") else None
