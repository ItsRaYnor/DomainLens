"""A watchlist of domains someone wants: expiring, in quarantine, or taken.

DomainLens is not a registrar and cannot register a domain. What it can do
is know the moment one becomes available and say so, instead of someone
checking the registry by hand or setting an alarm for 02:05. Each watched
domain is looked up over RDAP on a schedule that tightens as its release
comes closer: every six hours normally, hourly while it is being deleted,
and every minute in the hour a .nl domain leaves SIDN's quarantine. Every
phase change is recorded and sent through the notification channels.

A lookup that fails changes nothing: "could not be measured" is never
turned into "available", which is the one mistake that would send someone
to a registrar for a domain that is still taken.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone

import db
import rdap
import whois_batch

MAX_WATCHED = 200
_PER_RUN = 20
_run_lock = threading.Lock()

# How long before the published release moment the minute-by-minute checks
# start, and how long after it they continue (SIDN releases within an hour).
_WINDOW_BEFORE = timedelta(minutes=5)
_WINDOW_AFTER = timedelta(minutes=75)

PHASE_TEXT = {
    "registered": "Registered",
    "quarantine": "In quarantine",
    "pending_delete": "Being deleted",
    "redemption": "Redemption period",
    "not_in_dns": "Registered, not in DNS",
    "available": "Available to register",
    "unmeasured": "Not measured yet",
}


def init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS watched_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            note TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            phase TEXT NOT NULL DEFAULT 'unmeasured',
            status TEXT NOT NULL DEFAULT '[]',
            registered_on TEXT,
            released_from TEXT,
            last_checked_at TEXT,
            last_error TEXT,
            last_change_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS watched_domain_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            at TEXT NOT NULL,
            old_phase TEXT,
            new_phase TEXT NOT NULL,
            detail TEXT
        )
        """
    )


def _now():
    return datetime.now(timezone.utc)


def _row(row):
    out = dict(row)
    out["status"] = json.loads(out.get("status") or "[]")
    out["phase_text"] = PHASE_TEXT.get(out["phase"], out["phase"])
    return out


def list_all():
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM watched_domains ORDER BY domain").fetchall()
    return [_row(r) for r in rows]


def events(limit=50):
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM watched_domain_events ORDER BY id DESC LIMIT ?",
                            (int(limit),)).fetchall()
    return [dict(r) for r in rows]


def add(domains, *, note=None, created_by=None):
    """Add domains; returns (added, already_watched). Raises on the cap."""
    current = {w["domain"] for w in list_all()}
    new = [d for d in dict.fromkeys(domains) if d not in current]
    if len(current) + len(new) > MAX_WATCHED:
        raise ValueError(f"At most {MAX_WATCHED} domains on the watchlist")
    now = _now().isoformat()
    with db._lock, db._connect() as conn:
        for domain in new:
            conn.execute("INSERT INTO watched_domains (domain, note, created_by, created_at) "
                         "VALUES (?, ?, ?, ?)", (domain, (note or "").strip()[:200] or None,
                                                 created_by, now))
    return new, [d for d in domains if d in current]


def remove(watch_id):
    with db._lock, db._connect() as conn:
        return conn.execute("DELETE FROM watched_domains WHERE id = ?", (int(watch_id),)).rowcount > 0


def get(watch_id):
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM watched_domains WHERE id = ?", (int(watch_id),)).fetchone()
    return _row(row) if row else None


def is_due(watch, now=None):
    """Whether this domain should be looked up now."""
    now = now or _now()
    if not watch.get("last_checked_at"):
        return True
    last = datetime.fromisoformat(watch["last_checked_at"])
    released = watch.get("released_from")
    if released:
        at = datetime.fromisoformat(released.replace("Z", "+00:00"))
        if at - _WINDOW_BEFORE <= now <= at + _WINDOW_AFTER:
            return now - last >= timedelta(seconds=55)
    if watch.get("phase") in ("quarantine", "pending_delete", "redemption", "unmeasured"):
        return now - last >= timedelta(hours=1)
    return now - last >= timedelta(hours=6)


def _state(result):
    """(phase, status list, registered_on, released_from, error) from RDAP."""
    if result.get("success"):
        lc = result.get("lifecycle") or {}
        return (lc.get("phase") or "registered", result.get("status") or [],
                result.get("registered"), lc.get("released_from"), None)
    if result.get("registered") is False:
        return "available", [], None, None, None
    return None, None, None, None, result.get("error") or "No answer"


def _describe(domain, old, new, registered_on, released_from):
    if new == "available":
        return f"{domain} is available to register now."
    if new == "registered" and old in ("quarantine", "pending_delete", "available"):
        if registered_on and released_from and registered_on >= released_from[:10]:
            return f"{domain} was registered again on {registered_on} — by someone else."
        return f"{domain} is registered again (restored by the holder)."
    if new == "quarantine":
        return f"{domain} went into quarantine" + (f"; released from {released_from}." if released_from else ".")
    return f"{domain}: {PHASE_TEXT.get(old, old)} -> {PHASE_TEXT.get(new, new)}."


def check(watch, *, fetch=None, notify=None):
    """Look one domain up, store it, and report a phase change once."""
    result = (fetch or (lambda d: whois_batch.lookup_paced(d)))(watch["domain"])
    phase, status, registered_on, released_from, error = _state(result)
    now = _now().isoformat()
    with db._lock, db._connect() as conn:
        if phase is None:
            # Not measured: keep the last known phase, note the error.
            conn.execute("UPDATE watched_domains SET last_checked_at=?, last_error=? WHERE id=?",
                         (now, error, watch["id"]))
            return None
        changed = phase != watch.get("phase")
        conn.execute(
            "UPDATE watched_domains SET phase=?, status=?, registered_on=?, released_from=?, "
            "last_checked_at=?, last_error=NULL, last_change_at=COALESCE(?, last_change_at) "
            "WHERE id=?",
            (phase, json.dumps(status), registered_on, released_from, now,
             now if changed else None, watch["id"]))
        if not changed:
            return None
        # A registered domain has no release moment any more; whether it went to
        # someone else is judged against the one it had while in quarantine.
        detail = _describe(watch["domain"], watch.get("phase"), phase, registered_on,
                           released_from or watch.get("released_from"))
        conn.execute("INSERT INTO watched_domain_events (domain, at, old_phase, new_phase, detail) "
                     "VALUES (?, ?, ?, ?, ?)", (watch["domain"], now, watch.get("phase"), phase, detail))
    # The first real answer is a baseline, not news.
    if watch.get("phase") != "unmeasured":
        (notify or _notify)(watch["domain"], phase, detail)
    return {"domain": watch["domain"], "old": watch.get("phase"), "new": phase, "detail": detail}


def _notify(domain, phase, detail):
    try:
        import notifications
        severity = "high" if phase in ("available", "registered", "quarantine") else "medium"
        notifications.dispatch({"event_type": "domain_watch", "severity": severity,
                                "summary": detail, "details": {"target": domain}},
                               {"target": domain, "name": f"Watchlist: {domain}"})
    except Exception:
        pass


def maybe_run(now=None, *, fetch=None, notify=None):
    """From the scheduler loop: look up the domains that are due."""
    if not _run_lock.acquire(blocking=False):
        return []
    try:
        now = now or _now()
        due = [w for w in list_all() if is_due(w, now)][:_PER_RUN]
        changes = []
        for watch in due:
            try:
                change = check(watch, fetch=fetch, notify=notify)
            except Exception:
                continue
            if change:
                changes.append(change)
        return changes
    finally:
        _run_lock.release()
