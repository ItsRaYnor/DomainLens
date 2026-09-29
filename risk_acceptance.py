"""Accepted risks: a finding the organisation has decided to live with, for now.

Every finding came back on every scan and every report until it was fixed,
including the ones that were known and deliberately left: a legacy mail host
that cannot do DANE this year, a header a vendor's widget breaks. Those
buried the new findings, and nobody could show an auditor that the decision
had been made, by whom, and until when.

An acceptance names one condition on one domain, a reason, an owner and an
expiry date, never more than a year out. While it holds, the finding is still
reported -- it is measured and still true -- but marked accepted and left out
of the severity counts that drive scores and trends. When it expires the
finding counts again, which is the point: a decision is revisited, not
forgotten.

Conditions are matched by the same key that de-duplicates overlapping checks
(recommendations._condition_key), so accepting "HSTS missing" covers it
whichever check reported it.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import date, datetime, timedelta, timezone

import db

log = logging.getLogger("domainlens.risk")

MAX_DAYS = 366

# Active acceptances, for the day and database they were read for. Findings
# are generated per scan, and the report and trend pages generate them for
# every scan in a list: one query each, where the answer changes only when an
# acceptance is created or revoked -- both of which empty this -- or when a
# day passes, which the key covers.
_active_cache = {"key": None, "rows": ()}
_cache_lock = threading.Lock()


def _invalidate():
    with _cache_lock:
        _active_cache["key"] = None


def init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_exceptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            finding_key TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT,
            reason TEXT NOT NULL,
            owner TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            expires_on TEXT NOT NULL,
            revoked_at TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_exceptions_domain ON finding_exceptions(domain, finding_key)")


def _today():
    return datetime.now(timezone.utc).date()


def _row(row):
    out = dict(row)
    out["active"] = not out["revoked_at"] and out["expires_on"] >= _today().isoformat()
    return out


def create(*, domain, finding_key, title, severity, reason, owner, expires_on, created_by):
    reason = (reason or "").strip()
    owner = (owner or "").strip()
    if not reason:
        raise ValueError("State why the risk is accepted; that is what an auditor will ask")
    if not owner:
        raise ValueError("Name who owns the risk until it expires")
    try:
        expiry = date.fromisoformat(str(expires_on))
    except ValueError:
        raise ValueError("Expiry must be a date (YYYY-MM-DD)")
    if expiry < _today():
        raise ValueError("Expiry is in the past")
    if expiry > _today() + timedelta(days=MAX_DAYS):
        raise ValueError("Accept a risk for at most a year; renew it when it expires")
    with db._lock, db._connect() as conn:
        cursor = conn.execute(
            "INSERT INTO finding_exceptions (domain, finding_key, title, severity, reason, owner, "
            "created_by, created_at, expires_on) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (domain.strip().lower(), finding_key, title, severity, reason, owner, created_by,
             datetime.now(timezone.utc).isoformat(), expiry.isoformat()),
        )
        exception_id = cursor.lastrowid
    _invalidate()
    return exception_id


def revoke(exception_id):
    with db._lock, db._connect() as conn:
        revoked = conn.execute(
            "UPDATE finding_exceptions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (datetime.now(timezone.utc).isoformat(), int(exception_id))).rowcount > 0
    _invalidate()
    return revoked


def get(exception_id):
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM finding_exceptions WHERE id = ?",
                           (int(exception_id),)).fetchone()
    return _row(row) if row else None


def list_all(domain=None):
    sql = "SELECT * FROM finding_exceptions"
    params = []
    if domain:
        sql += " WHERE domain = ?"
        params.append(domain.strip().lower())
    with db._connect() as conn:
        rows = conn.execute(sql + " ORDER BY expires_on", params).fetchall()
    return [_row(r) for r in rows]


def _active_for(domains):
    """Active acceptances for these domains, keyed by finding key.

    Fails soft to "none": advice is generated in places with no database at
    all (tests, the report of an imported scan), and a missing table must
    not stop a finding from being reported. Nor may it create an empty
    database file where none was configured, which sqlite would do on
    connect.
    """
    domains = {d for d in {(d or "").strip().lower() for d in domains} if d}
    if not domains or not os.path.exists(db._db_path()):
        return {}
    out = {}
    for row in _all_active():
        if row["domain"] in domains:
            out.setdefault(row["finding_key"], row)
    return out


def _all_active():
    key = (db._db_path(), _today().isoformat())
    with _cache_lock:
        if _active_cache["key"] == key:
            return _active_cache["rows"]
    try:
        with db._connect() as conn:
            rows = tuple(dict(r) for r in conn.execute(
                "SELECT * FROM finding_exceptions WHERE revoked_at IS NULL AND expires_on >= ? "
                "ORDER BY expires_on DESC", (key[1],)).fetchall())
    except Exception:
        log.debug("Risk acceptances unavailable", exc_info=True)
        return ()
    with _cache_lock:
        _active_cache["key"] = key
        _active_cache["rows"] = rows
    return rows


# Categories whose findings describe the zone rather than the scanned host.
_APEX_CATEGORIES = {"email", "dns", "whois"}


def _apex_level(rec):
    return (str(rec.get("category") or "").lower() in _APEX_CATEGORIES
            or str(rec.get("finding_key") or "").startswith("email:"))


def apply(results, recs, key_fn):
    """Mark accepted findings in place.

    An acceptance on the scanned host covers its findings. One on the apex
    covers a subdomain scan only for email, DNS and WHOIS findings, which
    describe the zone: finding keys name no host, so letting it cover a web
    or TLS finding would hide an expired certificate on every subdomain
    because one legacy host at the apex was accepted.
    """
    domain = (results.get("domain") or "").strip().lower()
    apex = (results.get("apex_domain") or "").strip().lower()
    own = _active_for([domain])
    inherited = _active_for([apex]) if apex and apex != domain else {}
    for rec in recs:
        rec["finding_key"] = key_fn(rec)
        match = own.get(rec["finding_key"])
        if not match and _apex_level(rec):
            match = inherited.get(rec["finding_key"])
        if match:
            rec["accepted"] = {
                "id": match["id"],
                "reason": match["reason"],
                "owner": match["owner"],
                "expires_on": match["expires_on"],
                "created_by": match["created_by"],
            }
    return recs
