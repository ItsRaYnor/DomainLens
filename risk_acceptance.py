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
from datetime import date, datetime, timedelta, timezone

import db

log = logging.getLogger("domainlens.risk")

MAX_DAYS = 366


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
        return cursor.lastrowid


def revoke(exception_id):
    with db._lock, db._connect() as conn:
        return conn.execute(
            "UPDATE finding_exceptions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (datetime.now(timezone.utc).isoformat(), int(exception_id))).rowcount > 0


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
    domains = [d for d in {(d or "").strip().lower() for d in domains} if d]
    if not domains or not os.path.exists(db._db_path()):
        return {}
    try:
        with db._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM finding_exceptions WHERE revoked_at IS NULL AND expires_on >= ? "
                f"AND domain IN ({', '.join('?' for _ in domains)}) ORDER BY expires_on DESC",
                [_today().isoformat(), *domains]).fetchall()
    except Exception:
        log.debug("Risk acceptances unavailable", exc_info=True)
        return {}
    out = {}
    for row in rows:
        out.setdefault(row["finding_key"], dict(row))
    return out


def apply(results, recs, key_fn):
    """Mark accepted findings in place. Email and DNS findings live at the
    apex, so an acceptance on the apex covers them when a subdomain is
    scanned."""
    accepted = _active_for([results.get("domain"), results.get("apex_domain")])
    for rec in recs:
        rec["finding_key"] = key_fn(rec)
        match = accepted.get(rec["finding_key"])
        if match:
            rec["accepted"] = {
                "id": match["id"],
                "reason": match["reason"],
                "owner": match["owner"],
                "expires_on": match["expires_on"],
                "created_by": match["created_by"],
            }
    return recs
