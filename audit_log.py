"""Append-only record of who did what.

An organisation that runs this under ISO 27001 or NIS2 has to be able to
answer "who changed that setting", "who removed those scans" and "who pointed
active probes at that domain" after the fact. Nothing answered them: the
settings table kept only the last editor, and deletions left no trace at all.

Two properties matter more than the columns:

* Nothing here raises into the caller. An audit write that fails is logged
  loudly, but it must never be the reason a login or a scan stops working.
* Each row carries the hash of the row before it. Editing or deleting a row
  in the database file breaks the chain from that point, and verify() says
  where. That does not make the log tamper-proof -- whoever holds the file can
  recompute every hash -- but it turns a quiet edit into a visible one, which
  is what an auditor asks for.

Details never hold secret values. Settings changes record which keys changed,
not what they changed to, because some settings are credential lists.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
from datetime import datetime, timezone

import db

log = logging.getLogger("domainlens.audit")

_GENESIS = "0" * 64

_COLUMNS = ("id", "created_at", "actor_id", "actor_email", "actor_role",
            "auth_method", "ip", "action", "target_type", "target_id",
            "outcome", "details", "prev_hash", "row_hash")


def init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            actor_id TEXT,
            actor_email TEXT,
            actor_role TEXT,
            auth_method TEXT NOT NULL,
            ip TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            outcome TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '{}',
            prev_hash TEXT NOT NULL,
            row_hash TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_email)")


def _hash(prev_hash, entry):
    body = json.dumps(
        [prev_hash] + [entry.get(c) for c in _COLUMNS if c not in {"id", "prev_hash", "row_hash"}],
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _request_context():
    """Actor and address of the current request, or the system outside one."""
    try:
        from flask import has_request_context, request, g
    except Exception:
        return None, "system", None
    if not has_request_context():
        return None, "system", None
    import auth
    user = auth.current_user()
    method = "token" if getattr(g, "api_token_user", None) is not None else "session"
    if user is None:
        method = "anonymous"
    return user, method, request.remote_addr


def record(action, *, target_type=None, target_id=None, outcome="success",
           details=None, actor=None, auth_method=None):
    """Append one entry. Returns its id, or None when the write failed."""
    try:
        user, method, ip = _request_context()
        if actor is not None:
            user = actor
        entry = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "actor_id": str(user.get("id")) if user and user.get("id") is not None else None,
            "actor_email": (user or {}).get("email"),
            "actor_role": (user or {}).get("role"),
            "auth_method": auth_method or method,
            "ip": ip,
            "action": str(action),
            "target_type": target_type,
            "target_id": str(target_id) if target_id is not None else None,
            "outcome": outcome,
            "details": json.dumps(details or {}, sort_keys=True, default=str),
        }
        with db._lock, db._connect() as conn:
            row = conn.execute(
                "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = row["row_hash"] if row else _GENESIS
            entry["prev_hash"] = prev_hash
            entry["row_hash"] = _hash(prev_hash, entry)
            cursor = conn.execute(
                f"INSERT INTO audit_log ({', '.join(_COLUMNS[1:])}) "
                f"VALUES ({', '.join('?' for _ in _COLUMNS[1:])})",
                [entry[c] for c in _COLUMNS[1:]],
            )
            return cursor.lastrowid
    except Exception:
        log.error("Audit write failed for %s", action, exc_info=True)
        return None


def _row_to_dict(row):
    out = {c: row[c] for c in _COLUMNS}
    try:
        out["details"] = json.loads(out["details"] or "{}")
    except ValueError:
        out["details"] = {}
    return out


def _filters(action=None, actor=None, since=None, until=None, outcome=None):
    clauses, params = [], []
    if action:
        clauses.append("action LIKE ?")
        params.append(action.rstrip("*") + "%")
    if actor:
        clauses.append("actor_email = ?")
        params.append(actor.strip().lower())
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    if until:
        clauses.append("created_at < ?")
        params.append(until)
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def list_entries(*, limit=100, offset=0, **filters):
    where, params = _filters(**filters)
    with db._connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM audit_log{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            [*params, int(limit), int(offset)],
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM audit_log{where}", params).fetchone()[0]
    return {"entries": [_row_to_dict(r) for r in rows], "total": total}


def export_csv(**filters):
    where, params = _filters(**filters)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_COLUMNS)
    with db._connect() as conn:
        for row in conn.execute(f"SELECT * FROM audit_log{where} ORDER BY id", params):
            writer.writerow([_csv_safe(row[c]) for c in _COLUMNS])
    return buffer.getvalue()


def _csv_safe(value):
    """Neutralise spreadsheet formulas. An email or domain is attacker-chosen
    text, and "=HYPERLINK(...)" in a cell runs when an auditor opens the file."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def verify():
    """Walk the chain. Reports the first row whose hash does not follow.

    The first remaining row is taken as the anchor, so purging old entries
    under a retention policy does not read as tampering.
    """
    checked = 0
    prev = None
    with db._connect() as conn:
        for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
            entry = {c: row[c] for c in _COLUMNS}
            if prev is not None and entry["prev_hash"] != prev:
                return {"intact": False, "checked": checked, "broken_at": entry["id"],
                        "reason": "previous-hash mismatch (a row was removed or reordered)"}
            if _hash(entry["prev_hash"], entry) != entry["row_hash"]:
                return {"intact": False, "checked": checked, "broken_at": entry["id"],
                        "reason": "row content does not match its hash (the row was edited)"}
            prev = entry["row_hash"]
            checked += 1
    return {"intact": True, "checked": checked, "broken_at": None, "reason": None}


def purge_older_than(cutoff_iso):
    """Remove entries before the cutoff. Recorded as an entry of its own."""
    with db._lock, db._connect() as conn:
        removed = conn.execute(
            "DELETE FROM audit_log WHERE created_at < ?", (cutoff_iso,)).rowcount
    if removed:
        record("audit.purge", outcome="success",
               details={"removed": removed, "before": cutoff_iso}, auth_method="system")
    return removed
