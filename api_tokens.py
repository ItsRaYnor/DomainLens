"""Personal API tokens, for scripts and pipelines rather than browsers.

Automation could only reach the API with a copied session cookie, which
carries the person's full role, cannot be scoped or named, expires on its own
schedule and is revoked only by signing out everywhere. A token is:

* bound to one account, and never worth more than that account: its role is
  the lower of the role it was issued with and the account's current role, so
  demoting or disabling the person demotes or disables every token they made;
* stored as a SHA-256 hash only. Tokens are 256 random bits, so a slow
  password hash would add nothing but latency to every API call; the value is
  shown once at creation and cannot be recovered;
* always expiring, at most a year out, because a forgotten token in a CI
  secret store is the kind that leaks;
* usable only on /api/ paths (and /metrics), never to render pages or change
  an account's password or MFA.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import db
import roles

PREFIX = "dlk_"
MAX_DAYS = 365
DEFAULT_DAYS = 90
# last_used_at is written at most this often per token, so a busy pipeline
# does not turn every read into a write.
_TOUCH_INTERVAL = timedelta(minutes=1)


def init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            display_prefix TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_used_at TEXT,
            last_used_ip TEXT,
            revoked_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)")


def _now():
    return datetime.now(timezone.utc)


def _digest(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _public(row):
    """Everything about a token except anything that could be used as it."""
    out = {k: row[k] for k in ("id", "user_id", "name", "display_prefix", "role", "created_at",
                               "expires_at", "last_used_at", "last_used_ip", "revoked_at")}
    out["active"] = not row["revoked_at"] and row["expires_at"] > _now().isoformat()
    return out


def create(user, *, name, role=None, days=DEFAULT_DAYS):
    """Issue a token for a users-table account. Returns (raw_token, record)."""
    name = (name or "").strip()[:80]
    if not name:
        raise ValueError("Give the token a name, so it can be recognised when it has to be revoked")
    try:
        days = int(days)
    except (TypeError, ValueError):
        raise ValueError("Expiry must be a number of days")
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f"Expiry must be between 1 and {MAX_DAYS} days")
    owner_role = roles.normalize(user.get("role"))
    wanted = roles.normalize(role, default=owner_role)
    if not roles.at_least(owner_role, wanted):
        raise ValueError("A token cannot hold more rights than its owner")

    raw = PREFIX + secrets.token_urlsafe(32)
    now = _now()
    with db._lock, db._connect() as conn:
        cursor = conn.execute(
            "INSERT INTO api_tokens (user_id, name, display_prefix, token_hash, role, "
            "created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (int(user["id"]), name, raw[:len(PREFIX) + 6], _digest(raw), wanted,
             now.isoformat(), (now + timedelta(days=days)).isoformat()),
        )
        token_id = cursor.lastrowid
    return raw, get(token_id)


def get(token_id):
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM api_tokens WHERE id = ?", (int(token_id),)).fetchone()
    return _public(row) if row else None


def list_for_user(user_id):
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM api_tokens WHERE user_id = ? ORDER BY id DESC",
                            (int(user_id),)).fetchall()
    return [_public(r) for r in rows]


def list_all():
    with db._connect() as conn:
        rows = conn.execute(
            "SELECT t.*, u.email AS owner_email FROM api_tokens t "
            "LEFT JOIN users u ON u.id = t.user_id ORDER BY t.id DESC").fetchall()
    return [{**_public(r), "owner_email": r["owner_email"]} for r in rows]


def revoke(token_id, *, user_id=None):
    """Revoke a token; with user_id, only if it belongs to that user."""
    sql = "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"
    params = [_now().isoformat(), int(token_id)]
    if user_id is not None:
        sql += " AND user_id = ?"
        params.append(int(user_id))
    with db._lock, db._connect() as conn:
        return conn.execute(sql, params).rowcount > 0


def authenticate(raw, ip=None):
    """The acting user for a presented token, or None.

    Checked on every request, against the account as it is now.
    """
    if not raw or not raw.startswith(PREFIX):
        return None
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM api_tokens WHERE token_hash = ?",
                           (_digest(raw),)).fetchone()
    if not row or row["revoked_at"]:
        return None
    now = _now()
    if row["expires_at"] <= now.isoformat():
        return None
    owner = db.get_user(row["user_id"])
    if not owner or not owner.get("enabled"):
        return None
    last = row["last_used_at"]
    if not last or datetime.fromisoformat(last) < now - _TOUCH_INTERVAL:
        with db._lock, db._connect() as conn:
            conn.execute("UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?",
                         (now.isoformat(), ip, row["id"]))
    return {
        "id": owner["id"],
        "email": owner.get("email"),
        "name": owner.get("name"),
        "role": roles.lower_of(roles.normalize(row["role"]), roles.normalize(owner.get("role"))),
        "provider": "api_token",
        "token_id": row["id"],
        "token_name": row["name"],
    }
