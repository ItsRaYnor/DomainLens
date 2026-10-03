"""The people to ask about a domain: who decides whether it is kept, and who
answers when it goes into quarantine.

A contact belongs with a company or business unit, and every unit and
domain below it has that contact unless it names its own -- the same way a
unit's expected registrar is inherited.

A contact is a record of its own that domains point to, not a name typed
into every domain: a person who leaves is replaced once, not in a hundred
rows that each spell the name a little differently.

With accounts (local or single sign-on), a contact can be an account. Its
name, e-mail address and phone number then come from the account, which SCIM
or each sign-in keeps current; the copy stored here is only what is shown
once the account is gone, and the contact says so.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import db

_EMAIL = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")
MAX_CONTACTS = 1000


def init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            phone TEXT,
            user_id INTEGER UNIQUE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )


def _now():
    return datetime.now(timezone.utc).isoformat()


_SELECT = """
    SELECT c.id, c.user_id, c.created_at,
           c.name AS own_name, c.email AS own_email, c.phone AS own_phone,
           u.id AS account_id, u.name AS account_name, u.email AS account_email,
           u.phone_number AS account_phone, u.enabled AS account_enabled,
           u.provider AS account_provider
    FROM contacts c LEFT JOIN users u ON u.id = c.user_id
"""


def _shape(row):
    r = dict(row)
    linked = r["user_id"] is not None
    present = r["account_id"] is not None
    if linked and present:
        name = r["account_name"] or r["account_email"] or r["own_name"]
        email, phone = r["account_email"], r["account_phone"] or r["own_phone"]
    else:
        name, email, phone = r["own_name"], r["own_email"], r["own_phone"]
    account = None
    if linked:
        # "removed": the account is gone; what is shown is the last copy.
        account = {"id": r["user_id"],
                   "state": ("removed" if not present
                             else "enabled" if r["account_enabled"] else "disabled"),
                   "provider": r["account_provider"] if present else None}
    return {"id": r["id"], "name": name or email or f"Contact {r['id']}", "email": email,
            "phone": phone, "account": account, "created_at": r["created_at"]}


def list_contacts():
    """Every contact, with how many units and domains name it themselves."""
    with db._connect() as conn:
        rows = conn.execute(_SELECT + " ORDER BY COALESCE(u.name, c.name, u.email, c.email) "
                                      "COLLATE NOCASE").fetchall()
        used = {r["contact_id"]: r["n"] for r in conn.execute(
            "SELECT contact_id, COUNT(*) AS n FROM portfolio_domains "
            "WHERE contact_id IS NOT NULL GROUP BY contact_id").fetchall()}
        units = {}
        for r in conn.execute("SELECT id, contact_id FROM portfolio_groups "
                              "WHERE contact_id IS NOT NULL ORDER BY id").fetchall():
            units.setdefault(r["contact_id"], []).append(r["id"])
    # unit_ids: the units this contact is set on itself (those below inherit).
    return [{**_shape(r), "domains": used.get(r["id"], 0), "units": len(units.get(r["id"], [])),
             "unit_ids": units.get(r["id"], [])} for r in rows]


def by_id(conn):
    """{id: contact} for showing contacts next to units and domains."""
    return {r["id"]: _shape(r) for r in conn.execute(_SELECT).fetchall()}


def get(contact_id):
    with db._connect() as conn:
        row = conn.execute(_SELECT + " WHERE c.id = ?", (int(contact_id),)).fetchone()
    return _shape(row) if row else None


def _clean(name, email, phone):
    name = " ".join(str(name or "").split())[:200] or None
    email = str(email or "").strip()[:254] or None
    phone = " ".join(str(phone or "").split())[:50] or None
    if email and not _EMAIL.match(email):
        raise ValueError(f"Not an e-mail address: {email}")
    return name, email, phone


def create(*, name=None, email=None, phone=None, user_id=None):
    """A contact by hand (a name or an address at least), or for an account."""
    now = _now()
    with db._lock, db._connect() as conn:
        if conn.execute("SELECT COUNT(*) AS n FROM contacts").fetchone()["n"] >= MAX_CONTACTS:
            raise ValueError(f"At most {MAX_CONTACTS} contacts")
        if user_id not in (None, ""):
            user = conn.execute("SELECT id, name, email, phone_number FROM users WHERE id = ?",
                                (int(user_id),)).fetchone()
            if not user:
                raise ValueError("Unknown account")
            existing = conn.execute("SELECT id FROM contacts WHERE user_id = ?", (user["id"],)).fetchone()
            if existing:
                # One account, one contact: choosing it again finds the same one.
                return get_in(conn, existing["id"])
            cur = conn.execute(
                "INSERT INTO contacts (name, email, phone, user_id, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (user["name"], user["email"], user["phone_number"], user["id"], now, now))
        else:
            name, email, phone = _clean(name, email, phone)
            if not (name or email):
                raise ValueError("Give the contact a name or an e-mail address")
            cur = conn.execute(
                "INSERT INTO contacts (name, email, phone, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (name, email, phone, now, now))
        return get_in(conn, cur.lastrowid)


def get_in(conn, contact_id):
    row = conn.execute(_SELECT + " WHERE c.id = ?", (int(contact_id),)).fetchone()
    return _shape(row) if row else None


def update(contact_id, *, name=None, email=None, phone=None):
    """Change a contact made by hand. One that is an account takes its name
    and address from the account; only a phone number can be added to it."""
    current = get(contact_id)
    if not current:
        raise ValueError("Unknown contact")
    with db._lock, db._connect() as conn:
        if current["account"] and current["account"]["state"] != "removed":
            _, _, phone = _clean(None, None, phone)
            conn.execute("UPDATE contacts SET phone = ?, updated_at = ? WHERE id = ?",
                         (phone, _now(), int(contact_id)))
        else:
            name, email, phone = _clean(name, email, phone)
            if not (name or email):
                raise ValueError("Give the contact a name or an e-mail address")
            conn.execute("UPDATE contacts SET name = ?, email = ?, phone = ?, updated_at = ? WHERE id = ?",
                         (name, email, phone, _now(), int(contact_id)))
    return get(contact_id)


def delete(contact_id):
    """Remove a contact; its units and domains are left without one (a
    domain then falls back on its unit's contact), not deleted."""
    with db._lock, db._connect() as conn:
        conn.execute("UPDATE portfolio_domains SET contact_id = NULL WHERE contact_id = ?",
                     (int(contact_id),))
        conn.execute("UPDATE portfolio_groups SET contact_id = NULL WHERE contact_id = ?",
                     (int(contact_id),))
        return conn.execute("DELETE FROM contacts WHERE id = ?", (int(contact_id),)).rowcount > 0


def accounts():
    """Enabled accounts that are not a contact yet, to choose one from."""
    with db._connect() as conn:
        rows = conn.execute(
            "SELECT u.id, u.name, u.email, u.provider FROM users u "
            "WHERE u.enabled = 1 AND u.id NOT IN (SELECT user_id FROM contacts WHERE user_id IS NOT NULL) "
            "ORDER BY COALESCE(u.name, u.email) COLLATE NOCASE").fetchall()
    return [dict(r) for r in rows]
