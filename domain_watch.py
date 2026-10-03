"""The former watchlist of wanted domains: only its tables remain.

Domains someone wants used to be a list of their own, next to the portfolio
that already had a decision "request or claim" for exactly that. They are
portfolio domains with that decision now (domain_portfolio), which keeps the
minute-by-minute lookups around a .nl release and the "registered again by a
new holder" report this list had, and adds units, contacts and the import.

The tables stay so an existing database still has them: the portfolio moves
each row over once and marks it (moved_to_portfolio_at), so a wanted domain
removed from the portfolio later is not brought back, and the rows remain
as they were if anyone needs to look back.
"""

from __future__ import annotations


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
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(watched_domains)").fetchall()}
    if "moved_to_portfolio_at" not in columns:
        conn.execute("ALTER TABLE watched_domains ADD COLUMN moved_to_portfolio_at TEXT")
