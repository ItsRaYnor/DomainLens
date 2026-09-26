"""Retention and backups.

Retention: scan results hold names, addresses and, through SCIM, personal
data about staff. Keeping them forever is a GDPR question an organisation
has to be able to answer, and "reporting.retention_days" was documented as a
target that nothing enforced. The `retention` settings enforce it, and every
limit defaults to 0 -- keep everything -- so upgrading deletes nothing an
operator did not ask to delete.

A monitor's baseline scan is never purged: deleting it would make the next
run a new baseline, and a regression in between would never be reported.

Backups: copying domainlens.db while the app runs can capture a half-written
WAL and restore to a corrupt file. SQLite's online backup API takes a
consistent snapshot of a live database; `backup_to()` uses it, for the admin
download and for `python maintenance.py backup <file>` from cron.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone

import db

log = logging.getLogger("domainlens.maintenance")

_RUN_EVERY = timedelta(hours=24)
_state_lock = threading.Lock()
_last_run = None


def retention_config():
    try:
        import config as domainlens_config
        raw = domainlens_config.load_settings().retention()
    except Exception:
        raw = {}

    def days(key):
        try:
            return max(0, int(raw.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    return {"scan_days": days("scan_days"), "event_days": days("event_days"),
            "audit_days": days("audit_days")}


def _cutoff(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def purge(now=None):
    """Delete what is older than each configured limit. Returns the counts."""
    cfg = retention_config()
    removed = {"scans": 0, "monitor_events": 0, "audit_entries": 0}
    with db._lock, db._connect() as conn:
        if cfg["scan_days"]:
            removed["scans"] = conn.execute(
                "DELETE FROM scans WHERE created_at < ? AND id NOT IN "
                "(SELECT last_scan_id FROM monitors WHERE last_scan_id IS NOT NULL)",
                (_cutoff(cfg["scan_days"]),)).rowcount
        if cfg["event_days"]:
            removed["monitor_events"] = conn.execute(
                "DELETE FROM monitor_events WHERE created_at < ?",
                (_cutoff(cfg["event_days"]),)).rowcount
    if cfg["audit_days"]:
        import audit_log
        removed["audit_entries"] = audit_log.purge_older_than(_cutoff(cfg["audit_days"]))
    if removed["scans"] or removed["monitor_events"]:
        import audit_log
        audit_log.record("retention.purge", details={**removed, **cfg}, auth_method="system")
    return removed


def maybe_purge():
    """Once a day from the scheduler loop; cheap to call every poll."""
    global _last_run
    now = datetime.now(timezone.utc)
    with _state_lock:
        if _last_run and now - _last_run < _RUN_EVERY:
            return None
        _last_run = now
    try:
        return purge()
    except Exception:
        log.exception("Retention purge failed")
        return None


def backup_to(path):
    """Write a consistent snapshot of the live database to `path`."""
    source = sqlite3.connect(db._db_path(), timeout=30)
    try:
        target = sqlite3.connect(path)
        try:
            with target:
                source.backup(target)
        finally:
            target.close()
    finally:
        source.close()
    return path


def backup_to_tempfile():
    handle, path = tempfile.mkstemp(prefix="domainlens-backup-", suffix=".db")
    os.close(handle)
    return backup_to(path)


def backup_filename():
    return f"domainlens-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.db"


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "backup":
        print("usage: python maintenance.py backup <target.db>", file=sys.stderr)
        sys.exit(2)
    print(backup_to(sys.argv[2]))
