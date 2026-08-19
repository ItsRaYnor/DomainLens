"""
SQLite-backed scan history storage for DomainLens.
Uses only stdlib sqlite3 — no external dependencies.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

_lock = threading.Lock()


def _db_path():
    return os.environ.get(
        "DOMAINLENS_DB",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "domainlens.db"),
    )


def _connect():
    conn = sqlite3.connect(_db_path(), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they don't exist."""
    with _lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                created_at TEXT NOT NULL,
                grade TEXT,
                score INTEGER,
                issues_count INTEGER DEFAULT 0,
                data TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS monitors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                domain TEXT NOT NULL,
                target TEXT NOT NULL,
                record_type TEXT NOT NULL,
                record_value TEXT,
                source_type TEXT NOT NULL,
                source_label TEXT,
                provider TEXT,
                schedule_minutes INTEGER NOT NULL DEFAULT 1440,
                checks TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                metadata TEXT NOT NULL DEFAULT '{}',
                last_scan_id INTEGER,
                last_scan_at TEXT,
                last_state_hash TEXT,
                next_scan_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(last_scan_id) REFERENCES scans(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_monitors_domain ON monitors(domain)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_monitors_target ON monitors(target)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_monitors_next_scan ON monitors(next_scan_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_monitors_enabled ON monitors(enabled)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS monitor_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                monitor_id INTEGER NOT NULL,
                scan_id INTEGER,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_monitor_events_monitor ON monitor_events(monitor_id, created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_monitor_events_created ON monitor_events(created_at DESC)"
        )
        event_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(monitor_events)").fetchall()
        }
        if "servicenow_sys_id" not in event_columns:
            conn.execute("ALTER TABLE monitor_events ADD COLUMN servicenow_sys_id TEXT")
        if "servicenow_number" not in event_columns:
            conn.execute("ALTER TABLE monitor_events ADD COLUMN servicenow_number TEXT")
        if "notified_at" not in event_columns:
            conn.execute("ALTER TABLE monitor_events ADD COLUMN notified_at TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_metrics (
                scan_id INTEGER PRIMARY KEY,
                domain TEXT NOT NULL,
                monitor_id INTEGER,
                created_at TEXT NOT NULL,
                day TEXT NOT NULL,
                grade TEXT,
                grade_score INTEGER,
                header_score INTEGER,
                issues_count INTEGER NOT NULL DEFAULT 0,
                recommendation_count INTEGER NOT NULL DEFAULT 0,
                blacklist_listed INTEGER NOT NULL DEFAULT 0,
                dnssec_signed INTEGER,
                https_redirect INTEGER,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_metrics_day ON scan_metrics(day)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_metrics_domain_day ON scan_metrics(domain, day)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_metrics_monitor_day ON scan_metrics(monitor_id, day)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_monitor_events_severity ON monitor_events(severity, created_at DESC)"
        )
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(monitors)").fetchall()
        }
        if "last_state_hash" not in columns:
            conn.execute("ALTER TABLE monitors ADD COLUMN last_state_hash TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                name TEXT,
                password_hash TEXT,
                role TEXT NOT NULL DEFAULT 'user',
                enabled INTEGER NOT NULL DEFAULT 1,
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                mfa_secret TEXT,
                mfa_backup_codes TEXT NOT NULL DEFAULT '[]',
                password_changed_at TEXT,
                failed_logins INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                last_login_at TEXT,
                provider TEXT NOT NULL DEFAULT 'local',
                external_id TEXT,
                user_name TEXT,
                prefs TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        user_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "provider" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'local'"
            )
        if "external_id" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN external_id TEXT")
        if "user_name" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN user_name TEXT")
        # Display preferences (theme, accent). JSON rather than a column per
        # preference: these are cosmetic, nothing queries them, and each new
        # one would otherwise be another migration.
        if "prefs" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN prefs TEXT NOT NULL DEFAULT '{}'")
        # Org / enterprise profile fields (SCIM + Entra default logical attrs)
        for col, decl in (
            ("department", "TEXT"),
            ("company_name", "TEXT"),
            ("job_title", "TEXT"),
            ("office_location", "TEXT"),
            ("employee_number", "TEXT"),
            ("cost_center", "TEXT"),
            ("division", "TEXT"),
            ("organization", "TEXT"),
            ("manager_external_id", "TEXT"),
            ("manager_display_name", "TEXT"),
            ("phone_number", "TEXT"),
            ("mobile_number", "TEXT"),
            ("preferred_language", "TEXT"),
            ("street_address", "TEXT"),
            ("city", "TEXT"),
            ("state", "TEXT"),
            ("postal_code", "TEXT"),
            ("country", "TEXT"),
            ("scim_profile", "TEXT"),
        ):
            if col not in user_columns:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_user_name ON users(user_name)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_department ON users(department)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_manager_ext ON users(manager_external_id)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                section TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by INTEGER,
                FOREIGN KEY(updated_by) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vuln_imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                source_format TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                row_count INTEGER NOT NULL DEFAULT 0,
                finding_count INTEGER NOT NULL DEFAULT 0,
                summary TEXT,
                warnings TEXT,
                header_map TEXT,
                imported_by INTEGER,
                FOREIGN KEY(imported_by) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vuln_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                import_id INTEGER NOT NULL,
                asset_ip TEXT,
                hostname TEXT,
                domain TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss REAL,
                cves TEXT,
                solution TEXT,
                description TEXT,
                port INTEGER,
                protocol TEXT,
                vuln_id TEXT,
                result_code TEXT,
                exploit TEXT,
                raw TEXT,
                FOREIGN KEY(import_id) REFERENCES vuln_imports(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vuln_findings_domain ON vuln_findings(domain)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vuln_findings_import ON vuln_findings(import_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vuln_findings_severity ON vuln_findings(severity)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS external_cache (
                cache_key TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                domain TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_external_cache_kind ON external_cache(kind, domain)"
        )


def _summarize(results):
    """Extract grade, score and issue count from scan results."""
    grade = None
    score = None
    issues = 0

    tls = results.get("tls_deep") or {}
    if tls.get("success"):
        grade = tls.get("grade")
        issues += len(tls.get("warnings") or [])

    headers = results.get("http_headers") or {}
    if headers.get("success"):
        score = headers.get("score")
        issues += len(headers.get("headers_missing") or [])

    for key in ("spf", "dmarc", "dkim", "mta_sts", "tlsrpt"):
        block = results.get(key) or {}
        if block and not block.get("pass", True):
            issues += 1

    if (results.get("https_redirect") or {}).get("pass") is False:
        issues += 1

    dnssec = results.get("dnssec") or {}
    if dnssec and not dnssec.get("signed"):
        issues += 1

    bl = results.get("blacklist") or {}
    if bl.get("is_listed"):
        issues += len(bl.get("listed") or [])

    sec = results.get("security") or {}
    if sec.get("success"):
        issues += len(sec.get("findings") or [])

    hs = results.get("hubspot_cf") or {}
    for finding in hs.get("findings") or []:
        if finding.get("severity") in ("critical", "high", "medium"):
            issues += 1

    deep = results.get("http_deep") or {}
    issues += len(deep.get("diagnostics") or [])

    js = results.get("js_scan") or {}
    if js.get("success"):
        issues += len(js.get("vulnerable_libraries") or [])
        issues += len(js.get("secrets_found") or [])

    ac = results.get("active_scan") or {}
    if ac.get("success") and ac.get("enabled"):
        issues += len(ac.get("findings") or [])

    return grade, score, issues


def _grade_to_score(grade):
    mapping = {"A+": 100, "A": 90, "B": 75, "C": 60, "D": 40, "F": 20, "T": 10}
    return mapping.get(grade)


def _extract_metrics(domain, results, issues_count, grade, header_score, monitor_id=None, created_at=None):
    created_at = created_at or datetime.now(timezone.utc).isoformat()
    day = created_at[:10]
    rec_count = issues_count
    try:
        import recommendations
        rec_count = len(recommendations.generate(results) or [])
    except Exception:
        pass

    dnssec = results.get("dnssec") or {}
    https = results.get("https_redirect") or {}
    blacklist = results.get("blacklist") or {}
    return {
        "domain": domain,
        "monitor_id": monitor_id,
        "created_at": created_at,
        "day": day,
        "grade": grade,
        "grade_score": _grade_to_score(grade),
        "header_score": header_score,
        "issues_count": issues_count,
        "recommendation_count": rec_count,
        "blacklist_listed": 1 if blacklist.get("is_listed") else 0,
        "dnssec_signed": None if not dnssec else (1 if dnssec.get("signed") else 0),
        "https_redirect": None if "pass" not in https else (1 if https.get("pass") else 0),
    }


def save_scan(domain, results):
    """Persist a scan result, return the new row id."""
    grade, score, issues = _summarize(results)
    created_at = datetime.now(timezone.utc).isoformat()
    payload = json.dumps(results, default=str)
    monitor_meta = results.get("monitor") or {}
    monitor_id = monitor_meta.get("id")
    metrics = _extract_metrics(
        domain, results, issues, grade, score, monitor_id=monitor_id, created_at=created_at
    )

    # The connection runs in autocommit mode (isolation_level=None), so the two
    # dependent inserts are wrapped in an explicit transaction: either both the
    # scans row and its scan_metrics row commit, or neither does. Otherwise a
    # failing metrics insert would leave an orphaned scans row.
    with _lock, _connect() as conn:
        try:
            conn.execute("BEGIN")
            cur = conn.execute(
                """
                INSERT INTO scans (domain, created_at, grade, score, issues_count, data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (domain, created_at, grade, score, issues, payload),
            )
            scan_id = cur.lastrowid
            conn.execute(
                """
                INSERT INTO scan_metrics (
                    scan_id, domain, monitor_id, created_at, day, grade, grade_score,
                    header_score, issues_count, recommendation_count, blacklist_listed,
                    dnssec_signed, https_redirect
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    metrics["domain"],
                    metrics["monitor_id"],
                    metrics["created_at"],
                    metrics["day"],
                    metrics["grade"],
                    metrics["grade_score"],
                    metrics["header_score"],
                    metrics["issues_count"],
                    metrics["recommendation_count"],
                    metrics["blacklist_listed"],
                    metrics["dnssec_signed"],
                    metrics["https_redirect"],
                ),
            )
            conn.execute("COMMIT")
            return scan_id
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise


def list_scans(domain=None, limit=100, days=None):
    """Return recent scans, optionally filtered by domain and age."""
    from datetime import timedelta

    clauses = []
    params = []
    if domain:
        clauses.append("domain = ?")
        params.append(domain)
    if days:
        days = max(1, min(int(days), 365))
        start = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date().isoformat()
        clauses.append("created_at >= ?")
        params.append(start)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)

    with _lock, _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT id, domain, created_at, grade, score, issues_count
            FROM scans
            {where}
            ORDER BY created_at DESC LIMIT ?
            """,
            params,
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id):
    """Return a full scan record including the JSON data, or None."""
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        record = dict(row)
        try:
            record["data"] = json.loads(record["data"])
        except (TypeError, ValueError):
            record["data"] = {}
        return record


def latest_scans_by_domain(domains):
    """Return the newest scan per domain as {domain: row}.

    A monitor only records the scans it ran itself, so its last_scan_id goes
    stale as soon as the domain is scanned by hand. This gives the caller the
    genuinely newest scan so the two can be shown side by side.
    """
    wanted = [d for d in dict.fromkeys(domains) if d]
    if not wanted:
        return {}

    latest = {}
    with _lock, _connect() as conn:
        # SQLite has a parameter limit, so ask in batches rather than one
        # oversized IN clause.
        for start in range(0, len(wanted), 400):
            batch = wanted[start:start + 400]
            placeholders = ",".join("?" for _ in batch)
            rows = conn.execute(
                f"""
                SELECT id, domain, created_at, grade, score, issues_count
                FROM scans
                WHERE domain IN ({placeholders})
                ORDER BY created_at DESC, id DESC
                """,
                batch,
            ).fetchall()
            for row in rows:
                # Rows arrive newest first, so the first one per domain wins.
                latest.setdefault(row["domain"], dict(row))
    return latest


def external_cache_get(kind, domain):
    """Return (payload, created_at) for a cached third-party lookup, or None.

    Age is deliberately not judged here: the caller owns the TTL, so the same
    row can serve a fresh read and a deliberate stale read.
    """
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT payload, created_at FROM external_cache WHERE cache_key = ?",
            (f"{kind}:{domain}",),
        ).fetchone()
    if not row:
        return None
    try:
        payload = json.loads(row["payload"])
    except (TypeError, ValueError):
        return None
    try:
        created_at = datetime.fromisoformat(row["created_at"])
    except (TypeError, ValueError):
        return None
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return payload, created_at


def external_cache_put(kind, domain, payload):
    """Store a third-party lookup, replacing any earlier copy."""
    with _lock, _connect() as conn:
        conn.execute(
            """
            INSERT INTO external_cache (cache_key, kind, domain, payload, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                payload = excluded.payload,
                created_at = excluded.created_at
            """,
            (f"{kind}:{domain}", kind, domain,
             json.dumps(payload, default=str),
             datetime.now(timezone.utc).isoformat()),
        )


def external_cache_clear(kind=None, domain=None):
    """Drop cached lookups. Returns the number of rows removed."""
    clauses = []
    params = []
    if kind:
        clauses.append("kind = ?")
        params.append(kind)
    if domain:
        clauses.append("domain = ?")
        params.append(domain)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with _lock, _connect() as conn:
        return conn.execute(f"DELETE FROM external_cache{where}", params).rowcount


def external_cache_stats():
    """Per-kind counts and newest entry, for the admin view."""
    with _lock, _connect() as conn:
        rows = conn.execute(
            """
            SELECT kind, COUNT(*) AS entries, MAX(created_at) AS newest
            FROM external_cache GROUP BY kind ORDER BY kind
            """
        ).fetchall()
        return [dict(r) for r in rows]


def monitors_using_scan(scan_id):
    """Return monitors that use this scan as their comparison baseline.

    Deleting it clears their last_scan_id through the foreign key, which is
    silent, so the caller needs to know before it happens.
    """
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, name, target FROM monitors WHERE last_scan_id = ?",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def delete_scan(scan_id):
    """Remove a single scan. Returns True if a row was deleted."""
    with _lock, _connect() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


def clear_history():
    """Remove every stored scan."""
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM scans")


def history_stats():
    """Return simple aggregate stats for the dashboard."""
    with _lock, _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        domains = conn.execute(
            "SELECT COUNT(DISTINCT domain) AS c FROM scans"
        ).fetchone()["c"]
        last = conn.execute(
            "SELECT created_at FROM scans ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return {
            "total_scans": total,
            "unique_domains": domains,
            "last_scan": last["created_at"] if last else None,
        }


def _to_json(value):
    return json.dumps(value, default=str)


def _from_json(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _row_to_monitor(row):
    monitor = dict(row)
    monitor["checks"] = _from_json(monitor.get("checks"), ["all"])
    monitor["metadata"] = _from_json(monitor.get("metadata"), {})
    monitor["enabled"] = bool(monitor.get("enabled"))
    return monitor


def create_monitor(
    *,
    name,
    domain,
    target,
    record_type,
    record_value=None,
    source_type="manual",
    source_label=None,
    provider=None,
    schedule_minutes=1440,
    checks=None,
    enabled=True,
    metadata=None,
):
    """Create a new monitor and return its id."""
    now = datetime.now(timezone.utc).isoformat()
    if checks is None:
        checks = ["all"]
    if metadata is None:
        metadata = {}
    next_scan_at = now if enabled else None

    with _lock, _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO monitors (
                name, domain, target, record_type, record_value, source_type,
                source_label, provider, schedule_minutes, checks, enabled,
                metadata, next_scan_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                domain,
                target,
                record_type,
                record_value,
                source_type,
                source_label,
                provider,
                int(schedule_minutes),
                _to_json(checks),
                1 if enabled else 0,
                _to_json(metadata),
                next_scan_at,
                now,
                now,
            ),
        )
        return cur.lastrowid


def list_monitors(enabled=None, due_only=False, limit=500):
    """Return monitors, optionally filtering by enabled state or due scans."""
    clauses = []
    params = []

    if enabled is not None:
        clauses.append("enabled = ?")
        params.append(1 if enabled else 0)

    if due_only:
        now = datetime.now(timezone.utc).isoformat()
        clauses.append("next_scan_at IS NOT NULL AND next_scan_at <= ?")
        params.append(now)

    where = ""
    if clauses:
        where = "WHERE " + " AND ".join(clauses)

    with _lock, _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM monitors
            {where}
            ORDER BY next_scan_at IS NULL, next_scan_at ASC, created_at DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
        return [_row_to_monitor(r) for r in rows]


def get_monitor(monitor_id):
    """Return one monitor by id or None."""
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM monitors WHERE id = ?",
            (monitor_id,),
        ).fetchone()
        return _row_to_monitor(row) if row else None


def update_monitor(monitor_id, **fields):
    """Update a monitor with the provided fields."""
    if not fields:
        return get_monitor(monitor_id)

    allowed = {
        "name",
        "domain",
        "target",
        "record_type",
        "record_value",
        "source_type",
        "source_label",
        "provider",
        "schedule_minutes",
        "checks",
        "enabled",
        "metadata",
        "next_scan_at",
        "last_scan_id",
        "last_scan_at",
        "last_state_hash",
    }
    assignments = []
    params = []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key in {"checks", "metadata"}:
            value = _to_json(value)
        elif key == "enabled":
            value = 1 if value else 0
        assignments.append(f"{key} = ?")
        params.append(value)

    if not assignments:
        return get_monitor(monitor_id)

    assignments.append("updated_at = ?")
    params.append(datetime.now(timezone.utc).isoformat())
    params.append(monitor_id)

    with _lock, _connect() as conn:
        conn.execute(
            f"UPDATE monitors SET {', '.join(assignments)} WHERE id = ?",
            params,
        )
    return get_monitor(monitor_id)


def delete_monitor(monitor_id):
    """Delete a monitor. Returns True when removed."""
    with _lock, _connect() as conn:
        cur = conn.execute("DELETE FROM monitors WHERE id = ?", (monitor_id,))
        return cur.rowcount > 0


def upsert_monitor(
    *,
    domain,
    target,
    record_type,
    defaults,
):
    """Create or update a monitor identified by domain, target and record type."""
    with _lock, _connect() as conn:
        existing = conn.execute(
            """
            SELECT id FROM monitors
            WHERE domain = ? AND target = ? AND record_type = ?
            """,
            (domain, target, record_type),
        ).fetchone()

    if existing:
        return update_monitor(existing["id"], **defaults)

    monitor_id = create_monitor(
        domain=domain,
        target=target,
        record_type=record_type,
        **defaults,
    )
    return get_monitor(monitor_id)


def mark_monitor_scanned(monitor_id, scan_id, schedule_minutes):
    """Update monitor timestamps after a successful scan."""
    now_dt = datetime.now(timezone.utc)
    next_dt = now_dt.timestamp() + (int(schedule_minutes) * 60)
    next_scan_at = datetime.fromtimestamp(next_dt, tz=timezone.utc).isoformat()
    return update_monitor(
        monitor_id,
        last_scan_id=scan_id,
        last_scan_at=now_dt.isoformat(),
        next_scan_at=next_scan_at,
    )


def create_monitor_event(
    monitor_id,
    *,
    scan_id=None,
    event_type,
    severity,
    summary,
    details=None,
):
    """Store a monitor event and return its id."""
    created_at = datetime.now(timezone.utc).isoformat()
    if details is None:
        details = {}
    with _lock, _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO monitor_events (
                monitor_id, scan_id, event_type, severity, summary, details, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                monitor_id,
                scan_id,
                event_type,
                severity,
                summary,
                _to_json(details),
                created_at,
            ),
        )
        return cur.lastrowid


def update_monitor_event(event_id, **fields):
    """Update notification metadata for a monitor event."""
    allowed = {"servicenow_sys_id", "servicenow_number", "notified_at", "details"}
    assignments = []
    params = []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "details":
            value = _to_json(value)
        assignments.append(f"{key} = ?")
        params.append(value)
    if not assignments:
        return False
    params.append(event_id)
    with _lock, _connect() as conn:
        cur = conn.execute(
            f"UPDATE monitor_events SET {', '.join(assignments)} WHERE id = ?",
            params,
        )
        return cur.rowcount > 0


def list_monitor_events(monitor_id=None, limit=100):
    """List recent monitor events, optionally for a single monitor."""
    with _lock, _connect() as conn:
        if monitor_id is None:
            rows = conn.execute(
                """
                SELECT e.*, m.name AS monitor_name, m.target AS monitor_target
                FROM monitor_events e
                JOIN monitors m ON m.id = e.monitor_id
                ORDER BY e.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT e.*, m.name AS monitor_name, m.target AS monitor_target
                FROM monitor_events e
                JOIN monitors m ON m.id = e.monitor_id
                WHERE e.monitor_id = ?
                ORDER BY e.created_at DESC
                LIMIT ?
                """,
                (monitor_id, limit),
            ).fetchall()
    events = []
    for row in rows:
        item = dict(row)
        item["details"] = _from_json(item.get("details"), {})
        events.append(item)
    return events


def monitor_stats():
    """Return aggregate monitor statistics for the dashboard."""
    with _lock, _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM monitors").fetchone()["c"]
        enabled = conn.execute(
            "SELECT COUNT(*) AS c FROM monitors WHERE enabled = 1"
        ).fetchone()["c"]
        due = conn.execute(
            """
            SELECT COUNT(*) AS c FROM monitors
            WHERE enabled = 1 AND next_scan_at IS NOT NULL AND next_scan_at <= ?
            """,
            (datetime.now(timezone.utc).isoformat(),),
        ).fetchone()["c"]
        by_source = conn.execute(
            """
            SELECT source_type, COUNT(*) AS c
            FROM monitors
            GROUP BY source_type
            ORDER BY c DESC, source_type ASC
            """
        ).fetchall()
        events = conn.execute("SELECT COUNT(*) AS c FROM monitor_events").fetchone()["c"]
        return {
            "total_monitors": total,
            "enabled_monitors": enabled,
            "due_monitors": due,
            "event_count": events,
            "sources": [
                {"source_type": row["source_type"], "count": row["c"]}
                for row in by_source
            ],
        }

def reporting_overview(days=30, domain=None):
    """Compact KPIs for the trends dashboard.

    When `domain` is given every KPI is scoped to that domain. Previously the
    filter only narrowed the scan count while avg issues, scores, blacklist
    hits and incident counts stayed global, so a per-domain report showed
    fleet-wide numbers under a single domain's heading.
    """
    from datetime import timedelta

    days = max(1, min(int(days), 365))
    start_day = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date().isoformat()

    metric_where = "day >= ?"
    metric_params = [start_day]
    if domain:
        metric_where += " AND domain = ?"
        metric_params.append(domain)

    # monitor_events has no domain column; scope it through its monitor.
    event_where = "created_at >= ?"
    event_params = [start_day]
    if domain:
        event_where += " AND monitor_id IN (SELECT id FROM monitors WHERE domain = ?)"
        event_params.append(domain)

    # Quality figures describe the CURRENT state, so they come from the most
    # recent scan per domain. Summing every scan in the window meant a problem
    # that had since been fixed kept being counted — a rescanned domain still
    # showed the old blacklist hit until it aged out of the period.
    latest_per_domain = f"""
        JOIN (
            SELECT domain, MAX(scan_id) AS scan_id
            FROM scan_metrics
            WHERE {metric_where}
            GROUP BY domain
        ) latest ON latest.domain = sm.domain AND latest.scan_id = sm.scan_id
    """

    with _lock, _connect() as conn:
        # Activity counts stay over the whole window: "26 scans" is how much
        # scanning happened, not how many domains are currently healthy.
        activity = conn.execute(
            f"""
            SELECT COUNT(*) AS scans, COUNT(DISTINCT domain) AS domains
            FROM scan_metrics
            WHERE {metric_where}
            """,
            metric_params,
        ).fetchone()
        totals = conn.execute(
            f"""
            SELECT
                AVG(sm.issues_count) AS avg_issues,
                AVG(sm.header_score) AS avg_header_score,
                AVG(sm.grade_score) AS avg_grade_score,
                SUM(sm.blacklist_listed) AS blacklist_hits
            FROM scan_metrics sm
            {latest_per_domain}
            """,
            metric_params,
        ).fetchone()
        severity = conn.execute(
            f"""
            SELECT severity, COUNT(*) AS c
            FROM monitor_events
            WHERE {event_where}
            GROUP BY severity
            """,
            event_params,
        ).fetchall()
        top_noisy = conn.execute(
            f"""
            SELECT domain, COUNT(*) AS scans, AVG(issues_count) AS avg_issues
            FROM scan_metrics
            WHERE {metric_where}
            GROUP BY domain
            ORDER BY avg_issues DESC, scans DESC
            LIMIT 8
            """,
            metric_params,
        ).fetchall()
        sn_linked = conn.execute(
            f"""
            SELECT COUNT(*) AS c FROM monitor_events
            WHERE servicenow_sys_id IS NOT NULL AND {event_where}
            """,
            event_params,
        ).fetchone()["c"]

    severity_map = {row["severity"]: row["c"] for row in severity}
    return {
        "days": days,
        "domain": domain,
        "scans": activity["scans"] or 0,
        "domains": activity["domains"] or 0,
        "avg_issues": round(totals["avg_issues"] or 0, 2),
        "avg_header_score": round(totals["avg_header_score"] or 0, 1),
        "avg_grade_score": round(totals["avg_grade_score"] or 0, 1),
        "blacklist_hits": totals["blacklist_hits"] or 0,
        "servicenow_incidents": sn_linked,
        "events_by_severity": severity_map,
        "top_domains": [dict(row) for row in top_noisy],
    }


def reporting_domains(days=30, domain=None):
    """Latest scan per domain, for the KPI drill-downs.

    One row per domain describing where it stands right now, plus how many
    times it was scanned in the window.
    """
    from datetime import timedelta

    days = max(1, min(int(days), 365))
    start_day = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date().isoformat()

    where = "day >= ?"
    params = [start_day]
    if domain:
        where += " AND domain = ?"
        params.append(domain)

    with _lock, _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                sm.domain,
                sm.scan_id,
                sm.created_at,
                sm.grade,
                sm.grade_score,
                sm.header_score,
                sm.issues_count,
                sm.blacklist_listed,
                sm.dnssec_signed,
                sm.https_redirect,
                counts.scans
            FROM scan_metrics sm
            JOIN (
                SELECT domain, MAX(scan_id) AS scan_id, COUNT(*) AS scans
                FROM scan_metrics
                WHERE {where}
                GROUP BY domain
            ) counts ON counts.domain = sm.domain AND counts.scan_id = sm.scan_id
            ORDER BY sm.issues_count DESC, sm.domain ASC
            """,
            params,
        ).fetchall()

    return {
        "days": days,
        "domain": domain,
        "domains": [dict(r) for r in rows],
    }


def reporting_trends(days=30, domain=None):
    """Daily trend series optimized for dashboards (no JSON blob scans)."""
    from datetime import timedelta

    days = max(1, min(int(days), 365))
    start = datetime.now(timezone.utc) - timedelta(days=days - 1)
    start_day = start.date().isoformat()

    clauses = ["day >= ?"]
    params = [start_day]
    if domain:
        clauses.append("domain = ?")
        params.append(domain)
    where = " AND ".join(clauses)

    with _lock, _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                day,
                COUNT(*) AS scans,
                AVG(issues_count) AS avg_issues,
                AVG(header_score) AS avg_header_score,
                AVG(grade_score) AS avg_grade_score,
                SUM(blacklist_listed) AS blacklist_hits,
                SUM(CASE WHEN dnssec_signed = 1 THEN 1 ELSE 0 END) AS dnssec_ok,
                SUM(CASE WHEN https_redirect = 1 THEN 1 ELSE 0 END) AS https_ok
            FROM scan_metrics
            WHERE {where}
            GROUP BY day
            ORDER BY day ASC
            """,
            params,
        ).fetchall()

        # Events must honour the same domain filter as the metrics above.
        # They previously did not, so filtering the dashboard to one domain
        # still charted every domain's events next to that domain's metrics.
        if domain:
            event_rows = conn.execute(
                """
                SELECT substr(e.created_at, 1, 10) AS day, e.severity, COUNT(*) AS c
                FROM monitor_events e
                JOIN monitors m ON m.id = e.monitor_id
                WHERE e.created_at >= ? AND m.domain = ?
                GROUP BY day, e.severity
                ORDER BY day ASC
                """,
                (start_day, domain),
            ).fetchall()
        else:
            event_rows = conn.execute(
                """
                SELECT substr(created_at, 1, 10) AS day, severity, COUNT(*) AS c
                FROM monitor_events
                WHERE created_at >= ?
                GROUP BY day, severity
                ORDER BY day ASC
                """,
                (start_day,),
            ).fetchall()

    by_day = {row["day"]: dict(row) for row in rows}
    series = []
    for offset in range(days):
        day = (start + timedelta(days=offset)).date().isoformat()
        item = by_day.get(day, {
            "day": day,
            "scans": 0,
            "avg_issues": 0,
            "avg_header_score": None,
            "avg_grade_score": None,
            "blacklist_hits": 0,
            "dnssec_ok": 0,
            "https_ok": 0,
        })
        series.append({
            "day": day,
            "scans": item["scans"] or 0,
            "avg_issues": round(item["avg_issues"] or 0, 2),
            "avg_header_score": None if item["avg_header_score"] is None else round(item["avg_header_score"], 1),
            "avg_grade_score": None if item["avg_grade_score"] is None else round(item["avg_grade_score"], 1),
            "blacklist_hits": item["blacklist_hits"] or 0,
            "dnssec_ok": item["dnssec_ok"] or 0,
            "https_ok": item["https_ok"] or 0,
        })

    events_series = {}
    for row in event_rows:
        day = row["day"]
        events_series.setdefault(day, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        sev = row["severity"] if row["severity"] in events_series[day] else "info"
        events_series[day][sev] = row["c"]

    return {"days": days, "domain": domain, "series": series, "events": events_series}


def _row_to_user(row, include_secrets=False):
    if not row:
        return None
    user = dict(row)
    user["enabled"] = bool(user.get("enabled"))
    user["mfa_enabled"] = bool(user.get("mfa_enabled"))
    user["mfa_backup_codes"] = _from_json(user.get("mfa_backup_codes"), [])
    user["scim_profile"] = _from_json(user.get("scim_profile"), {})
    user["prefs"] = _from_json(user.get("prefs"), {})
    if not include_secrets:
        user.pop("password_hash", None)
        user.pop("mfa_secret", None)
        user.pop("mfa_backup_codes", None)
    return user


PROFILE_FIELDS = (
    "department",
    "company_name",
    "job_title",
    "office_location",
    "employee_number",
    "cost_center",
    "division",
    "organization",
    "manager_external_id",
    "manager_display_name",
    "phone_number",
    "mobile_number",
    "preferred_language",
    "street_address",
    "city",
    "state",
    "postal_code",
    "country",
    "scim_profile",
)


def create_user(
    *,
    email,
    password_hash=None,
    name=None,
    role="user",
    enabled=True,
    provider="local",
    external_id=None,
    user_name=None,
    **profile,
):
    now = datetime.now(timezone.utc).isoformat()
    email = email.strip().lower()
    provider = (provider or "local").strip().lower() or "local"
    external = (external_id or "").strip() or None
    uname = (user_name or email).strip()
    profile_vals = {}
    for key in PROFILE_FIELDS:
        if key not in profile:
            continue
        value = profile[key]
        if key == "scim_profile":
            profile_vals[key] = _to_json(value if isinstance(value, dict) else {})
        else:
            profile_vals[key] = (str(value).strip() if value is not None and str(value).strip() else None)

    columns = [
        "email", "name", "password_hash", "role", "enabled", "password_changed_at",
        "provider", "external_id", "user_name", "created_at", "updated_at",
    ]
    values = [
        email,
        name or email.split("@")[0],
        password_hash,
        role,
        1 if enabled else 0,
        now if password_hash else None,
        provider,
        external,
        uname,
        now,
        now,
    ]
    for key, value in profile_vals.items():
        columns.append(key)
        values.append(value)

    placeholders = ", ".join("?" for _ in columns)
    with _lock, _connect() as conn:
        cur = conn.execute(
            f"INSERT INTO users ({', '.join(columns)}) VALUES ({placeholders})",
            values,
        )
        return cur.lastrowid


def get_user_by_email(email, include_secrets=False):
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email.strip().lower(),),
        ).fetchone()
        return _row_to_user(row, include_secrets=include_secrets)


def get_user_by_external_id(external_id, include_secrets=False):
    external_id = (external_id or "").strip()
    if not external_id:
        return None
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE external_id = ?",
            (external_id,),
        ).fetchone()
        return _row_to_user(row, include_secrets=include_secrets)


def get_user_by_user_name(user_name, include_secrets=False):
    user_name = (user_name or "").strip()
    if not user_name:
        return None
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE lower(user_name) = lower(?)",
            (user_name,),
        ).fetchone()
        return _row_to_user(row, include_secrets=include_secrets)


def get_user(user_id, include_secrets=False):
    with _lock, _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_to_user(row, include_secrets=include_secrets)


def list_users():
    with _lock, _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, email, name, role, enabled, mfa_enabled, last_login_at,
                   failed_logins, locked_until, created_at, updated_at, password_changed_at,
                   provider, external_id, user_name,
                   department, company_name, job_title, office_location,
                   employee_number, cost_center, division, organization,
                   manager_external_id, manager_display_name,
                   phone_number, mobile_number, preferred_language,
                   street_address, city, state, postal_code, country, scim_profile
            FROM users
            ORDER BY created_at ASC
            """
        ).fetchall()
        return [_row_to_user(r, include_secrets=False) for r in rows]


def find_users_for_scim(*, user_name=None, external_id=None, start_index=1, count=100):
    """SCIM list/filter helper. start_index is 1-based."""
    start_index = max(1, int(start_index or 1))
    count = max(1, min(200, int(count or 100)))
    clauses = []
    params = []
    if user_name:
        clauses.append("lower(user_name) = lower(?)")
        params.append(user_name.strip())
    if external_id:
        clauses.append("external_id = ?")
        params.append(external_id.strip())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _lock, _connect() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM users {where}",
            params,
        ).fetchone()["c"]
        rows = conn.execute(
            f"""
            SELECT * FROM users {where}
            ORDER BY id ASC
            LIMIT ? OFFSET ?
            """,
            [*params, count, start_index - 1],
        ).fetchall()
        return {
            "total": total,
            "start_index": start_index,
            "items": [_row_to_user(r, include_secrets=False) for r in rows],
        }


def update_user(user_id, **fields):
    allowed = {
        "email", "name", "password_hash", "role", "enabled", "mfa_enabled",
        "mfa_secret", "mfa_backup_codes", "password_changed_at", "failed_logins",
        "locked_until", "last_login_at", "provider", "external_id", "user_name",
        "prefs",
        *PROFILE_FIELDS,
    }
    assignments = []
    params = []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "mfa_backup_codes":
            value = _to_json(value)
        elif key == "prefs":
            value = _to_json(value if isinstance(value, dict) else {})
        elif key == "scim_profile":
            value = _to_json(value if isinstance(value, dict) else {})
        elif key in {"enabled", "mfa_enabled"}:
            value = 1 if value else 0
        elif key == "external_id":
            value = (value or "").strip() or None
        elif key == "email" and value:
            value = str(value).strip().lower()
        elif key == "provider" and value:
            value = str(value).strip().lower()
        elif key in PROFILE_FIELDS and key != "scim_profile":
            value = (str(value).strip() if value is not None and str(value).strip() else None)
        assignments.append(f"{key} = ?")
        params.append(value)
    if not assignments:
        return get_user(user_id)
    assignments.append("updated_at = ?")
    params.append(datetime.now(timezone.utc).isoformat())
    params.append(user_id)
    with _lock, _connect() as conn:
        conn.execute(
            f"UPDATE users SET {', '.join(assignments)} WHERE id = ?",
            params,
        )
    return get_user(user_id, include_secrets=True)


def delete_user(user_id):
    with _lock, _connect() as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cur.rowcount > 0


def count_users():
    with _lock, _connect() as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]


def get_all_settings():
    """Return all persisted settings sections as {section: dict}."""
    with _lock, _connect() as conn:
        rows = conn.execute("SELECT section, value FROM app_settings").fetchall()
    result = {}
    for row in rows:
        result[row["section"]] = _from_json(row["value"], {})
    return result


def get_setting_section(section):
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT value FROM app_settings WHERE section = ?",
            (section,),
        ).fetchone()
    if not row:
        return None
    return _from_json(row["value"], {})


def get_or_create_app_secret():
    """Return a persistent, cryptographically random app secret.

    Generated once on first use and stored in app_settings so Flask sessions
    survive restarts without the secret being derivable from public config.
    """
    import secrets as _secrets
    existing = get_setting_section("_app_secret")
    if existing and isinstance(existing.get("value"), str) and len(existing["value"]) >= 32:
        return existing["value"]
    value = _secrets.token_hex(32)
    set_setting_section("_app_secret", {"value": value})
    return value


def set_setting_section(section, value, user_id=None):
    now = datetime.now(timezone.utc).isoformat()
    payload = _to_json(value if isinstance(value, dict) else {})
    with _lock, _connect() as conn:
        conn.execute(
            """
            INSERT INTO app_settings (section, value, updated_at, updated_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(section) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            """,
            (section, payload, now, user_id),
        )
    return get_setting_section(section)


# ---------------------------------------------------------------------------
# Rapid7 / InsightVM vulnerability imports
# ---------------------------------------------------------------------------

def save_vuln_import(
    *,
    filename,
    source_format,
    findings,
    summary=None,
    warnings=None,
    header_map=None,
    row_count=0,
    imported_by=None,
):
    now = datetime.now(timezone.utc).isoformat()
    with _lock, _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO vuln_imports (
                filename, source_format, imported_at, row_count, finding_count,
                summary, warnings, header_map, imported_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                filename,
                source_format,
                now,
                int(row_count or 0),
                len(findings or []),
                _to_json(summary or {}),
                _to_json(warnings or []),
                _to_json(header_map or {}),
                imported_by,
            ),
        )
        import_id = cur.lastrowid
        for f in findings or []:
            conn.execute(
                """
                INSERT INTO vuln_findings (
                    import_id, asset_ip, hostname, domain, title, severity, cvss,
                    cves, solution, description, port, protocol, vuln_id,
                    result_code, exploit, raw
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    import_id,
                    f.get("asset_ip"),
                    f.get("hostname"),
                    f.get("domain"),
                    f.get("title") or "Untitled",
                    f.get("severity") or "info",
                    f.get("cvss"),
                    _to_json(f.get("cves") or []),
                    f.get("solution"),
                    f.get("description"),
                    f.get("port"),
                    f.get("protocol"),
                    f.get("vuln_id"),
                    f.get("result_code"),
                    f.get("exploit"),
                    _to_json(f.get("raw") or {}),
                ),
            )
    return get_vuln_import(import_id)


def _finding_row_to_dict(row):
    if not row:
        return None
    d = dict(row)
    d["cves"] = _from_json(d.get("cves"), [])
    d["raw"] = _from_json(d.get("raw"), {})
    return d


def get_vuln_import(import_id):
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM vuln_imports WHERE id = ?",
            (import_id,),
        ).fetchone()
    if not row:
        return None
    data = dict(row)
    data["summary"] = _from_json(data.get("summary"), {})
    data["warnings"] = _from_json(data.get("warnings"), [])
    data["header_map"] = _from_json(data.get("header_map"), {})
    return data


def list_vuln_imports(limit=50):
    with _lock, _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, filename, source_format, imported_at, row_count,
                   finding_count, summary, warnings
            FROM vuln_imports
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["summary"] = _from_json(item.get("summary"), {})
        item["warnings"] = _from_json(item.get("warnings"), [])
        out.append(item)
    return out


def delete_vuln_import(import_id):
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM vuln_findings WHERE import_id = ?", (import_id,))
        cur = conn.execute("DELETE FROM vuln_imports WHERE id = ?", (import_id,))
        return cur.rowcount > 0


def get_vuln_finding(finding_id):
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM vuln_findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
    return _finding_row_to_dict(row)


def list_vuln_findings(
    *,
    domain=None,
    import_id=None,
    min_severity=None,
    limit=500,
    offset=0,
):
    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    clauses = []
    params = []
    if import_id is not None:
        clauses.append("import_id = ?")
        params.append(import_id)
    if domain:
        target = domain.strip().lower().rstrip(".")
        clauses.append("(domain = ? OR domain LIKE ? OR lower(hostname) = ? OR lower(hostname) LIKE ?)")
        params.extend([target, "%." + target, target, "%." + target])

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM vuln_findings{where} ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([int(limit), int(offset)])

    with _lock, _connect() as conn:
        rows = conn.execute(sql, params).fetchall()

    findings = [_finding_row_to_dict(r) for r in rows]
    if min_severity and min_severity in severity_rank:
        threshold = severity_rank[min_severity]
        findings = [
            f for f in findings
            if severity_rank.get(f.get("severity"), 99) <= threshold
        ]
    return findings


def vuln_findings_for_domain(domain, *, min_severity=None, limit=500):
    return list_vuln_findings(domain=domain, min_severity=min_severity, limit=limit)


def vuln_import_stats():
    with _lock, _connect() as conn:
        imports = conn.execute("SELECT COUNT(*) AS c FROM vuln_imports").fetchone()["c"]
        findings = conn.execute("SELECT COUNT(*) AS c FROM vuln_findings").fetchone()["c"]
        by_sev = {
            row["severity"]: row["c"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS c FROM vuln_findings GROUP BY severity"
            ).fetchall()
        }
    return {"imports": imports, "findings": findings, "by_severity": by_sev}
