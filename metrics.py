"""Prometheus metrics at /metrics.

/health says the process is up and nothing else. Whether the scheduler is
keeping up, how long its runs take, whether scans are failing and whether
alerts are being delivered could only be read off the UI by a person. This
exposes them in the text format every monitoring stack scrapes.

Values that live in the database are read at scrape time (gauges); events
that only happen in this process are counted here (counters, reset on
restart as Prometheus expects). Nothing here names a domain: the metrics end
up in systems with wider access than DomainLens itself.
"""

from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()
_counters = defaultdict(float)

_HELP = {
    "domainlens_scans_started_total": ("counter", "Scans started through the API or UI"),
    "domainlens_notifications_total": ("counter", "Alert deliveries by channel and result"),
}


def inc(name, amount=1.0, **labels):
    key = (name, tuple(sorted(labels.items())))
    with _lock:
        _counters[key] += amount


def _fmt_labels(labels):
    if not labels:
        return ""
    parts = []
    for key, value in labels:
        escaped = str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
        parts.append(f'{key}="{escaped}"')
    return "{" + ",".join(parts) + "}"


def _num(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def render(*, db, scheduler_state, running_jobs, version):
    lines = []

    def metric(name, kind, help_text, samples):
        """samples: list of (labels tuple, value). None values are left out
        rather than reported as 0 -- 'no run yet' is not 'a run of 0 s'."""
        samples = [(labels, v) for labels, v in samples if v is not None]
        if not samples:
            return
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            lines.append(f"{name}{_fmt_labels(labels)} {value:g}")

    metric("domainlens_build_info", "gauge", "Version of this instance",
           [((("version", version),), 1)])

    stats = db.monitor_stats()
    metric("domainlens_monitors", "gauge", "Monitors by state", [
        ((("state", "total"),), stats.get("total_monitors")),
        ((("state", "enabled"),), stats.get("enabled_monitors")),
        ((("state", "due"),), stats.get("due_monitors")),
    ])
    history = db.history_stats()
    metric("domainlens_scans_stored", "gauge", "Scans kept in history",
           [((), history.get("total_scans"))])
    metric("domainlens_domains_stored", "gauge", "Distinct domains in history",
           [((), history.get("unique_domains"))])
    metric("domainlens_scan_jobs_running", "gauge", "Background scans running now",
           [((), running_jobs)])

    with db._connect() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM monitor_events "
            "WHERE created_at >= ? GROUP BY severity", (_now_iso(days_ago=1),)).fetchall()
        events = {row["severity"]: row["c"] for row in rows}
        verified = conn.execute(
            "SELECT COUNT(*) FROM verified_domains WHERE status = 'verified'").fetchone()[0]
        tokens = conn.execute(
            "SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL "
            "AND expires_at > ?", (_now_iso(),)).fetchone()[0]
    metric("domainlens_monitor_events_24h", "gauge", "Monitor events in the last 24 hours",
           [((("severity", sev),), events.get(sev, 0))
            for sev in ("critical", "high", "medium", "low", "info")])
    metric("domainlens_verified_domains", "gauge", "Domains verified for active tests",
           [((), verified)])
    metric("domainlens_api_tokens_active", "gauge", "Unexpired, unrevoked API tokens",
           [((), tokens)])

    state = scheduler_state or {}
    duration = _num(state.get("last_run_duration_ms"))
    metric("domainlens_scheduler_runs_total", "counter", "Scheduler runs since start",
           [((), state.get("total_runs"))])
    metric("domainlens_scheduler_last_run_duration_seconds", "gauge", "Duration of the last scheduler run",
           [((), duration / 1000 if duration is not None else None)])
    metric("domainlens_scheduler_last_run_processed", "gauge", "Monitors scanned in the last run",
           [((), state.get("last_run_processed"))])
    metric("domainlens_scheduler_last_run_errors", "gauge", "Monitor scans that failed in the last run",
           [((), state.get("last_run_errors"))])
    metric("domainlens_scheduler_last_run_timestamp_seconds", "gauge", "Unix time of the last run",
           [((), _epoch(state.get("last_run_at")))])

    with _lock:
        snapshot = dict(_counters)
    by_name = defaultdict(list)
    for (name, labels), value in snapshot.items():
        by_name[name].append((labels, value))
    for name, samples in sorted(by_name.items()):
        kind, help_text = _HELP.get(name, ("counter", name))
        metric(name, kind, help_text, sorted(samples))

    return "\n".join(lines) + "\n"


def _now_iso(days_ago=0):
    # Timestamps are stored as ISO strings with a "T"; SQLite's datetime()
    # uses a space, and comparing the two as text is off by up to a day.
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _epoch(iso):
    if not iso:
        return None
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(iso)).timestamp()
    except ValueError:
        return None
