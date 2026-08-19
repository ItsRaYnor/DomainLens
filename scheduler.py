"""
Background monitor scheduler with configurable concurrency and backoff.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
from datetime import datetime, timedelta, timezone

import config as domainlens_config

log = logging.getLogger("domainlens.scheduler")

_state_lock = threading.Lock()
_state = {
    "started_at": None,
    "last_run_at": None,
    "last_run_duration_ms": None,
    "last_run_processed": 0,
    "last_run_errors": 0,
    "last_run_skipped_backoff": 0,
    "last_error": None,
    "total_runs": 0,
    "last_digest_at": None,
}


def state_snapshot() -> dict:
    with _state_lock:
        return dict(_state)


def _update_state(**kwargs):
    with _state_lock:
        _state.update(kwargs)


def _scheduler_meta(monitor: dict) -> dict:
    meta = monitor.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}
    sched = meta.get("scheduler")
    if not isinstance(sched, dict):
        sched = {}
    return meta, sched


def _in_backoff(monitor: dict, settings: dict) -> bool:
    _, sched = _scheduler_meta(monitor)
    until = sched.get("backoff_until")
    if not until:
        return False
    try:
        return datetime.fromisoformat(until) > datetime.now(timezone.utc)
    except ValueError:
        return False


def _record_success(db, monitor_id: int, metadata: dict):
    sched = metadata.get("scheduler") or {}
    sched["consecutive_failures"] = 0
    sched.pop("backoff_until", None)
    metadata["scheduler"] = sched
    db.update_monitor(monitor_id, metadata=metadata)


def _record_failure(db, monitor: dict, settings: dict, error: str):
    meta, sched = _scheduler_meta(monitor)
    failures = int(sched.get("consecutive_failures", 0)) + 1
    sched["consecutive_failures"] = failures
    sched["last_error"] = error
    sched["last_failed_at"] = datetime.now(timezone.utc).isoformat()
    max_failures = int(settings.get("max_consecutive_failures", 8))
    backoff_minutes = int(settings.get("failure_backoff_minutes", 15))
    if failures >= max_failures:
        until = datetime.now(timezone.utc) + timedelta(minutes=backoff_minutes)
        sched["backoff_until"] = until.isoformat()
        log.warning(
            "Monitor %s (%s) backing off until %s after %s failures",
            monitor.get("id"),
            monitor.get("target"),
            sched["backoff_until"],
            failures,
        )
    meta["scheduler"] = sched
    db.update_monitor(monitor["id"], metadata=meta)


def process_due_monitors(
    *,
    db,
    scan_monitor_fn,
    notify_fn,
    safe_error_fn,
    run_lock: threading.Lock,
    limit: int | None = None,
) -> dict:
    """Run all due monitors once with optional parallelism."""
    if not run_lock.acquire(blocking=False):
        return {"processed": 0, "results": [], "running": True}

    started = datetime.now(timezone.utc)
    settings = domainlens_config.load_settings().scheduler()
    batch_limit = limit or int(settings.get("max_monitors_per_run", 200))
    concurrency = int(settings.get("concurrency", 2))

    try:
        due_monitors = db.list_monitors(enabled=True, due_only=True, limit=batch_limit)
        runnable = []
        skipped_backoff = 0
        for monitor in due_monitors:
            if _in_backoff(monitor, settings):
                skipped_backoff += 1
                continue
            runnable.append(monitor)

        results = []
        errors = 0

        def _run_one(monitor):
            try:
                outcome = scan_monitor_fn(monitor)
                meta = monitor.get("metadata") or {}
                if not isinstance(meta, dict):
                    meta = {}
                _record_success(db, monitor["id"], meta)
                return {
                    "monitor_id": monitor["id"],
                    "scan_id": outcome["scan_id"],
                    "target": monitor["target"],
                    "status": "ok",
                    "event_type": outcome["event"]["event_type"],
                }
            except Exception as exc:
                error = safe_error_fn(exc)
                _record_failure(db, monitor, settings, error)
                event_id = db.create_monitor_event(
                    monitor["id"],
                    event_type="scan_failed",
                    severity="high",
                    summary=f"Scheduled scan failed for {monitor['target']}",
                    details={"error": error, "target": monitor["target"]},
                )
                notify_fn(
                    event_id,
                    {
                        "event_type": "scan_failed",
                        "severity": "high",
                        "summary": f"Scheduled scan failed for {monitor['target']}",
                        "details": {"error": error, "target": monitor["target"]},
                    },
                    monitor,
                )
                return {
                    "monitor_id": monitor["id"],
                    "target": monitor["target"],
                    "status": "error",
                    "error": error,
                }

        if concurrency <= 1:
            for monitor in runnable:
                item = _run_one(monitor)
                results.append(item)
                if item.get("status") == "error":
                    errors += 1
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [pool.submit(_run_one, monitor) for monitor in runnable]
                for future in concurrent.futures.as_completed(futures):
                    item = future.result()
                    results.append(item)
                    if item.get("status") == "error":
                        errors += 1

        duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        with _state_lock:
            total_runs = _state.get("total_runs", 0) + 1
        _update_state(
            last_run_at=started.isoformat(),
            last_run_duration_ms=duration_ms,
            last_run_processed=len(results),
            last_run_errors=errors,
            last_run_skipped_backoff=skipped_backoff,
            last_error=None if errors == 0 else f"{errors} monitor scan(s) failed",
            total_runs=total_runs,
        )
        return {
            "processed": len(results),
            "results": results,
            "running": False,
            "skipped_backoff": skipped_backoff,
            "duration_ms": duration_ms,
        }
    except Exception as exc:
        _update_state(last_error=str(exc))
        raise
    finally:
        run_lock.release()


def maybe_run_reporting_digest(db) -> dict | None:
    """Optional periodic summary for dashboards / ops."""
    reporting = domainlens_config.load_settings().reporting()
    if not reporting.get("digest_enabled"):
        return None

    now = datetime.now(timezone.utc)
    with _state_lock:
        last = _state.get("last_digest_at")
    if last:
        try:
            last_dt = datetime.fromisoformat(last)
            hours = int(reporting.get("digest_interval_hours", 24))
            if now - last_dt < timedelta(hours=hours):
                return None
        except ValueError:
            pass

    overview = db.reporting_overview(days=7)
    stats = db.monitor_stats()
    digest = {
        "generated_at": now.isoformat(),
        "window_days": 7,
        "overview": overview,
        "monitors": stats,
        "scheduler": state_snapshot(),
    }
    _update_state(last_digest_at=now.isoformat())
    return digest


def scheduler_loop(stop_event: threading.Event, run_due_fn, digest_fn):
    """Background loop — reloads scheduler settings every iteration."""
    _update_state(started_at=datetime.now(timezone.utc).isoformat())
    log.info("Monitor scheduler thread started")
    while not stop_event.is_set():
        settings = domainlens_config.load_settings().scheduler()
        try:
            if settings.get("enabled"):
                run_due_fn()
                digest_fn()
        except Exception as exc:
            log.exception("Monitor scheduler failed: %s", exc)
            _update_state(last_error=str(exc))
        stop_event.wait(int(settings.get("poll_seconds", 60)))
