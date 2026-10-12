"""
Background monitor scheduler with configurable concurrency and backoff.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
from datetime import datetime, timedelta, timezone

import config as domainlens_config
import dns_health

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
    "dns_down_since": None,
    "dns_error": None,
    "last_run_postponed_dns": 0,
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


def next_run(schedule_minutes, *, scan_time=None, scan_tz=None, now=None, first=False):
    """When a monitor runs next: `schedule_minutes` from now, or -- with a
    time of day -- on that time, in the zone it was chosen in.

    Daily and longer: the first `scan_time` at least a day less than the
    interval ahead, so a daily scan at 03:00 stays at 03:00 even after a run
    that came late or was started by hand. Shorter: the slots `scan_time`,
    `scan_time` + interval, ... of each day. `first` is the run right after
    the time was chosen: the next slot from now.
    """
    now = now or datetime.now(timezone.utc)
    minutes = max(int(schedule_minutes or 1440), 1)
    zone = _zone(scan_tz)
    hour_minute = _parse_time(scan_time)
    if not hour_minute or zone is None:
        return now + timedelta(minutes=minutes)
    local = now.astimezone(zone)
    anchor = datetime(local.year, local.month, local.day, *hour_minute, tzinfo=zone)
    if minutes < 1440:
        step = timedelta(minutes=minutes)
        slots = (now - anchor) // step + 1
        return (anchor + slots * step).astimezone(timezone.utc)
    earliest = now + timedelta(minutes=1 if first else max(minutes - 1440, 0) + 1)
    day = earliest.astimezone(zone).date()
    candidate = datetime(day.year, day.month, day.day, *hour_minute, tzinfo=zone)
    if candidate < earliest:
        day = day + timedelta(days=1)
        candidate = datetime(day.year, day.month, day.day, *hour_minute, tzinfo=zone)
    return candidate.astimezone(timezone.utc)


def _parse_time(value):
    """(hour, minute) for "HH:MM", else None."""
    try:
        hour, minute = (int(part) for part in str(value).split(":"))
    except (TypeError, ValueError):
        return None
    return (hour, minute) if 0 <= hour < 24 and 0 <= minute < 60 else None


def _zone(name):
    if not name:
        return None
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(str(name))
    except Exception:
        return None


def valid_time(value):
    return _parse_time(value) is not None and len(str(value)) == 5


def valid_zone(name):
    return _zone(name) is not None


def plan_slot(start, spacing, index):
    """The time of the index-th scan of a plan: start, start + spacing, ...
    round the clock."""
    hour, minute = _parse_time(start)
    total = (hour * 60 + minute + index * int(spacing)) % 1440
    return f"{total // 60:02d}:{total % 60:02d}"


def free_plan_slot(start, spacing, taken):
    """The first time of the plan no monitor has yet, so a monitor added
    later does not land on top of one already planned."""
    taken = set(taken)
    for index in range(max(1440 // max(int(spacing), 1), 1)):
        slot = plan_slot(start, spacing, index)
        if slot not in taken:
            return slot
    return plan_slot(start, spacing, len(taken))


def _postpone_for_dns(db, monitor: dict, settings: dict, exc, notify_fn) -> dict:
    """A scan DNS could not serve is put off, not run and not failed.

    The scanner's own resolver down: the monitor stays due and runs as soon
    as DNS answers again. Only this domain's name servers silent: it is
    tried again in a quarter of an hour; after an hour of silence one event
    says so, and the monitor waits for its next regular run.
    """
    result = {"monitor_id": monitor["id"], "target": monitor["target"],
              "status": "postponed", "reason": exc.state}
    if exc.state == dns_health.RESOLVER_DOWN:
        _note_dns_down(exc.error)
        return result
    meta, sched = _scheduler_meta(monitor)
    retries = int(sched.get("dns_retries", 0)) + 1
    retry_minutes = int(settings.get("dns_retry_minutes", 15))
    max_retries = int(settings.get("dns_max_retries", 4))
    now = datetime.now(timezone.utc)
    if retries < max_retries:
        sched["dns_retries"] = retries
        sched.setdefault("dns_unanswered_since", now.isoformat())
        meta["scheduler"] = sched
        db.update_monitor(monitor["id"], metadata=meta,
                          next_scan_at=(now + timedelta(minutes=retry_minutes)).isoformat())
        return result
    since = sched.pop("dns_unanswered_since", None) or now.isoformat()
    sched.pop("dns_retries", None)
    meta["scheduler"] = sched
    fresh = db.get_monitor(monitor["id"]) or monitor
    following = next_run(fresh.get("schedule_minutes") or 1440, scan_time=fresh.get("scan_time"),
                         scan_tz=fresh.get("scan_tz"), now=now)
    db.update_monitor(monitor["id"], metadata=meta, next_scan_at=following.isoformat())
    event = {
        "event_type": "dns_unanswered",
        "severity": "medium",
        "summary": f"No answer from the name servers of {monitor['target']}: not scanned, nothing judged",
        "details": {"target": monitor["target"], "error": exc.error, "since": since,
                    "attempts": retries, "next_scan_at": following.isoformat()},
    }
    event_id = db.create_monitor_event(monitor["id"], event_type=event["event_type"],
                                       severity=event["severity"], summary=event["summary"],
                                       details=event["details"])
    notify_fn(event_id, event, monitor)
    result["event_type"] = event["event_type"]
    return result


def _note_dns_down(error):
    with _state_lock:
        if not _state.get("dns_down_since"):
            _state["dns_down_since"] = datetime.now(timezone.utc).isoformat()
            log.warning("DNS does not answer on this server; scheduled scans wait (%s)", error)
        _state["dns_error"] = error


def _note_dns_up():
    with _state_lock:
        if _state.get("dns_down_since"):
            log.info("DNS answers again; postponed scans run")
        _state["dns_down_since"] = None
        _state["dns_error"] = None


def _record_success(db, monitor_id: int, metadata: dict):
    sched = metadata.get("scheduler") or {}
    sched["consecutive_failures"] = 0
    sched.pop("backoff_until", None)
    sched.pop("dns_retries", None)
    sched.pop("dns_unanswered_since", None)
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
    resolver_check_fn=None,
) -> dict:
    """Run all due monitors once with optional parallelism.

    With `resolver_check_fn` the scanner's own DNS is asked first: when it
    does not answer, every due scan waits rather than each running blind
    and rating its domain F."""
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
        if runnable and resolver_check_fn:
            ok, error = resolver_check_fn()
            if ok:
                _note_dns_up()
            else:
                _note_dns_down(error)
                results = [{"monitor_id": m["id"], "target": m["target"], "status": "postponed",
                            "reason": dns_health.RESOLVER_DOWN} for m in runnable]
                runnable = []

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
            except dns_health.DnsUnavailable as exc:
                return _postpone_for_dns(db, monitor, settings, exc, notify_fn)
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

        postponed = sum(1 for item in results if item.get("status") == "postponed")
        duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        with _state_lock:
            total_runs = _state.get("total_runs", 0) + 1
        _update_state(
            last_run_at=started.isoformat(),
            last_run_duration_ms=duration_ms,
            last_run_processed=len(results),
            last_run_errors=errors,
            last_run_skipped_backoff=skipped_backoff,
            last_run_postponed_dns=postponed,
            last_error=None if errors == 0 else f"{errors} monitor scan(s) failed",
            total_runs=total_runs,
        )
        return {
            "processed": len(results),
            "results": results,
            "running": False,
            "skipped_backoff": skipped_backoff,
            "postponed_dns": postponed,
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
