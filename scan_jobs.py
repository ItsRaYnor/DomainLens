"""Background scan jobs with progress, so a scan is not an opaque wait.

Scanning used to be a single synchronous request: the browser posted and sat
there until every check had finished. That meant no progress indication, and
navigating away lost the scan entirely — the work carried on server-side but
its result was thrown away, and nothing stopped the user from starting the
same scan again on top of it.

Jobs live in memory. A restart loses in-flight jobs, which is acceptable:
a scan takes under a minute and finished results are persisted to the scan
history anyway.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone

log = logging.getLogger("domainlens.scan_jobs")

# How long a finished job stays queryable, so a page that returns after a
# short absence can still collect its result.
_RETENTION_SECONDS = 900
# Hard ceiling on a single job, so a hung check cannot pin the domain
# forever and block every later scan of it.
_MAX_RUNTIME_SECONDS = 600

_lock = threading.Lock()
_jobs: dict[str, dict] = {}


def _now():
    return datetime.now(timezone.utc)


def _age(job, field="finished_at"):
    stamp = job.get(field)
    return (_now() - stamp).total_seconds() if stamp else 0.0


def _prune_locked():
    stale = [
        job_id for job_id, job in _jobs.items()
        if job["status"] in ("done", "error") and _age(job) > _RETENTION_SECONDS
    ]
    for job_id in stale:
        _jobs.pop(job_id, None)


def _is_stuck(job):
    return job["status"] == "running" and _age(job, "started_at") > _MAX_RUNTIME_SECONDS


def public_view(job, include_result=False):
    """Job state for the client. The result is large, so it is opt-in."""
    view = {
        "job_id": job["job_id"],
        "domain": job["domain"],
        "status": job["status"],
        "done": job["done"],
        "total": job["total"],
        "percent": job["percent"],
        "current": job["current"],
        "started_at": job["started_at"].isoformat() if job.get("started_at") else None,
        "finished_at": job["finished_at"].isoformat() if job.get("finished_at") else None,
        "error": job.get("error"),
        "scan_id": job.get("scan_id"),
    }
    if include_result and job["status"] == "done":
        view["result"] = job.get("result")
    return view


def find_active(domain):
    """Return the running job for a domain, if there is one."""
    with _lock:
        _prune_locked()
        for job in _jobs.values():
            if job["domain"] == domain and job["status"] == "running":
                if _is_stuck(job):
                    job["status"] = "error"
                    job["error"] = "Scan exceeded the maximum runtime and was abandoned"
                    job["finished_at"] = _now()
                    continue
                return public_view(job)
    return None


def get(job_id, include_result=False):
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return None
        if _is_stuck(job):
            job["status"] = "error"
            job["error"] = "Scan exceeded the maximum runtime and was abandoned"
            job["finished_at"] = _now()
        return public_view(job, include_result=include_result)


def start(domain, runner):
    """Register a job and run `runner(progress_cb)` on a worker thread.

    `runner` returns the finished result dict, and may set job["scan_id"] via
    the returned dict's "scan_id" key.
    """
    job_id = uuid.uuid4().hex
    job = {
        "job_id": job_id,
        "domain": domain,
        "status": "running",
        "done": 0,
        "total": 0,
        "percent": 0,
        "current": None,
        "started_at": _now(),
        "finished_at": None,
        "result": None,
        "error": None,
        "scan_id": None,
    }
    with _lock:
        _prune_locked()
        _jobs[job_id] = job

    def progress_cb(done, total, name):
        with _lock:
            job["done"] = done
            job["total"] = total
            # Report 99% at most until the result is actually stored, so the
            # bar never sits at 100% while work is still happening.
            job["percent"] = min(99, round((done / total) * 100)) if total else 0
            job["current"] = name

    def worker():
        try:
            result = runner(progress_cb)
            with _lock:
                job["result"] = result
                job["scan_id"] = (result or {}).get("scan_id")
                job["status"] = "done"
                job["percent"] = 100
                job["current"] = None
                job["finished_at"] = _now()
        except Exception as exc:
            log.exception("Scan job for %s failed", domain)
            with _lock:
                job["status"] = "error"
                job["error"] = str(exc)[:300]
                job["finished_at"] = _now()

    threading.Thread(target=worker, name=f"scan-{domain}", daemon=True).start()
    return public_view(job)


def reset():
    """Drop every job. For tests."""
    with _lock:
        _jobs.clear()
