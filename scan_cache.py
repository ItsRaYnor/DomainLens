"""Reuse today's answer from third-party services instead of asking again.

Some checks depend on services DomainLens does not own: crt.sh for certificate
transparency, and the OSINT feeds (OTX, URLhaus/ThreatFox, the Wayback
Machine). Those answers change on the order of a day, but a scan asked them
every single time — and a daily monitor plus a few manual scans of the same
domain meant hitting them repeatedly for an answer that had not moved. crt.sh
in particular is chronically overloaded, and every avoidable request makes
that worse for everyone.

A cached answer is never presented as a fresh one: everything served from
here carries `cached`, `cached_at` and `cache_age_seconds`, so a report says
where its data came from. A scan can always ask for fresh data explicitly,
which is what the `force` argument is for.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import config as domainlens_config
import db

log = logging.getLogger("domainlens.scan_cache")

# Kinds are named here rather than passed as free strings so a typo cannot
# silently create a second, never-read cache.
KIND_OSINT = "osint"
KIND_CRTSH = "crtsh"

_DEFAULT_TTL_HOURS = 24
# During an outage a cached answer may be shown up to this old.
_DEFAULT_MAX_STALE_HOURS = 168


def _config():
    try:
        return dict(domainlens_config.load_settings().scan().get("external_cache") or {})
    except Exception:
        return {}


def is_enabled():
    cfg = _config()
    return bool(cfg.get("enabled", True))


def ttl_seconds():
    cfg = _config()
    try:
        hours = float(cfg.get("ttl_hours", _DEFAULT_TTL_HOURS))
    except (TypeError, ValueError):
        hours = _DEFAULT_TTL_HOURS
    return max(0.0, hours) * 3600.0


def _age_seconds(created_at):
    return (datetime.now(timezone.utc) - created_at).total_seconds()


def lookup(kind, domain, force=False):
    """Return (payload, age_seconds) for a still-fresh entry, else None."""
    if force or not is_enabled():
        return None
    ttl = ttl_seconds()
    if ttl <= 0:
        return None
    try:
        hit = db.external_cache_get(kind, domain)
    except Exception:
        log.debug("Cache read failed for %s:%s", kind, domain, exc_info=True)
        return None
    if not hit:
        return None
    payload, created_at = hit
    age = _age_seconds(created_at)
    if age > ttl:
        return None
    return payload, age


def max_stale_seconds():
    """How far past the TTL a cached answer may still be shown during an outage.

    Not unbounded: a months-old certificate list presented during a crt.sh
    outage is worse than saying nothing, because it looks like coverage.
    """
    cfg = _config()
    try:
        hours = float(cfg.get("max_stale_hours", _DEFAULT_MAX_STALE_HOURS))
    except (TypeError, ValueError):
        hours = _DEFAULT_MAX_STALE_HOURS
    return max(0.0, hours) * 3600.0


def lookup_stale(kind, domain):
    """Return (payload, age_seconds, cached_at) for an expired-but-usable entry.

    Only for the case where a live lookup has already failed: this is the last
    answer we know to be real, and the caller must label it as such.
    """
    if not is_enabled():
        return None
    limit = max_stale_seconds()
    if limit <= 0:
        return None
    try:
        hit = db.external_cache_get(kind, domain)
    except Exception:
        log.debug("Stale cache read failed for %s:%s", kind, domain, exc_info=True)
        return None
    if not hit:
        return None
    payload, created_at = hit
    age = _age_seconds(created_at)
    if age > limit:
        return None
    return payload, age, created_at


def store(kind, domain, payload):
    """Record a successful lookup. A cache write must never fail a scan."""
    if not is_enabled():
        return
    try:
        db.external_cache_put(kind, domain, payload)
    except Exception:
        log.debug("Cache write failed for %s:%s", kind, domain, exc_info=True)


def mark(payload, age_seconds):
    """Stamp a dict result as served from cache.

    Returns the payload unchanged when it is not a dict — a cached list (as
    crt.sh returns) carries its provenance on the surrounding result instead.
    """
    if not isinstance(payload, dict):
        return payload
    stamped = datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() - age_seconds, tz=timezone.utc)
    marked = dict(payload)
    marked["cached"] = True
    marked["cache_age_seconds"] = round(age_seconds)
    marked["cached_at"] = stamped.isoformat()
    return marked


def cached_call(kind, domain, producer, force=False, should_store=None):
    """Return a cached result if fresh, otherwise run `producer` and store it.

    `should_store(result)` decides whether a result is worth keeping; a failed
    lookup must not be cached, or the failure is what gets replayed all day.
    """
    hit = lookup(kind, domain, force=force)
    if hit is not None:
        payload, age = hit
        return mark(payload, age)

    result = producer()
    keep = should_store(result) if should_store else _default_should_store(result)
    if keep:
        store(kind, domain, result)
    return result


def _default_should_store(result):
    if not isinstance(result, dict):
        return result is not None
    if result.get("error"):
        return False
    # `success: False` is an explicit failure; absence of the key is not.
    return result.get("success", True) is not False
