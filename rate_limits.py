"""Stay within the free tiers of the third-party APIs, and say so when not.

The free VirusTotal key allows 4 lookups a minute and 500 a day; ip-api.com
allows 45 a minute. A few scans close together -- or a monitor plan, or a
mail with several links -- went past that, and the answer came back as
HTTP 429 and was shown as an error, or as nothing at all. Every further
request in the next minute failed the same way and counted against the
quota too.

So each provider has a budget (from Settings, as a paid key allows more): a
lookup waits a little for a free slot, and when none comes in time -- or
the day's quota is used up -- it is not made, and the result says why. A
provider that answers 429 is not asked again until it says it may be
(Retry-After), or for a minute.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone

NAMES = {"virustotal": "VirusTotal", "ip-api": "ip-api.com", "otx": "AlienVault OTX",
         "abuse.ch": "abuse.ch", "wayback": "the Internet Archive"}

_lock = threading.Lock()
_minute = {}      # provider -> deque of monotonic times in the last minute
_day = {}         # provider -> (UTC date, count)
_cooldown = {}    # provider -> (monotonic until, reason)


def _settings():
    try:
        import config as domainlens_config
        return dict(domainlens_config.load_settings().raw.get("api_limits") or {})
    except Exception:
        return {}


def limits(provider):
    """(per_minute, per_day) for a provider; None is "no budget kept"."""
    cfg = _settings()
    if provider == "virustotal":
        return int(cfg.get("virustotal_per_minute") or 4), int(cfg.get("virustotal_per_day") or 500)
    if provider == "ip-api":
        return int(cfg.get("ip_api_per_minute") or 45), None
    return None, None


def max_wait():
    try:
        return max(0, int(_settings().get("wait_seconds", 20)))
    except (TypeError, ValueError):
        return 20


def _name(provider):
    return NAMES.get(provider, provider)


def acquire(provider, wait=None):
    """(True, None) when a lookup may be made now, else (False, reason).

    Waits up to `wait` seconds (Settings) for a free slot in the minute.
    """
    per_minute, per_day = limits(provider)
    budget = max_wait() if wait is None else wait
    waited = 0.0
    while True:
        with _lock:
            now = time.monotonic()
            until, reason = _cooldown.get(provider, (0, None))
            if until > now:
                return False, reason
            today = datetime.now(timezone.utc).date()
            day, count = _day.get(provider, (today, 0))
            if day != today:
                day, count = today, 0
            if per_day and count >= per_day:
                return False, (f"The daily limit for {_name(provider)} ({per_day} lookups) is used up; "
                               "it resets at 00:00 UTC. Not measured; try again later.")
            calls = _minute.setdefault(provider, deque())
            while calls and now - calls[0] >= 60:
                calls.popleft()
            if not per_minute or len(calls) < per_minute:
                calls.append(now)
                _day[provider] = (day, count + 1)
                return True, None
            pause = 60 - (now - calls[0]) + 0.05
        if waited + pause > budget:
            return False, (f"{_name(provider)} allows {per_minute} lookups a minute and they were in use. "
                           "Not measured; try again later.")
        time.sleep(pause)
        waited += pause


def cooldown(provider, seconds, reason=None):
    with _lock:
        _cooldown[provider] = (time.monotonic() + max(1, seconds), reason or (
            f"{_name(provider)} asked to slow down (its rate limit was reached). "
            "Not measured; try again later."))


def note_response(provider, response):
    """Start a cooldown when a provider answered 429. True when it did."""
    if getattr(response, "status_code", None) != 429:
        return False
    seconds = 60
    try:
        seconds = int((getattr(response, "headers", None) or {}).get("Retry-After") or 60)
    except (TypeError, ValueError):
        pass
    cooldown(provider, min(seconds, 24 * 3600))
    return True


def status():
    """What is used and what is blocked, for the settings page."""
    out = {}
    now = time.monotonic()
    today = datetime.now(timezone.utc).date()
    with _lock:
        for provider in NAMES:
            per_minute, per_day = limits(provider)
            calls = [t for t in _minute.get(provider, ()) if now - t < 60]
            day, count = _day.get(provider, (today, 0))
            until, reason = _cooldown.get(provider, (0, None))
            out[provider] = {
                "name": _name(provider), "per_minute": per_minute, "per_day": per_day,
                "last_minute": len(calls), "today": count if day == today else 0,
                "blocked_for_seconds": max(0, int(until - now)), "blocked_reason": reason if until > now else None,
            }
    return out


def reset():
    """Forget every count and cooldown. For tests."""
    with _lock:
        _minute.clear()
        _day.clear()
        _cooldown.clear()
