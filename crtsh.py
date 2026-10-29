"""Single place that talks to crt.sh.

Certificate Transparency lookups are used from several angles — the OSINT
tab, subdomain-takeover enumeration and the CAA check — and two of them carried
their own copy of the fetch-and-retry logic. Fixing crt.sh's flakiness twice
in a row made the duplication worth removing: this module is now the only
thing that knows how crt.sh behaves.
"""

from __future__ import annotations

import logging
import threading
import time

import requests

import scan_cache

log = logging.getLogger("domainlens.crtsh")

_UA = "DomainLens-OSINT/1.0 (+https://github.com/ItsRaYnor/DomainLens)"

# crt.sh's front end is chronically overloaded. During an outage it does not
# settle on one status: the same query can answer 502, then 504, then 404
# minutes apart. So 404 is treated as transient here too — a genuinely empty
# result set comes back as HTTP 200 with an empty JSON array, not a 404.
_TRANSIENT_STATUS = {404, 429, 500, 502, 503, 504}

_OUTAGE_MESSAGE = (
    "Certificate Transparency lookup unavailable — crt.sh answered HTTP {status} "
    "after {attempts} attempts. This is an outage at crt.sh, not a problem with "
    "the scanned domain; re-run the scan shortly."
)

_TIMEOUT_MESSAGE = (
    "Certificate Transparency lookup unavailable — crt.sh did not answer within "
    "{timeout}s. This is an outage at crt.sh, not a problem with the scanned "
    "domain; re-run the scan shortly."
)


def fetch(domain, timeout=20, attempts=3, session=None, force=False):
    """Return (rows, error). `rows` is the parsed JSON list, or None on failure."""
    rows, error, _meta = fetch_detailed(
        domain, timeout=timeout, attempts=attempts, session=session, force=force)
    return rows, error


# One full scan asks crt.sh for the same domain from three places at once:
# the OSINT tab, takeover enumeration and the CAA check. With an empty cache
# each sent its own request and its own retries, so an outage cost crt.sh up
# to nine requests per scan and the tabs could disagree about the same list.
# Now a lookup that is already under way is joined instead of repeated.
_flights_lock = threading.Lock()
_flights: dict[str, "_Flight"] = {}


class _Flight:
    """One lookup in progress, and what it found once it is done."""

    def __init__(self, timeout, attempts):
        self.timeout = timeout
        self.attempts = attempts
        self.waiters = 0
        self.done = threading.Event()
        # (rows, error, last_status, may_fall_back): set by the one caller
        # that asks crt.sh, read by everyone who joined it.
        self.outcome = (None, "crt.sh lookup failed", None, True)

    def covers(self, timeout, attempts):
        """Whether this lookup was at least as patient as the caller would
        have been. A failure after fewer or shorter tries does not answer for
        a caller that would have kept trying, so that caller asks again."""
        return self.timeout >= timeout and self.attempts >= attempts


def fetch_detailed(domain, timeout=20, attempts=3, session=None, force=False):
    """Return (rows, error, meta) where meta says whether this came from cache.

    A successful result is cached for the day (see scan_cache), because both
    callers ask for the same thing during one scan and a daily monitor asks
    again tomorrow. crt.sh is overloaded often enough that not asking is the
    single most useful thing we can do for it. Pass force=True to bypass.

    The caller gets `meta` so a report can say the data is a day old rather
    than implying it was just looked up.
    """
    cached = scan_cache.lookup(scan_cache.KIND_CRTSH, domain, force=force)
    if cached is not None:
        rows, age = cached
        return rows, None, {"cached": True, "stale": False, "cache_age_seconds": round(age)}

    key = (domain or "").lower()
    while True:
        with _flights_lock:
            flight = _flights.get(key)
            leader = flight is None
            if leader:
                flight = _flights[key] = _Flight(timeout, attempts)
            else:
                flight.waiters += 1
        if leader:
            break
        # Bounded, so a lookup that never reports back cannot hold this
        # caller forever: it then asks for itself.
        finished = flight.done.wait(timeout=(timeout + 5) * attempts + 30)
        if not finished:
            return _result(domain, _ask(domain, timeout, attempts, session), force)
        if flight.outcome[0] is not None or flight.covers(timeout, attempts):
            return _result(domain, flight.outcome, force)

    try:
        flight.outcome = _ask(domain, timeout, attempts, session)
    finally:
        with _flights_lock:
            if _flights.get(key) is flight:
                del _flights[key]
        flight.done.set()
    return _result(domain, flight.outcome, force)


def _ask(domain, timeout, attempts, session):
    """The requests themselves: (rows, error, last_status, may_fall_back)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    get = (session or requests).get
    last_status = None
    last_error = None

    for attempt in range(attempts):
        try:
            resp = get(url, timeout=timeout, headers={"User-Agent": _UA})
            last_status = resp.status_code
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    # An HTML error page served with a 200, which crt.sh also
                    # does under load.
                    last_error = "crt.sh returned a non-JSON response"
                else:
                    if isinstance(data, list):
                        scan_cache.store(scan_cache.KIND_CRTSH, domain, data)
                        return data, None, 200, False
                    last_error = "crt.sh returned an unexpected response shape"
            elif resp.status_code in _TRANSIENT_STATUS:
                last_error = _OUTAGE_MESSAGE.format(status=resp.status_code, attempts=attempts)
            else:
                return None, f"crt.sh returned HTTP {resp.status_code}", resp.status_code, False
        except requests.Timeout:
            # No answer within the whole budget is crt.sh overloaded on this
            # query. A second and third try of the same heavy query took the
            # scan to over a minute and did not make an answer more likely;
            # fast failures (502, 504, a dropped connection) are still retried.
            return None, _TIMEOUT_MESSAGE.format(timeout=timeout), None, True
        except Exception as exc:
            last_error = f"crt.sh request failed: {str(exc)[:120]}"

        if attempt < attempts - 1:
            time.sleep(1.5 * (attempt + 1))

    if last_error and last_status in _TRANSIENT_STATUS:
        last_error = _OUTAGE_MESSAGE.format(status=last_status, attempts=attempts)
    return None, last_error or "crt.sh lookup failed", last_status, True


def _result(domain, outcome, force):
    """What one caller gets from a finished lookup, its own or a shared one."""
    rows, last_error, _status, may_fall_back = outcome
    if rows is not None:
        return rows, None, {"cached": False}
    if not may_fall_back:
        return None, last_error, {"cached": False}

    # crt.sh is down often enough that returning nothing means the subdomain
    # section goes blank for hours. The last answer we know to be real is more
    # use than no answer — but only if it is labelled as such, with the moment
    # it was actually retrieved, so nobody reads it as a current result.
    stale = scan_cache.lookup_stale(scan_cache.KIND_CRTSH, domain) if not force else None
    if stale is not None:
        rows, age, created_at = stale
        return rows, None, {
            "cached": True,
            "stale": True,
            "cache_age_seconds": round(age),
            "cached_at": created_at.isoformat(),
            "outage": last_error,
        }
    return None, last_error, {"cached": False}
