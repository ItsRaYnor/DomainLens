"""Single place that talks to crt.sh.

Certificate Transparency lookups are used from two very different angles —
the OSINT tab and subdomain-takeover enumeration — and both were carrying
their own copy of the fetch-and-retry logic. Fixing crt.sh's flakiness twice
in a row made the duplication worth removing: this module is now the only
thing that knows how crt.sh behaves.
"""

from __future__ import annotations

import logging
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


def fetch(domain, timeout=20, attempts=3, session=None, force=False):
    """Return (rows, error). `rows` is the parsed JSON list, or None on failure."""
    rows, error, _meta = fetch_detailed(
        domain, timeout=timeout, attempts=attempts, session=session, force=force)
    return rows, error


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
                        return data, None, {"cached": False}
                    last_error = "crt.sh returned an unexpected response shape"
            elif resp.status_code in _TRANSIENT_STATUS:
                last_error = _OUTAGE_MESSAGE.format(status=resp.status_code, attempts=attempts)
            else:
                return None, f"crt.sh returned HTTP {resp.status_code}", {"cached": False}
        except Exception as exc:
            last_error = f"crt.sh request failed: {str(exc)[:120]}"

        if attempt < attempts - 1:
            time.sleep(1.5 * (attempt + 1))

    if last_error and last_status in _TRANSIENT_STATUS:
        last_error = _OUTAGE_MESSAGE.format(status=last_status, attempts=attempts)
    last_error = last_error or "crt.sh lookup failed"

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
