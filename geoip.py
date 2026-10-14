"""Where an address is, from MaxMind GeoLite2, read on this server.

Location came from ip-api.com's free endpoint: every address scanned was
sent over plain HTTP to a third party whose free tier is for non-commercial
use only. GeoLite2 is a database downloaded to this server and read here, so
no address leaves it. It needs a free MaxMind account (account ID and
license key, under Settings -> API keys); without one, location is reported
as not configured, never guessed.

The GeoLite EULA asks for two things this module keeps to: attribution
wherever the data is shown (ATTRIBUTION), and that an old version is not used
for more than 30 days after a newer one is released -- a database older than
that is not read, and location becomes "not measured" until it is updated.
"""

from __future__ import annotations

import io
import logging
import os
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone

import requests

import net_errors

log = logging.getLogger("domainlens.geoip")

EDITION = "GeoLite2-City"
_URL = f"https://download.maxmind.com/geoip/databases/{EDITION}/download?suffix=tar.gz"
ATTRIBUTION = "This product includes GeoLite Data created by MaxMind, available from https://www.maxmind.com."
# MaxMind releases GeoLite2 City on Tuesdays and Fridays; a free account may
# download 30 times a day. Every three days keeps up without coming close.
_REFRESH_SECONDS = 3 * 24 * 3600
_RETRY_SECONDS = 6 * 3600
_MAX_AGE_DAYS = 30
_MAX_DOWNLOAD = 200 * 1024 * 1024

_lock = threading.Lock()          # one download at a time
_reader_lock = threading.Lock()   # one reader swap at a time
_reader = {"path": None, "mtime": None, "db": None}
_last = {"attempt": 0.0, "error": None, "refreshed_at": None}


def _path():
    base = os.environ.get("DOMAINLENS_DATA_DIR")
    if not base:
        import db
        base = os.path.dirname(os.path.abspath(db._db_path()))
    return os.path.join(base, "geoip", f"{EDITION}.mmdb")


def _credentials():
    try:
        from settings import api_keys
        return api_keys.resolve("MAXMIND_ACCOUNT_ID"), api_keys.resolve("MAXMIND_LICENSE_KEY")
    except Exception:
        return (os.environ.get("MAXMIND_ACCOUNT_ID") or "").strip(), (os.environ.get("MAXMIND_LICENSE_KEY") or "").strip()


def configured():
    account, key = _credentials()
    return bool(account and key)


def refresh():
    """Download the database. Returns {"ok", "error"}."""
    account, key = _credentials()
    if not (account and key):
        return {"ok": False, "error": "No MaxMind account ID and license key set"}
    if not _lock.acquire(blocking=False):
        return {"ok": False, "error": "A download is already running"}
    _last["attempt"] = time.time()
    try:
        # Basic auth; the answer redirects to a presigned storage URL, and
        # requests drops the credentials when it follows that to another host.
        resp = requests.get(_URL, auth=(account, key), stream=True, timeout=60)
        if resp.status_code in (401, 403):
            raise ValueError("MaxMind rejected the account ID or license key")
        resp.raise_for_status()
        buffer, total = io.BytesIO(), 0
        for chunk in resp.iter_content(chunk_size=1 << 20):
            total += len(chunk)
            if total > _MAX_DOWNLOAD:
                raise ValueError("The download was larger than expected")
            buffer.write(chunk)
        buffer.seek(0)
        with tarfile.open(fileobj=buffer, mode="r:gz") as archive:
            member = next((m for m in archive.getmembers() if m.isfile() and m.name.endswith(".mmdb")), None)
            if member is None:
                raise ValueError("The download held no .mmdb database")
            data = archive.extractfile(member).read()
        target = _path()
        os.makedirs(os.path.dirname(target), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(target), suffix=".part")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        _open(tmp).close()  # a database that cannot be read never replaces one that can
        os.replace(tmp, target)
        _last.update(error=None, refreshed_at=datetime.now(timezone.utc).isoformat())
        log.info("GeoLite2 database updated (%s bytes)", len(data))
        return {"ok": True, "error": None}
    except Exception as exc:
        error = str(exc) if isinstance(exc, ValueError) else net_errors.describe(exc, "download.maxmind.com")
        _last["error"] = error
        log.warning("GeoLite2 download failed: %s", error)
        return {"ok": False, "error": error}
    finally:
        _lock.release()


def maybe_refresh():
    """From the scheduler: fetch the database when it is missing or due."""
    if not configured() or time.time() - _last["attempt"] < _RETRY_SECONDS:
        return
    path = _path()
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < _REFRESH_SECONDS:
        return
    refresh()


def _open(path):
    import maxminddb
    return maxminddb.open_database(path)


def _db():
    path = _path()
    if not os.path.exists(path):
        return None
    mtime = os.path.getmtime(path)
    with _reader_lock:
        if _reader["path"] != path or _reader["mtime"] != mtime or _reader["db"] is None:
            if _reader["db"] is not None:
                try:
                    _reader["db"].close()
                except Exception:
                    pass
            _reader.update(path=path, mtime=mtime, db=_open(path))
    return _reader["db"]


def _build_date(reader):
    return datetime.fromtimestamp(reader.metadata().build_epoch, tz=timezone.utc)


def lookup(ip):
    """{"state", "country", "country_code", "region", "city", "source", "attribution", "error"}.

    state: "measured", "not_configured" (no account set), "not_in_database",
    or "unmeasured" (no database yet, an unreadable one, or one too old to use).
    """
    base = {"country": None, "country_code": None, "region": None, "city": None,
            "source": None, "attribution": ATTRIBUTION, "error": None}
    if not configured():
        return {**base, "state": "not_configured", "attribution": None}
    try:
        reader = _db()
    except Exception as exc:
        return {**base, "state": "unmeasured", "error": f"The GeoLite2 database could not be read: {exc}"}
    if reader is None:
        return {**base, "state": "unmeasured",
                "error": _last["error"] or "The GeoLite2 database has not been downloaded yet"}
    built = _build_date(reader)
    age = (datetime.now(timezone.utc) - built).days
    if age > _MAX_AGE_DAYS:
        # The EULA: no old version 30 days after a newer one is out.
        return {**base, "state": "unmeasured",
                "error": f"The GeoLite2 database is {age} days old and could not be updated, so it is not used"}
    source = f"MaxMind GeoLite2, {built.date().isoformat()}"
    try:
        record = reader.get(ip)
    except ValueError:
        return {**base, "state": "unmeasured", "error": "Not an IP address"}
    if not record:
        return {**base, "state": "not_in_database", "source": source}
    country = record.get("country") or record.get("registered_country") or {}
    subdivisions = record.get("subdivisions") or [{}]
    return {**base, "state": "measured", "source": source,
            "country": (country.get("names") or {}).get("en"),
            "country_code": country.get("iso_code"),
            "region": ((subdivisions[0] or {}).get("names") or {}).get("en"),
            "city": ((record.get("city") or {}).get("names") or {}).get("en")}


def status():
    path = _path()
    built = None
    try:
        reader = _db()
        built = _build_date(reader).date().isoformat() if reader else None
    except Exception:
        pass
    return {"configured": configured(), "database": built, "path_exists": os.path.exists(path),
            "last_error": _last["error"], "refreshed_at": _last["refreshed_at"]}
