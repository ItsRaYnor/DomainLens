"""Links in a message checked without handing them to anyone.

A link in a mail often carries something personal: a password-reset token,
a customer number in an unsubscribe link, a session in the query. Sending
such a URL to a reputation service publishes it -- a submission to
VirusTotal is searchable by every paying subscriber, including whoever
watches whether their phishing page has been noticed. So the checks here are
built to leak nothing, or as little as can be:

  * Lookalikes of the organisation's own domains (the domain portfolio):
    worked out locally. "examp1e.com" in a mail while you hold example.com.
  * Threat lists (feeds) downloaded whole by the scheduler and searched
    locally: per link nothing leaves the server. Which feeds, if any, is the
    admin's choice (Admin -> Settings -> Mail analysis).
  * VirusTotal, only when an admin switches it on, and only by hash: the
    SHA-256 of the URL is asked about, the URL is never sent and nothing is
    ever submitted. A URL VirusTotal does not know stays unknown to it.

Every answer keeps its state: on a list, not on a list, not checked, could
not be checked. "Not known" is never "safe".
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone

import db

log = logging.getLogger("domainlens.links")

_FEED_MAX_BYTES = 64 * 1024 * 1024
_FEED_MAX_ENTRIES = 3_000_000
_FEED_EVERY = timedelta(hours=12)
_VT_CACHE = timedelta(hours=24)
_refresh_lock = threading.Lock()


def init_schema(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS link_feed_urls (hash TEXT NOT NULL, host TEXT NOT NULL, "
                 "source TEXT NOT NULL)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_link_feed_hash ON link_feed_urls(hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_link_feed_host ON link_feed_urls(host)")
    conn.execute("CREATE TABLE IF NOT EXISTS link_feed_meta (source TEXT PRIMARY KEY, refreshed_at TEXT, "
                 "entries INTEGER, error TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS link_vt_cache (hash TEXT PRIMARY KEY, checked_at TEXT NOT NULL, "
                 "result TEXT NOT NULL)")


def _now():
    return datetime.now(timezone.utc)


def _settings():
    import config as domainlens_config
    return dict(domainlens_config.load_settings().raw.get("mail_test") or {})


# --------------------------------------------------------------- URLs

def normalise(url):
    """The form a URL is compared and hashed in: scheme and host lower case,
    an empty path as "/", the fragment dropped (it never reaches a server)."""
    parts = urllib.parse.urlsplit(str(url or "").strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii") if host and not host.isascii() else host
    except UnicodeError:
        pass
    netloc = host + (f":{parts.port}" if parts.port and parts.port not in (80, 443) else "")
    return urllib.parse.urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def url_hash(url):
    return hashlib.sha256(normalise(url).encode("utf-8")).hexdigest()


def host_of(url):
    return (urllib.parse.urlsplit(str(url or "")).hostname or "").lower().rstrip(".")


# --------------------------------------------------------------- lookalikes

# Characters that read the same as a Latin letter: digits, and the Cyrillic
# and Greek letters an internationalised domain can use instead.
_CONFUSABLE = str.maketrans({
    "0": "o", "1": "l", "i": "l", "|": "l", "5": "s", "3": "e", "4": "a", "7": "t", "8": "b",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "к": "k",
    "м": "m", "т": "t", "н": "h", "в": "b", "і": "l", "ј": "j", "ѕ": "s", "ԁ": "d",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "l", "κ": "k", "χ": "x",
})


def _skeleton(label):
    text = label.lower()
    try:
        text = text.encode("ascii").decode("idna") if text.startswith("xn--") else text
    except UnicodeError:
        pass
    text = text.translate(_CONFUSABLE)
    return text.replace("rn", "m").replace("vv", "w").replace("-", "")


def _distance(a, b):
    """Damerau-Levenshtein distance, stopping early above 1."""
    if abs(len(a) - len(b)) > 1:
        return 2
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if prev2 and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def own_domains():
    """The registered domains the organisation holds or wants (the portfolio)."""
    try:
        with db._connect() as conn:
            return {r["domain"] for r in conn.execute("SELECT domain FROM portfolio_domains").fetchall()}
    except Exception:
        return set()


def lookalike(host, own):
    """The own domain this host imitates, or None. The same name under
    another TLD, a name one typo away, the same name written with look-alike
    characters, or the name with a word attached ("example-login")."""
    from domain_portfolio import registrable
    if not host or not own:
        return None
    reg = registrable(host)
    if reg in own:
        return None
    label = reg.split(".")[0]
    suffix = reg.split(".", 1)[1] if "." in reg else ""
    # Under the same TLD first: examp1e.org imitates example.org, not the
    # example.be that sorts before it.
    for mine in sorted(own, key=lambda d: (d.split(".", 1)[-1] != suffix, d)):
        ours = mine.split(".")[0]
        if len(ours) < 4:
            continue
        if label == ours or _skeleton(label) == _skeleton(ours):
            return mine
        if len(ours) >= 5 and _distance(label, ours) == 1:
            return mine
        if len(ours) >= 5 and ours in label.split("-"):
            return mine
    return None


# --------------------------------------------------------------- threat lists

def _feed_lines(text):
    """URLs from a list: one per line, or CSV with the URL in a column."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        found = re.search(r"https?://[^\s\",]+", line)
        if found:
            yield found.group(0)


def refresh(sources=None, *, get=None):
    """Download each configured list whole and replace what it held. Nothing
    about any message is sent: the same request goes out whatever is asked."""
    import requests
    from settings import api_keys
    sources = list(sources if sources is not None else (_settings().get("link_feeds") or []))
    get = get or (lambda url, headers: requests.get(url, headers=headers, timeout=60, stream=True))
    report = {}
    with _refresh_lock:
        for source in sources:
            source = str(source).strip()
            if not source.startswith("https://"):
                report[source] = "skipped: only https:// lists are fetched"
                continue
            headers = {"User-Agent": "DomainLens"}
            if host_of(source).endswith("abuse.ch"):
                key = api_keys.resolve("ABUSECH_AUTH_KEY")
                if key:
                    headers["Auth-Key"] = key
            try:
                resp = get(source, headers)
                resp.raise_for_status()
                body = b""
                for chunk in resp.iter_content(1 << 20):
                    body += chunk
                    if len(body) > _FEED_MAX_BYTES:
                        raise ValueError("list larger than 64 MB")
                rows = []
                for url in _feed_lines(body.decode("utf-8", "replace")):
                    rows.append((url_hash(url), host_of(url), source))
                    if len(rows) >= _FEED_MAX_ENTRIES:
                        break
                with db._lock, db._connect() as conn:
                    conn.execute("DELETE FROM link_feed_urls WHERE source = ?", (source,))
                    conn.executemany("INSERT INTO link_feed_urls (hash, host, source) VALUES (?, ?, ?)", rows)
                    conn.execute("INSERT OR REPLACE INTO link_feed_meta (source, refreshed_at, entries, error) "
                                 "VALUES (?, ?, ?, NULL)", (source, _now().isoformat(), len(rows)))
                report[source] = len(rows)
            except Exception as exc:
                text = str(exc)[:200]
                with db._lock, db._connect() as conn:
                    conn.execute("INSERT INTO link_feed_meta (source, error) VALUES (?, ?) "
                                 "ON CONFLICT(source) DO UPDATE SET error = excluded.error", (source, text))
                report[source] = f"error: {text}"
        # A list no longer configured is no longer used.
        with db._lock, db._connect() as conn:
            marks = ",".join("?" * len(sources)) or "''"
            conn.execute(f"DELETE FROM link_feed_urls WHERE source NOT IN ({marks})", sources)
            conn.execute(f"DELETE FROM link_feed_meta WHERE source NOT IN ({marks})", sources)
    return report


def feed_status():
    """[{source, refreshed_at, entries, error}] for the configured lists."""
    sources = [str(s).strip() for s in (_settings().get("link_feeds") or []) if str(s).strip()]
    with db._connect() as conn:
        rows = {r["source"]: dict(r) for r in conn.execute("SELECT * FROM link_feed_meta").fetchall()}
    return [rows.get(s, {"source": s, "refreshed_at": None, "entries": None, "error": None}) for s in sources]


def maybe_refresh():
    """Called from the scheduler: refresh lists older than twelve hours."""
    status = feed_status()
    due = [s["source"] for s in status
           if not s.get("refreshed_at") or _now() - datetime.fromisoformat(s["refreshed_at"]) > _FEED_EVERY]
    if due and not _refresh_lock.locked():
        refresh([s["source"] for s in status])


def check_feeds(urls):
    """{url: "listed" | "host_listed" | "not_listed"} -- or None for every URL
    when no list has been loaded, which is "not checked", not "clean"."""
    with db._connect() as conn:
        loaded = conn.execute("SELECT COUNT(*) AS n FROM link_feed_meta WHERE entries IS NOT NULL").fetchone()["n"]
        if not loaded:
            return None
        out = {}
        for url in urls:
            if conn.execute("SELECT 1 FROM link_feed_urls WHERE hash = ? LIMIT 1", (url_hash(url),)).fetchone():
                out[url] = "listed"
            elif conn.execute("SELECT 1 FROM link_feed_urls WHERE host = ? LIMIT 1", (host_of(url),)).fetchone():
                out[url] = "host_listed"
            else:
                out[url] = "not_listed"
    return out


# --------------------------------------------------------------- VirusTotal

def virustotal_state():
    """"off", "no_key" or "on"."""
    from settings import api_keys
    if not _settings().get("virustotal_links"):
        return "off"
    return "on" if api_keys.resolve("VIRUSTOTAL_API_KEY") else "no_key"


def check_virustotal(urls, *, get=None, key=None, limit=None):
    """{url: {"state", "malicious", "suspicious", "engines"}} by hash only.

    state: "malicious" | "suspicious" | "no_detections" (known, no engine
    flags it) | "unknown" (VirusTotal has not seen it) | "unmeasured" (an
    error, a rejected key, the rate limit) | "not_checked" (over the limit
    per message). Never a POST: nothing is ever submitted.
    """
    import requests
    from settings import api_keys
    key = key or api_keys.resolve("VIRUSTOTAL_API_KEY")
    limit = int(limit or _settings().get("virustotal_max_links") or 4)
    get = get or (lambda url, headers: requests.get(url, headers=headers, timeout=15))
    out, asked, stop = {}, 0, None
    for url in urls:
        digest = url_hash(url)
        cached = _vt_cached(digest)
        if cached:
            out[url] = cached
            continue
        if stop:
            out[url] = {"state": "unmeasured", "error": stop}
            continue
        if asked >= limit:
            out[url] = {"state": "not_checked"}
            continue
        asked += 1
        try:
            resp = get(f"https://www.virustotal.com/api/v3/urls/{digest}", {"x-apikey": key})
        except Exception as exc:
            out[url] = {"state": "unmeasured", "error": str(exc)[:200]}
            continue
        if resp.status_code == 404:
            result = {"state": "unknown"}
        elif resp.status_code in (401, 403):
            stop = "VirusTotal rejected the API key"
            out[url] = {"state": "unmeasured", "error": stop}
            continue
        elif resp.status_code == 429:
            stop = "VirusTotal's rate limit was reached"
            out[url] = {"state": "unmeasured", "error": stop}
            continue
        elif resp.status_code != 200:
            out[url] = {"state": "unmeasured", "error": f"HTTP {resp.status_code}"}
            continue
        else:
            stats = ((resp.json().get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
            malicious, suspicious = int(stats.get("malicious") or 0), int(stats.get("suspicious") or 0)
            result = {"state": "malicious" if malicious else "suspicious" if suspicious else "no_detections",
                      "malicious": malicious, "suspicious": suspicious,
                      "engines": sum(int(v or 0) for v in stats.values())}
        _vt_store(digest, result)
        out[url] = result
    return out


def _vt_cached(digest):
    with db._connect() as conn:
        row = conn.execute("SELECT checked_at, result FROM link_vt_cache WHERE hash = ?", (digest,)).fetchone()
    if row and _now() - datetime.fromisoformat(row["checked_at"]) < _VT_CACHE:
        return json.loads(row["result"])
    return None


def _vt_store(digest, result):
    with db._lock, db._connect() as conn:
        conn.execute("INSERT OR REPLACE INTO link_vt_cache (hash, checked_at, result) VALUES (?, ?, ?)",
                     (digest, _now().isoformat(), json.dumps(result)))
