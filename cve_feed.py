"""Known CVEs for the software versions a site shows, from the NVD. Opt-in.

The advisory rules (software_advisories.py) cover the flaws someone wrote a
rule for. This covers the rest of the record for a short list of products
a web server or CMS names itself by -- PHP, nginx, the Apache HTTP Server,
lighttpd, OpenSSL, WordPress, Drupal -- from the National Vulnerability
Database.

No mirror: the NVD's full match data is close to a gigabyte, nearly all of it
about software no web page shows. For each followed product the CVE API is
asked for the CVEs whose configuration names it (virtualMatchString), the
first time in full and after that only what changed (lastModStartDate), at
most once every two hours as the NVD asks, normally once a day. What is kept
is per CVE: its score, whether CISA lists it as exploited (KEV), and the
version ranges the NVD gives for the followed product.

A scan then compares the version a server shows with those ranges, the same
way the rules do, and reports one finding per product rather than one per
CVE: "PHP 8.1.2 has 31 known CVEs, 2 of them exploited".

What is measured, what is not, kept apart:

  * vulnerable -- the version shown is inside the range of at least one CVE;
  * no known CVEs -- the data is current and no CVE the NVD has analysed
    names this version. CVEs the NVD has not analysed yet have no ranges,
    so this is never "has no CVEs";
  * cannot tell -- a distribution build ("Apache/2.4.52 (Ubuntu)": its
    package may carry fixes without a new number), a version without its
    patch release, or a CVE that applies only on some platforms;
  * not measured -- the data is older than the setting allows, or was never
    fetched. That is never "no known CVEs".

Off by default, because switching it on sends requests to nvd.nist.gov
(and, when set, advisories.ncsc.nl). With it off, nothing is said at all:
deliberately not applicable, not "no CVEs".
"""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import db

log = logging.getLogger("domainlens.cve_feed")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# The NVD's terms ask every product that uses the API to say this.
ATTRIBUTION = "This product uses data from the NVD API but is not endorsed or certified by the NVD."
API_KEY_ENV = "NVD_API_KEY"
_UA = "DomainLens-CVE/1.0 (+https://github.com/ItsRaYnor/DomainLens)"

# The products followed. `token` and `sources` read the version exactly as an
# advisory rule would; `cpe` is the NVD's vendor:product for it. `ncsc_names`
# are matched against an NCSC-NL product name; `ncsc_vendor`, where given, must
# be in its vendor or name too: Oracle ships an "HTTP Server" of its own.
PRODUCTS = [
    {"key": "php", "product": "PHP", "token": "PHP", "sources": ["x-powered-by", "server"],
     "cpe": "php:php", "ncsc_names": ["php"],
     "seen_cookies": ["phpsessid", "laravel_session", "ci_session", "wordpress_", "wp-settings"],
     "seen_paths": [".php"]},
    {"key": "nginx", "product": "nginx", "token": "nginx", "sources": ["server"],
     "cpe": "f5:nginx", "ncsc_names": ["nginx"]},
    {"key": "apache-httpd", "product": "Apache HTTP Server", "token": "Apache", "sources": ["server"],
     "cpe": "apache:http_server", "ncsc_names": ["http server", "httpd"], "ncsc_vendor": "apache"},
    {"key": "lighttpd", "product": "lighttpd", "token": "lighttpd", "sources": ["server"],
     "cpe": "lighttpd:lighttpd", "ncsc_names": ["lighttpd"]},
    # Named in the Server header beside Apache: "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f".
    {"key": "openssl", "product": "OpenSSL", "token": "OpenSSL", "sources": ["server"],
     "cpe": "openssl:openssl", "ncsc_names": ["openssl"]},
    {"key": "wordpress", "product": "WordPress", "token": "WordPress", "sources": ["meta:generator"],
     "cpe": "wordpress:wordpress", "ncsc_names": ["wordpress"], "seen_cookies": ["wordpress_", "wp-settings"]},
    {"key": "drupal", "product": "Drupal", "token": "Drupal", "sources": ["meta:generator", "x-generator"],
     "cpe": "drupal:drupal", "ncsc_names": ["drupal"]},
]
PRODUCT_KEYS = tuple(p["key"] for p in PRODUCTS)

# The NVD asks not to sync more often than this; normally it is once a day.
MIN_INTERVAL = timedelta(hours=2)
SYNC_INTERVAL = timedelta(hours=24)
# lastModStartDate/EndDate may span at most 120 days; past that, start over.
_MAX_INCREMENT = timedelta(days=119)
_OVERLAP = timedelta(hours=1)
_PAGE = 2000
# Pauses between requests: the NVD advises six seconds without a key; with
# one, 50 requests per 30 seconds are allowed.
_PAUSE_WITHOUT_KEY = 6.0
_PAUSE_WITH_KEY = 0.7
_TIMEOUT = 60
_MAX_LISTED = 25
_PATCH_UNKNOWN_HIGH = 999999

_lock = threading.Lock()


# --------------------------------------------------------------- settings

def settings():
    """{"enabled", "ncsc", "max_age_days"} from Admin -> Settings."""
    try:
        import config as domainlens_config
        raw = dict(domainlens_config.load_settings().raw.get("cve_feed") or {})
    except Exception:
        raw = {}
    try:
        max_age = max(1, int(raw.get("max_age_days", 3)))
    except (TypeError, ValueError):
        max_age = 3
    return {"enabled": bool(raw.get("enabled", False)), "ncsc": bool(raw.get("ncsc", True)),
            "max_age_days": max_age}


def enabled():
    return settings()["enabled"]


def _api_key():
    try:
        from settings import api_keys
        return api_keys.resolve(API_KEY_ENV)
    except Exception:
        return ""


def _now():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------- storage

def init_schema(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS cve_items (cve_id TEXT PRIMARY KEY, published TEXT, "
                 "last_modified TEXT, status TEXT, score REAL, severity TEXT, kev_added TEXT, summary TEXT)")
    # One row per range (or exact version) the NVD gives for a followed
    # product. `conditional`: the CVE applies only together with something
    # else (a platform, another component) that a response does not show.
    conn.execute("CREATE TABLE IF NOT EXISTS cve_ranges (cve_id TEXT NOT NULL, product TEXT NOT NULL, "
                 "exact TEXT, start TEXT, start_incl INTEGER NOT NULL DEFAULT 0, end_ TEXT, "
                 "end_incl INTEGER NOT NULL DEFAULT 0, conditional INTEGER NOT NULL DEFAULT 0)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_ranges_product ON cve_ranges(product, cve_id)")
    conn.execute("CREATE TABLE IF NOT EXISTS cve_feed_state (source TEXT PRIMARY KEY, synced_at TEXT, "
                 "cursor TEXT, attempted_at TEXT, error TEXT, items INTEGER)")


def _state(source):
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM cve_feed_state WHERE source = ?", (source,)).fetchone()
    return dict(row) if row else {"source": source, "synced_at": None, "cursor": None, "attempted_at": None,
                                  "error": None, "items": None}


def _save_state(source, **fields):
    current = _state(source)
    current.update(fields)
    with db._lock, db._connect() as conn:
        conn.execute("INSERT OR REPLACE INTO cve_feed_state (source, synced_at, cursor, attempted_at, error, items) "
                     "VALUES (?, ?, ?, ?, ?, ?)",
                     (source, current["synced_at"], current["cursor"], current["attempted_at"], current["error"],
                      current["items"]))


def _parse_time(text):
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(str(text))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------- NVD records

def _score(metrics):
    """(score, severity) from the first CVSS the NVD has: 3.1, 4.0, 3.0, then 2."""
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = (metrics or {}).get(key) or []
        primary = [e for e in entries if e.get("type") == "Primary"] or entries
        if primary:
            data = primary[0].get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or primary[0].get("baseSeverity")
            if score is not None:
                return float(score), str(severity or "").lower() or _severity_of(float(score))
    return None, None


def _severity_of(score):
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def ranges_for(cve, cpe):
    """[(exact, start, start_incl, end, end_incl, conditional)] for one
    product (vendor:product) in an NVD CVE record."""
    vendor, product = cpe.split(":", 1)
    out = []
    for config in cve.get("configurations") or []:
        nodes = config.get("nodes") or []
        together = config.get("operator") == "AND" or len(nodes) > 1
        for node in nodes:
            conditional = together or node.get("operator") == "AND" or bool(node.get("negate"))
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parts = str(match.get("criteria") or "").split(":")
                if len(parts) < 7 or parts[3] != vendor or parts[4] != product:
                    continue
                version, update = parts[5], parts[6]
                if version == "-" or update not in ("*", "-"):
                    # "-" is "no version applies"; an update field is a
                    # pre-release (rc1, beta), which a release is not.
                    continue
                out.append((
                    None if version == "*" else version,
                    match.get("versionStartIncluding") or match.get("versionStartExcluding"),
                    1 if match.get("versionStartIncluding") else 0,
                    match.get("versionEndIncluding") or match.get("versionEndExcluding"),
                    1 if match.get("versionEndIncluding") else 0,
                    1 if conditional else 0,
                ))
    return list(dict.fromkeys(out))


def _item(cve):
    summary = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "") or ""
    score, severity = _score(cve.get("metrics"))
    return (cve.get("id"), cve.get("published"), cve.get("lastModified"), cve.get("vulnStatus"), score, severity,
            cve.get("cisaExploitAdd"), summary[:500])


def _store(product_key, records, full):
    """Write one product's CVEs. A full sync replaces what the product held;
    an increment replaces only the CVEs it carries, and drops rejected ones."""
    with db._lock, db._connect() as conn:
        if full:
            conn.execute("DELETE FROM cve_ranges WHERE product = ?", (product_key,))
        for cve, ranges in records:
            cve_id = cve.get("id")
            if not cve_id:
                continue
            conn.execute("DELETE FROM cve_ranges WHERE product = ? AND cve_id = ?", (product_key, cve_id))
            if cve.get("vulnStatus") == "Rejected":
                continue
            conn.execute("INSERT OR REPLACE INTO cve_items (cve_id, published, last_modified, status, score, "
                         "severity, kev_added, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", _item(cve))
            conn.executemany("INSERT INTO cve_ranges (cve_id, product, exact, start, start_incl, end_, end_incl, "
                             "conditional) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                             [(cve_id, product_key, *r) for r in ranges])
        conn.execute("DELETE FROM cve_items WHERE cve_id NOT IN (SELECT DISTINCT cve_id FROM cve_ranges)")
        return conn.execute("SELECT COUNT(DISTINCT cve_id) AS n FROM cve_ranges WHERE product = ?",
                            (product_key,)).fetchone()["n"]


# --------------------------------------------------------------- sync

def _nvd_time(moment):
    return quote(moment.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"))


def _fetch_product(product, since, now, get, pause):
    """Every CVE record for one product: [(cve, ranges)]."""
    base = f"{NVD_URL}?virtualMatchString={quote('cpe:2.3:a:' + product['cpe'])}&resultsPerPage={_PAGE}"
    if since:
        base += f"&lastModStartDate={_nvd_time(since)}&lastModEndDate={_nvd_time(now)}"
    else:
        base += "&noRejected"
    headers = {"User-Agent": _UA}
    key = _api_key()
    if key:
        headers["apiKey"] = key
    records, start, total = [], 0, None
    while total is None or start < total:
        pause()
        resp = get(f"{base}&startIndex={start}", headers=headers, timeout=_TIMEOUT)
        if resp.status_code in (401, 403) and key:
            raise RuntimeError("The NVD refused the API key (HTTP %d)." % resp.status_code)
        if resp.status_code != 200:
            raise RuntimeError(f"The NVD answered HTTP {resp.status_code}.")
        data = resp.json()
        total = int(data.get("totalResults") or 0)
        page = data.get("vulnerabilities") or []
        for entry in page:
            cve = entry.get("cve") or {}
            records.append((cve, ranges_for(cve, product["cpe"])))
        if not page:
            break
        start += len(page)
    return records


def sync_nvd(products=None, *, get=None, sleep=None, now=None):
    """Bring the followed products up to date. {product key: count or "error: ..."}."""
    import requests
    get = get or requests.get
    sleep = sleep or time.sleep
    now = now or _now()
    wait = _PAUSE_WITH_KEY if _api_key() else _PAUSE_WITHOUT_KEY
    first = [True]

    def pause():
        if not first[0]:
            sleep(wait)
        first[0] = False

    report = {}
    for product in (products or PRODUCTS):
        source = f"nvd:{product['key']}"
        state = _state(source)
        cursor = _parse_time(state.get("cursor"))
        since = cursor - _OVERLAP if cursor and now - cursor < _MAX_INCREMENT else None
        _save_state(source, attempted_at=now.isoformat())
        try:
            records = _fetch_product(product, since, now, get, pause)
            count = _store(product["key"], records, full=since is None)
            _save_state(source, synced_at=now.isoformat(), cursor=now.isoformat(), error=None, items=count)
            report[product["key"]] = count
        except Exception as exc:
            text = str(exc)[:200] or type(exc).__name__
            log.warning("NVD sync for %s failed: %s", product["key"], text)
            _save_state(source, error=text)
            report[product["key"]] = f"error: {text}"
    return report


def sync(*, get=None, sleep=None, now=None):
    """The NVD, then the NCSC-NL advisories when switched on. Refuses to ask
    the NVD again within two hours of the last attempt, button or not."""
    now = now or _now()
    if not enabled():
        return {"started": False, "reason": "The CVE data is switched off (Admin -> Settings -> CVE data (NVD, NCSC-NL))."}
    if not _lock.acquire(blocking=False):
        return {"started": False, "reason": "A sync is already running."}
    try:
        last = last_attempt()
        if last and now - last < MIN_INTERVAL:
            return {"started": False,
                    "reason": "The NVD asks not to be synced more than once every two hours; the last sync "
                              f"started at {last.isoformat(timespec='minutes')}."}
        report = {"nvd": sync_nvd(get=get, sleep=sleep, now=now)}
        if settings()["ncsc"]:
            import ncsc_advisories
            report["ncsc"] = ncsc_advisories.sync(get=get, sleep=sleep, now=now)
        # What changed for the versions monitored domains showed: new CVEs
        # and newly exploited ones become monitor events (cve_alerts.py).
        try:
            import cve_alerts
            report["alerts"] = cve_alerts.recheck(now=now)
        except Exception as exc:
            log.warning("Comparing monitored versions after the sync failed: %s", exc)
            report["alerts"] = None
        return {"started": True, "report": report}
    finally:
        _lock.release()


def last_attempt():
    times = [_parse_time(_state(f"nvd:{p['key']}").get("attempted_at")) for p in PRODUCTS]
    times = [t for t in times if t]
    return max(times) if times else None


def maybe_sync():
    """Called from the scheduler: once a day, when switched on. A product
    that was never fetched -- one an update added -- is fetched at the next
    turn allowed, not a day later."""
    if not enabled() or _lock.locked():
        return None
    last = last_attempt()
    missing = any(not _state(f"nvd:{p['key']}").get("synced_at") for p in PRODUCTS)
    if last and _now() - last < (MIN_INTERVAL if missing else SYNC_INTERVAL):
        return None
    return sync()


def running():
    return _lock.locked()


# --------------------------------------------------------------- freshness

def freshness(now=None, keys=None):
    """{"state": "current" | "stale" | "never" | "off", "synced_at", "max_age_days"}.

    "current" only when every followed product (or every one in `keys`) was
    synced within the setting: one product that has not been fetched is not
    "no CVEs". A comparison asks for its own product only, so a product
    added in an update does not hold up the ones already fetched."""
    cfg = settings()
    if not cfg["enabled"]:
        return {"state": "off", "synced_at": None, "max_age_days": cfg["max_age_days"]}
    now = now or _now()
    times = [_parse_time(_state(f"nvd:{p['key']}").get("synced_at")) for p in PRODUCTS
             if keys is None or p["key"] in keys]
    if not all(times):
        return {"state": "never", "synced_at": None, "max_age_days": cfg["max_age_days"]}
    oldest = min(times)
    current = now - oldest <= timedelta(days=cfg["max_age_days"])
    return {"state": "current" if current else "stale", "synced_at": oldest.isoformat(),
            "max_age_days": cfg["max_age_days"]}


def status():
    """For Admin -> Vulnerability rules: per product when it was synced and what it holds."""
    cfg = settings()
    rows = []
    for product in PRODUCTS:
        state = _state(f"nvd:{product['key']}")
        rows.append({"key": product["key"], "product": product["product"], "synced_at": state.get("synced_at"),
                     "attempted_at": state.get("attempted_at"), "error": state.get("error"),
                     "cves": state.get("items")})
    out = {"enabled": cfg["enabled"], "ncsc_enabled": cfg["ncsc"], "max_age_days": cfg["max_age_days"],
           "api_key": bool(_api_key()), "running": running(), "freshness": freshness(), "products": rows,
           "attribution": ATTRIBUTION}
    if cfg["ncsc"]:
        import ncsc_advisories
        out["ncsc"] = ncsc_advisories.status()
    return out


# --------------------------------------------------------------- versions

_NUMERIC = re.compile(r"^\d+(?:\.\d+)*$")
_LETTERED = re.compile(r"^(\d+(?:\.\d+)*)([a-z])$", re.I)


def _version(text, letters=False):
    """(1, 1, 1) from "1.1.1"; with `letters`, OpenSSL's "1.1.1w" is
    (1, 1, 1, 23), after 1.1.1 and every lettered release before it."""
    text = str(text or "").strip()
    if _NUMERIC.match(text):
        return tuple(int(n) for n in text.split("."))
    found = _LETTERED.match(text) if letters else None
    if found:
        return tuple(int(n) for n in found.group(1).split(".")) + (ord(found.group(2).lower()) - 96,)
    return None


def _cmp(a, b):
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


class _Range:
    def __init__(self, row, letters=False):
        self.exact = row["exact"]
        self.start, self.start_incl = row["start"], bool(row["start_incl"])
        self.end, self.end_incl = row["end_"], bool(row["end_incl"])
        self.conditional = bool(row["conditional"])
        self.exact_v = _version(self.exact, letters) if self.exact else None
        self.start_v = _version(self.start, letters) if self.start else None
        self.end_v = _version(self.end, letters) if self.end else None

    def usable(self):
        """A range a version can be compared with: numbers only, and not
        "every version ever" (a CVE record with no bounds at all)."""
        if self.exact:
            return self.exact_v is not None
        if not self.start and not self.end:
            return False
        return (not self.start or self.start_v is not None) and (not self.end or self.end_v is not None)

    def contains(self, version):
        if self.exact:
            return _cmp(version, self.exact_v) == 0
        if self.start:
            c = _cmp(version, self.start_v)
            if c < 0 or (c == 0 and not self.start_incl):
                return False
        if self.end:
            c = _cmp(version, self.end_v)
            if c > 0 or (c == 0 and not self.end_incl):
                return False
        return True

    def bounds_in(self, branch):
        return [v for v in (self.exact_v, self.start_v, self.end_v) if v and tuple(v[:2]) == branch]


def _hits(rng, shown):
    """("yes" | "maybe" | "no") for one range and the version shown."""
    if shown["patch_known"]:
        return "yes" if rng.contains(shown["version"]) else "no"
    major, minor = shown["version"][:2]
    low, high = (major, minor, 0), (major, minor, _PATCH_UNKNOWN_HIGH)
    if rng.contains(low) and rng.contains(high) and not rng.exact:
        return "yes"
    probes = [low, high]
    for bound in rng.bounds_in((major, minor)):
        patch = bound[2] if len(bound) > 2 else 0
        probes += [(major, minor, patch), (major, minor, max(0, patch - 1)), (major, minor, patch + 1)]
    return "maybe" if any(rng.contains(p) for p in probes) else "no"


def _fmt(version, letters=False):
    """A version as written; with `letters`, a fourth number is OpenSSL's
    patch letter (1.1.1w)."""
    if letters and len(version) == 4 and 1 <= version[3] <= 26:
        return ".".join(str(n) for n in version[:3]) + chr(96 + version[3])
    return ".".join(str(n) for n in version)


# --------------------------------------------------------------- assessment

def readers():
    """The followed products as version readers, or [] when switched off."""
    if not enabled():
        return []
    import software_advisories as engine
    # The same signs of use without a version as the PHP2Shell rule: the
    # rule said "PHP in use" from a PHPSESSID cookie while the CVE data, not
    # knowing the cookie, left PHP out of the same result.
    return [{**p, **engine.reader(p["token"], p["sources"], p.get("seen_cookies", ()), p.get("seen_paths", ()))}
            for p in PRODUCTS]


def _letters(product_key):
    import software_advisories as engine
    product = next((p for p in PRODUCTS if p["key"] == product_key), None)
    return bool(product) and "letters" in engine.traits(product["token"])


def _ranges(product_key):
    with db._connect() as conn:
        rows = conn.execute("SELECT r.*, i.score, i.severity, i.kev_added, i.published, i.summary "
                            "FROM cve_ranges r JOIN cve_items i ON i.cve_id = r.cve_id "
                            "WHERE r.product = ?", (product_key,)).fetchall()
    by_cve, letters = {}, _letters(product_key)
    for row in rows:
        entry = by_cve.setdefault(row["cve_id"], {"cve": row["cve_id"], "score": row["score"],
                                                  "severity": row["severity"], "kev": bool(row["kev_added"]),
                                                  "kev_added": row["kev_added"], "published": row["published"],
                                                  "summary": row["summary"], "ranges": []})
        entry["ranges"].append(_Range(row, letters))
    return by_cve


def _rank(cve):
    return (not cve["kev"], -(cve["score"] or 0), cve["cve"])


def _fixed_in(applicable, shown, letters=False):
    """The release in the shown branch that leaves every applicable CVE
    behind, or None when one of them has no fix in this branch."""
    branch = shown["version"][:2]
    target = None
    for cve in applicable:
        ends = [r for r in cve["ranges"] if r.usable() and not r.exact and r.contains(shown["version"])]
        if not ends:
            return None
        for rng in ends:
            if not rng.end_v or rng.end_incl or tuple(rng.end_v[:2]) != branch:
                return None
            target = rng.end_v if target is None or _cmp(rng.end_v, target) > 0 else target
    return _fmt(target, letters) if target else None


def _release(version):
    """A version as an advisory rule's major.minor.patch, or None."""
    if not version or len(version) < 2 or len(version) > 3:
        return None
    return tuple(version) + (0,) * (3 - len(version))


def fix_releases(product_key, cve_ids):
    """What the NVD data says about some CVEs of one product, in the shape of
    an advisory rule: the release with the fix per branch, and the release the
    oldest of them came in with.

    An NCSC-NL advisory names its CVEs but no versions, so a rule started from
    one had nothing to compare a version with until the admin looked every
    release up. {"cves": the ones the NVD lists for the product, in the order
    given; "fixed": newest branch first; "introduced": "" when a range has no
    start; "without_fix": CVEs with a range the NVD gives no fixed release
    for, which the admin still has to check}.
    """
    by_cve = _ranges(product_key)
    listed, without_fix, fixed, starts = [], [], {}, []
    every_start = True
    for cve_id in dict.fromkeys(str(c).upper() for c in cve_ids):
        ranges = [r for r in (by_cve.get(cve_id) or {}).get("ranges", []) if not r.conditional and r.usable()]
        if not ranges:
            continue
        listed.append(cve_id)
        for rng in ranges:
            end = _release(rng.end_v)
            if rng.exact or rng.end_incl or end is None:
                # An exact version or an inclusive end says where the flaw
                # is, not which release left it behind.
                if cve_id not in without_fix:
                    without_fix.append(cve_id)
                continue
            branch = end[:2]
            if branch not in fixed or end > fixed[branch]:
                fixed[branch] = end
            start = _release(rng.start_v)
            if start is None:
                every_start = False
            else:
                starts.append(start)
    introduced = min(starts) if every_start and starts else None
    if introduced and fixed and introduced >= max(fixed.values()):
        introduced = None
    return {"cves": listed, "fixed": [_fmt(fixed[b]) for b in sorted(fixed, reverse=True)],
            "introduced": _fmt(introduced) if introduced else "", "without_fix": without_fix}


def _split(product_key, shown):
    """(applicable, uncertain, not_versioned) for a version shown: the CVEs
    whose ranges take it in, the ones that may, and how many have no
    versions to compare with. A distribution build has none applicable:
    its package may carry the fixes without a new number."""
    applicable, uncertain, not_versioned = [], [], 0
    for cve in _ranges(product_key).values():
        usable = [r for r in cve["ranges"] if r.usable()]
        if not usable:
            not_versioned += 1
            continue
        verdicts = [("maybe" if r.conditional and hit == "yes" else hit) for r in usable for hit in [_hits(r, shown)]]
        if "yes" in verdicts:
            applicable.append(cve)
        elif "maybe" in verdicts:
            uncertain.append(cve)
    if shown["vendor"] and applicable:
        uncertain, applicable = applicable + uncertain, []
    applicable.sort(key=_rank)
    uncertain.sort(key=_rank)
    return applicable, uncertain, not_versioned


def assess_product(product, shown, *, fresh=None, partial=None):
    """One followed product as a response shows it.

    {"product", "key", "state": "vulnerable" | "no_known_cves" |
    "cannot_tell" | "unmeasured", "version", "reason", "cves": [...],
    "counts": {...}, "fixed_in", "synced_at", "distribution"}"""
    fresh = fresh or freshness(keys=[product["key"]])
    base = {"product": product["product"], "key": product["key"], "version": shown["raw"] if shown else None,
            "cves": [], "counts": {"applicable": 0, "uncertain": 0, "exploited": 0, "not_versioned": 0},
            "fixed_in": None, "synced_at": fresh.get("synced_at"),
            # Kept so a later comparison (cve_alerts.py) need not read the
            # version again from its text, which does not show "beside".
            "distribution": bool(shown and shown["vendor"])}
    if not shown and partial:
        # "Drupal 11": shown, but not which release, so not comparable.
        return {**base, "version": partial, "state": "cannot_tell",
                "reason": f"{partial} shows only its major version, not the release, so it cannot be compared "
                          "with the known CVEs."}
    if not shown:
        # First: without a version nothing could be compared, however
        # current the data is.
        return {**base, "state": "unmeasured",
                "reason": f"{product['product']} is in use but its version is not shown."}
    if fresh["state"] in ("never", "stale"):
        why = ("has not been fetched yet" if fresh["state"] == "never"
               else f"is older than {fresh['max_age_days']} days")
        return {**base, "state": "unmeasured",
                "reason": f"The CVE data {why}, so the {product['product']} version was not compared."}

    applicable, uncertain, not_versioned = _split(product["key"], shown)
    raw = shown["raw"]
    listed = applicable or uncertain
    counts = {"applicable": len(applicable), "uncertain": len(uncertain),
              "exploited": sum(1 for c in listed if c["kev"]), "not_versioned": not_versioned}
    cves = [{k: c[k] for k in ("cve", "score", "severity", "kev", "kev_added", "published", "summary")}
            for c in listed[:_MAX_LISTED]]
    out = {**base, "cves": cves, "counts": counts}
    if applicable:
        exploited = f", {counts['exploited']} of them exploited (CISA KEV)" if counts["exploited"] else ""
        return {**out, "state": "vulnerable", "fixed_in": _fixed_in(applicable, shown, _letters(product["key"])),
                "reason": f"{raw} is inside the affected versions of {len(applicable)} known CVE(s){exploited}."}
    if uncertain:
        if shown.get("beside"):
            why = (f"is named beside a distribution build {shown['beside']} in the same header; that "
                   "distribution's package may carry the fixes without a new number")
        elif shown["vendor"]:
            why = "is a distribution build; its package may carry the fixes without a new number"
        elif not shown["patch_known"]:
            why = "does not show its patch release"
        else:
            why = "matches CVEs that apply only together with a platform or component a response does not show"
        return {**out, "state": "cannot_tell",
                "reason": f"{raw} {why}. {len(uncertain)} known CVE(s) may apply."}
    return {**out, "state": "no_known_cves",
            "reason": f"No CVE the NVD has analysed names {raw}. CVEs not analysed yet are not included."}


def assess(headers, generator=None, cookies="", url="", page=None):
    """[assessment] for each followed product the response shows, or None
    when the CVE data is switched off (not applicable)."""
    products = readers()
    if not products:
        return None
    import software_advisories as engine
    out = []
    for product in products:
        shown, partial, read_from = engine.read_version(product, headers, generator, page, url)
        if not shown and not partial and not engine.seen(product, headers, cookies, url, generator, page):
            continue
        found = assess_product(product, shown, partial=partial)
        if read_from:
            found["reason"] += engine.read_from_text(read_from)
            found["read_from"] = read_from
        out.append(found)
    return _with_ncsc(out)


def _with_ncsc(assessments):
    """Add the NCSC-NL advisories that name the listed CVEs."""
    if not assessments or not settings()["ncsc"]:
        return assessments
    try:
        import ncsc_advisories
        found = ncsc_advisories.for_cves({c["cve"] for a in assessments for c in a["cves"]})
    except Exception:
        log.debug("NCSC-NL lookup failed", exc_info=True)
        return assessments
    for assessment in assessments:
        seen = {}
        for cve in assessment["cves"]:
            for adv in found.get(cve["cve"], []):
                seen.setdefault(adv["id"], adv)
        assessment["ncsc"] = list(seen.values())[:10]
    return assessments


# --------------------------------------------------------------- findings

def _finding_severity(assessment):
    scores = [c["score"] for c in assessment["cves"] if c.get("score") is not None]
    severity = _severity_of(max(scores)) if scores else "medium"
    if assessment["counts"]["exploited"] and severity in ("medium", "low"):
        # Exploited in the wild outranks a modest score.
        severity = "high"
    return severity


def _ncsc_text(assessment):
    advisories = assessment.get("ncsc") or []
    if not advisories:
        return ""
    # One advisory named in full, in a sentence of its own that translates
    # as a whole; the rest counted.
    first = advisories[0]
    text = (f" NCSC-NL: {first['id']} (likelihood {first.get('kans') or 'not given'}, "
            f"damage {first.get('schade') or 'not given'}).")
    if len(advisories) > 1:
        text += f" {len(advisories) - 1} more NCSC-NL advisories name these CVEs."
    return text


def _evidence(assessment):
    ids = [c["cve"] + (" (KEV)" if c["kev"] else "") for c in assessment["cves"][:10]]
    more = (assessment["counts"]["applicable"] or assessment["counts"]["uncertain"]) - len(ids)
    return ", ".join(ids) + (f" and {more} more" if more > 0 else "")


def finding(assessment):
    """The scan finding for one product, or None when there is nothing the
    operator can act on: no known CVEs, or a version that is not shown."""
    state = assessment.get("state")
    product, version = assessment["product"], assessment.get("version")
    if state == "vulnerable":
        counts = assessment["counts"]
        exploited = f", {counts['exploited']} exploited" if counts["exploited"] else ""
        fix = (f"Update {product} to {assessment['fixed_in']} or later (or the patched package from your vendor)."
               if assessment.get("fixed_in") else
               f"Update {product} to a current release of a branch that still gets fixes (or the patched package "
               "from your vendor).")
        return {"severity": _finding_severity(assessment),
                "title": f"{version}: {counts['applicable']} known CVE(s){exploited}",
                "detail": assessment["reason"] + _ncsc_text(assessment) + " " + ATTRIBUTION,
                "fix": fix, "evidence": _evidence(assessment)}
    if state == "cannot_tell" and assessment["cves"]:
        return {"severity": "info",
                "title": f"{version}: known CVEs may apply, not visible from outside",
                "detail": assessment["reason"] + _ncsc_text(assessment) + " " + ATTRIBUTION,
                "fix": f"On the server: the installed {product} version or package, against the CVEs listed.",
                "evidence": _evidence(assessment)}
    if state == "unmeasured" and version:
        return {"severity": "info",
                "title": f"{version}: not compared with known CVEs",
                "detail": assessment["reason"],
                "fix": "Admin -> Vulnerability rules: sync the CVE data, or check why the last sync failed.",
                "evidence": version}
    return None


def stored_cves(product_key):
    """For tests and the admin page: the CVE ids kept for a product."""
    with db._connect() as conn:
        return sorted(r["cve_id"] for r in conn.execute(
            "SELECT DISTINCT cve_id FROM cve_ranges WHERE product = ?", (product_key,)).fetchall())



def _reaches(rng, release):
    """Whether a range takes in the release or anything later in its branch:
    "no known CVE from 1.4.67" must hold for 1.4.80 too."""
    upper = (release[0], release[1] + 1, 0)
    if rng.exact:
        return _cmp(rng.exact_v, release) >= 0 and _cmp(rng.exact_v, upper) < 0
    if rng.end_v is not None:
        c = _cmp(rng.end_v, release)
        if c < 0 or (c == 0 and not rng.end_incl):
            return False
    return rng.start_v is None or _cmp(rng.start_v, upper) < 0


def overview(branches=4):
    """Per followed product what the CVE data holds, for Tools -> Versions:
    the CVEs kept, how many are exploited (CISA KEV), the newest CVE, and per
    branch the first release none of the known CVEs applies to.

    That release is checked against every range, not just taken from the
    highest fix: a branch with a CVE in a later release, or one with no fix
    yet, gets no release, so it is never offered as safe."""
    out = []
    for product in PRODUCTS:
        by_cve = _ranges(product["key"])
        ranges = [r for cve in by_cve.values() for r in cve["ranges"] if r.usable() and not r.conditional]
        candidates = {}
        for rng in ranges:
            end = _release(rng.end_v) if rng.end and not rng.end_incl and not rng.exact else None
            if end and end > candidates.get(end[:2], (0,)):
                candidates[end[:2]] = end
        clean = [end for _, end in sorted(candidates.items(), reverse=True)
                 if not any(_reaches(r, end) for r in ranges)][:branches]
        newest = max(by_cve.values(), key=lambda c: (c["published"] or "", c["cve"]), default=None)
        out.append({"key": product["key"], "product": product["product"], "cves": len(by_cve),
                    "exploited": sum(1 for c in by_cve.values() if c["kev"]),
                    # CVEs the NVD lists without versions: they cannot rule a
                    # release in or out, so the page says how many there are.
                    "not_versioned": sum(1 for c in by_cve.values() if not any(r.usable() for r in c["ranges"])),
                    "clean_from": [_fmt(v) for v in clean],
                    "newest": None if newest is None else {
                        "cve": newest["cve"], "published": (newest["published"] or "")[:10],
                        "score": newest["score"], "kev": newest["kev"]}})
    return out
