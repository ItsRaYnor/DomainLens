"""NCSC-NL security advisories: a second opinion beside the NVD, not a source of matches.

The NCSC publishes its advisories as CSAF 2.0 documents at
advisories.ncsc.nl, public, without a key. Each names the CVEs it is about
and its own judgement of them: "kans" (likelihood) and "schade" (damage),
low / medium / high. What it does not give is a version a response can be
compared with: products are free text, and the versions are "vers:unknown/*".
So nothing is matched on them here.

Two uses instead:

  * A CVE finding (cve_feed.py) names the NCSC advisories about its CVEs,
    with their kans and schade, so a Dutch reader sees the NCSC's view.
  * An advisory about a product DomainLens follows is offered on Admin ->
    Vulnerability rules as the start of a rule, with its CVEs and a link filled in.
    The administrator adds the releases with the fix; nothing is guessed.

Fetched incrementally: changes.csv lists every advisory with the moment it
last changed, and only the ones changed since the last sync are read, the
first time the last 90 days. Each is checked against its published SHA-512
before it is used.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone

import db

log = logging.getLogger("domainlens.ncsc")

BASE = "https://advisories.ncsc.nl/csaf/v2/"
ADVISORY_URL = "https://advisories.ncsc.nl/advisory?id={id}"
SOURCE = "ncsc"
_FIRST_WINDOW = timedelta(days=90)
_MAX_PER_RUN = 400
_PAUSE = 0.3
_TIMEOUT = 30
_MAX_BYTES = 8 * 1024 * 1024
_PATH = re.compile(r"^\d{4}/ncsc-\d{4}-\d{4,6}\.json$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_UA = "DomainLens-CVE/1.0 (+https://github.com/ItsRaYnor/DomainLens)"
_LEVELS = ("low", "medium", "high")


def init_schema(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS ncsc_advisories (id TEXT PRIMARY KEY, title TEXT, kans TEXT, "
                 "schade TEXT, products TEXT, cves TEXT, facts TEXT, published TEXT, updated TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS ncsc_cves (cve_id TEXT NOT NULL, advisory_id TEXT NOT NULL, "
                 "PRIMARY KEY (cve_id, advisory_id))")


def _now():
    return datetime.now(timezone.utc)


def _parse_time(text):
    try:
        moment = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _get_bytes(get, url):
    resp = get(url, headers={"User-Agent": _UA}, timeout=_TIMEOUT)
    if resp.status_code != 200:
        raise RuntimeError(f"advisories.ncsc.nl answered HTTP {resp.status_code} for {url.rsplit('/', 1)[-1]}.")
    body = resp.content
    if len(body) > _MAX_BYTES:
        raise RuntimeError("An NCSC-NL file was larger than 8 MB.")
    return body


def changes(text):
    """[(path, changed_at)] from changes.csv, oldest first; anything that is
    not an advisory path is left out."""
    out = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2 or not _PATH.match(row[0].strip()):
            continue
        moment = _parse_time(row[1].strip())
        if moment:
            out.append((row[0].strip(), moment))
    return sorted(out, key=lambda item: item[1])


def _level(value):
    value = str(value or "").strip().lower()
    return value if value in _LEVELS else None


def parse(document):
    """The parts of one CSAF advisory DomainLens uses."""
    doc = document.get("document") or {}
    tracking = doc.get("tracking") or {}
    notes = {str(n.get("title") or "").strip().lower(): n.get("text") for n in doc.get("notes") or []}
    products = []

    def walk(branches, vendor=""):
        for branch in branches or []:
            category, name = branch.get("category"), str(branch.get("name") or "").strip()
            if category == "vendor":
                walk(branch.get("branches"), name)
            elif category == "product_name":
                products.append({"vendor": vendor, "product": name})
            else:
                walk(branch.get("branches"), vendor)

    walk((document.get("product_tree") or {}).get("branches"))
    cves = []
    for vuln in document.get("vulnerabilities") or []:
        cve = str(vuln.get("cve") or "").strip().upper()
        if _CVE.match(cve) and cve not in cves:
            cves.append(cve)
    advisory_id = str(tracking.get("id") or "").strip().upper()
    return {"id": advisory_id, "title": str(doc.get("title") or "").strip()[:300],
            "kans": _level(notes.get("kans")), "schade": _level(notes.get("schade")),
            "products": products[:50], "cves": cves[:500], "facts": str(notes.get("feiten") or "")[:600],
            "published": tracking.get("initial_release_date"), "updated": tracking.get("current_release_date"),
            "url": ADVISORY_URL.format(id=advisory_id)}


def _store(advisory):
    with db.transaction() as conn:
        conn.execute("INSERT OR REPLACE INTO ncsc_advisories (id, title, kans, schade, products, cves, facts, "
                     "published, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (advisory["id"], advisory["title"], advisory["kans"], advisory["schade"],
                      json.dumps(advisory["products"]), json.dumps(advisory["cves"]), advisory["facts"],
                      advisory["published"], advisory["updated"]))
        conn.execute("DELETE FROM ncsc_cves WHERE advisory_id = ?", (advisory["id"],))
        conn.executemany("INSERT OR IGNORE INTO ncsc_cves (cve_id, advisory_id) VALUES (?, ?)",
                         [(cve, advisory["id"]) for cve in advisory["cves"]])


def sync(*, get=None, sleep=None, now=None):
    """Read the advisories changed since the last sync. Returns how many,
    or "error: ..."; the cursor only moves past advisories that were read,
    so one that failed is asked again next time."""
    import cve_feed
    import requests
    get = get or requests.get
    sleep = sleep or time.sleep
    now = now or _now()
    state = cve_feed._state(SOURCE)
    cursor = _parse_time(state.get("cursor")) or (now - _FIRST_WINDOW)
    cve_feed._save_state(SOURCE, attempted_at=now.isoformat())
    read = 0
    try:
        listing = changes(_get_bytes(get, BASE + "changes.csv").decode("utf-8", "replace"))
        for path, changed_at in [item for item in listing if item[1] > cursor][:_MAX_PER_RUN]:
            sleep(_PAUSE)
            body = _get_bytes(get, BASE + path)
            published_hash = _get_bytes(get, BASE + path + ".sha512").decode("ascii", "replace").split()
            if not published_hash or hashlib.sha512(body).hexdigest() != published_hash[0].lower():
                raise RuntimeError(f"{path} does not match its published SHA-512; not used.")
            advisory = parse(json.loads(body.decode("utf-8")))
            if advisory["id"]:
                _store(advisory)
            read += 1
            cursor = changed_at
            cve_feed._save_state(SOURCE, cursor=cursor.isoformat())
        with db._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS n FROM ncsc_advisories").fetchone()["n"]
        cve_feed._save_state(SOURCE, synced_at=now.isoformat(), error=None, items=total)
        return read
    except Exception as exc:
        text = str(exc)[:200] or type(exc).__name__
        log.warning("NCSC-NL sync failed: %s", text)
        cve_feed._save_state(SOURCE, error=text)
        return f"error: {text}"


def status():
    import cve_feed
    state = cve_feed._state(SOURCE)
    return {"synced_at": state.get("synced_at"), "attempted_at": state.get("attempted_at"),
            "error": state.get("error"), "advisories": state.get("items")}


def _row(row):
    return {"id": row["id"], "title": row["title"], "kans": row["kans"], "schade": row["schade"],
            "url": ADVISORY_URL.format(id=row["id"])}


def for_cves(cve_ids):
    """{cve: [{"id", "title", "kans", "schade", "url"}]} for the CVEs given."""
    cve_ids = [c for c in cve_ids if _CVE.match(str(c))]
    if not cve_ids:
        return {}
    out = {}
    with db._connect() as conn:
        for start in range(0, len(cve_ids), 500):
            chunk = cve_ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            rows = conn.execute(f"SELECT c.cve_id, a.* FROM ncsc_cves c JOIN ncsc_advisories a "
                                f"ON a.id = c.advisory_id WHERE c.cve_id IN ({marks}) ORDER BY a.id DESC",
                                chunk).fetchall()
            for row in rows:
                out.setdefault(row["cve_id"], []).append(_row(row))
    return out


def _word(needle, text):
    return re.search(r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])", text) is not None


def _followed(products):
    import cve_feed
    out = []
    for product in cve_feed.PRODUCTS:
        for entry in products:
            name = entry.get("product", "").lower()
            vendor = product.get("ncsc_vendor")
            if vendor and not _word(vendor, f"{entry.get('vendor', '')} {name}".lower()):
                continue
            if any(_word(alias, name) for alias in product["ncsc_names"]):
                out.append(product)
                break
    return out


def _severity(kans, schade):
    if schade == "high" and kans == "high":
        return "critical"
    if schade == "high" or kans == "high":
        return "high"
    return "medium"


def candidates(existing_ids=(), limit=50):
    """NCSC advisories about a followed product, each with a rule to start
    from. The advisory gives no versions a response can be compared with, so
    the releases with the fix come from the NVD data for its CVEs; where the
    NVD lists none of them for the product, they are left for the admin."""
    import cve_feed
    existing = {str(i).lower() for i in existing_ids}
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM ncsc_advisories ORDER BY updated DESC").fetchall()
    out = []
    for row in rows:
        products = json.loads(row["products"] or "[]")
        cves = json.loads(row["cves"] or "[]")
        if not cves:
            continue
        for product in _followed(products):
            rule_id = f"{row['id'].lower()}-{product['key']}"[:40]
            published = (row["published"] or "")[:10]
            nvd = cve_feed.fix_releases(product["key"], cves)
            out.append({
                **_row(row), "product": product["product"], "cves": cves[:20], "cve_count": len(cves),
                "updated": row["updated"], "rule_added": rule_id in existing,
                "nvd": {"listed": len(nvd["cves"]), "fixed": nvd["fixed"], "without_fix": nvd["without_fix"][:10]},
                "rule": {"id": rule_id, "name": row["title"][:80], "product": product["product"],
                         "token": product["token"], "sources": product["sources"],
                         # The CVEs the NVD knows for this product, when it
                         # knows any: an advisory about a suite names many
                         # that are not this product's.
                         "cves": (nvd["cves"] or cves)[:20],
                         "severity": _severity(row["kans"], row["schade"]), "published": published,
                         "summary": (row["facts"] or row["title"])[:600], "fixed": nvd["fixed"],
                         "introduced": nvd["introduced"],
                         "references": [ADVISORY_URL.format(id=row["id"])]},
            })
            if len(out) >= limit:
                return out
    return out
