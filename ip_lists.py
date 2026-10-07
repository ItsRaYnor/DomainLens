"""IP threat lists, downloaded from their maintainers and searched locally.

The DNS blocklists ask their operator about every address, one query each,
and the Spamhaus zones answer nothing through a public resolver without a
key. These lists are fetched whole from the maintainer's own site, a few
times a day, and searched on this server: no address that is checked leaves
it.

Built in, from the official source:

  * Spamhaus DROP (IPv4 and IPv6): netblocks Spamhaus advises not to route
    or peer with -- hijacked ranges and networks run by criminals. Free for
    any use with credit to The Spamhaus Project; fetched no more than once an
    hour (we fetch every twelve). On by default.
  * DShield Recommended Block List (SANS Internet Storm Center): the twenty
    /24 networks that scanned the most targets in the past three days.
    Commercial use is allowed with attribution and without resale, but the
    file itself carries a non-commercial licence, so it is off until an admin
    switches it on.

An admin can add lists of their own: one IP or CIDR per line.

Only public addresses are looked up: a private or reserved address is "not
public", never "not listed". Every answer keeps its state: listed, not
listed, not checked (no list loaded), not public.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
from datetime import datetime, timedelta, timezone

import db

log = logging.getLogger("domainlens.iplists")

_MAX_BYTES = 32 * 1024 * 1024
_MAX_RANGES = 2_000_000
_EVERY = timedelta(hours=12)
_lock = threading.Lock()

SPAMHAUS = "Spamhaus DROP"
DSHIELD = "DShield block list (SANS ISC)"

# name -> (setting, default, [official URLs], parser, credit)
BUILT_IN = {
    SPAMHAUS: ("spamhaus_drop", True,
               ["https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"],
               "spamhaus", "© The Spamhaus Project SLU"),
    DSHIELD: ("dshield", False, ["https://feeds.dshield.org/block.txt"],
              "dshield", "SANS Technology Institute, Internet Storm Center, https://isc.sans.edu"),
}


def init_schema(conn):
    # Addresses as fixed-width hex, so a text comparison orders them: 8
    # digits for IPv4, 32 for IPv6 (an IPv6 address does not fit an integer).
    conn.execute("CREATE TABLE IF NOT EXISTS ip_list_ranges (version INTEGER NOT NULL, first TEXT NOT NULL, "
                 "last TEXT NOT NULL, source TEXT NOT NULL, detail TEXT)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_list_first ON ip_list_ranges(version, first)")
    conn.execute("CREATE TABLE IF NOT EXISTS ip_list_meta (source TEXT PRIMARY KEY, refreshed_at TEXT, "
                 "entries INTEGER, error TEXT)")


def _now():
    return datetime.now(timezone.utc)


def _settings():
    import config as domainlens_config
    return dict(domainlens_config.load_settings().raw.get("ip_lists") or {})


def _hex(address):
    return format(int(address), "08x" if address.version == 4 else "032x")


# --------------------------------------------------------------- parsing

def _network(text):
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None


def parse(kind, text):
    """[(network, detail)] from a list in its maintainer's format."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if kind == "spamhaus":
            # One JSON object per line; the last one is metadata.
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            net = _network(entry.get("cidr") or "") if isinstance(entry, dict) else None
            if net:
                out.append((net, entry.get("sblid") or ""))
        elif kind == "dshield":
            # start, end, prefix length, targets, name, country, contact.
            cols = line.split("\t")
            if len(cols) >= 3 and cols[2].strip().isdigit():
                net = _network(f"{cols[0]}/{cols[2]}")
                if net:
                    out.append((net, " ".join(c.strip() for c in cols[4:6] if c.strip())))
        else:
            # One address or CIDR per line, with an optional "; comment".
            net = _network(line.split(";", 1)[0].split("#", 1)[0].split()[0] if line.split() else "")
            if net:
                out.append((net, ""))
        if len(out) >= _MAX_RANGES:
            break
    return out


# --------------------------------------------------------------- sources

def configured_sources():
    """[(name, [urls], kind)]: the built-in lists switched on, then the admin's own."""
    settings = _settings()
    out = []
    for name, (key, default, urls, kind, _) in BUILT_IN.items():
        if settings.get(key, default):
            out.append((name, urls, kind))
    for line in settings.get("custom_lists") or []:
        line = str(line).strip()
        if line:
            out.append((line, [line], "plain"))
    return out


def credit(name):
    return BUILT_IN[name][4] if name in BUILT_IN else ""


def refresh(sources=None, *, get=None):
    """Download each list whole from its maintainer and replace what it held."""
    import requests
    sources = sources if sources is not None else configured_sources()
    get = get or (lambda url: requests.get(url, headers={"User-Agent": "DomainLens"}, timeout=60, stream=True))
    report = {}
    with _lock:
        for name, urls, kind in sources:
            try:
                ranges = []
                for url in urls:
                    if not str(url).startswith("https://"):
                        raise ValueError("only https:// lists are fetched")
                    resp = get(url)
                    resp.raise_for_status()
                    body = b""
                    for chunk in resp.iter_content(1 << 20):
                        body += chunk
                        if len(body) > _MAX_BYTES:
                            raise ValueError("list larger than 32 MB")
                    ranges += parse(kind, body.decode("utf-8", "replace"))
                if not ranges:
                    raise ValueError("the list held no addresses")
                rows = [(net.version, _hex(net.network_address), _hex(net.broadcast_address), name, detail[:100])
                        for net, detail in ranges]
                with db._lock, db._connect() as conn:
                    conn.execute("DELETE FROM ip_list_ranges WHERE source = ?", (name,))
                    conn.executemany("INSERT INTO ip_list_ranges (version, first, last, source, detail) "
                                     "VALUES (?, ?, ?, ?, ?)", rows)
                    conn.execute("INSERT OR REPLACE INTO ip_list_meta (source, refreshed_at, entries, error) "
                                 "VALUES (?, ?, ?, NULL)", (name, _now().isoformat(), len(rows)))
                report[name] = len(rows)
            except Exception as exc:
                text = str(exc)[:200]
                with db._lock, db._connect() as conn:
                    conn.execute("INSERT INTO ip_list_meta (source, error) VALUES (?, ?) "
                                 "ON CONFLICT(source) DO UPDATE SET error = excluded.error", (name, text))
                report[name] = f"error: {text}"
        names = [name for name, _, _ in sources]
        with db._lock, db._connect() as conn:
            marks = ",".join("?" * len(names)) or "''"
            conn.execute(f"DELETE FROM ip_list_ranges WHERE source NOT IN ({marks})", names)
            conn.execute(f"DELETE FROM ip_list_meta WHERE source NOT IN ({marks})", names)
    return report


def status():
    """[{source, refreshed_at, entries, error, credit}] for the lists in use."""
    names = [name for name, _, _ in configured_sources()]
    with db._connect() as conn:
        rows = {r["source"]: dict(r) for r in conn.execute("SELECT * FROM ip_list_meta").fetchall()}
    return [{**rows.get(n, {"source": n, "refreshed_at": None, "entries": None, "error": None}),
             "credit": credit(n)} for n in names]


def maybe_refresh():
    """Called from the scheduler: refresh lists older than twelve hours."""
    due = [s for s in status()
           if not s.get("refreshed_at") or _now() - datetime.fromisoformat(s["refreshed_at"]) > _EVERY]
    if due and not _lock.locked():
        refresh()


def _public(address):
    return address.is_global


def check(ip):
    """{"state": "listed" | "not_listed" | "not_checked" | "not_public",
        "lists": [{"source", "detail", "credit"}]}"""
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return {"state": "not_checked", "lists": []}
    if not _public(address):
        return {"state": "not_public", "lists": []}
    value = _hex(address)
    with db._connect() as conn:
        loaded = conn.execute("SELECT COUNT(*) AS n FROM ip_list_meta WHERE entries IS NOT NULL").fetchone()["n"]
        if not loaded:
            return {"state": "not_checked", "lists": []}
        rows = conn.execute("SELECT DISTINCT source, detail FROM ip_list_ranges "
                            "WHERE version = ? AND first <= ? AND last >= ?",
                            (address.version, value, value)).fetchall()
    lists = [{"source": r["source"], "detail": r["detail"] or "", "credit": credit(r["source"])} for r in rows]
    return {"state": "listed" if lists else "not_listed", "lists": lists}
