"""The domains you hold: where each is registered, until when, and in what state.

The watchlist is for domains someone wants; this is for the ones an
organisation already has, often hundreds spread over several registrars and
business units. Each domain sits in a group (a company or a department) that
may name the registrar its domains are supposed to be at; a domain that is
registered elsewhere is marked "to move", so a consolidation can be tracked
to the end.

Every domain is looked up over RDAP on a schedule -- daily, every six hours
once its registration ends within a month, hourly while it is being deleted
-- through the same per-registry pacing as the batch lookup, so a large
portfolio never gets this server blocked. A change of phase, registrar,
reseller or name servers is recorded and sent through the notification
channels, as is an approaching expiry.

Three states, kept apart as elsewhere: a lookup that failed keeps the last
known answer and says it is stale; it is never shown as "not registered",
and a missing expiry date for .nl (SIDN publishes none: the registrar renews
until the holder cancels) is "not published", not "unknown".
"""

from __future__ import annotations

import csv
import io
import json
import re
import threading
from datetime import date, datetime, timedelta, timezone

import db
import whois_batch

MAX_DOMAINS = 2000
_PER_RUN = 30
_run_lock = threading.Lock()

EXPIRY_WARN_DAYS = (30, 7)      # one notification at each threshold per term
_SOON = timedelta(days=30)

PHASE_TEXT = {
    "registered": "Registered",
    "quarantine": "In quarantine",
    "pending_delete": "Being deleted",
    "redemption": "Redemption period",
    "not_in_dns": "Registered, not in DNS",
    "not_registered": "Not registered",
    "unmeasured": "Not looked up yet",
}
_ATTENTION_PHASES = ("quarantine", "pending_delete", "redemption", "not_in_dns", "not_registered")
_NO_EXPIRY_TLDS = ("nl",)


_GROUPS_TABLE = """
        CREATE TABLE IF NOT EXISTS portfolio_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL COLLATE NOCASE,
            parent_id INTEGER,
            expected_registrar TEXT,
            created_at TEXT NOT NULL
        )
        """


def _migrate_groups(conn):
    """Flat groups with globally unique names become units that nest.

    The first version had no parent and a UNIQUE name, so "Sales" could not
    exist under two companies. SQLite cannot drop a constraint, so the table
    is rebuilt once, keeping every id the domains point to.
    """
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(portfolio_groups)").fetchall()}
    if "parent_id" in columns:
        return
    conn.execute("BEGIN")
    try:
        conn.execute("ALTER TABLE portfolio_groups RENAME TO portfolio_groups_flat")
        conn.execute(_GROUPS_TABLE)
        conn.execute("INSERT INTO portfolio_groups (id, name, expected_registrar, created_at) "
                     "SELECT id, name, expected_registrar, created_at FROM portfolio_groups_flat")
        conn.execute("DROP TABLE portfolio_groups_flat")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def init_schema(conn):
    conn.execute(_GROUPS_TABLE)
    _migrate_groups(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS portfolio_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            group_id INTEGER,
            note TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            phase TEXT NOT NULL DEFAULT 'unmeasured',
            status TEXT NOT NULL DEFAULT '[]',
            registrar TEXT,
            reseller TEXT,
            registered_on TEXT,
            expires TEXT,
            released_from TEXT,
            dnssec TEXT,
            nameservers TEXT,
            source TEXT,
            last_checked_at TEXT,
            last_ok_at TEXT,
            last_error TEXT,
            last_change_at TEXT,
            expiry_warned INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS portfolio_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            at TEXT NOT NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
        """
    )


def _now():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- organisation
#
# Groups are organisation units: a company, a business unit under it, a
# department under that. A domain sits in one unit; monitors and scans of
# its hostnames belong to the same unit through the registered domain, so
# the structure is kept in one place.

PATH_SEPARATOR = " › "
_PATH_SPLIT = re.compile(r"\s*(?:>|/|›)\s*")


def list_groups():
    """Every unit, depth first, with its path, depth and the registrar it
    is held to (its own, or the nearest ancestor's)."""
    with db._connect() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM portfolio_groups").fetchall()]
    by_id = {r["id"]: r for r in rows}
    children = {}
    for r in rows:
        parent = r["parent_id"] if r["parent_id"] in by_id else None
        children.setdefault(parent, []).append(r)
    out = []

    def walk(parent, path, depth, inherited, seen):
        for r in sorted(children.get(parent, []), key=lambda g: g["name"].lower()):
            if r["id"] in seen:          # a cycle written by hand; never loop on it
                continue
            names = path + [r["name"]]
            expected = r.get("expected_registrar") or inherited
            out.append({**r, "path": PATH_SEPARATOR.join(names), "depth": depth,
                        "effective_registrar": expected,
                        "registrar_inherited": bool(expected and not r.get("expected_registrar"))})
            walk(r["id"], names, depth + 1, expected, seen | {r["id"]})

    walk(None, [], 0, None, frozenset())
    return out


def descendants(group_id, groups=None):
    """The unit and every unit below it."""
    groups = groups if groups is not None else list_groups()
    found, frontier = {int(group_id)}, [int(group_id)]
    while frontier:
        parent = frontier.pop()
        for g in groups:
            if g["parent_id"] == parent and g["id"] not in found:
                found.add(g["id"])
                frontier.append(g["id"])
    return found


def _clean_group_name(name):
    name = " ".join(_PATH_SPLIT.sub(" ", str(name or "")).split())[:80]
    if not name:
        raise ValueError("A unit needs a name")
    return name


def _find(conn, name, parent_id):
    row = conn.execute("SELECT id FROM portfolio_groups WHERE name = ? AND parent_id IS ?",
                       (name, parent_id)).fetchone()
    return row["id"] if row else None


def ensure_group(name, conn=None, parent_id=None):
    """The id of the unit with this name under this parent, created if needed."""
    name = _clean_group_name(name)

    def run(c):
        found = _find(c, name, parent_id)
        if found:
            return found
        return c.execute("INSERT INTO portfolio_groups (name, parent_id, created_at) VALUES (?, ?, ?)",
                         (name, parent_id, _now().isoformat())).lastrowid

    if conn is not None:
        return run(conn)
    with db._lock, db._connect() as c:
        return run(c)


def ensure_path(path, conn=None):
    """"Org X > Sales" (or "Org X / Sales"): the unit at the end, created
    level by level where missing."""
    parts = [p for p in _PATH_SPLIT.split(str(path or "")) if p.strip()]
    if not parts:
        raise ValueError("A unit needs a name")

    def run(c):
        parent = None
        for part in parts:
            parent = ensure_group(part, c, parent)
        return parent

    if conn is not None:
        return run(conn)
    with db._lock, db._connect() as c:
        return run(c)


_UNSET = object()


def update_group(group_id, *, name=None, expected_registrar=None, parent_id=_UNSET):
    group = get_group(group_id)
    if not group:
        raise ValueError("Unknown unit")
    new_parent = group["parent_id"] if parent_id is _UNSET else (int(parent_id) if parent_id else None)
    if new_parent is not None:
        if not get_group(new_parent):
            raise ValueError("Unknown parent unit")
        if new_parent in descendants(group_id):
            raise ValueError("A unit cannot be placed under itself or one of its own units")
    new_name = _clean_group_name(name) if name is not None else group["name"]
    fields, values = ["name = ?", "parent_id = ?"], [new_name, new_parent]
    if expected_registrar is not None:
        fields.append("expected_registrar = ?")
        values.append(" ".join(str(expected_registrar).split())[:200] or None)
    with db._lock, db._connect() as conn:
        clash = _find(conn, new_name, new_parent)
        if clash and clash != int(group_id):
            raise ValueError("That level already has a unit with this name; use Merge to combine them")
        conn.execute(f"UPDATE portfolio_groups SET {', '.join(fields)} WHERE id = ?",
                     (*values, int(group_id)))
    return get_group(group_id)


def get_group(group_id):
    try:
        group_id = int(group_id)
    except (TypeError, ValueError):
        return None
    return next((g for g in list_groups() if g["id"] == group_id), None)


def merge_group(source_id, target_id):
    """Fold one unit into another, as in a reorganisation.

    The source's domains go to the target; each of its units moves under the
    target, or, where the target already has a unit of that name, is merged
    into that one in turn. The target keeps its own expected registrar and
    takes the source's only when it had none. The source is removed.
    Returns counts of what moved.
    """
    source, target = get_group(source_id), get_group(target_id)
    if not source or not target:
        raise ValueError("Unknown unit")
    if source["id"] == target["id"]:
        raise ValueError("A unit cannot be merged into itself")
    if target["id"] in descendants(source["id"]):
        raise ValueError("A unit cannot be merged into one of its own units")
    # Every domain in the merged branch goes along, also those in units that
    # move as a whole; the count says so.
    branch = descendants(source["id"])
    with db._connect() as conn:
        in_branch = sum(1 for r in conn.execute("SELECT group_id FROM portfolio_domains").fetchall()
                        if r["group_id"] in branch)
    counts = {"domains": in_branch, "units_moved": 0, "units_merged": 0}

    def fold(conn, src, dst):
        conn.execute("UPDATE portfolio_domains SET group_id = ? WHERE group_id = ?", (dst, src))
        for child in conn.execute("SELECT id, name FROM portfolio_groups WHERE parent_id = ?",
                                  (src,)).fetchall():
            twin = _find(conn, child["name"], dst)
            if twin:
                fold(conn, child["id"], twin)
                counts["units_merged"] += 1
            else:
                conn.execute("UPDATE portfolio_groups SET parent_id = ? WHERE id = ?", (dst, child["id"]))
                counts["units_moved"] += 1
        own = conn.execute("SELECT expected_registrar FROM portfolio_groups WHERE id = ?", (src,)).fetchone()
        if own and own["expected_registrar"]:
            conn.execute("UPDATE portfolio_groups SET expected_registrar = ? "
                         "WHERE id = ? AND expected_registrar IS NULL", (own["expected_registrar"], dst))
        conn.execute("DELETE FROM portfolio_groups WHERE id = ?", (src,))

    with db._lock, db._connect() as conn:
        conn.execute("BEGIN")
        try:
            fold(conn, source["id"], target["id"])
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return counts


def delete_group(group_id):
    """Remove a unit; its domains and units move up to its parent."""
    group = get_group(group_id)
    if not group:
        return False
    with db._lock, db._connect() as conn:
        conn.execute("UPDATE portfolio_domains SET group_id = ? WHERE group_id = ?",
                     (group["parent_id"], group["id"]))
        conn.execute("UPDATE portfolio_groups SET parent_id = ? WHERE parent_id = ?",
                     (group["parent_id"], group["id"]))
        return conn.execute("DELETE FROM portfolio_groups WHERE id = ?", (group["id"],)).rowcount > 0


def unit_of(hostname):
    """{id, path} of the unit a hostname belongs to through its registered
    domain, or None when that domain is not in the portfolio."""
    domain = registrable(str(hostname or "").lower().rstrip("."))
    with db._connect() as conn:
        row = conn.execute("SELECT group_id FROM portfolio_domains WHERE domain = ?", (domain,)).fetchone()
    if not row or row["group_id"] is None:
        return None
    group = get_group(row["group_id"])
    return {"id": group["id"], "path": group["path"]} if group else None


def units_by_domain():
    """{registered domain: unit id} for every grouped portfolio domain."""
    with db._connect() as conn:
        rows = conn.execute("SELECT domain, group_id FROM portfolio_domains "
                            "WHERE group_id IS NOT NULL").fetchall()
    return {r["domain"]: r["group_id"] for r in rows}


def assign(hostname, group_id, *, created_by=None):
    """Put the registered domain of a hostname in a unit: added when new,
    moved when it was elsewhere. Returns (domain, "added" | "moved" | "unchanged")."""
    found, _ = whois_batch.parse_domains(str(hostname or ""))
    if not found:
        raise ValueError("Not a domain name")
    domain = registrable(found[0])
    group_id = int(group_id) if group_id not in (None, "") else None
    if group_id is not None and not get_group(group_id):
        raise ValueError("Unknown unit")
    with db._connect() as conn:
        row = conn.execute("SELECT id, group_id FROM portfolio_domains WHERE domain = ?",
                           (domain,)).fetchone()
        total = conn.execute("SELECT COUNT(*) AS c FROM portfolio_domains").fetchone()["c"]
    if row is None:
        if total >= MAX_DOMAINS:
            raise ValueError(f"At most {MAX_DOMAINS} domains in the portfolio")
        with db._lock, db._connect() as conn:
            conn.execute("INSERT INTO portfolio_domains (domain, group_id, created_by, created_at) "
                         "VALUES (?, ?, ?, ?)", (domain, group_id, created_by, _now().isoformat()))
        return domain, "added"
    if row["group_id"] == group_id:
        return domain, "unchanged"
    with db._lock, db._connect() as conn:
        conn.execute("UPDATE portfolio_domains SET group_id = ? WHERE id = ?", (group_id, row["id"]))
    return domain, "moved"


# ---------------------------------------------------------------- import

# Registries that register names at the third level under these. Not the
# whole Public Suffix List: every conversion is reported back by the import,
# so a name this misses is visible and can be corrected by hand.
_SECOND_LEVEL = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "net.nz", "org.nz",
    "co.za", "org.za", "com.br", "net.br", "org.br", "co.jp", "ne.jp", "or.jp",
    "com.tr", "com.cn", "net.cn", "org.cn", "com.mx", "co.in", "net.in", "org.in",
    "com.sg", "com.hk", "co.il", "co.kr", "com.ar", "com.pl", "co.at", "or.at",
    "com.es", "com.pt",
}

# Header names that say which column holds the domain and which the group.
_DOMAIN_HEADERS = {"domain", "domein", "domains", "domeinen", "domeinnaam", "domain name",
                   "hostname", "host", "url", "website"}
_GROUP_HEADERS = {"group", "groep", "company", "bedrijf", "afdeling", "department",
                  "business unit", "bedrijfsonderdeel", "bu", "organisation",
                  "organization", "organisatie", "entity", "entiteit", "customer", "klant",
                  "label", "unit", "eenheid", "org unit", "organisation unit",
                  "organisatieonderdeel"}


def registrable(domain):
    """The name a registry registers: example.nl for shop.example.nl.

    RDAP has no record of a subdomain, so looking one up answers "not
    registered" -- which the portfolio would report as a lost domain.
    """
    parts = domain.split(".")
    keep = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in _SECOND_LEVEL else 2
    return ".".join(parts[-keep:])


def _domain_of(token):
    found, _ = whois_batch.parse_domains(token)
    return found[0] if len(found) == 1 and "." in token else None


def _header(cells):
    """(domain column, group column) when this row is a header, else None."""
    names = [" ".join(c.lower().replace("_", " ").split()) for c in cells]
    if any(_domain_of(c) for c in cells if c):
        return None
    domain_col = next((i for i, n in enumerate(names) if n in _DOMAIN_HEADERS), None)
    group_col = next((i for i, n in enumerate(names) if n in _GROUP_HEADERS), None)
    if domain_col is None and group_col is None:
        return None
    return domain_col, group_col


def parse_import(text):
    """Domains and their groups from a paste, a CSV or a converted sheet.

    Returns (entries, rejected, converted): entries are (domain, group or
    None); converted maps what was given to the registered domain used
    instead (shop.example.nl -> example.nl).

    Without a header: one or more domains per line, the group in the first
    cell that is not a domain ("example.nl;Sales"). With a header row that
    names the columns ("Domain;Company;Notes"), only those columns are read,
    so a notes column is never taken for the group. A dotted token that is
    not a domain name is rejected rather than guessed.
    """
    entries, rejected, converted, seen = [], [], {}, set()
    columns = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        raw = [c.strip().strip('"\'') for c in next(csv.reader([line], delimiter=_delimiter(line)), [])]
        if columns is None and not entries:
            header = _header(raw)
            if header:
                columns = header
                continue
        cells = [c for c in raw if c]
        names, others = [], []
        if columns and columns[0] is not None:
            cell = raw[columns[0]] if columns[0] < len(raw) else ""
            domain = _domain_of(cell)
            if domain:
                names.append(domain)
            elif " " in cell and all(_domain_of(t) for t in cell.split()):
                names.extend(_domain_of(t) for t in cell.split())
            elif "." in cell:
                rejected.append(cell)
        else:
            for cell in cells:
                domain = _domain_of(cell)
                if domain:
                    names.append(domain)
                elif " " in cell and all(_domain_of(t) for t in cell.split()):
                    names.extend(_domain_of(t) for t in cell.split())
                else:
                    others.append(cell)
        if not names:
            if not columns and cells and "." in cells[0] and " " not in cells[0]:
                rejected.append(cells[0])
            continue          # a header, or a line without a domain
        if columns and columns[1] is not None:
            group = raw[columns[1]] if columns[1] < len(raw) else ""
            # "example.com, example.org" under a header is a list on one
            # line, not a domain in a group called example.org.
            if _domain_of(group):
                names.append(_domain_of(group))
                group = None
        else:
            # "example.nl;Sales" names its group; "example.nl, example.com"
            # is just a list. The group is the first cell that is not a domain.
            group = others[0] if others else None
        for name in names:
            domain = registrable(name)
            if domain != name:
                converted.setdefault(name, domain)
            if domain not in seen:
                seen.add(domain)
                entries.append((domain, " ".join(group.split())[:80] if group else None))
    return entries, rejected, converted


MAX_SHEET_ROWS = 10000


def sheet_to_text(data):
    """An .xlsx workbook's first sheet as tab-separated lines for parse_import.

    Read-only and values only: formulas are not evaluated, macros not run.
    """
    import openpyxl
    book = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    try:
        sheet = book.worksheets[0]
        lines = []
        for row in sheet.iter_rows(values_only=True, max_row=MAX_SHEET_ROWS):
            lines.append("\t".join("" if v is None else str(v).replace("\t", " ").strip() for v in row))
        return "\n".join(lines)
    finally:
        book.close()


def _delimiter(line):
    for d in ("\t", ";", ","):
        if d in line:
            return d
    return ","


def import_domains(entries, *, default_group=None, default_group_id=None, created_by=None):
    """Add or regroup domains. Returns counts and the names that changed.

    A group is a unit path ("Org X > Sales"); missing levels are created. A
    domain already in the portfolio is moved to the unit the import names
    for it; one imported without a unit keeps the unit it has.
    """
    if default_group_id is not None and not get_group(default_group_id):
        raise ValueError("Unknown unit")
    with db._connect() as conn:
        existing = {r["domain"]: dict(r) for r in
                    conn.execute("SELECT id, domain, group_id FROM portfolio_domains").fetchall()}
    new = [d for d, _ in entries if d not in existing]
    if len(existing) + len(new) > MAX_DOMAINS:
        raise ValueError(f"At most {MAX_DOMAINS} domains in the portfolio "
                         f"({len(existing)} now, {len(new)} new in this import)")
    added, moved, unchanged = [], [], []
    now = _now().isoformat()
    with db._lock, db._connect() as conn:
        default_id = (int(default_group_id) if default_group_id is not None
                      else ensure_path(default_group, conn) if default_group else None)
        for domain, group in entries:
            group_id = ensure_path(group, conn) if group else default_id
            current = existing.get(domain)
            if current is None:
                conn.execute("INSERT INTO portfolio_domains (domain, group_id, created_by, created_at) "
                             "VALUES (?, ?, ?, ?)", (domain, group_id, created_by, now))
                added.append(domain)
            elif group_id is not None and group_id != current["group_id"]:
                conn.execute("UPDATE portfolio_domains SET group_id = ? WHERE id = ?",
                             (group_id, current["id"]))
                moved.append(domain)
            else:
                unchanged.append(domain)
    return {"added": added, "moved": moved, "unchanged": unchanged}


def move(domain_ids, group_id):
    if group_id is not None and not get_group(group_id):
        raise ValueError("Unknown unit")
    ids = [int(i) for i in domain_ids]
    with db._lock, db._connect() as conn:
        return sum(conn.execute("UPDATE portfolio_domains SET group_id = ? WHERE id = ?",
                                (group_id, i)).rowcount for i in ids)


def remove(domain_ids):
    ids = [int(i) for i in domain_ids]
    with db._lock, db._connect() as conn:
        return sum(conn.execute("DELETE FROM portfolio_domains WHERE id = ?", (i,)).rowcount
                   for i in ids)


# ---------------------------------------------------------------- reading

def _days_left(expires, today=None):
    if not expires:
        return None
    try:
        return (date.fromisoformat(str(expires)[:10]) - (today or _now().date())).days
    except ValueError:
        return None


def transfer_state(domain, group):
    """Whether the domain is at the registrar its unit expects.

    "ok", "move", "unmeasured" (no registrar known yet) or "not_applicable"
    (neither the unit nor any unit above it names one). A match on the
    reseller counts too: for .nl the name a customer knows is often the
    reseller, not the registrar.
    """
    group = group or {}
    wanted = group.get("effective_registrar", group.get("expected_registrar"))
    expected = [e.strip().lower() for e in str(wanted or "").split(",") if e.strip()]
    if not expected:
        return "not_applicable"
    if domain.get("phase") in ("unmeasured", "not_registered") or not domain.get("registrar"):
        return "unmeasured"
    names = f"{domain.get('registrar') or ''} {domain.get('reseller') or ''}".lower()
    return "ok" if any(e in names for e in expected) else "move"


def expiry_state(domain, today=None):
    """("known", days), ("not_published", None) or ("unmeasured", None)."""
    if domain.get("expires"):
        return "known", _days_left(domain["expires"], today)
    if domain["domain"].rsplit(".", 1)[-1] in _NO_EXPIRY_TLDS and domain.get("phase") != "unmeasured":
        return "not_published", None
    return "unmeasured", None


def _enrich(row, groups, today=None):
    out = dict(row)
    out["status"] = json.loads(out.get("status") or "[]")
    out["nameservers"] = (out.get("nameservers") or "").split()
    out["phase_text"] = PHASE_TEXT.get(out["phase"], out["phase"])
    group = groups.get(out.get("group_id"))
    out["group"] = group["path"] if group else None
    out["transfer"] = transfer_state(out, group)
    out["expiry_state"], out["days_left"] = expiry_state(out, today)
    # The last lookup failed, so what is shown is the answer before it.
    out["stale"] = bool(out.get("last_error")) and out["phase"] != "unmeasured"
    flags = []
    if out["phase"] in _ATTENTION_PHASES:
        flags.append("attention")
    if out["days_left"] is not None and out["days_left"] <= _SOON.days:
        flags.append("expiring")
    if out["transfer"] == "move":
        flags.append("move")
    if out["phase"] == "unmeasured" or out["stale"]:
        flags.append("unmeasured")
    out["flags"] = flags
    return out


def list_all(today=None):
    groups = {g["id"]: g for g in list_groups()}
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM portfolio_domains ORDER BY domain").fetchall()
    return [_enrich(r, groups, today) for r in rows]


def get(domain_id):
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM portfolio_domains WHERE id = ?", (int(domain_id),)).fetchone()
    return _enrich(row, {g["id"]: g for g in list_groups()}) if row else None


def summary(domains, groups):
    """Counts per unit and in total. A unit's counts are its own domains;
    "subtree" adds those of every unit below it."""
    def counts(items):
        return {"total": len(items),
                **{flag: sum(1 for d in items if flag in d["flags"])
                   for flag in ("attention", "expiring", "move", "unmeasured")}}
    per_group = []
    for g in groups:
        below = descendants(g["id"], groups)
        per_group.append({**g, **counts([d for d in domains if d.get("group_id") == g["id"]]),
                          "subtree": counts([d for d in domains if d.get("group_id") in below])})
    ungrouped = [d for d in domains if not d.get("group")]
    return {"total": counts(domains), "groups": per_group,
            "ungrouped": counts(ungrouped)}


def events(limit=50):
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM portfolio_events ORDER BY id DESC LIMIT ?",
                            (int(limit),)).fetchall()
    return [dict(r) for r in rows]


CSV_COLUMNS = ["domain", "group", "phase", "registrar", "reseller", "transfer", "expires",
               "days_left", "registered_on", "dnssec", "nameservers", "status", "last_checked_at",
               "last_error"]


def to_csv(domains):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for d in domains:
        values = {**d, "nameservers": " ".join(d.get("nameservers") or []),
                  "status": "; ".join(d.get("status") or []),
                  "expires": d.get("expires") or ("not published" if d["expiry_state"] == "not_published" else ""),
                  "days_left": "" if d.get("days_left") is None else d["days_left"]}
        writer.writerow([whois_batch._csv_safe(values.get(c)) for c in CSV_COLUMNS])
    return out.getvalue()


# ---------------------------------------------------------------- checking

def is_due(domain, now=None):
    now = now or _now()
    if not domain.get("last_checked_at"):
        return True
    elapsed = now - datetime.fromisoformat(domain["last_checked_at"])
    if domain.get("last_error") or domain.get("phase") in ("quarantine", "pending_delete",
                                                           "redemption", "unmeasured"):
        return elapsed >= timedelta(hours=1)
    days = _days_left(domain.get("expires"), now.date())
    if days is not None and days <= _SOON.days:
        return elapsed >= timedelta(hours=6)
    return elapsed >= timedelta(hours=24)


def _answer(result):
    """The stored fields from a lookup, or None when it could not be made."""
    if result.get("success"):
        lc = result.get("lifecycle") or {}
        dnssec = result.get("dnssec")
        return {"phase": lc.get("phase") or "registered",
                "status": json.dumps(result.get("status") or []),
                "registrar": (result.get("registrar") or {}).get("name") or None,
                "reseller": (result.get("reseller") or {}).get("name") or None,
                "registered_on": result.get("registered") or None,
                "expires": result.get("expires") or None,
                "released_from": lc.get("released_from"),
                "dnssec": {True: "yes", False: "no"}.get(dnssec),
                "nameservers": " ".join(sorted(result.get("nameservers") or [])) or None,
                "source": result.get("source")}
    if result.get("registered") is False:
        return {"phase": "not_registered", "status": "[]", "registrar": None, "reseller": None,
                "registered_on": None, "expires": None, "released_from": None, "dnssec": None,
                "nameservers": None, "source": "rdap"}
    return None


def _changes(domain, old, new):
    """[(kind, severity, text)] worth telling someone about."""
    out = []
    if new["phase"] != old.get("phase"):
        before = PHASE_TEXT.get(old.get("phase"), old.get("phase"))
        after = PHASE_TEXT.get(new["phase"], new["phase"])
        if new["phase"] == "not_registered":
            out.append(("phase", "critical", f"{domain} is no longer registered (was: {before})."))
        elif new["phase"] == "quarantine":
            when = f"; released from {new['released_from']}" if new.get("released_from") else ""
            out.append(("phase", "critical", f"{domain} went into quarantine{when}. "
                                             "Only the holder can restore it until then."))
        else:
            severity = "high" if new["phase"] in _ATTENTION_PHASES else "medium"
            out.append(("phase", severity, f"{domain}: {before} -> {after}."))
    for field, label in (("registrar", "registrar"), ("reseller", "reseller")):
        # A missing value is not a change: some answers simply leave it out.
        if new.get(field) and old.get(field) and new[field] != old[field]:
            out.append((field, "high", f"{domain} changed {label}: {old[field]} -> {new[field]}."))
    if new.get("nameservers") and old.get("nameservers") and new["nameservers"] != old["nameservers"]:
        out.append(("nameservers", "high",
                    f"{domain} has new name servers: {new['nameservers']} (was {old['nameservers']})."))
    return out


def _expiry_warning(domain, row, new, today):
    """(threshold, text) when an expiry threshold is newly crossed."""
    days = _days_left(new.get("expires"), today)
    if days is None:
        return None
    warned = row.get("expiry_warned") if row.get("expires") == new.get("expires") else None
    crossed = [t for t in EXPIRY_WARN_DAYS if days <= t and (warned is None or t < warned)]
    if not crossed:
        return None
    threshold = min(crossed)
    when = "has expired" if days < 0 else f"expires in {days} day{'s' if days != 1 else ''}"
    return threshold, f"{domain} {when} ({new['expires']})."


def check(row, *, fetch=None, notify=None, now=None):
    """Look one domain up, store the answer, and report what changed."""
    now = now or _now()
    result = (fetch or (lambda d: whois_batch.lookup_paced(d)))(row["domain"])
    new = _answer(result)
    stamp = now.isoformat()
    with db._lock, db._connect() as conn:
        if new is None:
            # Not measured: keep the last answer, say the lookup failed.
            conn.execute("UPDATE portfolio_domains SET last_checked_at=?, last_error=? WHERE id=?",
                         (stamp, result.get("error") or "No answer", row["id"]))
            return []
        baseline = row.get("phase") == "unmeasured"
        changes = [] if baseline else _changes(row["domain"], row, new)
        warning = _expiry_warning(row["domain"], row, new, now.date())
        expiry_warned = row.get("expiry_warned") if row.get("expires") == new.get("expires") else None
        if warning:
            expiry_warned = warning[0]
            changes.append(("expiry", "high" if warning[0] <= 7 else "medium", warning[1]))
        conn.execute(
            "UPDATE portfolio_domains SET phase=?, status=?, registrar=?, reseller=?, registered_on=?, "
            "expires=?, released_from=?, dnssec=?, nameservers=?, source=?, last_checked_at=?, "
            "last_ok_at=?, last_error=NULL, expiry_warned=?, "
            "last_change_at=COALESCE(?, last_change_at) WHERE id=?",
            (new["phase"], new["status"], new["registrar"], new["reseller"], new["registered_on"],
             new["expires"], new["released_from"], new["dnssec"], new["nameservers"], new["source"],
             stamp, stamp, expiry_warned, stamp if changes else None, row["id"]))
        for kind, _, text in changes:
            conn.execute("INSERT INTO portfolio_events (domain, at, kind, detail) VALUES (?, ?, ?, ?)",
                         (row["domain"], stamp, kind, text))
    for _, severity, text in changes:
        (notify or _notify)(row["domain"], severity, text)
    return [{"domain": row["domain"], "kind": k, "severity": s, "detail": t} for k, s, t in changes]


def _notify(domain, severity, detail):
    try:
        import notifications
        notifications.dispatch({"event_type": "domain_portfolio", "severity": severity,
                                "summary": detail, "details": {"target": domain}},
                               {"target": domain, "name": f"Domain portfolio: {domain}"})
    except Exception:
        pass


def maybe_run(now=None, *, fetch=None, notify=None):
    """From the scheduler loop: look up the domains that are due, oldest first."""
    if not _run_lock.acquire(blocking=False):
        return []
    try:
        now = now or _now()
        with db._connect() as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM portfolio_domains ORDER BY last_checked_at IS NOT NULL, "
                "last_checked_at").fetchall()]
        changes = []
        for row in [r for r in rows if is_due(r, now)][:_PER_RUN]:
            try:
                changes.extend(check(row, fetch=fetch, notify=notify, now=now))
            except Exception:
                continue
        return changes
    finally:
        _run_lock.release()


def raw(domain_id):
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM portfolio_domains WHERE id = ?", (int(domain_id),)).fetchone()
    return dict(row) if row else None
