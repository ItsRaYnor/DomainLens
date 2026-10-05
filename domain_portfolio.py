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

Each domain also carries a decision -- keep it, decide later, let it lapse,
or request or claim it -- and the warnings follow that decision: an expiry
is news for a domain you keep and the plan for one you cancel. Whether a
domain is in use (it receives or sends mail, or has a web address) is
measured with each lookup; a domain in use belongs with the threat
intelligence service, one that is not does not need it.
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
# A domain to request or claim is looked up every minute from just before
# the published release moment until well after it (SIDN releases within
# an hour), so "free now" is known within a minute, not within the hour.
_RELEASE_BEFORE = timedelta(minutes=5)
_RELEASE_AFTER = timedelta(minutes=75)

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

# What the organisation means to do with a domain. Keep is the default: a
# domain in the portfolio is held until someone decides otherwise.
LIFECYCLE_TEXT = {
    "keep": "Keep and renew",
    "review": "To decide",
    "cancel": "Cancel (let it lapse)",
    "claim": "Request or claim",
}
DEFAULT_LIFECYCLE = "keep"
# Not (or no longer) the organisation's to look after: no expiry warnings,
# no registrar to move to, no threat intelligence.
_NOT_HELD = ("cancel", "claim")
# Phases in which a domain has no DNS at all, so it is measurably unused.
_NO_DNS_PHASES = ("not_registered", "quarantine", "not_in_dns")
# Registries that publish no expiry date: the registrar renews until the
# holder cancels. Their missing date is "not published", not "unknown".
_NO_EXPIRY_TLDS = ("nl", "be", "de", "eu", "at")


_GROUPS_TABLE = """
        CREATE TABLE IF NOT EXISTS portfolio_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL COLLATE NOCASE,
            parent_id INTEGER,
            expected_registrar TEXT,
            notify_emails TEXT,
            contact_id INTEGER,
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
        if "notify_emails" not in columns:
            conn.execute("ALTER TABLE portfolio_groups ADD COLUMN notify_emails TEXT")
        if "contact_id" not in columns:
            conn.execute("ALTER TABLE portfolio_groups ADD COLUMN contact_id INTEGER")
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
    _migrate_domains(conn)
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
    _adopt_watchlist(conn)


_DOMAIN_COLUMNS = {
    "lifecycle": "TEXT NOT NULL DEFAULT 'keep'",
    "threat_intel": "INTEGER NOT NULL DEFAULT 0",
    "contact_id": "INTEGER",
    "uses_mail": "TEXT",      # 'yes', 'no', or NULL: not measured
    "uses_web": "TEXT",
    "usage_checked_at": "TEXT",
    "dns_state": "TEXT",      # 'ok', 'no_answer' (its name servers do not answer), NULL
}


def _migrate_domains(conn):
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(portfolio_domains)").fetchall()}
    for name, kind in _DOMAIN_COLUMNS.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE portfolio_domains ADD COLUMN {name} {kind}")


def _adopt_watchlist(conn):
    """Wanted domains were a list of their own (domain_watch); they are
    portfolio domains with the decision "request or claim" now. Each row is
    moved once, with its last answer and its history, and marked, so one
    removed from the portfolio afterwards stays removed. A domain the
    portfolio already has keeps the decision it has there."""
    tables = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
    if "watched_domains" not in tables:
        return
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(watched_domains)").fetchall()}
    if "moved_to_portfolio_at" not in columns:
        conn.execute("ALTER TABLE watched_domains ADD COLUMN moved_to_portfolio_at TEXT")
    rows = conn.execute("SELECT * FROM watched_domains WHERE moved_to_portfolio_at IS NULL").fetchall()
    if not rows:
        return
    present = {r["domain"] for r in conn.execute("SELECT domain FROM portfolio_domains").fetchall()}
    stamp = _now().isoformat()
    for row in rows:
        domain = registrable(str(row["domain"]).lower())
        if domain not in present:
            phase = {"available": "not_registered"}.get(row["phase"], row["phase"])
            if phase not in PHASE_TEXT:
                phase = "unmeasured"
            answered = phase != "unmeasured" and not row["last_error"]
            conn.execute(
                "INSERT INTO portfolio_domains (domain, note, created_by, created_at, phase, status, "
                "registered_on, released_from, last_checked_at, last_ok_at, last_error, last_change_at, "
                "lifecycle) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'claim')",
                (domain, row["note"], row["created_by"], row["created_at"], phase,
                 row["status"] or "[]", row["registered_on"], row["released_from"],
                 row["last_checked_at"], row["last_checked_at"] if answered else None,
                 row["last_error"], row["last_change_at"]))
            for event in conn.execute("SELECT at, detail FROM watched_domain_events WHERE domain = ? "
                                      "ORDER BY id", (row["domain"],)).fetchall():
                conn.execute("INSERT INTO portfolio_events (domain, at, kind, detail) VALUES (?, ?, 'phase', ?)",
                             (domain, event["at"], event["detail"]))
            present.add(domain)
        conn.execute("UPDATE watched_domains SET moved_to_portfolio_at = ? WHERE id = ?", (stamp, row["id"]))


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
    """Every unit, depth first, with its path, depth, the registrar it is
    held to and its contact (each its own, or the nearest ancestor's)."""
    import contacts
    with db._connect() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM portfolio_groups").fetchall()]
        people = contacts.by_id(conn)
    by_id = {r["id"]: r for r in rows}
    children = {}
    for r in rows:
        parent = r["parent_id"] if r["parent_id"] in by_id else None
        children.setdefault(parent, []).append(r)
    out = []

    def walk(parent, path, depth, inherited, person, seen):
        for r in sorted(children.get(parent, []), key=lambda g: g["name"].lower()):
            if r["id"] in seen:          # a cycle written by hand; never loop on it
                continue
            names = path + [r["name"]]
            expected = r.get("expected_registrar") or inherited
            own = people.get(r.get("contact_id"))
            contact = own or person
            out.append({**r, "path": PATH_SEPARATOR.join(names), "depth": depth,
                        "effective_registrar": expected,
                        "registrar_inherited": bool(expected and not r.get("expected_registrar")),
                        "contact": contact, "contact_inherited": bool(contact and not own)})
            walk(r["id"], names, depth + 1, expected, contact, seen | {r["id"]})

    walk(None, [], 0, None, None, frozenset())
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


_EMAIL = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")
MAX_UNIT_RECIPIENTS = 10


def clean_recipients(text):
    """A unit's notification addresses from "a@x, b@y": checked, deduplicated."""
    found = []
    for part in re.split(r"[\s,;]+", str(text or "")):
        part = part.strip().lower()
        if not part:
            continue
        if not _EMAIL.match(part):
            raise ValueError(f"{part} is not an e-mail address")
        if part not in found:
            found.append(part)
    if len(found) > MAX_UNIT_RECIPIENTS:
        raise ValueError(f"At most {MAX_UNIT_RECIPIENTS} addresses per unit")
    return found


def unit_recipients(hostname):
    """(unit path, addresses) for a host: its unit's addresses and those of
    every unit above it, so a company's contact hears of its business units.
    (None, []) when the domain is in no unit."""
    unit = unit_of(hostname)
    if not unit:
        return None, []
    groups = {g["id"]: g for g in list_groups()}
    found, current, seen = [], unit["id"], set()
    while current in groups and current not in seen:
        seen.add(current)
        for address in (groups[current].get("notify_emails") or "").split(","):
            if address and address not in found:
                found.append(address)
        current = groups[current]["parent_id"]
    return unit["path"], found


def update_group(group_id, *, name=None, expected_registrar=None, parent_id=_UNSET,
                 notify_emails=None, contact_id=_UNSET):
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
    if notify_emails is not None:
        fields.append("notify_emails = ?")
        values.append(",".join(clean_recipients(notify_emails)) or None)
    if contact_id is not _UNSET:
        import contacts
        contact_id = int(contact_id) if contact_id not in (None, "") else None
        if contact_id is not None and not contacts.get(contact_id):
            raise ValueError("Unknown contact")
        fields.append("contact_id = ?")
        values.append(contact_id)
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
        own = conn.execute("SELECT expected_registrar, contact_id FROM portfolio_groups WHERE id = ?",
                           (src,)).fetchone()
        if own and own["expected_registrar"]:
            conn.execute("UPDATE portfolio_groups SET expected_registrar = ? "
                         "WHERE id = ? AND expected_registrar IS NULL", (own["expected_registrar"], dst))
        if own and own["contact_id"]:
            conn.execute("UPDATE portfolio_groups SET contact_id = ? "
                         "WHERE id = ? AND contact_id IS NULL", (own["contact_id"], dst))
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


def delete_group(group_id, *, with_contents=False):
    """Remove a unit. Its domains and units move up to its parent, or, with
    `with_contents`, go as well: every unit below it is deleted and their
    domains leave the portfolio. Monitors and scans are not touched; they
    count as "not in a unit" afterwards.

    Returns {"domains": n, "units": n} that were deleted, or None for a
    unit that does not exist."""
    group = get_group(group_id)
    if not group:
        return None
    with db._lock, db._connect() as conn:
        if with_contents:
            ids = sorted(descendants(group["id"]))
            marks = ",".join("?" * len(ids))
            domains = conn.execute(f"DELETE FROM portfolio_domains WHERE group_id IN ({marks})",
                                   ids).rowcount
            units = conn.execute(f"DELETE FROM portfolio_groups WHERE id IN ({marks})", ids).rowcount
            return {"domains": domains, "units": units}
        conn.execute("UPDATE portfolio_domains SET group_id = ? WHERE group_id = ?",
                     (group["parent_id"], group["id"]))
        conn.execute("UPDATE portfolio_groups SET parent_id = ? WHERE parent_id = ?",
                     (group["parent_id"], group["id"]))
        units = conn.execute("DELETE FROM portfolio_groups WHERE id = ?", (group["id"],)).rowcount
        return {"domains": 0, "units": units}


def host_of(target):
    """The bare host in a monitor or scan target: "https://WWW.Example.com:8443/x"
    is www.example.com."""
    text = str(target or "").strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    text = text.rsplit("@", 1)[-1]
    if text.startswith("["):
        return text
    return text.split(":", 1)[0].rstrip(".")


def unit_of(hostname):
    """{id, path} of the unit a hostname belongs to through its registered
    domain, or None when that domain is not in the portfolio."""
    domain = registrable(host_of(hostname))
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
_DECISION_HEADERS = {"decision", "besluit", "beslissing", "lifecycle", "action", "actie", "plan",
                     "keep", "behouden", "verlengen", "renew"}
_CONTACT_HEADERS = {"contact", "contactpersoon", "contact person", "contact name", "owner",
                    "eigenaar", "domain owner", "verantwoordelijke", "responsible",
                    "aanspreekpunt", "beheerder"}
_EMAIL_HEADERS = {"e-mail", "email", "mail", "contact e-mail", "contact email", "e-mailadres",
                  "emailadres", "owner e-mail", "owner email"}
_INTEL_HEADERS = {"threat intel", "threat intelligence", "ti", "threatintel", "cti"}

# What people write in a decision column, in English or Dutch. The first
# word decides when the whole cell is not known ("Cancel (let it lapse)").
_DECISION_WORDS = {
    "keep": "keep", "renew": "keep", "keep and renew": "keep", "behouden": "keep",
    "behouden en verlengen": "keep", "verlengen": "keep", "houden": "keep", "behoud": "keep",
    "review": "review", "to decide": "review", "decide": "review", "undecided": "review",
    "nog te besluiten": "review", "besluiten": "review", "twijfel": "review", "onbekend": "review",
    "cancel": "cancel", "lapse": "cancel", "let it lapse": "cancel", "drop": "cancel",
    "opzeggen": "cancel", "laten verlopen": "cancel", "opheffen": "cancel", "verwijderen": "cancel",
    "claim": "claim", "request": "claim", "request or claim": "claim", "acquire": "claim",
    "claimen": "claim", "aanvragen": "claim", "aanvragen of claimen": "claim",
    "verwerven": "claim", "registreren": "claim",
}
_YES = {"yes", "ja", "y", "j", "true", "1", "x", "on", "aan", "enrolled", "aangemeld"}
_NO = {"no", "nee", "n", "false", "0", "off", "uit", "not enrolled", "niet aangemeld"}


def decision_of(text):
    """The decision a cell names, None for an empty cell, "" for one not understood."""
    words = " ".join(re.sub(r"[^\w\s-]", " ", str(text or "").lower()).split())
    if not words:
        return None
    return _DECISION_WORDS.get(words) or _DECISION_WORDS.get(words.split()[0]) or ""


def _intel_of(text):
    value = " ".join(str(text or "").lower().split())
    return True if value in _YES else False if value in _NO else None


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
    """{"domain", "group", "decision", "contact", "email", "intel": column}
    when this row is a header, else None."""
    names = [" ".join(c.lower().replace("_", " ").split()) for c in cells]
    if any(_domain_of(c) for c in cells if c):
        return None
    found = {}
    for key, known in (("domain", _DOMAIN_HEADERS), ("group", _GROUP_HEADERS),
                       ("decision", _DECISION_HEADERS), ("contact", _CONTACT_HEADERS),
                       ("email", _EMAIL_HEADERS), ("intel", _INTEL_HEADERS)):
        found[key] = next((i for i, n in enumerate(names) if n in known), None)
    if found["domain"] is None and found["group"] is None:
        return None
    return found


def parse_import(text):
    """(entries, rejected, converted): see parse_import_full."""
    return parse_import_full(text)[:3]


def parse_import_full(text):
    """Domains and their groups from a paste, a CSV or a converted sheet.

    Returns (entries, rejected, converted): entries are (domain, group or
    None); converted maps what was given to the registered domain used
    instead (shop.example.nl -> example.nl).

    Without a header: one or more domains per line, the group in the first
    cell that is not a domain ("example.nl;Sales"). With a header row that
    names the columns ("Domain;Company;Notes"), only those columns are read,
    so a notes column is never taken for the group. A dotted token that is
    not a domain name is rejected rather than guessed.

    A header may also name a decision, a contact (a name, an address, or
    "Name <address>"), a contact e-mail and threat intelligence column; the
    fourth value returned maps each domain to what those cells said. An
    empty cell says nothing, so an import never clears what is set.
    """
    entries, rejected, converted, seen = [], [], {}, set()
    extras = {}
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
        def at(key):
            col = columns.get(key) if columns else None
            return raw[col].strip() if col is not None and col < len(raw) else ""
        if columns and columns["domain"] is not None:
            cell = raw[columns["domain"]] if columns["domain"] < len(raw) else ""
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
        if columns and columns["group"] is not None:
            group = raw[columns["group"]] if columns["group"] < len(raw) else ""
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
                extra = {"decision": at("decision"), "contact": at("contact"),
                         "email": at("email"), "intel": at("intel")}
                if any(extra.values()):
                    extras[domain] = extra
    return entries, rejected, converted, extras


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


def _contact_for(name, email, people, made):
    """The contact a sheet names: an existing one by address or name, an
    account with that address, or a new contact. None when the cells name
    no one; ValueError for an address that is not one."""
    import contacts
    if "<" in name and name.rstrip().endswith(">") and not email:
        name, _, email = name.rstrip(">").partition("<")
    name, email = " ".join(name.split()), email.strip().lower()
    if not email and "@" in name and " " not in name:
        name, email = "", name.lower()
    if not (name or email):
        return None
    for c in people:
        if email and (c.get("email") or "").lower() == email:
            return c["id"]
    if not email:
        for c in people:
            if (c.get("name") or "").lower() == name.lower():
                return c["id"]
    if email:
        user = db.get_user_by_email(email)
        if user:
            contact = contacts.create(user_id=user["id"])
            people.append(contact)
            return contact["id"]
    contact = contacts.create(name=name or None, email=email or None)
    people.append(contact)
    made.append(contact["name"])
    return contact["id"]


def _apply_extras(extras):
    """Decision, contact and threat intelligence from the sheet's columns."""
    import contacts
    report = {"decisions": 0, "contacts": 0, "threat_intel": 0, "contacts_created": [],
              "not_understood": []}
    if not extras:
        return report
    people = contacts.list_contacts()
    with db._connect() as conn:
        ids = {r["domain"]: r["id"] for r in conn.execute("SELECT id, domain FROM portfolio_domains")}
    for domain, extra in extras.items():
        domain_id = ids.get(domain)
        if domain_id is None:
            continue
        decision = decision_of(extra.get("decision"))
        if decision:
            set_lifecycle([domain_id], decision)
            report["decisions"] += 1
        elif decision == "":
            report["not_understood"].append(f"{domain}: {extra['decision']}")
        intel = _intel_of(extra.get("intel"))
        if intel is not None:
            set_threat_intel([domain_id], intel)
            report["threat_intel"] += 1
        elif extra.get("intel"):
            report["not_understood"].append(f"{domain}: {extra['intel']}")
        try:
            contact_id = _contact_for(extra.get("contact") or "", extra.get("email") or "",
                                      people, report["contacts_created"])
        except ValueError as exc:
            report["not_understood"].append(f"{domain}: {exc}")
            continue
        if contact_id is not None:
            set_contact([domain_id], contact_id)
            report["contacts"] += 1
    return report


def import_domains(entries, *, default_group=None, default_group_id=None, created_by=None,
                   extras=None, default_lifecycle=None, note=None):
    """Add or regroup domains. Returns counts and the names that changed.

    A group is a unit path ("Org X > Sales"); missing levels are created. A
    domain already in the portfolio is moved to the unit the import names
    for it; one imported without a unit keeps the unit it has. `extras`
    (from parse_import_full) sets a decision, contact or threat intelligence.
    `default_lifecycle` is the decision for domains new to the portfolio; one
    already there keeps its own unless the sheet names another.
    """
    if default_group_id is not None and not get_group(default_group_id):
        raise ValueError("Unknown unit")
    if default_lifecycle in (None, ""):
        default_lifecycle = DEFAULT_LIFECYCLE
    if default_lifecycle not in LIFECYCLE_TEXT:
        raise ValueError("Unknown decision")
    note = " ".join(str(note or "").split())[:200] or None
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
                conn.execute("INSERT INTO portfolio_domains (domain, group_id, created_by, created_at, "
                             "lifecycle, note) VALUES (?, ?, ?, ?, ?, ?)",
                             (domain, group_id, created_by, now, default_lifecycle, note))
                added.append(domain)
            elif group_id is not None and group_id != current["group_id"]:
                conn.execute("UPDATE portfolio_domains SET group_id = ? WHERE id = ?",
                             (group_id, current["id"]))
                moved.append(domain)
            else:
                unchanged.append(domain)
    return {"added": added, "moved": moved, "unchanged": unchanged, **_apply_extras(extras)}


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


def add_wanted(domains, *, note=None, created_by=None):
    """Domains to request or claim -- from WHOIS, or the former watchlist's
    API. Returns (added, already in the portfolio); one already there keeps
    the decision it has, so a held domain is never turned into a wanted one."""
    names = list(dict.fromkeys(registrable(str(d).lower()) for d in domains))
    with db._connect() as conn:
        present = {r["domain"] for r in conn.execute("SELECT domain FROM portfolio_domains").fetchall()}
    new = [(d, None) for d in names if d not in present]
    result = import_domains(new, created_by=created_by, default_lifecycle="claim", note=note) if new \
        else {"added": []}
    return result["added"], [d for d in names if d in present]


def set_lifecycle(domain_ids, value):
    if value not in LIFECYCLE_TEXT:
        raise ValueError("Unknown decision")
    return _set(domain_ids, "lifecycle", value)


def set_threat_intel(domain_ids, enrolled):
    return _set(domain_ids, "threat_intel", 1 if enrolled else 0)


def set_contact(domain_ids, contact_id):
    if contact_id is not None:
        import contacts
        if not contacts.get(contact_id):
            raise ValueError("Unknown contact")
    return _set(domain_ids, "contact_id", contact_id)


def _set(domain_ids, column, value):
    ids = [int(i) for i in domain_ids]
    with db._lock, db._connect() as conn:
        return sum(conn.execute(f"UPDATE portfolio_domains SET {column} = ? WHERE id = ?",
                                (value, i)).rowcount for i in ids)


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


def usage_state(domain):
    """"in_use" (mail or web measured), "unused" (both measured absent) or
    "unmeasured". One answer missing is not enough to call a domain unused."""
    mail, web = domain.get("uses_mail"), domain.get("uses_web")
    if "yes" in (mail, web):
        return "in_use"
    if mail == "no" and web == "no":
        return "unused"
    return "unmeasured"


def threat_intel_state(domain):
    """"enrolled", "missing" (in use, not enrolled), "not_needed" (unused, or
    a domain being cancelled or claimed) or "unmeasured" (use not known)."""
    if domain.get("threat_intel"):
        return "enrolled"
    if domain.get("lifecycle") in _NOT_HELD:
        return "not_needed"
    return {"in_use": "missing", "unused": "not_needed"}.get(usage_state(domain), "unmeasured")


def _enrich(row, groups, today=None, people=None):
    out = dict(row)
    out["status"] = json.loads(out.get("status") or "[]")
    out["nameservers"] = (out.get("nameservers") or "").split()
    out["phase_text"] = PHASE_TEXT.get(out["phase"], out["phase"])
    group = groups.get(out.get("group_id"))
    out["group"] = group["path"] if group else None
    out["unit"], out["unit_id"] = out["group"], out.get("group_id")
    out["lifecycle"] = out.get("lifecycle") or DEFAULT_LIFECYCLE
    out["lifecycle_text"] = LIFECYCLE_TEXT.get(out["lifecycle"], out["lifecycle"])
    held = out["lifecycle"] not in _NOT_HELD
    # A domain being let go or still to be acquired has no registrar to move to.
    out["transfer"] = transfer_state(out, group) if held else "not_applicable"
    out["expiry_state"], out["days_left"] = expiry_state(out, today)
    out["threat_intel"] = bool(out.get("threat_intel"))
    out["usage"] = usage_state(out)
    out["threat_intel_state"] = threat_intel_state(out)
    # A domain's own contact, or else the one of its unit (or a unit above).
    own = (people or {}).get(out.get("contact_id")) if out.get("contact_id") else None
    out["contact"] = own or (group or {}).get("contact")
    out["contact_inherited"] = bool(out["contact"] and not own)
    # The last lookup failed, so what is shown is the answer before it.
    out["stale"] = bool(out.get("last_error")) and out["phase"] != "unmeasured"
    flags = []
    # Quarantine or an expiry is a problem for a domain you hold, and the
    # plan (or the opportunity) for one you cancel or want to acquire.
    if held and out["phase"] in _ATTENTION_PHASES:
        flags.append("attention")
    if held and out["days_left"] is not None and out["days_left"] <= _SOON.days:
        flags.append("expiring")
    if out["transfer"] == "move":
        flags.append("move")
    if out["threat_intel_state"] == "missing":
        flags.append("intel")
    if out["lifecycle"] == "claim":
        flags.append("wanted")
    if out["lifecycle"] == "claim" and out["phase"] == "not_registered":
        flags.append("claimable")
    # A delegation nobody answers for: measured, and the reason use is unknown.
    if held and out.get("dns_state") == "no_answer":
        flags.append("dns_dead")
    # Whether it is in use is not known yet, so whether it needs threat
    # intelligence is not known either: a third answer, counted on its own.
    elif held and out["usage"] == "unmeasured":
        flags.append("use_unmeasured")
    if out["phase"] == "unmeasured" or out["stale"]:
        flags.append("unmeasured")
    out["flags"] = flags
    return out


def _people():
    import contacts
    return {c["id"]: {k: c[k] for k in ("id", "name", "email", "phone", "account")}
            for c in contacts.list_contacts()}


def list_all(today=None):
    groups = {g["id"]: g for g in list_groups()}
    people = _people()
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM portfolio_domains ORDER BY domain").fetchall()
    return [_enrich(r, groups, today, people) for r in rows]


def get(domain_id):
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM portfolio_domains WHERE id = ?", (int(domain_id),)).fetchone()
    return _enrich(row, {g["id"]: g for g in list_groups()}, people=_people()) if row else None


def summary(domains, groups):
    """Counts per unit and in total. A unit's counts are its own domains;
    "subtree" adds those of every unit below it."""
    def counts(items):
        return {"total": len(items),
                **{flag: sum(1 for d in items if flag in d["flags"])
                   for flag in ("attention", "expiring", "move", "unmeasured", "intel", "claimable",
                                "use_unmeasured", "wanted", "dns_dead")}}
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


CSV_COLUMNS = ["domain", "unit", "phase", "registrar", "reseller", "transfer", "expires",
               "days_left", "registered_on", "dnssec", "nameservers", "status", "last_checked_at",
               "last_error", "decision", "threat_intel", "mail", "web", "contact", "contact_email",
               "contact_from", "dns"]


def to_csv(domains):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for d in domains:
        values = {**d, "nameservers": " ".join(d.get("nameservers") or []),
                  "status": "; ".join(d.get("status") or []),
                  "expires": d.get("expires") or ("not published" if d["expiry_state"] == "not_published" else ""),
                  "days_left": "" if d.get("days_left") is None else d["days_left"],
                  "decision": d.get("lifecycle"),
                  "threat_intel": d.get("threat_intel_state"),
                  # yes / no / empty: empty is "not measured", never "no".
                  "mail": d.get("uses_mail") or "", "web": d.get("uses_web") or "",
                  # ok, no_answer (its name servers do not answer), or empty: not measured.
                  "dns": d.get("dns_state") or "",
                  "contact": (d.get("contact") or {}).get("name"),
                  "contact_from": ("" if not d.get("contact")
                                   else "unit" if d.get("contact_inherited") else "domain"),
                  "contact_email": (d.get("contact") or {}).get("email")}
        writer.writerow([whois_batch._csv_safe(values.get(c)) for c in CSV_COLUMNS])
    return out.getvalue()


# ---------------------------------------------------------------- checking

def _release_window(domain, now):
    released = domain.get("released_from")
    if not released:
        return False
    try:
        at = datetime.fromisoformat(str(released).replace("Z", "+00:00"))
    except ValueError:
        return False
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return at - _RELEASE_BEFORE <= now <= at + _RELEASE_AFTER


def is_due(domain, now=None):
    now = now or _now()
    if not domain.get("last_checked_at"):
        return True
    elapsed = now - datetime.fromisoformat(domain["last_checked_at"])
    wanted = domain.get("lifecycle") == "claim"
    if wanted and _release_window(domain, now):
        return elapsed >= timedelta(seconds=55)
    if domain.get("last_error") or domain.get("phase") in ("quarantine", "pending_delete",
                                                           "redemption", "unmeasured"):
        return elapsed >= timedelta(hours=1)
    days = _days_left(domain.get("expires"), now.date())
    if wanted or (days is not None and days <= _SOON.days):
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
    lifecycle = old.get("lifecycle") or DEFAULT_LIFECYCLE
    if lifecycle == "cancel":
        return _changes_cancelled(domain, old, new)
    if lifecycle == "claim":
        return _changes_wanted(domain, old, new)
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


def _changes_cancelled(domain, old, new):
    """A domain being let go: lapsing is the plan, recorded but not alarming.
    A takeover while it is still registered to you is still news."""
    out = []
    if new["phase"] != old.get("phase"):
        before = PHASE_TEXT.get(old.get("phase"), old.get("phase"))
        after = PHASE_TEXT.get(new["phase"], new["phase"])
        out.append(("phase", "low", f"{domain}: {before} -> {after} (marked to cancel)."))
    for field, label in (("registrar", "registrar"), ("reseller", "reseller")):
        if new.get(field) and old.get(field) and new[field] != old[field]:
            out.append((field, "high", f"{domain} changed {label}: {old[field]} -> {new[field]}."))
    if new.get("nameservers") and old.get("nameservers") and new["nameservers"] != old["nameservers"]:
        out.append(("nameservers", "high",
                    f"{domain} has new name servers: {new['nameservers']} (was {old['nameservers']})."))
    return out


def _changes_wanted(domain, old, new):
    """A domain still to be requested or claimed: it coming free is the news,
    and so is it being registered again before you got to it."""
    was = old.get("phase")
    if new["phase"] == was:
        return []
    before = PHASE_TEXT.get(was, was)
    if new["phase"] == "not_registered":
        return [("phase", "high", f"{domain} is no longer registered (was: {before}): it can be requested now.")]
    if new["phase"] == "registered" and was in ("quarantine", "pending_delete", "redemption", "not_registered"):
        # Registered on or after the day it was released: a new holder, which
        # may be you. Before that: the old holder restored it.
        released = str(old.get("released_from") or new.get("released_from") or "")[:10]
        registered_on = str(new.get("registered_on") or "")[:10]
        if registered_on and released and registered_on >= released:
            return [("phase", "high", f"{domain} was registered again on {registered_on} by a new holder. "
                                      "If that was not you, it is taken.")]
        return [("phase", "medium", f"{domain} is registered again (restored by the holder).")]
    if new["phase"] == "quarantine":
        when = f"; released from {new['released_from']}" if new.get("released_from") else ""
        return [("phase", "medium", f"{domain} went into quarantine{when} (to request or claim).")]
    after = PHASE_TEXT.get(new["phase"], new["phase"])
    return [("phase", "medium", f"{domain}: {before} -> {after} (to request or claim).")]


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


def check(row, *, fetch=None, notify=None, now=None, probe=None):
    """Look one domain up, store the answer, and report what changed.

    `probe` measures whether the domain is in use. A caller that brings its
    own `fetch` brings its own probe too, or none: then the use stays as it
    was rather than being measured against the live DNS.
    """
    now = now or _now()
    if probe is None and fetch is None:
        probe = probe_usage
    if row.get("lifecycle") == "claim":
        probe = None        # someone else's domain: its use is not ours to measure
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
        held = (row.get("lifecycle") or DEFAULT_LIFECYCLE) not in _NOT_HELD
        warning = _expiry_warning(row["domain"], row, new, now.date()) if held else None
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
    dns = _store_usage(row, new["phase"], probe, stamp)
    if (row.get("lifecycle") or DEFAULT_LIFECYCLE) not in _NOT_HELD:
        change = _dns_change(row["domain"], row.get("dns_state"), dns)
        if change:
            changes.append(("dns",) + change)
            with db._lock, db._connect() as conn:
                conn.execute("INSERT INTO portfolio_events (domain, at, kind, detail) VALUES (?, ?, 'dns', ?)",
                             (row["domain"], stamp, change[1]))
    for _, severity, text in changes:
        (notify or _notify)(row["domain"], severity, text)
    return [{"domain": row["domain"], "kind": k, "severity": s, "detail": t} for k, s, t in changes]


def _store_usage(row, phase, probe, stamp):
    """Mail and web use: measured for a registered domain, "no" for one that
    has no DNS at all, and left as it was when it could not be measured.
    Returns the domain's DNS state when it was measured, else None."""
    dns = None
    if phase in _NO_DNS_PHASES:
        mail = web = "no"
    elif probe is not None and phase == "registered":
        try:
            found = probe(row["domain"]) or {}
        except Exception:
            found = {}
        word = {True: "yes", False: "no"}
        mail, web = word.get(found.get("mail")), word.get(found.get("web"))
        dns = found.get("dns")
        if mail is None and web is None and dns is None:
            return None
    else:
        return None
    with db._lock, db._connect() as conn:
        conn.execute("UPDATE portfolio_domains SET uses_mail = COALESCE(?, uses_mail), "
                     "uses_web = COALESCE(?, uses_web), dns_state = ?, usage_checked_at = ? WHERE id = ?",
                     (mail, web, dns, stamp, row["id"]))
    return dns


def _dns_change(domain, was, now):
    """(severity, text) when a held domain's name servers stop or start
    answering. The first measurement is a baseline, as elsewhere."""
    if was == "ok" and now == "no_answer":
        return "high", (f"{domain}: its name servers do not answer; the domain resolves nowhere "
                        "(no web, no mail). If the name servers' own domain lapses, someone else "
                        "could take over its DNS.")
    if was == "no_answer" and now == "ok":
        return "medium", f"{domain}: its name servers answer again."
    return None


def _sends_mail(spf):
    """An SPF record that allows any sender. "v=spf1 -all" is the opposite:
    the domain declares that it sends no mail at all."""
    terms = spf.lower().split()[1:]
    return any(not t.endswith("all") and not t.startswith(("exp=", "-", "~")) for t in terms) \
        or any(t in ("all", "+all", "?all") for t in terms)


def probe_usage(domain, query=None, delegation=None):
    """{"mail": bool|None, "web": bool|None, "dns": "ok"|"no_answer"|None}.

    Mail: an MX other than the null MX ("0 ."), or an SPF record that lets
    someone send. Web: an address (A or AAAA) on the domain or www. -- which a
    parking page has too, so "web" means reachable, not "a real site".

    When not one question gets an answer, the name servers the registry
    delegates the domain to are asked themselves: if none of them answers,
    the domain resolves nowhere ("no_answer"), which is a finding about the
    domain. If they do answer, the failure was ours, and use stays unknown.
    """
    if query is None or delegation is None:
        import dns_tools
        query = query or dns_tools.query
        delegation = delegation or dns_tools.nameservers_answer

    def records(name, rtype):
        try:
            r = query(name, rtype)
        except Exception:
            return None
        if r.get("error") or r.get("rcode") not in ("NOERROR", "NXDOMAIN"):
            return None
        return r.get("records") or []

    mx = records(domain, "MX")
    txt = records(domain, "TXT")
    has_mx = None if mx is None else any(r.split()[-1:] != ["."] for r in mx)
    spf = None if txt is None else any(t.lower().startswith("v=spf1") and _sends_mail(t) for t in txt)
    mail = True if (has_mx or spf) else (None if None in (has_mx, spf) else False)
    answers = [records(n, t) for n in (domain, f"www.{domain}") for t in ("A", "AAAA")]
    web = True if any(answers) else (None if None in answers else False)
    if all(a is None for a in [mx, txt] + answers):
        try:
            answered = delegation(domain)
        except Exception:
            answered = None
        dns = "no_answer" if answered is False else None
    else:
        dns = "ok"
    return {"mail": mail, "web": web, "dns": dns}


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
