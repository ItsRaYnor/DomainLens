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


def init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS portfolio_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            expected_registrar TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
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


# ---------------------------------------------------------------- groups

def list_groups():
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM portfolio_groups ORDER BY name COLLATE NOCASE").fetchall()
    return [dict(r) for r in rows]


def _clean_group_name(name):
    name = " ".join(str(name or "").split())[:80]
    if not name:
        raise ValueError("A group needs a name")
    return name


def ensure_group(name, conn=None):
    """The id of the group with this name, created when it does not exist."""
    name = _clean_group_name(name)

    def run(c):
        row = c.execute("SELECT id FROM portfolio_groups WHERE name = ?", (name,)).fetchone()
        if row:
            return row["id"]
        return c.execute("INSERT INTO portfolio_groups (name, created_at) VALUES (?, ?)",
                         (name, _now().isoformat())).lastrowid

    if conn is not None:
        return run(conn)
    with db._lock, db._connect() as c:
        return run(c)


def update_group(group_id, *, name=None, expected_registrar=None):
    fields, values = [], []
    if name is not None:
        fields.append("name = ?")
        values.append(_clean_group_name(name))
    if expected_registrar is not None:
        fields.append("expected_registrar = ?")
        values.append(" ".join(str(expected_registrar).split())[:200] or None)
    if not fields:
        return get_group(group_id)
    with db._lock, db._connect() as conn:
        try:
            conn.execute(f"UPDATE portfolio_groups SET {', '.join(fields)} WHERE id = ?",
                         (*values, int(group_id)))
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise ValueError("Another group already has that name") from exc
            raise
    return get_group(group_id)


def get_group(group_id):
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM portfolio_groups WHERE id = ?", (int(group_id),)).fetchone()
    return dict(row) if row else None


def delete_group(group_id):
    """Remove a group; its domains stay, ungrouped."""
    with db._lock, db._connect() as conn:
        conn.execute("UPDATE portfolio_domains SET group_id = NULL WHERE group_id = ?", (int(group_id),))
        return conn.execute("DELETE FROM portfolio_groups WHERE id = ?", (int(group_id),)).rowcount > 0


# ---------------------------------------------------------------- import

_SPLIT = re.compile(r"[\t;,]")


def _domain_of(token):
    found, _ = whois_batch.parse_domains(token)
    return found[0] if len(found) == 1 and "." in token else None


def parse_import(text):
    """[(domain, group or None)] and rejected tokens from a paste or a CSV.

    One domain per line, optionally followed by its group in the next column
    (comma, semicolon or tab): "example.nl;Sales". A line with several names
    and no group ("example.nl example.com") adds them all. A first line that
    is a header is skipped, and a dotted token that is not a domain name is
    rejected rather than guessed.
    """
    entries, rejected, seen = [], [], set()
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        cells = next(csv.reader([line], delimiter=_delimiter(line)), [])
        cells = [c.strip().strip('"\'') for c in cells if c.strip()]
        names, others = [], []
        for cell in cells:
            domain = _domain_of(cell)
            if domain:
                names.append(domain)
            elif " " in cell and all(_domain_of(t) for t in cell.split()):
                names.extend(_domain_of(t) for t in cell.split())
            else:
                others.append(cell)
        if not names:
            if cells and "." in cells[0] and " " not in cells[0]:
                rejected.append(cells[0])
            continue          # a header, or a line without a domain
        # "example.nl;Sales" names its group; "example.nl, example.com" is
        # just a list. The group is the first cell that is not a domain.
        group = others[0] if others else None
        pairs = [(n, group) for n in names]
        for domain, group in pairs:
            if domain not in seen:
                seen.add(domain)
                entries.append((domain, " ".join(group.split())[:80] if group else None))
    return entries, rejected


def _delimiter(line):
    for d in ("\t", ";", ","):
        if d in line:
            return d
    return ","


def import_domains(entries, *, default_group=None, created_by=None):
    """Add or regroup domains. Returns counts and the names that changed.

    A domain already in the portfolio is moved to the group the import
    names for it; one imported without a group keeps the group it has.
    """
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
        default_id = ensure_group(default_group, conn) if default_group else None
        for domain, group in entries:
            group_id = ensure_group(group, conn) if group else default_id
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
        raise ValueError("Unknown group")
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
    """Whether the domain is at the registrar its group expects.

    "ok", "move", "unmeasured" (no registrar known yet) or "not_applicable"
    (the group names no registrar). A match on the reseller counts too: for
    .nl the name a customer knows is often the reseller, not the registrar.
    """
    expected = [e.strip().lower() for e in str((group or {}).get("expected_registrar") or "").split(",")
                if e.strip()]
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
    out["group"] = group["name"] if group else None
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
    """Counts per group and in total, for the headers and the tiles."""
    def counts(items):
        return {"total": len(items),
                **{flag: sum(1 for d in items if flag in d["flags"])
                   for flag in ("attention", "expiring", "move", "unmeasured")}}
    per_group = []
    for g in groups:
        per_group.append({**g, **counts([d for d in domains if d.get("group_id") == g["id"]])})
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
