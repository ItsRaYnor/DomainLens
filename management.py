"""One page for management: how the domains stand, and which way it is going.

The trends page answers an engineer's questions (scans per day, header
scores); a manager asks different ones: how many domains are in order, what
the biggest risks are across all of them, whether it is getting better, and
which registrations need a decision. Those answers live in every domain's
latest scan, so they are computed from it here instead of being guessed from
the stored TLS grade, which only ever described TLS.

The rating is deliberately simple enough to explain in one sentence per
letter (see RATING_TEXT), so a reader can check it against the findings.
Nothing is averaged over what was not measured: a control that could not be
checked is counted as such, never as passed or failed.
"""

from __future__ import annotations

import threading
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone

import db
import overview
import recommendations

SEVERITIES = ("critical", "high", "medium", "low")

RATING_TEXT = {
    "A": "No open findings of medium severity or worse",
    "B": "Only medium findings open",
    "C": "One or two high findings, nothing critical",
    "D": "Three or more high findings, nothing critical",
    "F": "At least one critical finding",
}

_CACHE_MAX = 5000
# (scan id, created_at) -> summary. A stored scan never changes, but SQLite
# may hand a deleted scan's id to the next one, so the id alone is not a key.
_cache = OrderedDict()
_cache_lock = threading.Lock()


# ---------------------------------------------------------------- controls

def _measured(block):
    return isinstance(block, dict) and bool(block) and block.get("state", "measured") == "measured"


def _dmarc(r):
    d = r.get("dmarc")
    if not _measured(d):
        return "unmeasured"
    return "pass" if d.get("found") and (d.get("policy") or "").lower() in ("quarantine", "reject") else "fail"


def _spf(r):
    s = r.get("spf")
    if not _measured(s):
        return "unmeasured"
    return "pass" if s.get("found") and s.get("strict") else "fail"


def _dnssec(r):
    d = r.get("dnssec")
    if not _measured(d):
        return "unmeasured"
    return "pass" if d.get("signed") else "fail"


def _tls(r):
    t = r.get("tls_deep") or {}
    if not t.get("success") or not t.get("grade"):
        return "unmeasured"
    return "pass" if t["grade"] in ("A+", "A", "B") else "fail"


def _hsts(r):
    t = r.get("tls_deep") or {}
    enabled = (t.get("hsts") or {}).get("enabled") if t.get("success") else None
    return "unmeasured" if enabled is None else ("pass" if enabled else "fail")


def _https(r):
    red = r.get("https_redirect")
    if not isinstance(red, dict) or red.get("blocked") or red.get("pass") is None:
        return "unmeasured"
    return "pass" if red["pass"] else "fail"


def _reputation(r):
    tile = overview.blacklist(r)
    if not tile:
        return "unmeasured"
    # A CDN edge or PBL entry is context, not this domain's reputation.
    return "fail" if tile["state"] == "fail" else "pass"


CONTROLS = [
    ("dmarc", "DMARC blocks spoofed mail (quarantine or reject)", _dmarc),
    ("spf", "SPF is strict (-all)", _spf),
    ("dnssec", "DNSSEC signed", _dnssec),
    ("tls", "TLS rated A or B", _tls),
    ("hsts", "HSTS enabled", _hsts),
    ("https", "HTTP redirects to HTTPS", _https),
    ("reputation", "Not on a reputation blocklist", _reputation),
]


def rating(counts):
    if counts.get("critical"):
        return "F"
    if counts.get("high", 0) >= 3:
        return "D"
    if counts.get("high"):
        return "C"
    if counts.get("medium"):
        return "B"
    return "A"


def rating_of(recs):
    """The rating of a list of findings: open ones only, accepted left out."""
    return rating(Counter(r["severity"] for r in recs or [] if not r.get("accepted")))


def posture(recs):
    """{rating, text, counts} for a scan result or report."""
    counts = Counter(r["severity"] for r in recs or [] if not r.get("accepted"))
    letter = rating(counts)
    return {"rating": letter, "text": RATING_TEXT[letter],
            "counts": {s: counts.get(s, 0) for s in SEVERITIES}}


def fill_ratings(scans):
    """Give listed scans their rating, computing and storing it for rows
    saved before the rating was kept."""
    for scan in scans:
        if scan.get("rating"):
            continue
        record = db.get_scan(scan["id"])
        if not record:
            continue
        scan["rating"] = summarize_scan((record["id"], record["created_at"]), record.get("data"))["rating"]
        with db._lock, db._connect() as conn:
            conn.execute("UPDATE scan_metrics SET rating = ? WHERE scan_id = ?", (scan["rating"], scan["id"]))
    return scans


def summarize_scan(key, data):
    """Rating, findings and control states of one stored scan (cached)."""
    with _cache_lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    data = data or {}
    recs = recommendations.generate(data)
    open_recs = [r for r in recs if not r.get("accepted")]
    counts = Counter(r["severity"] for r in open_recs)
    if data.get("not_delegated"):
        controls = {key: "not_applicable" for key, _, _ in CONTROLS}
    else:
        controls = {}
        for key, _, fn in CONTROLS:
            try:
                controls[key] = fn(data)
            except Exception:
                controls[key] = "unmeasured"
    summary = {
        "counts": {s: counts.get(s, 0) for s in SEVERITIES},
        "accepted": sum(1 for r in recs if r.get("accepted")),
        "rating": rating(counts),
        "controls": controls,
        "findings": [{"severity": r["severity"], "category": r.get("category") or "Other",
                      "title": r.get("title") or ""} for r in open_recs
                     if r["severity"] in SEVERITIES],
    }
    with _cache_lock:
        _cache[key] = summary
        while len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)
    return summary


# ---------------------------------------------------------------- scope

def _in_scope(domain, wanted):
    """A scan of a subdomain belongs to the portfolio domain above it."""
    if wanted is None:
        return True
    parts = domain.split(".")
    return any(".".join(parts[i:]) in wanted for i in range(len(parts) - 1))


def _scope(group_id):
    """(set of portfolio domains, unit path) or (None, None) for everything.

    A unit includes the units below it: the dashboard of a company covers
    its business units."""
    if group_id is None:
        return None, None
    import domain_portfolio
    group = domain_portfolio.get_group(group_id)
    if not group:
        raise ValueError("Unknown unit")
    below = domain_portfolio.descendants(group["id"])
    domains = {d["domain"] for d in domain_portfolio.list_all() if d.get("group_id") in below}
    return domains, group["path"]


def _latest_scans(until, wanted, since=None):
    """{domain: (scan id, created_at)} of the newest scan per domain up to `until`."""
    clauses, params = ["created_at <= ?"], [until]
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    with db._lock, db._connect() as conn:
        rows = conn.execute(
            f"SELECT domain, MAX(id) AS id, created_at FROM scans "
            f"WHERE {' AND '.join(clauses)} GROUP BY domain", params).fetchall()
    return {r["domain"]: (r["id"], r["created_at"]) for r in rows if _in_scope(r["domain"], wanted)}


def _load(keys):
    """{(scan id, created_at): summary}, reading JSON only for uncached scans."""
    out, missing = {}, []
    with _cache_lock:
        for key in keys:
            if key in _cache:
                out[key] = _cache[key]
            else:
                missing.append(key)
    for key in missing:
        record = db.get_scan(key[0])
        if record:
            out[key] = summarize_scan(key, record.get("data"))
    return out


def latest_scan_keys(domains):
    """{host: (scan id, created_at)} of the newest scan of each host of
    these domains, the domains themselves included."""
    return _latest_scans(datetime.now(timezone.utc).isoformat(), set(domains))


def load_summaries(keys):
    """{(scan id, created_at): summary} for the given scans (cached)."""
    return _load(keys)


# ---------------------------------------------------------------- the page

def _trend(start, end, wanted, buckets):
    """Per bucket end: domains assessed and their open findings, from the
    stored per-scan counts (no JSON is read for history)."""
    with db._lock, db._connect() as conn:
        rows = conn.execute(
            "SELECT domain, scan_id, created_at, recommendation_count FROM scan_metrics "
            "WHERE created_at <= ? ORDER BY created_at, scan_id", (end.isoformat(),)).fetchall()
    rows = [r for r in rows if _in_scope(r["domain"], wanted)]
    step = (end - start) / buckets
    series, latest, i = [], {}, 0
    for b in range(1, buckets + 1):
        edge = (start + step * b).isoformat()
        while i < len(rows) and rows[i]["created_at"] <= edge:
            latest[rows[i]["domain"]] = rows[i]["recommendation_count"] or 0
            i += 1
        series.append({"at": edge[:10], "domains": len(latest),
                       "open_findings": sum(latest.values())})
    return series


def dashboard(days=90, group_id=None, now=None):
    days = max(7, min(int(days), 365))
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    wanted, group_name = _scope(group_id)

    current = _latest_scans(now.isoformat(), wanted, since=start.isoformat())
    before = _latest_scans(start.isoformat(), wanted)
    stale = sorted(set(before) - set(current))
    summaries = _load(set(current.values()) | {before[d] for d in current if d in before})

    domains = []
    for domain, key in sorted(current.items()):
        s = summaries.get(key)
        if not s:
            continue
        prev = summaries.get(before.get(domain))
        domains.append({"domain": domain, "scan_id": key[0], "key": key, "rating": s["rating"],
                        "counts": s["counts"], "accepted": s["accepted"],
                        "previous_rating": prev["rating"] if prev else None})

    ratings = Counter(d["rating"] for d in domains)
    totals = {sev: sum(d["counts"][sev] for d in domains) for sev in SEVERITIES}

    controls = []
    for key, label, _ in CONTROLS:
        states = Counter(summaries[current[d["domain"]]]["controls"][key] for d in domains)
        measured = states["pass"] + states["fail"]
        controls.append({"key": key, "label": label, "pass": states["pass"], "fail": states["fail"],
                         "unmeasured": states["unmeasured"],
                         "not_applicable": states["not_applicable"],
                         "pass_rate": round(100 * states["pass"] / measured) if measured else None})

    by_category, common = {}, {}
    for d in domains:
        seen = set()
        for f in summaries[d["key"]]["findings"]:
            cat = by_category.setdefault(f["category"], {s: 0 for s in SEVERITIES})
            cat[f["severity"]] += 1
            key = (f["severity"], f["title"])
            if key not in seen:
                seen.add(key)
                common.setdefault(key, []).append(d["domain"])
    order = {s: i for i, s in enumerate(SEVERITIES)}
    top_findings = sorted(
        ({"severity": s, "title": t, "domains": len(ds), "examples": ds[:5]}
         for (s, t), ds in common.items() if s in ("critical", "high", "medium")),
        key=lambda f: (order[f["severity"]], -f["domains"], f["title"]))[:10]

    rank = {r: i for i, r in enumerate("FDCBA")}
    attention = sorted((d for d in domains if d["rating"] in ("F", "D", "C")),
                       key=lambda d: (rank[d["rating"]], -d["counts"]["critical"],
                                      -d["counts"]["high"], d["domain"]))[:10]
    compared = [d for d in domains if d["previous_rating"]]
    improved = [d for d in compared if rank[d["rating"]] > rank[d["previous_rating"]]]
    worsened = [d for d in compared if rank[d["rating"]] < rank[d["previous_rating"]]]

    in_order = ratings["A"] + ratings["B"]
    return {
        "generated_at": now.isoformat(),
        "days": days,
        "group": group_name,
        "rating_text": RATING_TEXT,
        "kpis": {
            "domains": len(domains),
            "in_order": in_order,
            "in_order_pct": round(100 * in_order / len(domains)) if domains else None,
            "critical": totals["critical"], "high": totals["high"],
            "accepted": sum(d["accepted"] for d in domains),
            "improved": len(improved), "worsened": len(worsened), "compared": len(compared),
            "not_rescanned": len(stale),
        },
        "ratings": {r: ratings.get(r, 0) for r in "ABCDF"},
        "totals": totals,
        "controls": controls,
        "by_category": dict(sorted(by_category.items(),
                                   key=lambda kv: -sum(kv[1][s] * (4 - order[s]) for s in SEVERITIES))),
        "top_findings": top_findings,
        "attention": attention,
        "improved": improved[:10],
        "worsened": worsened[:10],
        "not_rescanned": stale[:20],
        "trend": _trend(start, now, wanted, 12 if days > 31 else days),
        "portfolio": _portfolio(group_id),
        "monitoring": _monitoring(days),
    }


def _portfolio(group_id):
    try:
        import domain_portfolio
        domains = domain_portfolio.list_all()
        groups = domain_portfolio.list_groups()
    except Exception:
        return None
    if group_id is not None:
        below = domain_portfolio.descendants(group_id, groups)
        domains = [d for d in domains if d.get("group_id") in below]
        groups = [g for g in groups if g["id"] in below]
    if not domains:
        return None
    summary = domain_portfolio.summary(domains, groups)
    expiring = sorted((d for d in domains if "expiring" in d["flags"]),
                      key=lambda d: d["days_left"])[:10]
    return {"total": summary["total"], "groups": summary["groups"],
            "expiring": [{"domain": d["domain"], "expires": d["expires"], "days_left": d["days_left"],
                          "group": d["group"]} for d in expiring],
            "attention": [{"domain": d["domain"], "phase_text": d["phase_text"], "group": d["group"]}
                          for d in domains if "attention" in d["flags"]][:10]}


def _monitoring(days):
    try:
        overview_ = db.reporting_overview(days=days)
        stats = db.monitor_stats()
    except Exception:
        return None
    return {"events_by_severity": overview_.get("events_by_severity") or {},
            "enabled_monitors": stats.get("enabled_monitors", 0)}


# ---------------------------------------------------------------- organisation

def organisation(days=90, now=None):
    """Per organisation unit, both kinds of monitoring side by side.

    Security: the domains scanned in the period with their rating and open
    critical and high findings, the monitors and their recent events.
    Registration: the portfolio counts (at risk, expiring, to move). Every
    figure of a unit includes the units below it. Hosts whose registered
    domain is in no unit are counted apart, so nothing silently drops out.
    """
    import domain_portfolio
    days = max(7, min(int(days), 365))
    now = now or datetime.now(timezone.utc)
    groups = domain_portfolio.list_groups()
    units = domain_portfolio.units_by_domain()
    parents = {g["id"]: g["parent_id"] for g in groups}

    def chain(host):
        unit, seen = units.get(domain_portfolio.registrable(host)), []
        while unit is not None and unit not in seen and unit in parents:
            seen.append(unit)
            unit = parents.get(unit)
        return seen or [None]

    def blank():
        return {"scanned": 0, "ratings": {r: 0 for r in "ABCDF"}, "critical": 0, "high": 0,
                "monitors": 0, "monitors_enabled": 0,
                "events": {s: 0 for s in ("critical", "high", "medium", "low", "info")}}

    security = {g["id"]: blank() for g in groups}
    security[None] = blank()

    current = _latest_scans(now.isoformat(), None, since=(now - timedelta(days=days)).isoformat())
    summaries = _load(set(current.values()))
    for host, key in current.items():
        s = summaries.get(key)
        if not s:
            continue
        for unit in chain(host):
            bucket = security[unit]
            bucket["scanned"] += 1
            bucket["ratings"][s["rating"]] += 1
            bucket["critical"] += s["counts"]["critical"]
            bucket["high"] += s["counts"]["high"]

    monitor_units = {}
    for m in db.list_monitors(limit=5000):
        monitor_units[m["id"]] = chain(m.get("target") or m.get("domain") or "")
        for unit in monitor_units[m["id"]]:
            security[unit]["monitors"] += 1
            security[unit]["monitors_enabled"] += 1 if m.get("enabled") else 0
    since = (now - timedelta(days=7)).isoformat()
    with db._lock, db._connect() as conn:
        rows = conn.execute("SELECT monitor_id, severity, COUNT(*) AS c FROM monitor_events "
                            "WHERE created_at >= ? GROUP BY monitor_id, severity", (since,)).fetchall()
    for row in rows:
        for unit in monitor_units.get(row["monitor_id"], [None]):
            events = security[unit]["events"]
            sev = row["severity"] if row["severity"] in events else "info"
            events[sev] += row["c"]

    registration = {g["id"]: g["subtree"] for g in
                    domain_portfolio.summary(domain_portfolio.list_all(), groups)["groups"]}
    return {
        "generated_at": now.isoformat(),
        "days": days,
        "units": [{"id": g["id"], "name": g["name"], "path": g["path"], "depth": g["depth"],
                   "parent_id": g["parent_id"], "expected_registrar": g.get("expected_registrar"),
                   "effective_registrar": g.get("effective_registrar"),
                   "registrar_inherited": g.get("registrar_inherited"),
                   "notify_emails": [e for e in (g.get("notify_emails") or "").split(",") if e],
                   "security": security[g["id"]], "registration": registration.get(g["id"])}
                  for g in groups],
        "unassigned": security[None],
    }
