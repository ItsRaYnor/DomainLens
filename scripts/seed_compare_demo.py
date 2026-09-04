"""Seed two scans of a fake domain so the comparison views have something to show.

Reports -> Compare and the Trends issues drill-down both need two scans of one
domain on different days. On a fresh install there is nothing to compare, and
the honest "no scan in that period" message looks like a broken page.

This writes throwaway rows for domains under .invalid -- a TLD reserved by
RFC 2606 precisely so it can never collide with anything real. Nothing here
touches your own scans.

    python scripts/seed_compare_demo.py            # add the demo rows
    python scripts/seed_compare_demo.py --remove   # take them out again

DOMAINLENS_DB must point at the database you are testing against, the same
way you start the app.
"""

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db  # noqa: E402  (path set above so this runs from anywhere)

# .invalid can never resolve, so these rows are recognisable as demo data at a
# glance and a stray scan of one can never reach a real host.
SPIKED = "spiked.invalid"
STEADY = "steady.invalid"
FIXED = "fixed.invalid"
ONCE = "once.invalid"
DEMO_DOMAINS = (SPIKED, STEADY, FIXED, ONCE)

STRONG = {
    "spf": {"found": True, "record": "v=spf1 mx include:_spf.example.com -all",
            "strict": True, "multiple_records": False},
    "dmarc": {"found": True, "policy": "reject",
              "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
    "dkim": {"found": True},
    "dnssec": {"signed": True, "status": "DNSSEC enabled"},
    "mta_sts": {"found": True},
    "tlsrpt": {"found": True},
    "tls_deep": {"grade": "A+", "protocols": [
        {"name": "TLS 1.2", "supported": True}, {"name": "TLS 1.3", "supported": True}]},
    "ssl": {"not_after": "2027-01-05T23:59:59+00:00", "expired": False,
            "issuer": {"organizationName": "Let's Encrypt"}},
    "http_headers": {"score": 90, "headers_missing": [], "status_code": 200},
    "https_redirect": {"pass": True},
    "blacklist": {"is_listed": False},
    "ipv6": {"has_ipv6": True, "mail_pass": True},
}

# The same site after a bad month: SPF weakened to a soft fail, DMARC dropped
# to monitoring only, DNSSEC switched off, TLS 1.0 back on, a header gone.
WEAK = {
    "spf": {"found": True, "record": "v=spf1 mx include:_spf.example.com ~all",
            "strict": False, "multiple_records": False},
    "dmarc": {"found": True, "policy": "none",
              "record": "v=DMARC1; p=none; rua=mailto:dmarc@example.com"},
    "dkim": {"found": False},
    "dnssec": {"signed": False, "status": "Not signed"},
    "mta_sts": {"found": False},
    "tlsrpt": {"found": True},
    "tls_deep": {"grade": "C", "protocols": [
        {"name": "TLS 1.0", "supported": True}, {"name": "TLS 1.2", "supported": True}]},
    "ssl": {"not_after": "2028-02-10T23:59:59+00:00", "expired": False,
            "issuer": {"organizationName": "Let's Encrypt"}},
    "http_headers": {"score": 58,
                     "headers_missing": ["Content-Security-Policy", "Permissions-Policy"],
                     "status_code": 200},
    "https_redirect": {"pass": True},
    "blacklist": {"is_listed": True},
    "ipv6": {"has_ipv6": True, "mail_pass": False},
}


def _insert(conn, domain, day, issues, grade, payload):
    """A scan row plus its metrics row.

    Both are needed: Compare reads the JSON payload on `scans`, while the
    trends drill-downs read the flattened `scan_metrics`. Writing only one
    makes half the feature look broken.
    """
    created = f"{day}T10:00:00+00:00"
    cur = conn.execute(
        "INSERT INTO scans (domain, created_at, grade, score, issues_count, data)"
        " VALUES (?,?,?,?,?,?)",
        (domain, created, grade, 100 - issues * 3, issues,
         json.dumps({**payload, "domain": domain, "timestamp": created})),
    )
    scan_id = cur.lastrowid
    conn.execute(
        "INSERT INTO scan_metrics (scan_id, domain, day, created_at, grade,"
        " grade_score, header_score, issues_count, blacklist_listed,"
        " dnssec_signed, https_redirect) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, domain, day, created, grade,
         {"A+": 95, "A": 90, "B": 75, "C": 60}.get(grade, 50),
         payload["http_headers"]["score"], issues,
         1 if payload["blacklist"]["is_listed"] else 0,
         1 if payload["dnssec"]["signed"] else 0, 1),
    )
    return scan_id


def seed():
    today = datetime.date.today()
    earlier = (today - datetime.timedelta(days=25)).isoformat()
    now = today.isoformat()

    with db._lock, db._connect() as conn:
        existing = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE domain LIKE '%.invalid'").fetchone()[0]
        if existing:
            print(f"{existing} demo row(s) already present. "
                  f"Run with --remove first if you want a clean set.")
            return

        # Four shapes, because the point of the drill-down is telling them
        # apart: one that got worse, one that stood still at the same number,
        # one that improved, and one with nothing to compare against.
        _insert(conn, SPIKED, earlier, 2, "A+", STRONG)
        _insert(conn, SPIKED, now, 20, "C", WEAK)

        _insert(conn, STEADY, earlier, 20, "C", WEAK)
        _insert(conn, STEADY, now, 20, "C", WEAK)

        _insert(conn, FIXED, earlier, 15, "C", WEAK)
        _insert(conn, FIXED, now, 3, "A+", STRONG)

        _insert(conn, ONCE, now, 8, "B", WEAK)

    print(f"Seeded demo scans dated {earlier} and {now}:")
    print(f"  {SPIKED:18s} 2 -> 20 issues   (SPF -all -> ~all, DMARC reject -> none)")
    print(f"  {STEADY:18s} 20 -> 20 issues  (same count, nothing changed)")
    print(f"  {FIXED:18s} 15 -> 3 issues   (improved)")
    print(f"  {ONCE:18s} one scan only    (nothing to compare against)")
    print()
    print("Trends -> issues tile shows the movement; 'what changed' on the")
    print(f"{SPIKED} row opens the field-level comparison.")


def remove():
    with db._lock, db._connect() as conn:
        scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE domain LIKE '%.invalid'").fetchone()[0]
        conn.execute("DELETE FROM scan_metrics WHERE domain LIKE '%.invalid'")
        conn.execute("DELETE FROM scans WHERE domain LIKE '%.invalid'")
    print(f"Removed {scans} demo scan(s). Your own scans were not touched.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remove", action="store_true",
                        help="delete the demo rows again")
    args = parser.parse_args()

    if not os.environ.get("DOMAINLENS_DB"):
        print("Set DOMAINLENS_DB to the database you are testing against, the same\n"
              "way you start the app. Refusing to guess: writing demo rows into the\n"
              "wrong database is not something you can undo by rerunning this.")
        return 1

    print(f"Database: {os.environ['DOMAINLENS_DB']}")
    db.init_db()
    remove() if args.remove else seed()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
