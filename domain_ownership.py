"""Proof that a domain is yours before anything active is pointed at it.

Weak-auth (login attempts with default passwords) and the active scan
(XSS, open-redirect and SQL-injection probes) were gated by one switch each.
Once an operator turned one on for their own site, any signed-in user could
aim it at any domain on the internet. Against someone else's server that is
an unauthorised intrusion attempt, and the organisation running DomainLens is
the one whose address it comes from.

So these checks now run only against a domain that has been verified, the way
search consoles and scanning services do it:

  dns    a TXT record at _domainlens-challenge.<domain> holding the token
  http   https://<domain>/.well-known/domainlens-verification.txt holding it
  admin  an administrator attests it, with a reason, for hosts where neither
         is possible (an internal name, a zone managed elsewhere); the
         attestation is in the audit log under their name

Verifying a domain covers its subdomains: whoever controls the zone controls
every name in it. A proof expires after `max_age_days`, because domains are
sold and delegations change; an expired one reads as unverified until it is
checked again.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
from datetime import datetime, timedelta, timezone

import dns.resolver
import requests

import db

log = logging.getLogger("domainlens.ownership")

CHALLENGE_LABEL = "_domainlens-challenge"
TXT_PREFIX = "domainlens-verification="
WELL_KNOWN_PATH = "/.well-known/domainlens-verification.txt"
DEFAULT_MAX_AGE_DAYS = 365
_TIMEOUT = 8

# The checks this gate protects. Kept here so the gate and its callers agree.
GATED_CHECKS = ("weak_auth", "active_scan")


def init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS verified_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            token TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            method TEXT,
            note TEXT,
            requested_by TEXT,
            verified_by TEXT,
            created_at TEXT NOT NULL,
            verified_at TEXT,
            last_checked_at TEXT,
            last_error TEXT
        )
        """
    )


def _now():
    return datetime.now(timezone.utc)


def normalize(domain):
    return (domain or "").strip().lower().rstrip(".")


def _max_age_days():
    try:
        import config as domainlens_config
        value = domainlens_config.load_settings().ownership().get("max_age_days")
        return int(value) if value is not None else DEFAULT_MAX_AGE_DAYS
    except Exception:
        return DEFAULT_MAX_AGE_DAYS


def _row(row):
    if row is None:
        return None
    out = dict(row)
    out["expired"] = _is_expired(out)
    out["instructions"] = instructions(out["domain"], out["token"])
    return out


def _is_expired(row):
    if row.get("status") != "verified" or row.get("method") == "admin":
        # An attestation is a person's judgement, not a measurement that can
        # go stale; it stands until someone revokes it.
        return False
    max_age = _max_age_days()
    if max_age <= 0 or not row.get("verified_at"):
        return False
    try:
        verified = datetime.fromisoformat(row["verified_at"])
    except ValueError:
        return True
    return _now() - verified > timedelta(days=max_age)


def instructions(domain, token):
    return {
        "dns": {"name": f"{CHALLENGE_LABEL}.{domain}", "type": "TXT",
                "value": f"{TXT_PREFIX}{token}"},
        "http": {"url": f"https://{domain}{WELL_KNOWN_PATH}", "body": token},
    }


def get(domain):
    with db._connect() as conn:
        return _row(conn.execute("SELECT * FROM verified_domains WHERE domain = ?",
                                 (normalize(domain),)).fetchone())


def list_domains():
    with db._connect() as conn:
        return [_row(r) for r in conn.execute(
            "SELECT * FROM verified_domains ORDER BY domain").fetchall()]


def request_verification(domain, requested_by=None):
    """Create a pending entry with a fresh token, or return the existing one."""
    domain = normalize(domain)
    existing = get(domain)
    if existing:
        return existing
    with db._lock, db._connect() as conn:
        conn.execute(
            "INSERT INTO verified_domains (domain, token, status, requested_by, created_at) "
            "VALUES (?, ?, 'pending', ?, ?)",
            (domain, secrets.token_urlsafe(24), requested_by, _now().isoformat()),
        )
    return get(domain)


def _txt_values(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except Exception as exc:
        return [], f"DNS lookup failed: {type(exc).__name__}"
    values = []
    for rdata in answers:
        values.append(b"".join(rdata.strings).decode("utf-8", "replace").strip())
    return values, None


def _public_addresses_only(host):
    """Refuse to fetch from a name that resolves to a private address.

    The fetch goes wherever the DNS says, and a name pointed at 127.0.0.1 or
    a cloud metadata address would turn this into a request from the server
    into its own network.
    """
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(ipaddress.ip_address(a).is_global for a in addresses)


def _check_dns(domain, token):
    values, error = _txt_values(f"{CHALLENGE_LABEL}.{domain}")
    if f"{TXT_PREFIX}{token}" in values:
        return True, None
    return False, error or f"No TXT record {TXT_PREFIX}… with this token at {CHALLENGE_LABEL}.{domain}"


def _check_http(domain, token):
    if not _public_addresses_only(domain):
        return False, "The domain does not resolve to public addresses only"
    try:
        with requests.get(f"https://{domain}{WELL_KNOWN_PATH}", timeout=_TIMEOUT,
                          allow_redirects=False, stream=True) as resp:
            # Only the first few KB: the file holds one token.
            body = resp.raw.read(4096, decode_content=True).decode("utf-8", "replace")
    except (requests.RequestException, OSError) as exc:
        return False, f"HTTPS fetch failed: {type(exc).__name__}"
    if resp.status_code == 200 and token in body.split():
        return True, None
    return False, f"{WELL_KNOWN_PATH} returned {resp.status_code} without the token"


def check(domain, checked_by=None):
    """Try DNS, then HTTPS. Records the outcome either way."""
    entry = request_verification(domain, requested_by=checked_by)
    domain, token = entry["domain"], entry["token"]
    method, errors = None, []
    for name, probe in (("dns", _check_dns), ("http", _check_http)):
        ok, error = probe(domain, token)
        if ok:
            method = name
            break
        errors.append(error)
    now = _now().isoformat()
    with db._lock, db._connect() as conn:
        if method:
            conn.execute(
                "UPDATE verified_domains SET status='verified', method=?, verified_by=?, "
                "verified_at=?, last_checked_at=?, last_error=NULL, note=NULL WHERE domain=?",
                (method, checked_by, now, now, domain),
            )
        else:
            # A failed re-check leaves an earlier proof as it was: it expires
            # on its own schedule, and one DNS timeout should not revoke it.
            conn.execute(
                "UPDATE verified_domains SET last_checked_at=?, last_error=? WHERE domain=?",
                (now, "; ".join(e for e in errors if e), domain),
            )
    return get(domain)


def attest(domain, admin_email, note):
    note = (note or "").strip()
    if not note:
        raise ValueError("An attestation needs a reason, for whoever reads the audit log later")
    entry = request_verification(domain, requested_by=admin_email)
    now = _now().isoformat()
    with db._lock, db._connect() as conn:
        conn.execute(
            "UPDATE verified_domains SET status='verified', method='admin', verified_by=?, "
            "verified_at=?, note=?, last_error=NULL WHERE domain=?",
            (admin_email, now, note, entry["domain"]),
        )
    return get(domain)


def revoke(domain):
    with db._lock, db._connect() as conn:
        return conn.execute("DELETE FROM verified_domains WHERE domain = ?",
                            (normalize(domain),)).rowcount > 0


def _candidates(domain):
    labels = normalize(domain).split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def verification_for(domain):
    """The verified, unexpired entry covering this domain, or None."""
    candidates = _candidates(domain)
    if not candidates:
        return None
    with db._connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM verified_domains WHERE status='verified' AND domain IN "
            f"({', '.join('?' for _ in candidates)})", candidates).fetchall()
    for row in sorted((_row(r) for r in rows), key=lambda r: -len(r["domain"])):
        if not row["expired"]:
            return row
    return None


def is_verified(domain):
    return verification_for(domain) is not None


def not_verified_result(domain, enabled):
    """What a gated check returns instead of running.

    Deliberately not applicable, not "clean": the check did not look, and a
    result that said nothing was found would be claiming it had.
    """
    entry = get(domain)
    detail = (
        f"{domain} is not verified as yours, so no login attempts or attack "
        "probes were sent. Verify it under Admin → Verified domains (a DNS TXT "
        "record or a file under /.well-known/)."
    )
    if entry and entry.get("expired"):
        detail = (f"The ownership proof for {entry['domain']} has expired, so no "
                  "active tests were sent. Re-check it under Admin → Verified domains.")
    return {
        "success": True,
        "skipped": True,
        "state": "not_applicable",
        "enabled": bool(enabled),
        "ownership_verified": False,
        "detail": detail,
    }
