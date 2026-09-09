"""Certificates issued for a domain, from the public CT logs.

CAA says which authorities *may* issue. It does not say which ones *did*, and
it is only consulted at issuance: a CA that ignores it, a record added after
the fact, or a certificate obtained through a compromised DNS account all
leave CAA looking correct while a certificate exists that nobody asked for.

The CT logs are the other half of that question, and DomainLens already
fetches them for subdomain enumeration. This reads the same data for a
different purpose: which authorities have issued recently, and whether any of
them is one the domain's own CAA record does not permit.

Three states, kept apart, because they are three different situations:

  measured        the logs answered and the issuers could be matched
  unrecognised    an issuer string we cannot map to a CAA identifier
  unmeasured      crt.sh did not answer

The middle one matters most. Reporting an unmapped issuer as a CAA violation
would raise an alarm about a certificate that is very likely legitimate, and
the second false alarm is the one that gets the check ignored.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

# crt.sh reports the issuer as an X.509 name string. Mapping it to the
# identifier a CAA record uses is a lookup table, not a rule: the two are
# unrelated namespaces, and only the CA knows which identifier it honours.
#
# Each entry maps a substring of the issuer name to the CAA domain(s) that
# authority publishes. Anything not listed is reported as unrecognised
# rather than guessed at.
_ISSUER_TO_CAA = {
    "let's encrypt": {"letsencrypt.org"},
    "google trust services": {"pki.goog"},
    "digicert": {"digicert.com"},
    "sectigo": {"sectigo.com"},
    "comodo": {"sectigo.com", "comodoca.com"},
    "globalsign": {"globalsign.com"},
    "godaddy": {"godaddy.com"},
    "starfield": {"starfieldtech.com"},
    "amazon": {"amazon.com", "amazontrust.com", "awstrust.com"},
    "buypass": {"buypass.com"},
    "zerossl": {"sectigo.com", "zerossl.com"},
    "entrust": {"entrust.net"},
    "actalis": {"actalis.it"},
    "certum": {"certum.pl"},
    "quovadis": {"quovadisglobal.com"},
    "microsoft": {"microsoft.com"},
    "apple public ev": {"apple.com"},
    "cloudflare": {"pki.goog", "digicert.com", "letsencrypt.org"},
}

_CAA_ISSUE_RE = re.compile(r'^\s*\d+\s+issue(?:wild)?\s+"([^"]*)"', re.I)


def caa_allowed_issuers(caa_records):
    """The CA identifiers a CAA record set permits.

    Returns None when the domain publishes no issue property at all, which
    means "any CA may issue" -- a different thing from an empty set, which
    means "no CA may issue" and is how a domain says it wants no
    certificates.
    """
    if not caa_records:
        return None
    allowed = set()
    found_issue = False
    for record in caa_records:
        match = _CAA_ISSUE_RE.match(str(record).strip())
        if not match:
            continue
        found_issue = True
        value = match.group(1).strip()
        # `issue ";"` is the explicit "no CA may issue" form.
        if value and value != ";":
            allowed.add(value.split(";")[0].strip().lower())
    return allowed if found_issue else None


def _issuer_caa_domains(issuer_name):
    lowered = (issuer_name or "").lower()
    for needle, domains in _ISSUER_TO_CAA.items():
        if needle in lowered:
            return domains
    return None


def _parse_ts(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(
            tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def analyse(rows, caa_records, days=30, now=None, source_error=None):
    """Summarise recent issuance and flag issuers CAA does not permit."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max(1, int(days)))
    result = {
        "state": "unmeasured",
        "days": days,
        "recent": [],
        "issuers": [],
        "unexpected": [],
        "unrecognised_issuers": [],
        "caa_allowed": None,
        "reason": None,
    }
    if source_error:
        result["reason"] = source_error
        return result
    if rows is None:
        result["reason"] = "Certificate Transparency logs could not be read"
        return result

    allowed = caa_allowed_issuers(caa_records)
    result["caa_allowed"] = sorted(allowed) if allowed is not None else None
    result["state"] = "measured"

    seen_serial = set()
    by_issuer = {}
    for row in rows:
        issued = _parse_ts(row.get("not_before"))
        if not issued or issued < cutoff:
            continue
        serial = row.get("serial_number") or row.get("id")
        if serial in seen_serial:
            continue
        seen_serial.add(serial)
        issuer = (row.get("issuer_name") or "").strip()
        entry = {
            "issuer": issuer,
            "common_name": row.get("common_name"),
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
            "serial": row.get("serial_number"),
        }
        result["recent"].append(entry)
        by_issuer.setdefault(issuer, 0)
        by_issuer[issuer] += 1

    result["issuers"] = [{"issuer": k, "certificates": v}
                         for k, v in sorted(by_issuer.items(), key=lambda kv: -kv[1])]

    # No issue property means any CA may issue, so nothing here can be
    # unexpected. Saying otherwise would flag a domain that has made no
    # restriction for failing to keep one.
    if allowed is None:
        result["reason"] = ("No CAA issue property, so any authority may issue and "
                            "no certificate here is unexpected")
        return result

    for issuer in by_issuer:
        domains = _issuer_caa_domains(issuer)
        if domains is None:
            result["unrecognised_issuers"].append(issuer)
            continue
        if not (domains & allowed):
            result["unexpected"].append({
                "issuer": issuer,
                "certificates": by_issuer[issuer],
                "caa_identifier": sorted(domains)[0],
            })
    return result


def findings(analysis, _finding):
    """Turn the analysis into findings, claiming only what was established."""
    out = []
    if not analysis or analysis.get("state") != "measured":
        return out

    for item in analysis.get("unexpected", []):
        out.append(_finding(
            "medium", "Certificates",
            "Certificate issued by an authority CAA does not permit",
            f"{item['certificates']} certificate(s) issued in the last "
            f"{analysis['days']} days by {item['issuer']}, whose CAA identifier "
            f"({item['caa_identifier']}) is not in this domain's CAA record. "
            "Either the record was added after the certificate was issued, or "
            "a certificate exists that the record was meant to prevent.",
            evidence=f"CAA allows: {', '.join(analysis.get('caa_allowed') or [])}",
            fix="Check who requested it. If it is legitimate, add that authority "
                "to the CAA record; if not, have the certificate revoked and "
                "review who can change this domain's DNS.",
        ))

    # Unrecognised issuers remain in the analysis as a coverage limitation.
    # They are not a defect of the scanned domain and therefore not a finding.
    return out
