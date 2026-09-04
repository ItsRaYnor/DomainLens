"""What changed between two scans of the same domain.

Monitoring already detects *that* something changed: it hashes a set of
tracked sections and raises an event when the hash moves. Unless the change
happened to be one of a handful it names outright -- a blacklist listing, a
TLS grade regression -- the event reads "Observed changes for example.com",
which tells an operator to go and diff two reports by eye.

This names the change instead: SPF went from -all to ~all, DMARC from reject
to none, TLS 1.0 came back.

The work is not the comparison, it is deciding what counts as a change. A
deep diff of two scan payloads reports something every single time: TTLs
count down, certificates lose a day of validity, elapsed_ms never repeats.
Those are not changes an operator can act on, and a report full of them is
one nobody reads. So the fields are listed explicitly below, each with the
name an operator would use for it.
"""

from __future__ import annotations

# Direction of travel, where it can be judged. "better" and "worse" are only
# claimed for fields where one value is genuinely preferable; anything else
# is reported as a change without a verdict, because inventing one would be
# worse than leaving the reader to judge.
BETTER = "better"
WORSE = "worse"
NEUTRAL = "changed"


def _spf_all(record):
    """The qualifier on SPF's all mechanism: -all, ~all, ?all or +all.

    This is the field the whole feature was asked for. A move from -all to
    ~all is a real weakening that no other tracked value reflects: the record
    still exists, still parses, still "passes" a presence check.
    """
    text = (record or "").strip().lower()
    for qualifier, label in (("-all", "-all (hard fail)"),
                             ("~all", "~all (soft fail)"),
                             ("?all", "?all (neutral)"),
                             ("+all", "+all (pass — accepts any sender)")):
        if qualifier in text:
            return label
    return None


# Each entry: (section, key path within it, label, extractor, direction map).
# The extractor takes the section dict and returns a comparable value.
_FIELDS = [
    # --- Email authentication -------------------------------------------
    ("spf", "found", "SPF record present", lambda s: s.get("found"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("spf", "all", "SPF all mechanism", lambda s: _spf_all(s.get("record")), {}),
    ("spf", "strict", "SPF strict (hard fail)", lambda s: s.get("strict"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("spf", "multiple_records", "SPF has multiple records", lambda s: s.get("multiple_records"),
     {(False, True): WORSE, (True, False): BETTER}),
    ("dmarc", "found", "DMARC record present", lambda s: s.get("found"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("dmarc", "policy", "DMARC policy", lambda s: s.get("policy"), {}),
    ("dkim", "found", "DKIM selector found", lambda s: s.get("found"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("mta_sts", "found", "MTA-STS published", lambda s: s.get("found"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("tlsrpt", "found", "TLS-RPT published", lambda s: s.get("found"),
     {(True, False): WORSE, (False, True): BETTER}),

    # --- DNS -------------------------------------------------------------
    ("dnssec", "signed", "DNSSEC signed", lambda s: s.get("signed"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("ipv6", "has_ipv6", "IPv6 (AAAA) present", lambda s: s.get("has_ipv6"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("ipv6", "mail_pass", "IPv6 on mail hosts", lambda s: s.get("mail_pass"),
     {(True, False): WORSE, (False, True): BETTER}),

    # --- Certificate and TLS ---------------------------------------------
    # not_after, not days_until_expiry: the latter changes every day without
    # anything having happened, which is exactly the noise to avoid.
    ("ssl", "not_after", "Certificate expiry date", lambda s: s.get("not_after"), {}),
    ("ssl", "issuer", "Certificate issuer",
     lambda s: (s.get("issuer") or {}).get("organizationName")
     or (s.get("issuer") or {}).get("commonName"), {}),
    ("ssl", "expired", "Certificate expired", lambda s: s.get("expired"),
     {(False, True): WORSE, (True, False): BETTER}),
    ("tls_deep", "grade", "TLS grade", lambda s: s.get("grade"), {}),
    ("tls_deep", "protocols", "TLS versions accepted",
     lambda s: ", ".join(sorted(
         p.get("name") for p in (s.get("protocols") or [])
         if isinstance(p, dict) and p.get("supported") and p.get("name"))) or None, {}),

    # --- Web --------------------------------------------------------------
    ("http_headers", "score", "Security header score", lambda s: s.get("score"), {}),
    ("http_headers", "headers_missing", "Missing security headers",
     lambda s: ", ".join(sorted(s.get("headers_missing") or [])) or None, {}),
    ("http_headers", "status_code", "HTTP status", lambda s: s.get("status_code"), {}),
    ("https_redirect", "pass", "Redirects HTTP to HTTPS", lambda s: s.get("pass"),
     {(True, False): WORSE, (False, True): BETTER}),

    # --- Reputation -------------------------------------------------------
    ("blacklist", "is_listed", "Listed on a DNS blacklist", lambda s: s.get("is_listed"),
     {(False, True): WORSE, (True, False): BETTER}),
]

# TLS grades ordered worst to best, so a move between them can be judged.
_TLS_GRADES = ["T", "F", "E", "D", "C", "B", "A", "A+"]

# DMARC policies ordered by how much they actually ask receivers to do.
_DMARC_POLICIES = ["none", "quarantine", "reject"]

# SPF all qualifiers, weakest first.
_SPF_ORDER = ["+all (pass — accepts any sender)", "?all (neutral)",
              "~all (soft fail)", "-all (hard fail)"]


def _ordered_direction(order, before, after):
    """Judge a move along a known scale, or decline to."""
    if before not in order or after not in order:
        return NEUTRAL
    delta = order.index(after) - order.index(before)
    if delta > 0:
        return BETTER
    if delta < 0:
        return WORSE
    return NEUTRAL


def _direction(section, key, mapping, before, after):
    if (before, after) in mapping:
        return mapping[(before, after)]
    if section == "tls_deep" and key == "grade":
        return _ordered_direction(_TLS_GRADES, before, after)
    if section == "dmarc" and key == "policy":
        return _ordered_direction(_DMARC_POLICIES, before, after)
    if section == "spf" and key == "all":
        return _ordered_direction(_SPF_ORDER, before, after)
    if section == "http_headers" and key == "score":
        if isinstance(before, int) and isinstance(after, int):
            return BETTER if after > before else WORSE if after < before else NEUTRAL
    return NEUTRAL


def _extract(data, section, extractor):
    payload = data.get(section)
    if not isinstance(payload, dict):
        return None
    try:
        return extractor(payload)
    except Exception:
        # A field that cannot be read is not a field that changed. Letting an
        # extractor error surface as None on one side would invent a
        # difference out of a parsing problem.
        return None


def compare(before, after):
    """Return the field-level differences between two scan payloads.

    A field missing from one side entirely -- a check that was not run then,
    or not run now -- is reported as unmeasured rather than as a change from
    or to nothing. "The check did not run" and "the value went away" look
    identical in the data and mean opposite things to whoever reads it.
    """
    before = before or {}
    after = after or {}
    changes = []
    unmeasured = []

    for section, key, label, extractor, mapping in _FIELDS:
        had_before = isinstance(before.get(section), dict)
        had_after = isinstance(after.get(section), dict)
        if not had_before or not had_after:
            if had_before != had_after:
                unmeasured.append({
                    "section": section, "key": key, "label": label,
                    "reason": ("not measured in the earlier scan" if not had_before
                               else "not measured in the later scan"),
                })
            continue

        old = _extract(before, section, extractor)
        new = _extract(after, section, extractor)
        if old == new:
            continue
        changes.append({
            "section": section,
            "key": key,
            "label": label,
            "before": old,
            "after": new,
            "direction": _direction(section, key, mapping, old, new),
        })

    return {
        "changes": changes,
        "unmeasured": unmeasured,
        "changed": bool(changes),
        "summary": summarise(changes),
    }


def summarise(changes):
    counts = {BETTER: 0, WORSE: 0, NEUTRAL: 0}
    for change in changes:
        counts[change.get("direction", NEUTRAL)] = counts.get(
            change.get("direction", NEUTRAL), 0) + 1
    return {
        "total": len(changes),
        "better": counts[BETTER],
        "worse": counts[WORSE],
        "neutral": counts[NEUTRAL],
    }


def field_catalogue():
    """The fields this comparison covers, for the UI's filter list."""
    seen = []
    for section, key, label, _extractor, _mapping in _FIELDS:
        seen.append({"section": section, "key": key, "label": label,
                     "id": f"{section}.{key}"})
    return seen
