"""What changed between two scans of the same domain.

Two complementary views share this module:

- ``compare`` / ``field_catalogue`` -- field-level diffs for the reporting UI
  (SPF -all to ~all, DMARC policy, cert expiry, ...).
- ``compare_dimensions`` -- posture dimensions for /api/compare (TLS grade,
  open ports, VirusTotal, JS secrets, recommendation severity, ...).

Monitoring already detects *that* something changed. These name *what*
moved, and only where both scans measured the field -- an absent check is
unmeasured, never a invented regression.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Field-level comparison (reporting UI)
# ---------------------------------------------------------------------------

BETTER = "better"
WORSE = "worse"
NEUTRAL = "changed"


def _spf_all(record):
    """The qualifier on SPF's all mechanism: -all, ~all, ?all or +all."""
    text = (record or "").strip().lower()
    for qualifier, label in (("-all", "-all (hard fail)"),
                             ("~all", "~all (soft fail)"),
                             ("?all", "?all (neutral)"),
                             ("+all", "+all (pass — accepts any sender)")):
        if qualifier in text:
            return label
    return None


_FIELDS = [
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
    ("dnssec", "signed", "DNSSEC signed", lambda s: s.get("signed"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("ipv6", "has_ipv6", "IPv6 (AAAA) present", lambda s: s.get("has_ipv6"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("ipv6", "mail_pass", "IPv6 on mail hosts", lambda s: s.get("mail_pass"),
     {(True, False): WORSE, (False, True): BETTER}),
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
    ("http_headers", "score", "Security header score", lambda s: s.get("score"), {}),
    ("http_headers", "headers_missing", "Missing security headers",
     lambda s: ", ".join(sorted(s.get("headers_missing") or [])) or None, {}),
    ("http_headers", "status_code", "HTTP status", lambda s: s.get("status_code"), {}),
    ("https_redirect", "pass", "Redirects HTTP to HTTPS", lambda s: s.get("pass"),
     {(True, False): WORSE, (False, True): BETTER}),
    ("blacklist", "is_listed", "Listed on a DNS blacklist", lambda s: s.get("is_listed"),
     {(False, True): WORSE, (True, False): BETTER}),
]

_TLS_GRADES = ["T", "F", "E", "D", "C", "B", "A", "A+"]
_DMARC_POLICIES = ["none", "quarantine", "reject"]
_SPF_ORDER = ["+all (pass — accepts any sender)", "?all (neutral)",
              "~all (soft fail)", "-all (hard fail)"]


def _ordered_direction(order, before, after):
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
        return None


def compare(before, after):
    """Field-level differences between two scan payloads (reporting UI)."""
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


# ---------------------------------------------------------------------------
# Dimension-level comparison (/api/compare, monitor "what changed")
# ---------------------------------------------------------------------------

_GRADE_RANK = {"A+": 7, "A": 6, "B": 5, "C": 4, "D": 3, "E": 2, "F": 1, "T": 0}

STATUS_WORSE = "worse"
STATUS_BETTER = "better"
STATUS_CHANGED = "changed"
STATUS_UNCHANGED = "unchanged"
STATUS_UNMEASURED = "unmeasured"


def _tls_grade(results):
    tls = results.get("tls_deep") or {}
    if not tls.get("success"):
        return None
    return tls.get("grade")


def _header_score(results):
    headers = results.get("http_headers") or {}
    if not headers.get("success"):
        return None
    return headers.get("score")


def _blacklist_count(results):
    bl = results.get("blacklist") or {}
    if not bl:
        return None
    return len(bl.get("listed") or []) if bl.get("is_listed") else 0


def _open_ports(results):
    ports = results.get("ports") or {}
    if not ports:
        return None
    open_ports = ports.get("open")
    if open_ports is None:
        return None
    return sorted(str(p) for p in open_ports)


def _dnssec_signed(results):
    dnssec = results.get("dnssec") or {}
    if not dnssec:
        return None
    return bool(dnssec.get("signed"))


def _https_redirect_ok(results):
    block = results.get("https_redirect") or {}
    if not block:
        return None
    passed = block.get("pass")
    return bool(passed) if passed is not None else None


def _security_findings(results):
    sec = results.get("security") or {}
    if not sec.get("success"):
        return None
    return len(sec.get("findings") or [])


def _missing_headers(results):
    headers = results.get("http_headers") or {}
    if not headers.get("success"):
        return None
    return sorted(headers.get("headers_missing") or [])


_EMAIL_KEYS = ("spf", "dmarc", "dkim", "mta_sts", "tlsrpt")


def _email_auth_passing(results):
    measured = [k for k in _EMAIL_KEYS if isinstance(results.get(k), dict)]
    if not measured:
        return None
    return sum(1 for k in measured if (results.get(k) or {}).get("pass"))


def _threat_feed_hits(results):
    osint = results.get("osint") or {}
    if not osint.get("success"):
        return None
    return int((osint.get("summary") or {}).get("threat_hits") or 0)


def _virustotal_detections(results):
    osint = results.get("osint") or {}
    if not osint.get("success"):
        return None
    summary = osint.get("summary") or {}
    if not summary.get("virustotal_measured"):
        return None
    return int(summary.get("virustotal_malicious") or 0) + int(
        summary.get("virustotal_suspicious") or 0)


def _leaked_secrets(results):
    js = results.get("js_scan") or {}
    if not js.get("success"):
        return None
    return len(js.get("secrets_found") or [])


def _vulnerable_js(results):
    js = results.get("js_scan") or {}
    if not js.get("success"):
        return None
    return len(js.get("vulnerable_libraries") or [])


def _set_growth_worse(old, new):
    if old == new:
        return STATUS_UNCHANGED
    added = set(new) - set(old)
    removed = set(old) - set(new)
    if added:
        return STATUS_WORSE
    if removed:
        return STATUS_BETTER
    return STATUS_CHANGED


def _grade_worse(old, new):
    o, n = _GRADE_RANK.get(old), _GRADE_RANK.get(new)
    if o is None or n is None:
        return None
    if n < o:
        return STATUS_WORSE
    if n > o:
        return STATUS_BETTER
    return STATUS_UNCHANGED


def _number_worse_when_higher(old, new):
    if old == new:
        return STATUS_UNCHANGED
    return STATUS_WORSE if new > old else STATUS_BETTER


def _number_worse_when_lower(old, new):
    if old == new:
        return STATUS_UNCHANGED
    return STATUS_WORSE if new < old else STATUS_BETTER


def _bool_worse_when_false(old, new):
    if old == new:
        return STATUS_UNCHANGED
    return STATUS_WORSE if (old and not new) else STATUS_BETTER


def _ports_status(old, new):
    if old == new:
        return STATUS_UNCHANGED
    opened = set(new) - set(old)
    closed = set(old) - set(new)
    if opened:
        return STATUS_WORSE
    if closed:
        return STATUS_BETTER
    return STATUS_CHANGED


_DIMENSIONS = [
    {"key": "tls_grade", "label": "TLS grade", "extract": _tls_grade,
     "compare": _grade_worse, "unit": "grade"},
    {"key": "header_score", "label": "Security-header score", "extract": _header_score,
     "compare": _number_worse_when_lower, "unit": "score"},
    {"key": "blacklist", "label": "Blacklist listings", "extract": _blacklist_count,
     "compare": _number_worse_when_higher, "unit": "listings"},
    {"key": "open_ports", "label": "Open ports", "extract": _open_ports,
     "compare": _ports_status, "unit": "ports"},
    {"key": "dnssec", "label": "DNSSEC signed", "extract": _dnssec_signed,
     "compare": _bool_worse_when_false, "unit": "bool"},
    {"key": "https_redirect", "label": "HTTP→HTTPS redirect", "extract": _https_redirect_ok,
     "compare": _bool_worse_when_false, "unit": "bool"},
    {"key": "security_findings", "label": "Security-audit findings", "extract": _security_findings,
     "compare": _number_worse_when_higher, "unit": "findings"},
    {"key": "missing_headers", "label": "Missing security headers", "extract": _missing_headers,
     "compare": _set_growth_worse, "unit": "headers"},
    {"key": "email_auth", "label": "Email auth passing", "extract": _email_auth_passing,
     "compare": _number_worse_when_lower, "unit": "mechanisms"},
    {"key": "reputation", "label": "Threat-feed hits", "extract": _threat_feed_hits,
     "compare": _number_worse_when_higher, "unit": "hits"},
    {"key": "virustotal", "label": "VirusTotal detections", "extract": _virustotal_detections,
     "compare": _number_worse_when_higher, "unit": "engines"},
    {"key": "secrets", "label": "Leaked secrets", "extract": _leaked_secrets,
     "compare": _number_worse_when_higher, "unit": "secrets"},
    {"key": "vulnerable_js", "label": "Vulnerable JS libraries", "extract": _vulnerable_js,
     "compare": _number_worse_when_higher, "unit": "libraries"},
]


def _severity_counts_worse(old, new):
    weights = {"critical": 1000, "high": 100, "medium": 10, "low": 1}
    ow = sum(weights.get(k, 0) * v for k, v in (old or {}).items())
    nw = sum(weights.get(k, 0) * v for k, v in (new or {}).items())
    if ow == nw:
        return STATUS_UNCHANGED
    return STATUS_WORSE if nw > ow else STATUS_BETTER


def compare_dimensions(old_results, new_results, old_severity=None, new_severity=None):
    """Posture dimensions for /api/compare (worse/better/changed/unmeasured)."""
    old_results = old_results or {}
    new_results = new_results or {}
    rows = []

    for dim in _DIMENSIONS:
        old_val = dim["extract"](old_results)
        new_val = dim["extract"](new_results)
        rows.append(_dimension_row(dim["key"], dim["label"], dim["unit"],
                                   old_val, new_val, dim["compare"]))

    if old_severity is not None or new_severity is not None:
        rows.append(_dimension_row(
            "recommendations", "Recommendation severity", "counts",
            old_severity, new_severity, _severity_counts_worse))

    summary = {STATUS_WORSE: 0, STATUS_BETTER: 0, STATUS_CHANGED: 0}
    for row in rows:
        if row["status"] in summary:
            summary[row["status"]] += 1
    return {"dimensions": rows, "summary": summary}


def _dimension_row(key, label, unit, old_val, new_val, comparator):
    if old_val is None or new_val is None:
        return {"key": key, "label": label, "unit": unit,
                "old": old_val, "new": new_val, "status": STATUS_UNMEASURED}
    status = comparator(old_val, new_val)
    if status is None:
        status = STATUS_CHANGED if old_val != new_val else STATUS_UNCHANGED
    return {"key": key, "label": label, "unit": unit,
            "old": old_val, "new": new_val, "status": status}
