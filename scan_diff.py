"""Structured comparison of two saved scans.

Change detection tells you *that* something moved (the monitor fingerprint
flipped); this tells you *what* and *which way*. It compares a handful of
high-signal dimensions between an older and a newer scan and, for each, says
whether it got worse, better, or merely changed, alongside the stored measured
values so the reader can drill straight to the numbers behind "TLS A -> F".

Two rules carried from the repo's reporting conventions:

- A dimension is only judged when both scans measured it. If a check ran in one
  scan and not the other, the dimension is reported as `unmeasured`, never as a
  regression — an absent answer is not a defect.
- Direction (worse/better) is only claimed where the dimension has a real
  ordering (a TLS grade, a header score, a blacklist listing). Where values
  simply differ with no better/worse (a CNAME target, an IP), the status is
  `changed`.
"""

from __future__ import annotations

# Higher rank is a better grade; used to decide whether a grade move is a
# regression. T (trust/name problems) sits below F.
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
    # Accept either a list of open ports or a dict keyed by port.
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


# The email-auth mechanisms, each a check that reports a boolean `pass`.
_EMAIL_KEYS = ("spf", "dmarc", "dkim", "mta_sts", "tlsrpt")


def _email_auth_passing(results):
    """Number of email-auth mechanisms that pass, among those measured.

    A mechanism counts as measured when its check ran (the key holds a dict);
    an absent record is a measured failure, not an unmeasured one. Returns None
    only when no email check ran at all, so the dimension is omitted rather
    than reported as a regression to zero.
    """
    measured = [k for k in _EMAIL_KEYS if isinstance(results.get(k), dict)]
    if not measured:
        return None
    return sum(1 for k in measured if (results.get(k) or {}).get("pass"))


def _threat_feed_hits(results):
    osint = results.get("osint") or {}
    if not osint.get("success"):
        return None
    return int((osint.get("summary") or {}).get("threat_hits") or 0)


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
    """A set where a newly present member is worse (a header that went missing,
    a port that opened). Growth is worse, shrinkage is better."""
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
        return None  # unknown grade string: cannot order it
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
    # A newly open port is an increase in exposure; closing one reduces it. If
    # both happened, call it worse only when something opened.
    if opened:
        return STATUS_WORSE
    if closed:
        return STATUS_BETTER
    return STATUS_CHANGED


# Each dimension: a stable key, a label, an extractor returning the measured
# value or None when unmeasured, and a comparator returning a status.
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
    {"key": "secrets", "label": "Leaked secrets", "extract": _leaked_secrets,
     "compare": _number_worse_when_higher, "unit": "secrets"},
    {"key": "vulnerable_js", "label": "Vulnerable JS libraries", "extract": _vulnerable_js,
     "compare": _number_worse_when_higher, "unit": "libraries"},
]


def _severity_counts_worse(old, new):
    # Compare weighted severity: a new critical outranks several lows. Only the
    # blocking severities move the needle.
    weights = {"critical": 1000, "high": 100, "medium": 10, "low": 1}
    ow = sum(weights.get(k, 0) * v for k, v in (old or {}).items())
    nw = sum(weights.get(k, 0) * v for k, v in (new or {}).items())
    if ow == nw:
        return STATUS_UNCHANGED
    return STATUS_WORSE if nw > ow else STATUS_BETTER


def compare(old_results, new_results, old_severity=None, new_severity=None):
    """Compare two scan result dicts.

    Returns {"dimensions": [...], "summary": {worse, better, changed}}.
    Optionally include recommendation severity counts (from
    recommendations.summarize_counts) as an extra ordered dimension; passing
    them keeps this module free of a recommendations import.
    """
    old_results = old_results or {}
    new_results = new_results or {}
    rows = []

    for dim in _DIMENSIONS:
        old_val = dim["extract"](old_results)
        new_val = dim["extract"](new_results)
        rows.append(_row(dim["key"], dim["label"], dim["unit"],
                         old_val, new_val, dim["compare"]))

    if old_severity is not None or new_severity is not None:
        rows.append(_row("recommendations", "Recommendation severity", "counts",
                         old_severity, new_severity, _severity_counts_worse))

    summary = {STATUS_WORSE: 0, STATUS_BETTER: 0, STATUS_CHANGED: 0}
    for row in rows:
        if row["status"] in summary:
            summary[row["status"]] += 1
    return {"dimensions": rows, "summary": summary}


def _row(key, label, unit, old_val, new_val, comparator):
    if old_val is None or new_val is None:
        # One side never measured this: report the state, claim no direction.
        return {"key": key, "label": label, "unit": unit,
                "old": old_val, "new": new_val, "status": STATUS_UNMEASURED}
    status = comparator(old_val, new_val)
    if status is None:
        status = STATUS_CHANGED if old_val != new_val else STATUS_UNCHANGED
    return {"key": key, "label": label, "unit": unit,
            "old": old_val, "new": new_val, "status": status}
