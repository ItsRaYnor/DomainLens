"""Web vulnerability helpers: CSP analysis, cookies, CORS, framing, disclosure."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


# ---------------------------------------------------------------------------
# CSP
# ---------------------------------------------------------------------------

_CSP_UNSAFE = ("'unsafe-inline'", "'unsafe-eval'", "data:", "blob:")
_CSP_WILDCARD_HOST = re.compile(r"(^|[;\s])https?:\/\/\*([;\s]|$)|(^|[;\s])\*(?=[;\s]|$)")


def parse_csp(policy: str | None) -> dict[str, list[str]]:
    """Parse a CSP header into directive → source-list."""
    out: dict[str, list[str]] = {}
    if not policy or not str(policy).strip():
        return out
    for part in str(policy).split(";"):
        part = part.strip()
        if not part:
            continue
        bits = part.split()
        directive = bits[0].lower()
        sources = bits[1:] if len(bits) > 1 else []
        out[directive] = sources
    return out


def analyze_csp(policy: str | None) -> dict[str, Any]:
    """
    Analyze Content-Security-Policy quality.

    Returns structured findings for scoring and Advies (how to build a safer CSP).
    """
    result: dict[str, Any] = {
        "present": bool(policy and str(policy).strip()),
        "raw": (policy or "").strip() or None,
        "directives": {},
        "issues": [],
        "grade": "missing",
        "suggestions": [],
    }
    if not result["present"]:
        result["issues"].append({
            "id": "csp_missing",
            "severity": "medium",
            "title": "Content-Security-Policy missing",
        })
        result["suggestions"] = _csp_build_steps(baseline=True)
        return result

    directives = parse_csp(policy)
    result["directives"] = {k: list(v) for k, v in directives.items()}
    issues = []

    if "default-src" not in directives and "script-src" not in directives:
        issues.append({
            "id": "csp_no_default_or_script",
            "severity": "high",
            "title": "CSP has neither default-src nor script-src",
            "detail": "Without a baseline, browsers fall back to allowing almost anything.",
        })

    for directive in ("default-src", "script-src", "style-src", "img-src", "connect-src", "font-src"):
        sources = directives.get(directive) or []
        joined = " ".join(sources).lower()
        if "'unsafe-inline'" in joined and directive in {"default-src", "script-src", "style-src"}:
            sev = "high" if directive in {"default-src", "script-src"} else "medium"
            issues.append({
                "id": f"csp_unsafe_inline_{directive.replace('-', '_')}",
                "severity": sev,
                "title": f"CSP {directive} allows 'unsafe-inline'",
                "detail": "Inline scripts/styles defeat XSS protections. Prefer nonces or hashes.",
            })
        if "'unsafe-eval'" in joined and directive in {"default-src", "script-src"}:
            issues.append({
                "id": f"csp_unsafe_eval_{directive.replace('-', '_')}",
                "severity": "high",
                "title": f"CSP {directive} allows 'unsafe-eval'",
                "detail": "eval() and similar APIs expand the XSS attack surface.",
            })
        if "*" in sources or any(s == "https:" for s in sources):
            issues.append({
                "id": f"csp_wildcard_{directive.replace('-', '_')}",
                "severity": "medium",
                "title": f"CSP {directive} is overly broad (* or https:)",
                "detail": "Restrict to concrete hostnames your app actually needs.",
            })

    if "object-src" not in directives and "default-src" not in directives:
        issues.append({
            "id": "csp_object_src",
            "severity": "low",
            "title": "CSP does not restrict object-src",
            "detail": "Set `object-src 'none'` to block Flash/plugins.",
        })
    elif directives.get("object-src") and "'none'" not in [s.lower() for s in directives["object-src"]]:
        if directives["object-src"] != ["'none'"]:
            issues.append({
                "id": "csp_object_src_not_none",
                "severity": "low",
                "title": "CSP object-src is not 'none'",
            })

    fa = directives.get("frame-ancestors")
    if fa is None:
        issues.append({
            "id": "csp_no_frame_ancestors",
            "severity": "medium",
            "title": "CSP missing frame-ancestors",
            "detail": "Add `frame-ancestors 'none'` (or 'self') to prevent clickjacking. Prefer CSP over X-Frame-Options.",
        })
    elif "*" in fa:
        issues.append({
            "id": "csp_frame_ancestors_star",
            "severity": "high",
            "title": "CSP frame-ancestors allows any site (*)",
            "detail": "Any origin may iframe this page (clickjacking risk).",
        })

    if "base-uri" not in directives:
        issues.append({
            "id": "csp_no_base_uri",
            "severity": "low",
            "title": "CSP missing base-uri",
            "detail": "Set `base-uri 'self'` to mitigate base-tag injection.",
        })

    if "form-action" not in directives:
        issues.append({
            "id": "csp_no_form_action",
            "severity": "low",
            "title": "CSP missing form-action",
            "detail": "Set `form-action 'self'` so forms cannot post to attacker sites.",
        })

    report = directives.get("report-uri") or directives.get("report-to")
    if not report:
        issues.append({
            "id": "csp_no_reporting",
            "severity": "info",
            "title": "CSP has no violation reporting",
            "detail": "Add Report-To / report-uri while tightening policy so breakages are visible.",
        })

    result["issues"] = issues
    high = sum(1 for i in issues if i["severity"] == "high")
    medium = sum(1 for i in issues if i["severity"] == "medium")
    if high:
        result["grade"] = "weak"
    elif medium:
        result["grade"] = "fair"
    elif issues:
        result["grade"] = "good"
    else:
        result["grade"] = "strong"

    result["suggestions"] = _csp_build_steps(
        baseline=False,
        has_unsafe_inline=any("unsafe_inline" in i["id"] for i in issues),
        has_unsafe_eval=any("unsafe_eval" in i["id"] for i in issues),
        has_wildcard=any("wildcard" in i["id"] for i in issues),
    )
    return result


def _csp_build_steps(
    *,
    baseline: bool = False,
    has_unsafe_inline: bool = False,
    has_unsafe_eval: bool = False,
    has_wildcard: bool = False,
) -> list[str]:
    steps = [
        "1. Start in report-only: `Content-Security-Policy-Report-Only` with a tight policy and a reporting endpoint.",
        "2. Baseline policy: `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`.",
        "3. Add only the hosts you need: `script-src 'self' https://cdn.example.com`, `style-src 'self'`, `img-src 'self' data:`, `connect-src 'self'`, `font-src 'self'`.",
        "4. Prefer nonces/hashes for any remaining inline scripts: `script-src 'self' 'nonce-{random}'` (rotate per response). Avoid `'unsafe-inline'`.",
        "5. Remove `'unsafe-eval'` — refactor code that needs `eval` / `new Function`.",
        "6. Lock framing with `frame-ancestors 'none'` (or `'self'` if you must embed yourself). You can drop legacy `X-Frame-Options` once CSP is enforced.",
        "7. When reports are clean, switch Report-Only → enforcing `Content-Security-Policy` and keep reporting via `report-to`.",
        "Example starter: "
        "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    ]
    if baseline:
        return steps
    notes = []
    if has_unsafe_inline:
        notes.append("Priority: replace `'unsafe-inline'` with nonces/hashes before enforcing.")
    if has_unsafe_eval:
        notes.append("Priority: eliminate `'unsafe-eval'` from script-src/default-src.")
    if has_wildcard:
        notes.append("Priority: replace `*` / `https:` with explicit host allow-lists.")
    return notes + steps


CSP_BUILD_ADVICE = " ".join(_csp_build_steps(baseline=True)[:4]) + " See full step list in Advies."


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------

_SESSIONISH = re.compile(
    r"(session|sess|sid|auth|token|jwt|remember|csrf|xsrf|login)",
    re.IGNORECASE,
)


# Attribute names defined by RFC 6265 (and later additions). A fragment
# starting with one of these is a continuation of the preceding cookie, never
# a new cookie.
_COOKIE_ATTRS = {
    "expires", "max-age", "domain", "path", "secure", "httponly",
    "samesite", "priority", "partitioned", "version", "comment",
}


def _split_joined_cookies(header: str) -> list[str]:
    """Split a comma-joined Set-Cookie header into individual cookies.

    requests folds multiple Set-Cookie headers into one comma-separated
    string, so they have to be split apart again — but an Expires attribute
    always contains a comma of its own ("Expires=Mon, 12 Aug 2026 ..."),
    which a naive split mistakes for a cookie boundary. That produced
    phantom cookies named after whatever attribute followed the date
    (a reported "cookie max-age missing Secure"), and worse, moved the real
    cookie's Secure/HttpOnly flags onto the phantom — so a properly secured
    cookie was reported as insecure.
    """
    if "," not in header:
        return [header]
    # A cookie name cannot contain whitespace, commas, semicolons or "=".
    fragments = re.split(r",\s*(?=[^\s;=,]+=)", header)
    cookies: list[str] = []
    for fragment in fragments:
        fragment = fragment.strip()
        if not fragment:
            continue
        name = fragment.split("=", 1)[0].strip().lower()
        is_continuation = "=" not in fragment or name in _COOKIE_ATTRS
        if cookies and is_continuation:
            # Re-attach to the cookie it belongs to, keeping its attributes.
            cookies[-1] = f"{cookies[-1]}, {fragment}"
        else:
            cookies.append(fragment)
    return cookies


def parse_set_cookie_headers(raw_headers) -> list[dict]:
    """
    Parse Set-Cookie from a requests-like headers object or a raw string/list.
    """
    cookies = []
    values: list[str] = []
    if raw_headers is None:
        return cookies
    if hasattr(raw_headers, "getlist"):
        values = list(raw_headers.getlist("Set-Cookie") or [])
    elif hasattr(raw_headers, "get_all"):
        values = list(raw_headers.get_all("Set-Cookie") or [])
    elif isinstance(raw_headers, Mapping):
        # requests hands back a CaseInsensitiveDict, which is a Mapping but
        # NOT a dict subclass. An isinstance(..., dict) test therefore missed
        # it and fell through to str(raw_headers) below, turning the entire
        # header dictionary into a "cookie" — and because Cache-Control
        # commonly reads "public, max-age=31536000", the comma and "=" made it
        # parse as a cookie named max-age on sites that set no cookies at all.
        val = raw_headers.get("Set-Cookie") or raw_headers.get("set-cookie")
        if val:
            values = [val]
    elif isinstance(raw_headers, (list, tuple)):
        values = [str(v) for v in raw_headers]
    elif isinstance(raw_headers, str):
        values = [raw_headers]
    else:
        # Anything else is not a Set-Cookie value; inventing a cookie from its
        # repr() is worse than reporting none.
        values = []

    for header in values:
        for part in _split_joined_cookies(header):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name = part.split("=", 1)[0].strip()
            attrs = part.lower()
            cookies.append({
                "name": name,
                "raw": part[:300],
                "secure": "secure" in attrs.split(";"),
                "httponly": "httponly" in attrs.split(";"),
                "samesite": (
                    "strict" if "samesite=strict" in attrs
                    else "lax" if "samesite=lax" in attrs
                    else "none" if "samesite=none" in attrs
                    else None
                ),
                "sessionish": bool(_SESSIONISH.search(name)),
            })
    # Fix secure/httponly detection — attribute tokens after splitting by ;
    fixed = []
    for c in cookies:
        tokens = [t.strip().lower() for t in c["raw"].split(";")]
        c["secure"] = any(t == "secure" for t in tokens)
        c["httponly"] = any(t == "httponly" for t in tokens)
        fixed.append(c)
    return fixed


def analyze_cookies(raw_headers) -> dict[str, Any]:
    cookies = parse_set_cookie_headers(raw_headers)
    issues = []
    for c in cookies:
        if not c["secure"]:
            issues.append({
                "id": "cookie_no_secure",
                "severity": "high" if c["sessionish"] else "medium",
                "title": f"Cookie `{c['name']}` missing Secure",
                "cookie": c["name"],
            })
        if c["sessionish"] and not c["httponly"]:
            issues.append({
                "id": "cookie_no_httponly",
                "severity": "high",
                "title": f"Session cookie `{c['name']}` missing HttpOnly",
                "cookie": c["name"],
            })
        if c["sessionish"] and not c["samesite"]:
            issues.append({
                "id": "cookie_no_samesite",
                "severity": "medium",
                "title": f"Session cookie `{c['name']}` missing SameSite",
                "cookie": c["name"],
            })
        if c.get("samesite") == "none" and not c["secure"]:
            issues.append({
                "id": "cookie_samesite_none_insecure",
                "severity": "high",
                "title": f"Cookie `{c['name']}` has SameSite=None without Secure",
                "cookie": c["name"],
            })
    return {
        "cookies": cookies,
        "issues": issues,
        "count": len(cookies),
    }


# ---------------------------------------------------------------------------
# CORS / framing / disclosure
# ---------------------------------------------------------------------------

def analyze_cors(headers_lc: dict) -> dict[str, Any]:
    acao = (headers_lc.get("access-control-allow-origin") or "").strip()
    acac = (headers_lc.get("access-control-allow-credentials") or "").strip().lower()
    issues = []
    if acao == "*" and acac in {"true", "1"}:
        issues.append({
            "id": "cors_star_with_credentials",
            "severity": "info",
            "title": "CORS * combined with credentials",
            "detail": "Standards-compliant browsers reject this header combination, so "
                      "credentialed cross-origin access was not established.",
        })
    if acao and acao != "*" and acac in {"true", "1"}:
        # Reflecting arbitrary Origin with credentials is dangerous — we only see the response value
        if acao.lower() in {"null"}:
            issues.append({
                "id": "cors_null_origin",
                "severity": "medium",
                "title": "CORS allows null origin",
            })
    return {
        "allow_origin": acao or None,
        "allow_credentials": acac in {"true", "1"},
        "issues": issues,
    }


def analyze_framing(headers_lc: dict, csp_analysis: dict | None = None) -> dict[str, Any]:
    xfo = (headers_lc.get("x-frame-options") or "").strip()
    xfo_l = xfo.lower()
    issues = []
    csp_issues = {i["id"] for i in (csp_analysis or {}).get("issues") or []}
    has_fa = "csp_no_frame_ancestors" not in csp_issues and (csp_analysis or {}).get("present")
    fa_star = "csp_frame_ancestors_star" in csp_issues

    if fa_star:
        issues.append({
            "id": "framing_csp_star",
            "severity": "high",
            "title": "Page can be framed by any origin (CSP)",
        })
    elif not has_fa:
        if not xfo:
            issues.append({
                "id": "framing_unprotected",
                "severity": "medium",
                "title": "No clickjacking protection (no CSP frame-ancestors, no X-Frame-Options)",
            })
        elif xfo_l.startswith("allow-from"):
            issues.append({
                "id": "framing_allow_from",
                "severity": "medium",
                "title": "X-Frame-Options uses deprecated ALLOW-FROM",
                "detail": "Modern browsers ignore ALLOW-FROM. Use CSP frame-ancestors instead.",
            })
    return {
        "x_frame_options": xfo or None,
        "issues": issues,
    }


def analyze_info_disclosure(headers_lc: dict) -> dict[str, Any]:
    issues = []
    powered = headers_lc.get("x-powered-by")
    if powered:
        issues.append({
            "id": "disclosure_x_powered_by",
            "severity": "low",
            "title": "X-Powered-By header discloses technology",
            "detail": f"Value: {powered[:120]}",
        })
    server = headers_lc.get("server") or ""
    # Version-like patterns: Apache/2.4.49, nginx/1.18.0
    if re.search(r"/\d", server):
        issues.append({
            "id": "disclosure_server_version",
            "severity": "low",
            "title": "Server header discloses software version",
            "detail": f"Value: {server[:120]}",
        })
    asp = headers_lc.get("x-aspnet-version") or headers_lc.get("x-aspnetmvc-version")
    if asp:
        issues.append({
            "id": "disclosure_aspnet",
            "severity": "low",
            "title": "ASP.NET version header exposed",
            "detail": str(asp)[:120],
        })
    return {"issues": issues}


def compare_csp(enforced: str | None, report_only: str | None) -> dict[str, Any]:
    """Diff an enforcing policy against a Report-Only one.

    A Report-Only header is a staged change: it says what the policy is about
    to become. Showing only the enforcing policy hides that entirely, so the
    part of the configuration that is actively being worked on was invisible.
    """
    result: dict[str, Any] = {
        "has_report_only": bool(report_only and str(report_only).strip()),
        "identical": False,
        "stricter": [],   # sources the staged policy would stop allowing
        "looser": [],     # sources it would start allowing
        "added_directives": [],
        "removed_directives": [],
    }
    if not result["has_report_only"]:
        return result

    enforced_d = parse_csp(enforced)
    staged_d = parse_csp(report_only)
    result["identical"] = enforced_d == staged_d
    if result["identical"]:
        return result

    for directive in sorted(set(staged_d) - set(enforced_d)):
        result["added_directives"].append(
            {"directive": directive, "sources": staged_d[directive]})
    for directive in sorted(set(enforced_d) - set(staged_d)):
        result["removed_directives"].append(
            {"directive": directive, "sources": enforced_d[directive]})

    for directive in sorted(set(enforced_d) & set(staged_d)):
        before = [s.lower() for s in enforced_d[directive]]
        after = [s.lower() for s in staged_d[directive]]
        dropped = [s for s in before if s not in after]
        # "'none'" grants nothing, so gaining it is a tightening, not a
        # loosening — reporting it as "would additionally allow 'none'" reads
        # as the opposite of what the change does.
        gained = [s for s in after if s not in before and s != "'none'"]
        if dropped:
            result["stricter"].append({"directive": directive, "sources": dropped})
        if gained:
            result["looser"].append({"directive": directive, "sources": gained})
    return result


# Destinations that a browser fetches in "no-cors" mode: images, media, fonts,
# classic scripts, stylesheets, frames, plugins. Under COEP: require-corp each
# of these must carry a Cross-Origin-Resource-Policy header from the third
# party, which sites you do not control generally do not send.
#
# connect-src is deliberately absent: fetch/XHR is a CORS request, and a CORS
# response satisfies COEP on its own. A site talking to an API cross-origin is
# not what COEP breaks.
_COEP_SENSITIVE_DIRECTIVES = (
    "default-src", "script-src", "script-src-elem", "style-src", "style-src-elem",
    "img-src", "media-src", "font-src", "frame-src", "child-src", "object-src",
    "worker-src",
)

# Sources that never need CORP: same-origin, nothing at all, inline keywords,
# and the two schemes whose responses are same-origin by construction.
_COEP_HARMLESS_SOURCES = {
    "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'",
    "'wasm-unsafe-eval'", "'unsafe-hashes'", "'report-sample'",
    "data:", "blob:", "filesystem:", "mediastream:",
}


def coep_breaking_sources(csp_analysis: dict | None) -> list[str]:
    """Return the CSP sources that COEP: require-corp would block.

    COEP is not a baseline header — it is an opt-in to cross-origin isolation
    with a hard prerequisite, and recommending it to a site that loads
    third-party images breaks those images. This reports the evidence that the
    prerequisite is not met, taken from the site's own policy.
    """
    directives = (csp_analysis or {}).get("directives") or {}
    if not directives:
        return []
    found = []
    for name in _COEP_SENSITIVE_DIRECTIVES:
        for source in directives.get(name) or []:
            token = str(source).strip()
            lowered = token.lower()
            if not token or lowered in _COEP_HARMLESS_SOURCES:
                continue
            if lowered.startswith("'nonce-") or lowered.startswith("'sha"):
                continue
            found.append(token)
    # Order-preserving de-duplication: the first mention reads most naturally
    # in the explanation.
    return list(dict.fromkeys(found))


# Headers whose value comes from a small fixed vocabulary. Presence was the
# only thing checked, so a typo — which a browser discards entirely — scored
# the same as a correct value, and a valid-but-toothless value scored the same
# as a protective one. Both leave you believing you are covered.
#
# "weak" values are spec-valid and do work; they simply grant what the header
# exists to deny, so they are reported separately from an outright typo.
_HEADER_VALUE_RULES = {
    "X-Content-Type-Options": {
        "valid": {"nosniff"},
        "weak": {},
        "expected": "nosniff",
    },
    "Cross-Origin-Resource-Policy": {
        "valid": {"same-origin", "same-site", "cross-origin"},
        "weak": {"cross-origin": "Any site may load your resources, which is what "
                                 "happens without the header at all."},
        "expected": "same-site (or same-origin)",
    },
    "Cross-Origin-Opener-Policy": {
        "valid": {"same-origin", "same-origin-allow-popups", "noopener-allow-popups",
                  "unsafe-none"},
        "weak": {"unsafe-none": "This is the browser default; the header grants "
                                "nothing it would not already do."},
        "expected": "same-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "valid": {"require-corp", "credentialless", "unsafe-none"},
        "weak": {"unsafe-none": "This is the browser default; the header grants "
                                "nothing it would not already do."},
        "expected": "require-corp",
    },
    "X-XSS-Protection": {
        # The legacy XSS auditor is removed from every modern browser, and in
        # the browsers that had it, filtering mode introduced vulnerabilities
        # of its own. 0 is the recommended value, not a weakness.
        "valid": {"0", "1"},
        "weak": {"1": "The legacy XSS auditor is deprecated and was itself a source of "
                      "vulnerabilities; browsers that still honour it can be tricked into "
                      "breaking a safe page."},
        "expected": "0 (and rely on Content-Security-Policy)",
    },
    "X-Frame-Options": {
        # ALLOW-FROM was removed from every browser; a policy relying on it is
        # not honoured anywhere.
        "valid": {"deny", "sameorigin"},
        "weak": {},
        "expected": "DENY or SAMEORIGIN (prefer CSP frame-ancestors)",
    },
}

# Referrer-Policy takes a comma-separated fallback list, and browsers skip
# tokens they do not know. So it is only broken when no token is recognised.
_REFERRER_TOKENS = {
    "no-referrer", "no-referrer-when-downgrade", "origin",
    "origin-when-cross-origin", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin", "unsafe-url", "",
}
_REFERRER_WEAK = {
    "unsafe-url": "The full URL, including path and query, is sent to every "
                  "site you link to — over plain HTTP as well.",
    "no-referrer-when-downgrade": "The full URL is sent to every other HTTPS "
                                  "site; this was the old browser default.",
}


# A feature omitted from Permissions-Policy is not wide open: most powerful
# features default to `self`. The value that actually grants everything is `*`,
# so that is what gets reported rather than absence.
_PERMISSIONS_ENTRY = re.compile(r"([a-z0-9-]+)\s*=\s*(\*|\([^)]*\)|[^,;]+)", re.I)

# Features where handing the capability to any embedded third party has a
# direct privacy or security consequence.
_PERMISSIONS_SENSITIVE = {
    "camera", "microphone", "geolocation", "display-capture", "usb", "midi",
    "payment", "serial", "hid", "bluetooth", "idle-detection",
    "local-fonts", "browsing-topics",
}


def analyze_permissions_policy(value: str | None) -> dict[str, Any]:
    """Report which features a Permissions-Policy hands to everyone.

    Only presence was checked, so a policy granting `camera=*` scored the same
    as one denying it. Absence of a feature is deliberately not reported: the
    browser default for the sensitive ones is already `self`.
    """
    result = {"present": bool(value), "features": {}, "wide_open": [],
              "sensitive_wide_open": []}
    if not value:
        return result
    for entry in str(value).split(","):
        # Everything after a semicolon is a parameter of this entry, most
        # commonly `;report-to=default`. Matching across it turned report-to
        # into a feature of its own in the parsed output.
        declaration = entry.split(";", 1)[0].strip()
        match = _PERMISSIONS_ENTRY.match(declaration)
        if not match:
            continue
        key = match.group(1).lower()
        raw = match.group(2).strip()
        result["features"][key] = raw
        inner = raw.strip("()").strip().lower()
        if raw == "*" or inner == "*":
            result["wide_open"].append(key)
    result["sensitive_wide_open"] = [
        f for f in result["wide_open"] if f in _PERMISSIONS_SENSITIVE
    ]
    return result


def check_header_values(headers_found: dict | None) -> list[dict]:
    """Report security headers whose value does not do what it looks like.

    Two separate failures, deliberately not merged: a value a browser rejects
    leaves you with no header at all, and a value a browser accepts but which
    permits everything leaves you with no protection. Presence alone told you
    neither.
    """
    issues = []
    for header, raw in (headers_found or {}).items():
        value = str(raw or "").strip()
        if not value:
            continue
        rule = _HEADER_VALUE_RULES.get(header)
        if rule:
            # Ignore any parameters (`; report-to=...`) — only the token counts.
            token = value.split(";", 1)[0].strip().lower()
            if token not in rule["valid"]:
                issues.append({
                    "header": header, "value": value, "problem": "invalid",
                    "expected": rule["expected"],
                    "detail": f"`{value}` is not a value {header} accepts, so browsers "
                              f"discard the header. The site is in the same position as "
                              f"if it were never sent.",
                })
            elif token in rule["weak"]:
                issues.append({
                    "header": header, "value": value, "problem": "permissive",
                    "expected": rule["expected"],
                    "detail": rule["weak"][token],
                })
            continue

        if header == "Referrer-Policy":
            tokens = [t.strip().lower() for t in value.split(",")]
            known = [t for t in tokens if t in _REFERRER_TOKENS and t]
            if not known:
                issues.append({
                    "header": header, "value": value, "problem": "invalid",
                    "expected": "strict-origin-when-cross-origin",
                    "detail": f"No token in `{value}` is a Referrer-Policy value, so "
                              f"browsers fall back to their own default and the header "
                              f"has no effect.",
                })
            else:
                # The last understood token is the one that applies.
                effective = known[-1]
                if effective in _REFERRER_WEAK:
                    issues.append({
                        "header": header, "value": value, "problem": "permissive",
                        "expected": "strict-origin-when-cross-origin",
                        "detail": _REFERRER_WEAK[effective],
                    })
    return issues


def analyze_response_security(headers) -> dict[str, Any]:
    """Run CSP + cookie + CORS + framing + disclosure analysis on response headers."""
    if hasattr(headers, "items"):
        headers_lc = {str(k).lower(): v for k, v in headers.items()}
        csp_raw = headers.get("Content-Security-Policy") or headers_lc.get("content-security-policy")
        csp_ro_raw = (headers.get("Content-Security-Policy-Report-Only")
                      or headers_lc.get("content-security-policy-report-only"))
    else:
        headers_lc = {str(k).lower(): v for k, v in (headers or {}).items()}
        csp_raw = headers_lc.get("content-security-policy")
        csp_ro_raw = headers_lc.get("content-security-policy-report-only")

    csp = analyze_csp(csp_raw)
    csp_report_only = analyze_csp(csp_ro_raw) if csp_ro_raw else None
    csp_delta = compare_csp(csp_raw, csp_ro_raw)
    cookies = analyze_cookies(headers)
    cors = analyze_cors(headers_lc)
    framing = analyze_framing(headers_lc, csp)
    disclosure = analyze_info_disclosure(headers_lc)

    all_issues = []
    for block in (csp, cookies, cors, framing, disclosure):
        all_issues.extend(block.get("issues") or [])

    return {
        "csp": csp,
        "csp_report_only": csp_report_only,
        "csp_delta": csp_delta,
        "cookies": cookies,
        "cors": cors,
        "framing": framing,
        "disclosure": disclosure,
        "issues": all_issues,
        "issue_count": len(all_issues),
    }
