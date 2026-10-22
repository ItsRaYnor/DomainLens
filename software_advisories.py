"""Known vulnerable software versions, matched against what a server shows.

Like nmap's version detection with a vulnerability script, and no more: one
ordinary request for the home page, the way a browser asks for it, and the
version the server volunteers -- X-Powered-By: PHP/8.2.7, or PHP/... in the
Server header -- compared with the versions that carry the fix. Nothing is
sent to trigger a flaw, and nothing is probed for.

Three outcomes, kept apart:

  * vulnerable -- the version shown is older than the fix for its branch,
    or its branch no longer gets fixes at all;
  * fixed -- the version shown carries the fix;
  * cannot tell -- the version is hidden (expose_php off, a proxy that
    strips the header), or it is a distribution build ("8.2.7-1~deb12u1",
    "8.1.2-1ubuntu2.18"): Debian, Ubuntu and Red Hat put fixes into their
    own packages without raising the upstream number, so only the package
    on the server says whether the fix is in.

A version shown is what the server says; a server can claim anything. And a
version hidden is not a version fixed: "cannot tell" is never "clean".
"""

from __future__ import annotations

import re

# One entry per advisory: the fixed release per supported branch, and the
# oldest branch still supported. Newer advisories are added here.
ADVISORIES = [
    {
        "id": "php2shell",
        "product": "PHP",
        "name": "PHP2Shell",
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "severity": "critical",
        "published": "2026-10-21",
        "summary": "Unauthenticated remote code execution in PHP itself (memory corruption on running "
                   "out of memory, and a use-after-free in state kept between requests); exploited "
                   "since the day of the fix.",
        "fixed": {"8.5": (8, 5, 12), "8.4": (8, 4, 27), "8.3": (8, 3, 36), "8.2": (8, 2, 35)},
        "supported_from": (8, 2),
        "references": [
            "https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/",
            "https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote",
        ],
    },
]

_PHP = re.compile(r"\bPHP/(\d+)\.(\d+)(?:\.(\d+))?([^\s,;()]*)", re.I)
_PHP_COOKIES = ("phpsessid", "laravel_session", "ci_session", "wordpress_", "wp-settings")


def _fmt(version):
    return ".".join(str(n) for n in version)


def parse_php(values):
    """{"version": (8, 2, 7), "suffix": "-1~deb12u1", "raw": "PHP/8.2.7-1~deb12u1"} from
    header values, or None. A suffix after the number is a distribution build."""
    for value in values:
        match = _PHP.search(value or "")
        if match:
            major, minor, patch, suffix = match.groups()
            return {"version": (int(major), int(minor), int(patch or 0)), "patch_known": patch is not None,
                    "suffix": suffix or "", "raw": match.group(0)}
    return None


def verdict(advisory, php):
    """("vulnerable" | "fixed" | "cannot_tell", reason) for one advisory."""
    if not php:
        return "cannot_tell", "The PHP version is not shown."
    version, branch = php["version"], php["version"][:2]
    shown = php["raw"]
    vendor = bool(php["suffix"]) and bool(re.search(r"[a-z]", php["suffix"], re.I))
    fixed = advisory["fixed"].get(f"{branch[0]}.{branch[1]}")
    if branch < advisory["supported_from"]:
        if vendor:
            return "cannot_tell", (f"{shown} is a distribution build of a PHP branch that no longer gets "
                                   "upstream fixes; only its package says whether the fix was put in.")
        return "vulnerable", (f"{shown} is PHP {branch[0]}.{branch[1]}, which no longer gets fixes; "
                              f"move to {', '.join(sorted(advisory['fixed']))} at the fixed release or later.")
    if fixed is None:
        return "fixed", f"{shown} is newer than the releases the fix went into."
    if not php["patch_known"]:
        return "cannot_tell", f"{shown} does not show its patch release; {_fmt(fixed)} has the fix."
    if version >= fixed:
        return "fixed", f"{shown} has the fix ({_fmt(fixed)} or later)."
    if vendor:
        return "cannot_tell", (f"{shown} is a distribution build; its package may carry the fix without a new "
                               f"number. Upstream, {_fmt(fixed)} has the fix.")
    return "vulnerable", f"{shown} is older than {_fmt(fixed)}, the release with the fix."


def php_seen(headers, cookies, url=""):
    """Whether the response shows PHP at all, with or without a version."""
    values = [headers.get("x-powered-by", ""), headers.get("server", "")]
    if any("php" in (v or "").lower() for v in values):
        return True
    lowered = (cookies or "").lower()
    return any(c in lowered for c in _PHP_COOKIES) or ".php" in (url or "").lower()


def match(headers, cookies="", url=""):
    """[{"advisory", "name", "cves", "severity", "verdict", "reason", "version"}] for
    the PHP advisories, from one response's headers (lower-case keys). Empty
    when the response shows no PHP at all: not applicable, not "fixed"."""
    php = parse_php([headers.get("x-powered-by", ""), headers.get("server", "")])
    if not php and not php_seen(headers, cookies, url):
        return []
    out = []
    for advisory in ADVISORIES:
        state, reason = verdict(advisory, php)
        out.append({"advisory": advisory["id"], "name": advisory["name"], "cves": advisory["cves"],
                    "severity": advisory["severity"], "verdict": state, "reason": reason,
                    "version": php["raw"] if php else None, "references": advisory["references"]})
    return out


class _Followed:
    """The last response of a chain of redirects, with the ones before it."""

    def __init__(self, resp, history, url):
        self.headers, self.status_code, self.history, self.url = resp.headers, resp.status_code, history, url


def _fetch(url, safe, max_hops=5):
    """GET url, following redirects by hand: each next address must pass
    `safe` (a public address), so a redirect cannot aim this server at its
    own network."""
    import urllib.parse
    import requests
    history = []
    for _ in range(max_hops + 1):
        resp = requests.get(url, timeout=8, allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; DomainLens version check)"})
        location = resp.headers.get("location")
        if resp.status_code not in (301, 302, 303, 307, 308) or not location:
            return _Followed(resp, history, url)
        history.append(resp)
        url = urllib.parse.urljoin(url, location)
        host = urllib.parse.urlsplit(url).hostname or ""
        if urllib.parse.urlsplit(url).scheme not in ("http", "https") or not safe(host):
            return _Followed(resp, history[:-1], url)  # stop at the last safe answer
    return _Followed(resp, history[:-1], url)


def check_host(domain, get=None, safe=None):
    """The fleet check for one domain: its home page asked for once (https,
    then http, then www.), every response on the way read, nothing else.
    {"domain", "url", "state", "php", "advisories", "error"}; state is
    "measured" (a response came), "unmeasured" (none did)."""
    if get is None:
        if safe is None:
            from security_checks import _safe_host as safe
        get = lambda url: _fetch(url, safe)
    candidates = [f"https://{domain}/", f"http://{domain}/"]
    if not domain.startswith("www."):
        candidates += [f"https://www.{domain}/"]
    errors = []
    for url in candidates:
        try:
            resp = get(url)
        except Exception as exc:
            errors.append(type(exc).__name__)
            continue
        # A redirect can carry the version even when the final page does not.
        merged, cookies = {"x-powered-by": [], "server": []}, []
        for step in list(getattr(resp, "history", []) or []) + [resp]:
            for key, value in step.headers.items():
                key = key.lower()
                if key == "set-cookie":
                    cookies.append(value)
                elif key in merged and value and value not in merged[key]:
                    merged[key].append(value)
        merged = {key: " ".join(values) for key, values in merged.items() if values}
        found = match(merged, " ".join(cookies), getattr(resp, "url", url))
        return {"domain": domain, "url": getattr(resp, "url", url), "state": "measured",
                "status": getattr(resp, "status_code", None),
                "server": merged.get("server"), "powered_by": merged.get("x-powered-by"),
                "php": bool(found), "advisories": found, "error": None}
    return {"domain": domain, "url": None, "state": "unmeasured", "php": None, "advisories": [],
            "error": "No response over https, http or www (" + ", ".join(dict.fromkeys(errors)) + ")"}


CSV_COLUMNS = ["domain", "result", "advisory", "cves", "verdict", "version_shown", "x_powered_by", "server",
               "reason", "url"]


def to_csv(results):
    """The version check as CSV, one row per domain and advisory, for the
    teams that patch. Every cell came from a server that is not ours, so a
    value a spreadsheet would run as a formula is defused."""
    import csv
    import io
    from whois_batch import _csv_safe
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for r in results:
        base = {"domain": r.get("domain"), "x_powered_by": r.get("powered_by"), "server": r.get("server"),
                "url": r.get("url")}
        advisories = r.get("advisories") or []
        if r.get("state") != "measured":
            rows = [{**base, "result": "no_response", "reason": r.get("error")}]
        elif not advisories:
            rows = [{**base, "result": "no_php"}]
        else:
            rows = [{**base, "result": a.get("verdict"), "advisory": a.get("name"), "cves": " ".join(a.get("cves") or []),
                     "verdict": a.get("verdict"), "version_shown": a.get("version"), "reason": a.get("reason")}
                    for a in advisories]
        for row in rows:
            writer.writerow([_csv_safe(row.get(c)) for c in CSV_COLUMNS])
    return out.getvalue()
