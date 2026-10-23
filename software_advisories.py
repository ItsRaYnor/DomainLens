"""Known vulnerable software versions, matched against what a server shows.

Like nmap's version detection with a vulnerability script, and no more: one
ordinary request for the home page, the way a browser asks for it, and the
version the server volunteers -- X-Powered-By: PHP/8.2.7, Apache/2.4.58 in
the Server header, a <meta name="generator"> -- compared with the versions
that carry the fix. Nothing is sent to trigger a flaw, and nothing is probed
for.

What to look for is data, not code: a rule names a product, the token it
shows itself by ("PHP" in "PHP/8.2.7"), where to read it, and the release
with the fix per branch. The built-in rules are below; an administrator adds
more on Admin -> Advisories (advisory_rules.py keeps them). Every rule runs
through the same engine here, so a rule can say what to compare, never how:
it cannot run code, send a request, or bring a regular expression of its own.

Four outcomes, kept apart:

  * vulnerable -- the version shown is older than the fix for its branch,
    or its branch no longer gets fixes at all;
  * fixed -- the version shown carries the fix;
  * not affected -- the version shown is older than the release the flaw
    came in with, or from a branch the rule says never had it;
  * cannot tell -- the version is hidden (expose_php off, a proxy that
    strips the header), or it is a distribution build ("8.2.7-1~deb12u1",
    "Apache/2.4.52 (Ubuntu)"): Debian, Ubuntu and Red Hat put fixes into
    their own packages without raising the upstream number, so only the
    package on the server says whether the fix is in.

A version shown is what the server says; a server can claim anything. And a
version hidden is not a version fixed: "cannot tell" is never "clean".
"""

from __future__ import annotations

import logging
import re
from datetime import date

log = logging.getLogger("domainlens.advisories")

SEVERITIES = ("critical", "high", "medium", "low")
# Where a version may be read: a response header by its name, or the page's
# <meta name="generator"> (WordPress, Drupal, Joomla put theirs there).
GENERATOR = "meta:generator"
# What an older branch than any listed means: one that no longer gets fixes
# (still vulnerable), or one from before the flaw was introduced.
OLDER_UNFIXED, OLDER_NOT_AFFECTED = "unfixed", "not_affected"

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,39}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,39}$")
_HEADER = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_COOKIE = re.compile(r"^[A-Za-z0-9_.-]{2,40}$")
_PATH = re.compile(r"^[^\s<>\"']{2,40}$")
_RELEASE = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,6})$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_URL = re.compile(r"^https?://[^\s<>\"']{3,300}$")
# A distribution's own build, named after the version: "Apache/2.4.52 (Ubuntu)".
_DISTRO = re.compile(r"^\s*\([^()]*\b(?:ubuntu|debian|red ?hat|centos|rocky|alma ?linux|fedora|suse|"
                     r"amazon linux|oracle linux|raspbian)\b[^()]*\)", re.I)
_GENERATOR_TAG = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)

_LIMITS = {"name": 80, "product": 60, "summary": 600, "impact": 400, "fix": 400, "check": 400}
_HEADERS_NOT_READ = {"set-cookie", "cookie", "authorization"}


# The rules that ship with DomainLens, written as the same data an
# administrator writes. Read-only on the admin page; tested like code.
BUILTIN_RULES = [
    {
        "id": "php2shell",
        "name": "PHP2Shell",
        "product": "PHP",
        "token": "PHP",
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "severity": "critical",
        "published": "2026-10-21",
        "summary": "Unauthenticated remote code execution in PHP itself (memory corruption on running "
                   "out of memory, and a use-after-free in state kept between requests); exploited "
                   "since the day of the fix.",
        "impact": "The flaw lets anyone run code on the server without signing in.",
        "fix": "Update PHP to the release with the fix (or the patched package from your vendor) and restart the "
               "web server and PHP-FPM.",
        "check": "On the server: php -v, or the package version (dpkg -l 'php*', rpm -qa 'php*'), against the "
                 "release with the fix.",
        "sources": ["x-powered-by", "server"],
        "seen_cookies": ["phpsessid", "laravel_session", "ci_session", "wordpress_", "wp-settings"],
        "seen_paths": [".php"],
        "fixed": ["8.5.12", "8.4.27", "8.3.36", "8.2.35"],
        "older_branches": OLDER_UNFIXED,
        "references": [
            "https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/",
            "https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote",
        ],
    },
]


class RuleError(ValueError):
    """A rule that cannot be used, with every reason at once."""

    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


def _fmt(version):
    return ".".join(str(n) for n in version)


def _text(raw, key, problems, required=False):
    value = " ".join(str(raw.get(key) or "").split())
    if required and not value:
        problems.append(f"{key} is required.")
    if len(value) > _LIMITS[key]:
        problems.append(f"{key} is longer than {_LIMITS[key]} characters.")
    return value


def _list(raw, key, problems, most):
    value = raw.get(key) or []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        problems.append(f"{key} must be a list of texts.")
        return []
    value = list(dict.fromkeys(v.strip() for v in value if v and v.strip()))
    if len(value) > most:
        problems.append(f"{key} has more than {most} entries.")
    return value


def compile_rule(raw, builtin=False):
    """A rule as the engine uses it, from the data an administrator wrote.

    Raises RuleError with every problem found, so a form shows them all at
    once. The result keeps the data as written (`public`) beside what the
    engine derives from it: the version pattern and the fix per branch."""
    if not isinstance(raw, dict):
        raise RuleError(["A rule is an object."])
    problems = []
    rule_id = str(raw.get("id") or "").strip().lower()
    if not _SLUG.match(rule_id):
        problems.append("id must be 2 to 40 lower-case letters, digits or dashes, starting with a letter or digit.")
    name = _text(raw, "name", problems, required=True)
    product = _text(raw, "product", problems, required=True)
    token = str(raw.get("token") or "").strip()
    if not _TOKEN.match(token):
        problems.append("token must be the name the software shows itself by, such as PHP, Apache or nginx "
                        "(letters, digits, . _ + -).")
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in SEVERITIES:
        problems.append(f"severity must be one of {', '.join(SEVERITIES)}.")
    published = str(raw.get("published") or "").strip()
    if published:
        try:
            date.fromisoformat(published)
        except ValueError:
            problems.append("published must be a date (YYYY-MM-DD).")
    summary = _text(raw, "summary", problems, required=True)
    impact, fix, check = (_text(raw, k, problems) for k in ("impact", "fix", "check"))

    sources = [s.lower() for s in _list(raw, "sources", problems, 5)]
    if not sources:
        problems.append("sources needs at least one header name, or meta:generator.")
    for source in sources:
        if source != GENERATOR and (not _HEADER.match(source) or source in _HEADERS_NOT_READ):
            problems.append(f"{source} is not a header the check reads.")
    seen_cookies = [c.lower() for c in _list(raw, "seen_cookies", problems, 10)]
    problems += [f"{c} is not a cookie name." for c in seen_cookies if not _COOKIE.match(c)]
    seen_paths = [p.lower() for p in _list(raw, "seen_paths", problems, 5)]
    problems += [f"{p} is not part of an address." for p in seen_paths if not _PATH.match(p)]
    cves = [c.upper() for c in _list(raw, "cves", problems, 20)]
    if not cves:
        problems.append("cves needs at least one CVE.")
    problems += [f"{c} is not a CVE id (CVE-2026-12345)." for c in cves if not _CVE.match(c)]
    references = _list(raw, "references", problems, 10)
    problems += [f"{r} is not an http(s) address." for r in references if not _URL.match(r)]

    fixed = {}
    releases = _list(raw, "fixed", problems, 30)
    for release in releases:
        match = _RELEASE.match(release)
        if not match:
            problems.append(f"{release} is not a release (major.minor.patch, such as 8.4.27).")
            continue
        version = tuple(int(n) for n in match.groups())
        if version[:2] in fixed:
            problems.append(f"Two releases are given for branch {_fmt(version[:2])}.")
        fixed[version[:2]] = version
    if not releases:
        problems.append("fixed needs the release with the fix for at least one branch.")
    older = str(raw.get("older_branches") or OLDER_UNFIXED).strip()
    if older not in (OLDER_UNFIXED, OLDER_NOT_AFFECTED):
        problems.append(f"older_branches must be {OLDER_UNFIXED} or {OLDER_NOT_AFFECTED}.")
    # The release the flaw came in with: anything older never had it.
    introduced = None
    introduced_text = str(raw.get("introduced") or "").strip()
    if introduced_text:
        match = _RELEASE.match(introduced_text)
        if not match:
            problems.append(f"introduced {introduced_text} is not a release (major.minor.patch).")
        else:
            introduced = tuple(int(n) for n in match.groups())
            if fixed and introduced >= max(fixed.values()):
                problems.append("introduced must be older than the newest release with the fix.")
    if problems:
        raise RuleError(problems)

    newest_first = [_fmt(fixed[b]) for b in sorted(fixed, reverse=True)]
    public = {"id": rule_id, "name": name, "product": product, "token": token, "cves": cves,
              "severity": severity, "published": published, "summary": summary, "impact": impact,
              "fix": fix, "check": check, "sources": sources, "seen_cookies": seen_cookies,
              "seen_paths": seen_paths, "fixed": newest_first, "older_branches": older,
              "introduced": _fmt(introduced) if introduced else "", "references": references}
    # The token is matched literally, so nothing an administrator types can
    # make the expression slow: "PHP/8.2.7", "nginx/1.25.3", "WordPress 6.4.2".
    pattern = re.compile(r"(?<![A-Za-z0-9])" + re.escape(token) + r"[/ ]v?(\d+)\.(\d+)(?:\.(\d+))?([^\s,;()]*)",
                         re.I)
    word = re.compile(r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9_-])", re.I)
    return {**public, "builtin": builtin, "public": public, "_pattern": pattern, "_word": word, "_fixed": fixed,
            "_introduced": introduced}


_BUILTIN = [compile_rule(r, builtin=True) for r in BUILTIN_RULES]
BUILTIN_IDS = frozenset(r["id"] for r in _BUILTIN)


def builtin_rules():
    return list(_BUILTIN)


def active_rules():
    """The built-in rules and the administrator's rules that are switched on.

    A custom rule that cannot be read is logged and left out; the built-in
    rules are never lost to it."""
    rules = builtin_rules()
    try:
        import advisory_rules
        rules += advisory_rules.enabled()
    except Exception as exc:
        log.warning("Custom advisory rules could not be read: %s", exc)
    return rules


def _values(rule, headers, generator):
    return [generator if source == GENERATOR else headers.get(source) for source in rule["sources"]]


def parse_version(rule, values):
    """{"version": (8, 2, 7), "suffix": "-1~deb12u1", "raw": "PHP/8.2.7-1~deb12u1",
    "vendor": bool} from what the server shows, or None. A suffix with letters
    after the number, or a distribution named right after it, is a
    distribution build."""
    for value in values:
        match = rule["_pattern"].search(value or "")
        if match:
            major, minor, patch, suffix = match.groups()
            distro = _DISTRO.match(value[match.end():])
            vendor = bool(re.search(r"[a-z]", suffix or "", re.I)) or bool(distro)
            return {"version": (int(major), int(minor), int(patch or 0)), "patch_known": patch is not None,
                    "suffix": suffix or "", "vendor": vendor,
                    "raw": match.group(0) + (distro.group(0) if distro else "")}
    return None


def verdict(rule, shown):
    """("vulnerable" | "fixed" | "not_affected" | "cannot_tell", reason) for one rule."""
    product = rule["product"]
    if not shown:
        return "cannot_tell", f"The {product} version is not shown."
    version, branch, raw = shown["version"], shown["version"][:2], shown["raw"]
    introduced = rule["_introduced"]
    if introduced and (branch < introduced[:2]
                       or (branch == introduced[:2] and shown["patch_known"] and version < introduced)):
        return "not_affected", f"{raw} is older than {_fmt(introduced)}, the release the flaw came in with."
    fixed = rule["_fixed"]
    release = fixed.get(branch)
    if release is None:
        if branch > max(fixed):
            return "fixed", f"{raw} is newer than the releases the fix went into."
        if branch < min(fixed):
            if rule["older_branches"] == OLDER_NOT_AFFECTED:
                return "not_affected", f"{raw} is older than the branches the flaw is in."
            if shown["vendor"]:
                return "cannot_tell", (f"{raw} is a distribution build of a {product} branch that no longer gets "
                                       "upstream fixes; only its package says whether the fix was put in.")
            branches = ", ".join(_fmt(b) for b in sorted(fixed))
            return "vulnerable", (f"{raw} is {product} {_fmt(branch)}, which no longer gets fixes; "
                                  f"move to {branches} at the fixed release or later.")
        return "cannot_tell", f"{raw}: the rule names no release with the fix for {product} {_fmt(branch)}."
    if not shown["patch_known"]:
        return "cannot_tell", f"{raw} does not show its patch release; {_fmt(release)} has the fix."
    if version >= release:
        return "fixed", f"{raw} has the fix ({_fmt(release)} or later)."
    if shown["vendor"]:
        return "cannot_tell", (f"{raw} is a distribution build; its package may carry the fix without a new "
                               f"number. Upstream, {_fmt(release)} has the fix.")
    return "vulnerable", f"{raw} is older than {_fmt(release)}, the release with the fix."


def seen(rule, headers, cookies="", url="", generator=None):
    """Whether the response shows the product at all, with or without a version.

    The token as a word of its own: "Apache-Coyote/1.1" is Tomcat, not the
    Apache HTTP Server, and must not read as it."""
    if any(rule["_word"].search(v or "") for v in _values(rule, headers, generator)):
        return True
    lowered = (cookies or "").lower()
    if any(c in lowered for c in rule["seen_cookies"]):
        return True
    address = (url or "").lower()
    return any(p in address for p in rule["seen_paths"])


def match(headers, cookies="", url="", generator=None, rules=None):
    """One entry per rule whose product the response shows (headers with
    lower-case names): {"advisory", "name", "product", "cves", "severity",
    "verdict", "reason", "version", ...}. A rule whose product is not seen
    gives nothing: not applicable, not "fixed"."""
    out = []
    for rule in (active_rules() if rules is None else rules):
        shown = parse_version(rule, _values(rule, headers, generator))
        if not shown and not seen(rule, headers, cookies, url, generator):
            continue
        state, reason = verdict(rule, shown)
        out.append({"advisory": rule["id"], "name": rule["name"], "product": rule["product"],
                    "cves": rule["cves"], "severity": rule["severity"], "verdict": state, "reason": reason,
                    "version": shown["raw"] if shown else None, "references": rule["references"],
                    "impact": rule["impact"], "fix": rule["fix"], "check": rule["check"]})
    return out


def finding(adv):
    """The scan finding for one match, or None when there is nothing to report.

    Scans stored before rules carried their own texts have only the name and
    the verdict; the built-in rule of the same id fills in the rest, so an
    old report reads as it did."""
    rule = next((r for r in _BUILTIN if r["id"] == adv.get("advisory")), {})
    product = adv.get("product") or rule.get("product") or "the software"
    cves = ", ".join(adv.get("cves") or [])
    pick = lambda key: adv.get(key) or rule.get(key) or ""  # noqa: E731
    if adv.get("verdict") == "vulnerable":
        impact = pick("impact")
        return {"severity": adv.get("severity") or rule.get("severity") or "high",
                "title": f"{adv['name']} ({cves}): the {product} version shown is vulnerable",
                "detail": f"{adv['reason']} {impact}".strip(),
                "fix": pick("fix") or (f"Update {product} to the release with the fix (or the patched package "
                                       "from your vendor)."),
                "evidence": adv.get("version") or ""}
    if adv.get("verdict") == "cannot_tell":
        # Not a defect of the domain: what the outside cannot see is said
        # as such, with what to check on the server.
        return {"severity": "info",
                "title": f"{adv['name']} ({cves}): {product} in use, fix not visible from outside",
                "detail": f"{adv['reason']} Check the {product} version or package on the server itself.",
                "fix": pick("check") or (f"On the server: the installed {product} version or package, against "
                                         "the release with the fix."),
                "evidence": adv.get("version") or ""}
    return None


def redirect_finding(adv, target, url=""):
    """The scan finding for a vulnerable version on the other domain this
    domain redirects to, or None.

    Its visitors end up on that server, so the risk is theirs; the fix is
    on that server, not on this domain's own. Said as such, with the other
    domain named, so it is never read as this domain's own version. A
    version that server hides is for its own scan to say."""
    if adv.get("verdict") != "vulnerable":
        return None
    rule = next((r for r in _BUILTIN if r["id"] == adv.get("advisory")), {})
    product = adv.get("product") or rule.get("product") or "the software"
    cves = ", ".join(adv.get("cves") or [])
    fix = adv.get("fix") or rule.get("fix") or f"Update {product} to the release with the fix."
    return {"severity": adv.get("severity") or rule.get("severity") or "high",
            "title": f"{adv['name']} ({cves}): {target}, where this domain redirects, shows a vulnerable {product} version",
            "detail": (f"This domain sends its visitors to {url or target}. That server, not this domain's own, "
                       f"shows the version: {adv['reason']}"),
            "fix": f"For whoever runs {target}: {fix}",
            "evidence": adv.get("version") or ""}


def generator_of(body):
    """The content of the page's <meta name="generator">, or None."""
    found = _GENERATOR_TAG.search(body[:20000]) if isinstance(body, str) else None
    return found.group(1) if found else None


def wanted_headers(rules):
    """The response headers the rules read, plus the two the page shows."""
    names = {"server", "x-powered-by"}
    for rule in rules:
        names.update(s for s in rule["sources"] if s != GENERATOR)
    return names


def _site(host, fallback=""):
    """The registered domain a host belongs to: example.org for www.example.org."""
    from domain_portfolio import registrable
    host = (host or fallback or "").lower().rstrip(".")
    return registrable(host) if host else ""


def _url_of(step):
    url = getattr(step, "url", "")
    return url if isinstance(url, str) else ""


def hops_of(resp, rules):
    """Every response on the way to the page, first to last, each with the
    headers the rules read: {"url", "host", "status", "headers", "cookies"}."""
    import urllib.parse
    wanted = wanted_headers(rules)
    hops = []
    for step in list(getattr(resp, "history", []) or []) + [resp]:
        headers, cookies = {}, []
        for key, value in step.headers.items():
            key = key.lower()
            if key == "set-cookie":
                cookies.append(value)
            elif key in wanted and value:
                headers[key] = value
        url = _url_of(step)
        hops.append({"url": url, "host": urllib.parse.urlsplit(url).hostname or "",
                     "status": getattr(step, "status_code", None), "headers": headers, "cookies": " ".join(cookies)})
    return hops


def split_hops(hops, domain):
    """(own, target_site, target): the hops on the domain's own registered
    domain (http to https, www., a subdomain), and, when the chain ends on
    another registered domain, that domain and its hops.

    A redirect to another domain hands the visitor to another server. What
    that server shows is its measurement, not the domain's: counting it as
    the domain's would report one site's PHP as another's."""
    site = _site(domain)
    count = 1  # the first answer always comes from the domain itself
    while count < len(hops) and _site(hops[count]["host"], domain) == site:
        count += 1
    own, rest = hops[:count], hops[count:]
    if not rest:
        return own, None, []
    target_site = _site(rest[-1]["host"], domain)
    target = []
    for hop in reversed(rest):
        if _site(hop["host"], domain) != target_site:
            break
        target.insert(0, hop)
    return own, target_site, target


def _side(hops, generator, rules):
    merged, cookies = {}, []
    for hop in hops:
        for key, value in hop["headers"].items():
            if value not in merged.setdefault(key, []):
                merged[key].append(value)
        if hop["cookies"]:
            cookies.append(hop["cookies"])
    headers = {key: " ".join(values) for key, values in merged.items()}
    url = hops[-1]["url"]
    found = match(headers, " ".join(cookies), url, generator, rules=rules)
    return {"url": url, "status": hops[-1]["status"], "server": headers.get("server"),
            "powered_by": headers.get("x-powered-by"), "generator": generator, "seen": bool(found),
            "advisories": found}


def measure(resp, domain, rules):
    """What the domain's own server shows, and apart from it what the server
    shows that a redirect to another registered domain ends on.

    {"url", "status", "server", "powered_by", "generator", "seen",
    "advisories", "redirect": None | {"domain", ...the same keys}, "hops":
    [{"url", "status", "server", "powered_by", "own"}]}. A redirect can carry
    the version even when the final page does not, so every hop on the
    domain's own name counts. The page itself is read only when a rule asks
    for its generator tag, and belongs to the side it was served on."""
    hops = hops_of(resp, rules)
    own, target_site, target = split_hops(hops, domain)
    generator = None
    if any(GENERATOR in rule["sources"] for rule in rules):
        generator = generator_of(getattr(resp, "text", ""))
    result = _side(own, None if target else generator, rules)
    result["redirect"] = {"domain": target_site, **_side(target, generator, rules)} if target else None
    result["hops"] = [{"url": h["url"], "status": h["status"], "server": h["headers"].get("server"),
                       "powered_by": h["headers"].get("x-powered-by"), "own": i < len(own)}
                      for i, h in enumerate(hops)]
    return result


class _Step:
    """One answer on the way, with the address it came from."""

    def __init__(self, resp, url):
        self.headers, self.status_code, self.url = resp.headers, resp.status_code, url
        text = getattr(resp, "text", "")
        self.text = text if isinstance(text, str) else ""


class _Followed(_Step):
    """The last response of a chain of redirects, with the ones before it."""

    def __init__(self, resp, history, url):
        super().__init__(resp, url)
        self.history = history


def _fetch(url, safe, max_hops=5):
    """GET url, following redirects by hand: each next address must pass
    `safe` (a public address), so a redirect cannot aim this server at its
    own network."""
    import urllib.parse
    import requests
    history = []
    here = url
    for _ in range(max_hops + 1):
        resp = requests.get(url, timeout=8, allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; DomainLens version check)"})
        location = resp.headers.get("location")
        if resp.status_code not in (301, 302, 303, 307, 308) or not location:
            return _Followed(resp, history, url)
        here, url = url, urllib.parse.urljoin(url, location)
        host = urllib.parse.urlsplit(url).hostname or ""
        if urllib.parse.urlsplit(url).scheme not in ("http", "https") or not safe(host):
            return _Followed(resp, history, here)  # stop at the last safe answer
        history.append(_Step(resp, here))
    return _Followed(resp, history[:-1], here)


def address_of(host):
    """What DNS says about a host before anything is asked of it: "public",
    "private" (an address inside a network, never asked), "none" (DNS
    answers, without an address) or "failed" (DNS gave no answer)."""
    from security_checks import _is_private_ip, _resolve
    ips = _resolve(host, "A")
    if ips:
        return "private" if _is_private_ip(ips[0]) else "public"
    return "none" if getattr(ips, "state", "measured") == "measured" else "failed"


def check_host(domain, get=None, safe=None, rules=None, address=None):
    """The fleet check for one domain: its home page asked for once (https,
    then http, then www.), every response on the way read, nothing else.
    {"domain", "url", "state", "seen", "advisories", "redirect", "hops",
    "error"} (see measure). state is "measured" (a response came),
    "unmeasured" (no response, or DNS gave no answer), "no_address" (DNS
    says the domain and its www. have no address: there is no website to
    ask) or "not_checked" (an address inside a network, never asked).

    A domain is never left out: one that cannot be checked says why, so a
    list of results never silently has fewer domains than were asked for."""
    if rules is None:
        rules = active_rules()
    if address is None:
        address = (lambda host: "public" if safe(host) else "private") if safe else address_of  # noqa: E731
    if safe is None:
        safe = lambda host: address(host) == "public"  # noqa: E731
    if get is None:
        get = lambda url: _fetch(url, safe)  # noqa: E731
    candidates = [(f"https://{domain}/", domain), (f"http://{domain}/", domain)]
    if not domain.startswith("www."):
        candidates += [(f"https://www.{domain}/", f"www.{domain}")]
    # What was looked up and asked, in order, for the page's details: the
    # answer and the way to it, so a result can be checked by hand.
    known, errors, attempts = {}, [], []
    for url, host in candidates:
        if host not in known:
            known[host] = address(host)
        if known[host] != "public":
            continue
        try:
            resp = get(url)
        except Exception as exc:
            errors.append(type(exc).__name__)
            attempts.append({"url": url, "error": type(exc).__name__})
            continue
        attempts.append({"url": url, "error": None})
        measured = measure(resp, domain, rules)
        return {"domain": domain, "state": "measured", **measured, "url": measured["url"] or url, "error": None,
                "lookups": [{"host": h, "address": a} for h, a in known.items()], "attempts": attempts}
    base = {"domain": domain, "url": None, "seen": None, "advisories": [], "redirect": None, "hops": [],
            "lookups": [{"host": h, "address": a} for h, a in known.items()], "attempts": attempts}
    states = set(known.values())
    if errors:
        return {**base, "state": "unmeasured",
                "error": "No response over https, http or www (" + ", ".join(dict.fromkeys(errors)) + ")"}
    if "failed" in states:
        return {**base, "state": "unmeasured",
                "error": "The DNS lookup gave no answer, so whether the site has an address is not known."}
    if "private" in states:
        return {**base, "state": "not_checked",
                "error": "Resolves to an address inside a network; not asked, so this server is not aimed at "
                         "its own network."}
    return {**base, "state": "no_address",
            "error": "No address in DNS for the domain or its www.: there is no website to ask."}


CSV_COLUMNS = ["domain", "measured_on", "result", "advisory", "cves", "verdict", "version_shown", "x_powered_by",
               "server", "reason", "url"]


def _csv_rows(domain, measured_on, side):
    base = {"domain": domain, "measured_on": measured_on, "x_powered_by": side.get("powered_by"),
            "server": side.get("server"), "url": side.get("url")}
    advisories = side.get("advisories") or []
    if not advisories:
        return [{**base, "result": "not_seen"}]
    return [{**base, "result": a.get("verdict"), "advisory": a.get("name"), "cves": " ".join(a.get("cves") or []),
             "verdict": a.get("verdict"), "version_shown": a.get("version"), "reason": a.get("reason")}
            for a in advisories]


def to_csv(results):
    """The version check as CSV, one row per domain and advisory, for the
    teams that patch. `measured_on` names the server a row was read from:
    the domain itself, or the other domain a redirect sends its visitors to
    (those rows come after the domain's own). Every cell came from a server
    that is not ours, so a value a spreadsheet would run as a formula is
    defused."""
    import csv
    import io
    from whois_batch import _csv_safe
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for r in results:
        domain = r.get("domain")
        if r.get("state") != "measured":
            result = {"no_address": "no_address", "not_checked": "not_checked"}.get(r.get("state"), "no_response")
            rows = [{"domain": domain, "measured_on": domain, "result": result, "reason": r.get("error")}]
        else:
            rows = _csv_rows(domain, domain, r)
            redirect = r.get("redirect")
            if isinstance(redirect, dict):
                rows += _csv_rows(domain, redirect.get("domain"), redirect)
        for row in rows:
            writer.writerow([_csv_safe(row.get(c)) for c in CSV_COLUMNS])
    return out.getvalue()
