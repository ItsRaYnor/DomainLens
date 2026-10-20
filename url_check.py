"""Judge a link without opening it: Tools -> Mail and web analysis, Links.

A suspicious link often arrives on its own -- forwarded, in a chat, read out
from a screenshot -- without the message around it. Opening it to see where
it goes is the one thing not to do: a phishing link usually carries a code
per recipient, and a single request tells its sender the link was seen, or
spends a one-time token. So nothing here fetches the link. It is judged by:

  * what it is: the real host behind an "@" ("https://bank.example@evil.example/"),
    letters that only look Latin, a bare IP address (also written as one
    number), a shortener, plain http, another domain's name put in front of
    the real one ("bank.example.login.evil.example"), a script or file link;
  * whether it imitates one of the organisation's own domains;
  * what is known about it: the threat lists on this server, VirusTotal by
    hash when switched on, the age of its domain at the registry (RDAP), and
    the reputation of the address its host points to.

The host name is looked up through DNS4EU, so the host's own name server
sees a question from DNS4EU, not from this server: a host name made unique
per recipient cannot tell its owner that this organisation looked.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

MAX_LINKS = 10
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
               "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in", "qrco.de"}
_TLD_LABELS = {"com", "net", "org", "nl", "be", "de", "eu", "co", "uk", "fr", "io", "info", "gov", "edu", "biz"}
_SEVERITY = ("critical", "high", "medium", "low", "info")
_URL_IN_TEXT = re.compile(r"(?:h[tx]{2}ps?|ftp)\[?:\]?//[^\s<>\"']+|(?:www\.)[^\s<>\"']+"
                          r"|\b(?:javascript|data|vbscript):[^\s<>\"']+", re.I)


# --------------------------------------------------------------- reading the text

def _refang(text):
    """Links as security people share them: hxxp://, example[.]com, [:]//."""
    text = re.sub(r"\bhxxp(s?)", r"http\1", text, flags=re.I)
    return text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://")


def extract(text):
    """The links in pasted text, defanged ones made whole, at most MAX_LINKS.
    A line that is only a host name or host/path counts as a link too."""
    text = _refang(str(text or ""))
    found = [m.group().rstrip(".,;)]}>'\"") for m in _URL_IN_TEXT.finditer(text)]
    for line in text.splitlines():
        token = line.strip()
        if token and " " not in token and "://" not in token and "." in token and not token.startswith("www."):
            if re.match(r"^[\w.-]+\.[A-Za-z¡-￿]{2,}(?::\d+)?(?:[/?#].*)?$", token):
                found.append(token)
    out = []
    for url in found:
        if "://" not in url and not re.match(r"(?i)(javascript|data|vbscript):", url):
            # A host with no scheme: read as a browser does today, https first.
            url = "https://" + url
        if url not in out:
            out.append(url)
    return out[:MAX_LINKS], max(0, len(dict.fromkeys(found)) - MAX_LINKS)


# --------------------------------------------------------------- what the link is

def _scripts(label):
    seen = set()
    for ch in label:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            seen.add(name.split(" ")[0] if name else "UNKNOWN")
    return seen


def _host_unicode(host):
    try:
        return ".".join(l.encode("ascii").decode("idna") if l.startswith("xn--") else l for l in host.split("."))
    except UnicodeError:
        return host


def _ip_literal(host):
    """An IP address, also written as one number or in hex ("http://3232235777/")."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d{8,10}", host):
            return ipaddress.ip_address(int(host))
        if re.fullmatch(r"0x[0-9a-f]{1,8}", host, re.I):
            return ipaddress.ip_address(int(host, 16))
    except ValueError:
        pass
    return None


def _registrable(host):
    from domain_portfolio import registrable
    return registrable(host) if "." in host else host


def inspect(url):
    """What the link itself says, before anything is asked about it.
    {"url", "scheme", "host", "host_unicode", "registrable", "ip", "port", "findings"}"""
    findings = []
    add = lambda severity, title, detail: findings.append({"severity": severity, "title": title, "detail": detail})
    parts = urllib.parse.urlsplit(url.strip())
    scheme = parts.scheme.lower()
    out = {"url": url, "scheme": scheme, "host": None, "host_unicode": None, "registrable": None,
           "ip": None, "port": None, "findings": findings}
    if scheme in ("javascript", "data", "vbscript", "file"):
        add("high", "The link runs code or opens a local file",
            f"A {scheme}: link does not lead to a web page: it runs in the browser or opens something on the computer.")
        return out
    try:
        host = (parts.hostname or "").rstrip(".").lower()
        out["port"] = parts.port
    except ValueError:
        host = ""
    if not host:
        add("info", "No host in the link", "This does not read as a web address.")
        return out
    # The name as DNS knows it (punycode): a host written with non-Latin
    # letters was looked up as written, and read as not existing.
    try:
        host = ".".join(label.encode("idna").decode("ascii") if not label.isascii() else label
                        for label in host.split("."))
    except UnicodeError:
        add("medium", "A host name that is not valid", f"\"{host}\" cannot be a name in DNS.")
        return out
    out["host"] = host
    unicode_host = _host_unicode(host)
    out["host_unicode"] = unicode_host
    if parts.username is not None:
        shown = urllib.parse.unquote(parts.username) + (":…" if parts.password else "")
        add("high", "The link hides its real destination behind an @",
            f"It reads as {shown}, but everything before the @ is ignored: it goes to {unicode_host}.")
    ip = _ip_literal(host)
    if ip is not None:
        out["ip"] = str(ip)
        written = "" if str(ip) == host else f" (written as {host})"
        add("medium", "The link points to a bare IP address",
            f"It goes to {ip}{written} rather than to a named site, which legitimate links rarely do.")
        if not ip.is_global:
            add("info", "The link points to a private address",
                f"{ip} is only reachable inside a network: the link is aimed at a device or service there.")
    else:
        out["registrable"] = _registrable(host)
        out["registrable_unicode"] = _host_unicode(out["registrable"])
        mixed = [label for label in unicode_host.split(".") if len(_scripts(label) - {"DIGIT"}) > 1]
        if mixed:
            add("high", "The link uses look-alike characters",
                f"{unicode_host} mixes alphabets in \"{mixed[0]}\" ({', '.join(sorted(_scripts(mixed[0])))}): "
                f"letters that look Latin but are not. Its real name is {host}.")
        elif unicode_host != host:
            add("info", "An internationalised domain name",
                f"{unicode_host} is written with non-Latin letters; its name in DNS is {host}.")
        sub = host[: -len(out["registrable"])].rstrip(".") if host != out["registrable"] else ""
        labels = sub.split(".") if sub else []
        # "bank.com.login" in front of the registrable domain: a TLD label
        # after the first one reads as the end of a domain name.
        if any(label in _TLD_LABELS for label in labels[1:]):
            add("medium", "Another domain's name is put in front of the real one",
                f"{unicode_host} belongs to {out['registrable']}; the \"{sub}\" before it is only a name "
                "that domain chose for itself.")
        if host in _SHORTENERS or out["registrable"] in _SHORTENERS:
            add("low", "A URL shortener hides the destination",
                f"{host} forwards to another address, which cannot be seen without opening the link.")
    if scheme == "http":
        add("low", "Over plain http", "The page would load without encryption: what is typed can be read on the way.")
    if out["port"] and out["port"] not in (80, 443):
        add("info", "An unusual port", f"The link uses port {out['port']}.")
    if len(url) > 300 or url.count("%") > 12:
        add("info", "A long or heavily encoded link",
            "Long, encoded links are used to hide where a link goes and to carry a code per recipient.")
    return out


# --------------------------------------------------------------- what is known about it

class Lookups:
    """What is asked of the outside, replaceable in tests."""

    def own_domains(self):
        import link_check
        return link_check.own_domains()

    def feeds(self, urls):
        import link_check
        return link_check.check_feeds(urls)

    def virustotal(self, urls):
        import link_check
        state = link_check.virustotal_state()
        return state, (link_check.check_virustotal(urls) if state == "on" else {})

    def resolve(self, host):
        """("measured", [addresses]) | ("nxdomain", []) | ("unmeasured", [])"""
        import dns.resolver
        import dns_tools
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(dns_tools.RESOLVERS[dns_tools.DEFAULT_RESOLVER])
        resolver.lifetime = 5
        addresses = []
        try:
            for rtype in ("A", "AAAA"):
                try:
                    addresses += [r.to_text() for r in resolver.resolve(host, rtype)]
                except dns.resolver.NoAnswer:
                    continue
        except dns.resolver.NXDOMAIN:
            return "nxdomain", []
        except Exception:
            return "unmeasured", []
        return "measured", addresses

    def registration(self, domain):
        import rdap
        return rdap.lookup(domain)

    def reputation(self, ip):
        return None


def _age_days(registered):
    if not registered:
        return None
    try:
        when = datetime.fromisoformat(str(registered).replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).days


def _known(item, lookups, own, feeds, vt):
    url, findings = item["url"], item["findings"]
    add = lambda severity, title, detail: findings.append({"severity": severity, "title": title, "detail": detail})
    checks = item["checks"] = {}
    host, reg = item["host"], item["registrable"]
    import link_check
    imitated = link_check.lookalike(host, own) if host and own and not item["ip"] else None
    checks["lookalike"] = {"state": "measured" if own else "not_configured", "imitates": imitated}
    if imitated:
        add("high", "The link goes to a lookalike of your domain",
            f"{item['host_unicode']} looks like {imitated}, which is yours.")
    feed = (feeds or {}).get(url) if feeds is not None else None
    checks["feeds"] = {"state": "not_configured" if feeds is None else feed}
    if feed == "listed":
        add("high", "The link is on a threat list", f"{url} is listed as malicious.")
    elif feed == "host_listed":
        add("medium", "The link goes to a host with listed links",
            f"Other links on {host} are on a threat list; this exact link is not.")
    vt_state, vt_results = vt
    vt_result = (vt_results or {}).get(url) or {"state": "off" if vt_state != "on" else "not_checked"}
    checks["virustotal"] = vt_result
    if vt_result.get("state") == "malicious":
        add("high", "VirusTotal engines flag the link",
            f"{vt_result.get('malicious')} of {vt_result.get('engines')} engines call it malicious.")
    elif vt_result.get("state") == "suspicious":
        add("medium", "VirusTotal engines call the link suspicious",
            f"{vt_result.get('suspicious')} of {vt_result.get('engines')} engines.")
    if not host:
        return item
    if reg and not item["ip"]:
        reg_data = lookups.registration(reg) or {}
        age = _age_days(reg_data.get("registered")) if reg_data.get("success") else None
        if reg_data.get("registered") is False:
            state = "not_registered"
        elif age is not None:
            state = "measured"
        elif reg_data.get("success"):
            state = "no_date"  # registered, but the registry gives no date
        else:
            state = reg_data.get("state") if reg_data.get("state") == "not_applicable" else "unmeasured"
        checks["registration"] = {"state": state, "registered": reg_data.get("registered") or None,
                                  "age_days": age, "registrar": ((reg_data.get("registrar") or {}).get("name")),
                                  "error": reg_data.get("error")}
        if state == "not_registered":
            add("medium", "The domain is not registered",
                f"{reg} has no registration: the link leads nowhere now, and anyone could register the "
                "domain and put something behind it.")
        if age is not None and age < 30:
            add("high", "The domain was registered days ago",
                f"{reg} was registered {age} day(s) ago. Phishing domains are used within days of registration.")
        elif age is not None and age < 90:
            add("medium", "The domain is only weeks old", f"{reg} was registered {age} days ago.")
    state, addresses = ("measured", [item["ip"]]) if item["ip"] else lookups.resolve(host)
    checks["dns"] = {"state": state, "addresses": addresses[:6]}
    if state == "nxdomain":
        add("info", "The host does not exist",
            f"{host} has no DNS record: the link leads nowhere now, though its owner can bring it back.")
    public = [a for a in addresses if _public(a)]
    if public:
        rep = lookups.reputation(public[0])
        checks["reputation"] = {"ip": public[0], "result": rep}
        if rep:
            if rep.get("is_listed"):
                add("medium", "The server's address is on a blocklist",
                    f"{public[0]} is listed on {', '.join(rep.get('listed') or [])}.")
            on_lists = ((rep.get("ip_lists") or {}).get("lists") or [])
            if on_lists:
                drop = any("DROP" in (e.get("source") or "") for e in on_lists)
                add("high" if drop else "medium", "The server's address is on an IP threat list",
                    f"{public[0]} is on " + ", ".join(e.get("source") or "" for e in on_lists) + ".")
    return item


def _public(text):
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


def check(text, lookups=None):
    """{"links": [...], "skipped": n} for the links in `text`."""
    lookups = lookups or Lookups()
    urls, skipped = extract(text)
    items = [inspect(u) for u in urls]
    for item in items:
        item["checks"] = {}
    web = [i["url"] for i in items if i["scheme"] in ("http", "https") and i["host"]]
    own = lookups.own_domains() or set()
    feeds = lookups.feeds(web) if web else {}
    vt = lookups.virustotal(web) if web else ("off", {})
    with ThreadPoolExecutor(max_workers=5) as pool:
        items = list(pool.map(lambda i: _known(i, lookups, own, feeds, vt) if i["host"] else i, items))
    for item in items:
        item["findings"].sort(key=lambda f: _SEVERITY.index(f["severity"]))
        item["worst"] = item["findings"][0]["severity"] if item["findings"] else None
    return {"links": items, "skipped": skipped, "own_domains": len(own),
            "feeds": "not_configured" if feeds is None else "checked", "virustotal": vt[0]}
