"""Judge one received e-mail: did SPF, DKIM and DMARC pass, and does it arrive safely.

The DNS checks say what a domain publishes. They cannot say whether the mail
it actually sends passes: an SPF record can be valid and still miss the
newsletter service, a DKIM key can be published and never used, and DMARC
fails most often on alignment -- SPF passing for the service's bounce
domain, not for the domain in From -- which no record shows.

This module reads one message as received (an .eml file, or the headers
pasted from "show original") and works it out from the message itself:

  * SPF for the address that handed the message to the receiving side,
    found in the Received chain;
  * every DKIM signature, verified against the key in DNS;
  * DMARC alignment from those two, against the policy of the From domain;
  * the sending server: reverse DNS, HELO name, blocklists, TLS on arrival;
  * the content: what receivers and readers trip over.

Nothing is stored except the DKIM selectors a message reveals, so later
scans check the real key instead of guessing selector names. The message
itself is analysed and forgotten.

Three states throughout: a result that could not be worked out from this
message (no body, so no signature check; no sending address in the
headers; a DNS lookup that failed) is "unmeasured", never a fail.
"""

from __future__ import annotations

import base64
import email
import email.policy
import email.utils
import html.parser
import ipaddress
import logging
import re
import urllib.parse
from datetime import datetime, timezone

MAX_BYTES = 10 * 1024 * 1024
_MAX_SIGNATURES = 10

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


# --------------------------------------------------------------- storage

def init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dkim_selectors_seen (
            domain TEXT NOT NULL,
            selector TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (domain, selector)
        )
        """
    )


def remember(pairs):
    """Keep (domain, selector) pairs a message showed to have a key."""
    import db
    now = datetime.now(timezone.utc).isoformat()
    with db._lock, db._connect() as conn:
        for domain, selector in pairs:
            conn.execute(
                "INSERT INTO dkim_selectors_seen (domain, selector, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(domain, selector) DO UPDATE SET last_seen = ?",
                (domain, selector, now, now, now))


def learned_selectors(domain):
    """Selectors seen in real mail of this domain, for the DKIM scan check."""
    import db
    try:
        with db._lock, db._connect() as conn:
            rows = conn.execute(
                "SELECT selector FROM dkim_selectors_seen WHERE domain = ? ORDER BY last_seen DESC",
                ((domain or "").lower(),)).fetchall()
    except Exception:
        return []
    return [r[0] for r in rows]


# --------------------------------------------------------------- lookups

class Lookups:
    """DNS and SPF, replaceable in tests. Each lookup returns None when it
    could not be answered (timeout, server failure): that is "unmeasured",
    while an empty list is a measured "nothing there"."""

    timeout = 5.0

    def _resolve(self, name, rdtype):
        import dns.resolver
        try:
            answer = dns.resolver.resolve(name, rdtype, lifetime=self.timeout)
            return [r.to_text() for r in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            return None

    def txt(self, name):
        records = self._resolve(name, "TXT")
        if records is None:
            return None
        return ["".join(part.strip('"') for part in re.findall(r'"((?:[^"\\]|\\.)*)"', r)) or r
                for r in records]

    def ptr(self, ip):
        import dns.reversename
        names = self._resolve(dns.reversename.from_address(ip).to_text(), "PTR")
        return None if names is None else [n.rstrip(".").lower() for n in names]

    def addresses(self, host):
        v4, v6 = self._resolve(host, "A"), self._resolve(host, "AAAA")
        if v4 is None and v6 is None:
            return None
        return (v4 or []) + (v6 or [])

    def spf(self, ip, mail_from, helo):
        import spf
        return spf.check2(i=ip, s=mail_from, h=helo or "unknown", timeout=int(self.timeout * 2))

    def dkim_key(self, name, timeout=5):
        """dkimpy's dnsfunc: the TXT record as bytes, None when absent."""
        import dkim
        name = (name.decode("ascii") if isinstance(name, bytes) else name).rstrip(".")
        records = self.txt(name)
        if records is None:
            raise dkim.DnsTimeoutError("DNS lookup for the DKIM key failed")
        return records[0].encode() if records else None

    def blocklist(self, ip):
        return None

    def own_domains(self):
        """The organisation's own registered domains, to spot lookalikes."""
        return set()

    def check_links(self, urls):
        """{"feeds": {url: state} or None, "virustotal": {"state", "results"}}
        -- see link_check.py. Here: nothing checked."""
        return {"feeds": None, "virustotal": {"state": "off", "results": {}}}


# --------------------------------------------------------------- parsing

def _normalise(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    raw = raw.lstrip(b"\r\n")
    # Pasted text arrives with bare newlines; signatures are over CRLF.
    return re.sub(rb"\r?\n", b"\r\n", raw)


def _split(raw):
    head, sep, body = raw.partition(b"\r\n\r\n")
    return head, body if sep else b""


def _org(domain):
    from domain_portfolio import registrable
    domain = (domain or "").strip(".").lower()
    return registrable(domain) if "." in domain else domain


def _ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _public(ip):
    return ip is not None and ip.is_global


_RECEIVED = re.compile(r"^\s*from\s+(?P<from>.*?)\s+by\s+(?P<by>\S+)(?P<tail>.*)$", re.S | re.I)
_BRACKETED = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_PAREN_IP = re.compile(r"\(([0-9A-Fa-f:.]{3,})\)")
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}\.?$")


def _hop(text, index):
    flat = " ".join(text.split())
    when = flat.rsplit(";", 1)[1].strip() if ";" in flat else ""
    head = flat.rsplit(";", 1)[0] if ";" in flat else flat
    m = _RECEIVED.match(head)
    hop = {"index": index, "helo": None, "rdns": None, "ip": None, "by": None,
           "protocol": None, "tls_version": None, "cipher": None, "at": when, "public": False,
           "text": flat[:400]}
    if not m:
        by = re.search(r"\bby\s+(\S+)", head, re.I)
        hop["by"] = by.group(1).rstrip(";").lower() if by else None
    else:
        source = m.group("from")
        hop["by"] = m.group("by").lower()
        tokens = source.split()
        if tokens and not tokens[0].startswith(("(", "[")):
            hop["helo"] = tokens[0].lower()
        found = _BRACKETED.search(source) or _PAREN_IP.search(source)
        candidate = _ip(found.group(1)) if found else None
        if candidate is None and hop["helo"]:
            candidate = _ip(hop["helo"].strip("[]"))
        if candidate is not None:
            hop["ip"] = str(candidate)
            hop["public"] = _public(candidate)
        rdns = re.search(r"\(\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,63})\.?\s*\[", source)
        if rdns:
            hop["rdns"] = rdns.group(1).lower()
        head = m.group("tail")
    proto = re.search(r"\bwith\s+(Microsoft SMTP Server|\S+)", head, re.I)
    if proto:
        hop["protocol"] = proto.group(1).rstrip(";")
    version = (re.search(r"version=(TLS\s?v?1[._]?[0-3]|SSLv\d)", head, re.I)
               or re.search(r"\((TLS\s?v?1[._][0-3])\)", head, re.I)
               or re.search(r"\b(TLSv1(?:\.[0-3])?)\b", head))
    if version:
        hop["tls_version"] = _tls_name(version.group(1))
    cipher = re.search(r"cipher=([A-Z0-9_-]+)", head, re.I) or re.search(r"\btls\s+([A-Z0-9_-]{8,})", head)
    if cipher:
        hop["cipher"] = cipher.group(1)
    return hop


def _tls_name(text):
    digits = re.search(r"1[._]?([0-3])", text)
    return f"TLS 1.{digits.group(1)}" if digits and "SSL" not in text.upper() else text


def _tls_of(hop):
    """True, False, or None when the header does not say."""
    if hop["tls_version"]:
        return True
    proto = (hop["protocol"] or "").upper()
    if proto in ("ESMTPS", "ESMTPSA", "UTF8SMTPS", "UTF8SMTPSA", "LMTPS"):
        return True
    if proto in ("ESMTP", "SMTP", "ESMTPA", "UTF8SMTP", "MICROSOFT SMTP SERVER"):
        return False
    return None


def _border(hops, received_spf):
    """The hop where the message entered the receiving side.

    The receiver's own Received-SPF names the address it judged; that is
    taken when a hop shows the same address. Otherwise the newest hop from a
    public address whose sending name belongs to another organisation than
    the receiving one: internal hops of a large provider stay within its own
    domain, the hand-over between organisations does not.
    """
    claimed = received_spf.get("client_ip") if received_spf else None
    if claimed:
        for hop in hops:
            if hop["ip"] and _ip(hop["ip"]) == _ip(claimed):
                return hop["index"], "received-spf"
    for hop in hops:
        if not hop["public"]:
            continue
        name = hop["rdns"] or (hop["helo"] if hop["helo"] and _HOSTNAME.match(hop["helo"]) else None)
        if not name or _org(name) != _org(hop["by"] or ""):
            return hop["index"], "received"
    return None, None


def _received_spf(msg):
    value = msg.get("Received-SPF")
    if not value:
        return None
    flat = " ".join(str(value).split())
    out = {"result": flat.split()[0].lower() if flat else None, "text": flat[:300]}
    for key in ("client-ip", "helo", "envelope-from"):
        m = re.search(rf"\b{key}=\"?([^;\s\"]+)", flat, re.I)
        out[key.replace("-", "_")] = m.group(1).strip("<>") if m else None
    return out


def _auth_results(msg):
    """What the receiving system wrote in its topmost Authentication-Results."""
    value = msg.get("Authentication-Results")
    if not value:
        return None
    flat = " ".join(str(value).split())
    out = {"authserv_id": flat.split(";", 1)[0].strip().split()[0] if flat else "", "methods": {}}
    for method, result in re.findall(r"\b(spf|dkim|dmarc|arc|compauth)=(\w+)", flat, re.I):
        out["methods"].setdefault(method.lower(), result.lower())
    for key in ("header.from", "header.d", "smtp.mailfrom"):
        m = re.search(rf"\b{re.escape(key)}=([^;\s]+)", flat, re.I)
        if m:
            out[key] = m.group(1).lower()
    # Each DKIM result with the signature it is about (domain, selector and
    # the start of the signature value), to compare with our own check.
    out["dkim"] = []
    for part in flat.split(";"):
        m = re.match(r"\s*dkim=(\w+)", part, re.I)
        if not m:
            continue
        attrs = {k.lower(): v for k, v in re.findall(r"\b(header\.[a-z]+)=([^\s;]+)", part, re.I)}
        domain = attrs.get("header.d") or (attrs.get("header.i") or "").rsplit("@", 1)[-1]
        out["dkim"].append({"result": m.group(1).lower(), "domain": domain.lower().rstrip("."),
                            "selector": attrs.get("header.s", ""), "b": attrs.get("header.b", "")})
    return out


def _tags(value):
    tags = {}
    for part in " ".join(str(value).split()).split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _address_domain(addr):
    addr = (addr or "").strip().strip("<>")
    return addr.rsplit("@", 1)[1].lower().rstrip(".") if "@" in addr else None


# --------------------------------------------------------------- checks

def _finding(findings, severity, area, title, detail=""):
    findings.append({"severity": severity, "area": area, "title": title, "detail": detail})


def _spf(lookups, ip, mail_from, helo):
    identity = mail_from or (f"postmaster@{helo}" if helo else None)
    domain = _address_domain(identity)
    out = {"state": "unmeasured", "result": None, "domain": domain, "ip": ip,
           "identity": "mail-from" if mail_from else "helo", "explanation": ""}
    if not ip:
        out["explanation"] = "The headers name no sending address."
        return out
    if not domain:
        out["explanation"] = "The message has no envelope sender (Return-Path) and no HELO name."
        return out
    try:
        result, explanation = lookups.spf(ip, identity, helo)
    except Exception as exc:  # a library or DNS failure is not a verdict
        out["explanation"] = f"SPF could not be evaluated: {type(exc).__name__}"
        return out
    out["explanation"] = explanation or ""
    if result == "temperror":
        return out
    out["state"] = "measured"
    out["result"] = result
    return out


def _key_bits(record):
    tags = _tags(record)
    p = tags.get("p", "")
    if not p:
        return None, tags.get("k", "rsa")
    if tags.get("k", "rsa").lower() == "ed25519":
        return 256, "ed25519"
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        return load_der_public_key(base64.b64decode(p)).key_size, "rsa"
    except Exception:
        return None, "rsa"


class _Collect(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def _receiver_verified(receiver, sig, b_value):
    """Whether the receiving system wrote that it verified this signature."""
    compact = re.sub(r"\s+", "", b_value or "")
    for entry in (receiver or {}).get("dkim", []):
        if (entry["result"] == "pass" and entry["domain"] == sig["domain"]
                and (not entry["selector"] or entry["selector"] == sig["selector"])
                and (not entry["b"] or compact.startswith(entry["b"]))):
            return True
    return False


_ALTERED = ("The receiving system verified this signature on arrival, so the message given here "
            "is not the one that was signed. It was altered on the way here: copying the source from "
            "a web page drops spaces and line breaks. Upload the original message file "
            "(Gmail: Download original) to verify it.")


def _dkim(lookups, raw, msg, has_body, receiver=None):
    import dkim
    # Each signature costs a DNS lookup; a message is not a way to make this
    # server send hundreds. Real mail carries one to three.
    headers = (msg.get_all("DKIM-Signature") or [])[:_MAX_SIGNATURES]
    signatures = []
    for idx, value in enumerate(headers):
        tags = _tags(value)
        sig = {"domain": (tags.get("d") or "").lower().rstrip("."), "selector": tags.get("s") or "",
               "algorithm": (tags.get("a") or "").lower(), "state": "unmeasured", "result": None,
               "reason": "", "key_bits": None, "key_type": None}
        signatures.append(sig)
        if not sig["domain"] or not sig["selector"]:
            sig.update(state="measured", result="fail", reason="The signature names no domain or selector.")
            continue
        key_name = f"{sig['selector']}._domainkey.{sig['domain']}"
        try:
            record = lookups.dkim_key(key_name.encode())
        except dkim.DnsTimeoutError:
            sig["reason"] = f"The key at {key_name} could not be looked up."
            continue
        if record:
            sig["key_bits"], sig["key_type"] = _key_bits(record.decode("utf-8", "replace"))
        if not has_body:
            sig["reason"] = ("Only headers were given; the signature covers the body too. "
                             "Upload the whole message to verify it.")
            if not record:
                sig.update(state="measured", result="fail", reason=f"No key is published at {key_name}.")
            continue
        logger = logging.getLogger(f"domainlens.mailtest.dkim.{id(sig)}")
        collect = _Collect()
        logger.addHandler(collect)
        logger.propagate = False
        try:
            ok = dkim.DKIM(raw, logger=logger, minkey=512).verify(idx=idx, dnsfunc=lookups.dkim_key)
            sig.update(state="measured", result="pass" if ok else "fail")
            if not ok:
                said = " ".join(collect.lines)
                sig["reason"] = ("The body was changed after signing (a footer, a re-encoding, a forward)."
                                 if "body hash mismatch" in said
                                 else f"No key is published at {key_name}." if "missing public key" in said
                                 else "The signature does not match the signed headers.")
        except dkim.DnsTimeoutError:
            sig["reason"] = f"The key at {key_name} could not be looked up."
        except dkim.DKIMException as exc:
            text = str(exc)
            sig.update(state="measured", result="fail",
                       reason=(f"No key is published at {key_name}." if "missing public key" in text
                               else "The body was changed after signing (a footer, a re-encoding, a forward)."
                               if "body hash mismatch" in text
                               else f"The signature could not be checked: {text}"))
        finally:
            logger.removeHandler(collect)
        # The receiver checked the message as it arrived; a mismatch here,
        # with its "pass" on record, says the copy changed since -- not the
        # sending side. That is not measured, never a fail.
        if (sig["result"] == "fail" and not sig["reason"].startswith("No key")
                and _receiver_verified(receiver, sig, tags.get("b"))):
            sig.update(state="unmeasured", result=None, reason=_ALTERED, receiver="pass")
    state = ("measured" if all(s["state"] == "measured" for s in signatures) else "unmeasured") \
        if signatures else "measured"
    return {"state": state, "signatures": signatures}


def _dmarc_policy(lookups, from_domain):
    """(record tags, the domain it came from) or None when DNS did not answer."""
    org = _org(from_domain)
    for name in dict.fromkeys((from_domain, org)):
        records = lookups.txt(f"_dmarc.{name}")
        if records is None:
            return None
        found = [r for r in records if r.replace(" ", "").lower().startswith("v=dmarc1")]
        if found:
            return _tags(found[0]), name
    return {}, None


def _aligned(a, b, mode):
    if not a or not b:
        return False
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    return a == b if mode == "s" else _org(a) == _org(b)


def _dmarc(lookups, from_domain, spf, dkim_result):
    out = {"state": "unmeasured", "result": None, "policy": None, "policy_domain": None,
           "spf_aligned": False, "dkim_aligned": False, "explanation": ""}
    if not from_domain:
        out["explanation"] = "The message does not have exactly one From address."
        return out
    found = _dmarc_policy(lookups, from_domain)
    if found is None:
        out["explanation"] = "The DMARC record could not be looked up."
        return out
    tags, policy_domain = found
    out["policy_domain"] = policy_domain
    if not tags:
        out.update(state="measured", result="none",
                   explanation=f"{from_domain} publishes no DMARC policy, so receivers decide on their own.")
        return out
    policy = tags.get("p", "none").lower()
    if policy_domain != from_domain and tags.get("sp"):
        policy = tags["sp"].lower()
    out["policy"] = policy
    spf_ok = spf["state"] == "measured" and spf["result"] == "pass"
    out["spf_aligned"] = spf_ok and _aligned(spf["domain"], from_domain, tags.get("aspf", "r").lower())
    passing = [s for s in dkim_result["signatures"] if s["state"] == "measured" and s["result"] == "pass"]
    out["dkim_aligned"] = any(_aligned(s["domain"], from_domain, tags.get("adkim", "r").lower()) for s in passing)
    if out["spf_aligned"] or out["dkim_aligned"]:
        out.update(state="measured", result="pass")
        via = " and ".join(n for n, ok in (("SPF", out["spf_aligned"]), ("DKIM", out["dkim_aligned"])) if ok)
        out["explanation"] = f"{via} passed for a domain aligned with {from_domain}."
        return out
    if spf["state"] != "measured" or dkim_result["state"] != "measured":
        out["explanation"] = "Not every part could be checked, and the parts that could did not pass aligned."
        return out
    out.update(state="measured", result="fail")
    # One sentence per reason: the page translates sentence by sentence.
    reasons = []
    if spf_ok:
        reasons.append(f"SPF passed for {spf['domain']}, which is not aligned with {from_domain}.")
    if passing:
        reasons.append("DKIM passed for " + ", ".join(sorted({s["domain"] for s in passing}))
                       + f", which is not aligned with {from_domain}.")
    out["explanation"] = " ".join(reasons) if reasons else "Neither SPF nor DKIM passed."
    return out


def _server(lookups, hop, findings):
    out = {"ip": None, "ptr": None, "ptr_state": "unmeasured", "fcrdns": None, "helo": None,
           "helo_ok": None, "tls": None, "tls_version": None, "cipher": None, "by": None,
           "blocklist": None}
    if not hop:
        return out
    out.update(ip=hop["ip"], helo=hop["helo"], by=hop["by"], tls=_tls_of(hop),
               tls_version=hop["tls_version"], cipher=hop["cipher"])
    ip = hop["ip"]
    names = lookups.ptr(ip) if ip else None
    if names is not None:
        out["ptr_state"] = "measured"
        out["ptr"] = names
        if not names:
            _finding(findings, "medium", "server", "The sending address has no reverse DNS",
                     f"{ip} has no PTR record. Many receivers reject or mark mail from such addresses.")
        else:
            confirmed = None
            for name in names[:3]:
                back = lookups.addresses(name)
                if back is None:
                    continue
                confirmed = bool(confirmed) or any(_ip(a) == _ip(ip) for a in back)
            out["fcrdns"] = confirmed
            if confirmed is False:
                _finding(findings, "low", "server", "Reverse DNS does not point back",
                         f"{ip} names {names[0]}, but that name does not resolve to {ip}.")
    if hop["helo"]:
        literal = hop["helo"].strip("[]")
        out["helo_ok"] = bool(_HOSTNAME.match(hop["helo"])) and _ip(literal) is None
        if not out["helo_ok"]:
            _finding(findings, "low", "server", "The HELO name is not a full host name",
                     f"The server introduced itself as \"{hop['helo']}\". Use its own fully qualified name.")
    if out["tls"] is False:
        _finding(findings, "medium", "server", "The message arrived without TLS",
                 f"{hop['by']} received it unencrypted: anyone on the path could read it.")
    elif out["tls_version"] in ("TLS 1.0", "TLS 1.1"):
        _finding(findings, "medium", "server", f"The message arrived over {out['tls_version']}",
                 "TLS 1.0 and 1.1 are outdated. Use TLS 1.2 or newer on the sending server.")
    if ip and _ip(ip) and _ip(ip).version == 4:
        listed = lookups.blocklist(ip)
        if listed is not None:
            out["blocklist"] = {"listed": listed.get("listed", []),
                                "spamhaus": bool(listed.get("spamhaus_dqs")),
                                "ip_lists": listed.get("ip_lists")}
            if listed.get("listed"):
                _finding(findings, "high", "server", "The sending address is on a blocklist",
                         f"{ip} is listed on " + ", ".join(listed["listed"]) + ".")
            # Spamhaus DROP names networks run by criminals, which no
            # legitimate sender uses: high. Other lists name addresses seen
            # attacking lately, which a shared or cloud address can be
            # without the message being bad: medium, as in the scan.
            import ip_lists
            on_lists = (listed.get("ip_lists") or {}).get("lists") or []
            drop = [e for e in on_lists if e["source"] == ip_lists.SPAMHAUS]
            other = [e for e in on_lists if e["source"] != ip_lists.SPAMHAUS]
            if drop:
                _finding(findings, "high", "server", "The sending address is in a network on Spamhaus DROP",
                         f"{ip} is in a netblock Spamhaus advises not to route: hijacked, or run by criminals. "
                         "Source: Spamhaus DROP, © The Spamhaus Project.")
            if other:
                _finding(findings, "medium", "server", "The sending address is on an IP threat list",
                         f"{ip} is listed on " + ", ".join(e["source"] for e in other) + ". "
                         "A shared or cloud address can be listed for another user's traffic.")
    return out


class _Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.images, self.text = [], 0, []
        self._href, self._label = None, []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("style", "script", "head"):
            self._skip += 1
        if tag == "a" and attrs.get("href"):
            self._href, self._label = attrs["href"].strip(), []
        if tag == "img":
            self.images += 1

    def handle_endtag(self, tag):
        if tag in ("style", "script", "head") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._label).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._label.append(data)


_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
               "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc"}
_DANGEROUS = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "ps1", "jar",
              "msi", "hta", "lnk", "iso", "img", "vhd", "vhdx", "cpl", "reg", "dll"}
_RISKY = {"docm", "xlsm", "pptm", "dotm", "xlam", "html", "htm", "shtml", "svg", "one"}
_DOMAINISH = re.compile(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:[/:?#]\S*)?$", re.I)


def _content(msg, findings):
    out = {"has_text": False, "has_html": False, "links": [], "attachments": [], "bulk": False,
           "unsubscribe": "not_applicable"}
    links = _Links()
    plain = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        if filename or disposition == "attachment":
            ext = (filename or "").rsplit(".", 1)[-1].lower() if filename and "." in filename else ""
            out["attachments"].append({"name": filename or "(unnamed)", "type": ctype})
            if ext in _DANGEROUS:
                _finding(findings, "high", "content", "A program or script is attached",
                         f"\"{filename}\" can run code when opened; receivers block or quarantine it.")
            elif ext in _RISKY:
                _finding(findings, "medium", "content", "An attachment type used for phishing",
                         f"\"{filename}\": macros or a web page in an attachment are a common lure.")
            continue
        try:
            text = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            text = payload.decode("utf-8", "replace")
        if not isinstance(text, str):
            continue
        if ctype == "text/html":
            out["has_html"] = True
            try:
                links.feed(text)
            except Exception:
                pass
        elif ctype == "text/plain":
            out["has_text"] = True
            plain.append(text)

    if out["has_html"] and not out["has_text"]:
        _finding(findings, "low", "content", "HTML only, no plain-text part",
                 "Add a text/plain alternative: spam filters weigh its absence, and some readers need it.")
    visible = " ".join(" ".join(links.text).split())
    if out["has_html"] and links.images and len(visible) < 40:
        _finding(findings, "low", "content", "Mostly images, hardly any text",
                 "A message that is one picture is what spam looks like to a filter; put the text in as text.")

    mismatched, ip_links, insecure, shortened = [], [], 0, []
    for href, label in links.links:
        parsed = urllib.parse.urlsplit(href)
        if parsed.scheme.lower() not in ("http", "https"):
            continue
        host = (parsed.hostname or "").lower()
        out["links"].append({"host": host, "text": label[:120], "https": parsed.scheme.lower() == "https",
                             "url": href[:2000]})
        if parsed.scheme.lower() == "http":
            insecure += 1
        if _ip(host):
            ip_links.append(host)
        if host in _SHORTENERS:
            shortened.append(host)
        shown = _DOMAINISH.match(label.strip())
        if shown and host and _org(shown.group(1)) != _org(host):
            mismatched.append(f"{shown.group(1).lower()} → {host}")
    for text in plain:
        insecure += len(re.findall(r"\bhttp://", text))
    if mismatched:
        _finding(findings, "medium", "content", "A link shows one address and leads to another",
                 "; ".join(dict.fromkeys(mismatched))[:400] + ". This is the pattern phishing filters look for.")
    if ip_links:
        _finding(findings, "medium", "content", "A link points to a bare IP address",
                 ", ".join(dict.fromkeys(ip_links)) + ". Link to a host name.")
    if shortened:
        _finding(findings, "low", "content", "A link uses a URL shortener",
                 ", ".join(dict.fromkeys(shortened)) + ". Shorteners hide the destination and are often filtered.")
    if insecure:
        _finding(findings, "low", "content", "Links over plain http",
                 f"{insecure} link(s) use http:// instead of https://.")

    list_unsub = str(msg.get("List-Unsubscribe") or "")
    precedence = str(msg.get("Precedence") or "").lower()
    out["bulk"] = bool(msg.get("List-Id") or list_unsub or precedence in ("bulk", "list"))
    if out["bulk"]:
        one_click = "list-unsubscribe=one-click" in str(msg.get("List-Unsubscribe-Post") or "").lower().replace(" ", "")
        has_https = "<https://" in list_unsub.lower()
        out["unsubscribe"] = "one-click" if (one_click and has_https) else "incomplete" if list_unsub else "missing"
        if not list_unsub:
            _finding(findings, "medium", "content", "Bulk mail without List-Unsubscribe",
                     "Gmail and Yahoo require a List-Unsubscribe header on bulk mail.")
        elif not (one_click and has_https):
            _finding(findings, "medium", "content", "Unsubscribe is not one-click",
                     "Add an https:// address to List-Unsubscribe and the header "
                     "List-Unsubscribe-Post: List-Unsubscribe=One-Click (RFC 8058).")
    return out


_MAX_CHECKED_LINKS = 100


def _link_checks(lookups, msg, from_domain, content, findings):
    """Lookalikes of the organisation's own domains (sender, reply address,
    links) and the threat-list and VirusTotal state of every link. Returns
    what was checked, for the page to say so."""
    import link_check
    own = lookups.own_domains() or set()
    out = {"own_domains": len(own), "feeds": "not_configured", "virustotal": "off"}
    if own:
        imitated = link_check.lookalike(from_domain, own) if from_domain else None
        if imitated:
            _finding(findings, "high", "headers", "The sender's domain looks like your own",
                     f"{from_domain} looks like {imitated}, which is yours. This is how impersonation mail is sent.")
        replies = email.utils.getaddresses([str(r) for r in (msg.get_all("Reply-To") or [])])
        for _, addr in replies:
            domain = _address_domain(addr)
            imitated = link_check.lookalike(domain, own) if domain else None
            if imitated:
                _finding(findings, "high", "headers", "Replies go to a lookalike of your domain",
                         f"Reply-To is {addr}; {domain} looks like {imitated}, which is yours.")
    if not content or not content["links"]:
        return out
    links = content["links"]
    seen = []
    for link in links:
        link["lookalike"] = link_check.lookalike(link["host"], own) if own else None
        if link["url"] not in seen:
            seen.append(link["url"])
    imitations = sorted({f"{l['host']} → {l['lookalike']}" for l in links if l["lookalike"]})
    if imitations:
        _finding(findings, "high", "content", "A link goes to a lookalike of your domain",
                 "; ".join(imitations) + ".")
    checked = lookups.check_links(seen[:_MAX_CHECKED_LINKS]) or {}
    feeds = checked.get("feeds")
    out["feeds"] = "not_configured" if feeds is None else "checked"
    vt = checked.get("virustotal") or {"state": "off", "results": {}}
    out["virustotal"] = vt.get("state", "off")
    for link in links:
        link["feed"] = (feeds or {}).get(link["url"], "not_checked") if feeds is not None else "not_checked"
        link["virustotal"] = (vt.get("results") or {}).get(link["url"], {"state": "not_checked"})
    listed = sorted({l["host"] for l in links if l["feed"] == "listed"})
    if listed:
        _finding(findings, "high", "content", "A link is on a threat list", ", ".join(listed) + ".")
    host_listed = sorted({l["host"] for l in links if l["feed"] == "host_listed"} - set(listed))
    if host_listed:
        _finding(findings, "medium", "content", "A link goes to a host with listed addresses",
                 ", ".join(host_listed) + ". This exact link is not on the list, other links on that host are.")
    flagged = sorted({f"{l['host']} ({l['virustotal'].get('malicious', 0)} of {l['virustotal'].get('engines', 0)})"
                      for l in links if l["virustotal"].get("state") == "malicious"})
    if flagged:
        _finding(findings, "high", "content", "VirusTotal engines flag a link as malicious", ", ".join(flagged) + ".")
    suspicious = sorted({l["host"] for l in links if l["virustotal"].get("state") == "suspicious"})
    if suspicious:
        _finding(findings, "medium", "content", "VirusTotal engines flag a link as suspicious", ", ".join(suspicious) + ".")
    return out


def _headers(msg, findings):
    """Checks on the header fields themselves. Returns the From domain, or None."""
    froms = msg.get_all("From") or []
    addresses = email.utils.getaddresses([str(f) for f in froms])
    from_domain = None
    if len(froms) != 1 or len(addresses) != 1:
        _finding(findings, "high", "headers", "The message does not have exactly one From address",
                 "Receivers reject such messages, and DMARC cannot be evaluated for them.")
    else:
        name, addr = addresses[0]
        from_domain = _address_domain(addr)
        shown = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name or "")
        if shown and addr and shown.group(0).lower() != addr.lower():
            _finding(findings, "medium", "headers", "The display name shows another address",
                     f"The name reads \"{name}\" while the message is from {addr}: "
                     "readers believe the name, and filters flag it.")
    reply = email.utils.getaddresses([str(r) for r in (msg.get_all("Reply-To") or [])])
    reply_domains = {_org(_address_domain(a)) for _, a in reply if _address_domain(a)}
    if from_domain and reply_domains and reply_domains != {_org(from_domain)}:
        _finding(findings, "info", "headers", "Replies go to another domain",
                 "Reply-To points to " + ", ".join(sorted(reply_domains)) + ". Often intended, sometimes a sign of misuse.")
    if not msg.get("Message-ID"):
        _finding(findings, "low", "headers", "No Message-ID",
                 "Every message should carry a Message-ID; Gmail requires one for bulk senders.")
    date = msg.get("Date")
    parsed = None
    try:
        parsed = email.utils.parsedate_to_datetime(str(date)) if date else None
    except (TypeError, ValueError):
        parsed = None
    if parsed is None:
        _finding(findings, "low", "headers", "No valid Date header" if date else "No Date header",
                 "A missing or unreadable date counts against a message in spam filters.")
    if not str(msg.get("Subject") or "").strip():
        _finding(findings, "low", "headers", "No subject", "A message without subject is more often filtered.")
    return from_domain


def _auth_findings(findings, spf, dkim_result, dmarc, from_domain):
    result = spf["result"]
    domain = spf["domain"]
    if spf["state"] == "measured":
        if result == "fail":
            _finding(findings, "high", "auth", "SPF fails for this sender",
                     f"{spf['ip']} is not allowed by the SPF record of {domain}. Add the service that sends this mail.")
        elif result == "softfail":
            _finding(findings, "medium", "auth", "SPF soft-fails for this sender",
                     f"{spf['ip']} is not in the SPF record of {domain} (~all).")
        elif result in ("neutral", "none"):
            _finding(findings, "medium", "auth", "SPF does not vouch for this sender",
                     f"{domain} " + ("has no SPF record." if result == "none" else f"says nothing about {spf['ip']} (?all)."))
        elif result == "permerror":
            _finding(findings, "high", "auth", "The SPF record is broken",
                     f"The SPF record of {domain} cannot be evaluated (permerror): {spf['explanation']}")
    sigs = dkim_result["signatures"]
    if not sigs:
        _finding(findings, "high", "auth", "The message is not DKIM-signed",
                 "Sign outgoing mail with DKIM for your own domain; without it DMARC rests on SPF alone, "
                 "and SPF breaks on every forward.")
    for s in sigs:
        if s["state"] == "measured" and s["result"] == "fail":
            _finding(findings, "high", "auth", f"DKIM signature of {s['domain'] or '?'} fails", s["reason"])
        if s["key_bits"] and s["key_type"] == "rsa":
            if s["key_bits"] < 1024:
                _finding(findings, "high", "auth", f"DKIM key of {s['domain']} is {s['key_bits']} bits",
                         "Keys under 1024 bits can be broken and are ignored by large receivers. Use 2048 bits.")
            elif s["key_bits"] < 2048:
                _finding(findings, "low", "auth", f"DKIM key of {s['domain']} is {s['key_bits']} bits",
                         "1024 bits still passes, but 2048 bits is the current advice.")
        if s["algorithm"] == "rsa-sha1":
            _finding(findings, "medium", "auth", f"DKIM signature of {s['domain']} uses SHA-1",
                     "rsa-sha1 is deprecated (RFC 8301) and treated as unsigned by some receivers. Use rsa-sha256.")
    if from_domain and sigs and not any(_aligned(s["domain"], from_domain, "r") for s in sigs):
        _finding(findings, "medium", "auth", "Signed, but not by the From domain",
                 "Signed by " + ", ".join(sorted({s['domain'] for s in sigs if s['domain']}))
                 + f", not by {from_domain}. Let the sending service sign with a key under your own domain.")
    if dmarc["state"] == "measured":
        if dmarc["result"] == "fail":
            action = {"reject": "rejected", "quarantine": "put in spam"}.get(dmarc["policy"], "delivered anyway, for now")
            _finding(findings, "high", "auth", "DMARC fails for this message",
                     f"{dmarc['explanation']} With p={dmarc['policy']} it is {action}.")
        elif dmarc["result"] == "none":
            _finding(findings, "medium", "auth", "No DMARC policy for the From domain", dmarc["explanation"])
        elif dmarc["policy"] == "none":
            _finding(findings, "low", "auth", "DMARC passes, but the policy only monitors",
                     f"p=none: messages that fail are still delivered. Move to quarantine or reject.")


# --------------------------------------------------------------- entry point

def analyse(raw, *, lookups=None, ip=None):
    """Judge one message. `ip` overrides the sending address found in the
    headers -- the page offers it when the chain was read wrongly."""
    lookups = lookups or Lookups()
    raw = _normalise(raw)
    head, body = _split(raw)
    has_body = bool(body.strip())
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    findings = []

    hops = [_hop(str(v), i) for i, v in enumerate(msg.get_all("Received") or [])]
    received_spf = _received_spf(msg)
    if ip:
        chosen = _ip(str(ip).strip())
        if chosen is None:
            raise ValueError("Not an IP address")
        border = next((h["index"] for h in hops if h["ip"] and _ip(h["ip"]) == chosen), None)
        source = "chosen"
    else:
        border, source = _border(hops, received_spf)
    hop = hops[border] if border is not None else None
    sending_ip = str(chosen) if ip else (hop["ip"] if hop else None)
    if ip and hop is None:
        hop = {"index": None, "helo": None, "rdns": None, "ip": sending_ip, "by": None, "protocol": None,
               "tls_version": None, "cipher": None, "at": "", "public": _public(chosen), "text": ""}

    return_path = msg.get_all("Return-Path") or []
    mail_from = None
    if return_path:
        addr = email.utils.parseaddr(str(return_path[0]))[1]
        mail_from = addr if "@" in addr else None
    helo = (hop or {}).get("helo") or (received_spf or {}).get("helo")

    from_domain = _headers(msg, findings)
    spf = _spf(lookups, sending_ip, mail_from, helo)
    receiver = _auth_results(msg)
    dkim_result = _dkim(lookups, raw, msg, has_body, receiver)
    dmarc = _dmarc(lookups, from_domain, spf, dkim_result)
    for sig in dkim_result["signatures"]:
        sig["aligned"] = bool(from_domain) and _aligned(sig["domain"], from_domain, "r")
    _auth_findings(findings, spf, dkim_result, dmarc, from_domain)
    server = _server(lookups, hop, findings)
    content = _content(msg, findings) if has_body else None
    link_checks = _link_checks(lookups, msg, from_domain, content, findings)

    arc_seals = msg.get_all("ARC-Seal") or []
    arc = None
    if arc_seals:
        top = _tags(arc_seals[0])
        arc = {"instances": len(arc_seals), "cv": (top.get("cv") or "").lower()}

    learned = sorted({(s["domain"], s["selector"]) for s in dkim_result["signatures"]
                      if s["key_bits"] and re.fullmatch(r"[A-Za-z0-9._-]{1,63}", s["selector"])
                      and re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", s["domain"])})

    findings.sort(key=lambda f: _SEVERITY_ORDER.index(f["severity"]))
    return {
        "summary": {
            "from": str(msg.get("From") or ""), "from_domain": from_domain,
            "to": str(msg.get("To") or ""), "subject": str(msg.get("Subject") or ""),
            "date": str(msg.get("Date") or ""), "message_id": str(msg.get("Message-ID") or ""),
            "return_path": mail_from, "has_body": has_body, "size": len(raw),
        },
        "hops": hops,
        "border": border,
        "border_source": source,
        "spf": spf,
        "dkim": dkim_result,
        "dmarc": dmarc,
        "receiver": receiver,
        "received_spf": received_spf,
        "arc": arc,
        "server": server,
        "content": content,
        "link_checks": link_checks,
        "findings": findings,
        "learned": [{"domain": d, "selector": s} for d, s in learned],
    }
