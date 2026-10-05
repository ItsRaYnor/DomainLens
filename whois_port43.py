"""Registration data over port 43, for the registries that offer no RDAP.

Many country registries (.be, .eu, .de, .at and others) are not in IANA's
RDAP bootstrap, so the RDAP lookup ends with "this registry does not offer
RDAP" and a domain there was never measured at all. Their port-43 WHOIS
does answer, as free text in a layout of each registry's own; the general
WHOIS parser read most of it wrong (no registrar, "NOT AVAILABLE" taken for
a status rather than for "registered", addresses glued to name servers),
and raised an error for a domain that is simply free.

This module asks the registry's WHOIS server itself and reads the answer
into the same shape an RDAP lookup returns, so the portfolio, the batch and
the WHOIS page treat both alike. Three outcomes, as elsewhere: registered
(with what could be read), not registered (the registry said so), or not
measured (no answer, or an answer that could not be read) -- never a guess.
"""

from __future__ import annotations

import re
import socket
import threading
from datetime import datetime

_TIMEOUT = 10
_MAX_BYTES = 128 * 1024

# Registries without RDAP, and their WHOIS servers. Others are found through
# IANA's WHOIS, which names the server for each TLD.
SERVERS = {
    "be": "whois.dns.be",
    "eu": "whois.eu",
    "de": "whois.denic.de",
    "at": "whois.nic.at",
}
# How a server wants the question; DENIC answers a bare name with the
# status only, and gives name servers and keys with these flags.
_QUESTION = {"whois.denic.de": "-T dn,ace {domain}"}
_IANA = "whois.iana.org"
_iana_cache = {}
_lock = threading.Lock()

# What a registry says when a name is free. Matched on the whole status value
# or on the whole line, so "NOT AVAILABLE" (registered, .be) is never "free".
_FREE_STATUS = {"available", "free", "no object found"}
_FREE_LINES = ("nothing found", "no match", "not found", "no entries found", "no data found",
               "domain not found", "object does not exist", "no such domain")
_STATUS_WORDS = {"not available": "Registered", "connect": "Registered, in DNS"}
_LIMIT_MARKERS = ("limit exceeded", "limit reached", "too many", "access control limit",
                  "quota exceeded", "try again later")


def server_for(domain):
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld in SERVERS:
        return SERVERS[tld]
    with _lock:
        if tld in _iana_cache:
            return _iana_cache[tld]
    server = None
    try:
        for line in query(_IANA, tld).splitlines():
            key, _, value = line.partition(":")
            if key.strip().lower() in ("whois", "refer") and value.strip():
                server = value.strip()
                break
    except OSError:
        return None
    with _lock:
        _iana_cache[tld] = server
    return server


def query(server, text):
    """One port-43 question; the answer as text."""
    with socket.create_connection((server, 43), timeout=_TIMEOUT) as sock:
        sock.sendall((text + "\r\n").encode("idna" if text.isascii() else "utf-8"))
        chunks, size = [], 0
        while size < _MAX_BYTES:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
            size += len(data)
    raw = b"".join(chunks)
    for encoding in ("utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def lookup(domain, *, ask=None):
    """Registration data for one domain, shaped like rdap.lookup's result."""
    domain = (domain or "").strip().lower().rstrip(".")
    server = server_for(domain)
    if not server:
        return {"success": False, "state": "not_applicable", "source": "whois",
                "error": "No WHOIS server is known for this TLD"}
    try:
        text = (ask or query)(server, _QUESTION.get(server, "{domain}").format(domain=domain))
    except OSError as exc:
        return {"success": False, "state": "unmeasured", "source": "whois", "server": server,
                "error": f"WHOIS request failed: {type(exc).__name__}"}
    result = parse(text, domain)
    result.update(source="whois", server=server)
    return result


# ---------------------------------------------------------------- reading

def _date(value):
    """An ISO date from the formats these registries use, or None."""
    value = " ".join(str(value or "").split())
    if not value:
        return None
    match = re.match(r"(\d{4})-(\d{2})-(\d{2})", value)
    if match:
        return "-".join(match.groups())
    for fmt in ("%Y%m%d %H:%M:%S", "%Y%m%d", "%a %b %d %Y", "%d.%m.%Y", "%d/%m/%Y", "%d-%b-%Y"):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def _lines(text):
    """(section, key, value) per line; comments dropped. A line "Name:" with
    nothing after it, or a bare heading ("Nameservers", .it), opens a section
    whose indented lines belong to it."""
    out, section = [], ""
    for raw in (text or "").splitlines():
        if not raw.strip() or raw.lstrip().startswith(("%", "#", ">>>")):
            continue
        indented = raw[:1] in (" ", "\t")
        line = raw.strip()
        if not indented:
            key, sep, value = line.partition(":")
            if not sep or not value.strip():
                section = key.strip().lower()
                continue
            section = ""
            out.append(("", key.strip().lower(), value.strip()))
        elif section in ("nameservers", "name servers", "flags", "keys", "status"):
            out.append((section, "", line))
        else:
            key, _, value = line.partition(":")
            out.append((section, key.strip().lower(), value.strip()))
    return out


def _first(fields, *keys, section=""):
    for sec, key, value in fields:
        if sec == section and key in keys and value:
            return value
    return None


def parse(text, domain):
    """The registration in a WHOIS answer, or why there is none."""
    lowered = (text or "").lower()
    fields = _lines(text)
    statuses = [v for s, k, v in fields if (s == "" and k in ("status", "domain status", "state"))
                or s in ("flags", "status")]
    # Registry words that read as the opposite of what they mean to someone
    # who does not know the registry: "NOT AVAILABLE" (DNS Belgium) and
    # "connect" (DENIC) both say the domain is registered.
    shown = [_STATUS_WORDS.get(s.strip().lower(), s) for s in statuses]
    status_words = {s.strip().lower() for s in statuses}

    if status_words & _FREE_STATUS or (
            not any(k in ("domain", "domain name") for _, k, _ in fields)
            and any(marker in lowered for marker in _FREE_LINES)):
        return {"success": False, "state": "measured", "registered": False,
                "error": "The registry has no registration for this domain"}
    if not fields or any(marker in lowered for marker in _LIMIT_MARKERS):
        return {"success": False, "state": "unmeasured",
                "error": "The registry's WHOIS gave no answer that could be read"
                         + (" (rate limited)" if any(m in lowered for m in _LIMIT_MARKERS) else "")}

    joined = " ".join(status_words)
    if "quarantine" in joined:
        phase = "quarantine"
    elif "redemption" in joined:
        phase = "redemption"
    elif "pendingdelete" in joined or "pending delete" in joined:
        phase = "pending_delete"
    else:
        phase = "registered"

    registrar = (_first(fields, "organization", "organisation", "name", section="registrar")
                 or _first(fields, "registrar", "sponsoring registrar", "registrar name"))
    nameservers = []
    for sec, key, value in fields:
        if sec in ("nameservers", "name servers") or key in ("nserver", "name server", "nameserver",
                                                             "name servers", "nameservers"):
            host = value.split()[0].rstrip(".").lower() if value.split() else ""
            if host and "." in host and host not in nameservers:
                nameservers.append(host)
    keys_present = any(sec == "keys" for sec, _, _ in fields) or any(k == "dnskey" for _, k, _ in fields)
    dnssec_word = (_first(fields, "dnssec", "signed") or "").lower()
    dnssec = (True if keys_present or dnssec_word in ("signed", "yes", "signeddelegation", "true")
              else False if dnssec_word in ("unsigned", "no", "false") else None)
    return {
        "success": True,
        "domain": domain,
        "registrar": {"name": registrar} if registrar else None,
        "nameservers": nameservers,
        "registered": _date(_first(fields, "registered", "created", "creation date", "registration date",
                                   "domain record activated")),
        "updated": _date(_first(fields, "changed", "last update", "updated date", "last modified")),
        "expires": _date(_first(fields, "expires", "expiry date", "expire date", "registry expiry date",
                                "expiration date", "paid-till")),
        "status": shown,
        "dnssec": dnssec,
        "lifecycle": {"phase": phase},
    }
