"""Registration data through RDAP, the structured successor to WHOIS.

WHOIS over port 43 is free text in a different layout per registry, and the
parser missed most of it for .nl: no reseller, no DNSSEC flag, no registrar
address. RDAP returns the same facts as JSON in one format for every
registry, found through IANA's bootstrap file.

Holder and contact details are withheld by most registries (GDPR); SIDN
shows them only on its own website. A withheld field is reported as
withheld, never as empty, with a link to the registry's own lookup where one
exists -- the operator can check there, this tool does not scrape it.
"""

from __future__ import annotations

import threading
import time

import requests

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_BOOTSTRAP_TTL = 24 * 3600
_TIMEOUT = 10
_bootstrap = {"at": 0.0, "services": None}
_lock = threading.Lock()

# Where a person can see what RDAP withholds, per TLD. ICANN's lookup covers
# the generic TLDs.
_REGISTRY_LOOKUP = {
    "nl": ("SIDN", "https://www.sidn.nl/whois?q={domain}"),
    "be": ("DNS Belgium", "https://www.dnsbelgium.be/en/whois/info/{domain}/details"),
    "eu": ("EURid", "https://whois.eurid.eu/en/search/?domain={domain}"),
}
_ICANN_LOOKUP = ("ICANN", "https://lookup.icann.org/en/lookup?name={domain}")

_REDACTED_MARKERS = ("redacted", "not disclosed", "withheld", "privacy")


def _services():
    with _lock:
        if _bootstrap["services"] is not None and time.time() - _bootstrap["at"] < _BOOTSTRAP_TTL:
            return _bootstrap["services"]
    resp = requests.get(_BOOTSTRAP_URL, timeout=_TIMEOUT)
    resp.raise_for_status()
    services = resp.json().get("services") or []
    with _lock:
        _bootstrap.update(at=time.time(), services=services)
    return services


def server_for(domain):
    """The RDAP base URL for the domain's TLD, or None when there is none."""
    tld = domain.rsplit(".", 1)[-1].lower()
    for tlds, urls in _services():
        if tld in (t.lower() for t in tlds):
            https = [u for u in urls if u.lower().startswith("https://")]
            return (https or [None])[0]
    return None


def registry_lookup(domain):
    tld = domain.rsplit(".", 1)[-1].lower()
    name, url = _REGISTRY_LOOKUP.get(tld, _ICANN_LOOKUP)
    return {"name": name, "url": url.format(domain=domain)}


def _vcard(entity):
    """{fn, org, email, address} from an entity's jCard."""
    out = {}
    try:
        fields = entity.get("vcardArray", [None, []])[1]
    except (IndexError, TypeError, AttributeError):
        return out
    for field in fields:
        if not isinstance(field, list) or len(field) < 4:
            continue
        name, value = field[0], field[3]
        if name in ("fn", "org", "email") and isinstance(value, str) and value.strip():
            out.setdefault(name, value.strip())
        elif name == "adr":
            label = (field[1] or {}).get("label") if isinstance(field[1], dict) else None
            if label:
                out.setdefault("address", " ".join(str(label).split()))
            elif isinstance(value, list):
                parts = [str(p).strip() for p in value if isinstance(p, str) and p.strip()]
                if parts:
                    out.setdefault("address", ", ".join(parts))
    return out


def _is_redacted(text):
    return bool(text) and any(m in text.lower() for m in _REDACTED_MARKERS)


def _party(entity):
    card = _vcard(entity)
    name = card.get("fn") or card.get("org")
    if not name or _is_redacted(name):
        return {"withheld": True}
    party = {"withheld": False, "name": name}
    for key in ("org", "email", "address"):
        if card.get(key) and not _is_redacted(card[key]) and card[key] != name:
            party[key] = card[key]
    abuse = [e for e in entity.get("entities") or [] if "abuse" in (e.get("roles") or [])]
    if abuse:
        email = _vcard(abuse[0]).get("email")
        if email:
            party["abuse_email"] = email
    return party


def _date(value):
    return str(value)[:10] if value else None


def parse(data, domain, server=None):
    """Normalise an RDAP domain object to the fields the pages show."""
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or []}
    parties = {}
    for entity in data.get("entities") or []:
        for role in entity.get("roles") or []:
            parties.setdefault(role, _party(entity))
    secure = data.get("secureDNS") or {}
    return {
        "success": True,
        "source": "rdap",
        "server": server,
        "domain": data.get("ldhName") or domain,
        "status": data.get("status") or [],
        "dnssec": bool(secure.get("delegationSigned")) if "delegationSigned" in secure else None,
        "nameservers": [n.get("ldhName", "").lower() for n in data.get("nameservers") or []
                        if n.get("ldhName")],
        "registered": _date(events.get("registration")),
        "updated": _date(events.get("last changed")),
        "expires": _date(events.get("expiration")),
        "registrar": parties.get("registrar"),
        "reseller": parties.get("reseller"),
        # Always present: a registry that returns no holder at all has not
        # published one, which is the same fact to the reader as withholding.
        "registrant": parties.get("registrant") or {"withheld": True},
        "administrative": parties.get("administrative") or {"withheld": True},
        "technical": parties.get("technical") or {"withheld": True},
        "registry_lookup": registry_lookup(domain),
    }


def lookup(domain):
    """RDAP registration data, or a result that says why there is none."""
    domain = (domain or "").strip().lower().rstrip(".")
    try:
        server = server_for(domain)
    except Exception as exc:
        return {"success": False, "state": "unmeasured",
                "error": f"RDAP bootstrap unavailable: {type(exc).__name__}"}
    if not server:
        return {"success": False, "state": "not_applicable",
                "error": "This TLD's registry does not offer RDAP",
                "registry_lookup": registry_lookup(domain)}
    try:
        resp = requests.get(server.rstrip("/") + "/domain/" + domain, timeout=_TIMEOUT,
                            headers={"Accept": "application/rdap+json"})
    except requests.RequestException as exc:
        return {"success": False, "state": "unmeasured",
                "error": f"RDAP request failed: {type(exc).__name__}"}
    if resp.status_code == 429:
        # Throttled: not an answer about the domain. The caller waits this
        # long before asking this server anything again.
        try:
            retry_after = float(resp.headers.get("Retry-After") or 10)
        except (TypeError, ValueError):
            retry_after = 10.0
        return {"success": False, "state": "unmeasured", "retry_after": retry_after,
                "error": "The registry is rate limiting lookups (HTTP 429)"}
    if resp.status_code == 404:
        return {"success": False, "state": "measured", "registered": False,
                "error": "The registry has no registration for this domain"}
    if resp.status_code != 200:
        return {"success": False, "state": "unmeasured",
                "error": f"RDAP server answered HTTP {resp.status_code}"}
    try:
        return parse(resp.json(), domain, server=server)
    except ValueError:
        return {"success": False, "state": "unmeasured", "error": "RDAP answer was not JSON"}
