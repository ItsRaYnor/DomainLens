"""Assemble a takedown dossier for a lookalike domain.

A notice about an impersonating domain is only acted on if it reaches someone
who can act and contains enough for them to verify the claim without doing
the work again. Two parties can act, and they are different: the registrar
can suspend the name, the hosting network can pull the content. The dossier
therefore carries both abuse addresses rather than one.

What it deliberately does not do is judge. Whether a domain is confusingly
similar to yours is a legal question about your mark and their use of it, not
something a string-distance score settles. DomainLens measures the similarity
and lays out the facts; the assertion stays yours to make and to sign.

Every observation is stamped with the moment it was made, because a registrar
will ask when you saw it and the page may have changed since.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

log = logging.getLogger("domainlens.evidence")


def _now():
    return datetime.now(timezone.utc).isoformat()


def confusable_score(candidate, protected):
    """How close two names are, and why — never whether that is infringement.

    Reported as components rather than one number: "differs by one character"
    and "same name under another TLD" are both high similarity but call for
    completely different wording in a notice.
    """
    candidate = (candidate or "").strip().lower().rstrip(".")
    protected = (protected or "").strip().lower().rstrip(".")
    if not candidate or not protected:
        return None

    def split(name):
        parts = name.split(".")
        return (parts[0], ".".join(parts[1:])) if len(parts) > 1 else (name, "")

    cand_label, cand_tld = split(candidate)
    prot_label, prot_tld = split(protected)

    distance = _levenshtein(cand_label, prot_label)
    longest = max(len(cand_label), len(prot_label)) or 1
    return {
        "candidate": candidate,
        "protected": protected,
        "same_label": cand_label == prot_label,
        "same_tld": cand_tld == prot_tld,
        "edit_distance": distance,
        "similarity": round(1 - (distance / longest), 3),
        "contains_protected": prot_label in cand_label and cand_label != prot_label,
        # A label that is only a TLD swap is the clearest case to describe and
        # the easiest for a registrar to check.
        "tld_swap_only": cand_label == prot_label and cand_tld != prot_tld,
    }


def _levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]


def body_fingerprint(text):
    """A hash a recipient can recompute, plus enough to recognise the page."""
    if text is None:
        return None
    raw = text.encode("utf-8", "replace")
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "length": len(raw),
        "algorithm": "sha256 of the response body as received",
    }


def _first_email(contact):
    return (contact or {}).get("email")


def build(*, domain, protected_domain=None, whois_result=None, dns_result=None,
          http_result=None, tls_result=None, ip_report=None, body_text=None,
          observed_from=None, tool_version=None):
    """Collect the observations into one dossier.

    Takes already-gathered results rather than fetching: the same scan that
    found the domain has the data, and fetching again would produce a dossier
    describing a different moment than the one that raised the alarm.
    """
    whois_data = (whois_result or {}).get("data") or {}
    rdap = (ip_report or {}).get("rdap") or {}

    registrar_abuse = whois_data.get("registrar_abuse_contact_email")
    network_abuse = _first_email(rdap.get("abuse"))

    dossier = {
        "generated_at": _now(),
        "tool": {"name": "DomainLens", "version": tool_version},
        "subject": {
            "domain": domain,
            "observed_from": observed_from,
        },
        "similarity": confusable_score(domain, protected_domain) if protected_domain else None,
        "where_to_report": {
            # Named separately because they can do different things: the
            # registrar can suspend the name, the network can remove the
            # content. A notice to the wrong one is simply forwarded, or not.
            "registrar": {
                "name": whois_data.get("registrar"),
                "abuse_email": registrar_abuse,
                "abuse_phone": whois_data.get("registrar_abuse_contact_phone"),
                "url": whois_data.get("registrar_url"),
                "iana_id": whois_data.get("registrar_iana_id"),
                "can": "suspend or transfer the domain name",
            },
            "hosting_network": {
                "name": rdap.get("name"),
                "range": rdap.get("range"),
                "abuse_email": network_abuse,
                "country": rdap.get("country"),
                "can": "remove or suspend the content on this address",
            },
        },
        "registration": {
            "created": whois_data.get("creation_date"),
            "updated": whois_data.get("updated_date"),
            "expires": whois_data.get("expiration_date"),
            "status": whois_data.get("status"),
            "name_servers": whois_data.get("name_servers"),
            "registrant_country": whois_data.get("country"),
            "registrant_org": whois_data.get("org"),
        },
        "dns": dns_result,
        "address": {
            "ip": (ip_report or {}).get("ip"),
            "reverse_dns": ((ip_report or {}).get("reverse_dns") or {}).get("names"),
            "geo": ((ip_report or {}).get("geo") or {}).get("geo"),
            "blacklisted_on": ((ip_report or {}).get("blacklist") or {}).get("listed"),
        },
        "http": http_result,
        "tls": tls_result,
        "body": body_fingerprint(body_text),
        "gaps": [],
    }

    # An absent contact is the single thing that stops a notice being sent, so
    # it is stated rather than left as an empty field to be noticed later.
    if not registrar_abuse:
        dossier["gaps"].append(
            "No registrar abuse address in WHOIS. Look it up in ICANN's registrar "
            "directory by IANA ID, or use the registrar's published abuse form."
        )
    if not network_abuse:
        dossier["gaps"].append(
            "No abuse contact in the registry record for this address. The RIR's "
            "own abuse-c may still exist at the parent range."
        )
    if not protected_domain:
        dossier["gaps"].append(
            "No protected domain given, so no similarity assessment was made."
        )
    return dossier
