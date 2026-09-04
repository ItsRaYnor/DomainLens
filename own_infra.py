"""Open relay and open resolver tests, for infrastructure you run yourself.

These two differ from every other check in DomainLens: they ask a mail server
to relay and a nameserver to recurse, which is asking someone's server to do
something on your behalf. Against a stranger's host that is a probe, and
against a badly configured one it is indistinguishable from the abuse the
test is looking for.

So they are gated three ways, and all three must pass:

  1. Off by default. Enabling is a settings change, not a checkbox.
  2. An allowlist. The scanned domain must be named in it. A global switch
     would mean "test my infrastructure" turned into "test everything I
     happen to scan", which is the failure worth designing out.
  3. Never part of a full scan unless the check is asked for by name.

They are also deliberately gentle. One connection, one probe, short timeout,
no retries, and the SMTP test disconnects before DATA -- it never sends a
message, so a server that would have relayed is identified without anything
being relayed.
"""

from __future__ import annotations

import smtplib
import socket

import dns.resolver

# A domain that cannot be ours and cannot be theirs: RFC 2606 reserves
# .invalid for exactly this. Relaying to it proves the server would accept
# mail for a domain it has no business accepting.
_PROBE_RECIPIENT = "relay-test@domainlens-probe.invalid"
_PROBE_SENDER = "relay-test@domainlens-probe.invalid"

# A name that no local zone would serve, so an answer means the server
# resolved it for us rather than reading it from its own data.
_RECURSION_PROBE = "a.root-servers.net"

_TIMEOUT = 8


def is_allowed(domain, config):
    """True when this domain is on the operator's own-infrastructure list.

    Matching includes subdomains of a listed domain: someone who lists
    example.com means their mail and nameservers under it, and making them
    enumerate every host would push people towards listing a bare wildcard.
    """
    if not config or not config.get("enabled"):
        return False
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return False
    for entry in config.get("domains") or []:
        allowed = str(entry).strip().lower().rstrip(".")
        if not allowed:
            continue
        if domain == allowed or domain.endswith("." + allowed):
            return True
    return False


def _blocked(domain, config):
    """The refusal, phrased so the reason is actionable."""
    if not config or not config.get("enabled"):
        return ("These tests are disabled. They ask a server to relay or recurse, "
                "so they are off until an operator turns them on in Settings.")
    return (f"{domain} is not on the own-infrastructure list, so it was not "
            "tested. Add it in Settings only if you run this infrastructure.")


def check_open_relay(domain, config, mx_hosts=None):
    """Ask each mail host whether it would relay for a domain it does not own.

    Stops at RCPT TO. Nothing is ever sent: the answer to "would you relay
    this" is the whole test, and delivering the message to find out would
    make the tool the thing it is checking for.
    """
    result = {"state": "not_applicable", "hosts": [], "open_relay": False,
              "reason": None}
    if not is_allowed(domain, config):
        result["reason"] = _blocked(domain, config)
        return result

    hosts = mx_hosts if mx_hosts is not None else _mx_hosts(domain)
    if not hosts:
        result["reason"] = "No MX records, so there is no mail host to test"
        return result

    result["state"] = "measured"
    for host in hosts[:3]:
        entry = {"host": host, "relays": None, "detail": None}
        try:
            with smtplib.SMTP(host, 25, timeout=_TIMEOUT) as smtp:
                smtp.ehlo_or_helo_if_needed()
                smtp.mail(_PROBE_SENDER)
                code, message = smtp.rcpt(_PROBE_RECIPIENT)
                # 2xx to RCPT for a domain the server has no reason to accept
                # is the definition of an open relay.
                entry["relays"] = 200 <= code < 300
                entry["detail"] = f"RCPT TO returned {code}"
                smtp.quit()  # before DATA, always
        except (smtplib.SMTPException, socket.error, OSError) as exc:
            # Refusing to talk to us is not a failure of the test; it is
            # usually the correct behaviour, and never a finding.
            entry["relays"] = None
            entry["detail"] = f"Could not complete the check: {type(exc).__name__}"
        result["hosts"].append(entry)
        if entry["relays"]:
            result["open_relay"] = True
    return result


def check_open_resolver(domain, config, nameservers=None):
    """Ask each nameserver to resolve a name outside its own zones."""
    result = {"state": "not_applicable", "nameservers": [], "open_resolver": False,
              "reason": None}
    if not is_allowed(domain, config):
        result["reason"] = _blocked(domain, config)
        return result

    servers = nameservers if nameservers is not None else _ns_addresses(domain)
    if not servers:
        result["reason"] = "No nameserver addresses found to test"
        return result

    result["state"] = "measured"
    for address in servers[:3]:
        entry = {"address": address, "recurses": None, "detail": None}
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [address]
            resolver.timeout = _TIMEOUT
            resolver.lifetime = _TIMEOUT
            answer = resolver.resolve(_RECURSION_PROBE, "A")
            # An authoritative-only server answers REFUSED here. Anything
            # that returns records resolved a name it has no authority for.
            entry["recurses"] = bool(answer)
            entry["detail"] = "Answered a recursive query for a name it is not authoritative for"
        except dns.resolver.NoNameservers:
            entry["recurses"] = False
            entry["detail"] = "Refused the recursive query, which is correct"
        except Exception as exc:
            entry["recurses"] = None
            entry["detail"] = f"Could not complete the check: {type(exc).__name__}"
        result["nameservers"].append(entry)
        if entry["recurses"]:
            result["open_resolver"] = True
    return result


def _mx_hosts(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=_TIMEOUT)
    except Exception:
        return []
    hosts = []
    for rdata in answers:
        host = str(rdata.exchange).rstrip(".")
        if host and host != "." and host not in hosts:
            hosts.append(host)
    return hosts


def _ns_addresses(domain):
    addresses = []
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=_TIMEOUT)
    except Exception:
        return addresses
    for rdata in answers:
        host = str(rdata.target).rstrip(".")
        try:
            for a in dns.resolver.resolve(host, "A", lifetime=_TIMEOUT):
                if a.address not in addresses:
                    addresses.append(a.address)
        except Exception:
            continue
    return addresses


def findings(relay, resolver_result, _finding):
    out = []
    if relay and relay.get("open_relay"):
        hosts = [h["host"] for h in relay.get("hosts", []) if h.get("relays")]
        out.append(_finding(
            "critical", "Email",
            "Mail server accepts relay for a foreign domain",
            "A mail host accepted a recipient in a domain it has no reason to "
            "serve. An open relay is used to send spam and phishing in your "
            "name, and gets the address blocklisted quickly.",
            evidence="Relaying: " + ", ".join(hosts),
            fix="Restrict relaying to authenticated users and your own networks. "
                "On Postfix that is smtpd_relay_restrictions; on Exchange, the "
                "receive connector's permission groups.",
        ))
    if resolver_result and resolver_result.get("open_resolver"):
        servers = [n["address"] for n in resolver_result.get("nameservers", [])
                   if n.get("recurses")]
        out.append(_finding(
            "high", "DNS",
            "Nameserver answers recursive queries from anywhere",
            "An authoritative nameserver also resolves names it has no authority "
            "for, for any client that asks. Open resolvers are used to amplify "
            "denial-of-service traffic against third parties.",
            evidence="Recursing: " + ", ".join(servers),
            fix="Separate the authoritative and recursive roles, or restrict "
                "recursion to your own networks (BIND: allow-recursion).",
        ))
    return out
