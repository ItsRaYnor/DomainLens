"""States for the security-overview tiles that need more than one field.

The tiles were decided in the browser from a single field each, and three of
them turned red for things that were not the scanned domain's defect:

* Weak auth showed "Fail" for a scan that never ran it: the missing result
  compared as "not false", which the tile read as a failure.
* Blacklist showed "Fail" for a shared CDN edge address -- an IP hundreds of
  other sites use, that sends none of this domain's mail -- and counted the
  one Spamhaus XBL listing twice, once through CBL and once through ZEN.
* IPv6 Mail showed "Fail" because the mail provider's MX hosts have no AAAA
  record, which the domain owner cannot change short of changing provider.

Each tile gets one of: "pass", "fail", "context" (measured and true, but not
a defect of this domain), "not_tested", or None when there is nothing to
show. The note says why, in words the operator can check.
"""

from __future__ import annotations

# Spamhaus ZEN answers by sub-list. CBL is published as part of the XBL, so
# a CBL hit and a ZEN answer in the XBL range are one listing, not two.
_ZEN_XBL = {"127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"}
# The PBL lists address ranges that should not send mail directly (end-user
# and hosting ranges). It says nothing about the reputation of a web server.
_ZEN_PBL = {"127.0.0.10", "127.0.0.11"}
_CBL = "cbl.abuseat.org"


def _tile(state, note=None):
    return {"state": state, "note": note}


def weak_auth(results):
    data = results.get("weak_auth")
    if not isinstance(data, dict):
        # Not part of this scan. Absent is not a failure of the domain.
        return None
    if data.get("skipped") or data.get("state") == "not_applicable":
        return _tile("not_tested", data.get("detail") or "Weak-auth did not run for this scan.")
    found = data.get("weak_credentials_found")
    if found is True:
        return _tile("fail", "Default or weak credentials were accepted.")
    if found is False:
        return _tile("pass")
    return _tile("not_tested", data.get("error") or "Weak-auth returned no result.")


def distinct_listings(blacklist):
    """Listed zones with the CBL/XBL double count folded into one."""
    listed = list(blacklist.get("listed") or [])
    codes = blacklist.get("codes") or {}
    zen = next((z for z in listed if z.startswith("zen.")), None)
    if _CBL in listed and zen and codes.get(zen) in _ZEN_XBL:
        listed.remove(_CBL)
    return listed


def _only_pbl(blacklist, listed):
    codes = blacklist.get("codes") or {}
    return bool(listed) and all(codes.get(z) in _ZEN_PBL for z in listed)


def blacklist(results):
    data = results.get("blacklist")
    if not isinstance(data, dict) or data.get("error"):
        return None
    if not data.get("is_listed"):
        return _tile("pass") if data.get("ip") else None
    listed = distinct_listings(data)
    names = ", ".join(listed)
    # A listing without the address it was for is still a listing: it is
    # reported, never dropped for want of context.
    address = data.get("ip") or "The address"
    if _only_pbl(data, listed):
        return _tile("context", f"{address} is only on the Spamhaus PBL, a list of ranges that "
                                "should not send mail directly. It is not a reputation listing.")
    cdn = results.get("cdn") or {}
    a_records = ((results.get("dns") or {}).get("A") or [])
    if cdn.get("id") and data.get("ip") and data["ip"] in a_records:
        return _tile("context", f"{address} is a shared {cdn.get('name') or 'CDN'} edge address, "
                                f"listed on {names}. Other sites use it too; it is not this "
                                "domain's mail server, and only the CDN can have it delisted.")
    return _tile("fail", f"{address} is listed on {names}.")


def _mx_hosts(results):
    ipv6 = results.get("ipv6") or {}
    if isinstance(ipv6.get("mx_hosts"), list):
        return ipv6["mx_hosts"]
    hosts = []
    for record in (results.get("dns") or {}).get("MX") or []:
        host = str(record).split()[-1].rstrip(".").lower()
        if host:
            hosts.append(host)
    return hosts


def ipv6_mail(results):
    data = results.get("ipv6")
    if not isinstance(data, dict):
        return None
    if data.get("mail_pass"):
        return _tile("pass")
    hosts = [h for h in _mx_hosts(results) if h]
    if not hosts:
        # No MX, or a null MX: the domain receives no mail to reach over IPv6.
        return None
    apex = str(results.get("apex_domain") or results.get("domain") or "").lower().rstrip(".")
    own = [h for h in hosts if apex and (h == apex or h.endswith("." + apex))]
    if not own:
        providers = sorted({".".join(h.split(".")[-2:]) for h in hosts})
        return _tile("context", f"The MX hosts belong to {', '.join(providers)} and have no IPv6 "
                                "address. That is the mail provider's choice, not this domain's.")
    return _tile("fail", "The domain's own MX hosts have no IPv6 address.")


def tile_states(results):
    """The overview states the browser shows instead of deciding them itself."""
    results = results or {}
    return {
        "weak_auth": weak_auth(results),
        "blacklist": blacklist(results),
        "ipv6_mail": ipv6_mail(results),
    }
