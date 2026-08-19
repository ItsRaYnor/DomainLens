"""Live "does this key actually work" checks for the admin settings UI.

Saving a key only proves it was typed and stored correctly — it says nothing
about whether the value itself is valid, expired, or scoped correctly at the
provider. This module makes one small, read-only, non-mutating call per
integration against the CURRENTLY EFFECTIVE credential (environment first,
then the encrypted store — same resolution order as the real checks use), and
reports back a plain ok/detail pair. Nothing here is destructive: no
incidents are filed, no assets are modified, no scans are triggered.

Each test function takes no arguments (it resolves credentials itself, the
same way the real integration does) and returns {"ok": bool, "detail": str}.
"""

from __future__ import annotations

import logging

import dns.resolver
import requests

log = logging.getLogger("domainlens.connection_tests")

_TIMEOUT = 10


def _result(ok, detail):
    return {"ok": bool(ok), "detail": detail}


# ---------------------------------------------------------------------------
# OSINT keys
# ---------------------------------------------------------------------------

def test_spamhaus_dqs():
    from settings import api_keys
    key = api_keys.resolve("SPAMHAUS_DQS_KEY")
    if not key:
        return _result(False, "No key configured yet.")

    # 127.0.0.2 is Spamhaus's permanent DNSBL test entry — it is guaranteed
    # to always be listed, so querying it end-to-end exercises the exact
    # DQS zone construction check_blacklist() uses, without touching a real
    # domain's reputation data.
    query = f"2.0.0.127.{key}.zen.dq.spamhaus.net"
    try:
        answers = dns.resolver.resolve(query, "A", lifetime=_TIMEOUT)
        for rdata in answers:
            text = rdata.to_text()
            parts = text.split(".")
            if len(parts) == 4 and parts[0] == "127":
                if parts[1] == "255":
                    # Spamhaus's documented signal for an auth/quota problem,
                    # not a real listing — see _dnsbl_is_real_hit in app.py.
                    return _result(False, f"Spamhaus returned an error code ({text}) — the key is likely invalid, disabled, or over quota, not a real DNSBL result.")
                return _result(True, f"Test entry (127.0.0.2) correctly reported as listed ({text}) — the key works.")
        return _result(False, "Unexpected response with no usable A record.")
    except dns.resolver.NXDOMAIN:
        return _result(False, "NXDOMAIN — the key is not recognised by Spamhaus (check for typos or an unactivated trial).")
    except dns.resolver.NoNameservers:
        return _result(False, "SERVFAIL — Spamhaus rejected the query, which usually means an invalid or blocked key.")
    except Exception as exc:
        return _result(False, f"DNS query failed: {exc}")


def test_abusech():
    from settings import api_keys
    key = api_keys.resolve("ABUSECH_AUTH_KEY")
    if not key:
        return _result(False, "No key configured yet.")
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": key},
            json={"query": "get_iocs", "days": 1},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 401:
            return _result(False, "401 Unauthorized — the Auth-Key was rejected by abuse.ch.")
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")
        if status in ("ok", "no_result"):
            return _result(True, "Authenticated successfully against the ThreatFox API (also covers URLhaus, which shares the same key).")
        return _result(False, f"Unexpected response: query_status={status!r}")
    except Exception as exc:
        return _result(False, f"Request failed: {exc}")


def test_otx():
    from settings import api_keys
    key = api_keys.resolve("OTX_API_KEY")
    if not key:
        return _result(False, "No key configured yet.")
    try:
        # /user/me requires a valid key (unlike the domain/general lookup
        # endpoint, which returns public data even without one) — an
        # authenticated-only endpoint is the honest way to test this.
        resp = requests.get(
            "https://otx.alienvault.com/api/v1/user/me",
            headers={"X-OTX-API-KEY": key},
            timeout=_TIMEOUT,
        )
        if resp.status_code in (401, 403):
            return _result(False, f"{resp.status_code} — the key was rejected by AlienVault OTX.")
        resp.raise_for_status()
        data = resp.json()
        who = data.get("username") or "account"
        return _result(True, f"Authenticated successfully as {who}.")
    except Exception as exc:
        return _result(False, f"Request failed: {exc}")


# ---------------------------------------------------------------------------
# Integration credential groups
# ---------------------------------------------------------------------------

def test_servicenow():
    import servicenow
    cfg = servicenow.config()
    missing = [n for n, v in (("instance", cfg["instance"]), ("user", cfg["user"]), ("password", cfg["password"])) if not v]
    if missing:
        return _result(False, f"Missing: {', '.join(missing)}.")
    try:
        resp = requests.get(
            f"{cfg['instance']}/api/now/table/sys_user",
            auth=(cfg["user"], cfg["password"]),
            headers={"Accept": "application/json"},
            params={"sysparm_limit": 1, "sysparm_fields": "sys_id"},
            timeout=_TIMEOUT + 5,
        )
        if resp.status_code == 401:
            return _result(False, "401 Unauthorized — check the ServiceNow user/password.")
        if resp.status_code == 403:
            return _result(False, "403 Forbidden — credentials are valid but lack Table API read access.")
        resp.raise_for_status()
        return _result(True, "Authenticated successfully against the ServiceNow Table API.")
    except Exception as exc:
        return _result(False, f"Request failed: {exc}")


def test_rapid7():
    import insightvm
    cfg = insightvm.config()
    if cfg["console_configured"]:
        try:
            resp = requests.get(
                f"{cfg['api_base_url']}/api/3/asset_groups",
                auth=(cfg["username"], cfg["password"]),
                headers={"Accept": "application/json"},
                params={"page": 0, "size": 1},
                verify=cfg["verify_ssl"],
                timeout=_TIMEOUT + 5,
            )
            if resp.status_code == 401:
                return _result(False, "401 Unauthorized — check the Console API username/password.")
            resp.raise_for_status()
            return _result(True, "Authenticated successfully against the InsightVM Console API (v3).")
        except Exception as exc:
            return _result(False, f"Console API request failed: {exc}")
    if cfg["cloud_configured"]:
        try:
            resp = requests.get(
                f"{cfg['cloud_api_base_url']}/vm/v4/integration/assets",
                headers={"Accept": "application/json", "X-Api-Key": cfg["api_key"]},
                params={"size": 1},
                timeout=_TIMEOUT + 5,
            )
            if resp.status_code in (401, 403):
                return _result(False, f"{resp.status_code} — the Insight Platform API key was rejected.")
            resp.raise_for_status()
            return _result(True, "Authenticated successfully against the Insight Platform Cloud API (v4).")
        except Exception as exc:
            return _result(False, f"Cloud API request failed: {exc}")
    return _result(False, "Neither Console API (username+password+base URL) nor a Cloud API key is fully configured.")


# Single-value keys, tested individually from their own row.
KEY_TESTS = {
    "SPAMHAUS_DQS_KEY": test_spamhaus_dqs,
    "ABUSECH_AUTH_KEY": test_abusech,
    "OTX_API_KEY": test_otx,
}

# Grouped credentials that only make sense to test together (a lone
# username or password can't authenticate by itself), tested from a button
# on the group heading rather than per field. OAuth/Entra and SCIM are
# deliberately absent: verifying a client secret means performing an actual
# OAuth grant, which is provider-specific (Google/GitHub/generic OIDC don't
# all support client_credentials the way Azure AD does) — a correct
# implementation is a bigger scope than one test button covers honestly.
GROUP_TESTS = {
    "ServiceNow": test_servicenow,
    "Rapid7": test_rapid7,
}


def run_test(target):
    """Run a named test and return {"ok": bool, "detail": str}.

    Never raises — any unexpected error becomes a failed result instead of a
    500, since this endpoint exists specifically to surface failures safely.
    """
    fn = KEY_TESTS.get(target) or GROUP_TESTS.get(target)
    if fn is None:
        return _result(False, "No connection test is available for this integration.")
    try:
        return fn()
    except Exception as exc:
        log.exception("Connection test %s crashed", target)
        return _result(False, f"Test crashed: {exc}")
