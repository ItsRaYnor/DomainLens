"""Whether a file is known: its SHA-256 asked of MalwareBazaar and VirusTotal.

Only the hash leaves this server, never the file. Uploading an attachment
to a public service publishes it -- an invoice, a contract, a password in a
document -- to everyone with an account there; asking for its hash tells
the service only that someone has a file with that hash. A sandbox report
(Joe Sandbox among them) that VirusTotal or MalwareBazaar holds for that
hash comes with the answer.

MalwareBazaar (abuse.ch, Switzerland) answers with the abuse.ch Auth-Key
already used for ThreatFox and URLhaus; VirusTotal only when it is switched
on for the mail analysis (the same switch and budget as the links).
"""

from __future__ import annotations

import requests

import net_errors

_MB_URL = "https://mb-api.abuse.ch/api/v1/"
_VT_URL = "https://www.virustotal.com/api/v3/files/{}"
MAX_HASHES = 10


def _malwarebazaar(digest, key, post=None):
    import rate_limits
    allowed, reason = rate_limits.acquire("abuse.ch")
    if not allowed:
        return {"state": "unmeasured", "error": reason}
    post = post or (lambda url, data, headers: requests.post(url, data=data, headers=headers, timeout=15))
    try:
        # A query, not a submission: "get_info" only looks the hash up.
        resp = post(_MB_URL, {"query": "get_info", "hash": digest}, {"Auth-Key": key})
        rate_limits.note_response("abuse.ch", resp)
        if resp.status_code in (401, 403):
            return {"state": "unmeasured", "error": "abuse.ch rejected the Auth-Key"}
        resp.raise_for_status()
        body = resp.json()
    except Exception as exc:
        return {"state": "unmeasured", "error": net_errors.describe(exc, "mb-api.abuse.ch")}
    status = body.get("query_status")
    if status in ("hash_not_found", "no_results"):
        return {"state": "unknown"}
    if status != "ok":
        return {"state": "unmeasured", "error": f"MalwareBazaar answered {status}"}
    entry = (body.get("data") or [{}])[0]
    return {"state": "listed", "signature": entry.get("signature"), "tags": (entry.get("tags") or [])[:8],
            "first_seen": entry.get("first_seen")}


def _virustotal(digest, key, get=None):
    import link_check
    import rate_limits
    cached = link_check._vt_cached("file:" + digest)
    if cached:
        return cached
    allowed, reason = rate_limits.acquire("virustotal")
    if not allowed:
        return {"state": "unmeasured", "error": reason}
    get = get or (lambda url, headers: requests.get(url, headers=headers, timeout=15))
    try:
        resp = get(_VT_URL.format(digest), {"x-apikey": key})
    except Exception as exc:
        return {"state": "unmeasured", "error": net_errors.describe(exc, "www.virustotal.com")}
    if resp.status_code == 404:
        result = {"state": "unknown"}
    elif resp.status_code in (401, 403):
        return {"state": "unmeasured", "error": "VirusTotal rejected the API key"}
    elif resp.status_code == 429:
        rate_limits.note_response("virustotal", resp)
        return {"state": "unmeasured", "error": "VirusTotal's rate limit was reached"}
    elif resp.status_code != 200:
        return {"state": "unmeasured", "error": f"HTTP {resp.status_code}"}
    else:
        attrs = (resp.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious, suspicious = int(stats.get("malicious") or 0), int(stats.get("suspicious") or 0)
        result = {"state": "malicious" if malicious else "suspicious" if suspicious else "no_detections",
                  "malicious": malicious, "suspicious": suspicious,
                  "engines": sum(int(v or 0) for v in stats.values()),
                  "label": ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"))}
    link_check._vt_store("file:" + digest, result)
    return result


def check(digests):
    """{sha256: {"malwarebazaar": {...}, "virustotal": {...}}} for up to
    MAX_HASHES hashes, or None when neither service is set up. A service
    not set up says "not_configured"."""
    import link_check
    from settings import api_keys
    mb_key = api_keys.resolve("ABUSECH_AUTH_KEY")
    vt_state = link_check.virustotal_state()
    vt_key = api_keys.resolve("VIRUSTOTAL_API_KEY") if vt_state == "on" else None
    if not mb_key and not vt_key:
        return None  # nothing set up to ask: said as such, not as "not known"
    out = {}
    for n, digest in enumerate(dict.fromkeys(digests)):
        if n >= MAX_HASHES:
            out[digest] = {"malwarebazaar": {"state": "not_checked"}, "virustotal": {"state": "not_checked"}}
            continue
        out[digest] = {
            "malwarebazaar": _malwarebazaar(digest, mb_key) if mb_key else {"state": "not_configured"},
            "virustotal": _virustotal(digest, vt_key) if vt_key else {"state": "not_configured" if vt_state != "on" else "unmeasured"},
        }
    return out
