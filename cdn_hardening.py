"""CDN-specific TLS / security hardening guidance (Bunny, Cloudflare, OVHcloud)."""

from __future__ import annotations

from typing import Any


CDN_BUNNY = "bunny"
CDN_CLOUDFLARE = "cloudflare"
CDN_OVH = "ovh"
CDN_GENERIC = "generic"


def detect_cdn(http_deep: dict | None = None, http_headers: dict | None = None) -> dict[str, Any]:
    """Identify edge CDN from scan results."""
    headers = {}
    for block in (http_headers, http_deep):
        if not block:
            continue
        notable = block.get("notable_headers") or {}
        for k, v in notable.items():
            headers[str(k).lower()] = str(v)
        if block.get("server"):
            headers["server"] = str(block["server"])
        found = block.get("headers_found") or {}
        for k, v in found.items():
            headers[str(k).lower()] = str(v)

    server = (headers.get("server") or "").lower()
    infra = []
    for block in (http_deep,):
        if block:
            infra.extend(block.get("infrastructure") or [])

    names = " ".join(d.get("name", "") for d in infra).lower()
    detail = headers.get("server") or ""

    if "bunnycdn" in server or "cdn-pullzone" in headers or "bunny" in names:
        return {
            "id": CDN_BUNNY,
            "name": "BunnyCDN",
            "confidence": "high",
            "detail": detail or headers.get("cdn-pullzone"),
            "geo_country": headers.get("cdn-requestcountrycode"),
        }
    if "cloudflare" in server or "cf-ray" in headers or "cloudflare" in names:
        return {
            "id": CDN_CLOUDFLARE,
            "name": "Cloudflare",
            "confidence": "high",
            "detail": headers.get("cf-ray") or detail,
            "geo_country": headers.get("cf-ipcountry"),
        }
    if "ovh" in server or "ovhcloud" in names or any(
        "ovh" in (c or "").lower()
        for c in ((http_deep or {}).get("cname_chain") or [])
    ):
        return {
            "id": CDN_OVH,
            "name": "OVHcloud",
            "confidence": "medium",
            "detail": detail,
        }
    return {"id": CDN_GENERIC, "name": None, "confidence": "low", "detail": detail or None}


def advice_for_signature_hashes(*, cdn: dict | None = None) -> dict[str, str]:
    """How to disable SHA-1 (and MD5) signature hashes for TLS 1.2 key exchange."""
    cdn = cdn or {}
    cid = cdn.get("id") or CDN_GENERIC
    common = (
        "NCSC §3.3.5 / internet.nl / RFC 9155: only allow SHA-256/384/512 for the "
        "TLS 1.2 signature algorithms used during key exchange (not the cipher-suite "
        "PRF name). This is configured separately from cipher suites "
        "(OpenSSL: `SignatureAlgorithms` / `SSLSignatureAlgorithms`)."
    )
    if cid == CDN_BUNNY:
        fix = (
            f"{common} On **BunnyCDN** (Pull Zone): open the zone → **Security** / **SSL** "
            "and set the strongest TLS profile available (TLS 1.2+ only). If the panel does "
            "not expose SignatureAlgorithms, open a Bunny support ticket asking to disable "
            "SHA-1 (and SHA-224) signature algorithms on the edge for your pull zone — "
            "internet.nl fails when the edge still accepts `ECDSA+SHA1` / `RSA+SHA1`. "
            "Also remove legacy CBC-SHA1 cipher suites and enforce AEAD-first cipher order "
            "in the same SSL settings. Origin: if SSL mode is Full/Strict to your origin, "
            "harden origin OpenSSL too: "
            "`SSLSignatureAlgorithms SHA256+ECDSA:SHA384+ECDSA:SHA256+RSA:RSA-PSS+SHA256` "
            "(Apache) / nginx+OpenSSL 3 `ssl_conf_command SignatureAlgorithms …`."
        )
    elif cid == CDN_CLOUDFLARE:
        fix = (
            f"{common} On **Cloudflare**: SSL/TLS → **Edge Certificates** → Minimum TLS Version "
            "**1.2** (prefer 1.3). Under **Cipher suites** (Business/Enterprise or cipher "
            "customization), use a modern Mozilla Intermediate set without CBC-SHA1. "
            "Legacy signature algorithms are controlled by Cloudflare’s edge — if internet.nl "
            "still reports SHA-1 for key-exchange hashes, contact Cloudflare support / use "
            "Advanced Certificate Manager custom cipher+sigalg profiles where available. "
            "Also set origin SSL to Full (strict) and harden origin SignatureAlgorithms as above."
        )
    elif cid == CDN_OVH:
        fix = (
            f"{common} On **OVHcloud**: for **SSL Gateway / Load Balancer**, pick a modern SSL "
            "profile (TLS 1.2+ / Mozilla Intermediate). For a VPS/origin behind CDN, set "
            "Apache `SSLSignatureAlgorithms` / Nginx OpenSSL `SignatureAlgorithms` to "
            "SHA-256/384/512 only and reload. Confirm both the CDN VIP and origin IPs "
            "(IPv4+IPv6) — internet.nl lists each address that still offers SHA-1."
        )
    else:
        fix = (
            f"{common} OpenSSL 3 example: "
            "`SSLSignatureAlgorithms ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:"
            "rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384`. "
            "Nginx: `ssl_conf_command SignatureAlgorithms …;` Apache: `SSLSignatureAlgorithms …`. "
            "If a CDN terminates TLS, change the CDN SSL profile (Bunny / Cloudflare / OVH) — "
            "origin-only changes will not fix internet.nl edge findings."
        )
    retest = (
        "Re-run DomainLens SSL/TLS + NCSC TLS and confirm no `signature-hash-insufficient` finding. "
        "Cross-check internet.nl → HTTPS → “Hashfuncties voor sleuteluitwisseling”. "
        "Verify both A and AAAA addresses. From outside NL/DE/BE, TLS still works when Bunny "
        "geo-blocks HTTP."
    )
    return {"fix": fix, "retest": retest, "reference": "https://www.rfc-editor.org/rfc/rfc9155"}


def advice_for_cipher_order(*, cdn: dict | None = None) -> str:
    cdn = cdn or {}
    cid = cdn.get("id") or CDN_GENERIC
    base = (
        "Enforce server cipher preference with AEAD (AES-GCM / AES-CCM / ChaCha20) "
        "before CBC phase-out suites; remove CBC-SHA1."
    )
    if cid == CDN_BUNNY:
        return (
            f"{base} BunnyCDN: Pull Zone → SSL → custom cipher list / modern preset; "
            "ensure server order prefers ECDHE-*GCM/CCM over *SHA384 CBC."
        )
    if cid == CDN_CLOUDFLARE:
        return (
            f"{base} Cloudflare: SSL/TLS → Edge Certificates → Cipher suites → "
            "modern/custom list with GCM/ChaCha first (requires eligible plan)."
        )
    if cid == CDN_OVH:
        return (
            f"{base} OVH SSL Gateway: select Intermediate/Modern profile; "
            "on Nginx origin: `ssl_prefer_server_ciphers on;` + ordered `ssl_ciphers`."
        )
    return base + " Nginx: `ssl_prefer_server_ciphers on;` Apache: `SSLHonorCipherOrder on`."


def advice_for_headers_csp(*, cdn: dict | None = None) -> str:
    cdn = cdn or {}
    cid = cdn.get("id") or CDN_GENERIC
    csp = (
        "Send security headers on **all** HTTPS responses (including CDN error/geo-block pages). "
        "Build CSP: Report-Only → `default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'` → add hosts → nonces → enforce."
    )
    if cid == CDN_BUNNY:
        return (
            f"{csp} BunnyCDN: Pull Zone → **Edge Rules / Headers** (or Bunny Optimizer/Worker) "
            "to inject `Strict-Transport-Security`, `Content-Security-Policy`, "
            "`X-Content-Type-Options`, `Referrer-Policy`. Geo-allow NL/DE/BE if needed, "
            "but still attach HSTS/CSP on 403 block pages so scanners and users get consistent headers."
        )
    if cid == CDN_CLOUDFLARE:
        return (
            f"{csp} Cloudflare: **Transform Rules → Managed Transforms / Response Header "
            "Transform** (or Workers) to set HSTS + CSP. Use SSL/TLS → Edge Certificates → "
            "Always Use HTTPS + HSTS. Configuration Rules can scope headers per hostname."
        )
    if cid == CDN_OVH:
        return (
            f"{csp} OVH: configure headers on the **SSL Gateway** or origin vhost; "
            "for CDN caching, ensure HTML responses from origin include CSP/HSTS or add "
            "them at the load-balancer layer."
        )
    return csp


def optimizations_summary(cdn: dict, tls_deep: dict | None = None, http_headers: dict | None = None) -> list[dict]:
    """Structured optimization checklist for Advies / reports."""
    items = []
    sig = (tls_deep or {}).get("signature_hashes") or {}
    if sig.get("insufficient"):
        adv = advice_for_signature_hashes(cdn=cdn)
        items.append({
            "id": "cdn-sig-hash",
            "title": "Disable SHA-1 signature hashes for TLS key exchange",
            "fix": adv["fix"],
            "retest": adv["retest"],
        })
    order = (tls_deep or {}).get("cipher_order") or {}
    if order.get("applicable") and order.get("pass") is False:
        items.append({
            "id": "cdn-cipher-order",
            "title": "Fix TLS cipher suite order (AEAD first)",
            "fix": advice_for_cipher_order(cdn=cdn),
        })
    if (http_headers or {}).get("blocked") or ((tls_deep or {}).get("hsts") or {}).get("blocked"):
        items.append({
            "id": "cdn-geo-headers",
            "title": "CDN geo-block: verify headers from NL/DE/BE",
            "fix": advice_for_headers_csp(cdn=cdn)
            + " Re-test HSTS/CSP from an allowed country or internet.nl.",
        })
    missing = (http_headers or {}).get("headers_missing") or []
    if "Content-Security-Policy" in missing or ((http_headers or {}).get("csp") or {}).get("grade") in {
        "missing", "weak", "fair"
    }:
        items.append({
            "id": "cdn-csp",
            "title": "Deploy / tighten Content-Security-Policy at the CDN edge",
            "fix": advice_for_headers_csp(cdn=cdn),
        })
    return items
