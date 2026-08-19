"""
NCSC-NL TLS Security Guidelines 2025-05 compliance assessment.

Assesses TLS configurations against the Netherlands NCSC publication
"Security guidelines for Transport Layer Security" version 2025-05.

Security levels (worst wins for a cipher suite):
  good → sufficient → phased_out → insufficient

Reference:
  https://www.ncsc.nl/en/transport-layer-security-tls/tls-security-guidelines
"""

from __future__ import annotations

import re
from typing import Optional

GUIDELINE = "NCSC TLS Security Guidelines 2025-05"
GUIDELINE_URL = (
    "https://www.ncsc.nl/en/transport-layer-security-tls/tls-security-guidelines"
)
GUIDELINE_PDF = (
    "https://www.ncsc.nl/binaries/ncsc/documenten/publicaties/2025/juni/01/"
    "ict-beveiligingsrichtlijnen-voor-transport-layer-security-2025-05/"
    "Publication_TLS-Security+guidelines-2025-05_ENG.pdf"
)

LEVEL_GOOD = "good"
LEVEL_SUFFICIENT = "sufficient"
LEVEL_PHASED_OUT = "phased_out"
LEVEL_INSUFFICIENT = "insufficient"

_LEVEL_RANK = {
    LEVEL_GOOD: 0,
    LEVEL_SUFFICIENT: 1,
    LEVEL_PHASED_OUT: 2,
    LEVEL_INSUFFICIENT: 3,
    "unknown": 2,
}

_LEVEL_LABEL = {
    LEVEL_GOOD: "Good",
    LEVEL_SUFFICIENT: "Sufficient",
    LEVEL_PHASED_OUT: "To be phased out",
    LEVEL_INSUFFICIENT: "Insufficient",
    "unknown": "Unknown",
}


def _worst(*levels: str) -> str:
    ranked = [(_LEVEL_RANK.get(level, 2), level) for level in levels if level]
    if not ranked:
        return "unknown"
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1]


def _normalize_cipher_name(name: str) -> str:
    raw = (name or "").strip()
    if not raw:
        return ""
    # IANA style TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 → OpenSSL-ish tokens
    upper = raw.upper().replace(" ", "")
    upper = upper.replace("TLS_", "")
    upper = upper.replace("_WITH_", "-")
    upper = upper.replace("_", "-")
    return upper


def _classify_protocol(name: str, supported: bool) -> dict:
    mapping = {
        "TLS 1.3": LEVEL_GOOD,
        "TLS 1.2": LEVEL_SUFFICIENT,
        "TLS 1.1": LEVEL_INSUFFICIENT,
        "TLS 1.0": LEVEL_INSUFFICIENT,
        "SSL 3.0": LEVEL_INSUFFICIENT,
        "SSL 2.0": LEVEL_INSUFFICIENT,
        "SSL 1.0": LEVEL_INSUFFICIENT,
    }
    level = mapping.get(name, LEVEL_INSUFFICIENT if supported else LEVEL_GOOD)
    return {
        "name": name,
        "supported": bool(supported),
        "level": level if supported else None,
        "label": _LEVEL_LABEL.get(level) if supported else "Disabled",
    }


def _classify_key_exchange(tokens: str) -> tuple[str, str]:
    t = tokens.upper()
    if "X25519MLKEM" in t or "SECP256R1MLKEM" in t or "SECP384R1MLKEM" in t:
        return LEVEL_GOOD, "hybrid-pq"
    if "ECDHE" in t or "EECDH" in t:
        return LEVEL_SUFFICIENT, "ECDHE"
    if re.search(r"(?<![E])DHE(?!E)", t) or t.startswith("EDH") or "-EDH-" in t:
        return LEVEL_PHASED_OUT, "DHE"
    if "ECDH" in t and "ECDHE" not in t:
        return LEVEL_INSUFFICIENT, "ECDH"
    if re.search(r"(?<![EC])DH(?!E)", t):
        return LEVEL_INSUFFICIENT, "DH"
    if "PSK" in t or "SRP" in t or "KRB5" in t or "NULL" in t:
        return LEVEL_INSUFFICIENT, "legacy"

    # TLS 1.3 suites: name is only bulk+hash (AES-*-GCM / CHACHA20...). Ephemeral KX is inherent.
    tls13_bulk = bool(
        re.match(r"^(AES-?\d+-GCM|AES-?\d+-CCM|CHACHA20)", t)
        or t.startswith("AES-256-GCM")
        or t.startswith("AES-128-GCM")
        or t.startswith("AES-256-CCM")
        or t.startswith("AES-128-CCM")
        or t.startswith("CHACHA20")
    )
    if tls13_bulk and "ECDHE" not in t and "DHE" not in t and "RSA" not in t:
        return LEVEL_GOOD, "TLS1.3-ephemeral"

    # OpenSSL static-RSA suites start with the bulk cipher (e.g. AES256-SHA, RC4-MD5).
    if re.match(r"^(AES|CAMELLIA|ARIA|DES|3DES|RC4|IDEA|SEED|NULL)", t) and "ECDHE" not in t and "DHE" not in t:
        return LEVEL_INSUFFICIENT, "RSA"

    if "RSA" in t and "ECDHE" not in t and "DHE" not in t:
        return LEVEL_INSUFFICIENT, "RSA"

    return LEVEL_SUFFICIENT, "unknown"


def _classify_auth(tokens: str) -> tuple[str, str]:
    t = tokens.upper()
    if "ANON" in t or "NULL" in t:
        return LEVEL_INSUFFICIENT, "anon/null"
    if "EXPORT" in t:
        return LEVEL_INSUFFICIENT, "EXPORT"
    if "PSK" in t or "KRB5" in t:
        return LEVEL_INSUFFICIENT, "PSK/KRB5"
    # Check ECDSA/EdDSA before DSS/DSA — "DSA" is a substring of "ECDSA".
    if "ECDSA" in t or "EDDSA" in t or "ED25519" in t or "ED448" in t:
        return LEVEL_SUFFICIENT, "ECDSA/EdDSA"
    if re.search(r"(?<![A-Z])DSS(?![A-Z])", t) or re.search(r"(?<![CE])DSA(?![A-Z])", t):
        return LEVEL_INSUFFICIENT, "DSS"
    if "RSA" in t:
        return LEVEL_SUFFICIENT, "RSA"
    # TLS 1.3 cipher names omit auth; do not cap Good AEAD suites.
    if re.match(r"^(AES-?\d+-GCM|AES-?\d+-CCM|CHACHA20)", t) or (
        ("GCM" in t or "CCM" in t or "CHACHA" in t)
        and "ECDHE" not in t
        and "DHE" not in t
        and "RSA" not in t
    ):
        return LEVEL_GOOD, "certificate"
    # OpenSSL static-RSA suites omit the auth token in the name.
    if re.match(r"^(AES|CAMELLIA|ARIA|DES|3DES|RC4|IDEA|SEED)", t):
        return LEVEL_SUFFICIENT, "RSA"
    return LEVEL_SUFFICIENT, "unknown"


def _classify_bulk(tokens: str) -> tuple[str, str]:
    t = tokens.upper()
    if "NULL" in t or "RC4" in t or "IDEA" in t or re.search(r"(?<![A-Z])SEED(?![A-Z])", t):
        return LEVEL_INSUFFICIENT, "legacy-bulk"
    # Do not match the "DES" substring inside "ECDSA".
    if "3DES" in t or "DES-CBC3" in t or re.search(r"(?<![A-Z0-9])DES(?![A-Z0-9])", t):
        return LEVEL_INSUFFICIENT, "3DES/DES"
    if "CCM-8" in t or "CCM_8" in t or "CCM8" in t:
        return LEVEL_INSUFFICIENT, "AES-CCM_8"
    if "CHACHA20" in t:
        return LEVEL_GOOD, "ChaCha20-Poly1305"
    if "AES-256-GCM" in t or "AES256-GCM" in t:
        return LEVEL_GOOD, "AES-256-GCM"
    if "AES-128-GCM" in t or "AES128-GCM" in t:
        return LEVEL_SUFFICIENT, "AES-128-GCM"
    if "AES-256-CCM" in t or "AES256-CCM" in t:
        return LEVEL_SUFFICIENT, "AES-256-CCM"
    if "AES-128-CCM" in t or "AES128-CCM" in t:
        return LEVEL_SUFFICIENT, "AES-128-CCM"
    # CBC-mode AES (incl. OpenSSL ...-AES256-SHA / ...-AES256-SHA384)
    if "AES-256-CBC" in t or re.search(r"AES256-(SHA|SHA384)\b", t) or (
        "AES256" in t and "GCM" not in t and "CCM" not in t
    ):
        return LEVEL_PHASED_OUT, "AES-256-CBC"
    if "AES-128-CBC" in t or re.search(r"AES128-(SHA|SHA256)\b", t) or (
        "AES128" in t and "GCM" not in t and "CCM" not in t
    ):
        return LEVEL_PHASED_OUT, "AES-128-CBC"
    if "CAMELLIA" in t or "ARIA" in t:
        return LEVEL_PHASED_OUT, "CAMELLIA/ARIA"
    if "AES" in t and "GCM" in t:
        return LEVEL_SUFFICIENT, "AES-GCM"
    if "AES" in t:
        return LEVEL_PHASED_OUT, "AES-CBC"
    return "unknown", "unknown"


def _classify_hash(tokens: str) -> tuple[str, str]:
    t = tokens.upper()
    if "MD5" in t:
        return LEVEL_INSUFFICIENT, "MD5"
    if "SHA1" in t or t.endswith("-SHA") or "-SHA-" in t:
        # OpenSSL: ...-SHA means SHA-1
        if "SHA256" in t or "SHA384" in t or "SHA512" in t or "SHA224" in t:
            pass
        else:
            return LEVEL_INSUFFICIENT, "SHA-1"
    if "SHA512" in t:
        return LEVEL_GOOD, "SHA-512"
    if "SHA384" in t:
        return LEVEL_GOOD, "SHA-384"
    if "SHA256" in t:
        return LEVEL_GOOD, "SHA-256"
    if "SHA224" in t:
        return LEVEL_PHASED_OUT, "SHA-224"
    # AEAD TLS 1.3 suites embed hash in name already handled; default good for AEAD
    if "GCM" in t or "CHACHA" in t or "CCM" in t:
        return LEVEL_GOOD, "AEAD"
    return LEVEL_SUFFICIENT, "unknown"


def classify_cipher_suite(name: str) -> dict:
    """Classify one cipher suite name against NCSC 2025-05 tables."""
    normalized = _normalize_cipher_name(name)
    kx_level, kx = _classify_key_exchange(normalized)
    auth_level, auth = _classify_auth(normalized)
    bulk_level, bulk = _classify_bulk(normalized)
    hash_level, hsh = _classify_hash(normalized)
    level = _worst(kx_level, auth_level, bulk_level, hash_level)
    return {
        "name": name,
        "normalized": normalized,
        "level": level,
        "label": _LEVEL_LABEL.get(level, level),
        "components": {
            "key_exchange": {"name": kx, "level": kx_level},
            "authentication": {"name": auth, "level": auth_level},
            "bulk_encryption": {"name": bulk, "level": bulk_level},
            "hash": {"name": hsh, "level": hash_level},
        },
    }


def _finding(fid, severity, title, detail, level=None, fix=None, retest=None):
    item = {
        "id": fid,
        "severity": severity,
        "title": title,
        "problem": detail,
        "fix": fix or "",
        "reference": GUIDELINE_URL,
    }
    if level:
        item["ncsc_level"] = level
    if retest:
        item["retest"] = retest
    return item


def _severity_for_level(level: str) -> str:
    return {
        LEVEL_INSUFFICIENT: "critical",
        LEVEL_PHASED_OUT: "medium",
        LEVEL_SUFFICIENT: "low",
        LEVEL_GOOD: "info",
    }.get(level, "medium")


def assess_certificate_key(cert: Optional[dict], bits: Optional[int] = None) -> dict:
    """Assess RSA/ECDSA key parameters when available (Table 3 / Table 4)."""
    result = {
        "evaluated": False,
        "level": None,
        "label": None,
        "bits": bits,
        "detail": None,
    }
    if bits is None and isinstance(cert, dict):
        bits = cert.get("key_bits") or cert.get("bits")
    if bits is None:
        result["detail"] = "Certificate key length not available from scan."
        return result

    result["evaluated"] = True
    result["bits"] = bits
    key_type = (cert or {}).get("key_type") or (cert or {}).get("pubkey_type") or "RSA"
    key_type = str(key_type).upper()

    if "EC" in key_type or "ECDSA" in key_type:
        if bits >= 256:
            level = LEVEL_SUFFICIENT
        elif bits >= 224:
            level = LEVEL_PHASED_OUT
        else:
            level = LEVEL_INSUFFICIENT
        result["level"] = level
        result["label"] = _LEVEL_LABEL[level]
        result["detail"] = f"ECDSA/EC key size {bits} bit"
        return result

    # RSA modulus (Table 4)
    if bits >= 3072:
        level = LEVEL_SUFFICIENT
    elif bits >= 2048:
        level = LEVEL_PHASED_OUT
    else:
        level = LEVEL_INSUFFICIENT
    result["level"] = level
    result["label"] = _LEVEL_LABEL[level]
    result["detail"] = f"RSA modulus {bits} bit"
    return result


def assess(tls_deep: Optional[dict] = None, *, cert_key_bits: Optional[int] = None) -> dict:
    """
    Build an NCSC 2025-05 assessment from a tls_deep scan result.

    Returns a structured report with overall level, per-protocol / per-cipher
    ratings, and actionable findings.
    """
    if not tls_deep or not tls_deep.get("success"):
        return {
            "success": False,
            "guideline": GUIDELINE,
            "guideline_url": GUIDELINE_URL,
            "error": (tls_deep or {}).get("error") or "TLS deep scan required for NCSC assessment",
        }

    findings = []
    protocol_rows = []
    overall_parts = []

    for proto in tls_deep.get("protocols") or []:
        row = _classify_protocol(proto.get("name") or "", proto.get("supported"))
        protocol_rows.append(row)
        if row["supported"] and row["level"]:
            overall_parts.append(row["level"])
            if row["level"] == LEVEL_INSUFFICIENT:
                findings.append(_finding(
                    f"proto-{row['name'].lower().replace(' ', '-')}",
                    "critical",
                    f"{row['name']} is insufficient (NCSC 2025-05)",
                    f"{row['name']} is classified as Insufficient. Disable it and require TLS 1.2 minimum, preferably TLS 1.3.",
                    LEVEL_INSUFFICIENT,
                    "Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`.",
                ))

    proto_map = {p["name"]: p.get("supported") for p in protocol_rows}
    if not proto_map.get("TLS 1.3"):
        findings.append(_finding(
            "proto-missing-tls13",
            "medium",
            "TLS 1.3 not offered (NCSC prefers Good)",
            "NCSC rates TLS 1.3 as Good and recommends preferring it for future quantum-safe migration.",
            LEVEL_SUFFICIENT,
            "Enable TLS 1.3 alongside TLS 1.2 in the server TLS stack.",
        ))
        overall_parts.append(LEVEL_SUFFICIENT)
    else:
        overall_parts.append(LEVEL_GOOD)

    if not proto_map.get("TLS 1.2") and not proto_map.get("TLS 1.3"):
        findings.append(_finding(
            "proto-no-modern",
            "critical",
            "No modern TLS versions offered",
            "Neither TLS 1.2 nor TLS 1.3 is available. The configuration is Insufficient.",
            LEVEL_INSUFFICIENT,
        ))
        overall_parts.append(LEVEL_INSUFFICIENT)

    cipher_rows = []
    level_counts = {
        LEVEL_GOOD: 0,
        LEVEL_SUFFICIENT: 0,
        LEVEL_PHASED_OUT: 0,
        LEVEL_INSUFFICIENT: 0,
        "unknown": 0,
    }
    for cipher in tls_deep.get("ciphers") or []:
        classified = classify_cipher_suite(cipher.get("name") or "")
        classified["protocol"] = cipher.get("protocol")
        classified["bits"] = cipher.get("bits")
        cipher_rows.append(classified)
        level_counts[classified["level"]] = level_counts.get(classified["level"], 0) + 1
        overall_parts.append(classified["level"])

    if level_counts.get(LEVEL_INSUFFICIENT, 0) > 0:
        findings.append(_finding(
            "cipher-insufficient",
            "critical",
            f"{level_counts[LEVEL_INSUFFICIENT]} insufficient cipher suite(s)",
            "One or more accepted cipher suites use algorithms rated Insufficient "
            "(e.g. static RSA key exchange, 3DES, RC4, SHA-1, NULL, DSS, CCM-8).",
            LEVEL_INSUFFICIENT,
            "Restrict the cipher list to AEAD suites with ECDHE (and TLS 1.3 suites). "
            "Remove CBC-SHA1 and CCM-8. See NCSC Appendix B / Mozilla Intermediate SSL config.",
            retest=(
                "Re-run DomainLens NCSC TLS and confirm zero Insufficient cipher suites. "
                "Cross-check internet.nl → HTTPS → cipher suites (should no longer list "
                "Insufficient algorithms)."
            ),
        ))
    if level_counts.get(LEVEL_PHASED_OUT, 0) > 0:
        findings.append(_finding(
            "cipher-phased-out",
            "medium",
            f"{level_counts[LEVEL_PHASED_OUT]} cipher suite(s) to be phased out",
            "CBC-mode AES/CAMELLIA/ARIA and/or DHE suites are still accepted. "
            "NCSC 2025-05 marks these as To be phased out.",
            LEVEL_PHASED_OUT,
            "Prefer AES-GCM / ChaCha20-Poly1305 and ECDHE. Remove or schedule removal of "
            "CBC-SHA256/SHA384 suites. Keep `ssl_prefer_server_ciphers on` with AEAD first.",
            retest=(
                "Re-run DomainLens NCSC TLS and confirm phased-out cipher count is 0 (or accepted "
                "as an explicit temporary exception). Cross-check internet.nl HTTPS results."
            ),
        ))

    compression = bool(tls_deep.get("tls_compression"))
    if compression:
        overall_parts.append(LEVEL_INSUFFICIENT)
        findings.append(_finding(
            "tls-compression",
            "critical",
            "TLS compression enabled (Insufficient)",
            "TLS compression is Insufficient per NCSC Table 10 and enables CRIME-class attacks.",
            LEVEL_INSUFFICIENT,
            "Disable TLS compression. TLS 1.3 does not support compression.",
        ))
    else:
        overall_parts.append(LEVEL_GOOD)

    cert = tls_deep.get("certificate") or {}
    cert_assessment = assess_certificate_key(cert, bits=cert_key_bits or cert.get("key_bits"))
    if cert_assessment.get("level"):
        overall_parts.append(cert_assessment["level"])
        if cert_assessment["level"] == LEVEL_INSUFFICIENT:
            findings.append(_finding(
                "cert-key-insufficient",
                "critical",
                "Certificate key parameters are Insufficient",
                cert_assessment.get("detail") or "Key length below NCSC minimum.",
                LEVEL_INSUFFICIENT,
                "Use RSA ≥ 3072-bit (Sufficient) or at least 2048-bit while phasing out; "
                "prefer ECDSA secp256r1 or stronger.",
            ))
        elif cert_assessment["level"] == LEVEL_PHASED_OUT:
            findings.append(_finding(
                "cert-key-phased-out",
                "medium",
                "Certificate key parameters should be phased out",
                cert_assessment.get("detail") or "Key length is To be phased out.",
                LEVEL_PHASED_OUT,
                "Plan migration to RSA ≥ 3072-bit or ECDSA P-256+.",
            ))

    if cert.get("expired"):
        findings.append(_finding(
            "cert-expired",
            "critical",
            "Certificate expired",
            "An expired certificate breaks authentication trust.",
            LEVEL_INSUFFICIENT,
        ))
        overall_parts.append(LEVEL_INSUFFICIENT)
    if cert.get("self_signed"):
        findings.append(_finding(
            "cert-self-signed",
            "high",
            "Self-signed certificate",
            "Self-signed certificates are not suitable for public TLS authentication.",
            LEVEL_INSUFFICIENT,
        ))
        overall_parts.append(LEVEL_INSUFFICIENT)

    # internet.nl marks OCSP as "not testable" when the certificate has no OCSP
    # URI. Only warn when stapling appears applicable but was not observed.
    cert_has_ocsp_hint = bool(
        cert.get("ocsp_uris") or cert.get("ocsp") or cert.get("has_ocsp_uri")
    )
    if cert_has_ocsp_hint and tls_deep.get("ocsp_stapling") is False:
        findings.append(_finding(
            "ocsp-stapling",
            "low",
            "OCSP stapling not detected",
            "The certificate advertises OCSP, but no stapled response was observed.",
            LEVEL_SUFFICIENT,
            "Enable OCSP stapling on the TLS terminator.",
        ))

    cipher_order = tls_deep.get("cipher_order") or {}
    if cipher_order.get("applicable") and cipher_order.get("pass") is False:
        findings.append(_finding(
            "cipher-order",
            "high",
            "Cipher suite order prefers weaker suites",
            (
                cipher_order.get("detail")
                or "The server does not prefer Good/Sufficient cipher suites over "
                "phase-out/insufficient ones (internet.nl / NCSC cipher order)."
            )
            + (
                f" Server preferred "
                f"`{cipher_order.get('server_preferred_iana') or cipher_order.get('server_preferred')}` "
                f"({cipher_order.get('server_preferred_level')}); "
                f"expected something like "
                f"`{cipher_order.get('expected_preferred_iana') or cipher_order.get('expected_preferred')}` "
                f"({cipher_order.get('expected_preferred_level')})."
                if cipher_order.get("server_preferred")
                else ""
            ),
            LEVEL_PHASED_OUT,
            "Enforce server cipher order and put AEAD suites (AES-GCM / AES-CCM / "
            "ChaCha20-Poly1305) before CBC 'phase out' suites. Also remove or demote "
            "Insufficient suites (CBC-SHA1, CCM-8). Nginx: "
            "`ssl_prefer_server_ciphers on;` with an ordered `ssl_ciphers` list "
            "(Good/Sufficient AEAD first). Apache: `SSLHonorCipherOrder on`. "
            "On BunnyCDN/Cloudflare: set a modern custom cipher suite list and prefer "
            "server order if the control panel exposes it.",
            retest=(
                "Re-run DomainLens SSL/TLS + NCSC TLS and confirm Cipher suite order passes "
                "(no `cipher-order` finding). Cross-check internet.nl → HTTPS → "
                "“Volgorde van cipher suites”. From a blocked region, TLS probes still work; "
                "HTTP/HSTS checks need NL/DE/BE."
            ),
        ))

    # NCSC §3.3.5 / internet.nl: hash functions for TLS 1.2 key-exchange signatures
    # (SignatureAlgorithms — not the cipher-suite PRF suffix).
    sig_hashes = tls_deep.get("signature_hashes") or {}
    if sig_hashes.get("applicable") is not False and sig_hashes.get("evaluated"):
        insuff = sig_hashes.get("insufficient") or []
        phased = sig_hashes.get("phased_out") or []
        if insuff:
            overall_parts.append(LEVEL_INSUFFICIENT)
            addr_bits = []
            for row in sig_hashes.get("by_address") or []:
                if row.get("insufficient"):
                    addr_bits.append(
                        f"{row.get('address')} ({', '.join(row['insufficient'])})"
                    )
            findings.append(_finding(
                "signature-hash-insufficient",
                "critical",
                "Insufficient hash for TLS key-exchange signatures (SHA-1)",
                (
                    sig_hashes.get("detail")
                    or (
                        "The server accepts SHA-1 (or MD5) as a signature hash during "
                        "TLS 1.2 key exchange. NCSC §3.3.5 / RFC 9155 rate this Insufficient."
                    )
                )
                + (f" Addresses: {'; '.join(addr_bits)}." if addr_bits else ""),
                LEVEL_INSUFFICIENT,
                "Restrict SignatureAlgorithms to SHA-256/384/512 only "
                "(OpenSSL `SignatureAlgorithms` / Apache `SSLSignatureAlgorithms`). "
                "This is independent of cipher suites. On BunnyCDN / Cloudflare / OVHcloud, "
                "harden the edge SSL profile or ask the CDN to disable SHA-1 signature algorithms "
                "on both IPv4 and IPv6 VIPs.",
                retest=(
                    "Re-run DomainLens NCSC TLS and confirm no `signature-hash-insufficient` finding. "
                    "Cross-check internet.nl → HTTPS → “Hashfuncties voor sleuteluitwisseling”. "
                    "Verify both A and AAAA addresses."
                ),
            ))
        elif phased:
            overall_parts.append(LEVEL_PHASED_OUT)
            findings.append(_finding(
                "signature-hash-phased-out",
                "medium",
                "Phased-out signature hash still accepted (SHA-224)",
                sig_hashes.get("detail")
                or "SHA-224 is still accepted for TLS 1.2 key-exchange signatures (NCSC: phase out).",
                LEVEL_PHASED_OUT,
                "Remove SHA-224 from SignatureAlgorithms; keep SHA-256/384/512 only.",
                retest=(
                    "Re-run DomainLens NCSC TLS; confirm only Good signature hashes remain."
                ),
            ))
        elif sig_hashes.get("good"):
            overall_parts.append(LEVEL_GOOD)

    overall = _worst(*overall_parts) if overall_parts else "unknown"
    compliant = overall in {LEVEL_GOOD, LEVEL_SUFFICIENT}
    order_ok = (not cipher_order.get("applicable")) or cipher_order.get("pass") is True
    sig_ok = (not sig_hashes.get("applicable")) or (
        not sig_hashes.get("evaluated") or not (sig_hashes.get("insufficient") or [])
    )
    preferred = (
        overall == LEVEL_GOOD
        and level_counts.get(LEVEL_PHASED_OUT, 0) == 0
        and level_counts.get(LEVEL_INSUFFICIENT, 0) == 0
        and order_ok
        and sig_ok
        and not (sig_hashes.get("phased_out") or [])
    )

    # Deduplicate findings by id
    seen = set()
    unique_findings = []
    for item in findings:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        unique_findings.append(item)

    return {
        "success": True,
        "guideline": GUIDELINE,
        "guideline_url": GUIDELINE_URL,
        "guideline_pdf": GUIDELINE_PDF,
        "overall_level": overall,
        "overall_label": _LEVEL_LABEL.get(overall, overall),
        "compliant": compliant,
        "preferred": preferred,
        "pass": (
            compliant
            and level_counts.get(LEVEL_INSUFFICIENT, 0) == 0
            and order_ok
            and sig_ok
        ),
        "protocols": protocol_rows,
        "ciphers": cipher_rows,
        "cipher_summary": {
            "total": len(cipher_rows),
            **level_counts,
        },
        "cipher_order": cipher_order,
        "signature_hashes": sig_hashes,
        "compression": {
            "enabled": compression,
            "level": LEVEL_INSUFFICIENT if compression else LEVEL_GOOD,
            "label": _LEVEL_LABEL[LEVEL_INSUFFICIENT if compression else LEVEL_GOOD],
        },
        "certificate": cert_assessment,
        "findings": unique_findings,
        "finding_counts": {
            "critical": sum(1 for f in unique_findings if f["severity"] == "critical"),
            "high": sum(1 for f in unique_findings if f["severity"] == "high"),
            "medium": sum(1 for f in unique_findings if f["severity"] == "medium"),
            "low": sum(1 for f in unique_findings if f["severity"] == "low"),
            "info": sum(1 for f in unique_findings if f["severity"] == "info"),
        },
    }


def scan(domain: str, port: int = 443, tls_deep=None, tls_deep_fn=None) -> dict:
    """Run or reuse a TLS deep scan, then assess against NCSC 2025-05."""
    deep = tls_deep
    if deep is None and callable(tls_deep_fn):
        deep = tls_deep_fn(domain, port)
    if deep is None:
        return {
            "success": False,
            "guideline": GUIDELINE,
            "guideline_url": GUIDELINE_URL,
            "error": "No TLS deep scan data available",
        }
    return assess(deep)
