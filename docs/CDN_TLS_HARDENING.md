# CDN TLS hardening (BunnyCDN, Cloudflare, OVHcloud)

Guidance for internet.nl / NCSC TLS 2025-05 findings when TLS terminates at a CDN edge.

## Signature hashes for key exchange (NCSC §3.3.5)

internet.nl reports: *“Je webserver ondersteunt een of meer onvoldoende veilige hashfuncties voor sleuteluitwisseling”* with **SHA1** on IPv4 and IPv6.

| Level | Hashes |
|-------|--------|
| Good | SHA-256, SHA-384, SHA-512 |
| Phase out | SHA-224 |
| Insufficient | SHA-1, MD5 |

This is **TLS 1.2 `SignatureAlgorithms`**, not the hash suffix in cipher suite names (`…-SHA384`). DomainLens probes with OpenSSL `-sigalgs` and records `tls_deep.signature_hashes`.

### BunnyCDN

1. Pull Zone → SSL: TLS 1.2+ only, strongest/modern cipher profile; AEAD before CBC.
2. If the panel has no SignatureAlgorithms control, open a Bunny support ticket: disable SHA-1 (and SHA-224) signature algorithms on the edge for the pull zone (IPv4 + IPv6).
3. Edge Rules / Headers: inject HSTS + CSP on all responses, including geo-block 403 pages.
4. Origin (Full/Strict): harden OpenSSL `SignatureAlgorithms` / Apache `SSLSignatureAlgorithms`.

### Cloudflare

1. SSL/TLS → Edge Certificates → Minimum TLS Version **1.2** (prefer 1.3).
2. Cipher suites: Mozilla Intermediate / custom without CBC-SHA1; AEAD first where customizable.
3. If SHA-1 signature hashes remain, contact Cloudflare support / use Advanced Certificate Manager profiles where available.
4. Origin: Full (strict) + origin SignatureAlgorithms lockdown.
5. Transform Rules / Managed Transforms for HSTS + CSP.

### OVHcloud

1. SSL Gateway / Load Balancer: Intermediate or Modern SSL profile (TLS 1.2+).
2. Origin Nginx/Apache: `ssl_conf_command SignatureAlgorithms …` / `SSLSignatureAlgorithms` limited to SHA-256/384/512.
3. Re-test both CDN VIP and origin A/AAAA addresses.

### Origin OpenSSL examples

Apache:

```apache
SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder     on
SSLSignatureAlgorithms  ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384
```

Nginx (OpenSSL 3):

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_conf_command SignatureAlgorithms ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384;
```

## Cipher order

Server must prefer Good/Sufficient (AEAD) over phase-out CBC suites. DomainLens pairwise-negotiates TLS 1.2 suites (same class of finding as internet.nl “Volgorde van cipher suites”).

## Geo-blocking

Bunny (and similar) may return HTTP 403 outside NL/DE/BE. TLS probes still succeed. Re-check HSTS/CSP from an allowed country or via internet.nl; still attach security headers on block pages.

## Retest

1. DomainLens: SSL/TLS + NCSC TLS → no `signature-hash-insufficient` / `cipher-order`.
2. internet.nl HTTPS subtests for hash functions and cipher order on A and AAAA.
