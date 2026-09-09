"""
Remediation suggestions (Advies) for DomainLens findings.
Each item includes how to solve the issue and how to retest.
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"


def _default_retest(category, title, domain=None):
    """Category-aware retest guidance when a finding has no custom steps."""
    target = domain or "the domain"
    title_l = (title or "").lower()
    cat = (category or "").lower()

    if "ncsc" in cat or "cipher" in title_l or "tls" in cat:
        return (
            f"Re-run a DomainLens scan for `{target}` with SSL/TLS + NCSC TLS enabled. "
            "Confirm the finding is gone and NCSC overall is Good/Sufficient with cipher order OK. "
            f"Cross-check on https://internet.nl/site/{target}/ (from NL/DE/BE if the site is geo-restricted)."
        )
    if cat == "email" or any(k in title_l for k in ("spf", "dmarc", "dkim", "mta-sts", "tls-rpt")):
        return (
            f"Wait for DNS TTL, then re-scan `{target}` in DomainLens (E-mail Security). "
            "Also verify with `dig TXT` / MX Toolbox, and optionally https://www.mail-tester.com/ "
            f"or https://internet.nl/mail/{target}/."
        )
    if cat == "dns" or "dnssec" in title_l:
        return (
            f"After DNS propagates, re-scan `{target}` in DomainLens (DNS/DNSSEC). "
            f"Confirm with `dig +dnssec {target}` or https://dnsviz.net/."
        )
    if cat == "web" or "header" in title_l or "hsts" in title_l or "redirect" in title_l:
        return (
            f"Re-run DomainLens Web Security for `{target}`. "
            "Confirm with `curl -sI https://…` from an allowed region (NL/DE/BE if geo-blocked). "
            f"Optional: https://internet.nl/site/{target}/."
        )
    if cat in {"certificate", "tls"}:
        return (
            f"Re-run DomainLens SSL/TLS for `{target}` and confirm the grade/warnings clear. "
            "Validate the certificate chain in a browser or with `openssl s_client -connect …:443 -servername …`."
        )
    if cat == "network" or "blacklist" in title_l or "port" in title_l or "ipv6" in title_l:
        return (
            f"Re-run DomainLens Network checks for `{target}`. "
            "Confirm the port/blacklist/IPv6 finding no longer appears."
        )
    if cat == "hubspot":
        return (
            f"Re-run the DomainLens HubSpot/Cloudflare check for `{target}` after changing WAF/CDN rules."
        )
    if cat == "osint":
        return (
            f"Re-run DomainLens OSINT for `{target}` after cleanup; threat-feed listings can take time to clear."
        )
    if cat == "rapid7":
        return (
            f"Re-scan matching assets for `{target}` in InsightVM/Nexpose after remediation, "
            "then re-import the export or confirm the finding is closed in Rapid7."
        )
    return (
        f"Re-run a full DomainLens scan for `{target}` and confirm this item is no longer listed."
    )


def _r(severity, category, title, problem, fix, reference=None, retest=None, domain=None):
    rec = {
        "severity": severity,
        "category": category,
        "title": title,
        "problem": problem,
        "fix": fix,
        "retest": retest or _default_retest(category, title, domain),
    }
    if reference:
        rec["reference"] = reference
    return rec


def _dnssec(results):
    out = []
    dnssec = results.get("dnssec")
    if not dnssec:
        return out
    if not dnssec.get("signed"):
        out.append(_r(
            SEVERITY_MEDIUM, "DNS", "DNSSEC not configured",
            "DNSSEC is not fully set up. Responses cannot be cryptographically verified, so attackers may inject spoofed DNS records.",
            "Enable DNSSEC at your DNS provider. Publish DNSKEY records and a DS record at the parent zone (registrar). Verify with `dig +dnssec` or dnsviz.net.",
            "https://www.cloudflare.com/dns/dnssec/how-dnssec-works/",
        ))
    return out


def _spf(results):
    out = []
    spf = results.get("spf")
    if not spf:
        return out
    if not spf.get("found"):
        out.append(_r(
            SEVERITY_HIGH, "Email", "SPF record missing",
            "No SPF record was found. Without SPF, anyone can spoof mail from your domain.",
            "Publish a TXT record on the apex: `v=spf1 include:_spf.yourprovider.com -all`. Start with `~all` during roll-out, then move to `-all`.",
            "https://datatracker.ietf.org/doc/html/rfc7208",
        ))
    elif not spf.get("strict"):
        out.append(_r(
            SEVERITY_MEDIUM, "Email", "SPF not strict (~all / ?all)",
            "SPF exists but the final mechanism is not `-all`, so receivers may still accept spoofed mail.",
            "Once you have verified every legitimate sending source, tighten the SPF record to end with `-all`.",
        ))
    return out


def _mx_posture(results):
    """Classify a domain's mail-receiving setup: "null", "none" or "mx".

    MX says whether a domain *receives* mail. It says nothing about sending:
    a domain with no MX at all can still send perfectly well, and plenty do.
    That distinction decides what may be advised below, because telling a
    working sender to publish `-all` would stop their mail.

    RFC 7505 null MX is the one unambiguous case: a single `0 .` record is
    the operator stating outright that this domain receives no mail.
    """
    dns_data = results.get("dns")
    if not isinstance(dns_data, dict) or "MX" not in dns_data:
        return None  # not measured; nothing may be concluded
    records = [str(r).strip() for r in (dns_data.get("MX") or []) if str(r).strip()]
    if not records:
        return "none"
    targets = []
    for record in records:
        parts = record.split()
        targets.append(parts[-1] if parts else "")
    if len(targets) == 1 and targets[0] in (".", ""):
        return "null"
    return "mx"


def _non_mailing_domain(results):
    """A domain that receives no mail should say it sends none either.

    The case that prompted this: a blacklist hit on the web server address,
    no mail of its own, and nothing published to say so. A domain nobody
    sends from is still worth forging, and SPF `-all` with DMARC `p=reject`
    is what makes that forgery fail at the receiver.

    Nothing here fires for a domain with real MX records. The advice would
    break a working mail setup, and advice an operator cannot follow without
    breaking their own site does not belong in the findings list.
    """
    out = []
    posture = _mx_posture(results)
    if posture is None or posture == "mx":
        return out

    spf = results.get("spf") or {}
    dmarc = results.get("dmarc") or {}
    record = (spf.get("record") or "").lower()
    spf_locked = spf.get("found") and "-all" in record and "include:" not in record \
        and "a:" not in record and "mx" not in record.replace("mx 0", "")
    policy = (dmarc.get("policy") or "").lower()

    # An explicit null MX is a statement; an absent MX is only an absence.
    # The first justifies naming an inconsistency, the second a suggestion.
    explicit = posture == "null"
    severity = SEVERITY_MEDIUM if explicit else SEVERITY_LOW
    receives = ("publishes a null MX record, so it states outright that it receives "
                "no mail" if explicit else "publishes no MX record, so it receives no mail")

    if not spf.get("found"):
        out.append(_r(
            severity, "Email", "No SPF on a domain that receives no mail",
            f"This domain {receives}. Without SPF, anyone can still send mail claiming "
            "to be from it, and receivers have nothing to check that against.",
            "If nothing sends mail from this domain either, publish the shortest "
            "possible record: `v=spf1 -all`. That tells every receiver to reject "
            "anything claiming to come from here. Only do this if no service — "
            "newsletters, ticketing, CRM — sends on its behalf.",
            "https://datatracker.ietf.org/doc/html/rfc7208",
        ))
    elif not spf_locked:
        out.append(_r(
            severity, "Email", "SPF still allows senders on a domain that receives no mail",
            f"This domain {receives}, but its SPF record still authorises senders: "
            f"`{spf.get('record')}`.",
            "If nothing legitimately sends from this domain, replace the record with "
            "`v=spf1 -all`. If something does send, this is correct as it stands and "
            "the record should keep listing it.",
            "https://datatracker.ietf.org/doc/html/rfc7208",
        ))

    if not dmarc.get("found"):
        out.append(_r(
            severity, "Email", "No DMARC on a domain that receives no mail",
            f"This domain {receives}, and publishes no DMARC policy. Mail forged from "
            "it fails no check, because no check is asked for.",
            "Publish `_dmarc.yourdomain` TXT: `v=DMARC1; p=reject; rua=mailto:you@example.com`. "
            "For a domain that sends nothing, `p=reject` can be set immediately — there is "
            "no legitimate mail to break, which is the usual reason to roll out gradually.",
            "https://datatracker.ietf.org/doc/html/rfc7489",
        ))
    elif policy != "reject":
        out.append(_r(
            severity, "Email", f"DMARC is p={policy or 'none'} on a domain that receives no mail",
            f"This domain {receives}, but its DMARC policy is `p={policy or 'none'}`, so "
            "receivers are not asked to refuse forged mail.",
            "For a domain that sends nothing, move straight to `p=reject`: the gradual "
            "none → quarantine → reject roll-out exists to avoid dropping legitimate "
            "mail, and there is none here to drop.",
            "https://datatracker.ietf.org/doc/html/rfc7489",
        ))

    if posture == "none" and out:
        out.append(_r(
            SEVERITY_INFO, "Email", "No null MX published",
            "This domain has no MX record. Receivers must infer from that absence that "
            "it accepts no mail, and some will still try the A record instead.",
            "Publish an explicit null MX (RFC 7505): an `MX` record with priority `0` "
            "and target `.` — written as `0 .`. It states the same thing without "
            "leaving anything to inference.",
            "https://datatracker.ietf.org/doc/html/rfc7505",
        ))
    return out

def _own_infra(results):
    """Findings from the opt-in own-infrastructure tests.

    Only ever populated for a domain the operator listed as theirs, so
    nothing here can be a report about someone else's server.
    """
    data = results.get("own_infra") or {}
    if not data.get("allowed"):
        return []
    out = []
    relay = data.get("relay") or {}
    if relay.get("open_relay"):
        hosts = [h["host"] for h in relay.get("hosts", []) if h.get("relays")]
        out.append(_r(
            SEVERITY_CRITICAL, "Email", "Mail server accepts relay for a foreign domain",
            "A mail host accepted a recipient in a domain it has no reason to serve. "
            f"An open relay ({', '.join(hosts)}) is used to send spam and phishing in "
            "your name, and gets the address blocklisted quickly.",
            "Restrict relaying to authenticated users and your own networks. Postfix: "
            "`smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, "
            "reject_unauth_destination`. Exchange: the receive connector's permission "
            "groups.",
            "https://www.rfc-editor.org/rfc/rfc5321",
        ))
    resolver_result = data.get("resolver") or {}
    if resolver_result.get("open_resolver"):
        servers = [n["address"] for n in resolver_result.get("nameservers", [])
                   if n.get("recurses")]
        out.append(_r(
            SEVERITY_HIGH, "DNS", "Nameserver answers recursive queries from anywhere",
            "An authoritative nameserver also resolves names it has no authority for, "
            f"for any client that asks ({', '.join(servers)}). Open resolvers are used "
            "to amplify denial-of-service traffic against third parties.",
            "Separate the authoritative and recursive roles, or restrict recursion to "
            "your own networks. BIND: `allow-recursion { localnets; };`.",
            "https://www.rfc-editor.org/rfc/rfc5358",
        ))
    return out


def _mx_dane_advice(results):
    """DANE on the mail hosts -- the one internet.nl scores.

    DANE on port 443 is barely deployed and barely matters; on the mail
    exchangers it is what stops STARTTLS being stripped, and the Dutch
    government requires it.
    """
    audit = results.get("security") or {}
    dm = (audit.get("dns_mail") or {}) if isinstance(audit, dict) else {}
    dane = dm.get("mx_dane") or {}
    if dane.get("state") != "measured":
        return []
    missing = [h["host"] for h in dane.get("hosts", []) if not h.get("present")]
    if not missing:
        return []
    return [_r(
        SEVERITY_MEDIUM, "Email", "No DANE (TLSA) on the mail hosts",
        "These mail exchangers publish no TLSA record: "
        f"{', '.join(missing)}. A sending server cannot verify the certificate it "
        "is offered, so STARTTLS can be stripped or spoofed without detection.",
        "Publish a TLSA record at `_25._tcp.<mx-host>` for each exchanger, matching "
        "the certificate it serves. DNSSEC must be signed for DANE to mean anything, "
        "and the record has to be rotated with the certificate.",
        "https://datatracker.ietf.org/doc/html/rfc7672",
    )]


def _dmarc(results):
    out = []
    dmarc = results.get("dmarc")
    if not dmarc:
        return out
    if not dmarc.get("found"):
        out.append(_r(
            SEVERITY_HIGH, "Email", "DMARC record missing",
            "No DMARC policy is published. Receivers have no instructions for handling spoofed mail that fails SPF or DKIM.",
            "Publish `_dmarc.yourdomain` TXT: `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain; fo=1`. Monitor aggregate reports for a few weeks, then move to `p=quarantine` and finally `p=reject`.",
            "https://datatracker.ietf.org/doc/html/rfc7489",
        ))
    else:
        policy = (dmarc.get("policy") or "").lower()
        if policy == "none":
            out.append(_r(
                SEVERITY_MEDIUM, "Email", "DMARC policy is p=none",
                "DMARC is published but only in monitor mode. Spoofed mail is not blocked.",
                "After reviewing aggregate (rua) reports, change the policy to `p=quarantine` and eventually `p=reject`.",
            ))
    return out


def _dkim(results):
    out = []
    dkim = results.get("dkim")
    if not dkim:
        return out
    if not dkim.get("found"):
        out.append(_r(
            SEVERITY_MEDIUM, "Email", "No DKIM selectors detected",
            "No DKIM public keys were found for the common selectors tested. Mail from your domain may not be DKIM-signed.",
            "Enable DKIM signing at your mail provider. Publish the generated public key as `<selector>._domainkey.yourdomain` TXT record. Use at least 2048-bit RSA.",
            "https://datatracker.ietf.org/doc/html/rfc6376",
        ))
    return out


def _mta_sts(results):
    out = []
    mta = results.get("mta_sts")
    if mta and not mta.get("found"):
        out.append(_r(
            SEVERITY_LOW, "Email", "MTA-STS not configured",
            "Without MTA-STS, inbound mail can be delivered over unencrypted or misconfigured TLS connections.",
            "Publish `_mta-sts.yourdomain` TXT (`v=STSv1; id=<timestamp>`) and host an HTTPS policy file at `https://mta-sts.yourdomain/.well-known/mta-sts.txt` listing your MX hosts and `mode: enforce`.",
            "https://datatracker.ietf.org/doc/html/rfc8461",
        ))
    return out


def _tlsrpt(results):
    out = []
    rpt = results.get("tlsrpt")
    if rpt and not rpt.get("found"):
        out.append(_r(
            SEVERITY_LOW, "Email", "TLS-RPT not configured",
            "TLS-RPT is not set up. You won't receive reports about TLS failures on inbound mail.",
            "Publish `_smtp._tls.yourdomain` TXT record: `v=TLSRPTv1; rua=mailto:tls-reports@yourdomain`.",
            "https://datatracker.ietf.org/doc/html/rfc8460",
        ))
    return out


def _tls(results):
    out = []
    tls = results.get("tls_deep")
    if not tls or not tls.get("success"):
        return out

    grade = tls.get("grade")
    if grade in ("D", "F", "T"):
        out.append(_r(
            SEVERITY_CRITICAL, "TLS", f"Poor TLS grade ({grade})",
            "The TLS configuration scored a failing grade. Connections are exposed to known attacks.",
            "Address the warnings below: disable obsolete protocols, remove weak ciphers, install a trusted certificate, and enable HSTS.",
            "https://ssl-config.mozilla.org/",
        ))

    protocols = {p.get("name"): p.get("supported") for p in (tls.get("protocols") or [])}
    if protocols.get("TLS 1.0"):
        out.append(_r(
            SEVERITY_HIGH, "TLS", "TLS 1.0 enabled",
            "TLS 1.0 is deprecated (PCI-DSS forbids it) and vulnerable to BEAST and downgrade attacks.",
            "Disable TLS 1.0 in the web server. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`.",
        ))
    if protocols.get("TLS 1.1"):
        out.append(_r(
            SEVERITY_HIGH, "TLS", "TLS 1.1 enabled",
            "TLS 1.1 is deprecated (RFC 8996). Browsers have removed support.",
            "Disable TLS 1.1 and require TLS 1.2 as a minimum.",
        ))
    if not protocols.get("TLS 1.3"):
        out.append(_r(
            SEVERITY_LOW, "TLS", "TLS 1.3 not available",
            "TLS 1.3 is not offered. You miss performance and security improvements (0-RTT, cleaner handshake).",
            "Upgrade OpenSSL (>=1.1.1) and enable TLS 1.3 alongside TLS 1.2 in the server configuration.",
        ))

    summary = tls.get("cipher_summary") or {}
    if summary.get("weak", 0) > 0 or summary.get("insecure", 0) > 0:
        out.append(_r(
            SEVERITY_HIGH, "TLS", "Weak cipher suites accepted",
            f"{summary.get('weak', 0)} weak and {summary.get('insecure', 0)} insecure cipher suites are accepted. These include RC4, 3DES, DES, NULL or EXPORT ciphers.",
            "Restrict ciphers to modern AEAD suites, e.g. Nginx: `ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...; ssl_prefer_server_ciphers on;`. Use Mozilla's SSL Config Generator (intermediate profile).",
            "https://ssl-config.mozilla.org/",
        ))

    if summary.get("total", 0) > 0 and summary.get("forward_secrecy", 0) < summary.get("total", 0):
        out.append(_r(
            SEVERITY_MEDIUM, "TLS", "Forward secrecy not universal",
            "Some accepted cipher suites do not provide forward secrecy, so past sessions could be decrypted if the private key leaks.",
            "Only allow ECDHE/DHE based cipher suites. Disable static RSA key exchange.",
        ))

    if tls.get("tls_compression"):
        out.append(_r(
            SEVERITY_HIGH, "TLS", "TLS compression enabled (CRIME)",
            "TLS compression is enabled and leaves the server vulnerable to CRIME.",
            "Disable TLS compression. Nginx: already disabled by default. OpenSSL: compile with `-DOPENSSL_NO_COMP` or set `SSL_OP_NO_COMPRESSION`.",
        ))

    # Only report when stapling was positively determined to be absent.
    # None means the probe could not establish it, and an unverifiable claim
    # is worse than an absent one.
    #
    # And absent is not the same as possible: a certificate with no OCSP
    # responder in its Authority Information Access has nothing to staple.
    # Let's Encrypt removed the OCSP URI from its certificates in 2025 and
    # shut the responders down, so telling those operators to "enable OCSP
    # stapling" is an instruction no server can carry out.
    certificate = tls.get("certificate") or {}
    issuer_org = certificate.get("issuer_org")
    ocsp_uris = certificate.get("ocsp_uris")
    if tls.get("ocsp_stapling") is False and ocsp_uris:
        out.append(_r(
            SEVERITY_LOW, "TLS", "OCSP stapling disabled",
            "The certificate names an OCSP responder, but the server did not staple a "
            "response. Clients that check revocation must then contact the CA "
            "themselves, which is slower and tells the CA which sites they visit.",
            "Enable OCSP stapling on whatever terminates TLS. Nginx: `ssl_stapling on; "
            "ssl_stapling_verify on; resolver 1.1.1.1 valid=300s;`. Behind a CDN the edge "
            "terminates TLS, so this is a setting on the CDN, not on your origin.",
        ))
    elif tls.get("ocsp_stapling") is False and ocsp_uris is not None:
        out.append(_r(
            SEVERITY_INFO, "TLS", "OCSP stapling not applicable to this certificate",
            "The certificate carries no OCSP responder URL, so there is no response to "
            f"staple. {issuer_org or 'This CA'} does not offer OCSP for it; revocation is "
            "handled through the browser's own lists (CRLSets, CRLite) instead.",
            "Nothing to do. Enabling stapling on the server would have no effect, because "
            "there is no responder to fetch a status from.",
            "https://letsencrypt.org/2024/12/05/ending-ocsp/",
        ))

    hsts = tls.get("hsts") or {}
    if hsts.get("blocked") or hsts.get("enabled") is None:
        country = hsts.get("request_country")
        geo_hint = (
            f" Probe country was {country}; Benelux geo-allowlists (NL/DE/BE) will block "
            "scanners elsewhere."
            if country and country not in {"NL", "DE", "BE"}
            else ""
        )
        out.append(_r(
            SEVERITY_INFO, "TLS", "HSTS could not be verified",
            (
                hsts.get("block_detail")
                or (
                    "The HTTPS probe was blocked by a CDN/WAF (or failed), so "
                    "Strict-Transport-Security could not be confirmed from this vantage point."
                )
            )
            + geo_hint
            + " The site may still send HSTS to allowed clients (as internet.nl often shows).",
            "Re-check from NL, DE, or BE (or use internet.nl). Optionally configure BunnyCDN/"
            "Cloudflare to also send "
            "`Strict-Transport-Security: max-age=31536000; includeSubDomains` on geo-block responses.",
            "https://hstspreload.org/",
        ))
    elif hsts.get("enabled") is False:
        out.append(_r(
            SEVERITY_MEDIUM, "TLS", "HSTS header missing",
            "Strict-Transport-Security is not set. A downgrade to plain HTTP is possible on first visit.",
            "Return `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on every HTTPS response. After testing, submit to hstspreload.org.",
            "https://hstspreload.org/",
        ))
    elif hsts.get("enabled"):
        # max-age was parsed but never judged, so a header that switches HSTS
        # off, or expires before the next visit, counted as "HSTS enabled".
        max_age = hsts.get("max_age")
        if max_age == 0:
            out.append(_r(
                SEVERITY_HIGH, "TLS", "HSTS is switched off by max-age=0",
                "The header is present but `max-age=0` tells browsers to forget HSTS for "
                "this host. Visitors who were protected lose that protection on their next "
                "visit, and a downgrade to plain HTTP becomes possible again.",
                "Set `max-age=31536000` (one year). Use `max-age=0` only deliberately, to "
                "retire HSTS for a host you are decommissioning.",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security",
            ))
        elif max_age is not None and max_age < 86400:
            out.append(_r(
                SEVERITY_MEDIUM, "TLS", f"HSTS max-age is only {max_age} seconds",
                "The policy expires faster than a typical visit interval, so most returning "
                "visitors arrive unprotected and can be downgraded to HTTP.",
                "Raise it to `max-age=31536000` (one year). Shorter values are only for the "
                "first days of a rollout, while you confirm every path works over HTTPS.",
                "https://hstspreload.org/",
            ))
        elif max_age is not None and max_age < 31536000:
            out.append(_r(
                SEVERITY_LOW, "TLS", "HSTS max-age is below one year",
                f"`max-age={max_age}` protects returning visitors, but the preload list "
                "requires at least 31536000 seconds, so the domain cannot be submitted.",
                "Set `max-age=31536000` once you are confident every subdomain serves HTTPS.",
                "https://hstspreload.org/",
            ))
        if not hsts.get("include_subdomains"):
            out.append(_r(
                SEVERITY_LOW, "TLS", "HSTS does not cover subdomains",
                "Without `includeSubDomains` the policy applies to this host only. A "
                "subdomain reachable over plain HTTP can still be used to set cookies for "
                "the parent domain or to phish over an unprotected connection.",
                "Add `includeSubDomains` — but confirm first that every subdomain, including "
                "internal ones, serves HTTPS, because they will all become unreachable over "
                "HTTP at once.",
                "https://hstspreload.org/",
            ))
        elif not hsts.get("preload"):
            out.append(_r(
                SEVERITY_INFO, "TLS", "HSTS not preload-ready",
                "HSTS covers subdomains but does not include `preload`, so the very first "
                "visit to the domain is still made over an unprotected connection.",
                "Add `preload` and submit the domain to hstspreload.org. Note this is close "
                "to irreversible: removal takes months and never reaches older browsers.",
                "https://hstspreload.org/",
            ))

    cert = tls.get("certificate") or {}
    if cert.get("expired"):
        out.append(_r(
            SEVERITY_CRITICAL, "Certificate", "Certificate expired",
            "The TLS certificate has expired. Browsers block access.",
            "Renew the certificate immediately. Automate renewal with ACME (Let's Encrypt + certbot / acme.sh).",
        ))
    elif cert.get("days_until_expiry") is not None and cert["days_until_expiry"] < 30:
        out.append(_r(
            SEVERITY_HIGH, "Certificate", "Certificate expires soon",
            f"Certificate expires in {cert['days_until_expiry']} days.",
            "Renew the certificate now and automate renewal to avoid future outages.",
        ))

    if cert.get("self_signed"):
        out.append(_r(
            SEVERITY_HIGH, "Certificate", "Self-signed certificate",
            "The certificate is self-signed. Browsers show warnings and APIs will refuse the connection.",
            "Obtain a certificate from a public CA (Let's Encrypt is free and automated).",
        ))

    return out


def _https_redirect(results):
    out = []
    red = results.get("https_redirect")
    if not red:
        return out
    if red.get("blocked") or red.get("pass") is None:
        out.append(_r(
            SEVERITY_INFO, "Web", "HTTPS redirect could not be verified",
            red.get("note")
            or red.get("block_detail")
            or "The HTTP probe was blocked by a CDN/WAF, so an HTTP→HTTPS redirect could not be confirmed from this vantage point.",
            "Verify the redirect from NL/DE/BE (or another allowed region). Prefer a permanent 301/308 from HTTP to HTTPS on the same host.",
        ))
        return out
    if not red.get("pass"):
        out.append(_r(
            SEVERITY_HIGH, "Web", "HTTP does not redirect to HTTPS",
            "Plain HTTP traffic is not redirected to HTTPS, exposing users to MITM attacks.",
            "Force a 301 redirect from HTTP to HTTPS. Nginx: `return 301 https://$host$request_uri;`. Apache: `Redirect permanent / https://example.com/`.",
        ))
    elif red.get("pass") and not red.get("permanent"):
        out.append(_r(
            SEVERITY_LOW, "Web", "HTTPS redirect is temporary (302/307)",
            "The HTTP to HTTPS redirect uses a non-permanent status code.",
            "Use a permanent redirect (301 or 308) so browsers cache the redirect.",
        ))
    return out


_HEADER_FIX = {
    "Strict-Transport-Security": "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` (then add `preload` once all subdomains are HTTPS).",
    "Content-Security-Policy": (
        "Build CSP in stages: (1) deploy Content-Security-Policy-Report-Only with "
        "`default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`; "
        "(2) add only required hosts for script/style/img/connect/font; "
        "(3) replace inline scripts with nonces/hashes — never keep `'unsafe-inline'`/`'unsafe-eval'`; "
        "(4) when reports are clean, switch to enforcing Content-Security-Policy."
    ),
    "X-Content-Type-Options": "Set `X-Content-Type-Options: nosniff`.",
    "X-Frame-Options": "Prefer CSP `frame-ancestors 'none'` (or `'self'`). Legacy fallback: `X-Frame-Options: DENY`.",
    "Referrer-Policy": "Set `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` for sensitive apps).",
    "Permissions-Policy": "Deny everything, then open only what your own pages use: `Permissions-Policy: accelerometer=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=()`. Change a feature to `(self)` where your own pages need it, and use `*` only when you deliberately hand the capability to an embedded partner.",
    "Cross-Origin-Opener-Policy": "Set `Cross-Origin-Opener-Policy: same-origin`.",
    "Cross-Origin-Resource-Policy": "Set `Cross-Origin-Resource-Policy: same-site` (or `same-origin` if possible).",
    "Cross-Origin-Embedder-Policy": "Only if you need cross-origin isolation (SharedArrayBuffer, high-resolution timers): set `Cross-Origin-Embedder-Policy: require-corp`, and first confirm every cross-origin image, font, script and frame you load returns `Cross-Origin-Resource-Policy` or is fetched with CORS — those that do not will stop loading.",
    "X-XSS-Protection": "Set `X-XSS-Protection: 0` and rely on a strong CSP (legacy XSS auditor is deprecated/harmful).",
}


# What each CSP weakness actually lets an attacker do. Listing issue titles
# told the reader what the checker disliked, not why it matters or which part
# of their own policy caused it — so the advice was hard to act on.
# What each header buys you, in one sentence. The missing-headers advice used
# to say only "add this", which tells the reader nothing about whether it is
# worth their afternoon.
_HEADER_PURPOSE = {
    "Strict-Transport-Security": "It keeps browsers on HTTPS for this host, so a visitor cannot be downgraded to plain HTTP by someone on their network.",
    "Content-Security-Policy": "It limits where scripts, styles and images may be loaded from, and is the main defence against cross-site scripting.",
    "X-Content-Type-Options": "It stops browsers guessing a response's type, which is how an uploaded file can end up being executed as script.",
    "X-Frame-Options": "It stops other sites putting your pages in an iframe and tricking users into clicking them.",
    "Referrer-Policy": "It controls how much of your URLs — path and query included — is handed to every site you link to.",
    "Permissions-Policy": "It decides which browser features, such as camera, microphone and geolocation, your pages and any embedded frames may use.",
    "Cross-Origin-Opener-Policy": "It severs the link between your window and any page that opened it, closing off cross-window attacks.",
    "Cross-Origin-Resource-Policy": "It stops other sites loading your images, scripts and other resources directly.",
    "Cross-Origin-Embedder-Policy": "It is the second half of cross-origin isolation, needed only for SharedArrayBuffer and high-resolution timers.",
    "X-XSS-Protection": "Setting it to 0 turns off the legacy XSS auditor, which modern browsers have removed and which was itself exploitable.",
}


_CSP_ISSUE_IMPACT = {
    # Exact ids
    "csp_no_default_or_script":
        "nothing restricts where scripts may load from, so the policy offers no "
        "XSS protection at all",
    "csp_unsafe_inline_script_src":
        "inline <script> blocks and event handlers still execute — the exact "
        "payload most XSS attacks rely on. This is the single biggest weakness "
        "a policy can have",
    # 'unsafe-inline' on style-src is a genuinely smaller problem than on
    # script-src: it permits injected CSS, not code execution. Saying otherwise
    # would push people to spend effort on nonces where it buys least.
    "csp_unsafe_inline_style_src":
        "inline styles are allowed. This cannot execute code, so it is far less "
        "serious than on script-src, but injected CSS can still deface pages and "
        "leak data through attribute selectors",
    "csp_object_src":
        "plugin content (<object>, <embed>) is unrestricted — an old but still "
        "usable route to script execution",
    "csp_object_src_not_none":
        "plugin content is allowed from somewhere; there is rarely a reason for "
        "this to be anything but 'none'",
    "csp_no_frame_ancestors":
        "any site can place your pages in an iframe, which is what clickjacking "
        "needs",
    "csp_frame_ancestors_star":
        "framing is explicitly allowed from anywhere, so clickjacking is "
        "unimpeded",
    "csp_no_base_uri":
        "injected markup can rewrite <base href>, redirecting every relative URL "
        "on the page to an attacker's host",
    "csp_no_form_action":
        "injected markup can point a form at an attacker's server, so submitted "
        "credentials leave your site",
    "csp_no_reporting":
        "violations are invisible, so you cannot tell whether tightening the "
        "policy would break the site",
}

# Prefix fallbacks for the per-directive ids (csp_wildcard_img_src, ...).
_CSP_ISSUE_IMPACT_PREFIX = {
    "csp_unsafe_eval":
        "eval() and friends remain available, letting injected strings become "
        "executable code",
    "csp_wildcard":
        "the wildcard allows any host on the internet, so this directive stops "
        "being a meaningful restriction",
    "csp_unsafe_inline":
        "inline content is allowed, which weakens what this directive protects",
}


def _csp_directive_from_id(issue_id: str) -> str | None:
    """csp_wildcard_img_src -> img-src, so the current value can be quoted."""
    for prefix in ("csp_unsafe_inline_", "csp_unsafe_eval_", "csp_wildcard_"):
        if issue_id.startswith(prefix):
            return issue_id[len(prefix):].replace("_", "-")
    return None


def _csp_problem_from_analysis(csp: dict, issues: list) -> str:
    """Explain each CSP weakness and quote the directive that caused it.

    Listing issue titles told the reader what the checker disliked, not why it
    matters or which part of their own policy caused it.
    """
    directives = csp.get("directives") or {}
    lines = []
    for issue in issues[:6]:
        issue_id = issue.get("id") or ""
        line = issue.get("title") or issue_id

        impact = _CSP_ISSUE_IMPACT.get(issue_id)
        if impact is None:
            for prefix, text in _CSP_ISSUE_IMPACT_PREFIX.items():
                if issue_id.startswith(prefix):
                    impact = text
                    break
        if impact:
            line += f" — {impact}"

        directive = _CSP_DIRECTIVE_OVERRIDES.get(issue_id) or _csp_directive_from_id(issue_id)
        value = directives.get(directive) if directive else None
        if value:
            shown = value if isinstance(value, str) else " ".join(value)
            line += f". Currently: `{directive} {shown}`"
        lines.append(line)

    return (
        "A Content-Security-Policy is present, so the foundation is there. "
        "These parts weaken it:\n- " + "\n- ".join(lines)
    )


_CSP_DIRECTIVE_OVERRIDES = {
    "csp_object_src_not_none": "object-src",
    "csp_frame_ancestors_star": "frame-ancestors",
}


def _csp_fix_from_analysis(csp: dict) -> str:
    suggestions = csp.get("suggestions") or []
    if suggestions:
        return " ".join(suggestions[:6])
    return _HEADER_FIX["Content-Security-Policy"]


def _headers(results):
    out = []
    headers = results.get("http_headers")
    if not headers or not headers.get("success"):
        return out
    domain = results.get("domain")
    if headers.get("blocked"):
        out.append(_r(
            SEVERITY_INFO, "Web", "Security headers could not be fully verified",
            headers.get("note")
            or headers.get("block_detail")
            or "The HTTPS probe was blocked by a CDN/WAF, so missing headers are inconclusive.",
            "Re-check headers from NL/DE/BE (or another allowed region), or configure the CDN to return security headers on geo-block responses too.",
            "https://owasp.org/www-project-secure-headers/",
            domain=domain,
        ))
        return out

    # COEP is an opt-in to cross-origin isolation with a hard prerequisite,
    # not a baseline header. When the site's own policy shows it loads
    # third-party subresources, require-corp would block them, so it is
    # reported as a deliberate omission rather than as a gap to close.
    coep = headers.get("coep") or {}
    if coep.get("blocking_sources"):
        sources = ", ".join(f"`{s}`" for s in coep["blocking_sources"][:5])
        out.append(_r(
            SEVERITY_INFO, "Web",
            "Cross-Origin-Embedder-Policy intentionally not advised here",
            "COEP `require-corp` blocks every cross-origin subresource that does not "
            "return a Cross-Origin-Resource-Policy header. This site loads subresources "
            f"from {sources}, which are not yours to add headers to, so enabling it "
            "would break them. This is not a missing header — it is the correct setting "
            "for this site.",
            "Leave Cross-Origin-Embedder-Policy unset unless you need cross-origin "
            "isolation (SharedArrayBuffer or high-resolution timers). If you do, mirror "
            "those resources onto your own origin first, or proxy them, so they carry "
            "your CORP header.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy",
            domain=domain,
        ))

    # A header that is present but not honoured is worse than one that is
    # absent: the absence at least shows up in the missing list.
    for issue in headers.get("header_value_issues") or []:
        if issue.get("problem") == "invalid":
            out.append(_r(
                SEVERITY_MEDIUM, "Web",
                f"{issue['header']} has a value browsers ignore",
                issue["detail"],
                f"Set `{issue['header']}: {issue['expected']}`.",
                "https://owasp.org/www-project-secure-headers/",
                domain=domain,
            ))
        else:
            out.append(_r(
                SEVERITY_LOW, "Web",
                f"{issue['header']} is set to a permissive value",
                f"`{issue['value']}` is valid, but grants what the header exists to "
                f"restrict. {issue['detail']}",
                f"Set `{issue['header']}: {issue['expected']}` unless you deliberately "
                f"need the permissive behaviour.",
                "https://owasp.org/www-project-secure-headers/",
                domain=domain,
            ))

    # Only the presence of Permissions-Policy was checked, so a policy handing
    # the camera to every embedded frame scored the same as one denying it.
    pp = headers.get("permissions_policy") or {}
    wide = pp.get("sensitive_wide_open") or []
    if wide:
        listed = ", ".join(f"`{f}`" for f in wide[:6])
        out.append(_r(
            SEVERITY_MEDIUM, "Web",
            f"Permissions-Policy grants {listed} to any embedded site",
            f"These features are set to `*`, so any third-party iframe on the page can use "
            f"them. That is more permissive than the browser default, which limits them to "
            f"your own origin.",
            "Replace `*` with `(self)` for features your own pages use, and `()` for the "
            "rest. `*` is only appropriate when you deliberately delegate a capability to an "
            "embedded partner.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy",
            domain=domain,
        ))

    missing = headers.get("headers_missing") or []
    if missing:
        severity = SEVERITY_MEDIUM if len(missing) >= 4 else SEVERITY_LOW
        # Dedicated CSP missing item with full build advice
        if "Content-Security-Policy" in missing:
            out.append(_r(
                SEVERITY_MEDIUM,
                "Web",
                "Content-Security-Policy missing — build a safe policy",
                "No CSP header was returned. Without CSP, XSS and framing defenses rely only on weaker legacy headers.",
                _HEADER_FIX["Content-Security-Policy"]
                + " Example: `Content-Security-Policy: default-src 'self'; script-src 'self'; "
                "style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`.",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
                domain=domain,
            ))
            missing = [h for h in missing if h != "Content-Security-Policy"]
        if missing:
            # "1 security header(s) missing … does not send several" named
            # nothing and did not agree with itself. A single missing header
            # is now named in the title, and every entry says what the header
            # would have done, so the reader can weigh it without looking it up.
            if len(missing) == 1:
                header = missing[0]
                title = f"{header} header missing"
                problem = f"The server does not send `{header}`. {_HEADER_PURPOSE.get(header, '')}".strip()
            else:
                title = f"{len(missing)} security headers missing"
                listed = ", ".join(f"`{h}`" for h in missing)
                problem = (
                    f"The server does not send {listed}. "
                    + " ".join(
                        f"{h}: {_HEADER_PURPOSE[h]}" for h in missing if h in _HEADER_PURPOSE
                    )
                ).strip()
            out.append(_r(
                severity, "Web", title, problem,
                " ".join(_HEADER_FIX.get(h, f"Add `{h}`.") for h in missing),
                "https://owasp.org/www-project-secure-headers/",
                domain=domain,
            ))

    # CSP quality when present
    csp = headers.get("csp") or (headers.get("web_security") or {}).get("csp") or {}
    if csp.get("present"):
        grade = csp.get("grade") or "fair"
        issues = csp.get("issues") or []
        high_issues = [i for i in issues if i.get("severity") == "high"]
        medium_issues = [i for i in issues if i.get("severity") == "medium"]
        if high_issues or medium_issues:
            sev = SEVERITY_HIGH if high_issues else SEVERITY_MEDIUM
            out.append(_r(
                sev,
                "Web",
                f"Content-Security-Policy is {grade} — tighten policy",
                _csp_problem_from_analysis(csp, high_issues + medium_issues),
                _csp_fix_from_analysis(csp),
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
                domain=domain,
            ))
        elif grade in {"good", "strong"} and any(i.get("id") == "csp_no_reporting" for i in issues):
            out.append(_r(
                SEVERITY_INFO,
                "Web",
                "CSP has no violation reporting",
                "Policy looks reasonable but has no report-uri / report-to, so breakages are hard to see while tightening.",
                "Add a reporting endpoint (`report-to` / Report-To) before and after switching from Report-Only to enforce.",
                domain=domain,
            ))

    out.extend(_csp_report_only(headers, domain))

    # Cookie / CORS / framing / disclosure from http_headers analysis
    out.extend(_web_vuln_findings(headers, domain))
    return out


def _fmt_sources(entries) -> str:
    return "; ".join(
        f"`{e['directive']}` {' '.join(e['sources'])}" for e in entries
    )


def _csp_report_only(headers: dict, domain: str | None) -> list:
    """Surface a staged Content-Security-Policy-Report-Only and its delta.

    A Report-Only header is a change in progress. Reporting only the enforcing
    policy hid the part of the configuration actively being worked on, and gave
    no prompt to go and read the violation reports that decide whether the
    change is safe to make.
    """
    delta = headers.get("csp_delta") or (headers.get("web_security") or {}).get("csp_delta") or {}
    if not delta.get("has_report_only"):
        return []

    if delta.get("identical"):
        return [_r(
            SEVERITY_INFO, "Web",
            "CSP Report-Only is identical to the enforced policy",
            "A Content-Security-Policy-Report-Only header is present but matches the "
            "enforced policy exactly, so it can only ever report violations you are "
            "already blocking. It tells you nothing about a change you are considering.",
            "Either point Report-Only at the stricter policy you intend to adopt, or "
            "remove the header so it stops adding weight to every response.",
            domain=domain,
        )]

    parts = []
    if delta.get("stricter"):
        parts.append("would no longer allow " + _fmt_sources(delta["stricter"]))
    if delta.get("looser"):
        parts.append("would additionally allow " + _fmt_sources(delta["looser"]))
    if delta.get("added_directives"):
        parts.append("adds " + _fmt_sources(delta["added_directives"]))
    if delta.get("removed_directives"):
        parts.append("drops " + _fmt_sources(delta["removed_directives"]))

    tightening = bool(delta.get("stricter") or delta.get("added_directives"))
    return [_r(
        SEVERITY_INFO, "Web",
        "CSP Report-Only staged — review violation reports before enforcing",
        "A Content-Security-Policy-Report-Only header is staged alongside the enforced "
        "policy. Compared to what is enforced today, it " + ", and ".join(parts) + ". "
        + ("Nothing is blocked by it — it only reports — so the site behaves as before."
           if tightening else
           "Note this staged policy is looser than what you enforce today, which is "
           "unusual for a Report-Only header."),
        "Check your CSP reporting tool (the `report-uri`/`report-to` endpoint in the "
        "policy, e.g. uriports) for violations attributed to the report-only "
        "disposition. No violations after a representative period — including the "
        "less-travelled pages such as admin screens — means the staged policy is safe "
        "to promote to the enforced header. Any host that does appear is one you must "
        "add first.",
        domain=domain,
    )]


def _web_vuln_findings(headers_block: dict, domain: str | None = None):
    """Map structured web_security issues to Advies items."""
    out = []
    analysis = headers_block.get("web_security") or {}
    issues = list(headers_block.get("vuln_findings") or analysis.get("issues") or [])

    # Deduplicate by id; CSP issues already covered above except when only in vuln_findings
    seen = set()
    for issue in issues:
        iid = issue.get("id") or issue.get("title")
        if not iid or iid in seen:
            continue
        # Skip CSP ids handled by dedicated CSP advies
        if str(iid).startswith("csp_"):
            continue
        seen.add(iid)
        severity = {
            "critical": SEVERITY_CRITICAL,
            "high": SEVERITY_HIGH,
            "medium": SEVERITY_MEDIUM,
            "low": SEVERITY_LOW,
            "info": SEVERITY_INFO,
        }.get(issue.get("severity"), SEVERITY_MEDIUM)
        title = issue.get("title") or iid
        detail = issue.get("detail") or title
        fix = _fix_for_web_issue(issue)
        out.append(_r(
            severity,
            "Web",
            title,
            detail,
            fix,
            "https://owasp.org/www-project-secure-headers/",
            domain=domain,
        ))
    return out


_FIX_FOR_WEB_ISSUE = {
    "cookie_no": (
        "Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies. "
        "Example: `Set-Cookie: session=…; Secure; HttpOnly; SameSite=Lax; Path=/`."
    ),
    "cors_star": (
        "Do not use `Access-Control-Allow-Origin: *` for authenticated APIs. "
        "Reflect an allow-listed Origin and only set `Access-Control-Allow-Credentials: true` for those origins."
    ),
    "framing_un": (
        "Add CSP `frame-ancestors 'none'` (preferred) or `X-Frame-Options: DENY` to prevent clickjacking."
    ),
    "framing_al": (
        "Replace deprecated `X-Frame-Options: ALLOW-FROM` with CSP `frame-ancestors https://trusted.example`."
    ),
    "framing_cs": (
        "Change CSP `frame-ancestors` from `*` to `'none'` or an explicit allow-list."
    ),
    "disclosure_x": (
        "Remove `X-Powered-By` (e.g. disable in Express/ASP.NET) so stack details are not advertised."
    ),
    "disclosure_s": (
        "Configure the reverse proxy to send a generic `Server` token without version numbers."
    ),
    "disclosure_a": (
        "Disable ASP.NET version headers (`httpRuntime enableVersionHeader=\"false\"` / remove X-AspNet* headers)."
    ),
}


def _fix_for_web_issue(issue: dict) -> str:
    iid = str(issue.get("id") or "")
    if iid.startswith("cookie_"):
        return _FIX_FOR_WEB_ISSUE["cookie_no"]
    if iid.startswith("cors_"):
        return _FIX_FOR_WEB_ISSUE["cors_star"]
    if iid.startswith("framing_"):
        if "allow_from" in iid:
            return _FIX_FOR_WEB_ISSUE["framing_al"]
        if "csp_star" in iid or "star" in iid:
            return _FIX_FOR_WEB_ISSUE["framing_cs"]
        return _FIX_FOR_WEB_ISSUE["framing_un"]
    if iid.startswith("disclosure_x"):
        return _FIX_FOR_WEB_ISSUE["disclosure_x"]
    if iid.startswith("disclosure_server"):
        return _FIX_FOR_WEB_ISSUE["disclosure_s"]
    if iid.startswith("disclosure_asp"):
        return _FIX_FOR_WEB_ISSUE["disclosure_a"]
    return issue.get("detail") or "Harden the HTTP response according to OWASP Secure Headers guidance."


def _ipv6(results):
    out = []
    ipv6 = results.get("ipv6")
    if ipv6 and not ipv6.get("has_ipv6"):
        out.append(_r(
            SEVERITY_LOW, "Network", "No IPv6 (AAAA) record",
            "The domain only resolves to IPv4. Clients on IPv6-only networks cannot reach it.",
            "Publish AAAA records that point to the IPv6 address of your web server and make sure the service listens on IPv6.",
        ))
    return out


def _blacklist(results):
    out = []
    bl = results.get("blacklist")
    if not bl:
        return out
    if bl.get("is_listed"):
        listed = ", ".join(bl.get("listed") or [])
        out.append(_r(
            SEVERITY_CRITICAL, "Network", "IP listed on DNSBL",
            f"The server IP is listed on: {listed}. Outbound mail will likely be blocked.",
            "Investigate potential compromise or spam sources. Request delisting on each DNSBL only after the root cause is fixed.",
        ))
    return out


RISKY_PORTS = {
    21: "FTP is unencrypted — use SFTP/FTPS instead.",
    23: "Telnet is unencrypted and deprecated — use SSH.",
    3306: "Database ports should not be public. Restrict with a firewall.",
    3389: "RDP is a common ransomware vector. Restrict to VPN or use a bastion.",
    5432: "Database ports should not be public. Restrict with a firewall.",
}


def _ports(results):
    out = []
    ports = results.get("ports")
    if not ports:
        return out
    for entry in ports.get("open") or []:
        port = entry.get("port")
        if port in RISKY_PORTS:
            out.append(_r(
                SEVERITY_HIGH, "Network", f"Risky port {port}/{entry.get('service')} is open",
                RISKY_PORTS[port],
                "Close the port on the public interface or restrict access via firewall/VPN.",
            ))
    return out


def _whois(results):
    out = []
    whois_data = (results.get("whois") or {}).get("data") or {}
    exp = whois_data.get("expiration_date")
    if isinstance(exp, list):
        exp = exp[0] if exp else None
    if isinstance(exp, str):
        try:
            from datetime import datetime, timezone
            parsed = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            days_left = (parsed - datetime.now(timezone.utc)).days
            if 0 <= days_left <= 30:
                out.append(_r(
                    SEVERITY_HIGH, "WHOIS", "Domain expires soon",
                    f"The domain registration expires in {days_left} days.",
                    "Renew the domain with your registrar and consider enabling auto-renew.",
                ))
            elif days_left < 0:
                out.append(_r(
                    SEVERITY_CRITICAL, "WHOIS", "Domain expired",
                    "The domain registration has expired.",
                    "Renew immediately; otherwise the domain may be released to another registrant.",
                ))
        except ValueError:
            pass
    return out


def _security_audit(results):
    """Fold the security-audit findings into the recommendation list."""
    out = []
    audit = results.get("security") or {}
    for f in audit.get("findings") or []:
        problem = f.get("detail", "")
        evidence = f.get("evidence", "")
        if evidence:
            problem = f"{problem} (Evidence: {evidence})"
        out.append(_r(
            f.get("severity", SEVERITY_INFO),
            f.get("category", "Security"),
            f.get("title", "Security finding"),
            problem,
            f.get("fix", "Review and remediate this finding."),
        ))
    return out


def _osint(results):
    out = []
    osint = results.get("osint")
    if not osint or not osint.get("success"):
        return out
    summary = osint.get("summary") or {}
    sources = osint.get("sources") or {}

    if summary.get("listed_in_threat_feeds"):
        out.append(_r(
            SEVERITY_CRITICAL, "OSINT", "Domain appears in open threat feeds",
            "Public OSINT sources (ThreatFox / URLhaus / OTX) returned indicators for this domain.",
            "Investigate host compromise, phishing abuse, or malware distribution. Rotate credentials, review web roots, and request delisting after cleanup.",
            "https://threatfox.abuse.ch/",
        ))

    subdomain_count = summary.get("subdomain_count") or 0
    if subdomain_count >= 25:
        out.append(_r(
            SEVERITY_MEDIUM, "OSINT", "Large Certificate Transparency footprint",
            f"crt.sh shows {subdomain_count} related hostnames. Unused or forgotten subdomains increase attack surface.",
            "Inventory CT-discovered hostnames, retire unused DNS records, and restrict certificate issuance where possible.",
            "https://crt.sh/",
        ))

    geo = ((sources.get("ip_context") or {}).get("geo") or {})
    if geo.get("proxy"):
        out.append(_r(
            SEVERITY_INFO, "OSINT", "IP marked as proxy/VPN",
            "Open IP enrichment marked this address as a proxy.",
            "Confirm whether this is expected for your hosting or CDN setup.",
        ))

    # VirusTotal only speaks when it actually ran. Without a key the lookup is
    # skipped, and an unconfigured source must never produce a verdict — in
    # either direction.
    if summary.get("virustotal_measured"):
        vt = sources.get("virustotal") or {}
        malicious = int(summary.get("virustotal_malicious") or 0)
        suspicious = int(summary.get("virustotal_suspicious") or 0)
        vendors = ", ".join(vt.get("flagged_by") or []) or "unnamed engines"
        # A single engine flagging a domain is very often a false positive, so
        # one detection is reported for confirmation rather than as a verdict;
        # several independent engines agreeing is treated as real.
        if malicious >= 2:
            out.append(_r(
                SEVERITY_CRITICAL, "OSINT",
                f"VirusTotal: {malicious} engines flag this domain as malicious",
                f"Multiple independent engines currently flag this domain ({vendors}). "
                "Independent agreement makes a false positive unlikely.",
                "Investigate compromise, phishing or malware hosting. After cleanup, request "
                "a re-analysis on VirusTotal and dispute any remaining incorrect verdicts with the vendors.",
                "https://www.virustotal.com/",
            ))
        elif malicious == 1 or suspicious:
            out.append(_r(
                SEVERITY_INFO, "OSINT",
                "VirusTotal: isolated detection — confirm before acting",
                f"{malicious} malicious and {suspicious} suspicious verdict(s) from {vendors}. "
                "A single engine disagreeing with the rest is commonly a false positive, so this "
                "is reported for confirmation, not as a finding about the domain.",
                "Open the VirusTotal report and check whether the detection is substantiated. "
                "If it is not, dispute it with that vendor.",
                "https://www.virustotal.com/",
            ))

    return out


_SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}


def _http_deep(results):
    out = []
    deep = results.get("http_deep") or {}
    if not deep.get("success"):
        return out
    domain = results.get("domain")
    for diag in deep.get("diagnostics") or []:
        severity = SEVERITY_HIGH if str(diag.get("title", "")).startswith(("403", "Cloudflare", "Azure WAF", "App-level")) else SEVERITY_MEDIUM
        title = diag.get("title") or "HTTP diagnostic"
        if "403" in title or "WAF" in title or "block" in title.lower():
            severity = SEVERITY_HIGH
        out.append(_r(
            severity,
            "Web",
            title,
            diag.get("detail") or "HTTP analysis reported an access issue.",
            diag.get("action") or "Review gateway/WAF and application access controls.",
            domain=domain,
        ))
    # If http_headers was not run, still surface cookie/CORS findings from http_deep
    headers = results.get("http_headers") or {}
    if not headers.get("web_security") and deep.get("web_security"):
        out.extend(_web_vuln_findings({"web_security": deep["web_security"], "vuln_findings": (deep["web_security"] or {}).get("issues")}, domain))
    return out


def _hubspot_cf(results):
    out = []
    hs = results.get("hubspot_cf") or {}
    if not hs.get("success"):
        return out
    for item in hs.get("findings") or []:
        severity = {
            "critical": SEVERITY_CRITICAL,
            "high": SEVERITY_HIGH,
            "medium": SEVERITY_MEDIUM,
            "low": SEVERITY_LOW,
            "info": SEVERITY_INFO,
        }.get(item.get("severity"), SEVERITY_INFO)
        out.append(_r(
            severity,
            "HubSpot",
            item.get("title") or "HubSpot finding",
            item.get("problem") or "",
            item.get("fix") or "",
            item.get("reference"),
        ))
    return out


def _ncsc_tls(results):
    out = []
    ncsc = results.get("ncsc_tls") or {}
    if not ncsc.get("success"):
        return out
    domain = results.get("domain")
    for item in ncsc.get("findings") or []:
        out.append(_r(
            item.get("severity") or SEVERITY_MEDIUM,
            "NCSC TLS",
            item.get("title") or "NCSC TLS finding",
            item.get("problem") or "",
            item.get("fix") or (
                "Align the TLS configuration with NCSC TLS Security Guidelines 2025-05 "
                "(prefer TLS 1.3 + AEAD/ECDHE cipher suites)."
            ),
            item.get("reference") or "https://www.ncsc.nl/en/transport-layer-security-tls/tls-security-guidelines",
            retest=item.get("retest"),
            domain=domain,
        ))
    return out


def _weak_auth(results):
    out = []
    wa = results.get("weak_auth") or {}
    domain = results.get("domain")
    if wa.get("skipped"):
        return out
    if not wa.get("success"):
        if wa.get("error"):
            out.append(_r(
                SEVERITY_INFO,
                "Authentication",
                "Weak-auth scan could not run",
                wa.get("error"),
                "Check weak_auth settings in config/domainlens.json and ensure the feature is enabled only for authorized targets.",
                domain=domain,
            ))
        return out
    if wa.get("weak_credentials_found"):
        findings = wa.get("findings") or []
        samples = []
        for item in findings[:3]:
            user = item.get("username", "?")
            samples.append(f"{user}@{item.get('url', domain)} ({item.get('method', 'basic')})")
        out.append(_r(
            SEVERITY_CRITICAL,
            "Authentication",
            "Weak or default credentials accepted",
            (
                "The server accepted one or more default/weak username/password combinations "
                f"on protected endpoints: {', '.join(samples)}."
            ),
            "Change all default passwords immediately. Enforce strong unique passwords, disable "
            "unused accounts, and prefer SSO/MFA. Restrict admin paths by IP or VPN. "
            "Remove HTTP Basic where possible; use application-level auth with lockout/rate limits.",
            retest=(
                f"Re-run DomainLens with the `weak_auth` check for `{domain}` after remediation. "
                "Confirm protected endpoints reject default credentials and require MFA where applicable."
            ),
            domain=domain,
        ))
    elif wa.get("protected_endpoints"):
        out.append(_r(
            SEVERITY_INFO,
            "Authentication",
            "HTTP Basic endpoints detected (no weak creds found)",
            (
                f"Found {len(wa.get('protected_endpoints') or [])} HTTP Basic protected path(s). "
                "No configured default credentials succeeded in this scan."
            ),
            "Keep strong passwords and monitor these endpoints. Re-run weak-auth checks after changes.",
            domain=domain,
        ))
    return out


def _js_scan(results):
    out = []
    js = results.get("js_scan") or {}
    if not js.get("success"):
        return out
    for f in js.get("findings") or []:
        out.append(_r(
            f.get("severity", SEVERITY_INFO),
            f.get("category", "JavaScript"),
            f.get("title", "JavaScript finding"),
            f.get("detail", ""),
            f.get("fix", "Review and remediate this finding."),
            domain=results.get("domain"),
        ))
    return out


def _active_scan(results):
    out = []
    ac = results.get("active_scan") or {}
    if not ac.get("success") or not ac.get("enabled"):
        return out
    for f in ac.get("findings_graded") or []:
        out.append(_r(
            f.get("severity", SEVERITY_INFO),
            f.get("category", "Active Vulnerability Scan"),
            f.get("title", "Active scan finding"),
            f.get("detail", ""),
            f.get("fix", "Review and remediate this finding."),
            retest=(
                f"Re-run DomainLens with the `active_scan` check for `{results.get('domain')}` "
                "after remediation to confirm the probe no longer triggers."
            ) if results.get("domain") else None,
            domain=results.get("domain"),
        ))
    return out


def _rapid7(results):
    out = []
    data = results.get("rapid7") or {}
    if not data or not data.get("success"):
        return out
    domain = results.get("domain")
    findings = data.get("findings") or []
    max_items = int(data.get("max_advies_items") or 40)
    min_sev = (data.get("min_severity_for_advies") or "medium").lower()
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    threshold = rank.get(min_sev, 2)

    try:
        import rapid7_import
    except ImportError:
        rapid7_import = None

    count = 0
    for finding in findings:
        if rank.get(finding.get("severity"), 99) > threshold:
            continue
        if rapid7_import:
            item = rapid7_import.finding_to_advies(finding, domain=domain)
            out.append(_r(
                item["severity"],
                item["category"],
                item["title"],
                item["problem"],
                item["fix"],
                reference=item.get("reference"),
                retest=item.get("retest"),
                domain=domain,
            ))
        else:
            title = finding.get("title") or "Rapid7 vulnerability"
            out.append(_r(
                finding.get("severity") or "info",
                "rapid7",
                title,
                finding.get("description") or f"Reported on {finding.get('hostname') or domain}",
                finding.get("solution") or "Remediate in InsightVM and re-scan.",
                domain=domain,
            ))
        count += 1
        if count >= max_items:
            break
    return out


def _cdn_hardening(results):
    """CDN-specific Advies (Bunny / Cloudflare / OVH) from NCSC + header findings."""
    out = []
    domain = results.get("domain")
    ncsc = results.get("ncsc_tls") or {}
    opts = ncsc.get("cdn_optimizations") or []
    if not opts:
        try:
            import cdn_hardening
        except ImportError:
            return out
        cdn = results.get("cdn") or cdn_hardening.detect_cdn(
            http_deep=results.get("http_deep"),
            http_headers=results.get("http_headers"),
        )
        opts = cdn_hardening.optimizations_summary(
            cdn,
            tls_deep=results.get("tls_deep"),
            http_headers=results.get("http_headers"),
        )
    # Skip ids already covered by NCSC findings to avoid duplicate Advies rows
    ncsc_ids = {f.get("id") for f in (ncsc.get("findings") or [])}
    skip_map = {
        "cdn-sig-hash": "signature-hash-insufficient",
        "cdn-cipher-order": "cipher-order",
    }
    for item in opts:
        mapped = skip_map.get(item.get("id"))
        if mapped and mapped in ncsc_ids:
            continue
        out.append(_r(
            SEVERITY_HIGH if item.get("id") == "cdn-sig-hash" else SEVERITY_MEDIUM,
            "CDN",
            item.get("title") or "CDN hardening",
            item.get("problem") or (
                f"Detected CDN edge needs hardening for `{domain}`."
                if domain else "CDN edge needs hardening."
            ),
            item.get("fix") or "",
            retest=item.get("retest"),
            domain=domain,
        ))
    return out


def generate(results):
    """Return a sorted list of advies items (problem / fix / retest) for a scan."""
    domain = results.get("domain")
    recs = []
    for fn in (
        _whois, _dnssec, _spf, _dmarc, _non_mailing_domain, _dkim, _mta_sts, _tlsrpt,
        _own_infra, _mx_dane_advice,
        _tls, _ncsc_tls, _cdn_hardening, _weak_auth, _https_redirect, _headers, _ipv6, _blacklist, _ports,
        _osint, _http_deep, _hubspot_cf, _rapid7, _security_audit, _js_scan, _active_scan,
    ):
        try:
            batch = fn(results) or []
        except Exception:
            continue
        for item in batch:
            if domain and not item.get("retest"):
                item["retest"] = _default_retest(item.get("category"), item.get("title"), domain)
            elif domain and "the domain" in (item.get("retest") or ""):
                item["retest"] = (item["retest"] or "").replace("the domain", domain)
            # Ensure every advies item always has retest guidance.
            if not item.get("retest"):
                item["retest"] = _default_retest(item.get("category"), item.get("title"), domain)
            recs.append(item)
    recs.sort(key=lambda r: _SEVERITY_ORDER.get(r["severity"], 99))
    return recs


def summarize_counts(recs):
    counts = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_HIGH: 0,
        SEVERITY_MEDIUM: 0,
        SEVERITY_LOW: 0,
        SEVERITY_INFO: 0,
    }
    for r in recs:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return counts
