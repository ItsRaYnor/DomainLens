"""What a scan measured, next to the advice drawn from it.

An advice item said what to change ("restrict ciphers to AEAD suites") but
not what the scan saw, so an operator who wanted to check the claim, or hand
it to the team that runs the server, went looking through the tabs. Each
item now carries the few lines of measured output it rests on: the cipher
suites by name, the header that was or was not sent, the record as found.

Only measured values are written here. A check that did not run, or a field
it could not fill, gives no line, not an invented "none" -- the page then
offers the check's raw output instead.
"""

from __future__ import annotations

# Long lists are cut so an advice item stays readable; the raw output on the
# page keeps everything.
MAX_LINES = 25


def _cut(lines):
    lines = [str(line) for line in lines if line]
    if len(lines) <= MAX_LINES:
        return lines
    rest = len(lines) - MAX_LINES
    return lines[:MAX_LINES] + [f"... and {rest} more in the raw output"]


def _ok(block):
    return isinstance(block, dict) and block.get("success") is not False and bool(block)


# ----- TLS -----------------------------------------------------------------

def _ncsc_levels(results):
    ncsc = results.get("ncsc_tls") or {}
    if not ncsc.get("success"):
        return {}
    return {c.get("name"): c for c in ncsc.get("ciphers") or [] if c.get("name")}


# The part of a suite the NCSC rates down, so "RSA" reads as key exchange.
_ROLES = {
    "key_exchange": "{} key exchange",
    "authentication": "{} authentication",
    "bulk_encryption": "{}",
    "hash": "{} hash",
}


def _cipher_line(cipher, ncsc_entry=None):
    parts = [cipher.get("name") or "?"]
    if cipher.get("protocol"):
        parts.append(cipher["protocol"])
    if cipher.get("strength"):
        parts.append(cipher["strength"])
    if ncsc_entry:
        level = ncsc_entry.get("label") or ncsc_entry.get("level")
        comp = ncsc_entry.get("components") or {}
        weak = [_ROLES[key].format(part["name"]) for key in _ROLES
                if (part := comp.get(key)) and part.get("level") in ("insufficient", "phased_out")
                and part.get("name")]
        parts.append(f"NCSC {level}" + (f" ({', '.join(weak)})" if weak else ""))
    return " · ".join(parts)


def _weak_ciphers(results):
    """Suites rated weak or insecure here, or Insufficient by the NCSC."""
    tls = results.get("tls_deep") or {}
    ncsc = _ncsc_levels(results)
    lines, seen = [], set()
    for c in tls.get("ciphers") or [] if tls.get("success") else []:
        entry = ncsc.get(c.get("name"))
        if c.get("strength") in ("weak", "insecure") or (entry and entry.get("level") == "insufficient"):
            lines.append(_cipher_line(c, entry))
            seen.add(c.get("name"))
    for name, entry in ncsc.items():
        if name not in seen and entry.get("level") == "insufficient":
            lines.append(_cipher_line({"name": name, "protocol": entry.get("protocol")}, entry))
    return lines


def _phased_out_ciphers(results):
    return [_cipher_line({"name": name, "protocol": entry.get("protocol")}, entry)
            for name, entry in _ncsc_levels(results).items() if entry.get("level") == "phased_out"]


def _no_forward_secrecy(results):
    tls = results.get("tls_deep") or {}
    if not tls.get("success"):
        return []
    return [f"{c.get('name')} · {c.get('protocol') or '?'} · no forward secrecy"
            for c in tls.get("ciphers") or [] if c.get("forward_secrecy") is False]


def _cipher_order(results):
    order = (results.get("ncsc_tls") or {}).get("cipher_order") or (results.get("tls_deep") or {}).get("cipher_order") or {}
    if not order.get("applicable") or order.get("pass") is not False:
        return []
    lines = [
        f"Server picks first: {order.get('server_preferred_iana') or order.get('server_preferred')}"
        f" ({order.get('server_preferred_level') or '?'})",
        f"Expected first: {order.get('expected_preferred_iana') or order.get('expected_preferred')}"
        f" ({order.get('expected_preferred_level') or '?'})",
    ]
    worse = order.get("worse_suites") or []
    if worse:
        lines.append("Weaker suites the server accepts: " + ", ".join(worse))
    return lines


def _protocols(results):
    tls = results.get("tls_deep") or {}
    ncsc = {p.get("name"): p for p in (results.get("ncsc_tls") or {}).get("protocols") or []}
    lines = []
    for p in tls.get("protocols") or [] if tls.get("success") else []:
        state = "enabled" if p.get("supported") else "disabled"
        level = ncsc.get(p.get("name"), {}).get("label") if p.get("supported") else None
        lines.append(f"{p.get('name')}: {state}" + (f" · NCSC {level}" if level else ""))
    return lines


def _hsts(results):
    hsts = (results.get("tls_deep") or {}).get("hsts")
    if isinstance(hsts, dict) and hsts:
        lines = []
        if hsts.get("checked_url"):
            status = f" (HTTP {hsts['status_code']})" if hsts.get("status_code") else ""
            lines.append(f"Checked {hsts['checked_url']}{status}")
        if hsts.get("blocked") or hsts.get("enabled") is None:
            lines.append("Strict-Transport-Security: could not be read"
                         + (f" ({hsts['block_detail']})" if hsts.get("block_detail") else ""))
        elif hsts.get("value"):
            lines.append(f"Strict-Transport-Security: {hsts['value']}")
        elif hsts.get("enabled") is False:
            lines.append("Strict-Transport-Security: not sent")
        return lines
    headers = results.get("http_headers") or {}
    if headers.get("success"):
        value = (headers.get("headers_found") or {}).get("Strict-Transport-Security")
        return [f"Strict-Transport-Security: {value}" if value else "Strict-Transport-Security: not sent"]
    return []


def _ocsp(results):
    tls = results.get("tls_deep") or {}
    if not tls.get("success") or tls.get("ocsp_stapling") is None:
        return []
    lines = [f"OCSP response stapled: {'yes' if tls['ocsp_stapling'] else 'no'}"]
    uris = (tls.get("certificate") or {}).get("ocsp_uris")
    if uris is not None:
        lines.append("OCSP responder in certificate: " + (", ".join(uris) if uris else "none"))
    return lines


def _certificate(results):
    cert = (results.get("tls_deep") or {}).get("certificate") or {}
    ssl = results.get("ssl") or {}
    lines = []
    if cert.get("verify_reason"):
        # The certificate that answered may not be the site's: name it.
        presented = cert.get("presented") or {}
        lines.append(f"Verification: {cert['verify_reason']}")
        if presented.get("issuer"):
            lines.append(f"Presented certificate issued by: {presented['issuer']}")
        if presented.get("subject") or presented.get("san"):
            names = ", ".join(presented.get("san") or [presented.get("subject")])
            lines.append(f"Presented certificate is for: {names}")
        return lines
    if cert.get("issuer_org"):
        lines.append(f"Issuer: {cert['issuer_org']}")
    elif (ssl.get("issuer") or {}).get("organizationName"):
        lines.append(f"Issuer: {ssl['issuer']['organizationName']}")
    if ssl.get("not_after"):
        lines.append(f"Valid until: {ssl['not_after']}")
    days = cert.get("days_until_expiry", ssl.get("days_until_expiry"))
    if days is not None:
        lines.append(f"Days remaining: {days}")
    if cert.get("self_signed") is not None:
        lines.append(f"Self-signed: {'yes' if cert['self_signed'] else 'no'}")
    return lines


def _compression(results):
    tls = results.get("tls_deep") or {}
    if not tls.get("success") or tls.get("tls_compression") is None:
        return []
    return [f"TLS compression: {'enabled' if tls['tls_compression'] else 'disabled'}"]


def _signature_hashes(results):
    hashes = (results.get("ncsc_tls") or {}).get("signature_hashes")
    if isinstance(hashes, dict):
        hashes = hashes.get("hashes") or hashes.get("offered") or []
    return [f"{h.get('name')}: NCSC {h.get('label') or h.get('level')}" if isinstance(h, dict) else str(h)
            for h in hashes or []]


# ----- Mail and DNS --------------------------------------------------------

def _txt(block, name, where):
    if not isinstance(block, dict) or block.get("state") not in (None, "measured"):
        return []
    records = block.get("records") or ([block["record"]] if block.get("record") else [])
    if records:
        return [f"{where}: {r}" for r in records]
    if block.get("found") is False:
        return [f"No {name} record at {where}"]
    return []


def _dkim(block):
    if not isinstance(block, dict):
        return []
    lines = []
    for sel in block.get("selectors") or []:
        state = " (revoked: empty key)" if sel.get("revoked") else ""
        lines.append(f"Selector {sel.get('selector')}: {sel.get('record') or '?'}{state}")
    if not lines and block.get("found") is False:
        lines.append("No DKIM key found under the selectors that were tried")
    return lines


def _dnssec(block):
    if not isinstance(block, dict) or block.get("state") not in (None, "measured"):
        return []
    lines = []
    if block.get("status"):
        lines.append(block["status"])
    for key, label in (("has_ds", "DS record at the parent"), ("has_dnskey", "DNSKEY in the zone")):
        if block.get(key) is not None:
            lines.append(f"{label}: {'yes' if block[key] else 'no'}")
    return lines


# ----- Web -----------------------------------------------------------------

def _redirect(results, domain):
    red = results.get("https_redirect") or {}
    if not red or red.get("status_code") is None:
        return []
    return [f"http://{domain}/ answered HTTP {red['status_code']}",
            f"Location: {red.get('location') or 'none'}"]


def _headers(results, rec, title):
    headers = results.get("http_headers") or {}
    if not headers.get("success"):
        return []
    found = headers.get("headers_found") or {}
    csp = (headers.get("csp") or {}).get("raw") or found.get("Content-Security-Policy")
    lines = []
    if headers.get("final_url"):
        lines.append(f"Response from {headers['final_url']} (HTTP {headers.get('status_code')})")
    if "clickjacking" in title or "x-frame-options" in title:
        xfo = (headers.get("framing") or {}).get("x_frame_options") or found.get("X-Frame-Options")
        lines.append(f"X-Frame-Options: {xfo}" if xfo else "X-Frame-Options: not sent")
        lines.append(f"Content-Security-Policy: {csp}" if csp else "Content-Security-Policy: not sent")
    elif "content-security-policy" in title or "csp" in title.split():
        lines.append(f"Content-Security-Policy: {csp}" if csp else "Content-Security-Policy: not sent")
    elif rec.get("headers"):
        lines.append("Not sent: " + ", ".join(rec["headers"]))
        if found:
            lines.append("Sent: " + ", ".join(found))
    return lines


# ----- Network -------------------------------------------------------------

def _ports(block):
    if not isinstance(block, dict) or "open" not in block:
        return []
    ip = f" on {block['ip']}" if block.get("ip") else ""
    open_ports = ", ".join(f"{p.get('port')}/{p.get('service')}" for p in block.get("open") or [])
    return [f"Open{ip}: {open_ports or 'none'}"]


def _blacklist(block):
    if not isinstance(block, dict):
        return []
    lines = [f"Listed on {entry}" if isinstance(entry, str) else
             f"Listed on {entry.get('list') or entry.get('zone') or entry}" for entry in block.get("listed") or []]
    if block.get("ip") and lines:
        lines.insert(0, f"Address checked: {block['ip']}")
    return lines


def _ipv6(block):
    if not isinstance(block, dict):
        return []
    lines = []
    if "aaaa_records" in block:
        lines.append("AAAA: " + (", ".join(block["aaaa_records"]) or "none"))
    mx = block.get("mx_ipv6")
    if isinstance(mx, dict) and block.get("mx_hosts"):
        for host in block["mx_hosts"]:
            lines.append(f"MX {host}: " + (", ".join(mx.get(host) or []) or "no IPv6 address"))
    return lines


def _whois(block):
    data = (block or {}).get("data") or {}
    exp = data.get("expiration_date")
    if isinstance(exp, list):
        exp = exp[0] if exp else None
    lines = [f"Expiration date: {exp}"] if exp else []
    if data.get("registrar"):
        lines.append(f"Registrar: {data['registrar']}")
    return lines


def lines_for(results, rec, key):
    """The measured lines behind one advice item; [] when there are none."""
    title = " ".join(str(rec.get("title") or "").lower().split())
    check = rec.get("check") or ""
    sources = rec.get("sources") or []
    domain = results.get("domain") or ""

    if rec.get("evidence"):
        return _cut(rec["evidence"])
    if key == "tls:cipher:insufficient" or check == "cipher-insufficient":
        return _cut(_weak_ciphers(results))
    if check == "cipher-phased-out":
        return _cut(_phased_out_ciphers(results))
    if "forward secrecy" in title:
        return _cut(_no_forward_secrecy(results))
    if check == "cipher-order" or "cipher suite order" in title:
        return _cut(_cipher_order(results))
    if key.startswith("tls:protocol") or check.startswith("proto-"):
        return _protocols(results)
    if "hsts" in title:
        return _hsts(results)
    if key == "tls:ocsp" or check == "ocsp-stapling":
        return _ocsp(results)
    if key == "tls:compression" or check == "tls-compression":
        return _compression(results)
    if check.startswith("signature-hash"):
        return _cut(_signature_hashes(results))
    if rec.get("category") == "Certificate" or check.startswith("cert-"):
        return _certificate(results)
    if "tls grade" in title and (results.get("tls_deep") or {}).get("certificate", {}).get("verify_reason"):
        return _certificate(results)
    if "tls grade" in title:
        return _cut((results.get("tls_deep") or {}).get("warnings") or [])

    source = sources[0] if sources else ""
    if source == "spf":
        return _txt(results.get("spf"), "SPF", domain)
    if source == "dmarc":
        return _txt(results.get("dmarc"), "DMARC", f"_dmarc.{domain}")
    if source == "dkim":
        return _cut(_dkim(results.get("dkim")))
    if source == "mta_sts":
        return _txt(results.get("mta_sts"), "MTA-STS", f"_mta-sts.{domain}")
    if source == "tlsrpt":
        return _txt(results.get("tlsrpt"), "TLS-RPT", f"_smtp._tls.{domain}")
    if source == "dnssec":
        return _dnssec(results.get("dnssec"))
    if source == "https_redirect":
        return _redirect(results, domain)
    if source == "http_headers":
        return _cut(_headers(results, rec, title))
    if source == "ports":
        return _ports(results.get("ports"))
    if source == "blacklist":
        return _cut(_blacklist(results.get("blacklist")))
    if source == "ipv6":
        return _cut(_ipv6(results.get("ipv6")))
    if source == "whois":
        return _whois(results.get("whois"))
    return []
