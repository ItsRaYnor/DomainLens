"""Minimal SAML 2.0 SP for legacy Entra SSO (OAuth/OIDC preferred).

Supports:
- SP metadata
- HTTP-Redirect AuthnRequest
- HTTP-POST ACS with unsigned or optionally validated assertions

OAuth 2 / OpenID Connect via Azure App Registration remains the preferred
interactive login path. SAML is retained for tenants that still require it.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import secrets
import time
import zlib
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote, urlencode

# defusedxml hardens XML parsing against XXE / billion-laughs. Fall back to the
# stdlib parser only if defusedxml is unavailable (parsing still works, but the
# hardening is lost — defusedxml is listed in requirements.txt).
try:
    from defusedxml.ElementTree import fromstring as _xml_fromstring
    _HAVE_DEFUSEDXML = True
except Exception:  # pragma: no cover
    from xml.etree.ElementTree import fromstring as _xml_fromstring
    _HAVE_DEFUSEDXML = False

from xml.etree import ElementTree as ET

# signxml verifies the XML-DSig signature on SAML assertions. Optional import so
# the app still starts without it, but signature verification then fails closed.
try:
    from signxml import XMLVerifier
    _HAVE_SIGNXML = True
except Exception:  # pragma: no cover
    XMLVerifier = None
    _HAVE_SIGNXML = False

log = logging.getLogger("domainlens.saml")


class SamlValidationError(Exception):
    """Raised when a SAML response cannot be trusted."""

NS = {
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}


def _settings() -> dict:
    try:
        from settings.store import get_store
        return dict(get_store().section("auth_saml", force_reload=True))
    except Exception:
        return {}


def saml_config() -> dict:
    raw = _settings()
    enabled = bool(raw.get("enabled", False)) or (
        (os.environ.get("SAML_ENABLED") or "").strip().lower() in {"1", "true", "yes", "on"}
    )
    entity_id = (
        (raw.get("entity_id") or "")
        or os.environ.get("SAML_ENTITY_ID")
        or os.environ.get("SAML_SP_ENTITY_ID")
        or ""
    ).strip()
    acs_url = (
        (raw.get("acs_url") or "")
        or os.environ.get("SAML_ACS_URL")
        or ""
    ).strip() or None
    idp_entity_id = (
        (raw.get("idp_entity_id") or "")
        or os.environ.get("SAML_IDP_ENTITY_ID")
        or ""
    ).strip()
    idp_sso_url = (
        (raw.get("idp_sso_url") or "")
        or os.environ.get("SAML_IDP_SSO_URL")
        or ""
    ).strip()
    # PEM (or bare base64) X.509 certificate of the IdP used to verify the
    # signature on SAML assertions. Without it, signed responses cannot be
    # validated and login is refused (fail closed).
    idp_cert = (
        (raw.get("idp_cert") or "")
        or os.environ.get("SAML_IDP_CERT")
        or ""
    ).strip()
    # Unsigned assertions are INSECURE (anyone can forge a login). Off by
    # default; only enabled via an explicit, clearly-named opt-in and never
    # when a certificate is configured.
    allow_unsigned = bool(raw.get("allow_unsigned", False))
    if os.environ.get("SAML_INSECURE_ALLOW_UNSIGNED") is not None:
        allow_unsigned = os.environ.get("SAML_INSECURE_ALLOW_UNSIGNED", "0").strip().lower() in {
            "1", "true", "yes", "on"
        }
    expected_audience = (
        (raw.get("audience") or entity_id or "")
        or os.environ.get("SAML_AUDIENCE")
        or ""
    ).strip()
    configured = bool(enabled and idp_sso_url and (idp_cert or allow_unsigned))
    return {
        "enabled": enabled,
        "configured": configured,
        "preferred": False,  # OAuth is preferred
        "legacy": True,
        "entity_id": entity_id or None,
        "acs_url": acs_url,
        "idp_entity_id": idp_entity_id or None,
        "idp_sso_url": idp_sso_url or None,
        "idp_cert": idp_cert or None,
        "allow_unsigned": allow_unsigned,
        "audience": expected_audience or None,
        "display_name": (raw.get("display_name") or "Microsoft Entra ID (SAML legacy)").strip(),
    }


def saml_status() -> dict:
    cfg = saml_config()
    return {
        "enabled": cfg["enabled"],
        "configured": cfg["configured"],
        "preferred": False,
        "legacy": True,
        "sso_path": "/auth/saml/login",
        "acs_path": "/auth/saml/acs",
        "metadata_path": "/auth/saml/metadata",
        "note": "Prefer OAuth 2 / OpenID Connect (Azure App Registration). SAML is legacy fallback.",
    }


def _deflate_base64(xml: str) -> str:
    compressed = zlib.compress(xml.encode("utf-8"))[2:-4]  # raw DEFLATE
    return base64.b64encode(compressed).decode("ascii")


def build_authn_request(*, entity_id: str, acs_url: str, idp_sso_url: str, force_authn: bool = False) -> str:
    req_id = f"_{secrets.token_hex(16)}"
    issue_instant = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    force = "true" if force_authn else "false"
    xml = (
        f'<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{req_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'Destination="{idp_sso_url}" AssertionConsumerServiceURL="{acs_url}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'ForceAuthn="{force}">'
        f"<saml2:Issuer>{entity_id}</saml2:Issuer>"
        f'<saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" '
        f'AllowCreate="true"/>'
        f"</saml2p:AuthnRequest>"
    )
    relay = ""
    params = {
        "SAMLRequest": _deflate_base64(xml),
    }
    if relay:
        params["RelayState"] = relay
    sep = "&" if "?" in idp_sso_url else "?"
    return f"{idp_sso_url}{sep}{urlencode(params)}"


def build_sp_metadata(*, entity_id: str, acs_url: str) -> str:
    return (
        f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">'
        f'<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>'
        f'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{acs_url}" index="0" isDefault="true"/>'
        f"</md:SPSSODescriptor>"
        f"</md:EntityDescriptor>"
    )


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _find_text(root: ET.Element, names: tuple[str, ...]) -> Optional[str]:
    for el in root.iter():
        if _local(el.tag) in names and (el.text or "").strip():
            return el.text.strip()
    return None


def _attr_values(root: ET.Element) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for el in root.iter():
        if _local(el.tag) != "Attribute":
            continue
        name = el.attrib.get("Name") or el.attrib.get("FriendlyName") or ""
        values = []
        for child in list(el):
            if _local(child.tag) == "AttributeValue" and (child.text or "").strip():
                values.append(child.text.strip())
        if name and values:
            out[name] = values
    return out


def _assert_status_success(root: ET.Element) -> None:
    status = None
    for el in root.iter():
        if _local(el.tag) == "StatusCode":
            status = el.attrib.get("Value")
            break
    if status and "Success" not in status:
        raise SamlValidationError(f"SAML status not success: {status}")


def _normalize_cert(cert: str) -> str:
    """Accept a bare base64 body or full PEM and return PEM."""
    cert = (cert or "").strip()
    if "BEGIN CERTIFICATE" in cert:
        return cert
    body = re.sub(r"\s+", "", cert)
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def _check_conditions(root: ET.Element, expected_audience: Optional[str]) -> None:
    """Enforce NotBefore/NotOnOrAfter and Audience restrictions."""
    now = datetime.now(timezone.utc)
    for el in root.iter():
        if _local(el.tag) != "Conditions":
            continue
        nb = el.attrib.get("NotBefore")
        na = el.attrib.get("NotOnOrAfter")
        if nb and now < _parse_instant(nb):
            raise SamlValidationError("SAML assertion not yet valid (NotBefore)")
        if na and now >= _parse_instant(na):
            raise SamlValidationError("SAML assertion expired (NotOnOrAfter)")
    if expected_audience:
        audiences = [
            (a.text or "").strip()
            for a in root.iter()
            if _local(a.tag) == "Audience" and (a.text or "").strip()
        ]
        if audiences and expected_audience not in audiences:
            raise SamlValidationError("SAML audience mismatch")


def _parse_instant(value: str) -> datetime:
    value = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_saml_response(saml_response_b64: str, cfg: Optional[dict] = None) -> dict:
    """Parse and validate a base64 SAMLResponse, returning a login profile.

    Security: when an IdP certificate is configured (the supported, secure
    setup) the XML-DSig signature is verified with signxml and identity is
    taken ONLY from the cryptographically-signed subtree. Unsigned responses
    are rejected unless the operator explicitly opted into the insecure
    allow_unsigned mode AND no certificate is configured.
    """
    if cfg is None:
        cfg = saml_config()

    raw = base64.b64decode(saml_response_b64)
    # Some IdPs wrap with compression; try plain XML first
    try:
        xml = raw.decode("utf-8")
    except UnicodeDecodeError:
        xml = zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8")

    idp_cert = cfg.get("idp_cert")
    allow_unsigned = bool(cfg.get("allow_unsigned")) and not idp_cert

    if idp_cert:
        if not _HAVE_SIGNXML:
            raise SamlValidationError(
                "signxml is required to verify SAML signatures but is not installed"
            )
        try:
            verifier = XMLVerifier()
            verified = verifier.verify(
                xml.encode("utf-8"),
                x509_cert=_normalize_cert(idp_cert),
            )
        except Exception as exc:
            raise SamlValidationError(f"SAML signature verification failed: {exc}")
        # Identity is taken only from the verified (signed) element.
        signed = verified.signed_xml
        root = ET.fromstring(ET.tostring(signed)) if signed is not None else _xml_fromstring(xml)
        # Status is on the outer response; parse it defensively for the reason.
        outer = _xml_fromstring(xml)
        _assert_status_success(outer)
    elif allow_unsigned:
        log.warning(
            "SAML: accepting UNSIGNED assertion (insecure allow_unsigned mode). "
            "Configure idp_cert to enable signature validation."
        )
        root = _xml_fromstring(xml)
        _assert_status_success(root)
    else:
        raise SamlValidationError(
            "SAML is not configured securely: set an IdP certificate (idp_cert) "
            "to verify signatures, or explicitly enable allow_unsigned."
        )

    _check_conditions(root, cfg.get("audience"))

    name_id = _find_text(root, ("NameID",))
    attrs = _attr_values(root)
    email = name_id
    for key in (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "email",
        "mail",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "http://schemas.microsoft.com/identity/claims/emailaddress",
    ):
        if key in attrs and attrs[key]:
            email = attrs[key][0]
            break
    display = None
    for key in (
        "http://schemas.microsoft.com/identity/claims/displayname",
        "displayName",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "givenname",
    ):
        if key in attrs and attrs[key]:
            display = attrs[key][0]
            break
    if not email or "@" not in email:
        raise ValueError("SAML response missing email NameID/claim")
    email = email.strip().lower()
    return {
        "id": name_id or email,
        "email": email,
        "name": display or email.split("@")[0],
        "provider": "saml",
        "sub": name_id or email,
    }
