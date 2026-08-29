"""Build this installation's own /.well-known/security.txt (RFC 9116).

DomainLens already checks other people's security.txt. This publishes one of
its own, pointing at the public half of a key generated here.

Two rules from the RFC drive the shape of this file:

  Contact is mandatory. Without it the file says nothing actionable, so an
  installation with no contact publishes nothing at all rather than a
  well-formed file that wastes a researcher's time.

  Expires is mandatory and must be under a year out. It is computed at
  request time from a configured number of days, so the file cannot quietly
  go stale the way a hand-written date does.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

# Where this app serves the armoured public key. Referenced by the
# Encryption: field, and by the admin UI so the two cannot drift apart.
PUBLIC_KEY_PATH = "/.well-known/pgp-key.asc"
SECURITY_TXT_PATH = "/.well-known/security.txt"

# RFC 9116 section 2.5.5: "The value of this field MUST NOT be in the past"
# and SHOULD be less than a year out. Anything longer is clamped rather than
# published, because a file promising a five-year window is worse than none.
MAX_EXPIRY_DAYS = 365


def _clean(value):
    """One line, no control characters.

    Every value here is operator-supplied and lands in a line-oriented text
    format, so a stray newline would forge a second field.
    """
    text = str(value or "").strip()
    return " ".join(text.split())


def _contacts(raw):
    """Contact may repeat and is ordered by preference (RFC 9116 s2.5.3).

    A bare address is accepted and turned into a mailto: URI: it is the most
    common thing to type, and publishing it unscheme'd would be invalid.
    """
    values = []
    for part in str(raw or "").replace(";", ",").split(","):
        item = _clean(part)
        if not item:
            continue
        if "://" not in item and not item.lower().startswith(("mailto:", "tel:")):
            item = f"mailto:{item}" if "@" in item else item
        values.append(item)
    return values


def expiry_for(days, now=None):
    now = now or datetime.now(timezone.utc)
    days = max(1, min(int(days or MAX_EXPIRY_DAYS), MAX_EXPIRY_DAYS))
    return (now + timedelta(days=days)).replace(microsecond=0)


def build(config, base_url=None, now=None, has_key=False):
    """Render the file, or return None when there is nothing valid to say.

    None means "do not serve this": the route turns it into a 404, which is
    the honest answer for an installation that has not configured disclosure.
    """
    if not config or not config.get("enabled"):
        return None
    contacts = _contacts(config.get("contact"))
    if not contacts:
        return None

    lines = []
    for contact in contacts:
        lines.append(f"Contact: {contact}")

    expires = expiry_for(config.get("expires_days"), now=now)
    lines.append("Expires: " + expires.strftime("%Y-%m-%dT%H:%M:%SZ"))

    if has_key and base_url:
        lines.append("Encryption: " + urljoin(base_url, PUBLIC_KEY_PATH))

    for field, key in (("Policy", "policy_url"),
                       ("Acknowledgments", "acknowledgments_url")):
        value = _clean(config.get(key))
        if value:
            lines.append(f"{field}: {value}")

    languages = _clean(config.get("preferred_languages"))
    if languages:
        lines.append(f"Preferred-Languages: {languages}")

    canonical = _clean(config.get("canonical_url")) or (
        urljoin(base_url, SECURITY_TXT_PATH) if base_url else "")
    if canonical:
        lines.append(f"Canonical: {canonical}")

    return "\n".join(lines) + "\n"


_SECURITYTXT_FIELD_RE = re.compile(r"(?im)^([A-Za-z-]+)\s*:\s*(.+?)\s*$")


def parse_security_txt(body):
    """Pull the RFC 9116 fields out of a security.txt body.

    Comments and the PGP signature wrapper of a signed file are ignored:
    only real "Field: value" lines count. Field names are case-insensitive
    per the RFC, so they are lowercased here; values are kept verbatim
    because URLs and addresses are case-sensitive.
    """
    fields = {}
    if not body:
        return fields
    in_signature = False
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("-----BEGIN PGP SIGNATURE-----"):
            in_signature = True
            continue
        if stripped.startswith("-----END PGP SIGNATURE-----"):
            in_signature = False
            continue
        if in_signature or not stripped or stripped.startswith("#"):
            continue
        match = _SECURITYTXT_FIELD_RE.match(stripped)
        if not match:
            continue
        # Multi-valued per the RFC (several Contact: lines are normal), so
        # every occurrence is kept rather than the last one winning.
        fields.setdefault(match.group(1).lower(), []).append(match.group(2))
    return fields


# --- Validation ------------------------------------------------------------
# RFC 9116 section 2.5. Only the two mandatory fields make a file invalid;
# everything else is advice, and it is labelled as such so an operator can
# tell "this file is broken" from "this file could say more".

_KNOWN_FIELDS = {
    "acknowledgments", "canonical", "contact", "encryption", "expires",
    "hiring", "policy", "preferred-languages", "csaf",
}


def validate(body, now=None):
    """Check a pasted security.txt against RFC 9116.

    Returns problems split by severity. An unparseable date and a missing
    Expires are both errors, but a field we do not recognise is only a note:
    the registry grows, and refusing an unknown field would make this tool
    wrong before the RFC changes.
    """
    from datetime import datetime, timezone as _tz

    now = now or datetime.now(_tz.utc)
    result = {"valid": False, "errors": [], "warnings": [], "notes": [],
              "fields": {}, "expires": None}
    text = (body or "").strip()
    if not text:
        result["errors"].append("The file is empty.")
        return result

    fields = parse_security_txt(text)
    result["fields"] = fields

    if not fields.get("contact"):
        result["errors"].append(
            "No Contact field. It is mandatory (RFC 9116 s2.5.3) and is the "
            "one thing a researcher actually needs.")
    else:
        for value in fields["contact"]:
            if "://" not in value and not value.lower().startswith(("mailto:", "tel:")):
                result["warnings"].append(
                    f"Contact '{value}' is not a URI. Use mailto:, tel: or https://.")

    expires = fields.get("expires") or []
    if not expires:
        result["errors"].append(
            "No Expires field. It is mandatory (RFC 9116 s2.5.5); without it "
            "a reader cannot tell whether this file is still maintained.")
    else:
        if len(expires) > 1:
            result["errors"].append("More than one Expires field; only one is allowed.")
        parsed = _parse_expires(expires[0])
        if parsed is None:
            result["errors"].append(
                f"Expires '{expires[0]}' is not a valid ISO 8601 timestamp.")
        else:
            result["expires"] = parsed.isoformat()
            if parsed <= now:
                result["errors"].append(
                    f"Expires is in the past ({expires[0]}); the file is stale "
                    "and tooling will ignore it.")
            elif (parsed - now).days > MAX_EXPIRY_DAYS:
                result["warnings"].append(
                    "Expires is more than a year out; RFC 9116 says it should "
                    "be less, so the file gets re-checked.")

    if not fields.get("encryption"):
        result["notes"].append(
            "No Encryption field. It is optional, so this is a choice rather "
            "than a fault, but researchers have no way to encrypt a report.")
    if not fields.get("policy"):
        result["notes"].append("No Policy field pointing at your disclosure policy.")
    if not fields.get("canonical"):
        result["notes"].append(
            "No Canonical field. Without it a copy of this file served "
            "elsewhere cannot be told apart from the original.")

    for name in fields:
        if name not in _KNOWN_FIELDS:
            result["notes"].append(f"'{name}' is not a field defined in RFC 9116.")

    result["valid"] = not result["errors"]
    return result


def _parse_expires(value):
    from datetime import datetime, timezone as _tz
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_tz.utc)
    return parsed
