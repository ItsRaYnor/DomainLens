"""Which secret signs what, and refusing the ones printed in our own docs.

The compose files and the README ship an example DOMAINLENS_SECRET_KEY. An
installation started from them unchanged signed its session cookies and its
SCIM access tokens with a value anyone can read on GitHub: forge a cookie
naming an admin and you are one, forge a SCIM token and you can provision
your own account.

For signing, a published example is therefore treated as no key at all and
the persisted random secret is used instead. That signs everyone out once and
costs nothing else: a signature only has to be checked by this installation.

Encryption of stored credentials is different. Those were encrypted with the
example value, and switching keys would make them unreadable, so encryption
keeps using it -- and the settings page says plainly that the key is public.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger("domainlens.app_secret")

# Every example value this repository has published for the key.
PUBLISHED_EXAMPLES = frozenset({
    "change-me-openssl-rand-hex-32",
    "long-random-string",
})


def configured_key() -> str:
    """DOMAINLENS_SECRET_KEY (or its old alias) exactly as the operator set it."""
    return (os.environ.get("DOMAINLENS_SECRET_KEY")
            or os.environ.get("FLASK_SECRET_KEY") or "").strip()


def is_published(value: str) -> bool:
    return (value or "").strip().lower() in PUBLISHED_EXAMPLES


def signing_secret(*, override: str = "") -> str:
    """The key to sign with: a configured one unless it is a published example.

    `override` is a purpose-specific key (SCIM_TOKEN_SIGNING_KEY) tried first,
    under the same rule. Falls back to the random secret persisted in the
    database; raises when that cannot be had either, so nothing ever signs
    with a guessable value.
    """
    for candidate, name in ((override.strip(), "signing key"),
                            (configured_key(), "DOMAINLENS_SECRET_KEY")):
        if not candidate:
            continue
        if is_published(candidate):
            log.error("%s is the example value from the DomainLens documentation; "
                      "it is not used for signing. Generate your own: openssl rand -hex 32",
                      name)
            continue
        return candidate
    import db as _db
    return _db.get_or_create_app_secret()
