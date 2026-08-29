"""OpenPGP keypair generation for responsible-disclosure contacts.

DomainLens helps you create and publish a key. It deliberately does not keep
the secret half.

The private key is generated in a throwaway GNUPGHOME, handed back to the
caller once, and the directory is removed before this module returns. Nothing
here writes it to the database, to settings, or to disk under /data. That is
the whole design: a stolen backup of a DomainLens install must not hand the
thief the key that decrypts vulnerability reports about their target.

Shelling out to gpg rather than adding an OpenPGP library is deliberate too.
The pure-Python option (PGPy 0.6.0, the newest release) no longer imports on
Python 3.13+ -- it needs `imghdr`, removed from the stdlib by PEP 594 -- and
declares `cryptography>=3.3.2` with no upper bound, which is the same trap
that already cost this project a pinned signxml. gpg is maintained, and key
material is the last place to accept a stale dependency.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

# gpg is a system package, not a Python one; it is installed in the image.
GPG_BINARY = os.environ.get("DOMAINLENS_GPG", "gpg")

# Where the throwaway GNUPGHOME is created. Point it at a tmpfs and the secret
# key never touches persistent storage at all -- the directory it lives in for
# those few seconds is the one place on disk it could otherwise be recovered
# from. Defaults to the system temp directory.
GPG_HOME_BASE = os.environ.get("DOMAINLENS_PGP_HOME_BASE") or None

_TIMEOUT = 180

# Key generation gathers entropy and can genuinely take a while on a small
# container, so this is not the usual few-second budget.
_ARMOR_PUBLIC = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
_ARMOR_PRIVATE = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
_ARMOR_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"
_ARMOR_MESSAGE = "-----BEGIN PGP MESSAGE-----"

_UID_NAME_RE = re.compile(r"^[^<>()@\x00-\x1f]{1,80}$")
_UID_EMAIL_RE = re.compile(r"^[^@\s<>()\x00-\x1f]+@[^@\s<>()\x00-\x1f]+\.[a-zA-Z]{2,}$")
_EXPIRY_RE = re.compile(r"^(0|\d{1,3}[dwmy])$")


class PgpError(RuntimeError):
    """A generation we could not complete, as opposed to bad input."""


class PgpInputError(ValueError):
    """Input we refuse, before any process is started."""


def available() -> bool:
    """True when a usable gpg is on PATH.

    Checked before the UI offers generation, so an install without gpg says
    so plainly instead of failing halfway through a key generation.
    """
    try:
        result = subprocess.run(
            [GPG_BINARY, "--version"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def version() -> str | None:
    try:
        result = subprocess.run(
            [GPG_BINARY, "--version"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    first = (result.stdout or "").splitlines()
    return first[0].strip() if first else None


def _validate(name, email, expiry):
    name = (name or "").strip()
    email = (email or "").strip()
    expiry = (expiry or "2y").strip().lower()
    # The uid is interpolated into a gpg argument. It is passed as a list
    # element so there is no shell to escape for, but angle brackets and
    # newlines would still corrupt the uid itself.
    if not _UID_NAME_RE.match(name):
        raise PgpInputError(
            "Enter a name of at most 80 characters, without <, >, @ or line breaks")
    if not _UID_EMAIL_RE.match(email):
        raise PgpInputError(f"{email!r} is not a valid email address")
    if not _EXPIRY_RE.match(expiry):
        raise PgpInputError(
            "Expiry must look like 2y, 18m, 90d or 0 for no expiry")
    return name, email, expiry


def _run(home, args, passphrase=None, stdin_text=None):
    command = [GPG_BINARY, "--batch", "--yes", "--no-tty"]
    if passphrase is not None:
        # loopback keeps gpg from trying to open a pinentry dialog, which has
        # no one to talk to in a container.
        command += ["--pinentry-mode", "loopback", "--passphrase", passphrase]
    command += list(args)
    try:
        return subprocess.run(
            command,
            env={**os.environ, "GNUPGHOME": home},
            input=stdin_text,
            capture_output=True, text=True, timeout=_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise PgpError("gpg did not finish in time") from exc
    except OSError as exc:
        raise PgpError(f"Could not run gpg: {exc}") from exc


def generate(name, email, passphrase="", expiry="2y"):
    """Create a keypair and return both halves to the caller, once.

    The returned dict carries `private_key`. It is the only copy that will
    ever exist: this function keeps nothing, and callers must not persist it.
    Store `public_key` and `fingerprint`; hand the private key to the
    operator and forget it.
    """
    name, email, expiry = _validate(name, email, expiry)
    uid = f"{name} <{email}>"

    home = tempfile.mkdtemp(prefix="domainlens-pgp-", dir=GPG_HOME_BASE)
    try:
        # 0700: on a shared host the secret key exists inside this directory
        # for the moments between generation and export.
        os.chmod(home, 0o700)
        result = _run(home, [
            "--quick-generate-key", uid, "default", "default", expiry,
        ], passphrase=passphrase or "")
        if result.returncode != 0:
            raise PgpError(_clean_error(result.stderr))

        listing = _run(home, ["--list-keys", "--with-colons"])
        fingerprint = _first_fingerprint(listing.stdout)
        if not fingerprint:
            raise PgpError("gpg generated a key but reported no fingerprint")

        public = _run(home, ["--armor", "--export", fingerprint])
        if public.returncode != 0 or _ARMOR_PUBLIC not in (public.stdout or ""):
            raise PgpError("gpg did not return an armoured public key")

        private = _run(home, ["--armor", "--export-secret-keys", fingerprint],
                       passphrase=passphrase or "")
        if private.returncode != 0 or _ARMOR_PRIVATE not in (private.stdout or ""):
            raise PgpError("gpg did not return an armoured private key")

        return {
            "fingerprint": fingerprint,
            "uid": uid,
            "public_key": public.stdout,
            "private_key": private.stdout,
            "expiry": expiry,
            "protected": bool(passphrase),
        }
    finally:
        # Unconditional: an exception halfway through must not leave a secret
        # key sitting in the system temp directory.
        shutil.rmtree(home, ignore_errors=True)


def _first_fingerprint(colon_listing):
    for line in (colon_listing or "").splitlines():
        if line.startswith("fpr:"):
            parts = line.split(":")
            if len(parts) > 9 and parts[9]:
                return parts[9]
    return None


def _clean_error(stderr):
    """gpg is chatty on stderr even when it succeeds; keep the last real line.

    Paths are dropped: they name the temporary directory, which tells the
    reader nothing and hints at internals.
    """
    lines = [l.strip() for l in (stderr or "").splitlines() if l.strip()]
    meaningful = [l for l in lines if "created" not in l and "directory" not in l]
    message = (meaningful or lines or ["gpg failed"])[-1]
    return re.sub(r"'[^']*'", "'...'", message)[:200]


def inspect_key(armored):
    """Read an armoured key and say what it actually is.

    Answers the question the operator has: does this key work, and is it the
    half I meant to publish? A private key pasted here is the finding, not
    an input error -- it means the wrong export is in circulation.
    """
    result = {
        "valid": False,
        "is_private": False,
        "keys": [],
        "error": None,
    }
    text = (armored or "").strip()
    if not text:
        result["error"] = "Paste an armoured PGP key block"
        return result
    result["is_private"] = _ARMOR_PRIVATE in text
    if not result["is_private"] and _ARMOR_PUBLIC not in text:
        # Named separately because it is the common mistake: a signed
        # security.txt carries a signature block, and copying that instead of
        # the key is an easy slip to make and a confusing one to be told
        # "no key found" about.
        if _ARMOR_SIGNATURE in text:
            result["error"] = (
                "That is a PGP signature, not a key. A signature proves who "
                "wrote a file; the key is what someone encrypts to. Export it "
                "with `gpg --armor --export <fingerprint>`.")
        elif _ARMOR_MESSAGE in text:
            result["error"] = ("That is an encrypted PGP message, not a key.")
        else:
            result["error"] = ("No PGP key block found. An armoured key starts "
                               "with -----BEGIN PGP PUBLIC KEY BLOCK-----")
        return result

    # gpg is only needed to read the key, not to tell that this is not one.
    # Checking it earlier answered "gpg is not installed" to someone who had
    # actually pasted the wrong thing.
    if not available():
        result["error"] = (
            "This is a key block, but gpg is not installed on this server, so "
            "its contents cannot be read. The Docker image ships with it.")
        return result

    home = tempfile.mkdtemp(prefix="domainlens-pgp-", dir=GPG_HOME_BASE)
    try:
        os.chmod(home, 0o700)
        # show-only: parse and describe without ever adding it to a keyring.
        # Nothing pasted into a validator should end up trusted anywhere.
        # The key goes in on stdin: --import reads there, and writing it to a
        # file would put a pasted secret on disk for no reason.
        listing = _run(home, ["--import-options", "show-only", "--import",
                              "--with-colons", "--fingerprint"],
                       passphrase="", stdin_text=text)
        parsed = _parse_colon_keys(listing.stdout)
        if not parsed:
            result["error"] = _clean_error(listing.stderr) or "gpg could not read this key"
            return result
        result["valid"] = True
        result["keys"] = parsed
        return result
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _parse_colon_keys(listing):
    """Pull the key facts out of gpg's --with-colons output."""
    import datetime as _dt

    keys = []
    current = None
    for line in (listing or "").splitlines():
        parts = line.split(":")
        tag = parts[0]
        if tag in ("pub", "sec"):
            current = {
                "algorithm": _ALGORITHMS.get(parts[3], f"algo {parts[3]}"),
                "bits": parts[2] or None,
                "created": _epoch_to_date(parts[5]),
                "expires": _epoch_to_date(parts[6]),
                "expired": False,
                "fingerprint": None,
                "uids": [],
            }
            if current["expires"]:
                current["expired"] = (
                    _dt.date.fromisoformat(current["expires"]) < _dt.date.today())
            keys.append(current)
        elif tag == "fpr" and current is not None and not current["fingerprint"]:
            current["fingerprint"] = parts[9] if len(parts) > 9 else None
        elif tag == "uid" and current is not None and len(parts) > 9 and parts[9]:
            current["uids"].append(parts[9])
    return keys


def _epoch_to_date(value):
    import datetime as _dt
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return _dt.datetime.fromtimestamp(seconds, _dt.timezone.utc).date().isoformat()


# gpg reports the algorithm as a number; the name is what an operator reads.
_ALGORITHMS = {
    "1": "RSA", "2": "RSA (encrypt only)", "3": "RSA (sign only)",
    "16": "ElGamal", "17": "DSA", "18": "ECDH", "19": "ECDSA",
    "22": "EdDSA (ed25519)",
}


def looks_like_public_key(text):
    """A stored key must be the public half. Cheap, but it is the check that
    stops a paste of the wrong export from being published to the world."""
    return _ARMOR_PUBLIC in (text or "")


def contains_private_key(text):
    """Guard for anything on its way into storage or into a published file."""
    return _ARMOR_PRIVATE in (text or "")
