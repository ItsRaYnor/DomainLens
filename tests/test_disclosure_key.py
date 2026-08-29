"""DomainLens generates a disclosure keypair and keeps only the public half.

That is the whole promise of the feature, so most of this file is about the
private key NOT being somewhere. The generator hands it back once; after that
no copy exists on the server. If any of these ever fail, the feature has
quietly become the thing it was designed not to be: a box that holds the key
to every vulnerability report its owner ever received.
"""

import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import pgp_keys
import security_txt


PUBLIC_BLOCK = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
PRIVATE_BLOCK = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

FAKE_PUBLIC = f"{PUBLIC_BLOCK}\n\nmDMEZfakedata\n-----END PGP PUBLIC KEY BLOCK-----\n"
FAKE_PRIVATE = f"{PRIVATE_BLOCK}\n\nlFgEZfakedata\n-----END PGP PRIVATE KEY BLOCK-----\n"


def _gpg_usable():
    """gpg on Windows/MSYS cannot start its agent with a native temp path.
    Production is Linux, so the round-trip test skips rather than failing on
    a developer laptop -- but everything that does not need a real key runs
    everywhere."""
    if not pgp_keys.available():
        return False
    try:
        home = tempfile.mkdtemp(prefix="gpgprobe-")
        result = subprocess.run(
            [pgp_keys.GPG_BINARY, "--batch", "--no-tty", "--list-keys"],
            env={**os.environ, "GNUPGHOME": home},
            capture_output=True, timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


class KeyInputTests(unittest.TestCase):
    """Refused before a process starts: the uid is built into a gpg argument
    and a newline in it would forge a second field in the key's identity."""

    def test_a_name_with_angle_brackets_is_refused(self):
        with self.assertRaises(pgp_keys.PgpInputError):
            pgp_keys.generate("Bad <name>", "a@example.com")

    def test_a_name_with_a_newline_is_refused(self):
        with self.assertRaises(pgp_keys.PgpInputError):
            pgp_keys.generate("Line\nbreak", "a@example.com")

    def test_an_invalid_email_is_refused(self):
        for bad in ("", "not-an-email", "a@b", "a b@example.com"):
            with self.subTest(email=bad):
                with self.assertRaises(pgp_keys.PgpInputError):
                    pgp_keys.generate("Security", bad)

    def test_a_nonsense_expiry_is_refused(self):
        with self.assertRaises(pgp_keys.PgpInputError):
            pgp_keys.generate("Security", "a@example.com", "", "whenever")

    def test_input_is_checked_before_gpg_is_started(self):
        """A refused request must cost no process and leave no directory."""
        with mock.patch.object(pgp_keys.subprocess, "run") as run:
            with self.assertRaises(pgp_keys.PgpInputError):
                pgp_keys.generate("Bad <name>", "a@example.com")
        run.assert_not_called()


class ArmourGuardTests(unittest.TestCase):
    def test_a_public_block_is_recognised(self):
        self.assertTrue(pgp_keys.looks_like_public_key(FAKE_PUBLIC))

    def test_a_private_block_is_not_a_public_key(self):
        self.assertFalse(pgp_keys.looks_like_public_key(FAKE_PRIVATE))

    def test_a_private_block_is_detected_anywhere_in_the_text(self):
        """A paste of `gpg --export-secret-keys` output often carries both
        blocks; finding the public one first must not clear it."""
        both = FAKE_PUBLIC + "\n" + FAKE_PRIVATE
        self.assertTrue(pgp_keys.contains_private_key(both))

    def test_empty_input_is_neither(self):
        for value in (None, "", "   "):
            with self.subTest(value=value):
                self.assertFalse(pgp_keys.looks_like_public_key(value))
                self.assertFalse(pgp_keys.contains_private_key(value))


class GenerationTests(unittest.TestCase):
    """The real round trip. Skipped where gpg cannot run; verified in the
    image, which is where this actually ships."""

    @unittest.skipUnless(_gpg_usable(), "gpg cannot generate keys in this environment")
    def test_a_generated_key_returns_both_halves_once(self):
        result = pgp_keys.generate("DomainLens Security", "security@example.com")
        self.assertIn(PUBLIC_BLOCK, result["public_key"])
        self.assertIn(PRIVATE_BLOCK, result["private_key"])
        self.assertRegex(result["fingerprint"], r"^[0-9A-F]{40}$")
        self.assertEqual("DomainLens Security <security@example.com>", result["uid"])

    @unittest.skipUnless(_gpg_usable(), "gpg cannot generate keys in this environment")
    def test_the_temporary_keyring_does_not_survive(self):
        """The seconds between generation and export are the only time the
        secret exists on disk. If the directory outlives the call, it is
        recoverable from the host afterwards."""
        import glob
        base = pgp_keys.GPG_HOME_BASE or tempfile.gettempdir()
        pgp_keys.generate("DomainLens Security", "security@example.com")
        self.assertEqual([], glob.glob(os.path.join(base, "domainlens-pgp-*")))

    def test_the_keyring_is_removed_even_when_gpg_fails(self):
        """An exception halfway through must not strand a secret key."""
        created = []
        real_mkdtemp = pgp_keys.tempfile.mkdtemp

        def spy(*args, **kwargs):
            path = real_mkdtemp(*args, **kwargs)
            created.append(path)
            return path

        with mock.patch.object(pgp_keys.tempfile, "mkdtemp", spy), \
             mock.patch.object(pgp_keys, "_run",
                               return_value=mock.Mock(returncode=2, stderr="boom")):
            with self.assertRaises(pgp_keys.PgpError):
                pgp_keys.generate("Security", "a@example.com")
        self.assertTrue(created, "no keyring directory was created at all")
        for path in created:
            self.assertFalse(os.path.exists(path), f"{path} survived the failure")

    def test_an_error_message_does_not_leak_the_keyring_path(self):
        with mock.patch.object(pgp_keys, "_run", return_value=mock.Mock(
                returncode=2, stderr="gpg: failed to open '/tmp/domainlens-pgp-abc/x'")):
            with self.assertRaises(pgp_keys.PgpError) as caught:
                pgp_keys.generate("Security", "a@example.com")
        self.assertNotIn("domainlens-pgp-", str(caught.exception))


class SecurityTxtBuildTests(unittest.TestCase):
    """RFC 9116. Contact and Expires are mandatory; the rest is optional and
    only appears when it has a value."""

    BASE = {"enabled": True, "contact": "security@example.com", "expires_days": 30}

    def test_nothing_is_published_when_disclosure_is_off(self):
        self.assertIsNone(security_txt.build({**self.BASE, "enabled": False}))

    def test_nothing_is_published_without_a_contact(self):
        """A file with no Contact reads as "they thought about this" and stops
        a researcher looking for another way to reach you. Worse than absent."""
        self.assertIsNone(security_txt.build({**self.BASE, "contact": "  "}))

    def test_a_bare_address_becomes_a_mailto_uri(self):
        body = security_txt.build(self.BASE)
        self.assertIn("Contact: mailto:security@example.com", body)

    def test_a_url_contact_is_left_alone(self):
        body = security_txt.build({**self.BASE, "contact": "https://example.com/report"})
        self.assertIn("Contact: https://example.com/report", body)

    def test_several_contacts_keep_their_order(self):
        """Contact is ordered by preference in the RFC."""
        body = security_txt.build(
            {**self.BASE, "contact": "security@example.com, https://example.com/report"})
        lines = [l for l in body.splitlines() if l.startswith("Contact:")]
        self.assertEqual(["Contact: mailto:security@example.com",
                          "Contact: https://example.com/report"], lines)

    def test_expires_is_always_present_and_in_the_future(self):
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        body = security_txt.build(self.BASE, now=now)
        line = [l for l in body.splitlines() if l.startswith("Expires:")][0]
        stamp = datetime.strptime(line.split(": ", 1)[1], "%Y-%m-%dT%H:%M:%SZ")
        self.assertGreater(stamp.replace(tzinfo=timezone.utc), now)

    def test_an_over_long_validity_is_clamped_to_a_year(self):
        """The RFC says under a year. A file promising five would be ignored
        by tooling and misleading to a human."""
        now = datetime(2026, 8, 29, tzinfo=timezone.utc)
        body = security_txt.build({**self.BASE, "expires_days": 5000}, now=now)
        line = [l for l in body.splitlines() if l.startswith("Expires:")][0]
        stamp = datetime.strptime(line.split(": ", 1)[1], "%Y-%m-%dT%H:%M:%SZ")
        self.assertLessEqual(stamp.replace(tzinfo=timezone.utc),
                             now + timedelta(days=security_txt.MAX_EXPIRY_DAYS))

    def test_encryption_is_only_offered_when_a_key_exists(self):
        without = security_txt.build(self.BASE, base_url="https://d.example/", has_key=False)
        self.assertNotIn("Encryption:", without)
        with_key = security_txt.build(self.BASE, base_url="https://d.example/", has_key=True)
        self.assertIn("Encryption: https://d.example/.well-known/pgp-key.asc", with_key)

    def test_a_newline_in_a_value_cannot_forge_a_field(self):
        """Values are operator-supplied and land in a line-oriented format."""
        body = security_txt.build(
            {**self.BASE, "policy_url": "https://example.com/p\nContact: mailto:evil@x.test"})
        contacts = [l for l in body.splitlines() if l.startswith("Contact:")]
        self.assertEqual(1, len(contacts))
        self.assertNotIn("evil@x.test", " ".join(contacts))

    def test_canonical_is_derived_when_not_configured(self):
        body = security_txt.build(self.BASE, base_url="https://d.example/")
        self.assertIn("Canonical: https://d.example/.well-known/security.txt", body)


if __name__ == "__main__":
    unittest.main()


class SecurityTxtValidationTests(unittest.TestCase):
    """The validator is for a file you have not published yet, so it reads
    text and fetches nothing.

    Errors and advice are kept apart: only the two mandatory fields make a
    file invalid. Treating "no Policy field" as an error would make the tool
    cry wolf about a file that is perfectly correct.
    """

    GOOD = ("Contact: mailto:security@example.com\n"
            "Expires: 2027-01-01T00:00:00Z\n")

    def test_a_minimal_correct_file_is_valid(self):
        result = security_txt.validate(self.GOOD, now=datetime(2026, 8, 29, tzinfo=timezone.utc))
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual([], result["errors"])

    def test_an_empty_file_is_not_silently_accepted(self):
        for body in ("", "   \n"):
            with self.subTest(body=body):
                self.assertFalse(security_txt.validate(body)["valid"])

    def test_a_missing_contact_is_an_error(self):
        result = security_txt.validate("Expires: 2027-01-01T00:00:00Z\n")
        self.assertFalse(result["valid"])
        self.assertTrue(any("Contact" in e for e in result["errors"]))

    def test_a_missing_expires_is_an_error(self):
        result = security_txt.validate("Contact: mailto:a@example.com\n")
        self.assertFalse(result["valid"])
        self.assertTrue(any("Expires" in e for e in result["errors"]))

    def test_an_expired_file_is_an_error(self):
        """Tooling ignores a stale file, so publishing one is worse than
        knowing it lapsed."""
        body = "Contact: mailto:a@example.com\nExpires: 2020-01-01T00:00:00Z\n"
        result = security_txt.validate(body, now=datetime(2026, 8, 29, tzinfo=timezone.utc))
        self.assertFalse(result["valid"])
        self.assertTrue(any("past" in e for e in result["errors"]))

    def test_an_unparseable_expires_is_an_error(self):
        body = "Contact: mailto:a@example.com\nExpires: next tuesday\n"
        self.assertFalse(security_txt.validate(body)["valid"])

    def test_a_far_future_expiry_is_a_warning_not_an_error(self):
        """RFC 9116 says it should be under a year, not that it must be."""
        body = "Contact: mailto:a@example.com\nExpires: 2099-01-01T00:00:00Z\n"
        result = security_txt.validate(body, now=datetime(2026, 8, 29, tzinfo=timezone.utc))
        self.assertTrue(result["valid"])
        self.assertTrue(any("more than a year" in w for w in result["warnings"]))

    def test_optional_fields_are_notes_and_never_errors(self):
        result = security_txt.validate(self.GOOD, now=datetime(2026, 8, 29, tzinfo=timezone.utc))
        self.assertTrue(result["valid"])
        self.assertTrue(any("Encryption" in n for n in result["notes"]))

    def test_an_unknown_field_is_a_note_not_a_rejection(self):
        """The field registry grows; refusing an unknown name would make this
        tool wrong before the RFC changes."""
        body = self.GOOD + "Invented-Field: whatever\n"
        result = security_txt.validate(body, now=datetime(2026, 8, 29, tzinfo=timezone.utc))
        self.assertTrue(result["valid"])
        self.assertTrue(any("invented-field" in n.lower() for n in result["notes"]))

    def test_a_bare_email_contact_is_flagged_as_not_a_uri(self):
        body = "Contact: security@example.com\nExpires: 2027-01-01T00:00:00Z\n"
        result = security_txt.validate(body, now=datetime(2026, 8, 29, tzinfo=timezone.utc))
        self.assertTrue(any("not a URI" in w for w in result["warnings"]))


class KeyInspectionTests(unittest.TestCase):
    """What a pasted key actually is."""

    def test_empty_input_asks_for_a_key(self):
        result = pgp_keys.inspect_key("")
        self.assertFalse(result["valid"])
        self.assertIn("armoured", result["error"])

    def test_text_that_is_not_a_key_is_refused_before_gpg_runs(self):
        with mock.patch.object(pgp_keys, "_run") as run:
            result = pgp_keys.inspect_key("just some text")
        run.assert_not_called()
        self.assertFalse(result["valid"])

    def test_a_signature_is_named_as_a_signature(self):
        """The common slip: a signed security.txt carries a signature block,
        and copying that instead of the key is easy to do and confusing to be
        told "no key found" about."""
        sig = ("-----BEGIN PGP SIGNATURE-----\n\niHUEARYKAB0\n"
               "-----END PGP SIGNATURE-----\n")
        with mock.patch.object(pgp_keys, "_run") as run:
            result = pgp_keys.inspect_key(sig)
        run.assert_not_called()
        self.assertFalse(result["valid"])
        self.assertIn("signature, not a key", result["error"])

    def test_an_encrypted_message_is_named_too(self):
        msg = "-----BEGIN PGP MESSAGE-----\n\nhQIMA\n-----END PGP MESSAGE-----\n"
        result = pgp_keys.inspect_key(msg)
        self.assertIn("message, not a key", result["error"])

    def test_the_format_is_checked_before_gpg_is_needed(self):
        """Answering "gpg is not installed" to someone who pasted the wrong
        block sends them after the wrong problem. Telling a signature from a
        key needs no gpg at all."""
        sig = "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n"
        with mock.patch.object(pgp_keys, "available", return_value=False):
            result = pgp_keys.inspect_key(sig)
        self.assertIn("signature", result["error"])
        self.assertNotIn("gpg is not installed", result["error"])

    def test_a_real_key_without_gpg_says_which_tool_is_missing(self):
        """Here the tool genuinely cannot answer, and says so as our own
        limitation rather than as a fault in the key."""
        with mock.patch.object(pgp_keys, "available", return_value=False):
            result = pgp_keys.inspect_key(FAKE_PUBLIC)
        self.assertFalse(result["valid"])
        self.assertIn("gpg is not installed", result["error"])
        self.assertIn("Docker image", result["error"])

    def test_a_private_key_is_reported_as_such(self):
        """Refusing it would hide the finding: someone checking "does my key
        work" with the wrong half needs to be told which half they have."""
        with mock.patch.object(pgp_keys, "_run",
                               return_value=mock.Mock(stdout="", stderr="")):
            result = pgp_keys.inspect_key(FAKE_PRIVATE)
        self.assertTrue(result["is_private"])

    @unittest.skipUnless(_gpg_usable(), "gpg cannot run in this environment")
    def test_a_generated_key_reads_back_with_its_own_details(self):
        made = pgp_keys.generate("DomainLens Security", "security@example.com")
        result = pgp_keys.inspect_key(made["public_key"])
        self.assertTrue(result["valid"], result["error"])
        self.assertFalse(result["is_private"])
        self.assertEqual(1, len(result["keys"]))
        self.assertEqual(made["fingerprint"], result["keys"][0]["fingerprint"])
        self.assertIn("security@example.com", " ".join(result["keys"][0]["uids"]))

    def test_the_key_is_handed_to_gpg_on_stdin(self):
        """--import reads the key from stdin. Without passing it there gpg
        reads nothing, and every key -- including a perfectly good one --
        came back "invalid" with no hint why."""
        captured = {}

        def fake_run(home, args, passphrase=None, stdin_text=None):
            captured["args"] = args
            captured["stdin"] = stdin_text
            return mock.Mock(stdout="", stderr="empty")

        with mock.patch.object(pgp_keys, "_run", side_effect=fake_run):
            pgp_keys.inspect_key(FAKE_PUBLIC)
        self.assertIn("--import", captured["args"])
        self.assertEqual(FAKE_PUBLIC.strip(), captured["stdin"])

    def test_a_pasted_key_is_never_imported_into_a_keyring(self):
        """show-only: nothing pasted into a validator should end up trusted,
        and the throwaway home should stay empty."""
        captured = {}

        def fake_run(home, args, passphrase=None, stdin_text=None):
            captured["args"] = args
            return mock.Mock(stdout="", stderr="")

        with mock.patch.object(pgp_keys, "_run", side_effect=fake_run):
            pgp_keys.inspect_key(FAKE_PUBLIC)
        self.assertIn("show-only", captured["args"])

    def test_the_colon_parser_reads_the_facts_that_matter(self):
        listing = (
            "pub:-:255:22:ABCDEF0123456789:1756400000:1819472000::-:::scESC::::::ed25519:::0:\n"
            "fpr:::::::::E6C99E9092A9B99A8BB76C0817A06D29D4C90D3C:\n"
            "uid:-::::1756400000::HASH::DomainLens Security <security@example.com>::::::::::0:\n"
        )
        keys = pgp_keys._parse_colon_keys(listing)
        self.assertEqual(1, len(keys))
        self.assertEqual("EdDSA (ed25519)", keys[0]["algorithm"])
        self.assertEqual("E6C99E9092A9B99A8BB76C0817A06D29D4C90D3C", keys[0]["fingerprint"])
        self.assertEqual(["DomainLens Security <security@example.com>"], keys[0]["uids"])
        self.assertEqual("2025-08-28", keys[0]["created"])

    def test_a_key_with_no_expiry_says_so_rather_than_guessing(self):
        listing = ("pub:-:255:22:ABCDEF:1756400000:::-:::scESC::::::ed25519:::0:\n"
                   "fpr:::::::::AAAA:\n")
        keys = pgp_keys._parse_colon_keys(listing)
        self.assertIsNone(keys[0]["expires"])
        self.assertFalse(keys[0]["expired"])
