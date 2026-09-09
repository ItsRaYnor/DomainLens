import pathlib
import re
import unittest


class NoCustomerIdentifiersInSourceTests(unittest.TestCase):
    """Real customer and employer identifiers must not reach the repository.

    This is public source. A docstring that says "for 'shop.acme-client.nl'
    this returns 'acme-client.nl'" tells the world who is being scanned, and a
    test fixture built from a real dangling hostname publishes that company's
    infrastructure — the exact finding the scan was meant to keep private.
    Both had crept in, so this pins the rule rather than the one-off cleanup.

    The check is deliberately narrow: it looks at national TLDs, where a
    customer or employer domain would show up, and requires each one to be a
    reserved documentation name or a known public reference. Anything else is
    assumed to be real until someone adds it here on purpose.
    """

    SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules"}
    SKIP_SUFFIXES = {".db", ".db-wal", ".db-shm", ".png", ".jpg", ".ico", ".pyc", ".woff", ".woff2"}

    # National-TLD hostnames that are allowed to appear, each because it is a
    # public standard, vendor or reference — never a scanned party. Listed one
    # by one so a customer domain cannot ride in on a broad pattern.
    ALLOWED_HOSTS = {
        "internet.nl",          # the public NL security-standards test
        "ncsc.nl",              # the NL NCSC, source of the TLS guideline
        "microsoft.de",         # appears in published Microsoft IP/host ranges
        "microsoftonline.de",   # idem
        "example.nl",           # RFC 2606 style placeholder
    }

    HOST_RE = re.compile(r"\b[a-z0-9][a-z0-9-]{1,40}\.(?:nl|be|fr|lu|dk|se|no|fi|it|es|pl)\b")

    def _source_files(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            if any(part in self.SKIP_DIRS for part in relative.parts):
                continue
            if path.suffix in self.SKIP_SUFFIXES:
                continue
            # This file names the rule and its allowlist on purpose.
            if path.name == pathlib.Path(__file__).name:
                continue
            yield path, root

    def test_no_unexpected_national_tld_hostnames(self):
        offenders = []
        for path, root in self._source_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                for host in self.HOST_RE.findall(line.lower()):
                    if host not in self.ALLOWED_HOSTS:
                        offenders.append(f"{path.relative_to(root)}:{lineno} {host}")
        self.assertEqual(
            offenders, [],
            "real-looking hostnames in the source. Use a reserved example "
            "domain (example.com / example.net / .example), or add the host to "
            "ALLOWED_HOSTS if it is genuinely a public reference.")

    def test_no_street_addresses(self):
        # A postal address belongs to an organisation, never to the scanner.
        # The letter pair may not be "IN": a zone-file example line such as
        # "@ 3600 IN A 203.0.113.10" is otherwise read as a postcode.
        address_re = re.compile(
            r"\b(?:postbus\s+\d|\d{4}\s?(?!IN\b)[A-Z]{2}\s+[A-Za-z]{3,})\b")
        offenders = []
        for path, root in self._source_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if address_re.search(line):
                    offenders.append(f"{path.relative_to(root)}:{lineno}")
        self.assertEqual(offenders, [], "what looks like a postal address in the source")


if __name__ == "__main__":
    unittest.main()
