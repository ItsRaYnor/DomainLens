"""Probing for TLS 1.0 and 1.1 is the check, not a mistake to be corrected.

Every scan wrote four DeprecationWarnings straight to stderr -- Python
complaining that ssl.TLSVersion.TLSv1 is deprecated, which it is, and which
is exactly why a server still answering on it is a finding. Several lines per
probed host buried the log lines that do mean something.

The tempting fix is to stop asking. That would delete the check: NCSC grades
both protocols insufficient, and the only way to report that a host offers
them is to offer them and see.
"""

import io
import os
import ssl
import tempfile
import unittest
import warnings
from contextlib import redirect_stderr
from unittest import mock


# Importing app opens the database; without this it resolves the configured
# Docker path and fails on a developer machine.
_tempdir = None


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "tls.db")
    os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
    os.environ.setdefault("DOMAINLENS_SECRET_KEY", "test-secret")
    import db
    db.init_db()


def tearDownModule():
    for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
        os.environ.pop(key, None)
    _tempdir.cleanup()


class TlsProbeStillAsksForLegacyProtocolsTests(unittest.TestCase):
    """The capability, not just the silence."""

    def setUp(self):
        import app
        self.app = app

    def test_the_probe_pins_one_version_at_both_ends(self):
        """min == max is what makes this a test of one protocol rather than
        a connection that negotiates the best available."""
        captured = {}

        class FakeContext:
            check_hostname = False
            verify_mode = None

            def __setattr__(self, name, value):
                captured[name] = value

            def wrap_socket(self, *args, **kwargs):
                raise OSError("stop here; the assignments are the point")

        with mock.patch.object(ssl, "SSLContext", return_value=FakeContext()):
            self.app._test_protocol("example.com", ssl.TLSVersion.TLSv1)
        self.assertEqual(ssl.TLSVersion.TLSv1, captured.get("minimum_version"))
        self.assertEqual(ssl.TLSVersion.TLSv1, captured.get("maximum_version"))

    def test_legacy_versions_are_still_among_what_the_deep_check_asks_for(self):
        """If these ever drop out of the table, the scan stops reporting the
        hosts that accept them -- silently, and looking cleaner for it."""
        names = [name for name, _version in self.app.TLS_PROTOCOLS]
        self.assertIn("TLS 1.0", names)
        self.assertIn("TLS 1.1", names)

    def test_the_table_carries_real_ssl_constants(self):
        """The names are looked up on ssl.TLSVersion at import and skipped
        when the local OpenSSL lacks them, so a typo would drop a protocol
        without any error."""
        by_name = dict(self.app.TLS_PROTOCOLS)
        self.assertEqual(ssl.TLSVersion.TLSv1, by_name["TLS 1.0"])
        self.assertEqual(ssl.TLSVersion.TLSv1_1, by_name["TLS 1.1"])


class TlsDeprecationIsNotLoggedTests(unittest.TestCase):
    def setUp(self):
        import app
        self.app = app

    def test_probing_tls10_writes_nothing_to_stderr(self):
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            with mock.patch.object(ssl.SSLContext, "wrap_socket",
                                   side_effect=OSError("no connection in tests")):
                for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                    self.app._test_protocol("example.com", version)
        self.assertNotIn("DeprecationWarning", buffer.getvalue())

    def test_the_filter_is_registered_for_exactly_these_messages(self):
        """A blanket DeprecationWarning filter would hide the next real one.
        This is scoped by message so only these two are affected."""
        matching = [f for f in warnings.filters
                    if f[1] is not None
                    and "TLSVersion" in getattr(f[1], "pattern", "")]
        self.assertTrue(matching, "no message-scoped filter for the TLS deprecation")
        for entry in matching:
            self.assertEqual("ignore", entry[0])
            self.assertIs(DeprecationWarning, entry[2])

    def test_an_unrelated_deprecation_still_surfaces(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            warnings.warn("something else is deprecated", DeprecationWarning)
        self.assertEqual(1, len(caught))

    def test_the_suppression_is_not_wrapped_around_the_call(self):
        """catch_warnings() mutates a global filter list, and _test_protocol
        runs in a thread pool: concurrent probes would race each other's
        suppression, silencing or unsilencing warnings elsewhere."""
        import inspect
        block = inspect.getsource(self.app._test_protocol)
        self.assertNotIn("catch_warnings", block)


if __name__ == "__main__":
    unittest.main()
