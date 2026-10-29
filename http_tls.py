"""Load the CA bundle once for every HTTPS request, not once per connection.

requests hands urllib3 the path of certifi's bundle, and urllib3 builds a new
SSL context for every new connection and loads that bundle into it: about
70 ms of CPU each time in the production image, 1.3 to 1.8 seconds on a
Windows development machine, and more on a slow NAS CPU. A full scan opens
well over a hundred HTTPS connections, nearly all of them to different hosts,
so connection reuse does not help.

`install()` gives requests one context with the bundle already loaded, for
requests that verify against the default bundle (`verify=True`). It verifies
exactly as before: the same bundle, CERT_REQUIRED, and urllib3 still checks
the host name. Requests with `verify=False`, a bundle path of their own
(including REQUESTS_CA_BUNDLE) or a client certificate are left as they were.
"""

from __future__ import annotations

import threading

from requests import adapters as _adapters
from requests.utils import DEFAULT_CA_BUNDLE_PATH
from urllib3.util.ssl_ import create_urllib3_context

_lock = threading.Lock()
_context = None
_installed = False


def shared_context():
    """The one SSL context, with the default CA bundle loaded once."""
    global _context
    with _lock:
        if _context is None:
            ctx = create_urllib3_context()
            ctx.load_verify_locations(cafile=DEFAULT_CA_BUNDLE_PATH)
            _context = ctx
        return _context


def uses_shared_context(pool):
    """Whether a urllib3 connection pool hands its connections the shared
    context (urllib3 keeps it with the other per-connection arguments)."""
    return (getattr(pool, "conn_kw", None) or {}).get("ssl_context") is shared_context()


def _applies(url, verify, cert):
    return verify is True and not cert and str(url or "").lower().startswith("https")


def install():
    """Make requests use the shared context. Safe to call more than once."""
    global _installed
    with _lock:
        if _installed:
            return
        _installed = True

    original_keys = _adapters.HTTPAdapter.build_connection_pool_key_attributes
    original_verify = _adapters.HTTPAdapter.cert_verify

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        host_params, pool_kwargs = original_keys(self, request, verify, cert)
        if _applies(request.url, verify, cert):
            # Part of urllib3's pool key, so pools are still reused per host.
            pool_kwargs["ssl_context"] = shared_context()
        return host_params, pool_kwargs

    def cert_verify(self, conn, url, verify, cert):
        original_verify(self, conn, url, verify, cert)
        if _applies(url, verify, cert) and uses_shared_context(conn):
            # The bundle is already in the context. Left set, urllib3 would
            # load the file into it again on every new connection.
            conn.ca_certs = None
            conn.ca_cert_dir = None

    _adapters.HTTPAdapter.build_connection_pool_key_attributes = build_connection_pool_key_attributes
    _adapters.HTTPAdapter.cert_verify = cert_verify
