"""Registration data for a list of domains, paced so no registry blocks us.

Registries throttle: SIDN and others answer 429 or stop answering when one
address asks too fast, and a blocked server is blocked for every lookup this
installation makes afterwards, scans included. So a batch runs in the
background and never sends two requests to the same registry server closer
than MIN_INTERVAL apart. Different registries are independent, so a mixed
list is not paced as if it were all one. A 429 is honoured (Retry-After,
then one more try), and RDAP comes first; the stricter port-43 WHOIS is only
asked when a registry has no RDAP or RDAP could not be reached.

Every domain ends in one of three states, kept apart as elsewhere:
registered (measured), not registered (measured) or not measured, with the
reason. A lookup that failed is never shown as "not registered".
"""

from __future__ import annotations

import csv
import io
import re
import threading
import time
import uuid
from urllib.parse import urlparse

import rdap

MAX_DOMAINS = 500
MIN_INTERVAL = 2.0          # seconds between requests to one registry server
MAX_RETRY_AFTER = 60.0      # longest a 429 may make one lookup wait
_JOB_TTL = 3600
_MAX_JOBS = 20

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_jobs = {}
_jobs_lock = threading.Lock()


def parse_domains(text):
    """Domain names from pasted text or CSV: every cell, deduplicated.

    Returns (domains, rejected). Scheme, path and a leading "www." are
    removed; a dotted token that is still not a hostname is rejected, not
    guessed.
    """
    seen, domains, rejected = set(), [], []
    for row in csv.reader(io.StringIO(text or ""), delimiter=","):
        for cell in row:
            for token in re.split(r"[\s;]+", cell):
                token = token.strip().strip('"\'').lower()
                if not token:
                    continue
                if "://" in token:
                    token = urlparse(token).hostname or ""
                token = token.split("/")[0].rstrip(".")
                if token.startswith("www."):
                    token = token[4:]
                if not _DOMAIN_RE.match(token):
                    # Only what was meant as a name is worth reporting: other
                    # CSV columns and headers have no dot and are skipped.
                    if "." in token:
                        rejected.append(token)
                    continue
                if token not in seen:
                    seen.add(token)
                    domains.append(token)
    return domains, rejected


class _Pacer:
    """Minimum spacing per server, shared by every batch in this process."""

    def __init__(self, interval=MIN_INTERVAL, clock=time.monotonic, sleep=time.sleep):
        self.interval, self.clock, self.sleep = interval, clock, sleep
        self._next = {}
        self._lock = threading.Lock()

    def wait(self, server):
        with self._lock:
            now = self.clock()
            at = max(now, self._next.get(server, 0.0))
            self._next[server] = at + self.interval
        if at > now:
            self.sleep(at - now)

    def hold(self, server, seconds):
        """A server said "slow down": nobody asks it again before then."""
        with self._lock:
            self._next[server] = max(self._next.get(server, 0.0), self.clock() + seconds)


_pacer = _Pacer()


def _row(domain, result):
    """One flat row per domain, for the table and the CSV."""
    base = {"domain": domain, "state": "", "detail": "", "registrar": "", "reseller": "",
            "registered": "", "updated": "", "expires": "", "dnssec": "", "nameservers": "",
            "holder": "", "source": ""}
    if result.get("success"):
        registrant = result.get("registrant") or {}
        base.update(
            state="registered",
            registrar=(result.get("registrar") or {}).get("name", ""),
            reseller=(result.get("reseller") or {}).get("name", ""),
            registered=result.get("registered") or "",
            updated=result.get("updated") or "",
            expires=result.get("expires") or "",
            dnssec={True: "yes", False: "no"}.get(result.get("dnssec"), ""),
            nameservers=" ".join(result.get("nameservers") or []),
            holder="withheld" if registrant.get("withheld") else registrant.get("name", ""),
            source=result.get("source", ""),
        )
    elif result.get("registered") is False:
        base.update(state="not_registered", detail=result.get("error", ""), source="rdap")
    else:
        base.update(state="unmeasured", detail=result.get("error", "No answer"),
                    source=result.get("source", ""))
    return base


def _whois_text_fallback(domain, text_lookup):
    """Port-43 WHOIS, reduced to the same row fields."""
    data = text_lookup(domain) or {}
    if not data.get("success"):
        return {"success": False, "error": data.get("error") or "WHOIS gave no answer",
                "source": "whois"}
    d = data.get("data") or {}

    def first(value):
        return (value[0] if isinstance(value, list) and value else value) or ""

    ns = d.get("name_servers") or []
    return {"success": True, "source": "whois", "registrar": {"name": first(d.get("registrar"))},
            "reseller": {"name": first(d.get("reseller"))} if d.get("reseller") else None,
            "registered": str(first(d.get("creation_date")))[:10],
            "updated": str(first(d.get("updated_date")))[:10],
            "expires": str(first(d.get("expiration_date")))[:10],
            "nameservers": [str(n).lower() for n in (ns if isinstance(ns, list) else [ns])],
            "registrant": {"withheld": True}}


def lookup_paced(domain, *, pacer=None, fetch=None, text_lookup=None):
    """One domain: RDAP within the pace, a 429 honoured, WHOIS as fallback."""
    pacer = pacer or _pacer
    fetch = fetch or rdap.lookup
    try:
        server = rdap.server_for(domain) or f"whois:{domain.rsplit('.', 1)[-1]}"
    except Exception:
        server = f"whois:{domain.rsplit('.', 1)[-1]}"
    result = None
    for _ in range(2):
        pacer.wait(server)
        result = fetch(domain)
        retry_after = result.get("retry_after")
        if not retry_after:
            break
        pacer.hold(server, min(float(retry_after), MAX_RETRY_AFTER))
    # Not after a 429: port 43 is the same registry, and stricter.
    if (result.get("state") in ("not_applicable", "unmeasured") and text_lookup is not None
            and not result.get("retry_after")):
        pacer.wait(f"whois:{domain.rsplit('.', 1)[-1]}")
        fallback = _whois_text_fallback(domain, text_lookup)
        if fallback.get("success"):
            return fallback
    return result


def _prune():
    cutoff = time.time() - _JOB_TTL
    for job_id in [j for j, job in _jobs.items() if job["finished"] and job["finished"] < cutoff]:
        _jobs.pop(job_id, None)
    while len(_jobs) > _MAX_JOBS:
        oldest = min(_jobs, key=lambda j: _jobs[j]["started"])
        _jobs.pop(oldest, None)


def start(domains, *, text_lookup=None, owner=None, runner=None):
    """Queue a batch; returns its public view. Raises ValueError on bad input."""
    if not domains:
        raise ValueError("No valid domain names in the input")
    if len(domains) > MAX_DOMAINS:
        raise ValueError(f"At most {MAX_DOMAINS} domains per batch; split the list")
    job = {"id": uuid.uuid4().hex, "owner": owner, "domains": list(domains), "rows": [],
           "status": "running", "started": time.time(), "finished": None, "error": None}
    with _jobs_lock:
        _prune()
        _jobs[job["id"]] = job

    def work():
        try:
            for domain in job["domains"]:
                if job["status"] == "cancelled":
                    break
                try:
                    result = lookup_paced(domain, text_lookup=text_lookup)
                except Exception as exc:
                    result = {"success": False, "error": f"{type(exc).__name__}"}
                job["rows"].append(_row(domain, result))
            if job["status"] == "running":
                job["status"] = "done"
        except Exception as exc:  # the job must end, whatever happened
            job["status"], job["error"] = "error", type(exc).__name__
        finally:
            job["finished"] = time.time()

    (runner or (lambda fn: threading.Thread(target=fn, daemon=True).start()))(work)
    return view(job["id"])


def view(job_id):
    job = _jobs.get(job_id)
    if not job:
        return None
    return {"id": job["id"], "status": job["status"], "total": len(job["domains"]),
            "done": len(job["rows"]), "rows": list(job["rows"]), "error": job["error"],
            "owner": job["owner"]}


def cancel(job_id):
    job = _jobs.get(job_id)
    if job and job["status"] == "running":
        job["status"] = "cancelled"
    return view(job_id)


CSV_COLUMNS = ["domain", "state", "detail", "registrar", "reseller", "registered", "updated",
               "expires", "dnssec", "nameservers", "holder", "source"]


def _csv_safe(value):
    """Spreadsheets run a cell that starts with = + - @ as a formula, and a
    registry's answer is not ours to trust."""
    text = str(value or "")
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def to_csv(job_id):
    job = view(job_id)
    if not job:
        return None
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for row in job["rows"]:
        writer.writerow([_csv_safe(row.get(c)) for c in CSV_COLUMNS])
    return out.getvalue()
