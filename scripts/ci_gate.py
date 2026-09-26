#!/usr/bin/env python3
"""Fail a CI/CD pipeline when a domain has open findings at or above a severity.

    DOMAINLENS_URL=https://domainlens.example.com \\
    DOMAINLENS_TOKEN=dlk_... \\
    python scripts/ci_gate.py www.example.com --fail-on high

Starts a scan through the API, waits for it, and exits:

    0  no open finding at or above --fail-on
    1  at least one open finding at or above --fail-on (they are listed)
    2  the scan could not be run or read (network, auth, timeout)

Exit 2 is kept apart from exit 1 on purpose: a gate that cannot reach
DomainLens has not found anything wrong with the domain, and a pipeline
should be able to tell "blocked by a finding" from "blocked by the gate".
Accepted risks do not fail the gate; they are counted separately.

Standard library only, so it runs in any pipeline image with Python 3.
A token with the Analyst role is enough.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def blocking(recommendations, fail_on):
    """Open findings at or above the threshold, most severe first."""
    limit = SEVERITIES.index(fail_on)
    return [r for r in recommendations or []
            if not r.get("accepted")
            and SEVERITIES.index(r.get("severity", "info")) <= limit]


def _call(base, token, method, path, body=None, timeout=60):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        base.rstrip("/") + path, data=data, method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8") or "{}")
        except ValueError:
            payload = {}
        return exc.code, payload


def _wait(base, token, job_id, deadline, timeout, poll, out):
    """Poll a job until it ends. Returns (final state, None) or (None, exit code)."""
    while True:
        status, state = _call(base, token, "GET", f"/api/scan/status/{job_id}")
        if status != 200:
            print(f"Could not read the scan: HTTP {status} {state.get('error', '')}", file=out)
            return None, 2
        if state.get("status") in ("done", "error"):
            return state, None
        if time.monotonic() > deadline:
            print(f"The scan did not finish within {timeout}s", file=out)
            return None, 2
        time.sleep(poll)


def run(domain, *, base, token, fail_on, checks, timeout, poll=5, out=sys.stdout):
    deadline = time.monotonic() + timeout
    while True:
        status, job = _call(base, token, "POST", "/api/scan/start",
                            {"domain": domain, "checks": checks})
        if status == 202:
            break
        if status == 409 and job.get("job_id"):
            # Someone else's scan of this domain, with whatever checks they
            # picked. Its result is not an answer to this gate's question:
            # wait for it to end, then start our own.
            _, code = _wait(base, token, job["job_id"], deadline, timeout, poll, out)
            if code is not None:
                return code
            continue
        print(f"Could not start the scan: HTTP {status} {job.get('error', '')}", file=out)
        return 2

    state, code = _wait(base, token, job.get("job_id"), deadline, timeout, poll, out)
    if code is not None:
        return code
    if state.get("status") == "error":
        print(f"The scan failed: {state.get('error', 'unknown error')}", file=out)
        return 2

    result = state.get("result") or {}
    recs = result.get("recommendations") or []
    found = blocking(recs, fail_on)
    accepted = sum(1 for r in recs if r.get("accepted"))
    for rec in found:
        print(f"[{rec['severity'].upper()}] {rec.get('category', '')}: {rec.get('title', '')}", file=out)
    summary = (f"{domain}: {len(found)} open finding(s) at or above {fail_on}"
               f"{f', {accepted} accepted risk(s) not counted' if accepted else ''}")
    if result.get("scan_id"):
        summary += f" — {base.rstrip('/')}/report/{result['scan_id']}"
    print(summary, file=out)
    return 1 if found else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("domain")
    parser.add_argument("--fail-on", choices=SEVERITIES, default="high")
    parser.add_argument("--checks", default="all",
                        help="Comma-separated check names (default: all)")
    parser.add_argument("--timeout", type=int, default=900, help="Seconds to wait for the scan")
    parser.add_argument("--url", default=os.environ.get("DOMAINLENS_URL"))
    args = parser.parse_args(argv)
    token = os.environ.get("DOMAINLENS_TOKEN")
    if not args.url or not token:
        print("Set DOMAINLENS_URL (or --url) and DOMAINLENS_TOKEN", file=sys.stderr)
        return 2
    return run(args.domain, base=args.url, token=token, fail_on=args.fail_on,
               checks=[c.strip() for c in args.checks.split(",") if c.strip()],
               timeout=args.timeout)


if __name__ == "__main__":
    sys.exit(main())
