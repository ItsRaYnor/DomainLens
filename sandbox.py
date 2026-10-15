"""Read untrusted files in a process of their own (scan_worker.py).

A mail attachment is written by whoever sent it, and every parser has bugs.
Reading an Outlook file, a PDF, a ZIP or a document in this process would
put the settings, the API keys and every other request within reach of
such a bug. The worker gets the bytes on stdin and nothing else: no
environment, no network, on Linux limits on memory, CPU, files and
processes, and here a wall-clock limit. When it runs out of any of those,
the files it was reading are "not measured", with the reason -- never
clean, and never a crash of this process.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys

_WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_worker.py")
TIMEOUT = 45
MAX_FILES = 20


class SandboxError(RuntimeError):
    """The worker did not answer: timed out, ran out of memory, crashed."""


def _env():
    # No inherited environment: no keys, no proxies, no database settings.
    env = {"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
    for name in ("SYSTEMROOT", "WINDIR"):  # Windows cannot start Python without them
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


def _run(op, files, timeout=TIMEOUT):
    header = json.dumps({"op": op, "files": [{"name": n, "size": len(d)} for n, d in files]}).encode() + b"\n"
    try:
        done = subprocess.run([sys.executable, "-E", "-s", "-B", _WORKER], input=header + b"".join(d for _n, d in files),
                              capture_output=True, timeout=timeout, env=_env(),
                              cwd=os.path.dirname(_WORKER))
    except subprocess.TimeoutExpired:
        raise SandboxError(f"The scan was stopped after {timeout} seconds.")
    if done.returncode != 0:
        said = done.stderr.decode("utf-8", "replace")
        if "MemoryError" in said:
            raise SandboxError("The scan was stopped: the file needed more memory than is allowed.")
        if done.returncode < 0 or "CPU" in said:
            raise SandboxError("The scan was stopped: the file took more processing than is allowed.")
        raise SandboxError("The scan stopped on a file it could not read.")
    try:
        return json.loads(done.stdout)
    except ValueError:
        raise SandboxError("The scan gave no readable answer.")


def scan_files(files, timeout=TIMEOUT):
    """[file_scan result] for [(name, bytes)], in order; a file the worker
    could not finish is "unmeasured" with the reason."""
    files = list(files)
    if not files:
        return []
    try:
        return _run("scan", files[:MAX_FILES], timeout)["results"] + [
            _unmeasured(n, d, f"Only the first {MAX_FILES} files are scanned.") for n, d in files[MAX_FILES:]]
    except SandboxError as exc:
        return [_unmeasured(n, d, str(exc)) for n, d in files]


def convert_msg(data, timeout=TIMEOUT):
    """(message bytes, info) from an Outlook .msg file, read in the worker.
    Raises ValueError with the reason when it cannot be read."""
    try:
        answer = _run("msg", [("message.msg", data)], timeout)
    except SandboxError as exc:
        raise ValueError(str(exc))
    if not answer.get("ok"):
        raise ValueError(answer.get("error") or "This is not a readable Outlook message file")
    return base64.b64decode(answer["message"]), answer["info"]


def _unmeasured(name, data, reason):
    import hashlib
    return {"name": name or "(unnamed)", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
            "type": "unknown", "type_label": "not read", "state": "unmeasured", "reason": reason,
            "findings": [], "urls": [], "children": [], "depth": 0}
