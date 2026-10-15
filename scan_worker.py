"""The process that reads untrusted files: started by sandbox.py, nothing else.

It reads one request from stdin, answers on stdout and exits. Before it
touches a byte of the input it takes away what a parser bug could be turned
into: on Linux a ceiling on memory and CPU time, no files written, no new
processes, few file handles; everywhere, no network. A file that makes a
parser loop, balloon or crash takes this process down and nothing else.
"""

import base64
import json
import socket
import sys


def _confine():
    try:
        import resource
    except ImportError:  # Windows: the time limit in sandbox.py still holds
        return
    limits = (
        (resource.RLIMIT_AS, 1024 * 1024 * 1024),  # 1 GB of address space
        (resource.RLIMIT_CPU, 30),                  # seconds of CPU time
        (resource.RLIMIT_FSIZE, 0),                 # no file written
        (resource.RLIMIT_NPROC, 0),                 # no process started
        (resource.RLIMIT_CORE, 0),                  # no core dump of the input
    )
    for limit, value in limits:
        try:
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):
            pass


def _no_network(*_args, **_kwargs):
    raise OSError("network access is not allowed while scanning files")


def main():
    # Everything this process will ever need is imported before the limits.
    import file_scan
    import msg_file
    import olefile  # noqa: F401  (msg_file and file_scan import it lazily)
    import zipfile  # noqa: F401
    _confine()
    socket.socket = _no_network
    socket.create_connection = _no_network
    socket.getaddrinfo = _no_network

    stream = sys.stdin.buffer
    request = json.loads(stream.readline())
    blobs = [stream.read(f["size"]) for f in request["files"]]
    if request["op"] == "msg":
        try:
            message, info = msg_file.to_message(blobs[0])
            answer = {"ok": True, "message": base64.b64encode(message).decode(), "info": info}
        except msg_file.MsgError as exc:
            answer = {"ok": False, "error": str(exc)}
    else:
        answer = {"ok": True, "results": [file_scan.scan(data, f["name"])
                                          for f, data in zip(request["files"], blobs)]}
    sys.stdout.write(json.dumps(answer))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
