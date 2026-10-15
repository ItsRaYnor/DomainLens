"""An Outlook .msg file, turned into a message the mail analysis can read.

A .msg file is not a message as it was received. It is an OLE compound file
of MAPI properties: the headers the server received with it (when Outlook
kept them: PR_TRANSPORT_MESSAGE_HEADERS), the body as plain text, as HTML or
only as compressed RTF with the HTML wrapped inside it, and each attachment
with its name and bytes. This module reads those and writes an RFC 5322
message from them: the received headers as they were, and a new MIME body.

What that cannot give back is the body exactly as it was sent, so a DKIM
signature over it cannot be verified (to_message says so with
body_as_sent=False). Everything else the analysis does -- the Received
chain, SPF, DMARC, the sending server, the links and the attachments -- works
from what the file keeps.
"""

from __future__ import annotations

import email.message
import email.policy
import io
import re
import struct

MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_PROPS = "__properties_version1.0"
_ATTACH = "__attach_version1.0_#"
_CONTENT_HEADERS = {"content-type", "content-transfer-encoding", "mime-version", "content-disposition"}
_MAX_ATTACHMENTS = 50


def is_msg(data):
    return data[:8] == MAGIC


class MsgError(ValueError):
    """A file that is not a readable Outlook message."""


# ------------------------------------------------------------ compressed RTF

# MS-OXRTFCP: the dictionary starts with this text, so common RTF needs no
# bytes of its own.
_PREBUF = (b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern "
           b"\\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0"
           b"\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx")


def decompress_rtf(data, limit=20 * 1024 * 1024):
    if len(data) < 16:
        raise MsgError("The RTF body is truncated")
    comp_size, raw_size, kind = struct.unpack_from("<III", data, 0)
    body = data[16:4 + comp_size]
    if kind == 0x414C454D:  # "MELA": stored uncompressed
        return bytes(body[:raw_size])
    if kind != 0x75465A4C:  # "LZFu"
        raise MsgError("The RTF body is in an unknown compression")
    window = bytearray(4096)
    window[:len(_PREBUF)] = _PREBUF
    write = len(_PREBUF)
    out = bytearray()
    i = 0
    while i < len(body):
        control = body[i]
        i += 1
        for bit in range(8):
            if i >= len(body):
                break
            if control & (1 << bit):
                if i + 1 >= len(body):
                    return bytes(out)
                ref = (body[i] << 8) | body[i + 1]
                i += 2
                offset, length = ref >> 4, (ref & 0xF) + 2
                if offset == write:
                    return bytes(out)
                for n in range(length):
                    byte = window[(offset + n) % 4096]
                    out.append(byte)
                    window[write] = byte
                    write = (write + 1) % 4096
            else:
                byte = body[i]
                i += 1
                out.append(byte)
                window[write] = byte
                write = (write + 1) % 4096
            if len(out) > limit:
                raise MsgError("The RTF body unpacks to more than is read here")
    return bytes(out)


# ------------------------------------------------- HTML wrapped in RTF

_TOKEN = re.compile(rb"\\([a-zA-Z]+)(-?\d+)? ?|\\'([0-9a-fA-F]{2})|\\(.)|([{}])|([^\\{}\r\n]+)|[\r\n]+", re.S)
_SKIP_GROUPS = {b"fonttbl", b"colortbl", b"stylesheet", b"info", b"pict", b"listtable", b"listoverridetable"}


def html_from_rtf(rtf, codepage="cp1252"):
    """The HTML Outlook wrapped in RTF (\\fromhtml1, MS-OXRTFEX), or None.

    The HTML is in {\\*\\htmltag...} groups and in text outside \\htmlrtf
    blocks; everything inside \\htmlrtf ... \\htmlrtf0 is RTF for display
    only and is dropped.
    """
    if b"\\fromhtml" not in rtf[:2048]:
        return None
    out = []
    # Per group: is it skipped, is it an htmltag, is \htmlrtf on.
    stack = [{"skip": False, "tag": False, "rtf": False}]
    pending_dest = False
    uc_skip = 0
    for m in _TOKEN.finditer(rtf):
        word, arg, hexed, symbol, brace, text = m.groups()
        state = stack[-1]
        if brace == b"{":
            stack.append(dict(state))
            pending_dest = False
            continue
        if brace == b"}":
            if len(stack) > 1:
                stack.pop()
            continue
        if word is not None:
            if pending_dest:
                pending_dest = False
                if word == b"htmltag":
                    state["tag"] = True
                    state["skip"] = False
                    continue
                state["skip"] = True
                continue
            if word in _SKIP_GROUPS:
                state["skip"] = True
            elif word == b"htmlrtf":
                state["rtf"] = arg != b"0"
            elif word in (b"par", b"line") and not state["skip"] and (state["tag"] or not state["rtf"]):
                out.append("\r\n")
            elif word == b"tab" and not state["skip"] and (state["tag"] or not state["rtf"]):
                out.append("\t")
            elif word == b"u" and arg and not state["skip"] and (state["tag"] or not state["rtf"]):
                value = int(arg)
                out.append(chr(value + 65536 if value < 0 else value))
                uc_skip = 1
            continue
        if symbol is not None:
            if symbol == b"*":
                pending_dest = True
            elif symbol in (b"{", b"}", b"\\") and not state["skip"] and (state["tag"] or not state["rtf"]):
                out.append(symbol.decode())
            continue
        if hexed is not None:
            if uc_skip:
                uc_skip -= 1
                continue
            if not state["skip"] and (state["tag"] or not state["rtf"]):
                out.append(bytes([int(hexed, 16)]).decode(codepage, "replace"))
            continue
        if text is not None:
            if uc_skip:
                text = text[uc_skip:]
                uc_skip = 0
            if not state["skip"] and (state["tag"] or not state["rtf"]):
                out.append(text.decode(codepage, "replace"))
    return "".join(out)


def links_from_rtf(rtf):
    """Plain RTF: its HYPERLINK fields, as a bare HTML list of links."""
    urls = re.findall(rb'HYPERLINK\s+"([^"]+)"', rtf)
    if not urls:
        return None
    return "".join(f'<a href="{u.decode("latin-1")}">{u.decode("latin-1")}</a><br>' for u in dict.fromkeys(urls))


# ------------------------------------------------------------- the file

class _Storage:
    """One storage of the file (the message, or an attachment) and its properties."""

    def __init__(self, ole, path, header):
        self.ole, self.path = ole, list(path)
        self.fixed = self._fixed(header)

    def _stream(self, name):
        full = self.path + [name]
        return self.ole.openstream(full).read() if self.ole.exists("/".join(full)) else None

    def _fixed(self, header):
        """The fixed-size properties (numbers, dates) from the properties stream."""
        data = self._stream(_PROPS) or b""
        values = {}
        for offset in range(header, len(data) - 15, 16):
            tag, _flags, value = struct.unpack_from("<IIQ", data, offset)
            values[tag] = value
        return values

    def string(self, prop, codepage="cp1252"):
        unicode = self._stream(f"__substg1.0_{prop:04X}001F")
        if unicode is not None:
            return unicode.decode("utf-16-le", "replace").rstrip("\x00")
        ansi = self._stream(f"__substg1.0_{prop:04X}001E")
        if ansi is not None:
            return ansi.decode(codepage, "replace").rstrip("\x00")
        return None

    def binary(self, prop):
        return self._stream(f"__substg1.0_{prop:04X}0102")

    def number(self, prop, kind=0x0003):
        value = self.fixed.get((prop << 16) | kind)
        return None if value is None else value & 0xFFFFFFFF


def _codepage(number):
    # Windows code page numbers are Python codec names with "cp" before them.
    if number in (65001,):
        return "utf-8"
    if number:
        try:
            "".encode(f"cp{number}")
            return f"cp{number}"
        except LookupError:
            pass
    return "cp1252"


def _headers_block(text):
    """The received headers without their own Content-* headers, which
    belong to a body this file no longer has. CRLF, folded as received."""
    keep, current, skip = [], [], False
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            if current:
                break
            continue
        if line[:1] in (" ", "\t") and current:
            if not skip:
                keep.append(line)
            continue
        name = line.split(":", 1)[0].strip().lower()
        skip = name in _CONTENT_HEADERS or ":" not in line
        current = [line]
        if not skip:
            keep.append(line)
    return "\r\n".join(keep)


def to_message(data):
    """(message bytes, info) for a .msg file.

    info: {"headers": True when Outlook kept the received headers,
           "body": "html" | "html_from_rtf" | "text" | "links_from_rtf" | None,
           "attachments": n, "body_as_sent": False}
    """
    import olefile
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:
        raise MsgError("This is not a readable Outlook message file") from exc
    try:
        if not ole.exists("__substg1.0_0037001F") and not ole.exists("__substg1.0_0037001E") \
                and not ole.exists("__substg1.0_007D001F") and not ole.exists("__substg1.0_007D001E") \
                and not ole.exists(_PROPS):
            raise MsgError("This file is not an Outlook message")
        top = _Storage(ole, [], 32)
        codepage = _codepage(top.number(0x3FFD) or top.number(0x3FDE))
        info = {"headers": False, "body": None, "attachments": 0, "body_as_sent": False}

        headers = top.string(0x007D, codepage)
        if headers and ":" in headers:
            head = _headers_block(headers)
            info["headers"] = True
        else:
            # A sent item or a draft: no received headers, only what Outlook
            # knows. The analysis says what that leaves out.
            sender = top.string(0x5D01) or top.string(0x0C1F) or top.string(0x0065)
            name = top.string(0x0C1A) or top.string(0x0042) or ""
            fields = [("From", f"{name} <{sender}>" if sender else name),
                      ("To", top.string(0x0E04) or ""), ("Subject", top.string(0x0037, codepage) or ""),
                      ("Message-ID", top.string(0x1035) or "")]
            head = "\r\n".join(f"{k}: {v}" for k, v in fields if v)

        body = email.message.EmailMessage(policy=email.policy.SMTP)
        plain = top.string(0x1000, codepage)
        html = None
        raw_html = top.binary(0x1013)
        if raw_html is not None:
            html = raw_html.decode(_codepage(top.number(0x3FDE)) if top.number(0x3FDE) else codepage, "replace")
            info["body"] = "html"
        elif top.string(0x1013, codepage):
            html = top.string(0x1013, codepage)
            info["body"] = "html"
        else:
            rtf_packed = top.binary(0x1009)
            if rtf_packed:
                try:
                    rtf = decompress_rtf(rtf_packed)
                    html = html_from_rtf(rtf, codepage)
                    info["body"] = "html_from_rtf" if html else None
                    if html is None:
                        html = links_from_rtf(rtf)
                        info["body"] = "links_from_rtf" if html else None
                except MsgError:
                    html = None
        if plain and html:
            body.set_content(plain)
            body.add_alternative(html, subtype="html")
        elif html:
            body.set_content(html, subtype="html")
        else:
            body.set_content(plain or "")
            info["body"] = info["body"] or ("text" if plain else None)

        for entry in sorted({e[0] for e in ole.listdir(streams=True, storages=True) if e and e[0].startswith(_ATTACH)}):
            if info["attachments"] >= _MAX_ATTACHMENTS:
                break
            att = _Storage(ole, [entry], 8)
            name = (att.string(0x3707, codepage) or att.string(0x3704, codepage)
                    or att.string(0x3001, codepage) or "(unnamed)")
            mime = (att.string(0x370E) or "application/octet-stream").lower()
            payload = att.binary(0x3701)
            if payload is None:
                # An attached message (method 5) is a storage, not bytes;
                # named, not opened.
                name = f"{name} (attached message)" if att.number(0x3705) == 5 else name
                payload, mime = b"", "application/octet-stream"
            maintype, _, subtype = mime.partition("/")
            body.add_attachment(payload, maintype=maintype or "application", subtype=subtype or "octet-stream",
                                filename=name)
            info["attachments"] += 1

        mime_part = body.as_bytes()
        return (head.encode("utf-8", "replace") + b"\r\n" + mime_part.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"),
                info)
    finally:
        ole.close()
