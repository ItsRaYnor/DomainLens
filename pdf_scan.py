"""What a PDF does when it is opened, read without opening it.

A phishing PDF rarely carries malware itself. It carries a link -- "the
document is protected, click here to view it" -- or a form that sends what
is typed to someone else's server, and now and then JavaScript, an action
that runs on opening, a program to launch, or another file inside it. All
of those are names in the PDF's own structure (/URI, /SubmitForm, /JS,
/OpenAction, /Launch, /EmbeddedFile), the way pdfid looks for them.

The file is read as data and never rendered or run. Compressed streams are
unpacked to find what is hidden in them (object streams hold whole objects),
with a ceiling on how much, so a small file cannot unpack into gigabytes.
Names may be written with #xx escapes ("/J#61vaScript") to slip past a plain
search; they are decoded first. The JavaScript itself is pulled out and
searched for the calls known exploits and droppers use, and a stream that
is itself a file (a program, an archive, an Office document) is handed back
for file_scan.py to look into.

An encrypted PDF keeps its strings and streams unreadable without the key,
so its links cannot be read here: that is "not measured", never "no links".
"""

from __future__ import annotations

import bisect
import re
import zlib

_MAX_STREAMS = 2000
_MAX_STREAM_OUT = 5 * 1024 * 1024
_MAX_TOTAL_OUT = 40 * 1024 * 1024
_MAX_URIS = 200
_MAX_EMBEDDED = 10
_MAX_JS = 20
# Literal strings are read byte by byte (their parentheses nest), so how
# many and how long is bounded: a file of a million "/JS (" is not read.
_MAX_LITERALS = 100
_JS_EXCERPT = 600

_STREAM = re.compile(rb"stream\r?\n")
_ENDSTREAM = re.compile(rb"endstream")
# Only names with a #xx escape in them: rewriting every name made a file of
# many names slow to read for nothing.
_NAME = re.compile(rb"/[^\s/<>\[\]()%{}#]*#[0-9A-Fa-f]{2}[^\s/<>\[\]()%{}]*")
_HEX = re.compile(rb"#([0-9A-Fa-f]{2})")
_URI_OPEN = re.compile(rb"/URI\s*\(")
_URI_HEX = re.compile(rb"/URI\s*<([0-9A-Fa-f\s]*)>")
_JS_OPEN = re.compile(rb"/JS\s*\(")
_PAREN = re.compile(rb"[()\\]")
_JS_HEX = re.compile(rb"/JS\s*<([0-9A-Fa-f\s]*)>")
_URL_IN_TEXT = re.compile(rb"https?://[^\s\"'<>()\\]{4,300}")

# The structure names that say what a PDF can do, as pdfid counts them.
_KEYWORDS = {
    "javascript": rb"/(?:JavaScript|JS)(?![A-Za-z0-9])",
    "open_action": rb"/OpenAction(?![A-Za-z0-9])",
    "auto_action": rb"/AA(?![A-Za-z0-9])",
    "launch": rb"/Launch(?![A-Za-z0-9])",
    "embedded_file": rb"/EmbeddedFiles?(?![A-Za-z0-9])",
    "submit_form": rb"/SubmitForm(?![A-Za-z0-9])",
    "import_data": rb"/ImportData(?![A-Za-z0-9])",
    "rich_media": rb"/RichMedia(?![A-Za-z0-9])",
    "xfa": rb"/XFA(?![A-Za-z0-9])",
    "encrypt": rb"/Encrypt(?![A-Za-z0-9])",
    "pages": rb"/Type\s*/Page(?![A-Za-z0-9])",
}

# Calls in PDF JavaScript that known exploits, droppers and obfuscation use.
# Ordinary form scripts (field formatting, totals) use none of them.
_JS_EXPLOIT = {
    "util.printf": "util.printf (CVE-2008-2992)",
    "Collab.getIcon": "Collab.getIcon (CVE-2009-0927)",
    "Collab.collectEmailInfo": "Collab.collectEmailInfo (CVE-2007-5659)",
    "media.newPlayer": "media.newPlayer (CVE-2009-4324)",
    "spell.customDictionaryOpen": "spell.customDictionaryOpen (CVE-2009-1493)",
    "getAnnots": "getAnnots (CVE-2009-1492)",
    "getIcon": "getIcon",
}
_JS_DROPPER = {
    "exportDataObject": "exportDataObject (saves or opens an embedded file)",
    "launchURL": "app.launchURL (opens a web address)",
    "submitForm": "submitForm (sends the form)",
    "getURL": "getURL (opens a web address)",
}
_JS_OBFUSCATION = ("eval(", "unescape(", "String.fromCharCode", "\\x", "%u")

# The first bytes of files worth looking into when a stream is one.
_FILE_MAGIC = (b"MZ", b"PK\x03\x04", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"%PDF-", b"{\\rtf")


def is_pdf(data):
    # The header may come after up to 1024 bytes of something else.
    return b"%PDF-" in data[:1024]


def what_it_is(data):
    """A word for a file that is not what its name says."""
    head = data[:512].lstrip().lower()
    if data[:2] == b"MZ":
        return "a Windows program"
    if data[:4] == b"PK\x03\x04":
        return "a ZIP archive (or an Office document)"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "an older Office document"
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<script", b"<svg")) or b"<html" in head:
        return "a web page"
    if data[:3] == b"Rar":
        return "a RAR archive"
    return "not a PDF"


def _streams(data):
    """[(raw, unpacked or None)] for every stream, as far as the ceilings
    allow, and whether one was reached. The ends are found once, not searched
    for from every start: a file of many "stream" words and one "endstream"
    at the end would otherwise be read over and over."""
    ends = [m.start() for m in _ENDSTREAM.finditer(data)]
    view = memoryview(data)  # a stream is a view, not a copy of megabytes
    out, total, cut = [], 0, False
    for count, match in enumerate(_STREAM.finditer(data)):
        if count >= _MAX_STREAMS:
            cut = True
            break
        start = match.end()
        at = bisect.bisect_left(ends, start)
        if at >= len(ends):
            break
        raw = view[start:ends[at]]
        room = min(_MAX_STREAM_OUT, _MAX_TOTAL_OUT - total)
        if room <= 0:
            cut = True
            break
        unpacked = None
        try:
            inflater = zlib.decompressobj()
            unpacked = inflater.decompress(raw, room)
            if inflater.unconsumed_tail:
                cut = True
            total += len(unpacked)
        except zlib.error:
            pass  # not Flate, or not compressed: the raw bytes are searched already
        out.append((raw, unpacked))
    return out, cut


def _names_decoded(text):
    return _NAME.sub(lambda m: _HEX.sub(lambda h: bytes([int(h.group(1), 16)]), m.group()), text)


def _balanced(text, start, limit=200_000):
    """The raw body of a literal string that opens just before `start`. A
    literal may hold balanced parentheses unescaped -- util.printf('%f', 1)
    -- so the first ")" is not its end; the matching one is."""
    depth, pos, end = 1, start, min(len(text), start + limit)
    while True:
        m = _PAREN.search(text, pos, end)
        if m is None:
            return text[start:end]
        at = m.start()
        if text[at] == 0x5C:  # a backslash: the byte after it is taken as it is
            pos = at + 2
            continue
        depth += 1 if text[at] == 0x28 else -1
        if depth == 0:
            return text[start:at]
        pos = at + 1


def _literal(raw):
    """A PDF literal string's bytes, its escapes undone."""
    out, i = bytearray(), 0
    simple = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}
    while i < len(raw):
        ch = raw[i:i + 1]
        if ch == b"\\" and i + 1 < len(raw):
            nxt = raw[i + 1:i + 2]
            if nxt in simple:
                out += simple[nxt]
                i += 2
            elif nxt.isdigit():
                digits = re.match(rb"[0-7]{1,3}", raw[i + 1:i + 4])
                if digits is None:
                    out += nxt
                    i += 2
                    continue
                out.append(int(digits.group(), 8) & 0xFF)
                i += 1 + len(digits.group())
            elif nxt in (b"\r", b"\n"):
                i += 2  # a line continuation
            else:
                out += nxt
                i += 2
        else:
            out += ch
            i += 1
    return bytes(out)


def _hex_string(raw):
    hexed = re.sub(rb"\s", b"", raw)
    if len(hexed) % 2:
        hexed += b"0"
    try:
        return bytes.fromhex(hexed.decode())
    except ValueError:
        return None


def _text(value):
    if value.startswith(b"\xfe\xff"):
        return value[2:].decode("utf-16-be", "replace")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1")


def _uris(texts, scripts):
    found = []
    for text in texts:
        for n, m in enumerate(_URI_OPEN.finditer(text)):
            if n >= _MAX_LITERALS:
                break
            found.append(_text(_literal(_balanced(text, m.end(), 8192))))
        for m in _URI_HEX.finditer(text):
            value = _hex_string(m.group(1))
            if value is not None:
                found.append(_text(value))
    # A web address written in the JavaScript is a link too: launchURL and
    # submitForm open one without an annotation to show it.
    for script in scripts:
        found += [m.group().decode("latin-1") for m in _URL_IN_TEXT.finditer(script.encode("latin-1", "replace"))]
    clean = []
    for uri in found:
        uri = uri.strip().strip("\x00")
        if uri and uri not in clean:
            clean.append(uri)
    return clean[:_MAX_URIS]


def _scripts(texts, streams):
    """The JavaScript in the file: /JS strings, and streams that read as code."""
    found = []
    for text in texts:
        for n, m in enumerate(_JS_OPEN.finditer(text)):
            if n >= _MAX_LITERALS:
                break
            found.append(_text(_literal(_balanced(text, m.end(), 65536))))
        for m in _JS_HEX.finditer(text):
            value = _hex_string(m.group(1))
            if value is not None:
                found.append(_text(value))
    markers = tuple(k.encode() for k in list(_JS_EXPLOIT) + list(_JS_DROPPER)) + (b"eval(", b"unescape(", b"app.")
    for _raw, unpacked in streams:
        if unpacked and any(m in unpacked for m in markers) and b"/Type" not in unpacked[:64]:
            found.append(unpacked[:200_000].decode("latin-1"))
    clean = []
    for script in found:
        if script.strip() and script not in clean:
            clean.append(script)
    return clean[:_MAX_JS]


def _js_indicators(scripts):
    joined = "\n".join(scripts)
    exploit = sorted({label for call, label in _JS_EXPLOIT.items() if call in joined})
    dropper = sorted({label for call, label in _JS_DROPPER.items() if call in joined})
    obfuscated = sorted({marker for marker in _JS_OBFUSCATION if marker in joined})
    return {"exploit": exploit, "dropper": dropper, "obfuscated": obfuscated}


def _embedded(streams):
    """Streams that are files in their own right."""
    found = []
    for raw, unpacked in streams:
        for blob in (unpacked, raw):
            if blob is None or not len(blob):
                continue
            head = bytes(blob[:64]).lstrip()
            if head[:8].startswith(_FILE_MAGIC):
                whole = bytes(blob)
                found.append(whole[len(whole) - len(whole.lstrip()):])
                break
        if len(found) >= _MAX_EMBEDDED:
            break
    return found


def scan(data, *, keep_embedded=False):
    """{"state", "is_pdf", "kind", "encrypted", "counts", "uris", "js", "cut", "reason"}.

    state: "scanned"; "partial" when the PDF is encrypted (its links cannot
    be read) or a ceiling was reached; "not_pdf" when it is something else.
    With keep_embedded, "embedded" holds the bytes of files found inside.
    """
    if not is_pdf(data):
        return {"state": "not_pdf", "is_pdf": False, "kind": what_it_is(data), "encrypted": False,
                "counts": {}, "uris": [], "js": {"count": 0, "excerpts": []}, "cut": False, "reason": None}
    streams, cut = _streams(data)
    texts = [_names_decoded(data)] + [_names_decoded(u) for _r, u in streams if u]
    counts = {key: sum(len(re.findall(pattern, t)) for t in texts) for key, pattern in _KEYWORDS.items()}
    encrypted = counts.pop("encrypt") > 0
    scripts = _scripts(texts, streams)
    uris = _uris(texts, scripts)
    reason = None
    if encrypted:
        reason = "The PDF is encrypted: its links and streams cannot be read without the key."
    elif cut:
        reason = "The PDF unpacks to more than is read here; only part of it was searched."
    result = {"state": "partial" if (encrypted or cut) else "scanned", "is_pdf": True, "kind": "a PDF",
              "encrypted": encrypted, "counts": counts, "uris": uris, "cut": cut, "reason": reason,
              "js": {"count": len(scripts), "excerpts": [s[:_JS_EXCERPT] for s in scripts[:3]],
                     **_js_indicators(scripts)}}
    if keep_embedded:
        result["embedded"] = _embedded(streams)
    return result


def findings(result, name):
    """[(severity, title, detail)] for one scanned file."""
    out = []
    shown = f"\"{name}\"" if name else "The PDF"
    if result["state"] == "not_pdf":
        severity = "high" if result["kind"] == "a Windows program" else "medium"
        out.append((severity, "A file named .pdf is not a PDF",
                    f"{shown} is {result['kind']}. A file that hides what it is, is meant to be opened by mistake."))
        return out
    c = result["counts"]
    js = result.get("js") or {}
    runs_on_open = c["open_action"] or c["auto_action"]
    if c["launch"]:
        out.append(("high", "A PDF can start a program",
                    f"{shown} contains a Launch action: opening it can ask to run a program or open a file."))
    if js.get("exploit"):
        out.append(("critical", "A PDF calls JavaScript used by known exploits",
                    f"{shown} calls " + ", ".join(js["exploit"]) + ". These calls have no use in an ordinary document."))
    if c["javascript"]:
        out.append(("high" if runs_on_open else "medium", "A PDF contains JavaScript",
                    f"{shown} carries JavaScript" + (", set to run when it is opened." if runs_on_open else ".")
                    + " Ordinary documents rarely need it; readers can be made to run it against you."))
    if js.get("dropper"):
        out.append(("high", "A PDF's JavaScript opens files or web addresses",
                    f"{shown} calls " + ", ".join(js["dropper"]) + "."))
    if js.get("obfuscated"):
        out.append(("medium", "A PDF's JavaScript is obfuscated",
                    f"{shown} uses " + ", ".join(js["obfuscated"]) + " in its JavaScript: written to be unreadable."))
    if c["embedded_file"]:
        out.append(("medium", "A PDF carries another file",
                    f"{shown} has a file embedded in it, which the reader can be asked to open."))
    if c["submit_form"]:
        out.append(("medium", "A PDF form sends what is typed",
                    f"{shown} has a form that submits its fields to a web address: "
                    "a way to collect passwords without a web page."))
    if c["import_data"] or c["rich_media"]:
        out.append(("low", "A PDF uses rarely needed features",
                    f"{shown} uses " + ", ".join(n for n, k in (("ImportData", "import_data"), ("RichMedia", "rich_media")) if c[k])
                    + ", which ordinary documents do not."))
    odd = [u for u in result["uris"] if not u.lower().startswith(("http://", "https://", "mailto:"))]
    if odd:
        out.append(("medium", "A PDF links to something other than a web page",
                    f"{shown} links to " + ", ".join(odd[:5]) + "."))
    web = [u for u in result["uris"] if u.lower().startswith(("http://", "https://"))]
    if web and c["pages"] == 1 and len(web) <= 3:
        out.append(("info", "A one-page PDF with a link",
                    f"{shown} is one page with {len(web)} link(s). \"Click to view the document\" is how most phishing PDFs work; "
                    "the links are checked below."))
    if result["encrypted"]:
        out.append(("info", "An encrypted PDF could not be read",
                    f"{shown} is encrypted, so its links could not be checked. A password given in the message "
                    "itself is a way to keep a PDF from being scanned."))
    return out
