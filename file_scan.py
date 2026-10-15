"""What a file does when it is opened, worked out without opening it.

A sandbox such as Joe Sandbox runs a file in a machine of its own and
watches what it does. Doing that here would run whatever arrived by mail on
the server that holds the monitoring, the settings and the API keys: the one
thing this must never do. So this is the static half of such an analysis,
the part that reads the file:

  * what the file really is, by its first bytes, against what its name says
    (an "invoice.pdf" that is a program or a web page);
  * names made to mislead: a right-to-left mark that turns "fdp.exe" around,
    a double extension, a gap of spaces before the real one;
  * PDF: links, forms, JavaScript and the calls exploits use, actions on
    opening, files inside (pdf_scan.py);
  * Office: macros and whether they run on opening (the VBA source is
    unpacked and read), a template fetched from the internet when the
    document opens, DDE fields, objects linked from outside, files embedded,
    and a password that keeps the content from being read;
  * RTF: embedded objects, the Equation Editor object used by CVE-2017-11882
    and its successors, objects set to update on opening;
  * archives: what they hold, programs among it, a password that keeps it
    closed, and a ZIP that unpacks to far more than it is (a ZIP bomb);
  * HTML: a login form in an attachment, HTML smuggling (a file assembled
    in the browser and saved), a redirect;
  * programs, scripts and shortcuts, whatever their name.

Everything found inside -- a file in a ZIP, a stream in a PDF that is a
file, an object in a document -- is looked into the same way, two levels
deep, with a ceiling on sizes and counts, so a file cannot unpack into more
than this is willing to read. Nothing is written to disk and nothing is
fetched: links are only collected, for the caller to check by name.

Run it through sandbox.py: in a process of its own, with limits on time,
memory and files, and no network.
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import zipfile
import zlib

import pdf_scan

MAX_DEPTH = 2
MAX_CHILDREN = 50
MAX_MEMBER = 20 * 1024 * 1024
MAX_UNPACKED = 60 * 1024 * 1024
_BOMB_RATIO = 100
_MAX_URLS = 200
_EXCERPT = 600

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00"

_EXECUTABLE_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1",
                   "jar", "msi", "msp", "hta", "lnk", "cpl", "reg", "dll", "sys", "iso", "img", "vhd", "vhdx",
                   "appx", "msix", "application", "gadget", "inf", "scf", "url", "chm", "xll", "elf", "sh"}
_RISKY_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "html", "htm", "shtml", "svg", "one"}
_DOCUMENT_EXT = {"pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "rtf", "txt",
                 "jpg", "jpeg", "png", "gif", "csv", "odt", "ods"}
_URL = re.compile(rb"https?://[^\s\"'<>()\\\x00]{4,300}")

_LABELS = {
    "pdf": "PDF", "ole": "Office document (older format) or OLE file", "ooxml": "Office document",
    "zip": "ZIP archive", "rtf": "RTF document", "html": "web page", "pe": "Windows program",
    "elf": "Linux program", "macho": "macOS program", "lnk": "Windows shortcut", "iso": "disk image",
    "rar": "RAR archive", "7z": "7-Zip archive", "gzip": "gzip archive", "cab": "cabinet archive",
    "image": "image", "text": "text", "script": "script file", "unknown": "unknown type",
}


# --------------------------------------------------------------- the type

def sniff(data):
    """The file's type by its first bytes, never by its name."""
    head = data[:4096]
    stripped = head.lstrip().lower()
    if pdf_scan.is_pdf(data):
        return "pdf"
    if head.startswith(OLE_MAGIC):
        return "ole"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        # An Office document is a ZIP with a [Content_Types].xml, wherever
        # in the archive it is listed.
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        except (zipfile.BadZipFile, ValueError, OSError):
            return "zip"
        return "ooxml" if "[Content_Types].xml" in names else "zip"
    if head.startswith(b"{\\rt"):
        return "rtf"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if head.startswith(_LNK_MAGIC):
        return "lnk"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if head.startswith(b"Rar!"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"MSCF"):
        return "cab"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM")):
        return "image"
    if stripped.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<svg", b"<form")) \
            or b"<html" in stripped[:1024] or b"<script" in stripped[:1024]:
        return "html"
    if stripped.startswith(b"#!") or re.match(rb"\s*(@echo off|powershell|wscript|set \w+=)", stripped):
        return "script"
    try:
        head.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "unknown"


def _ext(name):
    base = (name or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return base.rsplit(".", 1)[-1].lower().strip() if "." in base else ""


def _name_findings(name, kind, add):
    """A name made to be read as something it is not."""
    if not name:
        return
    if "\u202e" in name or "\u202d" in name:
        add("high", "A file name is written right-to-left to hide its type",
            f"\"{name}\" contains a right-to-left mark: what reads as \"…exe.pdf\" ends in .exe.")
    base = name.rsplit("/", 1)[-1]
    parts = base.lower().split(".")
    if len(parts) >= 3 and parts[-1].strip() in _EXECUTABLE_EXT and parts[-2].strip() in _DOCUMENT_EXT:
        add("high", "A program named like a document",
            f"\"{name}\" ends in .{parts[-1].strip()}: the .{parts[-2].strip()} before it is there to be read instead.")
    elif re.search(r"\s{3,}\.\w+$", base):
        add("medium", "A file name hides its extension behind spaces",
            f"\"{name}\": the spaces push the real extension out of view.")
    ext = _ext(name)
    real_program = kind in ("pe", "elf", "macho", "lnk", "script")
    # By the name alone, unless the content says it better below.
    if ext in _EXECUTABLE_EXT and not real_program and kind != "iso":
        add("high", "A program or script is attached",
            f"\"{name}\" can run code when opened; receivers block or quarantine it.")
    elif ext in _RISKY_EXT:
        add("medium", "An attachment type used for phishing",
            f"\"{name}\": macros or a web page in an attachment are a common lure.")
    if ext in _DOCUMENT_EXT and real_program:
        add("high", "A program disguised as a document",
            f"\"{name}\" is named .{ext} but is a {_LABELS[kind]}.")
    elif ext in ("pdf", "doc", "xls", "jpg", "png", "txt") and kind in ("html", "zip", "rar", "7z", "iso"):
        add("medium", "A file is not what its name says",
            f"\"{name}\" is named .{ext} but is a {_LABELS[kind]}. A file that hides what it is, is meant to be opened by mistake.")


# --------------------------------------------------------------- Office: VBA

def ovba_decompress(data, limit=10 * 1024 * 1024):
    """[MS-OVBA] 2.4.1: the compression VBA source is stored in."""
    if not data or data[0] != 1:
        raise ValueError("not a compressed VBA container")
    out = bytearray()
    pos = 1
    while pos + 2 <= len(data):
        header = int.from_bytes(data[pos:pos + 2], "little")
        chunk_end = min(pos + (header & 0x0FFF) + 3, len(data))
        pos += 2
        start = len(out)
        if not header & 0x8000:
            out += data[pos:pos + 4096]
            pos += 4096
            continue
        while pos < chunk_end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not flags & (1 << bit):
                    out.append(data[pos])
                    pos += 1
                    continue
                if pos + 2 > chunk_end:
                    pos = chunk_end
                    break
                token = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2
                bits = max((len(out) - start - 1).bit_length(), 4)
                length_mask = 0xFFFF >> bits
                length = (token & length_mask) + 3
                offset = (token >> (16 - bits)) + 1
                src = len(out) - offset
                if src < start:
                    raise ValueError("a copy token points before its chunk")
                for i in range(length):
                    out.append(out[src + i])
        if len(out) > limit:
            raise ValueError("the VBA source unpacks to more than is read here")
    return bytes(out)


_VBA_AUTO = ("AutoOpen", "Auto_Open", "Document_Open", "DocumentOpen", "Workbook_Open", "AutoExec", "AutoClose",
             "Auto_Close", "Document_Close", "Workbook_Activate", "Document_ContentControlOnEnter", "AutoNew",
             "Document_New", "Workbook_BeforeClose", "Presentation_Open", "Slide_Open")
_VBA_SUSPICIOUS = {
    "Shell": "runs a program (Shell)", "WScript.Shell": "runs a program (WScript.Shell)",
    "CreateObject": "creates objects (CreateObject)", "URLDownloadToFile": "downloads a file (URLDownloadToFile)",
    "XMLHTTP": "fetches from the internet (XMLHTTP)", "WinHttp": "fetches from the internet (WinHttp)",
    "powershell": "starts PowerShell", "cmd.exe": "starts cmd.exe", "mshta": "starts mshta",
    "ADODB.Stream": "writes files (ADODB.Stream)", "SaveToFile": "writes files (SaveToFile)",
    "Environ": "reads environment variables (Environ)", "CallByName": "calls by name (CallByName)",
    "ExecuteExcel4Macro": "runs Excel 4.0 macros", "Lib \"kernel32": "calls Windows directly (kernel32)",
    "VirtualAlloc": "allocates executable memory (VirtualAlloc)", "RtlMoveMemory": "copies into memory (RtlMoveMemory)",
    "StrReverse": "reverses strings (StrReverse)", "Chr(": "builds text from character codes (Chr)",
    "Base64": "decodes Base64", "GetObject(\"winmgmts": "uses WMI (winmgmts)",
}


def _vba_sources(ole):
    """The VBA modules' source, found the way olevba falls back to: the
    compressed source starts at its "Attribut" marker."""
    sources = []
    for entry in ole.listdir(streams=True, storages=False):
        lowered = [p.lower() for p in entry]
        if not any(p in ("vba", "_vba_project_cur", "macros") for p in lowered[:-1]):
            continue
        if lowered[-1] in ("dir", "_vba_project", "project", "projectwm") or lowered[-1].startswith("__srp_"):
            continue
        try:
            data = ole.openstream(entry).read(MAX_MEMBER)
        except Exception:
            continue
        at = data.find(b"\x00Attribut")
        if at < 3:
            continue
        try:
            source = ovba_decompress(data[at - 3:])
        except ValueError:
            continue
        sources.append(("/".join(entry), source.decode("latin-1", "replace")))
        if len(sources) >= 50:
            break
    return sources


def _vba_findings(sources, add, urls, shown, extra):
    joined = "\n".join(s for _n, s in sources)
    auto = sorted({a for a in _VBA_AUTO if re.search(rf"\b{re.escape(a)}\b", joined, re.I)})
    suspicious = sorted({label for word, label in _VBA_SUSPICIOUS.items() if word.lower() in joined.lower()})
    extra["macros"] = {"modules": len(sources), "auto_run": auto, "suspicious": suspicious,
                       "excerpt": joined[:_EXCERPT]}
    if auto:
        add("high", "Macros that run when the document is opened",
            f"{shown} has macros that run on their own ({', '.join(auto)})"
            + (f" and {', '.join(suspicious[:6])}." if suspicious else "."))
    elif sources:
        add("medium", "A document contains macros",
            f"{shown} has {len(sources)} macro module(s)" + (f" that {', '.join(suspicious[:6])}." if suspicious else "."))
    _collect_urls(joined.encode("latin-1", "replace"), urls)


# --------------------------------------------------------------- Office: OLE

def _ole10native(data):
    """(name, bytes) of a file packed into a document (Ole10Native / Package)."""
    for skip in (4, 0):
        try:
            pos = skip + 2
            label_end = data.index(b"\x00", pos)
            label = data[pos:label_end].decode("latin-1")
            pos = data.index(b"\x00", label_end + 1) + 1  # the original path
            pos += 4
            temp_len = struct.unpack_from("<I", data, pos)[0]
            pos += 4 + temp_len
            size = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if 0 < size <= len(data) - pos:
                return label or "(packaged file)", data[pos:pos + size]
        except (ValueError, struct.error):
            continue
    return None


def _has_macro_sheet(book, limit=200_000):
    """A BIFF8 workbook stream with a BOUNDSHEET record of sheet type 1: an
    Excel 4.0 macro sheet. Read record by record, not searched for, so the
    bytes of a cell cannot pass for one."""
    pos = 0
    for _ in range(limit):
        if pos + 4 > len(book):
            return False
        record, length = struct.unpack_from("<HH", book, pos)
        body = book[pos + 4:pos + 4 + length]
        if record == 0x0085 and len(body) >= 6 and body[5] == 0x01:
            return True
        if record == 0x000A and pos > 0:  # EOF of the workbook globals
            return False
        pos += 4 + length
    return False


def _scan_ole(data, name, depth, add, urls, children, extra):
    import olefile
    shown = f"\"{name}\"" if name else "The document"
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:
        extra["state"], extra["reason"] = "unmeasured", "The OLE structure could not be read."
        return
    try:
        names = ["/".join(e) for e in ole.listdir(streams=True, storages=True)]
        lowered = [n.lower() for n in names]
        if any(n == "encryptedpackage" or n.endswith("/encryptedpackage") for n in lowered) \
                or "encryptioninfo" in lowered:
            add("medium", "A password-protected Office document",
                f"{shown} is encrypted: its content, macros included, cannot be read without the password. "
                "A password given in the message itself is a way to keep it from being scanned.")
            extra["state"], extra["reason"] = "partial", "Encrypted: the content cannot be read without the password."
            return
        if any(n.startswith("__substg1.0_") for n in lowered):
            extra["ole_kind"] = "Outlook message"
        sources = _vba_sources(ole)
        if sources or any(n.split("/")[0] in ("macros", "_vba_project_cur", "vba") for n in lowered):
            _vba_findings(sources, add, urls, shown, extra)
        for entry in ole.listdir(streams=True, storages=False):
            leaf = entry[-1].lower()
            if leaf.endswith("ole10native") or leaf == "package":
                try:
                    packed = _ole10native(ole.openstream(entry).read(MAX_MEMBER))
                except Exception:
                    packed = None
                if packed and len(children) < MAX_CHILDREN:
                    add("medium", "A document carries another file",
                        f"{shown} has \"{packed[0]}\" packed into it; opening the object opens that file.")
                    children.append(scan(packed[1], packed[0], depth + 1))
            elif leaf in ("workbook", "book") and depth >= 0:
                try:
                    book = ole.openstream(entry).read(MAX_MEMBER)
                except Exception:
                    continue
                if _has_macro_sheet(book):
                    add("high", "An Excel 4.0 macro sheet",
                        f"{shown} has an Excel 4.0 (XLM) macro sheet: an old macro language malware still uses "
                        "because few scanners read it.")
        for entry in ole.listdir(streams=True, storages=False):
            if len(urls) >= _MAX_URLS:
                break
            try:
                _collect_urls(ole.openstream(entry).read(2 * 1024 * 1024), urls)
            except Exception:
                continue
    finally:
        ole.close()


# --------------------------------------------------------------- ZIP and Office (OOXML)

def _zip_members(data, add, extra, shown):
    """(zip, members to read) with the ceilings applied, or None."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        extra["state"], extra["reason"] = "unmeasured", "The archive could not be read."
        return None
    declared = sum(i.file_size for i in infos)
    packed = sum(i.compress_size for i in infos) or 1
    if declared > MAX_UNPACKED and declared / packed > _BOMB_RATIO:
        add("medium", "An archive that unpacks to far more than it is (a ZIP bomb)",
            f"{shown} is {packed} bytes and unpacks to {declared} bytes. Only the names were read.")
        extra["state"], extra["reason"] = "partial", "A ZIP bomb: only the names were read."
        return archive, []
    encrypted = [i.filename for i in infos if i.flag_bits & 0x1]
    if encrypted:
        add("medium", "A password-protected archive",
            f"{shown} keeps {len(encrypted)} file(s) behind a password, so they cannot be scanned. "
            "A password in the message itself is the usual way past a mail filter.")
        extra["state"], extra["reason"] = "partial", "Password-protected: the files inside could not be read."
    extra["members"] = [{"name": i.filename, "size": i.file_size, "encrypted": bool(i.flag_bits & 0x1)}
                        for i in infos[:200]]
    return archive, [i for i in infos if not i.flag_bits & 0x1 and not i.is_dir()]


def _read_member(archive, info, budget):
    if info.file_size > MAX_MEMBER or info.file_size > budget[0]:
        return None
    with archive.open(info) as handle:
        data = handle.read(MAX_MEMBER + 1)
    if len(data) > MAX_MEMBER:
        return None
    budget[0] -= len(data)
    return data


def _scan_zip(data, name, depth, add, urls, children, extra):
    shown = f"\"{name}\"" if name else "The archive"
    opened = _zip_members(data, add, extra, shown)
    if opened is None:
        return
    archive, members = opened
    budget = [MAX_UNPACKED]
    for info in members:
        ext = _ext(info.filename)
        if ext in _EXECUTABLE_EXT:
            add("high", "An archive holds a program",
                f"{shown} contains \"{info.filename}\": a .{ext} file runs code when it is opened.")
        if depth >= MAX_DEPTH or len(children) >= MAX_CHILDREN:
            continue
        member = _read_member(archive, info, budget)
        if member is None:
            continue
        children.append(scan(member, info.filename, depth + 1))


def _scan_ooxml(data, name, depth, add, urls, children, extra):
    shown = f"\"{name}\"" if name else "The document"
    opened = _zip_members(data, add, extra, shown)
    if opened is None:
        return
    archive, members = opened
    extra.pop("members", None)
    budget = [MAX_UNPACKED]
    texts = {}
    for info in members:
        lower = info.filename.lower()
        wanted = (lower.endswith(".rels") or lower.endswith("vbaproject.bin") or "/embeddings/" in lower
                  or lower in ("word/document.xml", "word/settings.xml") or lower.startswith("xl/externallinks/")
                  or (lower.startswith("xl/worksheets/") and lower.endswith(".xml"))
                  or lower.startswith("xl/macrosheets/"))
        if not wanted:
            continue
        member = _read_member(archive, info, budget)
        if member is not None:
            texts[info.filename] = member
    for path, member in texts.items():
        lower = path.lower()
        if lower.endswith("vbaproject.bin"):
            import olefile
            try:
                ole = olefile.OleFileIO(io.BytesIO(member))
                try:
                    sources = _vba_sources(ole)
                finally:
                    ole.close()
            except Exception:
                sources = []
            _vba_findings(sources, add, urls, shown, extra)
        elif lower.startswith("xl/macrosheets/"):
            add("high", "An Excel 4.0 macro sheet",
                f"{shown} has an Excel 4.0 (XLM) macro sheet: an old macro language malware still uses.")
        elif lower.endswith(".rels"):
            for rel in re.finditer(rb"<Relationship\b[^>]*>", member):
                tag = rel.group()
                if b'TargetMode="External"' not in tag:
                    continue
                target = re.search(rb'Target="([^"]*)"', tag)
                kind = re.search(rb'Type="[^"]*/([^"/]+)"', tag)
                target = target.group(1).decode("utf-8", "replace") if target else ""
                kind = kind.group(1).decode() if kind else ""
                if kind in ("attachedTemplate",):
                    add("high", "A document fetches its template from the internet",
                        f"{shown} loads a template from {target} when it is opened (remote template injection): "
                        "the macros come with it, past any scan of the document itself.")
                elif kind in ("oleObject", "frame", "subDocument"):
                    add("medium", "A document loads an object from outside",
                        f"{shown} links an object ({kind}) from {target}, fetched when it is opened.")
                if target.lower().startswith(("http://", "https://")):
                    urls.append(target)
        elif lower in ("word/document.xml", "word/settings.xml") or lower.startswith("xl/worksheets/"):
            if re.search(rb"\bDDE(?:AUTO)?\b", member) and (b"instrText" in member or b"fldSimple" in member
                                                            or b"ddeService" in member):
                add("high", "A document runs a command through DDE",
                    f"{shown} has a DDE field: opening it asks to start another program, the way "
                    "macro-less malware runs commands.")
            _collect_urls(member, urls)
        elif lower.startswith("xl/externallinks/"):
            if b"ddeService" in member:
                add("high", "A workbook runs a command through DDE",
                    f"{shown} links to a DDE service: opening it asks to start another program.")
        elif "/embeddings/" in lower and depth < MAX_DEPTH and len(children) < MAX_CHILDREN:
            children.append(scan(member, path, depth + 1))


# --------------------------------------------------------------- RTF

# The Equation Editor's class name and CLSID, as text and as the hex an
# \objdata block carries them in.
_EQUATION = (b"equation.3", b"0002ce02-0000-0000-c000-000000000046", b"02ce020000000000c000000000000046",
             b"4571756174696f6e2e33")


def _scan_rtf(data, name, depth, add, urls, children, extra):
    shown = f"\"{name}\"" if name else "The document"
    lower = data[:MAX_MEMBER].lower()
    objects = len(re.findall(rb"\\object\b", lower))
    if any(marker in lower for marker in _EQUATION) or re.search(rb"e\s*q\s*u\s*a\s*t\s*i\s*o\s*n\s*\.\s*3", lower):
        add("critical", "An RTF document with an Equation Editor object",
            f"{shown} embeds an Equation Editor object, used by CVE-2017-11882 and its successors to run code "
            "the moment the document is opened. Ordinary documents do not need it.")
    if objects:
        add("high" if b"\\objupdate" in lower else "medium", "An RTF document with embedded objects",
            f"{shown} has {objects} embedded object(s)"
            + (", set to update on opening (\\objupdate)." if b"\\objupdate" in lower else "."))
    template = re.search(rb"\\\*\\template\s+([^}]*)", data)
    if template and re.search(rb"https?://|\\\\\\\\", template.group(1)):
        add("high", "A document fetches its template from the internet",
            f"{shown} loads a template from {template.group(1)[:200].decode('latin-1').strip()} when it is opened.")
    for blob in re.findall(rb"\\objdata\b([^}]*)", data[:MAX_MEMBER])[:10]:
        hexed = re.sub(rb"[^0-9a-fA-F]", b"", blob)
        hexed = hexed[: len(hexed) // 2 * 2]
        try:
            raw = bytes.fromhex(hexed.decode())
        except ValueError:
            continue
        native = raw.find(OLE_MAGIC)
        if native >= 0 and depth < MAX_DEPTH and len(children) < MAX_CHILDREN:
            children.append(scan(raw[native:], "(embedded object)", depth + 1))
        else:
            packed = _ole10native(raw[raw.find(b"Package") + 12:]) if b"Package" in raw[:200] else None
            if packed and depth < MAX_DEPTH and len(children) < MAX_CHILDREN:
                add("medium", "A document carries another file",
                    f"{shown} has \"{packed[0]}\" packed into it; opening the object opens that file.")
                children.append(scan(packed[1], packed[0], depth + 1))
    for url in re.findall(rb'HYPERLINK\s+"([^"]+)"', data[:MAX_MEMBER]):
        urls.append(url.decode("latin-1"))


# --------------------------------------------------------------- HTML

def _scan_html(data, name, depth, add, urls, children, extra):
    shown = f"\"{name}\"" if name else "The page"
    text = data[:MAX_MEMBER].decode("utf-8", "replace")
    lower = text.lower()
    # Bounded: "<input" a million times without a ">" must not be read
    # a million times over.
    if re.search(r"<input[^>]{0,500}type\s*=\s*[\"']?password", lower):
        action = re.search(r"<form[^>]{0,2000}action\s*=\s*[\"']?([^\"'\s>]+)", text, re.I)
        add("high", "An attachment asks for a password",
            f"{shown} is a page with a password field" + (f" that sends it to {action.group(1)[:200]}." if action else ".")
            + " A login form arriving as an attachment is credential phishing.")
    smuggling = [m for m in ("msSaveOrOpenBlob", "createObjectURL", "new Blob", ".download") if m.lower() in lower]
    if ("atob(" in lower or "base64" in lower) and len(smuggling) >= 2:
        add("high", "HTML smuggling: a file assembled in the browser",
            f"{shown} builds a file from encoded data and saves it ({', '.join(smuggling)}): the file never "
            "crosses the mail filter as an attachment.")
    if re.search(r"(window|document|top)\.location(\.href)?\s*=|location\.replace\(|http-equiv\s*=\s*[\"']?refresh", lower):
        add("medium", "An attachment sends the browser elsewhere",
            f"{shown} redirects to another page as soon as it is opened.")
    if "eval(" in lower and ("unescape(" in lower or "atob(" in lower or "fromcharcode" in lower):
        add("medium", "Obfuscated script in an attachment",
            f"{shown} decodes and runs its own script (eval with unescape, atob or fromCharCode).")
    blobs = re.findall(r"[A-Za-z0-9+/]{20000,}={0,2}", text)
    if blobs:
        extra["encoded_blobs"] = len(blobs)
    _collect_urls(data[:MAX_MEMBER], urls)


# --------------------------------------------------------------- shortcuts and archives not opened

def _scan_lnk(data, name, add, extra):
    shown = f"\"{name}\"" if name else "The shortcut"
    strings = data[:65536].decode("utf-16-le", "ignore") + data[:65536].decode("latin-1")
    lowered = strings.lower()
    runs = [w for w in ("powershell", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
                        "bitsadmin", "certutil", "curl", "http") if w in lowered]
    add("high", "A Windows shortcut is attached",
        f"{shown} is a shortcut: opening it runs a command" + (f" ({', '.join(runs)})." if runs else "."))


def _collect_urls(data, urls):
    for match in _URL.finditer(data):
        if len(urls) >= _MAX_URLS:
            return
        url = match.group().decode("latin-1").rstrip(".,;")
        if url not in urls:
            urls.append(url)


# --------------------------------------------------------------- one file

def scan(data, name=None, depth=0):
    """{"name", "size", "sha256", "sha1", "md5", "type", "type_label", "state",
        "reason", "findings", "urls", "children", ...type-specific fields}.

    state: "scanned"; "partial" when part of it could not be read (encrypted,
    a ceiling reached); "unmeasured" when its structure could not be read.
    Findings are [severity, title, detail], worded for the file as named.
    """
    kind = sniff(data)
    result = {"name": name or "(unnamed)", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
              "sha1": hashlib.sha1(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
              "type": kind, "type_label": _LABELS[kind], "state": "scanned", "reason": None,
              "findings": [], "urls": [], "children": [], "depth": depth}
    add = lambda severity, title, detail: result["findings"].append([severity, title, detail])
    _name_findings(name, kind, add)
    shown = f"\"{name}\"" if name else "The file"
    try:
        if kind == "pdf":
            pdf = pdf_scan.scan(data, keep_embedded=True)
            embedded = pdf.pop("embedded", [])
            result["pdf"] = pdf
            for severity, title, detail in pdf_scan.findings(pdf, name):
                add(severity, title, detail)
            result["urls"] += pdf["uris"]
            if pdf["state"] == "partial":
                result["state"], result["reason"] = "partial", pdf["reason"]
            if depth < MAX_DEPTH:
                for blob in embedded[:MAX_CHILDREN]:
                    result["children"].append(scan(blob, "(file inside the PDF)", depth + 1))
        elif kind == "ole":
            _scan_ole(data, name, depth, add, result["urls"], result["children"], result)
        elif kind == "ooxml":
            _scan_ooxml(data, name, depth, add, result["urls"], result["children"], result)
        elif kind == "zip":
            _scan_zip(data, name, depth, add, result["urls"], result["children"], result)
        elif kind == "rtf":
            _scan_rtf(data, name, depth, add, result["urls"], result["children"], result)
        elif kind == "html":
            _scan_html(data, name, depth, add, result["urls"], result["children"], result)
        elif kind == "lnk":
            _scan_lnk(data, name, add, result)
        elif kind in ("pe", "elf", "macho", "script"):
            add("high", "A program or script is attached",
                f"{shown} is a {_LABELS[kind]}: it runs code when opened, whatever its name says.")
        elif kind == "iso":
            add("high", "A disk image is attached",
                f"{shown} is a disk image: opening it mounts a drive whose files skip the warnings "
                "Windows shows for files from the internet.")
        elif kind in ("rar", "7z", "cab"):
            result["state"], result["reason"] = "unmeasured", f"A {_LABELS[kind]} is not opened here."
            add("low", "An archive that could not be opened",
                f"{shown} is a {_LABELS[kind]}; what it holds was not read.")
        elif kind == "gzip":
            inflater = zlib.decompressobj(31)
            inner = inflater.decompress(data, MAX_MEMBER)
            if depth < MAX_DEPTH:
                result["children"].append(scan(inner, (name or "file").removesuffix(".gz"), depth + 1))
        elif kind == "text":
            _collect_urls(data[:MAX_MEMBER], result["urls"])
    except Exception as exc:  # a malformed file is a result, not a crash
        result["state"], result["reason"] = "unmeasured", f"The file could not be read to the end ({type(exc).__name__})."
    result["urls"] = list(dict.fromkeys(result["urls"]))[:_MAX_URLS]
    return result


def flatten(result, path=()):
    """Every file in the tree with the path of names that leads to it."""
    here = path + (result["name"],)
    yield here, result
    for child in result.get("children") or []:
        yield from flatten(child, here)
