"""A minimal OLE compound file writer, to build Outlook .msg files in tests.

olefile only reads, and a real .msg file from a mailbox does not belong in a
public repository. This writes version 3 files (512-byte sectors) with a
mini stream for the small streams, as [MS-CFB] lays them out.
"""

import struct

_SECTOR = 512
_MINI = 64
_CUTOFF = 4096
_FREE, _END, _FATSECT, _NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF


def _pad(data, size):
    return data + b"\x00" * (-len(data) % size)


def build(streams):
    """streams: {"storage/stream": bytes}. Storages are implied by the paths."""
    # The directory: the root, then each storage and stream once.
    entries = [{"name": "Root Entry", "type": 5, "children": [], "data": b""}]
    index = {(): 0}
    for path in sorted(streams):
        parts = tuple(path.split("/"))
        for depth in range(1, len(parts) + 1):
            key = parts[:depth]
            if key in index:
                continue
            is_stream = depth == len(parts)
            entries.append({"name": key[-1], "type": 2 if is_stream else 1, "children": [],
                            "data": streams[path] if is_stream else b""})
            index[key] = len(entries) - 1
            entries[index[key[:-1]]]["children"].append(index[key])

    # Small streams go to the mini stream, the rest to sectors of their own.
    mini, mini_fat = b"", []
    for e in entries:
        if e["type"] == 2 and len(e["data"]) < _CUTOFF:
            count = max(1, -(-len(e["data"]) // _MINI)) if e["data"] else 0
            e["start"] = len(mini) // _MINI if count else _END
            for n in range(count):
                mini_fat.append(len(mini) // _MINI + n + 1 if n < count - 1 else _END)
            mini += _pad(e["data"], _MINI)

    sectors, fat = [], []

    def place(data):
        count = -(-len(data) // _SECTOR)
        if not count:
            return _END
        start = len(sectors)
        padded = _pad(data, _SECTOR)
        for n in range(count):
            sectors.append(padded[n * _SECTOR:(n + 1) * _SECTOR])
            fat.append(start + n + 1 if n < count - 1 else _END)
        return start

    entries[0]["start"] = place(mini)
    entries[0]["size"] = len(mini)
    for e in entries:
        if e["type"] == 2 and len(e["data"]) >= _CUTOFF:
            e["start"] = place(e["data"])
    mini_fat_start = place(b"".join(struct.pack("<I", v) for v in mini_fat)) if mini_fat else _END
    mini_fat_count = -(-len(mini_fat) * 4 // _SECTOR)

    # Siblings in a chain to the right, every node black: a valid tree.
    for e in entries:
        kids = e["children"]
        e["child"] = kids[0] if kids else _NOSTREAM
        for a, b in zip(kids, kids[1:]):
            entries[a]["right"] = b
    directory = b""
    for e in entries:
        name = e["name"].encode("utf-16-le")
        start = e.get("start", _END)
        size = e.get("size", len(e["data"]) if e["type"] == 2 else 0)
        directory += (_pad(name + b"\x00\x00", 64)[:64]
                      + struct.pack("<HBBIII", len(name) + 2, e["type"], 1, _NOSTREAM, e.get("right", _NOSTREAM), e["child"])
                      + b"\x00" * 16 + b"\x00" * 4 + b"\x00" * 16
                      + struct.pack("<IQ", start if start is not None else _END, size))
    directory_start = place(_pad(directory, _SECTOR))

    # The FAT covers every sector, its own included.
    fat_count = 1
    while (len(sectors) + fat_count) > fat_count * (_SECTOR // 4):
        fat_count += 1
    fat_start = len(sectors)
    fat += [_FATSECT] * fat_count
    fat += [_FREE] * (fat_count * (_SECTOR // 4) - len(fat))
    fat_bytes = b"".join(struct.pack("<I", v) for v in fat)
    difat = [fat_start + n for n in range(fat_count)] + [_FREE] * (109 - fat_count)

    header = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16
              + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\x00" * 6
              + struct.pack("<IIIIIIIII", 0, fat_count, directory_start, 0, _CUTOFF,
                            mini_fat_start, mini_fat_count, _END, 0)
              + b"".join(struct.pack("<I", v) for v in difat))
    return _pad(header, _SECTOR) + b"".join(sectors) + fat_bytes


def prop_stream(header_size, fixed):
    """__properties_version1.0: a header, then 16 bytes per fixed property."""
    body = b"".join(struct.pack("<IIQ", tag, 6, value) for tag, value in fixed.items())
    return b"\x00" * header_size + body


def msg(*, headers=None, subject=None, body=None, html=None, rtf=None, attachments=(), codepage=65001):
    """An Outlook message: received headers, body forms and attachments."""
    utf16 = lambda s: s.encode("utf-16-le")
    streams = {"__properties_version1.0": prop_stream(32, {0x3FFD0003: codepage, 0x3FDE0003: codepage})}
    if headers is not None:
        streams["__substg1.0_007D001F"] = utf16(headers)
    if subject is not None:
        streams["__substg1.0_0037001F"] = utf16(subject)
    if body is not None:
        streams["__substg1.0_1000001F"] = utf16(body)
    if html is not None:
        streams["__substg1.0_10130102"] = html.encode("utf-8")
    if rtf is not None:
        streams["__substg1.0_10090102"] = rtf
    for n, (name, mime, data) in enumerate(attachments):
        base = f"__attach_version1.0_#{n:08X}"
        streams[f"{base}/__properties_version1.0"] = prop_stream(8, {0x37050003: 1})
        streams[f"{base}/__substg1.0_3707001F"] = utf16(name)
        streams[f"{base}/__substg1.0_370E001F"] = utf16(mime)
        streams[f"{base}/__substg1.0_37010102"] = data
    return build(streams)
