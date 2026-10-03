"""Turn the translation sheets (i18n/nl_ui/*.tsv) into catalogue files.

A sheet line is "English<TAB>Dutch". Text without placeholders becomes an
exact entry. "{}" marks a part filled in at run time (a number, a name,
another phrase), "{n}" a part that is only ever a number; such a line
becomes a pattern, and the Dutch may reorder
the parts with {1}, {2}, ... A part that is itself English text in the
catalogue is translated too (static/js/translate.js does that).

Run after editing a sheet:  python -m i18n.build_catalogue
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_DIR = Path(__file__).resolve().parent / "nl_ui"


_PLACEHOLDER = re.compile(r"\{n?\}")


def _pattern(english, dutch):
    # {} is any text; {n} only a number, for short patterns whose words
    # also occur in Dutch ("{n} of {n}" must not touch "A of B" in Dutch).
    pieces = _PLACEHOLDER.split(english)
    kinds = _PLACEHOLDER.findall(english)
    regex = re.escape(pieces[0])
    for kind, piece in zip(kinds, pieces[1:]):
        regex += (r"(\d[\d.,]*)" if kind == "{n}" else "(.+?)") + re.escape(piece)
    count = len(kinds)
    dutch = dutch.replace("{n}", "{}")
    if re.search(r"\{\d\}", dutch):
        replacement = re.sub(r"\{(\d)\}", r"$\1", dutch)
    else:
        n = iter(range(1, count + 1))
        replacement = re.sub(r"\{\}", lambda _: f"${next(n)}", dutch)
    return [regex, replacement]


def build_sheet(path):
    text, patterns = {}, []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        if "\t" not in line:
            raise ValueError(f"{path.name}:{number}: no tab between English and Dutch")
        english, dutch = (part.strip() for part in line.split("\t", 1))
        if _PLACEHOLDER.search(english):
            patterns.append(_pattern(english, dutch))
        else:
            text[english] = dutch
    return {"text": text, "patterns": patterns}


def main():
    for sheet in sorted(_DIR.glob("*.tsv")):
        target = sheet.with_suffix(".json")
        target.write_text(json.dumps(build_sheet(sheet), ensure_ascii=False, indent=1) + "\n",
                          encoding="utf-8", newline="\n")
        print(f"{sheet.name} -> {target.name}")


if __name__ == "__main__":
    main()
