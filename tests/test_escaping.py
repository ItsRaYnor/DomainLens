"""Every page's escape helper escapes quotes.

lookup.js, compare.js and the settings page escaped <, > and & but not ".
Their result also went into attribute values -- title="${esc(url)}" for a
link found in an analysed mail -- so a " in a link or a file name written
by whoever sent the mail ended the attribute and added one of its own. The
CSP stopped scripts; a style or a second attribute still got through.
"""

import pathlib
import re
import unittest

JS = pathlib.Path(__file__).resolve().parent.parent / "static" / "js"


class EscapeTests(unittest.TestCase):
    def test_every_escape_helper_escapes_both_quotes(self):
        helpers = 0
        for path in sorted(JS.glob("*.js")):
            source = path.read_text(encoding="utf-8")
            for match in re.finditer(r"function (esc|escapeHtml)\(\w+\) \{(.*?)\n\s*\}", source, re.S):
                helpers += 1
                body = match.group(2)
                self.assertIn("&quot;", body, f"{path.name}: {match.group(1)}")
                self.assertIn("&#39;", body, f"{path.name}: {match.group(1)}")
        self.assertGreaterEqual(helpers, 6)


if __name__ == "__main__":
    unittest.main()
