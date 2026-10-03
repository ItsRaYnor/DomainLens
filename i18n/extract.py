"""The English text of the templates, cut the way static/js/translate.js cuts it.

Used by the coverage test (every fixed text in a template has Dutch) and
when adding translations. An element whose children are all inline markup
(a sentence with a link or <strong> in it) is one "block", keyed by its
plain text; other text is taken node by node, plus the attributes a reader
sees (placeholder, title, aria-label, alt). Jinja is removed first: text
that is filled in at render time is data, not something to translate.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

INLINE = {"a", "strong", "em", "b", "i", "code", "span", "br", "small", "abbr", "kbd", "sup", "sub"}
SKIP = {"script", "style", "code", "pre", "textarea", "kbd", "samp", "noscript", "svg", "title"}
ATTRS = ("placeholder", "title", "aria-label", "alt")
VOID = {"br", "input", "img", "meta", "link", "hr", "source", "wbr", "col"}
_JINJA_VALUE = "⁣"   # stands in for {{ ... }}; text holding one is data


def norm(text):
    return " ".join(str(text).split())


def strip_jinja(source):
    source = re.sub(r"\{#.*?#\}", "", source, flags=re.S)
    source = re.sub(r"\{%.*?%\}", "", source, flags=re.S)
    source = re.sub(r"\{\{.*?\}\}", _JINJA_VALUE, source, flags=re.S)
    return source


def wanted(text):
    return bool(text) and _JINJA_VALUE not in text and re.search(r"[A-Za-z]{2}", text) is not None


class _Node:
    __slots__ = ("tag", "children", "text", "own", "texts", "blocks", "skip", "start", "parts")

    def __init__(self, tag, skip, start=0):
        self.tag, self.skip, self.start = tag, skip, start
        self.children, self.text, self.own = [], [], []
        self.texts, self.blocks = [], []     # found below, not yet committed
        self.parts = []                      # every text node below, for a block's fallback


class _Parser(HTMLParser):
    def __init__(self, source=""):
        super().__init__(convert_charrefs=True)
        self.stack = [_Node("#root", False)]
        self.attr_texts = set()
        self.source = source
        self.lines = [0]
        for line in source.splitlines(keepends=True):
            self.lines.append(self.lines[-1] + len(line))
        self.block_html = {}                 # block text -> its inner HTML (source)
        self.block_parts = {}                # block text -> its text nodes

    def _offset(self):
        line, col = self.getpos()
        return self.lines[line - 1] + col

    def handle_starttag(self, tag, attrs):
        skip = self.stack[-1].skip or tag in SKIP
        if not skip:
            values = dict(attrs)
            for key in ATTRS:
                if wanted(norm(values.get(key) or "")):
                    self.attr_texts.add(norm(values[key]))
            if values.get("type") in ("button", "submit") and wanted(norm(values.get("value") or "")):
                self.attr_texts.add(norm(values["value"]))
        self.stack[-1].children.append(tag)
        if tag not in VOID:
            start = self._offset() + len(self.get_starttag_text() or "")
            self.stack.append(_Node(tag, skip, start))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack[-1].tag == tag:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in VOID or not any(n.tag == tag for n in self.stack[1:]):
            return
        end = self._offset()
        while True:
            node = self.stack.pop()
            parent = self.stack[-1]
            parent.text.extend(node.text)
            parent.parts.extend(t for t in node.own if wanted(t))
            parent.parts.extend(node.parts)
            if not node.skip:
                block = bool(node.children) and all(c in INLINE for c in node.children)
                content = norm("".join(node.text))
                if block and wanted(content):
                    parent.blocks.append(content)
                    if node.tag == tag:
                        self.block_html[content] = " ".join(self.source[node.start:end].split())
                    self.block_parts[content] = [t for t in node.own if wanted(t)] + node.parts
                elif not block or not content:
                    parent.texts.extend(t for t in node.own if wanted(t))
                    parent.texts.extend(node.texts)
                    parent.blocks.extend(node.blocks)
                else:
                    # A block holding data ({{ ... }}): its parts on their own.
                    parent.texts.extend(t for t in node.own if wanted(t))
                    parent.texts.extend(node.texts)
            if node.tag == tag:
                return

    def handle_data(self, data):
        node = self.stack[-1]
        node.text.append(data)
        if not node.skip:
            node.own.append(norm(data))

    def result(self):
        while len(self.stack) > 1:
            self.handle_endtag(self.stack[-1].tag)
        root = self.stack[0]
        texts = {t for t in root.texts + [norm(t) for t in root.own] if wanted(t)} | self.attr_texts
        return texts, set(root.blocks)


def template_units(path):
    """(texts, blocks): the English a template shows, as translate.js sees it."""
    parser = _Parser(strip_jinja(Path(path).read_text(encoding="utf-8")))
    parser.feed(parser.source)
    return parser.result()


def template_blocks(path):
    """{block text: (inner HTML, [text nodes])} of a template, for translating
    a sentence with its markup, or else its parts one by one."""
    parser = _Parser(strip_jinja(Path(path).read_text(encoding="utf-8")))
    parser.feed(parser.source)
    parser.result()
    return {k: (parser.block_html.get(k, ""), parser.block_parts.get(k, []))
            for k in parser.block_parts}


def all_template_units(root):
    texts, blocks = set(), set()
    for path in sorted(Path(root, "templates").rglob("*.html")):
        t, b = template_units(path)
        texts |= t
        blocks |= b
    return texts, blocks
