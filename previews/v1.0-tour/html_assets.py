"""Attach the hosted tour without reserializing a reader or interpreting inline code."""
from collections import Counter
from html import escape
from html.parser import HTMLParser
import os
from pathlib import Path


class ReaderHead(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_head = False
        self.end = None
        self.base = None
        self.assets = Counter()

    def handle_starttag(self, tag, attrs):
        if tag == "head":
            if self.in_head or self.end is not None:
                raise ValueError("multiple HTML heads")
            self.in_head = True
        if self.in_head:
            attrs = dict(attrs)
            if tag == "base" and self.base is None:
                self.base = attrs.get("href")
            if tag == "script" or (tag == "link" and "stylesheet" in (attrs.get("rel") or "").split()):
                self.assets[attrs.get("src" if tag == "script" else "href")] += 1

    def handle_endtag(self, tag):
        if tag == "head" and self.in_head:
            self.end = self.getpos()
            self.in_head = False


def hosted_page(text, page, assets):
    head = ReaderHead()
    head.feed(text)
    head.close()
    if head.end is None or head.base not in (None, "../"):
        raise ValueError(f"Invalid reader head or base: {page}")
    base = page.parent / (head.base or ".")
    prefix = Path(os.path.relpath(assets, base)).as_posix()
    tags = []
    for name, template in (("tour.css", '<link rel="stylesheet" href="{}">'),
                           ("tour.js", '<script defer src="{}"></script>')):
        href = f"{prefix}/{name}"
        if head.assets[href] > 1:
            raise ValueError(f"Duplicate asset: {page}: {href}")
        if not head.assets[href]:
            tags.append(template.format(escape(href, quote=True)))
    line, col = head.end
    offset = sum(len(s) + 1 for s in text.split("\n", line - 1)[:line - 1]) + col
    return text[:offset] + "".join(tags) + text[offset:]
