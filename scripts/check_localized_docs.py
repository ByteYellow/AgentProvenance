#!/usr/bin/env python3
"""Check Chinese documentation coverage and local links without network access."""

from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]


def prose(path):
    return re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.S)


def anchors(path):
    text = prose(path)
    result = set(re.findall(r'\bid=["\']([^"\']+)["\']', text))
    seen = set()
    for title in re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", text, re.M):
        title = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", title)
        slug = re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")
        candidate, index = slug, 0
        while candidate in seen:
            index += 1
            candidate = f"{slug}-{index}"
        seen.add(candidate)
        result.add(candidate)
    return result


def main():
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "*.md"], cwd=ROOT
    ).decode().split("\0")
    files = [ROOT / name for name in tracked if name]
    chinese = [p for p in files if "zh-CN" in p.parts or p.name.endswith(".zh-CN.md")]
    errors = []
    for path in files:
        if path in chinese or path.name in {"AGENTS.md", "SKILL.md"}:
            continue
        candidates = [path.with_name(path.stem + ".zh-CN.md")]
        if path.is_relative_to(ROOT / "docs"):
            candidates.append(ROOT / "docs/zh-CN" / path.relative_to(ROOT / "docs"))
        if not any(p.is_file() for p in candidates):
            errors.append(f"{path.relative_to(ROOT)}: Chinese document missing")

    count = 0
    for path in chinese:
        text = prose(path)
        targets = re.findall(r"\]\(([^\s)]+)", text)
        targets += re.findall(r'(?:href|src)="([^"]+)"', text)
        for target in targets:
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            destination = path.parent / unquote(url.path) if url.path else path
            count += 1
            if not destination.exists():
                errors.append(f"{path.relative_to(ROOT)}: missing {target}")
            elif url.fragment and destination.suffix == ".md":
                if unquote(url.fragment) not in anchors(destination):
                    errors.append(f"{path.relative_to(ROOT)}: missing heading {target}")
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Checked {len(chinese)} Chinese documents and {count} local links/images")
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
