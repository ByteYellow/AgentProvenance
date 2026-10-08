#!/usr/bin/env python3
"""Make repository-relative Markdown links usable on a GitHub Release page."""
import argparse
from pathlib import Path
import posixpath
import re
from urllib.parse import quote, urlsplit, urlunsplit


def render(source, notes_path, repository, version):
    def replace(match):
        target = urlsplit(match[2])
        if target.scheme or target.netloc or not target.path:
            return match[0]
        path = posixpath.normpath(posixpath.join(posixpath.dirname(notes_path), target.path))
        if path.startswith(("../", "/")) or path == ".." or not Path(path).is_file():
            raise ValueError(f"Release-note link does not name a repository file: {match[2]}")
        url = urlunsplit(("https", "github.com",
                         f"/{repository}/blob/{quote(version, safe='')}/{quote(path, safe='/')}",
                         target.query, target.fragment))
        return f"{match[1]}{url})"

    # Release notes use inline links; leave fenced command examples untouched.
    fence = None
    output = []
    for line in source.splitlines(keepends=True):
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            if fence is None:
                fence = marker[1]
            elif marker[1][0] == fence[0] and len(marker[1]) >= len(fence):
                fence = None
            output.append(line)
            continue
        output.append(line if fence else re.sub(r"(!?\[[^\]\n]*\]\()([^\s()]+)\)", replace, line))
    return "".join(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("notes")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    print(render(Path(args.notes).read_text(encoding="utf-8"), args.notes,
                 args.repository, args.version), end="")
