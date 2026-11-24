"""Build the shared demo library as a preview or an approved release website."""
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[1]
READER = BASE.parent / "v1.0-reader"
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(READER))
from featured_cards import browser_card, investigation_card, team_card
from graph_navigation import refresh_graph_navigation
from compose import compose_reader, reader_tool
from workspace_card import workspace_card


def refresh_reader(root, production=False, *, legacy_navigation=True):
    inventory = json.loads((root / "export-inventory.json").read_text())
    if inventory.get("signed") is not False or inventory.get("delivery_mode", "reading") != "reading":
        raise ValueError("Reader refresh requires an unsigned reading copy")
    catalog = json.loads(base64.b64decode(re.search(r'"([A-Za-z0-9+/=]+)"', (root / "assets/catalog.js").read_text()).group(1)))

    def saved(ref):
        text = (root / ref["path"].replace(".json.gz", ".js")).read_text()
        return json.loads(gzip.decompress(base64.b64decode(re.search(r',"([A-Za-z0-9+/=]+)"', text).group(1))))

    if legacy_navigation:
        refresh_graph_navigation(root, catalog, saved)
    run = next(iter(catalog["runs"]))
    compose_reader(root, run, production)
    inventory["files"] = [
        {"path": str(p.relative_to(root)), "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in sorted(root.rglob("*")) if p.is_file() and p.name != "export-inventory.json"
    ]
    inventory["bytes_excluding_inventory"] = sum(item["bytes"] for item in inventory["files"])
    inventory["reader_build" if production else "ui_review"] = {"formal_ui_approval": "approved"}
    (root / "export-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")


def extract_reader(source, root):
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            path = Path(info.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in info.filename:
                raise ValueError("Invalid archive path")
        archive.extractall(root)


def add_x86_recordings(target, production):
    directory = REPO / "docs/benchmarks/v1.0-x86-completion/replays"
    manifest = json.loads((directory / "manifest.json").read_text())
    artifacts = {a["file"]: a for a in manifest["artifacts"] if a["delivery_mode"] == "reading"}
    sources = []
    for case in manifest["cases"]:
        name = "x86-" + case["id"]
        source = directory / case["reading"]
        artifact = artifacts[case["reading"]]
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if digest != artifact["sha256"] or artifact["run_id"] != case["run_id"]:
            raise ValueError(f"Invalid x86 replay: {name}")
        root = target / "recordings" / name
        extract_reader(source, root)
        refresh_reader(root, production, legacy_navigation=False)
        dest = target / "downloads" / (name + ".zip")
        shutil.copy2(source, dest)
        sources.append({"name": name, "run_id": case["run_id"], "source": str(source.relative_to(REPO)),
                        "sha256": digest, "reading_copy": str(dest.relative_to(target)), "reading_copy_sha256": digest})
    return sources


def build_home_pages(target, archive_root):
    """Render the single-source Apple homepage with build-time real-shard excerpts."""
    browser, png = browser_card(target / "current/browser")
    browser["png"]["asset"] = "refined-media/featured-browser.png"
    cards = {
        "investigation": investigation_card(target / "current/investigation"),
        "workspace": workspace_card(target / "current/workspace"),
        "browser": browser,
        "team": team_card(archive_root),
    }
    media_dir = target / "refined-media"
    media_dir.mkdir(exist_ok=True)
    for lang in ("zh-CN", "en"):
        shutil.copy2(BASE / "media" / f"team-{lang}.png", media_dir / f"team-{lang}.png")
    (target / browser["png"]["asset"]).write_bytes(png)

    shutil.copy2(BASE / "home.css", target / "home.css")
    shutil.copy2(BASE / "home.js", target / "home.js")
    data = json.dumps(cards, separators=(",", ":")).replace("<", "\\u003c")
    catalog_dir = archive_root.relative_to(target)
    catalog_base = catalog_dir.as_posix() + "/" if catalog_dir.parts else ""
    template = ((BASE / "index.html").read_text()
                .replace("__CATALOG_BASE__", catalog_base)
                .replace("__FEATURED_CARD_JSON__", data))
    (target / "index.html").write_text(template)
    for language in ("en", "zh-CN"):
        lang_dir = target / language
        lang_dir.mkdir(exist_ok=True)
        home = lang_dir / "index.html"
        if home.exists():
            shutil.copy2(home, lang_dir / "library.html")
        home.write_text(
            template.replace('<html lang="zh-CN">', f'<html lang="{language}">')
                    .replace("<head>", '<head><base href="../">')
        )


def build_reading_downloads(target, sources):
    """Package each refreshed unsigned reading copy once under downloads/reading/."""
    paths = {
        "task-investigation": "current/investigation",
        "native-matrix": "current/execution",
        "workspace-contract": "current/workspace",
        "browser-detailed": "current/browser",
        "browser-basic": "recordings/browser-basic",
        "notebook-basic": "recordings/notebook-basic",
        "notebook-detailed": "recordings/notebook-detailed",
    }
    folder = target / "downloads/reading"
    folder.mkdir(parents=True, exist_ok=True)
    for source in sources:
        root = target / paths[source["name"]]
        dest = folder / (source["name"] + ".zip")
        with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(root).as_posix())
        source["reading_copy"] = str(dest.relative_to(target))
        source["reading_copy_sha256"] = hashlib.sha256(dest.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="public site from agentprov demo export")
    parser.add_argument("--screenshots", type=Path, help="optional legacy screenshot argument (unused by single-source home)")
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    parser.add_argument("--production", action="store_true", help="build the approved homepage and preserve published reader paths")
    args = parser.parse_args()
    target = args.output.resolve()
    target.mkdir(parents=True, exist_ok=False)
    if args.production:
        shutil.copytree(args.archive.resolve(), target, dirs_exist_ok=True)
    else:
        shutil.copytree(args.archive.resolve(), target / "archive")
    for name in ("diagrams.js", "diagrams.css"):
        shutil.copy2(BASE / name, target / name)

    subprocess.run([reader_tool(), "-public", "-dir", target if args.production else target / "archive"], check=True)
    subprocess.run([sys.executable, str(READER / "build.py"), "--output", str(target / "current"), "--reader-tool", str(reader_tool())] + (["--production"] if args.production else []), check=True)

    (target / "downloads").mkdir(exist_ok=True)
    sources = []
    for name in ("task-investigation", "native-matrix", "workspace-contract", "browser-detailed", "browser-basic", "notebook-detailed", "notebook-basic"):
        source = REPO / "docs/benchmarks/v1.0-candidate/replays" / (name + ".zip")
        if name == "workspace-contract":
            source = READER / "fixtures/workspace-contract.zip"
        sources.append({"name": name, "source": str(source.relative_to(REPO)), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()})
        if name not in ("browser-basic", "notebook-basic", "notebook-detailed"):
            continue
        root = target / "recordings" / name
        extract_reader(source, root)
        refresh_reader(root, args.production)

    archive_root = target if args.production else target / "archive"
    build_home_pages(target, archive_root)
    build_reading_downloads(target, sources)

    sources.extend(add_x86_recordings(target, args.production))
    (target / "sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    subprocess.run(["node", str(BASE / "render-guides.cjs"), str(target)] + (["--production"] if args.production else []), check=True)
    if args.production:
        subprocess.run([sys.executable, str(BASE.parent / "v1.0-tour/build.py"), "--site", str(target), "--integrate"], check=True)
    print(target / "index.html")


if __name__ == "__main__":
    main()
