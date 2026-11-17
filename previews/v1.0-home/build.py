"""Build a separate homepage preview from public recordings and reader assets."""
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
sys.path.insert(0, str(READER))
from graph_navigation import refresh_graph_navigation


def refresh_reader(root):
    inventory = json.loads((root / "export-inventory.json").read_text())
    if inventory.get("signed") is not False or inventory.get("delivery_mode", "reading") != "reading":
        raise ValueError("Preview requires an unsigned reading copy")
    catalog = json.loads(base64.b64decode(re.search(r'"([A-Za-z0-9+/=]+)"', (root / "assets/catalog.js").read_text()).group(1)))

    def saved(ref):
        text = (root / ref["path"].replace(".json.gz", ".js")).read_text()
        return json.loads(gzip.decompress(base64.b64decode(re.search(r',"([A-Za-z0-9+/=]+)"', text).group(1))))

    refresh_graph_navigation(root, catalog, saved)
    run = next(iter(catalog["runs"]))
    for language in ("en", "zh-CN"):
        page = root / language / "index.html"
        text = page.read_text()
        bootstrap = '<script>if(!new URL(location.href).searchParams.has("run")){const u=new URL(location.href);u.searchParams.set("run",' + json.dumps(run) + ');history.replaceState(null,"",u);}</script>'
        text = text.replace("<body>", "<body>" + bootstrap)
        text = text.replace("</head>", '<link rel="stylesheet" href="../assets/evidence-preview.css"></head>')
        text = text.replace("</body>", '<script src="../assets/evidence-preview.js"></script></body>')
        text = text.replace("const overviewQ=q+'&lens=default&detail=summary';", "const overviewQ=q+scopeQuery+'&lens=default&detail=summary';")
        page.write_text(text)
    for extension in ("css", "js"):
        shutil.copy2(READER / ("evidence." + extension), root / "assets" / ("evidence-preview." + extension))
    shutil.copy2(REPO / "internal/dashboard/context.js", root / "assets/context.js")
    link_comparison(root, "index.html")
    inventory["files"] = [
        {"path": str(p.relative_to(root)), "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in sorted(root.rglob("*")) if p.is_file() and p.name != "export-inventory.json"
    ]
    inventory["bytes_excluding_inventory"] = sum(item["bytes"] for item in inventory["files"])
    inventory["ui_review"] = {"formal_ui_approval": "pending"}
    (root / "export-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")


def link_comparison(root, filename):
    shutil.copy2(REPO / "internal/dashboard/compare.js", root / "assets/compare.js")
    for language in ("en", "zh-CN"):
        page = root / language / filename
        text = page.read_text()
        if "await window.AgentCompareUI.openFromURL(INITIAL);" not in text:
            text = text.replace("await loadRun(first);", "await loadRun(first);\n  await window.AgentCompareUI.openFromURL(INITIAL);")
        page.write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="public site from agentprov demo export")
    parser.add_argument("--screenshots", type=Path, help="optional case-detail screenshots from reader acceptance")
    parser.add_argument("--output", type=Path, required=True, help="new preview directory")
    args = parser.parse_args()
    target = args.output.resolve()
    target.mkdir(parents=True, exist_ok=False)
    for name in ("index.html", "home.js", "home.css", "home-apple.css", "diagrams.js", "diagrams.css"):
        shutil.copy2(BASE / name, target / name)
    shutil.copytree(BASE / "media", target / "media")
    shutil.copytree(args.archive.resolve(), target / "archive")
    link_comparison(target / "archive", "replay.html")
    subprocess.run([sys.executable, str(READER / "build.py"), "--output", str(target / "current")], check=True)
    if args.screenshots:
        shutil.copytree(args.screenshots.resolve(), target / "screenshots")
    else:
        # These optional screenshots supplement the live reader links.
        for name in ("investigation", "workspace", "browser"):
            (target / "screenshots").mkdir(exist_ok=True)
            source = {"workspace": "remote", "browser": "native"}.get(name, name)
            shutil.copy2(BASE / "media" / (source + "-zh-CN.png"), target / "screenshots" / (name + ".png"))
    (target / "downloads").mkdir()
    sources = []
    for name in ("task-investigation", "native-matrix", "workspace-contract", "browser-detailed", "browser-basic", "notebook-detailed", "notebook-basic"):
        source = REPO / "docs/benchmarks/v1.0-candidate/replays" / (name + ".zip")
        if name == "workspace-contract":
            source = READER / "fixtures/workspace-contract.zip"
        shutil.copy2(source, target / "downloads" / source.name)
        sources.append({"name": name, "source": str(source.relative_to(REPO)), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()})
        if name not in ("browser-basic", "notebook-basic", "notebook-detailed"):
            continue
        root = target / "recordings" / name
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                path = Path(info.filename)
                if path.is_absolute() or ".." in path.parts or "\\" in info.filename:
                    raise ValueError("Invalid archive path")
            archive.extractall(root)
        refresh_reader(root)
    (target / "sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    subprocess.run(["node", str(BASE / "render-guides.cjs"), str(target)], check=True)
    print(target / "index.html")


if __name__ == "__main__":
    main()
