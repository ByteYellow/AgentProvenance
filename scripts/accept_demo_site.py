#!/usr/bin/env python3
"""Check the composed website, preserved evidence, and downloaded offline reader."""
import argparse
from functools import partial
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import zipfile

from accept_static_demo import QuietHandler

REPO = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_inventory(root):
    inventory = json.loads((root / "export-inventory.json").read_text())
    assert inventory["signed"] is False
    assert inventory.get("delivery_mode", "reading") == "reading"
    assert "ui_review" not in inventory
    assert inventory["reader_build"]["formal_ui_approval"] == "approved"
    expected = {item["path"]: item for item in inventory["files"]}
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    assert actual == set(expected) | {"export-inventory.json"}
    for name, item in expected.items():
        file = root / name
        assert file.stat().st_size == item["bytes"], name
        assert digest(file) == item["sha256"], name
    for extension in ("js", "css"):
        asset = root / "assets" / ("evidence." + extension)
        assert digest(asset) == digest(REPO / "internal/dashboard" / asset.name)
    for language in ("en", "zh-CN"):
        page = (root / language / "index.html").read_text()
        assert page.count('src="../assets/evidence.js"') == 1
        assert "evidence-preview" not in page
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=Path("output/demo-site-acceptance"))
    args = parser.parse_args()
    site, archive, report = args.site.resolve(), args.archive.resolve(), args.report.resolve()
    report.mkdir(parents=True, exist_ok=True)
    for extension in ("js", "css"):
        asset = "evidence." + extension
        assert digest(site / "assets" / asset) == digest(REPO / "internal/dashboard" / asset)
    preserved = 0
    for source in archive.rglob("*"):
        if not source.is_file():
            continue
        relative = source.relative_to(archive)
        if relative.parts[0] in ("data", "downloads") or relative.name in ("replay-manifest.json", "replay-catalog.json"):
            assert digest(source) == digest(site / relative), relative
            preserved += 1
    inventories = {str(root.parent.relative_to(site)): check_inventory(root.parent)
                   for root in site.glob("current/*/export-inventory.json")}
    inventories.update({str(root.parent.relative_to(site)): check_inventory(root.parent)
                        for root in site.glob("recordings/*/export-inventory.json")})
    assert len(inventories) == 8
    size = sum(p.stat().st_size for p in site.rglob("*") if p.is_file())
    assert size <= 900 * 1024 * 1024, "Static website exceeds the publication budget"
    for source in json.loads((site / "sources.json").read_text()):
        assert digest(site / "downloads" / (source["name"] + ".zip")) == source["sha256"]
        assert digest(site / source["reading_copy"]) == source["reading_copy_sha256"]

    env = {**os.environ, "AGENTPROV_SITE_PRODUCTION": "1"}
    ThreadingHTTPServer.request_queue_size = 128
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(site.parent)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    commands = []

    def run(*args, extra_env=None):
        command = [str(value) for value in args]
        result = subprocess.run(command, cwd=REPO, env={**env, **(extra_env or {})})
        commands.append({"command": command, "exit_code": result.returncode})
        (report / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        result.check_returncode()

    try:
        url = f"http://127.0.0.1:{server.server_port}/{site.name}/"
        run("node", "previews/v1.0-home/refined/check.cjs", url, report / "home")
        run("node", "previews/v1.0-home/check.cjs", url, report / "flows", site)
        run("node", "previews/v1.0-reader/check.cjs", report / "reader", extra_env={"AGENTPROV_PREVIEW_URL": url + "current"})
        run("node", "previews/v1.0-reader/check-portable.cjs", site / "current", report / "offline")
        run("node", "previews/v1.0-reader/check-select.cjs", site / "current", report / "select")
        with tempfile.TemporaryDirectory(prefix="agentprov-downloaded-reader-") as folder:
            root = Path(folder)
            with zipfile.ZipFile(report / "flows/workspace-current.zip") as downloaded:
                for item in downloaded.infolist():
                    name = Path(item.filename)
                    assert not name.is_absolute() and ".." not in name.parts and "\\" not in item.filename
                downloaded.extractall(root / "workspace")
            check_inventory(root / "workspace")
            run("node", "previews/v1.0-reader/check-reader.cjs", root, report / "downloaded", extra_env={"AGENTPROV_PREVIEW_URL": ""})
    finally:
        server.shutdown()
        server.server_close()
    manifest = json.loads((site / "replay-manifest.json").read_text())
    result = {"passed": True, "source_commit": manifest["commit"], "preserved_files": preserved, "inventories": inventories,
              "site_bytes": size, "commands": commands}
    (report / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
