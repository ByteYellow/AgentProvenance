"""Build the same embedded reader used by agentprov, outside the evidence tree."""
import atexit
from functools import lru_cache
from pathlib import Path
import subprocess
import tempfile


@lru_cache(maxsize=1)
def reader_tool():
    temp = tempfile.TemporaryDirectory(prefix="agentprov-site-builder-")
    atexit.register(temp.cleanup)
    binary = Path(temp.name) / "demo-reader"
    subprocess.run(["go", "build", "-o", str(binary), "./scripts/demo-reader"],
                   cwd=Path(__file__).resolve().parents[2], check=True)
    return binary


def compose_reader(root, run, production, tool=None):
    subprocess.run([str(tool or reader_tool()), "-dir", str(root), "-run", run]
                   + (["-gallery"] if production else []), check=True)
    # Only an extracted, unsigned staging copy reaches here. These old UI
    # files are now bundled in reader.js/css; never touch catalog or data.
    modules = ("context", "workspace", "access-control", "search", "compare", "export")
    old_assets = [name + ext for name in modules for ext in (".js", ".css")]
    for name in old_assets + ["search-engine.js", "compare-engine.js"]:
        (root / "assets" / name).unlink(missing_ok=True)
