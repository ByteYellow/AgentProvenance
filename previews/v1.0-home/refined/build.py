"""Add a separate visual variant to an existing local demo preview."""
import argparse
import hashlib
from pathlib import Path
import shutil

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--site", type=Path, required=True)
args = parser.parse_args()
site = args.site.resolve()
source = Path(__file__).resolve().parent
baseline = site / "index.html"
before = hashlib.sha256(baseline.read_bytes()).hexdigest()
for asset in ("home.js", "home-apple.css", "current", "archive"):
    if not (site / asset).exists():
        raise ValueError(f"Missing baseline preview asset: {asset}")
shutil.copy2(source / "index.html", site / "refined.html")
shutil.copy2(source / "refined.css", site / "refined.css")
shutil.copy2(source.parent / "home.js", site / "home.js")
shutil.copytree(source / "media", site / "refined-media", dirs_exist_ok=True)
assert before == hashlib.sha256(baseline.read_bytes()).hexdigest()
print(f"Preview: {site / 'refined.html'}")
print(f"Preserved baseline SHA-256: {before}")
