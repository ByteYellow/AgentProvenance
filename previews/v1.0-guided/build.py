"""Add a review-only case guide to an already built demo site."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--site', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
target = args.output.resolve()
if target.exists():
    raise SystemExit('Use a new preview directory')
shutil.copytree(args.site.resolve(), target)
for name in ('guide.js', 'guide.css'):
    shutil.copy2(BASE / name, target / name)
pages = [target / 'index.html']
for language in ('en', 'zh-CN'):
    pages.extend([target / language / 'index.html', target / language / 'replay.html'])
pages.extend(target.glob('current/*/*/index.html'))
pages.extend(target.glob('recordings/*/*/index.html'))
for page in pages:
    depth = len(page.relative_to(target).parts) - 1
    prefix = '../' * depth
    text = page.read_text()
    text = text.replace('</head>', f'<link rel="stylesheet" href="{prefix}guide.css"></head>')
    text = text.replace('</body>', f'<script src="{prefix}guide.js"></script></body>')
    page.write_text(text)
for asset in target.glob('current/*/assets/evidence.js'):
    shutil.copy2(REPO / 'internal/dashboard/evidence.js', asset)
for inventory_path in target.rglob('export-inventory.json'):
    inventory = json.loads(inventory_path.read_text())
    if inventory.get('signed') is not False or inventory.get('delivery_mode', 'reading') != 'reading':
        raise SystemExit('Guidance requires unsigned reading copies')
    root = inventory_path.parent
    inventory['files'] = [
        {'path': p.relative_to(root).as_posix(), 'bytes': p.stat().st_size,
         'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in sorted(root.rglob('*')) if p.is_file() and p != inventory_path
    ]
    inventory['bytes_excluding_inventory'] = sum(item['bytes'] for item in inventory['files'])
    inventory['ui_review'] = {'case_guidance': 'preview_only'}
    inventory_path.write_text(json.dumps(inventory, indent=2) + '\n')
print(target / 'index.html')
