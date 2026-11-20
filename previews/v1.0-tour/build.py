"""Add the hosted page tour after the standalone reading ZIPs have been built."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--site', type=Path, required=True)
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--output', type=Path, help='copy an older, unguided site into a new directory')
mode.add_argument('--integrate', action='store_true', help='finish a newly composed demo website')
args = parser.parse_args()
source = args.site.resolve()
target = source if args.integrate else args.output.resolve()
driver = BASE / 'node_modules/driver.js'
if not args.integrate and (target.exists() or source in target.parents):
    raise SystemExit('Use a new output directory outside the source site')
if not (driver / 'dist/driver.js.iife.js').is_file():
    raise SystemExit('Run npm ci --prefix previews/v1.0-tour first')
if not (source / 'sources.json').is_file() or (source / 'guide.js').exists():
    raise SystemExit('Expected a composed demo website')
if (source / 'tour-assets').exists():
    raise SystemExit('This site already includes Page tour; serve it directly')
inventories = {}
for path in source.rglob('export-inventory.json'):
    inventory = json.loads(path.read_text())
    if inventory.get('signed') is not False or inventory.get('delivery_mode', 'reading') != 'reading':
        raise SystemExit('Only unsigned reading copies can receive the hosted tour')
    inventories[path.relative_to(source)] = inventory
if not args.integrate:
    shutil.copytree(source, target)
assets = target / 'tour-assets'
assets.mkdir()
for name in ('tour.js', 'tour.css'):
    shutil.copy2(BASE / name, assets / name)
for name in ('driver.js.iife.js', 'driver.css'):
    shutil.copy2(driver / 'dist' / name, assets / name)
shutil.copy2(driver / 'license', assets / 'driver-LICENSE.txt')
# Each hosted reader is also a movable directory. It must not reach outside
# its inventory for scripts, styles or the bundled dependency license.
tour_files = [
    {'path': 'tour-assets/' + item.name, 'bytes': item.stat().st_size,
     'sha256': hashlib.sha256(item.read_bytes()).hexdigest()}
    for item in sorted(assets.iterdir())
]
reader_roots = {target / relative.parent for relative in inventories}
for root in reader_roots:
    shutil.copytree(assets, root / 'tour-assets')
pages = [target / 'index.html']
for lang in ('en', 'zh-CN'):
    pages.extend([target / lang / 'index.html', target / lang / 'replay.html'])
pages.extend(target.glob('current/*/*/index.html'))
pages.extend(target.glob('recordings/*/*/index.html'))
changed = {}
for page in pages:
    text = page.read_text()
    # Localized homepages already resolve assets through <base href="../">.
    base = target if '<base href="../">' in text else page.parent
    scope = page.parent.parent if page.parent.parent in reader_roots else target
    prefix = Path(os.path.relpath(scope / 'tour-assets', base)).as_posix()
    head = ''.join(f'<link rel="stylesheet" href="{prefix}/{name}">' for name in ('driver.css', 'tour.css'))
    head += ''.join(f'<script defer src="{prefix}/{name}"></script>' for name in ('driver.js.iife.js', 'tour.js'))
    if text.count('</head>') != 1:
        raise SystemExit(f'Expected one HTML head: {page}')
    body = text.replace('</head>', head + '</head>').encode('utf-8')
    page.write_bytes(body)
    changed[page] = (len(body), hashlib.sha256(body).hexdigest())
# Update the hosted HTML and add its local assets. Downloads stay untouched.
for relative, inventory in inventories.items():
    path = target / relative
    for item in inventory['files']:
        update = changed.get(path.parent / item['path'])
        if update is not None:
            item['bytes'], item['sha256'] = update
    inventory['files'] = sorted(inventory['files'] + tour_files, key=lambda item: item['path'])
    inventory['bytes_excluding_inventory'] = sum(item['bytes'] for item in inventory['files'])
    path.write_text(json.dumps(inventory, indent=2) + '\n')
print(target / 'index.html')
