"""Add a local, spotlight-style tour to an approved demo website."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--site', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
source, target = args.site.resolve(), args.output.resolve()
driver = BASE / 'node_modules/driver.js'
if target.exists() or source == target or source in target.parents:
    raise SystemExit('Use a new output directory outside the source site')
if not (driver / 'dist/driver.js.iife.js').is_file():
    raise SystemExit('Run npm ci --prefix previews/v1.0-tour first')
if (source / 'guide.js').exists():
    raise SystemExit('Use the approved site, not the previous guidance preview')
for path in source.rglob('export-inventory.json'):
    value = json.loads(path.read_text())
    if value.get('signed') is not False or value.get('delivery_mode', 'reading') != 'reading':
        raise SystemExit('Only unsigned reading copies can receive the preview UI')
shutil.copytree(source, target)
assets = target / 'tour-assets'
assets.mkdir()
for name in ('tour.js', 'tour.css'):
    shutil.copy2(BASE / name, assets / name)
for name in ('driver.js.iife.js', 'driver.css'):
    shutil.copy2(driver / 'dist' / name, assets / name)
shutil.copy2(driver / 'license', assets / 'driver-LICENSE.txt')
pages = [target / 'index.html']
for lang in ('en', 'zh-CN'):
    pages.extend([target / lang / 'index.html', target / lang / 'replay.html'])
pages.extend(target.glob('current/*/*/index.html'))
pages.extend(target.glob('recordings/*/*/index.html'))
for page in pages:
    text = page.read_text()
    # Localized homepages already resolve assets through <base href="../">.
    prefix = '' if '<base href="../">' in text else '../' * (len(page.relative_to(target).parts) - 1)
    head = ''.join(f'<link rel="stylesheet" href="{prefix}tour-assets/{name}">' for name in ('driver.css', 'tour.css'))
    head += ''.join(f'<script defer src="{prefix}tour-assets/{name}"></script>' for name in ('driver.js.iife.js', 'tour.js'))
    page.write_text(text.replace('</head>', head + '</head>'))
for path in target.rglob('export-inventory.json'):
    inventory = json.loads(path.read_text())
    root = path.parent
    inventory['files'] = [
        {'path': item.relative_to(root).as_posix(), 'bytes': item.stat().st_size,
         'sha256': hashlib.sha256(item.read_bytes()).hexdigest()}
        for item in sorted(root.rglob('*')) if item.is_file() and item != path
    ]
    inventory['bytes_excluding_inventory'] = sum(item['bytes'] for item in inventory['files'])
    inventory['ui_review'] = {'spotlight_tour': 'preview_only'}
    path.write_text(json.dumps(inventory, indent=2) + '\n')
print(target / 'index.html')
