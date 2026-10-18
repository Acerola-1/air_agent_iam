"""Compare configured secret values without executing .env or overwriting evidence."""
from datetime import datetime, timezone
from pathlib import Path
import os
import shlex
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
output = Path(sys.argv[1]).resolve()
if output.exists():
    raise SystemExit('拒绝覆盖已有证据，请使用新的文件名')
values = {}
for key, value in os.environ.items():
    if key.startswith('IAM_') and key.endswith(('_PASSWORD', '_SECRET')) and len(value) >= 12:
        values[(key, value)] = True
configs = [p for p in root.glob('.env*') if p.is_file() and p.name != '.env.example']
for config in configs:
    for line in config.read_text().splitlines():
        key, sep, rhs = line.removeprefix('export ').partition('=')
        key = key.strip()
        if not sep or not key.endswith(('_PASSWORD', '_SECRET')):
            continue
        try:
            parts = shlex.split(rhs, comments=True)
        except ValueError:
            raise SystemExit(f'配置语法不合法：{config.name}（未显示内容）')
        value = parts[0] if parts else ''
        if len(value) >= 12:
            values[(key, value)] = True
if not values:
    raise SystemExit('没有可比对的秘密配置，不能声明PASS')
binary = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf', '.jar', '.zip'}
hits = []
# Scan tracked files (even if later ignored) and unignored additions. Private
# backups and local configuration are not delivery files; tracked secrets still
# fail the gate. -z preserves filenames containing whitespace or newlines.
inventory = subprocess.run(
    ['git', '-c', 'core.fsmonitor=false', 'ls-files', '-z', '--cached',
     '--others', '--exclude-standard'],
    cwd=root, check=True, stdout=subprocess.PIPE,
).stdout
files = sorted(set(os.fsdecode(name) for name in inventory.split(b'\0') if name))
for name in files:
    file = root / name
    if not file.is_file() or file.is_symlink():
        continue
    if file.suffix.lower() in binary or file.resolve() == output:
        continue
    data = file.read_bytes()
    for key, value in values:
        if value.encode() in data:
            hits.append((key, str(file.relative_to(root))))
lines = [f'秘密扫描 {datetime.now(timezone.utc).isoformat()}',
         f'配置文件数：{len(configs)}；比对秘密数：{len(values)}（值不打印）',
         f'交付文件范围：Git tracked + unignored additions，共{len(files)}个路径']
lines.extend(f'HIT {key}: {file}' for key, file in sorted(set(hits)))
lines.append('结果：FAIL' if hits else '结果：PASS，交付物中真实秘密零命中')
output.parent.mkdir(parents=True, exist_ok=True)
with output.open('x') as handle:
    handle.write('\n'.join(lines) + '\n')
print('\n'.join(lines))
raise SystemExit(1 if hits else 0)
