"""Compare configured secret values without executing .env or overwriting evidence."""
from datetime import datetime, timezone
from pathlib import Path
import os
import shlex
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
ignored = {'node_modules', '.venv', 'target', '__pycache__', '.git', 'out'}
binary = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf', '.jar', '.zip'}
hits = []
for folder in ('server/src', 'scripts', 'contracts', 'web/src', 'web', 'openspec', 'docs', 'tools', 'server/logs'):
    path = root / folder
    if not path.exists():
        continue
    for parent, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignored]
        for name in files:
            file = Path(parent) / name
            if file.suffix.lower() in binary or file.resolve() == output:
                continue
            data = file.read_bytes()
            for key, value in values:
                if value.encode() in data:
                    hits.append((key, str(file.relative_to(root))))
lines = [f'秘密扫描 {datetime.now(timezone.utc).isoformat()}',
         f'配置文件数：{len(configs)}；比对秘密数：{len(values)}（值不打印）']
lines.extend(f'HIT {key}: {file}' for key, file in sorted(set(hits)))
lines.append('结果：FAIL' if hits else '结果：PASS，交付物中真实秘密零命中')
output.parent.mkdir(parents=True, exist_ok=True)
with output.open('x') as handle:
    handle.write('\n'.join(lines) + '\n')
print('\n'.join(lines))
raise SystemExit(1 if hits else 0)
