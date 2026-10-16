#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('root', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--baseline', type=Path)
args = parser.parse_args()
root = args.root.resolve()
excluded_trees = {'node_modules', 'target', 'dist', '.git', '__pycache__', 'logs', '.venv'}
excluded_outputs = ('docs/reviews/evidence/iam-independent/', 'docs/reviews/iam-independent-acceptance.md')
entries = []
for base, dirs, files in os.walk(root, followlinks=False):
    dirs[:] = sorted(d for d in dirs if d not in excluded_trees)
    for name in sorted(files):
        path = Path(base) / name
        rel = path.relative_to(root).as_posix()
        if any(rel.startswith(p) for p in excluded_outputs):
            continue
        stat = path.lstat()
        row = {'path': rel, 'size': stat.st_size, 'mtime_ns': stat.st_mtime_ns}
        if path.is_symlink():
            row['kind'] = 'symlink-not-followed'
        elif (name.startswith('.env') and name != '.env.example') or path.suffix.lower() in {'.dump', '.pem', '.key', '.p12', '.jks'}:
            row['kind'] = 'sensitive-content-omitted'
        else:
            row['kind'] = 'file'
            row['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(row)
result = {
    'captured_utc': datetime.now(timezone.utc).isoformat(),
    'root': str(root),
    'git': 'not-a-repository; no initialization; branch/HEAD/diff unavailable',
    'rules': 'No AGENTS.md found in project or ancestors; no project .qoder/skills directory',
    'excluded_generated_directory_names': sorted(excluded_trees),
    'excluded_audit_outputs': excluded_outputs,
    'sensitive_policy': 'Sensitive contents and secret hashes are not read or recorded; metadata only',
    'file_count': len(entries),
    'entries': entries,
}
if args.baseline:
    old = {e['path']: e for e in json.loads(args.baseline.read_text())['entries']}
    now = {e['path']: e for e in entries}
    result['comparison'] = {
        'added': sorted(now.keys() - old.keys()),
        'removed': sorted(old.keys() - now.keys()),
        'content_changed': [p for p in sorted(old.keys() & now.keys()) if old[p].get('sha256') != now[p].get('sha256')],
        'sensitive_metadata_changed': [p for p in sorted(old.keys() & now.keys()) if now[p]['kind'] == 'sensitive-content-omitted' and old[p] != now[p]],
    }
with args.output.open('x') as file:
    json.dump(result, file, ensure_ascii=False, indent=2)
    file.write('\n')
print(json.dumps({'output': str(args.output), 'file_count': len(entries), 'comparison': result.get('comparison')}, ensure_ascii=False))
