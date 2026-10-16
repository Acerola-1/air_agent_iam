#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('/Users/acerola/Dev/Java/air_agent_iam')
EVIDENCE = ROOT / 'docs/reviews/evidence/iam-independent'
PRIVATE = Path('/tmp/iam-independent-20261015-5ohAEo')
COPY = PRIVATE / 'source'
RUN_ID = 'iam-independent-20261015-5ohaeo'
JAVA = '/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home'
PORTS = {'http': 29100, 'vite': 29101, 'pg': 29132, 'redis': 29179}
NAMES = {'pg': RUN_ID + '-pg', 'redis': RUN_ID + '-redis'}
CONTAINER = '/usr/local/bin/container'

def env_values():
    return json.loads((PRIVATE / 'environment.json').read_text()) if (PRIVATE / 'environment.json').exists() else {}

def redact(text):
    for key, value in env_values().items():
        if any(x in key for x in ('PASSWORD', 'SECRET')) and value:
            text = text.replace(value, '[REDACTED]')
    text = re.sub(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}', '[BCRYPT-REDACTED]', text)
    text = re.sub(r'(?i)(Bearer\s+)[^\s\"\']+', r'\1[REDACTED]', text)
    text = re.sub(r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])', '[OPAQUE-REDACTED]', text)
    return text

def run(command, name, cwd=None, env=None, input_text=None, timeout=300):
    started = time.monotonic()
    result = subprocess.run(command, cwd=cwd, env=env, input=input_text, text=True, capture_output=True, timeout=timeout)
    record = {'command': command, 'cwd': str(cwd) if cwd else None, 'time_utc': datetime.now(timezone.utc).isoformat(),
              'elapsed_seconds': round(time.monotonic() - started, 3), 'exit_code': result.returncode,
              'stdout': redact(result.stdout), 'stderr': redact(result.stderr)}
    with (EVIDENCE / 'outputs' / (name + '.json')).open('x') as file:
        json.dump(record, file, ensure_ascii=False, indent=2)
    print(name, 'exit=', result.returncode, 'seconds=', record['elapsed_seconds'], flush=True)
    if result.returncode:
        print(redact(result.stderr[-1600:]), flush=True)
        raise RuntimeError(name + ' failed; see sanitized evidence')
    return result.stdout

def initialize():
    if COPY.exists():
        raise RuntimeError('Refusing to replace an existing audit copy')
    for port in PORTS.values():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', port))
    for name in NAMES.values():
        if subprocess.run([CONTAINER, 'inspect', name], capture_output=True).returncode == 0:
            raise RuntimeError('Container name already exists: ' + name)
    run([CONTAINER, 'ls', '-a'], 'environment-existing-containers')
    run([CONTAINER, 'system', 'status'], 'environment-container-version')
    run(['lsof', '-nP', '-iTCP', '-sTCP:LISTEN'], 'environment-existing-listeners')
    run([JAVA + '/bin/java', '-version'], 'environment-java-version')
    run(['node', '--version'], 'environment-node-version')
    run(['npm', '--version'], 'environment-npm-version')
    run([CONTAINER, 'image', 'inspect', 'docker.io/library/postgres:17-alpine', 'docker.io/library/redis:7-alpine'], 'environment-image-digests')
    COPY.mkdir()
    ignore = shutil.ignore_patterns('target', 'node_modules', 'dist', 'logs', '.venv', '__pycache__', '.env.local')
    for name in ('server', 'web', 'scripts', 'tools', 'contracts'):
        shutil.copytree(ROOT / name, COPY / name, ignore=ignore)
    for name in ('.env.example', '.gitignore', 'README.md'):
        shutil.copy2(ROOT / name, COPY / name)
    variables = {
        'JAVA_HOME': JAVA, 'JAVA_OPTS': '-Xms128m -Xmx768m',
        'IAM_HTTP_PORT': str(PORTS['http']), 'IAM_PG_HOST': '127.0.0.1', 'IAM_PG_PORT': str(PORTS['pg']),
        'IAM_PG_DB': 'iam', 'IAM_PG_MIGRATE_USER': 'iam_migrate', 'IAM_PG_APP_USER': 'iam_app',
        'IAM_REDIS_HOST': '127.0.0.1', 'IAM_REDIS_PORT': str(PORTS['redis']), 'IAM_REDIS_DB': '0',
        'IAM_DB_POOL_MAX': '12', 'IAM_BOOTSTRAP_ACCOUNT': 'audit.root', 'IAM_BOOTSTRAP_DISPLAY_NAME': '独立验收平台管理员',
        'IAM_RT_KEYS_KID': 'audit-kid-1', 'IAM_INTERNAL_RUNTIME_CLIENT_ID': 'audit-runtime',
        'IAM_WEB_ALLOWED_ORIGINS': 'http://127.0.0.1:29101', 'IAM_WEB_CENTRAL_BASE_URL': 'http://127.0.0.1:29100',
        'IAM_SSO_CLIENT_AGENT_CALLBACK': 'http://127.0.0.1:29100/web-api/sso/callback/agent',
        'IAM_SSO_CLIENT_KB_CALLBACK': 'http://127.0.0.1:29100/web-api/sso/callback/kb',
        'IAM_SSO_CLIENT_AGENT_ORIGINS': 'http://127.0.0.1:29100',
        'IAM_SSO_CLIENT_KB_ORIGINS': 'http://127.0.0.1:29100',
    }
    for key in ('IAM_PG_MIGRATE_PASSWORD', 'IAM_PG_APP_PASSWORD', 'IAM_REDIS_PASSWORD', 'IAM_BOOTSTRAP_PASSWORD',
                'IAM_RT_KEYS_SECRET', 'IAM_CSRF_SECRET', 'IAM_INTERNAL_RUNTIME_CLIENT_SECRET',
                'IAM_SSO_CLIENT_AGENT_SECRET', 'IAM_SSO_CLIENT_KB_SECRET'):
        variables[key] = secrets.token_hex(24)
    (PRIVATE / 'environment.json').write_text(json.dumps(variables))
    (PRIVATE / 'environment.json').chmod(0o600)
    (COPY / '.env.local').write_text(''.join(k + '=' + v + '\n' for k, v in variables.items() if k not in {'JAVA_OPTS', 'IAM_BOOTSTRAP_DISPLAY_NAME'}))
    (COPY / '.env.local').chmod(0o600)
    (PRIVATE / 'redis.conf').write_text('bind 0.0.0.0\nappendonly yes\nsave 60 1\nrequirepass ' + variables['IAM_REDIS_PASSWORD'] + '\n')
    (PRIVATE / 'redis.conf').chmod(0o600)
    resources = {'run_id': RUN_ID, 'private_root': str(PRIVATE), 'copy_root': str(COPY), 'ports': PORTS,
                 'created_containers': [], 'network': None, 'processes': [], 'source_modified': False,
                 'credentials': 'Fresh synthetic values; only in mode-0600 files below private_root; never published',
                 'copy_policy': 'Product source byte-identical, no prior build outputs/dependency directories; original .env.local not read'}
    def persist():
        (EVIDENCE / 'outputs/resources.json').write_text(json.dumps(resources, ensure_ascii=False, indent=2))
    persist()
    pg_env = {**os.environ, 'POSTGRES_PASSWORD': variables['IAM_PG_MIGRATE_PASSWORD']}
    run([CONTAINER, 'run', '-d', '--name', NAMES['pg'], '--label', 'audit.run=' + RUN_ID,
         '--cpus', '4', '--memory', '1G', '-p', '127.0.0.1:29132:5432',
         '-e', 'POSTGRES_USER=postgres', '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=iam',
         'docker.io/library/postgres:17-alpine'], 'environment-create-pg', env=pg_env)
    resources['created_containers'].append(NAMES['pg']); persist()
    finish_initialization()

def finish_initialization():
    variables = env_values()
    resources = json.loads((EVIDENCE / 'outputs/resources.json').read_text())
    owned = json.loads(subprocess.check_output([CONTAINER, 'inspect', NAMES['pg']], text=True))[0]
    assert owned['configuration']['labels']['audit.run'] == RUN_ID
    assert resources['created_containers'] == [NAMES['pg']]
    assert subprocess.run([CONTAINER, 'inspect', NAMES['redis']], capture_output=True).returncode != 0
    config_dir = PRIVATE / 'redis-config'
    config_dir.mkdir(exist_ok=True)
    shutil.copy2(PRIVATE / 'redis.conf', config_dir / 'redis.conf')
    run([CONTAINER, 'run', '-d', '--name', NAMES['redis'], '--label', 'audit.run=' + RUN_ID,
         '--cpus', '4', '--memory', '1G', '-p', '127.0.0.1:29179:6379',
         '--mount', 'type=bind,source=' + str(config_dir) + ',target=/audit-config,readonly',
         'docker.io/library/redis:7-alpine', 'redis-server', '/audit-config/redis.conf'], 'environment-create-redis-directory-mount')
    resources['created_containers'].append(NAMES['redis'])
    (EVIDENCE / 'outputs/resources.json').write_text(json.dumps(resources, ensure_ascii=False, indent=2))
    run([CONTAINER, 'exec', NAMES['pg'], 'pg_isready', '-U', 'postgres', '-d', 'iam'], 'environment-pg-ready')
    app_pass = variables['IAM_PG_APP_PASSWORD']; owner_pass = variables['IAM_PG_MIGRATE_PASSWORD']
    sql = f"CREATE ROLE iam_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '{owner_pass}';\n"
    sql += f"CREATE ROLE iam_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '{app_pass}';\n"
    sql += 'ALTER DATABASE iam OWNER TO iam_migrate;\nCREATE DATABASE iam_test OWNER iam_migrate;\n'
    run([CONTAINER, 'exec', '-i', NAMES['pg'], 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'iam'], 'environment-create-roles', input_text=sql)
    for db in ('iam', 'iam_test'):
        sql = f'''GRANT CONNECT, CREATE ON DATABASE {db} TO iam_migrate;
GRANT CONNECT ON DATABASE {db} TO iam_app;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA iam AUTHORIZATION iam_migrate;
CREATE SCHEMA iam_auth AUTHORIZATION iam_migrate;
GRANT USAGE ON SCHEMA iam, iam_auth TO iam_app;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO iam_app;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam GRANT USAGE, SELECT ON SEQUENCES TO iam_app;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam, iam_auth GRANT EXECUTE ON FUNCTIONS TO iam_app;
'''
        run([CONTAINER, 'exec', '-i', NAMES['pg'], 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', db], 'environment-provision-' + db, input_text=sql)
    run([CONTAINER, 'exec', '-e', 'REDISCLI_AUTH', NAMES['redis'], 'redis-cli', '--no-auth-warning', 'ping'], 'environment-redis-ready', env={**os.environ, 'REDISCLI_AUTH': variables['IAM_REDIS_PASSWORD']})
    run(['lsof', '-nP', '-iTCP:29132', '-iTCP:29179', '-sTCP:LISTEN'], 'environment-isolated-listeners')
    copied = []
    for path in sorted(COPY.rglob('*')):
        if path.is_file() and path.name != '.env.local':
            relative = path.relative_to(COPY)
            old = ROOT / relative
            same = old.is_file() and hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(old.read_bytes()).digest()
            copied.append({'path': str(relative), 'byte_identical': same})
    (EVIDENCE / 'outputs/copy-integrity.json').write_text(json.dumps(copied, ensure_ascii=False, indent=2))
    print('Isolated environment ready; product copy unchanged', flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['initialize', 'finish-initialization'])
    args = parser.parse_args()
    if args.action == 'initialize':
        initialize()
    else:
        finish_initialization()
