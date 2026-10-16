import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
import httpx
import psycopg
import redis
from environment import EVIDENCE, PRIVATE, PORTS, env_values

ENV = env_values()
BASE = 'http://127.0.0.1:' + str(PORTS['http'])
SECRET_FIELDS = {'access_token', 'subject_token', 'secret', 'password', 'new_password', 'old_password',
                 'csrf_token', 'ticket', 'authorization', 'cookie', 'set-cookie', 'password_hash',
                 'token_digest', 'secret_digest', 'handle_digest', 'raw_token'}

def safe(value):
    if isinstance(value, dict):
        return {key: '[REDACTED]' if key.lower() in SECRET_FIELDS else safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe(item) for item in value]
    if isinstance(value, str):
        for key, secret in ENV.items():
            if any(part in key for part in ('PASSWORD', 'SECRET')) and secret:
                value = value.replace(secret, '[REDACTED]')
        value = re.sub(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}', '[BCRYPT-REDACTED]', value)
        value = re.sub(r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])', '[OPAQUE-REDACTED]', value)
    return value

class Evidence:
    def __init__(self, name):
        self.path = EVIDENCE / 'outputs' / (name + '.jsonl')
        self.file = self.path.open('x')
    def emit(self, case, **data):
        row = {'case': case, 'time_utc': datetime.now(timezone.utc).isoformat(), **data}
        self.file.write(json.dumps(safe(row), ensure_ascii=False, default=str) + '\n')
        self.file.flush()
        print(case, data.get('status', data.get('actual', 'recorded')), flush=True)
    def close(self):
        self.file.close()

class Api:
    def __init__(self, evidence):
        self.evidence = evidence
        self.client = httpx.Client(base_url=BASE, timeout=10, trust_env=False)
    def request(self, case, method, path, body=None, token=None, internal=False, expected=None, headers=None):
        h = dict(headers or {})
        if token:
            h['Authorization'] = 'Bearer ' + token
        auth = (ENV['IAM_INTERNAL_RUNTIME_CLIENT_ID'], ENV['IAM_INTERNAL_RUNTIME_CLIENT_SECRET']) if internal else None
        started = time.perf_counter()
        response = self.client.request(method, path, json=body, headers=h, auth=auth)
        elapsed = (time.perf_counter() - started) * 1000
        try:
            payload = response.json()
        except ValueError:
            payload = response.text[:300]
        self.evidence.emit(case, method=method, path=path, input=body, authenticated_as='internal-client' if internal else 'human' if token else 'anonymous',
                           expected=expected, status=response.status_code, elapsed_ms=round(elapsed, 3),
                           response=payload, response_headers={k: v for k,v in response.headers.items() if k in {'content-type','cache-control','pragma','x-request-id','access-control-allow-origin'}})
        return response, payload
    def login(self, case, account=None, password=None, audience='iam-admin'):
        response, body = self.request(case, 'POST', '/v1/auth/login', {
            'account': account or ENV['IAM_BOOTSTRAP_ACCOUNT'], 'password': password or ENV['IAM_BOOTSTRAP_PASSWORD'],
            'realm': 'workforce', 'audience': audience}, expected='200; active human identity, no automatic tenant selection when multiple')
        if response.status_code != 200:
            raise RuntimeError(case + ' prerequisite login failed; see evidence')
        return body['access_token'], body['identity']
    def introspect(self, case, token, audience='langgraph-runtime', expected=None, **extra):
        return self.request(case, 'POST', '/v1/internal/identity/introspect',
                            {'subject_token': token, 'audience': audience, **extra}, internal=True, expected=expected)
    def close(self):
        self.client.close()

def db(role='app', database='iam', autocommit=True):
    assert database in {'iam', 'iam_test', 'iam_restore', 'iam_upgrade'}
    username = ENV['IAM_PG_APP_USER'] if role == 'app' else ENV['IAM_PG_MIGRATE_USER'] if role == 'migrate' else 'postgres'
    password = ENV['IAM_PG_APP_PASSWORD'] if role == 'app' else ENV['IAM_PG_MIGRATE_PASSWORD']
    return psycopg.connect(host='127.0.0.1', port=PORTS['pg'], dbname=database, user=username,
                           password=password, autocommit=autocommit, connect_timeout=3,
                           application_name='iam-independent-probe', options='-c search_path=iam,iam_auth')

def cache():
    return redis.Redis(host='127.0.0.1', port=PORTS['redis'], password=ENV['IAM_REDIS_PASSWORD'], db=0,
                       socket_connect_timeout=3, socket_timeout=3)

def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()
