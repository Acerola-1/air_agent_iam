#!/usr/bin/env python3
import argparse
import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from environment import COPY, EVIDENCE, JAVA, PORTS, PRIVATE, env_values, redact

parser = argparse.ArgumentParser()
parser.add_argument('action', choices=['start', 'stop'])
parser.add_argument('--label', default='primary')
args = parser.parse_args()
resource_path = EVIDENCE / 'outputs/resources.json'
resources = json.loads(resource_path.read_text())

if args.action == 'start':
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', PORTS['http']))
    jar = COPY / 'server/target/iam-server.jar'
    assert jar.is_file()
    log_path = PRIVATE / ('server-' + args.label + '.log')
    with log_path.open('x') as log:
        log_path.chmod(0o600)
        started = time.monotonic()
        process = subprocess.Popen([JAVA + '/bin/java', '-Xms128m', '-Xmx768m', '-jar', str(jar)],
                                   cwd=COPY, env={**os.environ, **env_values()}, stdout=log, stderr=log, start_new_session=True)
    resources['processes'].append({'kind': 'java', 'pid': process.pid, 'label': args.label, 'jar': str(jar),
                                   'created_utc': datetime.now(timezone.utc).isoformat(), 'log': str(log_path), 'stopped': False})
    resource_path.write_text(json.dumps(resources, ensure_ascii=False, indent=2))
    ready = False
    for attempt in range(120):
        if process.poll() is not None:
            break
        try:
            with urllib.request.urlopen('http://127.0.0.1:' + str(PORTS['http']) + '/healthz', timeout=1) as response:
                body = response.read().decode()
                ready = response.status == 200
                if ready:
                    break
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.5)
    result = {'ready': ready, 'pid': process.pid, 'elapsed_seconds': time.monotonic() - started,
              'health': body if ready else None, 'startup_log': redact(log_path.read_text())}
    with (EVIDENCE / 'outputs' / ('runtime-start-' + args.label + '.json')).open('x') as file:
        json.dump(result, file, ensure_ascii=False, indent=2)
    print(json.dumps({'ready': ready, 'pid': process.pid, 'elapsed_seconds': result['elapsed_seconds']}))
    if not ready:
        raise SystemExit(1)
else:
    for item in resources['processes']:
        if item['label'] != args.label or item['stopped']:
            continue
        command = subprocess.run(['ps', '-p', str(item['pid']), '-o', 'command='], text=True, capture_output=True).stdout
        if command:
            assert item['jar'] in command and JAVA + '/bin/java' in command
            os.kill(item['pid'], signal.SIGTERM)
        item['stopped'] = True
        item['stopped_utc'] = datetime.now(timezone.utc).isoformat()
    resource_path.write_text(json.dumps(resources, ensure_ascii=False, indent=2))
    print('SIGTERM sent only to matching owned Java process; shutdown still requires verification')
