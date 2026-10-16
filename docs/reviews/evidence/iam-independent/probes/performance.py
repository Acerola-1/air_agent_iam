#!/usr/bin/env python3
"""Independent C25; dedicated owned JVM; per-thread warm keep-alive, raw samples."""
import base64
import http.client
import json
import os
import signal
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from environment import COPY,EVIDENCE,JAVA,PRIVATE,env_values
from probe_client import Api,Evidence
port=29103
env=env_values();log=Evidence('independent-c25-r2')
resource_path=EVIDENCE/'outputs/resources.json'
resources=json.loads(resource_path.read_text())
with socket.socket() as sock: sock.bind(('127.0.0.1',port))
stream=(PRIVATE/'server-perf-independent-r2.log').open('x');os.chmod(stream.name,0o600)
proc=subprocess.Popen([JAVA+'/bin/java','-Xms128m','-Xmx768m','-jar',str(COPY/'server/target/iam-server.jar')],cwd=COPY,
    env={**os.environ,**env,'IAM_HTTP_PORT':str(port),'IAM_RATE_LIMIT_ENABLED':'false'},stdout=stream,stderr=stream,start_new_session=True)
item={'kind':'java','pid':proc.pid,'label':'independent-c25','jar':str(COPY/'server/target/iam-server.jar'),'port':port,'stopped':False}
resources['processes'].append(item);resource_path.write_text(json.dumps(resources,indent=2))
auth='Basic '+base64.b64encode((env['IAM_INTERNAL_RUNTIME_CLIENT_ID']+':'+env['IAM_INTERNAL_RUNTIME_CLIENT_SECRET']).encode()).decode()
connections=[];lock=threading.Lock();local=threading.local()
def request(body):
    start=time.perf_counter_ns()
    local.conn.request('POST','/v1/internal/identity/introspect',body=body,headers={'Authorization':auth,'Content-Type':'application/json'})
    r=local.conn.getresponse();raw=r.read();ms=(time.perf_counter_ns()-start)/1e6
    b=json.loads(raw)
    return {'elapsed_ms':round(ms,6),'status':r.status,'active':b.get('active'),'audience':b.get('audience'),'reason':b.get('reason'),
        'session_matches':b.get('session',{}).get('id')==identity['session']['id'],
        'permissions_match':sorted(b.get('permissions',[]))==sorted(identity['permissions'])}
body=None
def init():
    local.conn=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
    with lock:connections.append(local.conn)
    for _ in range(3):request(body)
def pct(values,q):
    v=sorted(values);p=(len(v)-1)*q;l=int(p);h=min(l+1,len(v)-1)
    return round(v[l]+(v[h]-v[l])*(p-l),3)
try:
    ready=False
    for _ in range(100):
        if proc.poll() is not None:break
        try:
            c=http.client.HTTPConnection('127.0.0.1',port,timeout=1);c.request('GET','/healthz');r=c.getresponse();r.read();ready=r.status==200;c.close()
            if ready:break
        except OSError:pass
        time.sleep(.5)
    assert ready,'dedicated JVM not ready'
    api=Api(log);token,identity=api.login('c25-real-session');api.close()
    body=json.dumps({'subject_token':token,'audience':'langgraph-runtime'}).encode()
    log.emit('first-attempt-invalidated',actual='independent-c25.jsonl measured 403 due unregistered iam-admin client audience; excluded from authorization performance results')
    log.emit('method',actual={'port':port,'rate_limit':'disabled only on dedicated JVM','authorization_cache':'unchanged; no product edits',
        'pool_max':12,'samples_per_round':100,'rounds':3,'concurrency':[1,10,30],'external_wait':'none, loopback',
        'latency':'request send through complete response read; excludes executor queue and connection warmup','token_usage':'未采集'})
    total=0
    for conc in [1,10,30]:
        with ThreadPoolExecutor(max_workers=conc,initializer=init) as pool:
            # Ensure each thread is initialized and warmed before measurement.
            barrier=threading.Barrier(conc)
            list(pool.map(lambda _:barrier.wait(),range(conc)))
            for round_id in range(1,4):
                start=time.perf_counter()
                samples=list(pool.map(lambda _:request(body),range(100)))
                wall=(time.perf_counter()-start)*1000;total+=len(samples)
                values=[s['elapsed_ms'] for s in samples]
                errors=sum(s['status']!=200 or s['active'] is not True or not s['session_matches'] or not s['permissions_match'] for s in samples)
                result={'p50_ms':pct(values,.5),'p95_ms':pct(values,.95),'p99_ms':pct(values,.99),
                    'errors':errors,'error_rate':errors/100,'round_wall_ms':wall,'samples':samples,
                    'audience_mismatch_count':sum(s['audience']!='langgraph-runtime' for s in samples)}
                log.emit('c25-c'+str(conc)+'-round'+str(round_id),measurement=result,
                    expected='P50<=10ms P95<=30ms, authorization errors=0; audience mismatch is separate contract failure')
                print(conc,round_id,{k:v for k,v in result.items() if k!='samples'},flush=True)
        for c in connections:c.close()
        connections.clear()
    log.emit('total-measured-introspections',actual=total,expected=900)
finally:
    if proc.poll() is None:
        os.kill(proc.pid,signal.SIGTERM)
        try:proc.wait(timeout=40)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
    item['stopped']=True;item['exit_code']=proc.returncode;item['stopped_utc']=datetime.now(timezone.utc).isoformat()
    resource_path.write_text(json.dumps(resources,indent=2));stream.close()
    log.emit('dedicated-jvm-cleanup',actual={'pid':proc.pid,'exit_code':proc.returncode,'stopped':proc.poll() is not None})
    log.close()
