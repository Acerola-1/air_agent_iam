#!/usr/bin/env python3
import json,os,socket,subprocess,time
from concurrent.futures import ThreadPoolExecutor
import httpx
from environment import COPY,PRIVATE,EVIDENCE,JAVA,env_values
from probe_client import Api,Evidence,db
log=Evidence('independent-hikari-runtime-reuse-r2');env=env_values();port=29106;proc=None
resources_path=EVIDENCE/'outputs/resources.json';resources=json.loads(resources_path.read_text());f=json.loads((PRIVATE/'fixtures.json').read_text())
with socket.socket() as s:s.bind(('127.0.0.1',port))
file=(PRIVATE/'server-independent-hikari-r2.log').open('x');os.chmod(file.name,0o600)
with db('super') as observer:
 before_pids={r[0] for r in observer.execute("SELECT pid FROM pg_stat_activity WHERE usename='iam_app' AND datname='iam'").fetchall()}
proc=subprocess.Popen([JAVA+'/bin/java','-Xms128m','-Xmx768m','-jar',str(COPY/'server/target/iam-server.jar')],cwd=COPY,
 env={**os.environ,**env,'IAM_HTTP_PORT':str(port),'IAM_DB_POOL_MAX':'1',
 'SPRING_DATASOURCE_URL':'jdbc:postgresql://127.0.0.1:29132/iam?ApplicationName=iam-independent-pool&options=-c%20search_path%3Diam%2Ciam_auth'},stdout=file,stderr=file,start_new_session=True)
item={'kind':'java','label':'independent-hikari','pid':proc.pid,'port':port,'jar':str(COPY/'server/target/iam-server.jar'),'stopped':False};resources['processes'].append(item);resources_path.write_text(json.dumps(resources,indent=2))
api=Api(log);api.client.base_url='http://127.0.0.1:'+str(port)
try:
 for _ in range(100):
  if proc.poll() is not None:break
  try:
   if api.client.get('/healthz').status_code==200:break
  except Exception:pass
  time.sleep(.5)
 assert proc.poll() is None
 with db('super') as c:
  rows=[r for r in c.execute("SELECT pid,usename FROM pg_stat_activity WHERE usename='iam_app' AND datname='iam'").fetchall() if r[0] not in before_pids]
 log.emit('actual-hikari-one-connection',actual=rows,expected='exactly one iam_app backend');assert len(rows)==1
 pid=rows[0][0];tokens={}
 for k in ['a','b']:
  t,i=api.login('pool-login-'+k,f['users']['dual']['account'],f['users']['dual']['password']);tokens[k]=t
  api.request('pool-select-'+k,'POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants'][k]['id'],'expected_ctx_version':i['context_version']},token=t)
  api.request('pool-normal-members-'+k,'GET','/v1/admin/members',token=t,expected='only tenant '+k)
 # Anonymous request reaches no protected service but cannot inherit prior tenant.
 api.request('pool-anonymous-between-a-b','GET','/v1/admin/members',expected='401')
 api.request('pool-sql-exception-bad-cursor','GET','/v1/admin/members?cursor=YmFk',token=tokens['a'],expected='4xx; no tenant GUC left after DB cast error')
 api.request('pool-b-after-a-error','GET','/v1/admin/members',token=tokens['b'],expected='only B')
 # Block a protected member read, identify the single owned backend, cancel it from PG.
 with db('migrate',autocommit=False) as blocker:
  blocker.execute('LOCK TABLE iam.tenant_memberships IN ACCESS EXCLUSIVE MODE')
  def call():
   client=Api(log);client.client.base_url='http://127.0.0.1:'+str(port)
   try:client.request('pool-cancelled-a','GET','/v1/admin/members',token=tokens['a'],expected='error, never positive stale data')
   finally:client.close()
  with ThreadPoolExecutor(1) as pool:
   future=pool.submit(call);waiting=False
   with db('super') as observer:
    for _ in range(100):
     row=observer.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s AND datname='iam' AND usename='iam_app'",(pid,)).fetchone()
     if row and row[0]=='Lock':waiting=True;break
     time.sleep(.02)
    log.emit('owned-hikari-backend-wait-before-cancel',actual=waiting);assert waiting
    cancelled=observer.execute('SELECT pg_cancel_backend(%s)',(pid,)).fetchone()[0]
    log.emit('cancel-only-owned-hikari-backend',actual={'pid':pid,'cancelled':cancelled})
   blocker.rollback();future.result(timeout=10)
 api.request('pool-a-after-cancel','GET','/v1/admin/members',token=tokens['a'],expected='only A')
 api.request('pool-b-after-cancel','GET','/v1/admin/members',token=tokens['b'],expected='only B')
 api.request('pool-anonymous-after-cancel','GET','/v1/admin/members',expected='401')
 with db('super') as c:after=[r for r in c.execute("SELECT pid FROM pg_stat_activity WHERE usename='iam_app' AND datname='iam'").fetchall() if r[0] not in before_pids]
 log.emit('hikari-backend-reused-after-cancel',expected=[[pid]],actual=after)
finally:
 api.close()
 if proc.poll() is None:proc.terminate();proc.wait(timeout=40)
 item['stopped']=True;item['exit_code']=proc.returncode;resources_path.write_text(json.dumps(resources,indent=2));file.close();log.emit('hikari-owned-jvm-cleanup',actual={'stopped':proc.poll() is not None});log.close()
