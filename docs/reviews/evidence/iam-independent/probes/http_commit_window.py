#!/usr/bin/env python3
import json,subprocess,time
from concurrent.futures import ThreadPoolExecutor
from environment import EVIDENCE,CONTAINER,NAMES,RUN_ID
from probe_client import Api,Evidence,db,cache,digest
log=Evidence('independent-http-commit-window-r2');api=Api(log);stopped=False
def redis_transition(action):
 resources=json.loads((EVIDENCE/'outputs/resources.json').read_text());assert NAMES['redis'] in resources['created_containers']
 d=json.loads(subprocess.check_output([CONTAINER,'inspect',NAMES['redis']],text=True))[0];assert d['configuration']['labels']['audit.run']==RUN_ID
 subprocess.run([CONTAINER,action,NAMES['redis']],capture_output=True,check=True,timeout=50)
try:
 t,i=api.login('commit-window-session');key='Authorization:login:token:'+digest(t);v=cache().get(key);ttl=cache().pttl(key);assert v
 with db('migrate',autocommit=False) as blocker:
  blocker.execute('SELECT id FROM iam.auth_sessions WHERE id=%s FOR UPDATE',(i['session']['id'],))
  def logout():
   a=Api(log)
   try:return a.request('actual-http-logout-during-cache-outage','POST','/v1/auth/logout',token=t,expected='204 after PG revoke/audit/outbox commit despite cache deletion outage')
   finally:a.close()
  with ThreadPoolExecutor(1) as pool:
   future=pool.submit(logout)
   with db('super') as observer:
    waiting=False
    for _ in range(150):
     waiting=observer.execute("SELECT count(*) FROM pg_stat_activity WHERE usename='iam_app' AND datname='iam' AND wait_event_type='Lock' AND query LIKE '%revoke_session%' AND query NOT LIKE '%pg_stat_activity%' ").fetchone()[0]>0
     if waiting:break
     time.sleep(.02)
   log.emit('logout-passed-auth-and-waiting-in-authoritative-revoke',actual=waiting);assert waiting
   redis_transition('stop');stopped=True;blocker.rollback();future.result(timeout=15)
 with db('migrate',autocommit=False) as c:
  c.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)')
  row=c.execute('SELECT status FROM iam.auth_sessions WHERE id=%s',(i['session']['id'],)).fetchone()
  audits=c.execute("SELECT count(*) FROM iam.audit_logs WHERE target_id=%s AND action='auth.logout'",(i['session']['id'],)).fetchone()[0]
  outbox=c.execute("SELECT id,status,attempts FROM iam.outbox WHERE payload->'keys' @> %s::jsonb ORDER BY id DESC LIMIT 1",(json.dumps([key]),)).fetchone()
  log.emit('http-commit-authoritative-state',expected='revoked and audit present and outbox tracked',actual={'session':row,'audit_count':audits,'outbox':outbox})
 redis_transition('start');stopped=False
 for _ in range(60):
  try:
   health=api.client.get('/healthz')
   if health.status_code==200 and health.json().get('status')=='ok':break
  except Exception:pass
  time.sleep(.3)
 for _ in range(40):
  with db('migrate') as c:state=c.execute('SELECT status,attempts FROM iam.outbox WHERE id=%s',(outbox[0],)).fetchone()
  if state[0]=='done':break
  time.sleep(.3)
 log.emit('http-commit-outbox-final',actual=state,expected='done after dependency recovery')
 cache().set(key,v,px=ttl)
 api.introspect('http-committed-logout-stale-redis-replay',t,expected='active=false, never active after successful authority commit')
 cache().delete(key)
finally:
 if stopped:redis_transition('start')
 api.close();log.close()
