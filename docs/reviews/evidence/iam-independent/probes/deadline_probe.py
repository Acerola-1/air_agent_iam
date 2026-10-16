#!/usr/bin/env python3
import time
from concurrent.futures import ThreadPoolExecutor
from probe_client import Api,Evidence,db
log=Evidence('independent-request-deadline-r2');api=Api(log)
try:
 t,_=api.login('deadline-positive-session');api.introspect('deadline-positive-control',t,expected='200 active=true')
 with db('migrate',autocommit=False) as blocker:
  blocker.execute('LOCK TABLE iam.auth_sessions IN ACCESS EXCLUSIVE MODE')
  def call():
   client=Api(log)
   try:return client.introspect('locked-authority-real-introspection',t,expected='503 by500ms total deadline; no positive permit after blocked authority')
   finally:client.close()
  with ThreadPoolExecutor(1) as pool:
   future=pool.submit(call);verified=False
   with db('super') as observer:
    for _ in range(50):
     rows=observer.execute("SELECT pid,wait_event_type,wait_event FROM pg_stat_activity WHERE usename='iam_app' AND datname='iam' AND wait_event_type='Lock'").fetchall()
     if rows:verified=True;break
     time.sleep(.02)
   log.emit('actual-blocked-runtime-connection',actual={'verified_lock_wait':verified,'connections':rows},expected='real IAM Hikari connection waiting on isolated authority lock')
   time.sleep(1.2);blocker.rollback();future.result(timeout=10)
 api.introspect('deadline-after-lock-release-control',t,expected='200 active=true')
finally:api.close();log.close()
