#!/usr/bin/env python3
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from probe_client import Api, Evidence, PRIVATE, db
log=Evidence('independent-session-timer-boundaries');api=Api(log)
f=json.loads((PRIVATE/'fixtures.json').read_text());u=f['users']['dual']
def session(case): return api.login(case,u['account'],u['password'])
def inject(sid,sql):
    with db('migrate') as c:
        with c.transaction():
            c.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)')
            c.execute('UPDATE iam.auth_sessions SET '+sql+' WHERE id=%s',(sid,))
try:
    for label,sql in [('consistent-idle-expired',"idle_expires_at=now()-interval '1 second',expires_at=now()-interval '1 second'"),
                      ('absolute-expired',"absolute_expires_at=now()-interval '1 second'")]:
        t,i=session(label+'-login');inject(i['session']['id'],sql)
        api.introspect(label+'-introspection',t,expected='active=false')
        api.request(label+'-renew','POST','/v1/auth/renew',{'expected_ctx_version':i['context_version']},token=t,expected='401')
    t,i=session('future-idle-no-rollback-login')
    inject(i['session']['id'],"idle_expires_at=now()+interval '10 days',expires_at=now()+interval '10 days'")
    _,before=api.request('future-idle-before','GET','/v1/auth/me',token=t)
    api.request('future-idle-renew','POST','/v1/auth/renew',{'expected_ctx_version':i['context_version']},token=t,expected='200; deadline never earlier than existing 10 days')
    _,after=api.request('future-idle-after','GET','/v1/auth/me',token=t)
    log.emit('renew-monotonic-comparison',expected='after >= before',actual={
        'before':before['session']['idle_expires_at'],'after':after['session']['idle_expires_at']},
        setup='Synthetic future idle deadline; renew idle policy is 7 days. Not normal unmodified session state.')
    t,i=session('renew-concurrency-login');barrier=threading.Barrier(2)
    def race(n):
        client=Api(log)
        try:
            barrier.wait()
            r,b=client.request('concurrent-renew-'+str(n),'POST','/v1/auth/renew',{'expected_ctx_version':i['context_version']},token=t,expected='200; no revision reset, no expiry rollback')
            return r.status_code,b
        finally:client.close()
    with ThreadPoolExecutor(2) as pool: outcomes=list(pool.map(race,[1,2]))
    log.emit('concurrent-renew-result',actual=outcomes,expected='both valid, bounded by absolute expiry')
finally:api.close();log.close()
