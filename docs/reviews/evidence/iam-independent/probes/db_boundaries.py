#!/usr/bin/env python3
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from probe_client import Api, Evidence, PRIVATE, db

f=json.loads((PRIVATE/'fixtures.json').read_text())
log=Evidence('independent-db-boundaries')
api=Api(log)
def ctx(c,key=None,platform=False):
    c.execute('SELECT iam_auth.set_request_context(%s,%s,%s)',(f['users']['dual']['id'],f['tenants'][key]['id'] if key else None,platform))
def attempt(c,case,sql,params=(),expected='SQL rejection'):
    try:
        with c.transaction():
            result=c.execute(sql,params)
            rows=result.fetchall() if result.description else []
            # Deliberately record only counts/types; never record password/token columns.
            log.emit(case,expected=expected,actual='accepted',row_count=len(rows))
            raise Rollback()
    except Rollback: pass
    except Exception as e: log.emit(case,expected=expected,actual='rejected',sqlstate=getattr(e,'sqlstate',None),exception_type=type(e).__name__)
class Rollback(Exception): pass

try:
    with db() as c:
        row=c.execute('SELECT current_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
        log.emit('real-request-role',actual=row,expected='iam_app,false,false')
        for key in ['a','b',None]:
            with c.transaction():
                ctx(c,key)
                rows=c.execute('SELECT DISTINCT tenant_id FROM iam.tenant_memberships').fetchall()
                log.emit('rls-visible-'+str(key),expected='only '+str(key)+'; none when no tenant',actual=rows)
        for mode in ['commit','exception','cancel']:
            try:
                with c.transaction():
                    ctx(c,'a')
                    if mode=='exception': c.execute('SELECT 1/0')
                    if mode=='cancel':
                        c.execute("SET LOCAL statement_timeout='20ms'")
                        c.execute('SELECT pg_sleep(1)')
            except Exception as e: log.emit('context-'+mode+'-error',actual=type(e).__name__,sqlstate=e.sqlstate)
            count=c.execute('SELECT count(*) FROM iam.tenant_memberships').fetchone()[0]
            log.emit('same-connection-after-'+mode,expected=0,actual=count)
        with c.transaction():
            ctx(c,'a')
            attempt(c,'password-column-denial','SELECT password_hash FROM iam.users',expected='42501; no password column grant')
            attempt(c,'cross-tenant-composite-fk',
                'INSERT INTO iam.membership_roles(tenant_id,membership_id,role_id) VALUES (%s,%s,%s)',
                (f['tenants']['a']['id'],f['memberships']['reader_b']['id'],f['roles']['memberwriter']['id']),expected='23503 or RLS rejection')
    # Verify actual privilege acquisition after re-login: revision invalidation alone is not a defense.
    u=f['users']['rolewriter']
    t,i=api.login('escalated-rolewriter-relogin',u['account'],u['password'])
    if i['current_tenant'] is None:
        _,i=api.request('escalated-rolewriter-select-a','POST','/v1/auth/switch-tenant',
            {'tenant_id':f['tenants']['a']['id'],'expected_ctx_version':i['context_version']},token=t)
    api.request('escalated-rolewriter-real-write','POST','/v1/admin/departments',
        {'code':'proof-rolewriter','name':'越权权限实际写验证'},token=t,expected='403 under original two-permission role')
    # Two tenant admins concurrently disable each other. Both requests start authenticated.
    actors={}
    for key in ['last1','last2']:
        u=f['users'][key]; t,i=api.login('last-admin-login-'+key,u['account'],u['password'])
        if i['current_tenant'] is None:
            api.request('last-admin-select-'+key,'POST','/v1/auth/switch-tenant',
                {'tenant_id':f['tenants']['last']['id'],'expected_ctx_version':i['context_version']},token=t)
        actors[key]=t
    barrier=threading.Barrier(2)
    def race(pair):
        actor,target=pair; client=Api(log)
        try:
            barrier.wait()
            r,_=client.request('last-admin-race-'+actor,'PATCH','/v1/admin/members/'+f['memberships'][target+'_last']['id'],
                {'status':'disabled'},token=actors[actor],expected='at least one rejection, final effective admin >=1')
            return r.status_code
        finally: client.close()
    with ThreadPoolExecutor(2) as pool: statuses=list(pool.map(race,[('last1','last2'),('last2','last1')]))
    with db('migrate') as c:
        with c.transaction():
            ctx(c,platform=True)
            count=c.execute("SELECT count(*) FROM iam.tenant_memberships m JOIN iam.membership_roles mr ON mr.membership_id=m.id JOIN iam.roles r ON r.id=mr.role_id JOIN iam.users u ON u.id=m.user_id WHERE m.tenant_id=%s AND m.status='active' AND u.status='active' AND r.code='tenant_admin' AND r.status='active'",(f['tenants']['last']['id'],)).fetchone()[0]
            log.emit('last-admin-final',actual={'statuses':statuses,'effective_admins':count},expected='effective_admins >=1')
finally: api.close();log.close()
