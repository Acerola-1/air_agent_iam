#!/usr/bin/env python3
"""Only stop containers with verified run label and manifest membership; always restore."""
import json
import secrets
import subprocess
import time
from environment import CONTAINER,NAMES,RUN_ID,EVIDENCE
from probe_client import Api,Evidence,db,cache,digest
log=Evidence('independent-dependency-faults-r2');api=Api(log);stopped=set()
resources=json.loads((EVIDENCE/'outputs/resources.json').read_text())
def owned(key):
    name=NAMES[key];assert name in resources['created_containers']
    r=subprocess.run([CONTAINER,'inspect',name],capture_output=True,text=True,check=True)
    d=json.loads(r.stdout)[0];assert d['configuration']['labels'].get('audit.run')==RUN_ID
    return name
def transition(key,action):
    name=owned(key);start=time.monotonic()
    r=subprocess.run([CONTAINER,action,name],capture_output=True,text=True,timeout=50)
    log.emit('owned-container-'+action+'-'+key,status=r.returncode,elapsed_seconds=time.monotonic()-start,resource=name)
    assert r.returncode==0
    if action=='stop':stopped.add(key)
    else:stopped.discard(key)
def ready():
    for _ in range(60):
        try:
            with db() as c:c.execute('SELECT 1')
            cache().ping();return
        except Exception:time.sleep(.5)
    raise RuntimeError('owned environment recovery timeout')
try:
    root,_=api.login('fault-root-login');password=secrets.token_hex(16)
    _,u=api.request('fault-synthetic-user','POST','/v1/admin/users',{'account':'fault.'+secrets.token_hex(4),'display_name':'独立故障注入','password':password},token=root)
    t,i=api.login('fault-session',u['account'],password)
    # Audit failure: save original effective ACL grants then revoke in isolated DB only.
    signature='iam_auth.write_audit(uuid,uuid,text,text,text,text,jsonb,text)'
    with db('migrate') as c:
        grants=c.execute("SELECT grantee::regrole::text,privilege_type,is_grantable FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid=%s::regprocedure",(signature,)).fetchall()
        c.execute('REVOKE EXECUTE ON FUNCTION '+signature+' FROM PUBLIC,iam_app')
    try:
        api.request('audit-failure-account-disable','PATCH','/v1/admin/users/'+u['id'],{'status':'disabled'},token=root,expected='error; status and revision roll back')
        api.introspect('audit-failure-user-still-active',t,expected='active=true')
        with db('migrate') as c:
            c.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)') # autocommit context intentionally not retained
            row=c.execute('SELECT status,auth_revision FROM iam.users WHERE id=%s',(u['id'],)).fetchone()
            log.emit('audit-failure-rollback-snapshot',expected=['active',0],actual=row)
    finally:
        with db('migrate') as c:
            for grantee,privilege,grantable in grants:
                if privilege!='EXECUTE':continue
                # Catalog derived trusted role names; only PUBLIC/iam roles are expected.
                role='PUBLIC' if grantee=='-' else '"'+grantee.replace('"','""')+'"'
                c.execute('GRANT EXECUTE ON FUNCTION '+signature+' TO '+role+(' WITH GRANT OPTION' if grantable else ''))
    redis=cache();key='Authorization:login:token:'+digest(t);original=redis.get(key);ttl=redis.pttl(key);assert original
    transition('redis','stop')
    api.introspect('redis-outage-introspection',t,expected='503; no anonymous fallback')
    api.request('redis-outage-me','GET','/v1/auth/me',token=t,expected='503')
    # Commit authoritative revocation and outbox during cache outage, using production functions.
    with db('migrate') as c:
        with c.transaction():
            c.execute('SELECT iam_auth.set_request_context(%s,NULL,true)',(u['id'],))
            td=c.execute("SELECT iam_auth.revoke_session(%s,'independent-cache-outage')",(i['session']['id'],)).fetchone()[0]
            outbox=c.execute("SELECT iam_auth.enqueue_outbox('redis_delete_keys',%s::jsonb)",(json.dumps({'keys':['Authorization:login:token:'+td]}),)).fetchone()[0]
            c.execute("SELECT iam_auth.write_audit(NULL,%s,'human','probe.revocation','auth_session',%s,'{}'::jsonb,'independent-fault')",(u['id'],i['session']['id']))
    time.sleep(3)
    with db('migrate') as c:
        row=c.execute('SELECT status,attempts FROM iam.outbox WHERE id=%s',(outbox,)).fetchone();log.emit('outbox-during-cache-outage',actual=row,expected='pending with failed attempt(s)')
    transition('redis','start');ready()
    # Re-inject exact stale key, prove PG rejects before asynchronous cleanup matters.
    cache().set(key,original,px=ttl)
    api.introspect('redis-restored-stale-key-first-introspection',t,expected='active=false')
    api.request('redis-restored-stale-key-me','GET','/v1/auth/me',token=t,expected='401')
    for _ in range(30):
        with db('migrate') as c: row=c.execute('SELECT status,attempts FROM iam.outbox WHERE id=%s',(outbox,)).fetchone()
        if row[0]=='done':break
        time.sleep(.5)
    log.emit('outbox-after-recovery',actual=row,expected='done, attempts>=2')
    cache().delete(key)
    transition('pg','stop')
    api.introspect('pg-outage-introspection',t,expected='503')
    api.request('pg-outage-me','GET','/v1/auth/me',token=t,expected='503')
    transition('pg','start');ready()
    api.introspect('both-dependencies-recovered-revocation-remains',t,expected='active=false')
finally:
    for key in list(stopped):
        try:transition(key,'start')
        except Exception as e:log.emit('recovery-failed-'+key,actual=type(e).__name__)
    api.close();log.close()
