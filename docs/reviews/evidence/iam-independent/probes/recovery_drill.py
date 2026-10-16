#!/usr/bin/env python3
"""Actual dump/restore only inside the labelled independent cluster. No dump published."""
import json
import os
import signal
import socket
import subprocess
import time
from environment import COPY,EVIDENCE,PRIVATE,JAVA,CONTAINER,NAMES,RUN_ID,env_values
from probe_client import Api,Evidence,db,cache
log=Evidence('independent-recovery-drill');api=Api(log);env=env_values();proc=None
dump=PRIVATE/'independent-dr-private.dump';assert not dump.exists()
rp=EVIDENCE/'outputs/resources.json';resources=json.loads(rp.read_text())
owned=json.loads(subprocess.check_output([CONTAINER,'inspect',NAMES['pg']],text=True))[0]
assert owned['configuration']['labels']['audit.run']==RUN_ID
port=29104
def request(case,method,path,body=None,token=None,internal=False,restore=False):
    old=api.client.base_url
    if restore:api.client.base_url='http://127.0.0.1:'+str(port)
    try:return api.request(case,method,path,body,token,internal)
    finally:api.client.base_url=old
def intro(case,token,restore=False):return request(case,'POST','/v1/internal/identity/introspect',{'subject_token':token,'audience':'langgraph-runtime'},internal=True,restore=restore)
try:
    import secrets
    root,_=api.login('dr-root');password=secrets.token_hex(16)
    _,u=request('dr-create-user','POST','/v1/admin/users',{'account':'dr.'+secrets.token_hex(4),'display_name':'独立恢复演练','password':password},root)
    request('dr-grant-auditor','POST','/v1/admin/users/'+u['id']+'/platform-roles',{'role_codes':['platform_auditor']},root)
    t,i=api.login('dr-before-backup',u['account'],password);intro('dr-pre-backup-active',t)
    # Preserve exact synthetic Redis entry for stale-backup counterexample, not a new identity.
    from probe_client import digest
    key='Authorization:login:token:'+digest(t);value=cache().get(key);ttl=cache().pttl(key);assert value
    with dump.open('xb') as stream:
        os.chmod(dump,0o600)
        r=subprocess.run([CONTAINER,'exec',NAMES['pg'],'pg_dump','-U','postgres','-d','iam','-Fc'],stdout=stream,stderr=subprocess.PIPE)
    assert r.returncode==0
    log.emit('actual-database-backup',actual={'bytes':dump.stat().st_size,'storage':'private mode0600; deleted in finally'},expected='real pg_dump, no secret contents published')
    newpassword=secrets.token_hex(16)
    request('dr-authoritative-reset-after-backup','POST','/v1/admin/users/'+u['id']+'/password',{'new_password':newpassword},root)
    request('dr-authoritative-remove-role-after-backup','POST','/v1/admin/users/'+u['id']+'/platform-roles',{'role_codes':[]},root)
    intro('dr-original-revocation-active-false',t)
    with db('super') as c:
        exists=c.execute("SELECT count(*) FROM pg_database WHERE datname='iam_restore'").fetchone()[0];assert exists==0
        c.execute('CREATE DATABASE iam_restore OWNER iam_migrate')
    resources.setdefault('created_databases',[]).append({'name':'iam_restore','cluster':NAMES['pg'],'stopped':False});rp.write_text(json.dumps(resources,indent=2))
    with dump.open('rb') as stream:
        r=subprocess.run([CONTAINER,'exec','-i',NAMES['pg'],'pg_restore','--no-owner','--role=iam_migrate','-U','postgres','-d','iam_restore'],stdin=stream,capture_output=True)
    log.emit('actual-database-restore',status=r.returncode,expected='0; no owner fallback in runtime');assert r.returncode==0
    from probe_client import ENV
    import redis
    restored_cache=redis.Redis(host='127.0.0.1',port=29179,password=ENV['IAM_REDIS_PASSWORD'],db=5)
    assert restored_cache.dbsize()==0,'Never reuse nonempty Redis DB for restore drill'
    restored_cache.set(key,value,px=ttl)
    with socket.socket() as s:s.bind(('127.0.0.1',port))
    file=(PRIVATE/'server-independent-restore.log').open('x');os.chmod(file.name,0o600)
    proc=subprocess.Popen([JAVA+'/bin/java','-Xms128m','-Xmx768m','-jar',str(COPY/'server/target/iam-server.jar')],cwd=COPY,
        env={**os.environ,**env,'IAM_HTTP_PORT':str(port),'IAM_PG_DB':'iam_restore','IAM_REDIS_DB':'5'},stdout=file,stderr=file,start_new_session=True)
    item={'kind':'java','label':'independent-restore','pid':proc.pid,'jar':str(COPY/'server/target/iam-server.jar'),'port':port,'stopped':False};resources['processes'].append(item);rp.write_text(json.dumps(resources,indent=2))
    import httpx
    for _ in range(100):
        if proc.poll() is not None:break
        try:
            r=httpx.get('http://127.0.0.1:'+str(port)+'/healthz',timeout=1,trust_env=False)
            if r.status_code==200:break
        except Exception:pass
        time.sleep(.5)
    assert proc.poll() is None
    # Restored stale authority would resurrect old permits if exposed immediately.
    intro('dr-unsafe-restore-before-revocation-replay',t,True)
    _,rb=request('dr-restored-platform-login','POST','/v1/auth/login',{'account':env['IAM_BOOTSTRAP_ACCOUNT'],'password':env['IAM_BOOTSTRAP_PASSWORD'],'realm':'workforce','audience':'iam-admin'},restore=True)
    rt=rb['access_token']
    request('dr-reapply-password-reset','POST','/v1/admin/users/'+u['id']+'/password',{'new_password':newpassword},rt,restore=True)
    request('dr-reapply-role-removal','POST','/v1/admin/users/'+u['id']+'/platform-roles',{'role_codes':[]},rt,restore=True)
    intro('dr-replayed-old-token-rejected',t,True)
    _,nb=request('dr-new-login-after-replay','POST','/v1/auth/login',{'account':u['account'],'password':newpassword,'realm':'workforce','audience':'iam-admin'},restore=True)
    request('dr-restored-role-removal-enforced','GET','/v1/admin/audit-logs',token=nb['access_token'],restore=True)
    with db('migrate',database='iam_restore') as c:
        rows=c.execute('SELECT version,success FROM iam.flyway_schema_history ORDER BY installed_rank').fetchall()
        log.emit('restored-idempotent-flyway-revalidation',actual=rows,expected='11 original successful migrations, no repeat reset')
    log.emit('recovery-scope',actual='I1 own-db actual restoration and explicit revocation replay; recovery service never public. No I4 source takeover or automatic replay claim.')
finally:
    if proc is not None:
        if proc.poll() is None:proc.terminate();proc.wait(timeout=40)
        item['stopped']=True;item['exit_code']=proc.returncode;file.close()
    dump.unlink(missing_ok=True)
    # Leave owned restore DB for fingerprint/evidence verification until final cleanup.
    rp.write_text(json.dumps(resources,indent=2));log.emit('restore-process-and-dump-cleanup',actual={'process_stopped':proc is None or proc.poll() is not None,'dump_absent':not dump.exists()})
    api.close();log.close()
