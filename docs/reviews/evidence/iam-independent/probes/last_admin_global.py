#!/usr/bin/env python3
import json,secrets,threading
from concurrent.futures import ThreadPoolExecutor
from probe_client import Api,Evidence,PRIVATE,db
log=Evidence('independent-global-admin-guards');api=Api(log);f=json.loads((PRIVATE/'fixtures.json').read_text())
def count(c,tenant):
 return c.execute("SELECT count(*) FROM iam.tenant_memberships m JOIN iam.users u ON u.id=m.user_id JOIN iam.membership_roles mr ON mr.membership_id=m.id JOIN iam.roles r ON r.id=mr.role_id WHERE m.tenant_id=%s AND m.status='active' AND u.status='active' AND r.status='active' AND r.code='tenant_admin'",(tenant,)).fetchone()[0]
rootid=None;newid=None
try:
 root,ri=api.login('guards-root');rootid=ri['user']['id']
 with db('migrate') as c:
  with c.transaction():
   c.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)');before=count(c,f['tenants']['last']['id'])
   active=c.execute("SELECT m.user_id::text FROM iam.tenant_memberships m JOIN iam.users u ON u.id=m.user_id WHERE m.tenant_id=%s AND m.status='active' AND u.status='active'",(f['tenants']['last']['id'],)).fetchone()[0]
 api.request('global-disable-last-tenant-admin','PATCH','/v1/admin/users/'+active,{'status':'disabled'},token=root,expected='409; preserve effective tenant administrator')
 with db('migrate') as c:
  with c.transaction():
   c.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)');after=count(c,f['tenants']['last']['id'])
 log.emit('tenant-last-admin-global-user-path',expected='after>=1',actual={'before':before,'after':after})
 api.request('restore-synthetic-tenant-admin','PATCH','/v1/admin/users/'+active,{'status':'active'},token=root)
 _,new=api.request('create-platform-concurrency-admin','POST','/v1/admin/users',{'account':'adminrace.'+secrets.token_hex(4),'display_name':'独立平台并发管理员','password':secrets.token_hex(16)},token=root)
 newid=new['id'];api.request('grant-second-platform-admin','POST','/v1/admin/users/'+newid+'/platform-roles',{'role_codes':['platform_super_admin']},token=root)
 barrier=threading.Barrier(2)
 def race(uid):
  try:
   with db() as c:
    with c.transaction():
     c.execute("SET LOCAL lock_timeout='3s'");c.execute('SELECT iam_auth.set_request_context(%s,NULL,true)',(uid,))
     c.execute("UPDATE iam.users SET status='disabled' WHERE id=%s",(uid,))
     barrier.wait(timeout=5) # Both AFTER triggers have passed before either transaction commits.
   return 'committed'
  except Exception as e:
   try:barrier.abort()
   except Exception:pass
   return {'error':type(e).__name__,'sqlstate':getattr(e,'sqlstate',None)}
 with ThreadPoolExecutor(2) as pool:outcomes=list(pool.map(race,[rootid,newid]))
 with db('migrate') as c:
  admins=c.execute("SELECT count(*) FROM iam.user_roles ur JOIN iam.roles r ON r.id=ur.role_id JOIN iam.users u ON u.id=ur.user_id WHERE r.code='platform_super_admin' AND u.status='active'").fetchone()[0]
 log.emit('platform-last-admin-true-concurrency',actual={'transactions':outcomes,'final_effective_admins':admins},expected='at least one rejected; effective_admins>=1',boundary='two real nonowner DB transactions with authenticated platform context, not claimed as HTTP scheduling test')
finally:
 if rootid:
  with db('migrate') as c:
   c.execute("UPDATE iam.users SET status='active' WHERE id=%s",(rootid,))
   if newid:c.execute("UPDATE iam.users SET status='active' WHERE id=%s",(newid,))
  log.emit('synthetic-admin-guard-fixture-restored',actual=True)
 api.close();log.close()
