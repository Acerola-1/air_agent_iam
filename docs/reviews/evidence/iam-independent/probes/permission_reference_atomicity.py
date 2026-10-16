#!/usr/bin/env python3
import json,secrets
from probe_client import Api,Evidence,PRIVATE,db
log=Evidence('independent-permission-reference-atomicity');api=Api(log);f=json.loads((PRIVATE/'fixtures.json').read_text())
signature='iam_auth.write_audit(uuid,uuid,text,text,text,text,jsonb,text)';acl=None
try:
 du=f['users']['dual'];admin,ai=api.login('permission-ref-admin',du['account'],du['password'])
 api.request('permission-ref-select-admin-a','POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants']['a']['id'],'expected_ctx_version':ai['context_version']},token=admin)
 suffix=secrets.token_hex(3);code='tenant_ref_'+suffix;account='refuser.'+suffix;password=secrets.token_hex(16)
 _,role=api.request('permission-ref-create-role','POST','/v1/admin/roles',{'scope':'tenant','code':code,'name':'执行引用撤权验证','permission_codes':['tenant:department:read']},token=admin)
 api.request('permission-ref-create-member','POST','/v1/admin/members',{'account':account,'display_name':'独立执行引用','password':password,'role_codes':[code]},token=admin)
 token,i=api.login('permission-ref-subject',account,password)
 api.request('permission-ref-select-subject-a','POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants']['a']['id'],'expected_ctx_version':i['context_version']},token=token)
 _,before=api.introspect('permission-ref-before-positive',token,include_execution_context=True,expected='contains department read and valid execution ref')
 ec=before['execution_context'];body={'execution_context':{'verification_ref':ec['verification_ref'],'expected_revisions':ec['revisions']},'audience':'langgraph-runtime'}
 with db('migrate') as c:
  acl=c.execute("SELECT grantee::regrole::text,privilege_type,is_grantable FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid=%s::regprocedure",(signature,)).fetchall()
  c.execute('REVOKE EXECUTE ON FUNCTION '+signature+' FROM PUBLIC,iam_app')
 try:
  api.request('permission-audit-failure-rollback','POST','/v1/admin/roles/'+role['id']+'/permissions',{'permission_codes':[]},token=admin,expected='error, original permission and revision preserved')
  api.introspect('permission-after-audit-failure',token,expected='still contains department read; transaction rolled back')
 finally:
  with db('migrate') as c:
   for grantee,privilege,grantable in acl:
    if privilege=='EXECUTE':
     role_name='PUBLIC' if grantee=='-' else '"'+grantee.replace('"','""')+'"'
     c.execute('GRANT EXECUTE ON FUNCTION '+signature+' TO '+role_name+(' WITH GRANT OPTION' if grantable else ''))
 api.request('permission-real-revoke-commit','POST','/v1/admin/roles/'+role['id']+'/permissions',{'permission_codes':[]},token=admin,expected='200; revisions must invalidate old run')
 _,after=api.introspect('permission-current-identity-after-revoke',token,expected='no department read')
 log.emit('permission-revision-before-after',expected='at least one relevant revision advances',actual={'before':before['revisions'],'after':after['revisions']})
 api.request('old-execution-ref-after-permission-revoke','POST','/v1/internal/identity/introspect',body,internal=True,expected='active=false; cannot keep previous execution permission')
finally:api.close();log.close()
