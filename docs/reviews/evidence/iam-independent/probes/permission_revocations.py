#!/usr/bin/env python3
import json,secrets
from probe_client import Api,Evidence,PRIVATE
log=Evidence('independent-permission-revocations');api=Api(log);f=json.loads((PRIVATE/'fixtures.json').read_text())
try:
 u=f['users']['dual'];admin,ai=api.login('permission-admin',u['account'],u['password'])
 api.request('permission-admin-select-a','POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants']['a']['id'],'expected_ctx_version':ai['context_version']},token=admin)
 api.request('restore-reader-a-fixture','PATCH','/v1/admin/members/'+f['memberships']['reader_a']['id'],{'status':'active'},token=admin)
 code='tenant_revoke_'+secrets.token_hex(3)
 _,role=api.request('create-revocable-role','POST','/v1/admin/roles',{'scope':'tenant','code':code,'name':'独立权限撤销','permission_codes':['tenant:department:read']},token=admin)
 api.request('assign-revocable-role','POST','/v1/admin/members/'+f['memberships']['reader_a']['id']+'/roles',{'role_codes':[code]},token=admin)
 ru=f['users']['reader'];tokens={}
 for k in ['a','b']:
  t,i=api.login('permission-reader-login-'+k,ru['account'],ru['password']);tokens[k]=t
  api.request('permission-reader-select-'+k,'POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants'][k]['id'],'expected_ctx_version':i['context_version']},token=t)
  api.introspect('permission-before-'+k,t,expected='contains tenant:department:read')
 api.request('revoke-permission-commit','POST','/v1/admin/roles/'+role['id']+'/permissions',{'permission_codes':[]},token=admin)
 for k in ['a','b']:api.introspect('permission-after-first-'+k,tokens[k],expected='A loses department read immediately; B still contains department read')
 api.request('remove-role-commit','POST','/v1/admin/members/'+f['memberships']['reader_a']['id']+'/roles',{'role_codes':[]},token=admin)
 api.introspect('role-removed-first-a',tokens['a'],expected='A cannot retain previous grant')
 api.introspect('role-removed-first-b',tokens['b'],expected='B unaffected')
finally:api.close();log.close()
