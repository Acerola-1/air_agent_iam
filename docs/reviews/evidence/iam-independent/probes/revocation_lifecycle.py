#!/usr/bin/env python3
import json
import secrets
from probe_client import Api, Evidence, PRIVATE, db
log=Evidence('independent-revocation-lifecycle')
api=Api(log)
f=json.loads((PRIVATE/'fixtures.json').read_text())
try:
    root,_=api.login('revocation-root-login')
    password=secrets.token_hex(16)
    _,u=api.request('revocation-create-user','POST','/v1/admin/users',
        {'account':'revoke.'+secrets.token_hex(4),'display_name':'独立撤销探针','password':password},token=root,expected='201')
    def login(name): return api.login(name,u['account'],password)
    def check(name,t,expect):
        _,body=api.introspect(name,t,expected=expect)
        log.emit(name+'-decision',expected=expect,actual={'active':body.get('active'),'reason':body.get('reason'),'audience':body.get('audience')})
    t1,i1=login('before-password-change-current');t2,_=login('before-password-change-other')
    check('before-password-positive',t1,'active=true')
    newpass=secrets.token_hex(16)
    api.request('password-change-commit','POST','/v1/auth/change-password',{'old_password':password,'new_password':newpass},token=t1,expected='204; all personal sessions revoked including caller')
    password=newpass
    check('after-password-current-first-introspection',t1,'active=false')
    check('after-password-other-first-introspection',t2,'active=false')
    api.request('after-password-current-renew','POST','/v1/auth/renew',{'expected_ctx_version':i1['context_version']},token=t1,expected='401; cannot revive')
    t3,_=login('before-admin-reset');newpass=secrets.token_hex(16)
    api.request('admin-reset-commit','POST','/v1/admin/users/'+u['id']+'/password',{'new_password':newpass},token=root,expected='204')
    password=newpass
    check('after-admin-reset-first',t3,'active=false')
    t4,_=login('before-logout-all-one');t5,_=login('before-logout-all-two')
    api.request('logout-all-commit','POST','/v1/auth/logout-all',token=t4,expected='204')
    check('after-logout-all-one',t4,'active=false');check('after-logout-all-two',t5,'active=false')
    t6,_=login('before-disable-account')
    api.request('disable-account-commit','PATCH','/v1/admin/users/'+u['id'],{'status':'disabled'},token=root,expected='200')
    check('after-disable-account-first',t6,'active=false; account_disabled')
    api.request('enable-account-commit','PATCH','/v1/admin/users/'+u['id'],{'status':'active'},token=root,expected='200')
    check('re-enabled-account-old-token',t6,'active=false; old session not revived')
    # Expiry is injected only into this fresh synthetic session; keeps Redis state intact.
    t7,i7=login('before-expiry')
    with db('migrate') as c:
        with c.transaction():
            c.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)')
            c.execute("UPDATE iam.auth_sessions SET idle_expires_at=now()-interval '1 second' WHERE id=%s",(i7['session']['id'],))
    check('idle-expired-first-introspection',t7,'active=false')
    api.request('idle-expired-renew','POST','/v1/auth/renew',{'expected_ctx_version':i7['context_version']},token=t7,expected='401')
    # Separate A/B sessions for member and tenant revocation scope.
    du=f['users']['reader']; ta,ia=api.login('reader-a-login',du['account'],du['password']);tb,ib=api.login('reader-b-login',du['account'],du['password'])
    for tok,ident,k in [(ta,ia,'a'),(tb,ib,'b')]:
        api.request('reader-select-'+k,'POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants'][k]['id'],'expected_ctx_version':ident['context_version']},token=tok,expected='200')
    admin,ai=api.login('dual-for-member-disable',f['users']['dual']['account'],f['users']['dual']['password'])
    api.request('dual-select-a','POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants']['a']['id'],'expected_ctx_version':ai['context_version']},token=admin,expected='200')
    api.request('disable-a-member-commit','PATCH','/v1/admin/members/'+f['memberships']['reader_a']['id'],{'status':'disabled'},token=admin,expected='200')
    check('disabled-a-member-first',ta,'inactive or context_usable=false and no tenant permissions')
    check('b-member-unaffected-positive',tb,'active=true; B usable')
    api.request('suspend-b-tenant-commit','PATCH','/v1/admin/tenants/'+f['tenants']['b']['id'],{'status':'suspended'},token=root,expected='200')
    check('suspended-b-tenant-first',tb,'inactive or context_usable=false and no tenant permissions')
    api.request('restore-b-tenant','PATCH','/v1/admin/tenants/'+f['tenants']['b']['id'],{'status':'active'},token=root,expected='200')
finally: api.close();log.close()
