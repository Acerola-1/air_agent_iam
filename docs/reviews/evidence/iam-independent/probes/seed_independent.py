#!/usr/bin/env python3
import json
import secrets
from probe_client import Api, Evidence, PRIVATE, db

log=Evidence('independent-fixture-setup')
api=Api(log)
fixture={'users':{},'tenants':{},'memberships':{},'roles':{}}
private_path=PRIVATE/'fixtures.json'
assert not private_path.exists(), 'Refuse to replace fixture identities'
try:
    root_token,root=api.login('fixture-platform-login')
    for key in ['dual','reader','memberwriter','rolewriter','outsider','last1','last2']:
        password=secrets.token_hex(12)+'aA7!'
        response,user=api.request('fixture-create-user-'+key,'POST','/v1/admin/users',
            {'account':'audit.'+key,'display_name':'独立验收-'+key,'password':password},token=root_token,expected='201; platform authorized user creation')
        if response.status_code!=201: raise RuntimeError('User creation failed; see evidence')
        fixture['users'][key]={**user,'password':password}
    for key in ['a','b','last']:
        response,tenant=api.request('fixture-create-tenant-'+key,'POST','/v1/admin/tenants',
            {'code':'independent-'+key,'name':'独立验收企业-'+key.upper()},token=root_token,expected='201; platform authorized tenant creation')
        if response.status_code!=201: raise RuntimeError('Tenant creation failed; see evidence')
        fixture['tenants'][key]=tenant
    api.request('platform-establish-first-admin-via-api','POST','/v1/admin/members',
        {'tenant_id':fixture['tenants']['a']['id'],'user_id':fixture['users']['dual']['id'],'role_codes':['tenant_admin']},
        token=root_token,expected='Approved flow allows platform to establish and authorize first member; no existing tenant admin in empty tenant')
    with db('migrate') as connection:
        with connection.transaction():
            connection.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)')
            for name,codes in [('memberwriter',['tenant:member:read','tenant:member:write']),('rolewriter',['tenant:role:read','tenant:role:write'])]:
                role_id=connection.execute("INSERT INTO iam.roles(scope,tenant_id,code,name) VALUES ('tenant',%s,%s,%s) RETURNING id",
                    (fixture['tenants']['a']['id'],'tenant_probe_'+name,'独立最小权限-'+name)).fetchone()[0]
                for code in codes:
                    connection.execute('INSERT INTO iam.role_permissions(role_id,permission_id) SELECT %s,id FROM iam.permissions WHERE code=%s',(role_id,code))
                fixture['roles'][name]={'id':str(role_id),'code':'tenant_probe_'+name,'permissions':codes}
            assignments=[('dual','a','tenant_admin'),('dual','b','tenant_admin'),('reader','a','tenant_reader'),('reader','b','tenant_reader'),
                         ('memberwriter','a','tenant_probe_memberwriter'),('rolewriter','a','tenant_probe_rolewriter'),
                         ('last1','last','tenant_admin'),('last2','last','tenant_admin')]
            for user_key,tenant_key,role_code in assignments:
                uid=fixture['users'][user_key]['id'];tid=fixture['tenants'][tenant_key]['id']
                mid=connection.execute('INSERT INTO iam.tenant_memberships(tenant_id,user_id,created_by) VALUES (%s,%s,%s) RETURNING id',(tid,uid,root['user']['id'])).fetchone()[0]
                rid=connection.execute("SELECT id FROM iam.roles WHERE code=%s AND scope='tenant' AND (tenant_id IS NULL OR tenant_id=%s)",(role_code,tid)).fetchone()[0]
                connection.execute('INSERT INTO iam.membership_roles(tenant_id,membership_id,role_id,granted_by) VALUES (%s,%s,%s,%s)',(tid,mid,rid,root['user']['id']))
                fixture['memberships'][user_key+'_'+tenant_key]={'id':str(mid),'tenant_id':tid,'user_id':uid,'role_code':role_code}
    private_path.write_text(json.dumps(fixture,ensure_ascii=False,indent=2))
    private_path.chmod(0o600)
    log.emit('isolated-sql-fixture-provisioning',expected='test setup only, not evidence that product supports first-admin provisioning',
             reason='First-admin product API unavailable; scoped synthetic fixture inserts unlock downstream acceptance without changing product',
             users={k:{'id':v['id'],'account':v['account']} for k,v in fixture['users'].items()},tenants=fixture['tenants'],memberships=fixture['memberships'],roles=fixture['roles'])
finally:
    api.close();log.close()
