#!/usr/bin/env python3
"""Independent HTTP counterexamples. Only synthetic audit fixtures are mutated."""
import json
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from probe_client import Api, Evidence, PRIVATE, db

f = json.loads((PRIVATE / 'fixtures.json').read_text())
log = Evidence('independent-tenant-boundaries')
api = Api(log)
suffix = secrets.token_hex(4)

def login(key):
    u = f['users'][key]
    return api.login('login-' + key, u['account'], u['password'])

def switch(token, identity, key, case):
    r, b = api.request(case, 'POST', '/v1/auth/switch-tenant',
        {'tenant_id': f['tenants'][key]['id'], 'expected_ctx_version': identity['context_version']}, token=token, expected='200')
    assert r.status_code == 200
    return b

def department(token, code, parent=None):
    r, b = api.request('create-dept-' + code, 'POST', '/v1/admin/departments',
        {'code': code + suffix, 'name': '独立部门-' + code, 'parent_id': parent}, token=token, expected='201')
    assert r.status_code == 201
    return b

try:
    token, identity = login('dual')
    log.emit('multi-tenant-no-default', expected='tenant=null, membership=null, needs_tenant_selection=true',
        actual={k: identity.get(k) for k in ['current_tenant','membership','needs_tenant_selection']})
    ia = switch(token, identity, 'a', 'select-a')
    da = department(token, 'parent')
    child = department(token, 'child', da['id'])
    api.request('department-cycle', 'PATCH', '/v1/admin/departments/' + da['id'], {'parent_id':child['id']}, token=token, expected='4xx; original tree preserved')
    api.request('reader-platform-user-create-control', 'POST', '/v1/admin/users',
        {'account':'blocked'+suffix,'display_name':'拒绝对照','password':secrets.token_hex(16)}, token=token, expected='403')
    ib = switch(token, ia, 'b', 'select-b')
    dbb = department(token, 'foreign')
    ia2 = switch(token, ib, 'a', 'return-a')
    api.request('cross-tenant-parent', 'POST', '/v1/admin/departments',
        {'code':'cross'+suffix,'name':'跨企业反例','parent_id':dbb['id']}, token=token, expected='4xx')
    api.request('cross-tenant-member-id', 'PATCH', '/v1/admin/members/' + f['memberships']['reader_b']['id'],
        {'status':'disabled'}, token=token, expected='404; B membership unchanged')
    api.request('cross-tenant-query', 'GET', '/v1/admin/members?tenant_id=' + f['tenants']['b']['id'], token=token, expected='403')
    api.request('same-account-no-implicit-merge', 'POST', '/v1/admin/members',
        {'account':f['users']['outsider']['account'],'display_name':'同名','password':secrets.token_hex(16),'role_codes':['tenant_reader']}, token=token, expected='409')
    api.request('tenant-arbitrary-global-user-link', 'POST', '/v1/admin/members',
        {'user_id':f['users']['outsider']['id'],'role_codes':['tenant_reader']}, token=token, expected='403; tenant cannot associate arbitrary existing global account')
    mw, mi = login('memberwriter')
    if mi['current_tenant'] is None: mi = switch(mw, mi, 'a', 'memberwriter-select')
    api.request('memberwriter-role-endpoint-negative', 'POST', '/v1/admin/members/' + f['memberships']['reader_a']['id'] + '/roles',
        {'role_codes':['tenant_admin']}, token=mw, expected='403; lacks tenant:role:write')
    api.request('memberwriter-builtin-admin-on-create', 'POST', '/v1/admin/members',
        {'account':'escalate'+suffix,'display_name':'低权限建档授管理员','password':secrets.token_hex(16),'role_codes':['tenant_admin']}, token=mw,
        expected='403; creation must not bypass grantable permission subset')
    rw, ri = login('rolewriter')
    if ri['current_tenant'] is None: ri = switch(rw, ri, 'a', 'rolewriter-select')
    api.request('rolewriter-grant-full-builtin-template', 'POST', '/v1/admin/members/' + f['memberships']['rolewriter_a']['id'] + '/roles',
        {'role_codes':['tenant_admin']}, token=rw, expected='403; must not grant permissions outside actor subset')
    api.request('rolewriter-after-attempt-department-write', 'POST', '/v1/admin/departments',
        {'code':'escalated'+suffix,'name':'越权后写入'}, token=rw, expected='403 if least privilege preserved')
    # Same session, real simultaneous requests: one CAS winner only.
    ct, ci = login('dual')
    barrier = threading.Barrier(2)
    def race(key):
        client = Api(log)
        try:
            barrier.wait()
            r, b = client.request('cas-race-' + key, 'POST', '/v1/auth/switch-tenant',
                {'tenant_id':f['tenants'][key]['id'],'expected_ctx_version':ci['context_version']}, token=ct, expected='one 200, one 409')
            return r.status_code
        finally: client.close()
    with ThreadPoolExecutor(2) as pool: statuses = list(pool.map(race,['a','b']))
    log.emit('cas-concurrent-summary', expected=[200,409], actual=sorted(statuses))
    # Stale A create request after A->B: explicit stale declaration must be rejected.
    current = api.request('context-before-stale-write','GET','/v1/auth/me',token=token)[1]
    switch(token, current, 'b', 'switch-before-stale-a-create')
    api.request('stale-a-create-after-switch-b', 'POST','/v1/admin/departments',
        {'code':'stale'+suffix,'name':'旧A表单','tenant_id':f['tenants']['a']['id'],'expected_ctx_version':ia2['context_version']}, token=token,
        expected='409; never write stale A operation into B')
    api.request('b-persistence-after-stale-write','GET','/v1/admin/departments?limit=200',token=token,
        expected='B must not contain stale A department')
    with db('migrate') as conn:
        with conn.transaction():
            conn.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)')
            row = conn.execute('SELECT status FROM iam.tenant_memberships WHERE id=%s',(f['memberships']['reader_b']['id'],)).fetchone()
            log.emit('cross-tenant-member-final-control',expected='active',actual=row[0])
finally:
    api.close()
    log.close()
