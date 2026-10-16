import sys,json,time,secrets,importlib.util,hashlib,subprocess,zipfile,concurrent.futures
from pathlib import Path
sys.dont_write_bytecode=True
from runtime import ROOT,PRIVATE,OUT,PORT,JAVA,env_values
import httpx,psycopg
ENV=env_values();BASE=f'http://127.0.0.1:{PORT}'
client=httpx.Client(base_url=BASE,timeout=5,trust_env=False)
log=(OUT/'real-http-acceptance-delivery.jsonl').open('x')
passed=0

def emit(case,**data):
    global passed
    row={'case':case,**data};log.write(json.dumps(row,ensure_ascii=False,default=str)+'\n');log.flush()
    print(case,data.get('status',data.get('passed','recorded')),flush=True)
    if data.get('passed'):passed+=1

def req(case,method,path,body=None,token=None,internal=False,expected=200):
    headers={}
    if token:headers['Authorization']='Bearer '+token
    if internal:headers['Authorization']='Bearer '+ENV['IAM_INTERNAL_RUNTIME_CLIENT_SECRET']
    start=time.perf_counter();r=client.request(method,path,json=body,headers=headers);elapsed=(time.perf_counter()-start)*1000
    emit(case,status=r.status_code,expected=expected,elapsed_ms=round(elapsed,3),passed=r.status_code==expected)
    if r.status_code!=expected:
        # Error envelopes are safe; never dump successful auth/credential responses.
        if r.status_code>=400:emit(case+'-error',error=r.json())
        raise AssertionError(case+' status mismatch')
    return r,r.json() if r.status_code!=204 else None

def login(account=None,password=None):
    _,r=req('login','POST','/v1/auth/login',{'account':account or ENV['IAM_BOOTSTRAP_ACCOUNT'],
        'password':password or ENV['IAM_BOOTSTRAP_PASSWORD'],'realm':'workforce','audience':'iam-admin'})
    return r['access_token'],r['identity']

def owner_connection():
    return psycopg.connect(host='127.0.0.1',port=29132,dbname='iam_remediation',user=ENV['IAM_PG_MIGRATE_USER'],password=ENV['IAM_PG_MIGRATE_PASSWORD'])

def main():
    stamp=str(int(time.time()))
    token,identity=login()
    req('unknown-login-uniform-401','POST','/v1/auth/login',{'account':'ghost-'+stamp,'password':secrets.token_hex(12),'realm':'workforce','audience':'iam-admin'},expected=401)
    _,tenantA=req('new-enterprise-initial-admin','POST','/v1/admin/tenants',{'code':'RA-'+stamp,'name':'整改验收企业甲'},token,expected=201)
    _,tenantB=req('new-enterprise-B','POST','/v1/admin/tenants',{'code':'RB-'+stamp,'name':'整改验收企业乙'},token,expected=201)
    _,memberships=req('creator-can-enter-new-enterprise','GET','/v1/auth/tenants',token=token)
    assert tenantA['id'] in {m['tenant_id'] for m in memberships}
    _,selected=req('select-A','POST','/v1/auth/switch-tenant',{'tenant_id':tenantA['id'],'expected_ctx_version':1},token)
    req('select-B','POST','/v1/auth/switch-tenant',{'tenant_id':tenantB['id'],'expected_ctx_version':2},token)
    req('old-A-form-rejected-in-B','POST','/v1/admin/departments',{'code':'STALE','name':'旧企业表单','tenant_id':tenantA['id'],'expected_ctx_version':2},token,expected=409)
    req('unbound-department-form-rejected','POST','/v1/admin/departments',{'code':'UNBOUND','name':'未绑定表单'},token,expected=400)
    req('return-to-A','POST','/v1/auth/switch-tenant',{'tenant_id':tenantA['id'],'expected_ctx_version':3},token)
    req('create-bound-department','POST','/v1/admin/departments',{'code':'VALID','name':'有效部门','tenant_id':tenantA['id'],'expected_ctx_version':4},token,expected=201)
    req('numeric-string-context-rejected','POST','/v1/auth/renew',{'expected_ctx_version':'4'},token,expected=400)
    req('string-boolean-rejected','POST','/v1/internal/identity/introspect',{'subject_token':token,'audience':'langgraph-runtime','include_execution_context':'true'},internal=True,expected=400)
    _,active=req('registered-client-Bearer','POST','/v1/internal/identity/introspect',{'subject_token':token,'audience':'langgraph-runtime','include_execution_context':True},internal=True)
    assert active['audience']=='langgraph-runtime' and not active['platform_roles'] and not active['platform_admin']
    assert not any(p.startswith('platform:') or p=='entitlement:manage' for p in active['permissions'])
    emit('runtime-audience-excludes-platform-authority',passed=True)
    _,ticket=req('real-runtime-ticket','POST','/v1/internal/runtime-tickets',{'subject_token':token,'audience':'langgraph-runtime','target_tenant_id':tenantA['id'],'expected_ctx_version':4},internal=True)
    # Original Python verifier (read-only reference, no new consumer reimplementation).
    sys.path.insert(0,'/tmp/iam-independent-20261015-5ohAEo/reference')
    import agent_ticket,agent_security
    claims=agent_ticket.verify_ticket(ticket['ticket'],[(ENV['IAM_RT_KEYS_KID'],ENV['IAM_RT_KEYS_SECRET'])],expected_audience='langgraph-runtime')
    assert claims.tenant_id==tenantA['id'] and claims.session_ctx_version==4
    emit('HTTP-Java-ticket-accepted-by-original-Python',segments=len(ticket['ticket'].split('.')),passed=True)
    _,writerRole=req('create-limited-writer-role','POST','/v1/admin/roles',{'scope':'tenant','code':'limited-'+stamp,'name':'有限授权人','permission_codes':['tenant:role:write','tenant:member:write']},token,expected=201)
    password=secrets.token_hex(18)+'Aa!'
    _,user=req('create-probe-user','POST','/v1/admin/users',{'account':'probe-'+stamp,'display_name':'整改验收账号','password':password},token,expected=201)
    _,member=req('associate-probe-member','POST','/v1/admin/members',{'tenant_id':tenantA['id'],'user_id':user['id'],'role_codes':[writerRole['code']]},token,expected=201)
    limited,limitedIdentity=login(user['account'],password)
    req('limited-select-A','POST','/v1/auth/switch-tenant',{'tenant_id':tenantA['id'],'expected_ctx_version':1},limited)
    req('limited-writer-cannot-self-promote','POST',f"/v1/admin/members/{member['id']}/roles",{'role_codes':['tenant_admin'],'expected_revision':member['revision']},limited,expected=403)
    req('limited-writer-cannot-create-admin','POST','/v1/admin/members',{'tenant_id':tenantA['id'],'account':'forbidden-'+stamp,'display_name':'越界账号','password':password,'role_codes':['tenant_admin']},limited,expected=403)
    req('limited-writer-cannot-attach-global-user','POST','/v1/admin/members',{'tenant_id':tenantA['id'],'user_id':identity['user']['id']},limited,expected=409) # already a member, no duplicate association
    _,ref=req('issue-reference-before-role-revoke','POST','/v1/internal/identity/introspect',{'subject_token':limited,'audience':'langgraph-runtime','include_execution_context':True},internal=True)
    req('revoke-role-permissions','POST',f"/v1/admin/roles/{writerRole['id']}/permissions",{'permission_codes':[]},token)
    ec=ref['execution_context'];_,rechecked=req('old-execution-ref-after-role-revoke','POST','/v1/internal/identity/introspect',{'audience':'langgraph-runtime','execution_context':{'verification_ref':ec['verification_ref'],'expected_revisions':ec['revisions']}},internal=True)
    assert not rechecked['active'] and not rechecked['context_matches'];emit('revoked-role-reference-rejected',passed=True)
    _,audit=req('typed-audit-query','GET','/v1/admin/audit-logs?limit=1',token=token)
    assert audit['items'] and isinstance(audit['items'][0]['detail'],dict);emit('audit-json-is-object',passed=True)
    # A real DB authority lock, held longer than the 500 ms total budget.
    with owner_connection() as locked:
        locked.execute('LOCK TABLE iam.auth_sessions IN ACCESS EXCLUSIVE MODE')
        start=time.perf_counter();response=client.post('/v1/internal/identity/introspect',headers={'Authorization':'Bearer '+ENV['IAM_INTERNAL_RUNTIME_CLIENT_SECRET']},json={'subject_token':token,'audience':'langgraph-runtime'})
        elapsed=(time.perf_counter()-start)*1000
        payload=response.json();assert response.status_code==503 and elapsed<650
        assert payload['error']['request_id']==response.headers['x-request-id']
        emit('authority-lock-total-deadline',status=response.status_code,elapsed_ms=round(elapsed,3),request_id_matches=True,passed=True)
        locked.rollback()
    req('dependency-recovery-positive-control','POST','/v1/internal/identity/introspect',{'subject_token':token,'audience':'langgraph-runtime'},internal=True)
    other,_=login();req('logout-once','POST','/v1/auth/logout',token=other,expected=204);req('logout-repeat-idempotent','POST','/v1/auth/logout',token=other,expected=204)
    req('logged-out-subject-rejected','GET','/v1/auth/me',token=other,expected=401)
    # Save only private synthetic material needed by subsequent independent probes/browser login.
    fixture={'token':token,'identity':identity,'tenantA':tenantA,'tenantB':tenantB,'ctx_version':4,'probe_user':user,'probe_password':password,'audience':'langgraph-runtime','reference':active['execution_context']}
    f=PRIVATE/'http-fixtures.json';f.write_text(json.dumps(fixture));f.chmod(0o600)
    emit('completed',passed_cases=passed)
    log.close();client.close()
if __name__=='__main__':main()
