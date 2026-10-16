#!/usr/bin/env python3
import base64
import hashlib
import json
import secrets
import sys
import time
from probe_client import Api,Evidence,PRIVATE,ENV,db
sys.dont_write_bytecode=True
sys.path.insert(0,str(PRIVATE/'reference'))
import agent_ticket
log=Evidence('independent-internal-principals');api=Api(log)
f=json.loads((PRIVATE/'fixtures.json').read_text());suffix=secrets.token_hex(4)
clients={}
def setup_client(name,scopes,audiences):
    cid='probe-'+name+'-'+suffix;secret=secrets.token_hex(24)
    with db('migrate') as c:
        c.execute('SELECT iam_auth.ensure_internal_client(%s,%s,%s,%s,%s)',(cid,'独立合成内部客户端',hashlib.sha256(secret.encode()).hexdigest(),scopes,audiences))
    clients[name]=(cid,secret)
def headers(name):
    cid,secret=clients[name]
    return {'Authorization':'Basic '+base64.b64encode((cid+':'+secret).encode()).decode()}
def introspect(case,body,client='full',expect=None):
    return api.request(case,'POST','/v1/internal/identity/introspect',body,headers=headers(client),expected=expect)
aud='langgraph-runtime'
try:
    for name,scopes,auds in [('full',['identity:introspect','runtime-ticket:issue'],[aud,'knowledge']),('other',['identity:introspect'],[aud,'knowledge']),('noscope',[],[aud])]:
        setup_client(name,scopes,auds)
    root,_=api.login('internal-root')
    u=f['users']['dual'];t,i=api.login('internal-dual',u['account'],u['password'])
    _,i=api.request('internal-select-a','POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants']['a']['id'],'expected_ctx_version':i['context_version']},token=t,expected='200')
    body={'subject_token':t,'audience':aud,'include_execution_context':True}
    _,b=introspect('verification-create',body,expect='200; bound ref')
    ec=b['execution_context'];ref={'execution_context':{'verification_ref':ec['verification_ref'],'expected_revisions':ec['revisions']},'audience':aud}
    introspect('verification-same-client',ref,expect='active=true context_matches=true')
    introspect('verification-wrong-client',ref,'other','active=false')
    introspect('verification-wrong-audience',{**ref,'audience':'knowledge'},expect='active=false')
    introspect('introspect-without-scope',{'subject_token':t,'audience':aud},'noscope','403')
    api.request('ref-not-bearer','GET','/v1/auth/me',token=ec['verification_ref'],expected='401')
    api.request('ref-cannot-exchange-ticket','POST','/v1/internal/runtime-tickets',{'subject_token':ec['verification_ref'],'audience':aud,'target_tenant_id':f['tenants']['a']['id'],'expected_ctx_version':i['context_version']},headers=headers('full'),expected='401')
    _,ticket=api.request('real-http-runtime-ticket','POST','/v1/internal/runtime-tickets',{'subject_token':t,'audience':aud,'target_tenant_id':f['tenants']['a']['id'],'expected_ctx_version':i['context_version']},headers=headers('full'),expected='200 rt-v1')
    try:
        agent_ticket.verify_ticket(ticket['ticket'],[(ENV['IAM_RT_KEYS_KID'],ENV['IAM_RT_KEYS_SECRET'])],expected_audience=aud,now=int(time.time()))
        outcome={'ok':True}
    except agent_ticket.TicketError as e:outcome={'ok':False,'reason':str(e)}
    log.emit('real-http-ticket-original-python-consumer',expected='ok=true',actual=outcome)
    # Persist bound reference only (not bearer credentials) for >60s recheck in later probe.
    pending={'reference':ref,'client_id':clients['full'][0],'client_secret':clients['full'][1],'session_id':i['session']['id'],'created_epoch':int(time.time())}
    pending_path=PRIVATE/'long-ref-probe.json';pending_path.write_text(json.dumps(pending));pending_path.chmod(0o600)
    mutated=json.loads(json.dumps(ref));mutated['execution_context']['expected_revisions']['session_ctx_version']+=1
    introspect('verification-forged-revision',mutated,expect='active=false revision_mismatch')
    api.request('verification-logout','POST','/v1/auth/logout',token=t,expected='204')
    introspect('verification-after-logout',ref,expect='active=false')
    # A new reference is retained with an unrevoked session for >60s checks.
    nt,ni=api.login('long-reference-new-session',u['account'],u['password'])
    _,ni=api.request('long-reference-select','POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants']['a']['id'],'expected_ctx_version':ni['context_version']},token=nt)
    _,nb=introspect('long-reference-create',{'subject_token':nt,'audience':aud,'include_execution_context':True})
    pending.update(reference={'execution_context':{'verification_ref':nb['execution_context']['verification_ref'],'expected_revisions':nb['execution_context']['revisions']},'audience':aud},session_id=ni['session']['id'],created_epoch=int(time.time()))
    pending_path.write_text(json.dumps(pending))
    # Service principal: actual HTTP creates/tokens and consumer introspection.
    sa={'account':'sa-probe-'+suffix,'name':'独立服务主体','tenant_id':f['tenants']['a']['id'],'audiences':['knowledge'],'expires_in_days':2,'permissions':['tenant:department:read']}
    _,s=api.request('service-create','POST','/v1/admin/service-accounts',sa,token=root,expected='200')
    sid=s['id'];path='/v1/admin/service-accounts/'+sid
    _,one=api.request('service-token-one','POST',path+'/tokens',{},token=root,expected='200; secret once')
    sb={'subject_token':one['secret'],'audience':'knowledge'}
    introspect('service-valid-principal',sb,expect='service_account; user/session/membership=null; fixed A')
    introspect('service-wrong-audience',{**sb,'audience':aud},expect='403')
    for endpoint in ['/v1/auth/switch-tenant','/v1/admin/users']:
        api.request('service-not-human-'+endpoint.rsplit('/',1)[-1],'POST',endpoint,{},token=one['secret'],expected='401/403')
    api.request('service-cannot-runtime-ticket','POST','/v1/internal/runtime-tickets',{'subject_token':one['secret'],'audience':aud,'target_tenant_id':f['tenants']['a']['id'],'expected_ctx_version':1},headers=headers('full'),expected='401')
    api.request('service-overlap-too-long','POST',path+'/tokens',{'overlap_hours':25},token=root,expected='400')
    _,two=api.request('service-rotate-no-overlap','POST',path+'/tokens',{'overlap_hours':0},token=root,expected='200; old credential must no longer remain indefinitely active')
    introspect('service-old-after-rotation-zero-overlap',sb,expect='active=false')
    introspect('service-new-after-rotation',{'subject_token':two['secret'],'audience':'knowledge'},expect='active=true')
    api.request('service-revoke-one','POST','/v1/admin/service-accounts/tokens/'+one['credential_id']+'/revoke',token=root,expected='204')
    introspect('service-revoked-first',sb,expect='active=false')
    api.request('service-disable','PATCH',path,{'status':'disabled'},token=root,expected='200')
    introspect('service-disabled-first',{'subject_token':two['secret'],'audience':'knowledge'},expect='active=false')
    api.request('service-too-long-account','POST','/v1/admin/service-accounts',{**sa,'account':'sa-long-'+suffix,'expires_in_days':366},token=root,expected='400')
    api.request('service-resource-denied','POST','/v1/admin/service-accounts',{**sa,'account':'sa-resource-'+suffix,'permissions':['knowledge:lib:air:read']},token=root,expected='400')
    # Authoritative client secret rotation/revocation must apply to next request.
    cid,oldsecret=clients['other'];newsecret=secrets.token_hex(24)
    with db('migrate') as c:c.execute('UPDATE iam.internal_clients SET secret_digest=%s WHERE client_id=%s',(hashlib.sha256(newsecret.encode()).hexdigest(),cid))
    introspect('internal-old-secret-rejected',ref,'other','401')
    clients['other']=(cid,newsecret)
    introspect('internal-new-secret-positive',{'subject_token':nt,'audience':aud},'other','200 active=true')
    with db('migrate') as c:c.execute("UPDATE iam.internal_clients SET status='disabled' WHERE client_id=%s",(cid,))
    introspect('internal-disabled-next-request',{'subject_token':nt,'audience':aud},'other','401')
finally:api.close();log.close()
