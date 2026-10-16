#!/usr/bin/env python3
import base64,json,secrets,time
from urllib.parse import urlparse,parse_qs
from probe_client import Api,Evidence,PRIVATE,BASE,ENV,db
log=Evidence('independent-expiry-surface');api=Api(log)
try:
 root,_=api.login('surface-live-root')
 api.request('surface-logout-first','POST','/v1/auth/logout',token=root,expected='204')
 api.request('surface-logout-repeat','POST','/v1/auth/logout',token=root,expected='204 idempotent even already inactive')
 root,_=api.login('expiry-root');f=json.loads((PRIVATE/'fixtures.json').read_text());client=json.loads((PRIVATE/'long-ref-probe.json').read_text())
 h={'Authorization':'Basic '+base64.b64encode((client['client_id']+':'+client['client_secret']).encode()).decode()}
 _,sa=api.request('expiry-service-create','POST','/v1/admin/service-accounts',{'account':'sa-expiry-'+secrets.token_hex(4),'name':'独立服务期限','tenant_id':f['tenants']['a']['id'],'audiences':['knowledge'],'expires_in_days':1,'permissions':[]},token=root)
 _,credential=api.request('expiry-service-token','POST','/v1/admin/service-accounts/'+sa['id']+'/tokens',{},token=root)
 body={'subject_token':credential['secret'],'audience':'knowledge'}
 api.request('expiry-service-before','POST','/v1/internal/identity/introspect',body,headers=h,expected='active=true')
 with db('migrate') as c:c.execute("UPDATE iam.service_tokens SET issued_at=now()-interval '1 hour',expires_at=now()-interval '1 minute' WHERE credential_id=%s",(credential['credential_id'],))
 api.request('expired-service-credential-first','POST','/v1/internal/identity/introspect',body,headers=h,expected='active=false')
 # SSO grant is tested after a real wall-clock >30s in a follow-up, not a mocked timestamp.
 _,csrf=api.request('expiry-csrf','GET','/web-api/auth/csrf')
 api.request('expiry-browser-login','POST','/web-api/auth/login',{'account':ENV['IAM_BOOTSTRAP_ACCOUNT'],'password':ENV['IAM_BOOTSTRAP_PASSWORD'],'realm':'workforce'},headers={'Origin':BASE,'X-CSRF-Token':csrf['csrf_token']})
 start=api.client.get('/web-api/sso/callback/agent/login');grant=api.client.get(start.headers['location']);q=parse_qs(urlparse(grant.headers['location']).query)
 pending={'ticket':q['ticket'][0],'state':q['state'][0],'redirect_uri':ENV['IAM_SSO_CLIENT_AGENT_CALLBACK'],'created_epoch':time.time()}
 p=PRIVATE/'sso-expiry-grant.json';p.write_text(json.dumps(pending));p.chmod(0o600);log.emit('real-sso-grant-retained-until-expiry',status=grant.status_code,actual='private only, follow-up after actual30s')
finally:api.close();log.close()
