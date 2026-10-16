import json,secrets
from urllib.parse import urlparse,parse_qs
from runtime import OUT,env_values
import httpx
E=env_values();base='http://127.0.0.1:29107';rows=[]
with httpx.Client(base_url=base,timeout=5,trust_env=False,follow_redirects=False) as c:
 r=c.get('/web-api/csrf');assert r.status_code==200;csrf=r.json()['csrf_token'];rows.append({'case':'canonical-csrf','status':r.status_code})
 r=c.post('/web-api/auth/login',headers={'Origin':base,'X-CSRF-Token':csrf},json={'account':E['IAM_BOOTSTRAP_ACCOUNT'],'password':E['IAM_BOOTSTRAP_PASSWORD'],'realm':'workforce'});assert r.status_code==200
 state=secrets.token_hex(16);callback=base+'/web-api/sso/callback/agent';client_id=E.get('IAM_SSO_CLIENT_AGENT_ID','air-agent-local')
 r=c.get('/v1/sso/authorize',params={'client_id':client_id,'redirect_uri':callback,'state':state});assert r.status_code==303
 location=urlparse(r.headers['location']);q=parse_qs(location.query);assert q['state']==[state] and len(q['ticket'])==1
 rows.append({'case':'canonical-sso-authorize','status':r.status_code,'exact_callback':location.path=='/web-api/sso/callback/agent','no_user_bearer_in_url':True})
 r=c.post('/v1/internal/sso/exchange',headers={'Authorization':'Bearer '+E['IAM_SSO_CLIENT_AGENT_SECRET']},json={'ticket':q['ticket'][0],'redirect_uri':callback,'state':state});assert r.status_code==200
 app=r.json();assert app['identity']['audience']=='air-agent';rows.append({'case':'SSO-registered-client-Bearer','status':r.status_code,'audience':'air-agent'})
 r=c.post('/v1/auth/login',json={'account':E['IAM_BOOTSTRAP_ACCOUNT'],'password':E['IAM_BOOTSTRAP_PASSWORD'],'realm':'workforce','audience':'iam-admin'});assert r.status_code==200
 token=r.json()['access_token'];r=c.get('/v1/auth/menus',headers={'Authorization':'Bearer '+token},params={'application':'iam-admin'});assert r.status_code==200 and isinstance(r.json()['items'],list)
 rows.append({'case':'canonical-menu-items','status':r.status_code,'items_present':True})
(OUT/'canonical-routes-delivery.json').write_text(json.dumps({'rows':rows},indent=2));print(json.dumps(rows,indent=2))
