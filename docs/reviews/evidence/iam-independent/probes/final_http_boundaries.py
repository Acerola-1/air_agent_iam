#!/usr/bin/env python3
import json,os,socket,subprocess,time
from http.cookies import SimpleCookie
from environment import EVIDENCE,COPY,PRIVATE,JAVA,CONTAINER,NAMES,RUN_ID,env_values
from probe_client import Api,Evidence,BASE,ENV
log=Evidence('independent-final-http-boundaries');api=Api(log);proc=None;pg_stopped=False
rp=EVIDENCE/'outputs/resources.json';resources=json.loads(rp.read_text())
def pg(action):
 assert NAMES['pg'] in resources['created_containers']
 d=json.loads(subprocess.check_output([CONTAINER,'inspect',NAMES['pg']],text=True))[0];assert d['configuration']['labels']['audit.run']==RUN_ID
 r=subprocess.run([CONTAINER,action,NAMES['pg']],capture_output=True,timeout=50);assert r.returncode==0
 log.emit('owned-pg-'+action,status=0)
try:
 token,i=api.login('final-live-root-positive')
 api.request('final-live-me-positive','GET','/v1/auth/me',token=token,expected='200')
 api.request('frozen-menu-contract','GET','/v1/auth/menus?application=iam-admin',token=token,expected='items menu tree')
 for path in ['/web-api/csrf','/v1/sso/authorize']:
  api.request('frozen-route-'+path,'GET',path,token=token if path.startswith('/v1') else None,expected='documented route exists; not404')
 _,csrf=api.request('csrf-positive-init','GET','/web-api/auth/csrf')
 api.request('origin-missing-with-csrf','POST','/web-api/auth/login',{'account':ENV['IAM_BOOTSTRAP_ACCOUNT'],'password':ENV['IAM_BOOTSTRAP_PASSWORD'],'realm':'workforce'},headers={'X-CSRF-Token':csrf['csrf_token']},expected='403')
 api.request('external-cors-preflight','OPTIONS','/web-api/auth/login',headers={'Origin':'https://unregistered.invalid','Access-Control-Request-Method':'POST'},expected='no credentialed wildcard or allowed external origin')
 # A valid token positive control makes PG fail-close observation meaningful.
 pg('stop');pg_stopped=True
 api.introspect('pg-outage-live-subject-introspection',token,expected='503')
 api.request('pg-outage-live-subject-me','GET','/v1/auth/me',token=token,expected='503, not401/anonymous')
 pg('start');pg_stopped=False
 for _ in range(60):
  try:
   if api.client.get('/healthz').status_code==200:break
  except Exception:pass
  time.sleep(.5)
 api.introspect('pg-recovered-live-subject-positive',token,expected='active=true')
 # Sequential guard costs and explicit simulated wait, not a real model consumer claim.
 for round_id in range(3):
  start=time.perf_counter()
  for n in range(5):api.introspect('sequential-'+str(round_id)+'-'+str(n),token,expected='same current authority on every call')
  log.emit('sequential-five-calls-'+str(round_id),actual={'total_wall_ms':(time.perf_counter()-start)*1000,'calls':5,'external_wait_ms':0})
 start=time.perf_counter();api.introspect('synthetic-wait-before',token);wait_start=time.perf_counter();time.sleep(.2);wait_ms=(time.perf_counter()-wait_start)*1000;api.introspect('synthetic-wait-after',token)
 log.emit('explicit-wait-separated',actual={'total_wall_ms':(time.perf_counter()-start)*1000,'synthetic_external_wait_ms':wait_ms,'real_external_model_or_tool':'not invoked in I1'})
 # Exercise actual Java production cookie rendering without claiming public TLS deployment.
 port=29105
 with socket.socket() as s:s.bind(('127.0.0.1',port))
 file=(PRIVATE/'server-independent-secure-cookie.log').open('x');os.chmod(file.name,0o600)
 proc=subprocess.Popen([JAVA+'/bin/java','-Xms128m','-Xmx768m','-jar',str(COPY/'server/target/iam-server.jar')],cwd=COPY,
  env={**os.environ,**env_values(),'IAM_HTTP_PORT':str(port),'IAM_WEB_SECURE_COOKIES':'true','IAM_WEB_SYNTHETIC_CONSUMER_ENABLED':'false'},stdout=file,stderr=file,start_new_session=True)
 item={'kind':'java','label':'independent-secure-cookie','pid':proc.pid,'port':port,'jar':str(COPY/'server/target/iam-server.jar'),'stopped':False};resources['processes'].append(item);rp.write_text(json.dumps(resources,indent=2))
 import httpx
 for _ in range(100):
  try:
   r=httpx.get('http://127.0.0.1:'+str(port)+'/web-api/auth/csrf',timeout=2,trust_env=False)
   if r.status_code==200:break
  except Exception:pass
  if proc.poll() is not None:break
  time.sleep(.5)
 attrs=[]
 for header in r.headers.get_list('set-cookie'):
  c=SimpleCookie();c.load(header)
  for name,m in c.items():attrs.append({'name':name,'secure':bool(m['secure']),'httponly':bool(m['httponly']),'path':m['path'],'domain':m['domain'],'samesite':m['samesite']})
 log.emit('actual-java-production-cookie-attributes',status=r.status_code,actual=attrs,expected='__Host names, Secure, session HttpOnly, Path=/, no Domain, SameSite=Lax',limitation='HTTP loopback inspects actual Set-Cookie attributes only; no public TLS deployment or browser HTTPS acceptance claimed')
finally:
 if pg_stopped:pg('start')
 if proc is not None:
  if proc.poll() is None:proc.terminate();proc.wait(timeout=40)
  item['stopped']=True;item['exit_code']=proc.returncode;file.close();rp.write_text(json.dumps(resources,indent=2))
 api.close();log.close()
