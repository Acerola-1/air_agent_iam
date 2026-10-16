import sys,json,time,subprocess
sys.dont_write_bytecode=True
from runtime import ROOT,PRIVATE,OUT,env_values
import httpx,redis
ENV=env_values();BASE='http://127.0.0.1:29107';client=httpx.Client(base_url=BASE,timeout=5,trust_env=False);rows=[]
response=client.post('/v1/auth/login',json={'account':ENV['IAM_BOOTSTRAP_ACCOUNT'],'password':ENV['IAM_BOOTSTRAP_PASSWORD'],'realm':'workforce','audience':'iam-admin'});assert response.status_code==200;token=response.json()['access_token']
headers={'Authorization':'Bearer '+ENV['IAM_INTERNAL_RUNTIME_CLIENT_SECRET']};body={'subject_token':token,'audience':'langgraph-runtime'}
def check(case):
 start=time.perf_counter();r=client.post('/v1/internal/identity/introspect',headers=headers,json=body);elapsed=(time.perf_counter()-start)*1000
 row={'case':case,'status':r.status_code,'elapsed_ms':round(elapsed,3),'request_id_matches':r.json().get('error',{}).get('request_id')==r.headers.get('x-request-id') if r.status_code>=400 else True};rows.append(row);print(row,flush=True);return r
assert check('positive-before-fault').status_code==200
r=redis.Redis(host='127.0.0.1',port=29179,password=ENV['IAM_REDIS_PASSWORD'],db=2,socket_timeout=3)
r.client_pause(1200,all=True)
paused=check('Redis-paused-beyond-total-budget');assert paused.status_code==503 and rows[-1]['elapsed_ms']<500
# The server pause expires automatically; wait for actual recovery.
for _ in range(15):
 time.sleep(.15)
 if check('redis-recovery').status_code==200:break
else:raise AssertionError('Redis recovery failed')
container='/usr/local/bin/container';name='iam-independent-20261015-5ohaeo-pg';manifest=json.loads((ROOT/'docs/reviews/evidence/iam-independent/outputs/resources.json').read_text())
assert name in manifest['created_containers']
owned=json.loads(subprocess.check_output([container,'inspect',name],text=True))[0]
assert owned['configuration']['labels']['audit.run']=='iam-independent-20261015-5ohaeo'
try:
 subprocess.run([container,'stop',name],check=True,capture_output=True)
 check('PostgreSQL-stopped-first-request')
finally:
 subprocess.run([container,'start',name],check=True,capture_output=True)
for _ in range(25):
 time.sleep(.2)
 if check('postgres-recovery').status_code==200:break
else:raise AssertionError('PostgreSQL recovery failed')
(OUT/'real-dependency-failures-delivery.json').write_text(json.dumps({'rows':rows,'only_owned_container_stopped':name,'container_restarted':True},indent=2));client.close()
