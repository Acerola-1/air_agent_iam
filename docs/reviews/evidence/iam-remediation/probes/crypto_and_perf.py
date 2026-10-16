import sys,json,time,subprocess,zipfile,hashlib,asyncio,statistics
from pathlib import Path
sys.dont_write_bytecode=True
from runtime import ROOT,PRIVATE,OUT,PORT,JAVA,env_values
import httpx
ENV=env_values();fixture=json.loads((PRIVATE/'http-fixtures.json').read_text());BASE=f'http://127.0.0.1:{PORT}'

def cross_language():
    manifest=json.loads((OUT/'runtime-resources.json').read_text());jar=Path(manifest['jar']);assert hashlib.sha256(jar.read_bytes()).hexdigest()==manifest['jar_sha256']
    export=PRIVATE/'runtime-classpath-connection-release';export.mkdir()
    with zipfile.ZipFile(jar) as archive:
        for name in archive.namelist():
            if name.startswith('BOOT-INF/classes/') and not name.endswith('/'):
                relative=Path(name.removeprefix('BOOT-INF/classes/'));assert '..' not in relative.parts
                p=export/'classes'/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(archive.read(name))
            elif name.startswith('BOOT-INF/lib/') and name.endswith('.jar'):
                p=export/'lib'/Path(name).name;p.parent.mkdir(exist_ok=True);p.write_bytes(archive.read(name))
    source=ROOT/'docs/reviews/evidence/iam-independent/probes/IndependentRtBoundary.java'
    cp=str(export/'classes')+':'+str(export/'lib/*')
    subprocess.run([JAVA+'/bin/javac','-cp',cp,'-d',str(export/'classes'),str(source)],check=True,capture_output=True)
    sys.path.insert(0,'/tmp/iam-independent-20261015-5ohAEo/reference');import agent_security,agent_ticket
    now=int(time.time());aud='langgraph-runtime';kid=ENV['IAM_RT_KEYS_KID'];secret=ENV['IAM_RT_KEYS_SECRET']
    def java(mode,token='',at=now,audience=aud):
        values='\n'.join([mode,kid,secret,audience,str(at),token])+'\n'
        r=subprocess.run([JAVA+'/bin/java','-cp',cp,'IndependentRtBoundary'],input=values,text=True,capture_output=True,check=True)
        return r.stdout.strip() if mode=='sign' else json.loads(r.stdout)
    j=java('sign');claims=agent_ticket.verify_ticket(j,[(kid,secret)],expected_audience=aud,now=now)
    original=agent_security.RuntimeTicket(session_id=claims.session_id,user_id=claims.user_id,tenant_id=claims.tenant_id,membership_id=claims.membership_id,audience=aud,issued_at=now,expires_at=now+60,session_ctx_version=3,user_auth_revision=5,tenant_auth_revision=7,membership_revision=11,kid=kid)
    py=agent_security.sign_runtime_ticket(original,[(kid,secret)])
    checked=java('verify',py);assert checked['ok']
    wrong=java('verify',py,audience='wrong');expired=java('verify',py,at=now+60)
    assert not wrong['ok'] and not expired['ok']
    record={'jar_sha256':manifest['jar_sha256'],'reference_files':[{'name':n,'sha256':hashlib.sha256(Path('/tmp/iam-independent-20261015-5ohAEo/reference',n).read_bytes()).hexdigest()} for n in ['agent_security.py','agent_ticket.py']],
        'java_to_original_python':True,'original_python_to_java':checked,'wrong_audience':wrong,'expiry_boundary':expired,'segments':2,'raw_tickets_and_keys':'not published'}
    (OUT/'original-cross-language-accepted-delivery.json').write_text(json.dumps(record,indent=2));print('Original cross-language acceptance passed',flush=True)

async def performance():
    token=fixture['token'];headers={'Authorization':'Bearer '+ENV['IAM_INTERNAL_RUNTIME_CLIENT_SECRET']};body={'subject_token':token,'audience':'langgraph-runtime'}
    async with httpx.AsyncClient(base_url=BASE,timeout=5,trust_env=False,limits=httpx.Limits(max_connections=40,max_keepalive_connections=40)) as client:
        for _ in range(30):
            response=await client.post('/v1/internal/identity/introspect',json=body,headers=headers);assert response.status_code==200
        expected=response.json();records=[]
        for concurrency in [1,10,30]:
            for round_ in range(1,4):
                semaphore=asyncio.Semaphore(concurrency)
                async def call(index):
                    async with semaphore:
                        start=time.perf_counter();r=await client.post('/v1/internal/identity/introspect',json=body,headers=headers);elapsed=(time.perf_counter()-start)*1000
                        p=r.json();valid=r.status_code==200 and p.get('active') is True and p.get('audience')==body['audience'] and p.get('session',{}).get('id')==expected['session']['id'] and set(p.get('permissions',[]))==set(expected['permissions'])
                        return {'index':index,'elapsed_ms':round(elapsed,3),'status':r.status_code,'authorization_matches':valid}
                values=await asyncio.gather(*(call(i) for i in range(100)));times=sorted(v['elapsed_ms'] for v in values)
                record={'concurrency':concurrency,'round':round_,'count':100,'p50_ms':statistics.median(times),'p95_ms':times[94],'p99_ms':times[98],'errors':sum(not v['authorization_matches'] for v in values),'samples':values}
                records.append(record);print('perf',concurrency,round_,record['p50_ms'],record['p95_ms'],record['errors'],flush=True)
    (OUT/'real-http-performance-delivery.json').write_text(json.dumps({'rate_limit':'disabled for isolated benchmark only','positive_authorization_checked':True,'rounds':records},indent=2))
if __name__=='__main__':cross_language();asyncio.run(performance())
