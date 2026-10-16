"""Own isolated remediation runtime; never imports the user's .env.local."""
import sys,os,json,subprocess,time,socket,hashlib
from pathlib import Path
ROOT=Path('/Users/acerola/Dev/Java/air_agent_iam')
sys.path.insert(0,str(ROOT/'docs/reviews/evidence/iam-independent/probes'))
from environment import env_values,redact,JAVA
PRIVATE=Path('/tmp/iam-remediation-20261015-ugpg7l0a')
OUT=ROOT/'docs/reviews/evidence/iam-remediation'
PORT=29107

def start(package=True):
    manifest=OUT/'runtime-resources.json'
    if manifest.exists():raise RuntimeError('Runtime manifest exists; inspect before restarting')
    with socket.socket() as sock:sock.bind(('127.0.0.1',PORT))
    env={**os.environ,**env_values(),'JAVA_HOME':JAVA,'MAVEN_USER_HOME':'/tmp/iam-independent-20261015-5ohAEo/maven-home',
         'IAM_HTTP_PORT':str(PORT),'IAM_PG_DB':'iam_remediation','IAM_REDIS_DB':'2','IAM_RATE_LIMIT_ENABLED':'false',
         'IAM_WEB_ALLOWED_ORIGINS':f'http://127.0.0.1:{PORT}', 'IAM_WEB_CENTRAL_BASE_URL':f'http://127.0.0.1:{PORT}',
         'IAM_WEB_STATIC_LOCATIONS':'file:'+str(ROOT/'web/dist')+'/,classpath:/static/',
         'IAM_SSO_CLIENT_AGENT_CALLBACK':f'http://127.0.0.1:{PORT}/web-api/sso/callback/agent',
         'IAM_SSO_CLIENT_KB_CALLBACK':f'http://127.0.0.1:{PORT}/web-api/sso/callback/kb',
         'IAM_SSO_CLIENT_AGENT_ORIGINS':f'http://127.0.0.1:{PORT}',
         'IAM_SSO_CLIENT_KB_ORIGINS':f'http://127.0.0.1:{PORT}'}
    build=PRIVATE/'server';cmd=['./mvnw','-B','-ntp','-Dmaven.repo.local=/tmp/iam-independent-20261015-5ohAEo/m2-clean','-DskipTests','package']
    if package:
        start=time.monotonic();r=subprocess.run(cmd,cwd=build,env=env,text=True,capture_output=True)
        with (OUT/'runtime-package.json').open('x') as f:json.dump({'command':cmd,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start,'stdout':redact(r.stdout),'stderr':redact(r.stderr)},f,ensure_ascii=False,indent=2)
        if r.returncode:print(redact((r.stdout+r.stderr)[-1800:]));raise RuntimeError('Package failed')
    log=PRIVATE/('runtime-'+str(time.time_ns())+'.log');fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    jar=build/'target/iam-server.jar'
    process=subprocess.Popen([JAVA+'/bin/java','-Xms128m','-Xmx768m','-jar',str(jar)],cwd=PRIVATE,env=env,stdin=subprocess.DEVNULL,stdout=fd,stderr=subprocess.STDOUT,start_new_session=True);os.close(fd)
    record={'pid':process.pid,'jar':str(jar),'jar_sha256':hashlib.sha256(jar.read_bytes()).hexdigest(),'http_port':PORT,
            'postgres_port':29132,'database':'iam_remediation','redis_port':29179,'redis_database':2,'private_log':str(log),'status':'starting',
            'rate_limit':'disabled only for independent counterexample/performance probes; production default remains enabled'}
    manifest.write_text(json.dumps(record,ensure_ascii=False,indent=2))
    import httpx
    for _ in range(100):
        if process.poll() is not None:raise RuntimeError('Runtime exited; inspect private log with redaction')
        try:
            response=httpx.get(f'http://127.0.0.1:{PORT}/healthz',timeout=1,trust_env=False)
            if response.status_code==200 and response.json()['status']=='ok':
                record['status']='running';record['health']=response.json();manifest.write_text(json.dumps(record,ensure_ascii=False,indent=2));print('Remediation runtime ready on',PORT,'pid',process.pid);return
        except (httpx.HTTPError,ValueError,KeyError):pass
        time.sleep(.4)
    raise RuntimeError('Health did not become ready; process remains registered')
if __name__=='__main__':start(package='--reuse-built-jar' not in sys.argv)
