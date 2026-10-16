#!/usr/bin/env python3
import base64
import hashlib
import subprocess
import zipfile
from environment import COPY,EVIDENCE,JAVA,PRIVATE
from probe_client import Evidence
import bcrypt
log=Evidence('independent-bcrypt-fixed-vectors')
export=PRIVATE/'java-bcrypt-boundary';export.mkdir()
jar=COPY/'server/target/iam-server.jar'
with zipfile.ZipFile(jar) as z:
    for name in ['BOOT-INF/classes/com/airagent/iam/security/password/PasswordHasher.class',
                 'BOOT-INF/classes/com/airagent/iam/web/error/ApiException.class']:
        out=export/name.removeprefix('BOOT-INF/classes/');out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(z.read(name))
    dependency=next(n for n in z.namelist() if n.startswith('BOOT-INF/lib/spring-security-crypto-') and n.endswith('.jar'))
    dep=export/'crypto.jar';data=z.read(dependency);dep.write_bytes(data)
    log.emit('actual-compiled-library',jar_sha256=hashlib.sha256(jar.read_bytes()).hexdigest(),dependency=dependency,dependency_sha256=hashlib.sha256(data).hexdigest(),python_bcrypt_version=bcrypt.__version__)
cp=str(export)+':'+str(dep)
subprocess.run([JAVA+'/bin/javac','-cp',cp,'-d',str(export),str(EVIDENCE/'probes/IndependentBcrypt.java')],capture_output=True,check=True)
def java(mode,password,hashed=''):
    result=subprocess.run([JAVA+'/bin/java','-cp',cp,'IndependentBcrypt'],text=True,input=mode+'\n'+base64.b64encode(password.encode()).decode()+'\n'+hashed+'\n',capture_output=True,check=True)
    return result.stdout.strip()
# Fixed synthetic salt retained in probe only; no resulting password hashes in evidence.
salt=b'$2b$04$......................'
vectors=[('ascii','Independent-Only-123!'),('chinese','中文固定向量123!'),('bytes71','x'*71),('bytes72','x'*72),('bytes73','x'*73),('multibyte-split','a'*71+'中')]
try:
    for label,p in vectors:
        raw=p.encode()[:72];ph=bcrypt.hashpw(raw,salt).decode()
        variants=[ph,ph.replace('$2b$','$2a$'),ph.replace('$2b$','$2y$')]
        results=[java('check',p,h)=='true' for h in variants]
        jh=java('hash',p)
        log.emit(label,expected='both directions accept; wrong password rejects; 2a/2b/2y match',actual={
            'python_fixed_to_java_prefixes':dict(zip(['2b','2a','2y'],results)),
            'java_to_python':bcrypt.checkpw(raw,jh.encode()),'wrong_password_java':java('check','wrong-control',ph)=='true',
            'wrong_password_python':bcrypt.checkpw(b'wrong-control',jh.encode()),'utf8_length':len(p.encode())})
    for label,h in [('malformed','invalid'),('empty',''),('bad-cost','$2b$xx$......................broken')]:
        log.emit('invalid-hash-'+label,expected=False,actual=java('check','Independent-Only-123!',h)=='true')
finally:log.close()
