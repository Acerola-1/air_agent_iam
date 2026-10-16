#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from environment import COPY, EVIDENCE, JAVA, PRIVATE
from probe_client import ENV, Evidence

sys.dont_write_bytecode = True
sys.path.insert(0,str(PRIVATE/'reference'))
import agent_security
import agent_ticket

log=Evidence('independent-rt-cross-consumer')
export=PRIVATE/'java-probes/export'
export.mkdir()
jar=COPY/'server/target/iam-server.jar'
with zipfile.ZipFile(jar) as archive:
    classes=[]
    for name in archive.namelist():
        if name.startswith('BOOT-INF/classes/com/airagent/iam/security/rt/') and name.endswith('.class'):
            relative=Path(name.removeprefix('BOOT-INF/classes/'))
            assert '..' not in relative.parts
            path=export/relative
            path.parent.mkdir(parents=True,exist_ok=True)
            data=archive.read(name)
            path.write_bytes(data)
            classes.append({'jar_entry':name,'sha256':hashlib.sha256(data).hexdigest()})
log.emit('actual-built-library-boundary',jar_file_sha256=hashlib.sha256(jar.read_bytes()).hexdigest(),classes=classes)
source=EVIDENCE/'probes/IndependentRtBoundary.java'
subprocess.run([JAVA+'/bin/javac','-cp',str(export),'-d',str(export),str(source)],check=True,capture_output=True)
secret=ENV['IAM_RT_KEYS_SECRET']
kid=ENV['IAM_RT_KEYS_KID']
now=int(time.time())
aud='langgraph-runtime'

def java(mode,token='',audience=aud,at=now,keyid=kid,keysecret=secret):
    stdin='\n'.join([mode,keyid,keysecret,audience,str(at),token])+'\n'
    result=subprocess.run([JAVA+'/bin/java','-cp',str(export),'IndependentRtBoundary'],input=stdin,text=True,capture_output=True,check=True)
    return result.stdout.strip() if mode=='sign' else json.loads(result.stdout)

def python_verify(token,keys=None,audience=aud,at=now):
    try:
        claims=agent_ticket.verify_ticket(token,keys or [(kid,secret)],expected_audience=audience,now=at)
        return {'ok':True,'audience':claims.audience,'ctx_version':claims.session_ctx_version}
    except agent_ticket.TicketError as error:
        return {'ok':False,'reason':str(error)}

jtoken=java('sign')
python_ticket=agent_security.RuntimeTicket(
    session_id='95b48e1e-7c1d-46fd-b1d7-cfb04b31ac01',user_id='95b48e1e-7c1d-46fd-b1d7-cfb04b31ac02',
    tenant_id='95b48e1e-7c1d-46fd-b1d7-cfb04b31ac03',membership_id='95b48e1e-7c1d-46fd-b1d7-cfb04b31ac04',
    audience=aud,issued_at=now,expires_at=now+60,session_ctx_version=3,user_auth_revision=5,
    tenant_auth_revision=7,membership_revision=11,kid=kid)
ptoken=agent_security.sign_runtime_ticket(python_ticket,[(kid,secret)])
log.emit('java-self-positive',expected='accepted',actual=java('verify',jtoken))
log.emit('real-python-self-positive',expected='accepted',actual=python_verify(ptoken))
log.emit('java-to-real-python',expected='accepted rt-v1 backward-compatible token',actual=python_verify(jtoken),token_segments=len(jtoken.split('.')))
log.emit('real-python-to-java',expected='accepted rt-v1 backward-compatible token',actual=java('verify',ptoken),token_segments=len(ptoken.split('.')))
log.emit('java-wrong-audience',expected='rejected',actual=java('verify',jtoken,audience='wrong-audience'))
log.emit('python-wrong-audience',expected='rejected',actual=python_verify(ptoken,audience='wrong-audience'))
log.emit('java-expired-at-boundary',expected='rejected',actual=java('verify',jtoken,at=now+60))
log.emit('python-expired-at-boundary',expected='rejected',actual=python_verify(ptoken,at=now+60))
for label,token,verify in [('java',jtoken,lambda t:java('verify',t)),('python',ptoken,python_verify)]:
    pieces=token.split('.')
    pieces[-1]=('A' if pieces[-1][0]!='A' else 'B')+pieces[-1][1:]
    log.emit(label+'-tampered-signature',expected='rejected',actual=verify('.'.join(pieces)))
log.emit('java-unknown-kid',expected='rejected',actual=java('verify',jtoken,keyid='retired-key'))
log.emit('python-rotation-old-key-retained',expected='accepted original kid despite new key first',actual=python_verify(ptoken,keys=[('new-audit-key','synthetic-new-key-for-rotation'),(kid,secret)]))
log.emit('python-rotation-old-key-removed',expected='rejected',actual=python_verify(ptoken,keys=[('new-audit-key','synthetic-new-key-for-rotation')]))
jparts=jtoken.split('.')
pparts=ptoken.split('.')
def signature_matches(text,signature):
    actual=base64.urlsafe_b64decode(signature+'='*(-len(signature)%4))
    return hmac.compare_digest(hmac.new(secret.encode(),text.encode('ascii'),hashlib.sha256).digest(),actual)
log.emit('raw-signature-input-comparison',expected='original rt-v1 signs original base64url body text, two segments',actual={
    'java_segment_count':len(jparts),'java_signs_header_dot_payload':signature_matches('.'.join(jparts[:2]),jparts[2]),
    'python_segment_count':len(pparts),'python_signs_original_body_text':signature_matches(pparts[0],pparts[1]),
    'python_envelope_keys':list(json.loads(base64.urlsafe_b64decode(pparts[0]+'='*(-len(pparts[0])%4))).keys()),
    'java_header_keys':list(json.loads(base64.urlsafe_b64decode(jparts[0]+'='*(-len(jparts[0])%4))).keys())})
log.close()
