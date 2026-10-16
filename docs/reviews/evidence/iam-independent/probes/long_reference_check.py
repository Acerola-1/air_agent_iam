#!/usr/bin/env python3
import base64
import json
import time
from probe_client import Api,Evidence,PRIVATE,db
p=json.loads((PRIVATE/'long-ref-probe.json').read_text());log=Evidence('independent-long-reference-r2');api=Api(log)
try:
    age=int(time.time())-p['created_epoch']
    assert age>60,'Run only after entrance ticket lifetime; no artificial clock shortcut'
    h={'Authorization':'Basic '+base64.b64encode((p['client_id']+':'+p['client_secret']).encode()).decode()}
    log.emit('real-elapsed-time',expected='>60 seconds, original human session still active',actual=age)
    api.request('reference-after-sixty-seconds','POST','/v1/internal/identity/introspect',p['reference'],headers=h,expected='active=true context_matches=true')
    with db('migrate') as c:
        with c.transaction():
            c.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)')
            c.execute('UPDATE iam.auth_sessions SET ctx_version=ctx_version+1 WHERE id=%s',(p['session_id'],))
    api.request('reference-after-authoritative-ctx-revision','POST','/v1/internal/identity/introspect',p['reference'],headers=h,expected='active=false revision_mismatch')
finally:api.close();log.close()
