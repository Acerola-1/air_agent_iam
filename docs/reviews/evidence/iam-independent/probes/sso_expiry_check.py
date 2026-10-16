#!/usr/bin/env python3
import base64,json,time
from probe_client import Api,Evidence,PRIVATE,ENV
log=Evidence('independent-sso-real-expiry');api=Api(log)
try:
 p=json.loads((PRIVATE/'sso-expiry-grant.json').read_text());age=time.time()-p.pop('created_epoch')
 if age<31:time.sleep(31-age)
 h={'Authorization':'Basic '+base64.b64encode(('air-agent-local:'+ENV['IAM_SSO_CLIENT_AGENT_SECRET']).encode()).decode()}
 log.emit('real-sso-age-greater-than-ttl',actual='wall-clock >31 seconds; nominal ticket TTL30 seconds')
 api.request('real-time-expired-sso-ticket','POST','/v1/internal/sso/exchange',p,headers=h,expected='401, no new access token')
finally:api.close();log.close()
