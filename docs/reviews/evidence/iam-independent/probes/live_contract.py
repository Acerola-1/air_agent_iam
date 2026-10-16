#!/usr/bin/env python3
import json
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
from probe_client import Api,Evidence,PRIVATE,EVIDENCE
api=Api(Evidence('independent-live-contract'));log=api.evidence;f=json.loads((PRIVATE/'fixtures.json').read_text())
root=EVIDENCE.parents[3]
try:
 schema=json.loads((root/'contracts/schemas/identity.schema.json').read_text());validator=Draft202012Validator(schema,format_checker=FormatChecker())
 t,i=api.login('contract-real-human')
 errors=[{'path':'/'.join(map(str,e.path)),'message':e.message} for e in validator.iter_errors(i)]
 log.emit('actual-login-identity-frozen-schema',expected='no errors',actual=errors)
 du=f['users']['dual'];dt,di=api.login('contract-dual',du['account'],du['password'])
 r,one=api.request('revision-string-type','POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants']['a']['id'],'expected_ctx_version':str(di['context_version'])},token=dt,expected='400; do not coerce string to integer')
 api.request('revision-bool-type','POST','/v1/auth/renew',{'expected_ctx_version':True},token=dt,expected='400; do not coerce bool')
 api.request('internal-illegal-json','POST','/v1/internal/identity/introspect',{'subject_token':dt,'audience':'langgraph-runtime','include_execution_context':'true'},internal=True,expected='400; do not coerce string boolean')
 # Review the entire contracts tree through structured decoding; preserve inventory, no secrets.
 import yaml,hashlib
 inventory=[]
 for p in sorted((root/'contracts').rglob('*')):
  if not p.is_file() or '__pycache__' in p.parts:continue
  text=p.read_text();item={'path':str(p.relative_to(root)),'sha256':hashlib.sha256(text.encode()).hexdigest()}
  if p.suffix=='.json':
   d=json.loads(text);item['top_level_keys']=list(d.keys());item['required']=d.get('required',[])
  elif p.suffix in ['.yaml','.yml']:
   d=yaml.safe_load(text);item['version']=d.get('info',{}).get('version');item['paths']=list(d.get('paths',{}))
  inventory.append(item)
 log.emit('all-contract-inputs-decoded',actual=inventory)
finally:api.close();log.close()
