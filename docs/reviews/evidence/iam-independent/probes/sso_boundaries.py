#!/usr/bin/env python3
import base64
import secrets
from urllib.parse import urlparse,parse_qs,urlencode
import httpx
from probe_client import Api,Evidence,BASE,ENV,safe
log=Evidence('independent-sso-boundaries');api=Api(log)
def get(case,url,expect=None):
    r=api.client.get(url)
    log.emit(case,path=urlparse(url).path,expected=expect,status=r.status_code,
        location_path=urlparse(r.headers.get('location','')).path,cookie_names=list(r.cookies.keys()))
    return r
def grant(key):
    r=get('sso-login-start-'+key,'/web-api/sso/callback/'+key+'/login','303')
    r=get('sso-central-authorize-'+key,r.headers['location'],'303 exact registered callback')
    q=parse_qs(urlparse(r.headers['location']).query)
    return r.headers['location'],q
def exchange(case,key,q,redirect=None):
    cid={'agent':'air-agent-local','kb':'knowledge-local'}[key]
    secret=ENV['IAM_SSO_CLIENT_'+key.upper()+'_SECRET']
    h={'Authorization':'Basic '+base64.b64encode((cid+':'+secret).encode()).decode()}
    body={'ticket':q['ticket'][0],'state':q['state'][0],'redirect_uri':redirect or ENV['IAM_SSO_CLIENT_'+key.upper()+'_CALLBACK']}
    return api.request(case,'POST','/v1/internal/sso/exchange',body,headers=h)
try:
    _,csrf=api.request('sso-browser-csrf','GET','/web-api/auth/csrf')
    _,b=api.request('sso-central-login','POST','/web-api/auth/login',{'account':ENV['IAM_BOOTSTRAP_ACCOUNT'],'password':ENV['IAM_BOOTSTRAP_PASSWORD'],'realm':'workforce'},headers={'Origin':BASE,'X-CSRF-Token':csrf['csrf_token']},expected='200')
    h={'Origin':BASE,'X-CSRF-Token':api.client.cookies.get('air_iam_dev_csrf')}
    for key in ['agent','kb']:
        location,q=grant(key)
        get('sso-browser-callback-'+key,location,'303 clean URL, server exchange only')
        api.request('sso-bff-identity-'+key,'GET','/web-api/sso/callback/'+key+'/me',expected='200 corresponding audience, shared session context')
        get('sso-callback-replay-'+key,location,'303 error, no new successful exchange')
    # White list, state binding, cross-client, one-time consume.
    api.request('sso-unregistered-callback','GET','/web-api/sso/start?'+urlencode({'client_id':'air-agent-local','redirect_uri':'http://127.0.0.1:29100/evil','state':secrets.token_hex(16)}),expected='400')
    location,q=grant('agent')
    get('sso-wrong-state-callback',location.replace(q['state'][0],secrets.token_hex(24)),'state_mismatch before exchange')
    exchange('sso-wrong-exchange-callback','agent',q,BASE+'/unregistered')
    exchange('sso-wrong-exchange-client','kb',q)
    exchange('sso-valid-exchange-positive','agent',q)
    exchange('sso-exchange-replay','agent',q)
    # Recheck originally authenticated app cookies after central current-session logout.
    api.request('sso-central-current-logout','POST','/web-api/auth/logout',{},headers=h,expected='204')
    for key in ['agent','kb']:
        api.request('sso-bff-after-central-logout-'+key,'GET','/web-api/sso/callback/'+key+'/me',expected='401; next protected request must reject shared session logout')
finally:api.close();log.close()
