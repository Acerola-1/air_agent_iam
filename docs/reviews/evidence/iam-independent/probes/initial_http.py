#!/usr/bin/env python3
from probe_client import Api, Evidence, ENV, cache, db, digest

log = Evidence('independent-initial-http')
api = Api(log)
try:
    with db('app') as connection:
        rows = connection.execute("SELECT current_user, r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole FROM pg_roles r WHERE rolname=current_user").fetchall()
        owners = connection.execute("SELECT n.nspname,c.relname,pg_get_userbyid(c.relowner),c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='iam' AND c.relkind='r' ORDER BY c.relname").fetchall()
        log.emit('runtime-nonowner-role', expected='non-superuser/nonBYPASS/nonowner for request role', role=rows, tables=owners)
    with db('migrate') as connection:
        migrations = connection.execute('SELECT installed_rank,version,description,success FROM iam.flyway_schema_history ORDER BY installed_rank').fetchall()
        log.emit('new-empty-database-migrations', expected='all V1–V11 applied successfully to new iam database', actual=migrations)
    api.request('no-token-me', 'GET', '/v1/auth/me', expected='401')
    api.request('garbage-token-me', 'GET', '/v1/auth/me', token='not-a-session', expected='401')
    api.request('unknown-account-login', 'POST', '/v1/auth/login', {'account':'audit.no-such-account','password':'synthetic-invalid-only','realm':'workforce','audience':'iam-admin'}, expected='401; same generic account/password error')
    token, identity = api.login('platform-login-positive')
    api.request('platform-me-positive', 'GET', '/v1/auth/me', token=token, expected='200 active=true')
    api.introspect('introspection-positive', token, expected='active=true; requested audience correctly bounded')
    api.introspect('introspection-unregistered-audience', token, audience='unregistered-audit-audience', expected='403')
    api.request('human-token-not-internal-client', 'POST', '/v1/internal/identity/introspect', {'subject_token': token,'audience':'langgraph-runtime'}, token=token, expected='401')
    redis = cache()
    key = 'Authorization:login:token:' + digest(token)
    old_value = redis.get(key)
    ttl = redis.pttl(key)
    if old_value is None:
        raise RuntimeError('Expected exact Sa-Token key is absent; do not broaden deletion')
    log.emit('redis-loss-positive-control', key_value_present=True, key_name='[REDACTED]', ttl_ms=ttl)
    redis.delete(key)
    api.request('redis-session-loss-me', 'GET', '/v1/auth/me', token=token, expected='401; Redis missing session fails closed')
    response, body = api.introspect('redis-session-loss-introspection', token, expected='inactive or error; must not accept missing Redis session')
    log.emit('redis-missing-authority-divergence', expected='both user and internal paths reject absent Redis session', actual={'introspection_status': response.status_code,'introspection_active': body.get('active')})
    redis.set(key, old_value, px=ttl)
    api.request('redis-restored-before-revocation-positive', 'GET', '/v1/auth/me', token=token, expected='200; unretracted synthetic session control')
    api.request('logout-commit', 'POST', '/v1/auth/logout', token=token, expected='204')
    api.introspect('first-introspection-after-logout', token, expected='active=false immediately after logout transaction commit')
    redis.set(key, old_value, px=ttl)
    api.request('stale-redis-replay-me', 'GET', '/v1/auth/me', token=token, expected='401; PG revocation overrides old Redis snapshot')
    api.introspect('stale-redis-replay-introspection', token, expected='active=false; PG revocation overrides old Redis snapshot')
    redis.delete(key)
    response, csrf = api.request('browser-csrf-handle', 'GET', '/web-api/auth/csrf', expected='200; anonymous handle and CSRF')
    cookie_metadata = [{ 'name':c.name, 'domain':c.domain, 'path':c.path, 'secure':c.secure,
                          'domain_specified':c.domain_specified, 'httponly':c.has_nonstandard_attr('HttpOnly'),
                          'samesite':c.get_nonstandard_attr('SameSite')} for c in api.client.cookies.jar]
    log.emit('dev-cookie-attributes', expected='host-only, HttpOnly session, SameSite=Lax, no __Host- prefix over HTTP', cookies=cookie_metadata)
    login_body={'account':ENV['IAM_BOOTSTRAP_ACCOUNT'],'password':ENV['IAM_BOOTSTRAP_PASSWORD'],'realm':'workforce'}
    api.request('browser-login-missing-csrf', 'POST', '/web-api/auth/login', login_body, headers={'Origin':'http://127.0.0.1:29100'}, expected='403')
    api.request('browser-login-evil-origin', 'POST', '/web-api/auth/login', login_body, headers={'Origin':'https://audit-invalid.example','X-CSRF-Token':csrf['csrf_token']}, expected='403')
    response, browser_login=api.request('browser-adapter-login-positive', 'POST', '/web-api/auth/login', login_body, headers={'Origin':'http://127.0.0.1:29100','X-CSRF-Token':csrf['csrf_token']}, expected='200 identity; no human bearer')
    assert response.status_code == 200
    csrf_value = api.client.cookies.get('air_iam_dev_csrf')
    headers = {'Origin':'http://127.0.0.1:29100','X-CSRF-Token':csrf_value}
    api.request('browser-adapter-renew-ui-body', 'POST', '/web-api/auth/renew', {}, headers=headers, expected='frontend sends {}; observe whether user renew flow works')
    api.request('browser-adapter-renew-explicit-cas-control', 'POST', '/web-api/auth/renew', {'expected_ctx_version':browser_login['identity']['context_version']}, headers=headers, expected='200 with mandatory expected_ctx_version supplied')
    api.request('browser-authorisation-injection', 'GET', '/web-api/auth/me', headers={'Authorization':'Bearer not-allowed-here'}, expected='403')
    api.request('browser-internal-proxy-denied', 'POST', '/web-api/internal/identity/introspect', {'audience':'langgraph-runtime'}, headers=headers, expected='not a functioning internal proxy')
    for path in ['/admin/tenant/departments','/web-api/not-found','/v1/not-found','/assets/no-such-audit-file.js']:
        api.request('static-route-' + path, 'GET', path, expected='SPA HTML only for frontend route; no HTML for unknown API or missing JS')
finally:
    api.close()
    log.close()
