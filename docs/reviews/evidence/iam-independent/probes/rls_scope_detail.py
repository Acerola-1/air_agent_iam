#!/usr/bin/env python3
"""Distinguish own-membership enumeration from forbidden cross-context business rows."""
import json
from probe_client import Evidence, PRIVATE, db
f=json.loads((PRIVATE/'fixtures.json').read_text())
log=Evidence('independent-rls-scope-detail')
try:
    with db() as c:
        for name,tid,uid in [('a','a','dual'),('b','b','dual'),('user-only',None,'dual'),('none',None,None)]:
            with c.transaction():
                c.execute('SELECT iam_auth.set_request_context(%s,%s,false)',
                    (f['users'][uid]['id'] if uid else None,f['tenants'][tid]['id'] if tid else None))
                rows=c.execute('SELECT tenant_id,code FROM iam.departments ORDER BY tenant_id,code').fetchall()
                log.emit('department-visibility-'+name,expected='current-tenant departments only; none without tenant context',actual=rows)
                grants=c.execute("SELECT has_column_privilege(current_user,'iam.users','password_hash','SELECT'),has_column_privilege(current_user,'iam.users','password_hash','UPDATE')").fetchone()
                log.emit('password-column-grants-'+name,expected=[False,False],actual=grants)
                count=c.execute('SELECT count(password_hash) FROM iam.users').fetchone()[0]
                log.emit('password-column-readable-count-'+name,expected='column access denied',actual=count)
finally: log.close()
