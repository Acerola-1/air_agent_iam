#!/usr/bin/env python3
import time
from probe_client import Api,Evidence,db
log=Evidence('independent-renew-transaction-order');api=Api(log)
try:
 t,i=api.login('renew-order-fresh-session');sid=i['session']['id'];version=i['context_version'];uid=i['user']['id']
 with db(autocommit=False) as older:
  older.execute('SELECT iam_auth.set_request_context(%s,NULL,false)',(uid,))
  old_start=older.execute('SELECT now()').fetchone()[0]
  time.sleep(.08)
  with db() as newer:
   with newer.transaction():
    newer.execute('SELECT iam_auth.set_request_context(%s,NULL,false)',(uid,))
    new_idle=newer.execute('SELECT idle_expires_at FROM iam_auth.renew_session(%s,%s,604800)',(sid,version)).fetchone()[0]
  late_idle=older.execute('SELECT idle_expires_at FROM iam_auth.renew_session(%s,%s,604800)',(sid,version)).fetchone()[0];older.commit()
 log.emit('real-nonowner-renew-transaction-order',expected='last commit must not reduce a previously committed idle deadline',actual={'older_transaction_started':old_start,'newer_committed_idle':new_idle,'older_late_commit_idle':late_idle,'deadline_regressed':late_idle<new_idle,'regression_ms':(new_idle-late_idle).total_seconds()*1000},boundary='Two genuine iam_app transactions calling product renewal function; no manually forged expiry, no claimed HTTP scheduling guarantee')
 api.request('renew-order-current-session-after','GET','/v1/auth/me',token=t,expected='200 with last committed deadline')
finally:api.close();log.close()
