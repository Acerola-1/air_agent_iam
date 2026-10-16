import sys,json,time,uuid,threading,concurrent.futures
from datetime import datetime,timezone
sys.dont_write_bytecode=True
from runtime import PRIVATE,OUT,env_values
import psycopg,httpx,bcrypt
ENV=env_values();f=json.loads((PRIVATE/'http-fixtures.json').read_text());results={}
def connect(owner=False):
 return psycopg.connect(host='127.0.0.1',port=29132,dbname='iam_remediation',user=ENV['IAM_PG_MIGRATE_USER'] if owner else ENV['IAM_PG_APP_USER'],password=ENV['IAM_PG_MIGRATE_PASSWORD'] if owner else ENV['IAM_PG_APP_PASSWORD'])
# Older transaction starts before a newer HTTP renewal, then renews after it commits.
with connect() as older:
 started=older.execute('SELECT now()').fetchone()[0]
 time.sleep(.15)
 response=httpx.post('http://127.0.0.1:29107/v1/auth/renew',headers={'Authorization':'Bearer '+f['token']},json={'expected_ctx_version':4},timeout=5,trust_env=False);assert response.status_code==200
 newer=datetime.fromisoformat(response.json()['idle_expires_at'].replace('Z','+00:00'))
 row=older.execute('SELECT * FROM iam_auth.renew_session(%s,%s,%s)',(f['identity']['session']['id'],4,604800)).fetchone();older.commit();final=row[1]
 assert final>=newer and final<=row[0]
 results['older_transaction_renewal']={'request_role':ENV['IAM_PG_APP_USER'],'transaction_started_before_newer_deadline':started.isoformat(),'deadline_regression_ms':max(0,(newer-final).total_seconds()*1000),'absolute_bound_preserved':final<=row[0],'passed':True}
# Dedicated synthetic platform administrators. Existing grants are restored in finally.
role=uuid.UUID('01930000-0000-4000-8000-000000000301');ids=[uuid.uuid4(),uuid.uuid4()];stash=[]
try:
 with connect(True) as setup:
  setup.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)')
  stash=setup.execute('SELECT user_id,role_id,granted_by FROM iam.user_roles WHERE role_id=%s',(role,)).fetchall()
  digest=bcrypt.hashpw(uuid.uuid4().hex.encode(),bcrypt.gensalt(rounds=10,prefix=b'2b')).decode()
  for index,id_ in enumerate(ids):
   setup.execute('INSERT INTO iam.users(id,account,display_name,password_hash) VALUES(%s,%s,%s,%s)',(id_,'race-'+id_.hex,'隔离并发管理员'+str(index),digest))
   setup.execute('INSERT INTO iam.user_roles(user_id,role_id,granted_by) VALUES(%s,%s,%s)',(id_,role,id_))
  for user_id,role_id,actor in stash:setup.execute('DELETE FROM iam.user_roles WHERE user_id=%s AND role_id=%s',(user_id,role_id))
 gate=threading.Barrier(2)
 def disable(id_):
  with connect() as con:
   con.execute('SELECT iam_auth.set_request_context(%s,NULL,true)',(id_,));gate.wait(timeout=5)
   try:con.execute("UPDATE iam.users SET status='disabled' WHERE id=%s",(id_,));con.commit();return {'committed':True}
   except psycopg.Error as error:con.rollback();return {'committed':False,'sqlstate':error.sqlstate}
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:outcomes=list(pool.map(disable,ids))
 with connect(True) as inspect:
  count=inspect.execute("SELECT count(DISTINCT u.id) FROM iam.users u JOIN iam.user_roles ur ON ur.user_id=u.id JOIN iam.roles r ON r.id=ur.role_id WHERE u.status='active' AND r.code='platform_super_admin'").fetchone()[0]
 assert count==1 and sum(v['committed'] for v in outcomes)==1
 results['two_nonowner_disable_transactions']={'request_role':ENV['IAM_PG_APP_USER'],'outcomes':outcomes,'final_effective_platform_admins':count,'fixture_boundary':'temporarily replaced grants only in own iam_remediation; existing grants restored','passed':True}
finally:
 with connect(True) as restore:
  restore.execute('SELECT iam_auth.set_request_context(NULL,NULL,true)')
  for user_id,role_id,actor in stash:restore.execute('INSERT INTO iam.user_roles(user_id,role_id,granted_by) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING',(user_id,role_id,actor))
  for id_ in ids:
   restore.execute('DELETE FROM iam.user_roles WHERE user_id=%s',(id_,));restore.execute('DELETE FROM iam.users WHERE id=%s',(id_,))
 results['original_grants_restored']=True
(OUT/'real-database-races-delivery.json').write_text(json.dumps(results,ensure_ascii=False,indent=2));print(json.dumps(results,ensure_ascii=False,indent=2))
