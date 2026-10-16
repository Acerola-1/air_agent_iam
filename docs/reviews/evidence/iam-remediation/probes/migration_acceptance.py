import sys,json,subprocess,uuid,hashlib
from pathlib import Path
sys.dont_write_bytecode=True
from runtime import ROOT,PRIVATE,OUT,JAVA,env_values
import psycopg
from psycopg import sql
E=env_values();export=PRIVATE/'runtime-classpath';cp=str(export/'classes')+':'+str(export/'lib/*')
subprocess.run([JAVA+'/bin/javac','-cp',cp,'-d',str(export/'classes'),str(Path(__file__).with_name('MigrationBoundary.java'))],check=True,capture_output=True)
record={'databases':[],'original_migrations_unchanged':all((ROOT/'server/src/main/resources/db/migration'/p.name).read_bytes()==p.read_bytes() for p in Path('/tmp/iam-independent-20261015-5ohAEo/source/server/src/main/resources/db/migration').glob('*.sql'))}
def con(db,user='iam_migrate',autocommit=False):return psycopg.connect(host='127.0.0.1',port=29132,dbname=db,user=user,password=E['IAM_PG_MIGRATE_PASSWORD'],autocommit=autocommit)
def migrate(db,target):
 values='\n'.join([f'jdbc:postgresql://127.0.0.1:29132/{db}','iam_migrate',E['IAM_PG_MIGRATE_PASSWORD'],'filesystem:'+str(ROOT/'server/src/main/resources/db/migration')])+'\n'
 r=subprocess.run([JAVA+'/bin/java','-cp',cp,'MigrationBoundary',target],input=values,text=True,capture_output=True)
 if r.returncode:raise RuntimeError('Migration failed; return code '+str(r.returncode))
 assert 'MIGRATION_OK' in r.stdout
for name,target in [('iam_remediation_empty','latest'),('iam_remediation_upgrade','5')]:
 created=False;row={'database':name,'first_target':target}
 try:
  with con('postgres','postgres',True) as admin:
   assert not admin.execute('SELECT 1 FROM pg_database WHERE datname=%s',(name,)).fetchone()
   admin.execute(sql.SQL('CREATE DATABASE {} OWNER iam_migrate').format(sql.Identifier(name)));created=True
  with con(name) as c:
   c.execute('CREATE SCHEMA iam AUTHORIZATION iam_migrate');c.execute('CREATE SCHEMA iam_auth AUTHORIZATION iam_migrate')
   c.execute('GRANT USAGE ON SCHEMA iam,iam_auth TO iam_app')
   c.execute('ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO iam_app')
   c.execute('ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam GRANT USAGE,SELECT ON SEQUENCES TO iam_app')
   c.execute('ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam,iam_auth GRANT EXECUTE ON FUNCTIONS TO iam_app')
  migrate(name,target)
  if target=='5':
   id_=uuid.uuid4();opaqueHash='synthetic-upgrade-hash-not-a-login-credential'
   with con(name) as c:c.execute('INSERT INTO iam.users(id,account,display_name,password_hash) VALUES(%s,%s,%s,%s)',(id_,'migration-'+id_.hex,'升级保留标记',opaqueHash))
   migrate(name,'latest')
   with con(name) as c:
    preserved=c.execute('SELECT id,password_hash FROM iam.users WHERE id=%s',(id_,)).fetchone()
    assert preserved==(id_,opaqueHash)
   row['business_uuid_and_hash_preserved']=True
  migrate(name,'latest')
  with con(name) as c:
   versions=[v[0] for v in c.execute('SELECT version FROM iam.flyway_schema_history WHERE success AND version IS NOT NULL ORDER BY installed_rank')]
  assert versions==[str(i) for i in range(1,20)];row.update({'successful_versions':versions,'idempotent_rerun':True,'passed':True})
 finally:
  if created:
   with con('postgres','postgres',True) as admin:admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))
   row['own_database_removed']=True
 record['databases'].append(row);print(name,'passed',flush=True)
(OUT/'real-migration-acceptance.json').write_text(json.dumps(record,ensure_ascii=False,indent=2))
