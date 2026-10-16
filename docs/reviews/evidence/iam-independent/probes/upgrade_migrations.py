#!/usr/bin/env python3
import json,os,subprocess,zipfile,uuid
from environment import COPY,PRIVATE,EVIDENCE,JAVA,env_values,redact
from probe_client import db,Evidence
import bcrypt
log=Evidence('independent-upgrade-migrations');env=env_values();out=PRIVATE/'migration-boundary';out.mkdir()
with db('super') as c:
 assert c.execute("SELECT count(*) FROM pg_database WHERE datname='iam_upgrade'").fetchone()[0]==0
 c.execute('CREATE DATABASE iam_upgrade OWNER iam_migrate')
rp=EVIDENCE/'outputs/resources.json';resources=json.loads(rp.read_text());resources.setdefault('created_databases',[]).append({'name':'iam_upgrade','purpose':'independent V5->V11 migration','stopped':False});rp.write_text(json.dumps(resources,indent=2))
with zipfile.ZipFile(COPY/'server/target/iam-server.jar') as z:
 for name in z.namelist():
  if name.startswith('BOOT-INF/lib/') and name.endswith('.jar'):(out/name.rsplit('/',1)[-1]).write_bytes(z.read(name))
cp=str(out)+':'+str(out/'*')
subprocess.run([JAVA+'/bin/javac','-cp',cp,'-d',str(out),str(EVIDENCE/'probes/IndependentMigration.java')],check=True,capture_output=True)
def migrate(target):
 inp='\n'.join(['jdbc:postgresql://127.0.0.1:29132/iam_upgrade',env['IAM_PG_MIGRATE_USER'],env['IAM_PG_MIGRATE_PASSWORD'],str(COPY/'server/src/main/resources/db/migration'),target])+'\n'
 r=subprocess.run([JAVA+'/bin/java','-cp',cp,'IndependentMigration'],input=inp,text=True,capture_output=True,timeout=60)
 log.emit('flyway-to-'+target,status=r.returncode,output=redact(r.stdout[-5000:]),error=redact(r.stderr[-1500:]));assert r.returncode==0
try:
 migrate('5')
 uid=str(uuid.uuid4());hashed=bcrypt.hashpw(b'independent-upgrade-only',bcrypt.gensalt(4)).decode()
 with db('migrate',database='iam_upgrade') as c:
  c.execute("INSERT INTO iam.users(id,account,display_name,password_hash,auth_revision) VALUES (%s,'upgrade.audit','升级保留',%s,9)",(uid,hashed))
 migrate('11');migrate('11')
 with db('migrate',database='iam_upgrade') as c:
  row=c.execute('SELECT id::text,display_name,password_hash,auth_revision FROM iam.users WHERE id=%s',(uid,)).fetchone()
  versions=c.execute('SELECT version,success FROM iam.flyway_schema_history ORDER BY installed_rank').fetchall()
  log.emit('upgrade-and-idempotence-data',expected='UUID, display, password hash and auth revision preserved;11 migrations once',actual={'uuid_unchanged':row[0]==uid,'display_unchanged':row[1]=='升级保留','hash_unchanged':row[2]==hashed,'auth_revision':row[3],'versions':versions})
finally:log.close()
