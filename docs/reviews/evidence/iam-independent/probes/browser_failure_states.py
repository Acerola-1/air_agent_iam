#!/usr/bin/env python3
import json,secrets,subprocess,time
from playwright.sync_api import sync_playwright
from environment import CONTAINER,NAMES,RUN_ID,EVIDENCE
from probe_client import BASE,ENV,Evidence,db
log=Evidence('browser-failure-states');images=EVIDENCE/'outputs/browser/failures';images.mkdir();stopped=False
resources=json.loads((EVIDENCE/'outputs/resources.json').read_text());assert NAMES['redis'] in resources['created_containers']
def owned_transition(action):
 d=json.loads(subprocess.check_output([CONTAINER,'inspect',NAMES['redis']],text=True))[0];assert d['configuration']['labels']['audit.run']==RUN_ID
 r=subprocess.run([CONTAINER,action,NAMES['redis']],capture_output=True,timeout=50);assert r.returncode==0
with sync_playwright() as p:
 b=p.chromium.launch(executable_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',headless=True);c=b.new_context(viewport={'width':1440,'height':1000},locale='zh-CN');page=c.new_page();page.set_default_timeout(10000)
 try:
  page.goto(BASE+'/admin/platform/users');page.get_by_placeholder('请输入账号',exact=True).fill(ENV['IAM_BOOTSTRAP_ACCOUNT']);page.get_by_placeholder('请输入密码',exact=True).fill(ENV['IAM_BOOTSTRAP_PASSWORD']);page.get_by_test_id('login-submit').click();page.get_by_role('button',name='新建用户',exact=True).wait_for()
  search=page.get_by_placeholder('按账号/显示名搜索');search.fill('nonexistent.audit.'+secrets.token_hex(8));page.get_by_role('button',name='搜索',exact=True).click();page.get_by_text('暂无用户',exact=True).wait_for()
  log.emit('real-db-empty-list',actual='暂无用户');page.screenshot(path=str(images/'empty.png'))
  search.fill(ENV['IAM_BOOTSTRAP_ACCOUNT']);owned_transition('stop');stopped=True
  with page.expect_response(lambda r:'/web-api/admin/users' in r.url) as ev:page.get_by_role('button',name='搜索',exact=True).click()
  page.locator('.el-alert--error').wait_for();log.emit('real-redis-outage-browser-load-error',status=ev.value.status,actual={'alert':page.locator('.el-alert--error').inner_text(),'url':page.url},expected='503, Chinese failure, no false success or anonymous fallback');page.screenshot(path=str(images/'dependency503.png'))
  owned_transition('start');stopped=False
  for _ in range(30):
   with page.expect_response(lambda r:'/web-api/admin/users' in r.url) as ev:page.get_by_role('button',name='搜索',exact=True).click()
   if ev.value.status==200:break
   page.wait_for_timeout(300)
  page.get_by_text(ENV['IAM_BOOTSTRAP_ACCOUNT'],exact=True).first.wait_for();log.emit('real-browser-recovery-retry',status=ev.value.status);page.screenshot(path=str(images/'recovered.png'))
  # Expire exactly the page's own synthetic browser handle session in this isolated DB.
  identity=page.evaluate('''() => document.querySelector('#app').__vue_app__.config.globalProperties.$pinia._s.get('auth').identity.session.id''')
  with db('migrate') as conn:conn.execute("UPDATE iam.auth_sessions SET expires_at=now()-interval '1 second',idle_expires_at=now()-interval '1 second' WHERE id=%s",(identity,))
  page.reload();page.wait_for_url('**/login**');log.emit('real-expired-session-browser-refresh',actual=page.url);page.screenshot(path=str(images/'expired-login.png'))
 except Exception as e:log.emit('browser-failure-state-interrupted',error=str(e).split('Call log:')[0][:400]);raise
 finally:
  if stopped:owned_transition('start')
  c.close();b.close();log.close()
