#!/usr/bin/env python3
import asyncio,json,secrets
from playwright.async_api import async_playwright
from probe_client import BASE,ENV,PRIVATE,EVIDENCE,Evidence,Api
f=json.loads((PRIVATE/'fixtures.json').read_text());log=Evidence('browser-response-races-r2');images=EVIDENCE/'outputs/browser/races-r2';images.mkdir()
async def main():
 async with async_playwright() as p:
  b=await p.chromium.launch(executable_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',headless=True)
  c=await b.new_context(viewport={'width':1440,'height':1000},locale='zh-CN');page=await c.new_page();page.set_default_timeout(10000)
  async def login(account,password):
   await page.get_by_placeholder('请输入账号',exact=True).fill(account);await page.get_by_placeholder('请输入密码',exact=True).fill(password);await page.get_by_test_id('login-submit').click();await page.locator('.header').wait_for()
  async def switch(name):
   await page.get_by_test_id('tenant-switcher').get_by_role('button').click();await page.get_by_role('menuitem',name=name,exact=False).click();await page.get_by_role('button',name='切换',exact=True).click();await page.get_by_test_id('ctx-tenant').filter(has_text=name).wait_for()
  try:
   await page.goto(BASE+'/profile');await login(f['users']['dual']['account'],f['users']['dual']['password'])
   await page.locator('label').filter(has_text='独立验收企业-A').click();await page.get_by_test_id('ctx-tenant').filter(has_text='企业-A').wait_for()
   await page.goto(BASE+'/admin/tenant/departments');await page.get_by_role('button',name='刷新',exact=True).wait_for()
   held=asyncio.Event();release=asyncio.Event();intercepted=False
   async def late_list(route):
    nonlocal intercepted
    if intercepted:await route.continue_();return
    intercepted=True;r=await route.fetch();held.set();await release.wait()
    try:await route.fulfill(response=r)
    except Exception:pass # AbortController may cancel the held original request legitimately.
   await page.route('**/web-api/admin/departments?*',late_list)
   await page.get_by_role('button',name='刷新',exact=True).click();await asyncio.wait_for(held.wait(),10)
   helper=Api(log);t,ident=helper.login('list-canary-login',f['users']['dual']['account'],f['users']['dual']['password'])
   helper.request('list-canary-select','POST','/v1/auth/switch-tenant',{'tenant_id':f['tenants']['a']['id'],'expected_ctx_version':ident['context_version']},token=t)
   marker='新A代次标记-'+secrets.token_hex(3)
   helper.request('list-canary-created-after-held-response','POST','/v1/admin/departments',{'code':'canary-'+secrets.token_hex(4),'name':marker},token=t);helper.close()
   await switch('独立验收企业-B');await switch('独立验收企业-A')
   await page.get_by_text(marker,exact=True).first.wait_for()
   await page.wait_for_timeout(150)
   before=await page.locator('.el-table__body-wrapper').first.inner_text();release.set();await page.wait_for_timeout(350)
   after=await page.locator('.el-table__body-wrapper').first.inner_text()
   log.emit('A-B-A-real-old-list-response',expected='old generation response discarded',actual={'table_unchanged':before==after,'new_generation_marker_retained':marker in after,'current_tenant':await page.get_by_test_id('ctx-tenant').inner_text()})
   await page.unroute('**/web-api/admin/departments?*');await page.screenshot(path=str(images/'aba-list.png'))
   # Hold a real committed switch response; logout and login another user before delivery.
   held2=asyncio.Event();release2=asyncio.Event()
   async def late_switch(route):
    r=await route.fetch();held2.set();await release2.wait();await route.fulfill(response=r)
   await page.route('**/web-api/auth/switch-tenant',late_switch)
   await page.get_by_test_id('tenant-switcher').get_by_role('button').click();await page.get_by_role('menuitem',name='独立验收企业-B',exact=False).click();await page.get_by_role('button',name='切换',exact=True).click();await asyncio.wait_for(held2.wait(),10)
   await page.get_by_test_id('user-menu').get_by_role('button').click();await page.get_by_role('menuitem',name='退出此设备',exact=True).click();await page.get_by_role('button',name='退出',exact=True).click();await page.wait_for_url('**/login**')
   await login(ENV['IAM_BOOTSTRAP_ACCOUNT'],ENV['IAM_BOOTSTRAP_PASSWORD'])
   release2.set();await page.wait_for_timeout(500)
   state=await page.evaluate('''() => {const s=document.querySelector('#app').__vue_app__.config.globalProperties.$pinia._s.get('auth');return {account:s.identity?.user?.account,tenant:s.identity?.current_tenant?.name,active:s.identity?.active,epoch:s.epoch}}''')
   log.emit('old-switch-after-logout-and-new-login',expected={'account':ENV['IAM_BOOTSTRAP_ACCOUNT'],'tenant':None},actual=state,boundary='Only held network delivery of real response; no product state mutations')
   await page.screenshot(path=str(images/'late-switch-new-user.png'))
  except Exception as e:log.emit('race-interrupted',error=str(e)[:500]);await page.screenshot(path=str(images/'interrupted.png'));raise
  finally:await c.close();await b.close();log.close()
asyncio.run(main())
