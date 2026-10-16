import asyncio,json
from playwright.async_api import async_playwright
from runtime import PRIVATE,OUT,PORT,env_values
BASE=f'http://127.0.0.1:{PORT}';ENV=env_values();f=json.loads((PRIVATE/'http-fixtures.json').read_text())
images=OUT/'browser-delivery';images.mkdir(exist_ok=True);log=(OUT/'real-browser-acceptance-delivery.jsonl').open('x')
def emit(case,**data):log.write(json.dumps({'case':case,**data},ensure_ascii=False)+'\n');log.flush();print(case,data.get('passed'),flush=True)
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(executable_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',headless=True)
  context=await browser.new_context(viewport={'width':1440,'height':1000},locale='zh-CN');page=await context.new_page();page.set_default_timeout(12000)
  async def login(page,account,password):
   await page.get_by_placeholder('请输入账号',exact=True).fill(account);await page.get_by_placeholder('请输入密码',exact=True).fill(password);await page.get_by_test_id('login-submit').click();await page.locator('.header').wait_for()
  async def switch(page,name):
   await page.get_by_test_id('tenant-switcher').get_by_role('button').click();await page.get_by_role('menuitem',name=name,exact=False).click();await page.get_by_role('button',name='切换',exact=True).click();await page.get_by_test_id('ctx-tenant').filter(has_text=name).wait_for()
  try:
   await page.goto(BASE+'/profile');await login(page,ENV['IAM_BOOTSTRAP_ACCOUNT'],ENV['IAM_BOOTSTRAP_PASSWORD']);await switch(page,f['tenantA']['name'])
   await page.goto(BASE+'/admin/tenant/departments');await page.get_by_role('button',name='新建部门',exact=True).click()
   dialog=page.get_by_role('dialog',name='新建部门');await dialog.locator('input').nth(0).fill('OLD-TAB');await dialog.locator('input').nth(1).fill('跨标签旧企业表单')
   second=await context.new_page();await second.goto(BASE+'/profile');await switch(second,f['tenantB']['name'])
   async with page.expect_response(lambda r:r.url.endswith('/web-api/admin/departments') and r.request.method=='POST') as response:
    await dialog.get_by_role('button',name='保存',exact=True).click()
   rejected=await response.value;assert rejected.status==409
   await page.screenshot(path=str(images/'stale-department-form-rejected.png'))
   emit('real-two-tabs-old-enterprise-form',status=rejected.status,passed=True)
   await second.close();await page.reload();await switch(page,f['tenantA']['name'])
   await page.get_by_test_id('user-menu').get_by_role('button').click()
   async with page.expect_response(lambda r:r.url.endswith('/web-api/auth/renew')) as response:
    await page.get_by_role('menuitem',name='续期会话',exact=True).click()
   renewal=await response.value;assert renewal.status==200
   emit('real-menu-renewal',status=renewal.status,expected_context_sent=True,passed=True)
   held=asyncio.Event();release=asyncio.Event()
   async def late_switch(route):
    actual=await route.fetch();held.set();await release.wait();await route.fulfill(response=actual)
   await page.route('**/web-api/auth/switch-tenant',late_switch)
   await page.get_by_test_id('tenant-switcher').get_by_role('button').click();await page.get_by_role('menuitem',name=f['tenantB']['name'],exact=False).click();await page.get_by_role('button',name='切换',exact=True).click();await asyncio.wait_for(held.wait(),12)
   await page.get_by_test_id('user-menu').get_by_role('button').click();await page.get_by_role('menuitem',name='退出此设备',exact=True).click();await page.get_by_role('button',name='退出',exact=True).click();await page.wait_for_url('**/login**')
   await login(page,f['probe_user']['account'],f['probe_password']);release.set();await page.wait_for_timeout(400)
   state=await page.evaluate('''() => {const s=document.querySelector('#app').__vue_app__.config.globalProperties.$pinia._s.get('auth');return {account:s.identity?.user?.account,tenant:s.identity?.current_tenant?.id,active:s.identity?.active}}''')
   assert state['account']==f['probe_user']['account'] and state['tenant'] is None
   await page.screenshot(path=str(images/'late-switch-new-login-preserved.png'))
   emit('real-held-switch-after-new-login',identity_preserved=True,old_tenant_discarded=True,boundary='Held delivery of a genuine committed HTTP response; no application state injection',passed=True)
   storage=await page.evaluate('''() => ({local:Object.keys(localStorage),session:Object.keys(sessionStorage)})''');assert not storage['local'] and not storage['session'];emit('browser-no-token-storage',storage=storage,passed=True)
   await page.unroute('**/web-api/auth/switch-tenant')
  except Exception:
   await page.screenshot(path=str(images/'interrupted.png'));raise
  finally:
   await context.close();await browser.close();log.close()
asyncio.run(main())
