import asyncio,json
from playwright.async_api import async_playwright
from runtime import PRIVATE,OUT,PORT,env_values
BASE=f'http://127.0.0.1:{PORT}';ENV=env_values();f=json.loads((PRIVATE/'http-fixtures.json').read_text())
images=OUT/'browser-delivery';log=(OUT/'real-browser-sso-status-delivery.jsonl').open('x')
def emit(case,**data):log.write(json.dumps({'case':case,**data},ensure_ascii=False)+'\n');log.flush();print(case,data.get('passed'),flush=True)
async def main():
 async with async_playwright() as p:
  b=await p.chromium.launch(executable_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',headless=True);c=await b.new_context(viewport={'width':1440,'height':1000},locale='zh-CN');page=await c.new_page();page.set_default_timeout(12000)
  async def login():
   await page.get_by_placeholder('请输入账号',exact=True).fill(ENV['IAM_BOOTSTRAP_ACCOUNT']);await page.get_by_placeholder('请输入密码',exact=True).fill(ENV['IAM_BOOTSTRAP_PASSWORD']);await page.get_by_test_id('login-submit').click();await page.locator('.header').wait_for()
  async def switch(name):
   await page.get_by_test_id('tenant-switcher').get_by_role('button').click();await page.get_by_role('menuitem',name=name,exact=False).click();await page.get_by_role('button',name='切换',exact=True).click();await page.get_by_test_id('ctx-tenant').filter(has_text=name).wait_for()
  try:
   await page.goto(BASE+'/profile');await login();await switch(f['tenantA']['name'])
   apps=[]
   for key,aud in [('agent','air-agent'),('kb','knowledge')]:
    app=await c.new_page();await app.goto(BASE+f'/demo/{key}/');await app.get_by_role('link',name='使用中央 IAM 登录',exact=True).click();await app.wait_for_url('**/demo/'+key+'/**')
    response=await c.request.get(BASE+f'/web-api/sso/callback/{key}/me');assert response.status==200
    identity=await response.json();assert identity['audience']==aud and identity['current_tenant']['id']==f['tenantA']['id']
    apps.append((key,app));emit('real-'+key+'-SSO-server-exchange',status=response.status,passed=True)
   await switch(f['tenantB']['name'])
   for key,_ in apps:
    response=await c.request.get(BASE+f'/web-api/sso/callback/{key}/me');assert response.status==200
    identity=await response.json();assert identity['current_tenant']['id']==f['tenantB']['id'] and identity['context_version']==3
   emit('central-context-shared-with-both-BFFs',passed=True)
   await page.get_by_test_id('user-menu').get_by_role('button').click();await page.get_by_role('menuitem',name='退出此设备',exact=True).click();await page.get_by_role('button',name='退出',exact=True).click();await page.wait_for_url('**/login**')
   statuses=[]
   for key,app in apps:
    response=await c.request.get(BASE+f'/web-api/sso/callback/{key}/me');statuses.append(response.status);assert response.status==401;await app.reload()
   emit('central-logout-rejects-both-old-BFF-cookies',statuses=statuses,passed=True)
   await login();await page.goto(BASE+'/admin/platform/tenants')
   for label,expected in [('停用','suspended'),('正常','active')]:
    row=page.get_by_role('row').filter(has_text=f['tenantB']['code']);await row.get_by_role('button',name='名称/状态',exact=True).click();dialog=page.get_by_role('dialog',name='修改企业（CAS）');await dialog.get_by_text(label,exact=True).click()
    async with page.expect_response(lambda r:r.url.endswith('/web-api/admin/tenants/'+f['tenantB']['id']) and r.request.method=='PATCH') as r:
     await dialog.get_by_role('button',name='保存',exact=True).click()
    response=await r.value;assert response.status==200 and (await response.json())['status']==expected;await dialog.wait_for(state='hidden')
   emit('real-enterprise-disable-and-enable',statuses=['suspended','active'],passed=True)
   await switch(f['tenantA']['name']);await page.goto(BASE+'/admin/tenant/departments');await page.set_viewport_size({'width':390,'height':844});await page.get_by_role('button',name='新建部门',exact=True).click();dialog=page.get_by_role('dialog',name='新建部门');await dialog.wait_for();await page.wait_for_timeout(350)
   bounds=await dialog.bounding_box();assert bounds['x']>=0 and bounds['x']+bounds['width']<=390
   focus=[]
   for _ in range(10):
    await page.keyboard.press('Tab');focus.append(await page.evaluate("!!document.activeElement.closest('.el-dialog')"))
   await page.keyboard.press('Escape');await page.wait_for_timeout(350);closed=not await dialog.is_visible()
   emit('narrow-dialog-keyboard',fits_width=True,tab_focus_inside=all(focus),escape_closes=closed,passed=all(focus) and closed)
   await page.screenshot(path=str(images/'narrow-dialog-keyboard.png'))
  except Exception:
   await page.screenshot(path=str(images/'sso-status-interrupted.png'));raise
  finally:await c.close();await b.close();log.close()
asyncio.run(main())
