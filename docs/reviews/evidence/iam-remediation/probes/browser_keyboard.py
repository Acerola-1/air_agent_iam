import asyncio,json
from playwright.async_api import async_playwright
from runtime import PRIVATE,OUT,env_values
ENV=env_values();f=json.loads((PRIVATE/'http-fixtures.json').read_text());BASE='http://127.0.0.1:29107'
async def main():
 async with async_playwright() as p:
  b=await p.chromium.launch(executable_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',headless=True);c=await b.new_context(viewport={'width':390,'height':844},locale='zh-CN');page=await c.new_page();page.set_default_timeout(10000)
  try:
   await page.goto(BASE+'/profile');await page.get_by_placeholder('请输入账号',exact=True).fill(ENV['IAM_BOOTSTRAP_ACCOUNT']);await page.get_by_placeholder('请输入密码',exact=True).fill(ENV['IAM_BOOTSTRAP_PASSWORD']);await page.get_by_test_id('login-submit').click();await page.locator('label').filter(has_text=f['tenantA']['code']).click();await page.get_by_test_id('ctx-tenant').filter(has_text=f['tenantA']['name']).wait_for()
   await page.goto(BASE+'/admin/tenant/departments');opening=page.get_by_role('button',name='新建部门',exact=True);await opening.click();dialog=page.get_by_role('dialog',name='新建部门');await dialog.wait_for();await page.wait_for_timeout(350)
   bound=await dialog.bounding_box();focus=[]
   for _ in range(10):
    await page.keyboard.press('Tab');focus.append(await page.evaluate("!!document.activeElement.closest('.el-dialog')"))
   await page.keyboard.press('Escape');await page.wait_for_timeout(350);closed=not await dialog.is_visible()
   result={'viewport':[390,844],'fits_width':bound['x']>=0 and bound['x']+bound['width']<=390,'tab_focus_inside':all(focus),'escape_closes':closed,'focus_restored_to_opener':await opening.evaluate('(element) => document.activeElement === element')}
   result['passed']=all(result[k] for k in ['fits_width','tab_focus_inside','escape_closes','focus_restored_to_opener']);print(json.dumps(result),flush=True)
   (OUT/'browser-keyboard-fixed.json').write_text(json.dumps(result,indent=2));await page.screenshot(path=str(OUT/'browser-r2/narrow-keyboard-fixed.png'));assert result['passed']
  finally:await c.close();await b.close()
asyncio.run(main())
