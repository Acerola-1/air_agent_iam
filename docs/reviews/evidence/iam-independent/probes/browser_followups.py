#!/usr/bin/env python3
import json,secrets
from playwright.sync_api import sync_playwright
from probe_client import BASE,PRIVATE,EVIDENCE,Evidence
log=Evidence('browser-followups-r2');images=EVIDENCE/'outputs/browser/followups-r2';images.mkdir()
f=json.loads((PRIVATE/'fixtures.json').read_text());suffix=secrets.token_hex(3)
with sync_playwright() as p:
 b=p.chromium.launch(executable_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',headless=True)
 c=b.new_context(viewport={'width':1440,'height':1000},locale='zh-CN');page=c.new_page();page.set_default_timeout(10000)
 def shot(name):page.screenshot(path=str(images/(name+'.png')))
 try:
  page.goto(BASE+'/profile');page.get_by_placeholder('请输入账号',exact=True).fill(f['users']['dual']['account']);page.get_by_placeholder('请输入密码',exact=True).fill(f['users']['dual']['password']);page.get_by_test_id('login-submit').click()
  page.locator('label').filter(has_text='独立验收企业-A').click();page.get_by_test_id('ctx-tenant').filter(has_text='企业-A').wait_for()
  page.goto(BASE+'/admin/tenant/members');page.get_by_role('button',name='新建/关联成员').click();d=page.get_by_role('dialog').filter(visible=True)
  ins=d.locator('input.el-input__inner');ins.nth(0).fill('browser.member.'+suffix);ins.nth(1).fill('独立中文成员-'+suffix);ins.nth(2).fill(secrets.token_hex(16))
  d.locator('.el-select__wrapper').nth(1).click();page.get_by_role('option',name='企业查询成员',exact=True).click();page.keyboard.press('Escape')
  with page.expect_response(lambda r:'/web-api/admin/members' in r.url and r.request.method=='POST') as ev:d.get_by_role('button',name='保存',exact=True).click()
  log.emit('member-create-roles',status=ev.value.status,expected='201')
  d.wait_for(state='hidden');page.reload();page.get_by_text('browser.member.'+suffix,exact=True).first.wait_for();shot('member-persisted')
  row=page.locator('.el-table__body tr').filter(has_text='browser.member.'+suffix).first;row.get_by_role('button',name='角色',exact=True).click()
  d=page.get_by_role('dialog').filter(visible=True);d.locator('.el-select__wrapper').click();page.get_by_role('option',name='企业查询成员',exact=True).click();page.keyboard.press('Escape')
  with page.expect_response(lambda r:'/roles' in r.url and r.request.method=='POST') as ev:d.get_by_role('button',name='保存授权').click()
  log.emit('member-role-replace',status=ev.value.status,expected='200');d.wait_for(state='hidden')
  # Same cookie, stale ctx page: the explicit switch endpoint must conflict.
  page.goto(BASE+'/profile');tab=c.new_page();tab.goto(BASE+'/profile');tab.locator('label').filter(has_text='独立验收企业-B').click();tab.get_by_test_id('ctx-tenant').filter(has_text='企业-B').wait_for()
  with page.expect_response(lambda r:'/web-api/auth/switch-tenant' in r.url) as ev:page.locator('label').filter(has_text='独立验收企业-B').click()
  log.emit('stale-tab-real-switch-conflict',status=ev.value.status,expected='409')
  page.locator('.context-banner').wait_for(timeout=1500) if page.locator('.context-banner').count() else None
  shot('ctx-conflict');tab.close()
  page.goto(BASE+'/admin/tenant/departments');page.set_viewport_size({'width':390,'height':844});page.get_by_role('button',name='新建部门',exact=True).click()
  page.wait_for_timeout(400) # Let the product's CSS overlay animation settle before geometry/focus evidence.
  dialog=page.locator('.el-dialog').filter(visible=True);box=dialog.bounding_box();log.emit('settled-narrow-dialog-geometry',actual=box,expected='all boundaries within390x844')
  dialog.locator('input.el-input__inner').nth(0).fill('narrow-'+suffix)
  field=dialog.locator('input.el-input__inner').nth(1);field.focus()
  # Real browser IME protocol. This is a CDP composition event test, not physical macOS input method acceptance.
  session=c.new_cdp_session(page);session.send('Input.imeSetComposition',{'text':'中文组合','selectionStart':4,'selectionEnd':4});session.send('Input.insertText',{'text':'中文组合完成'})
  log.emit('browser-ime-composition',actual={'value':field.input_value(),'method':'Chromium CDP IME protocol; physical OS IME not measured'})
  dialog.locator('.el-select__wrapper').click();page.wait_for_timeout(200);popup=page.get_by_role('listbox').filter(visible=True);log.emit('narrow-select-open',actual={'popup_count':popup.count(),'geometry':popup.first.bounding_box() if popup.count() else None});shot('narrow-select')
  page.keyboard.press('Escape');page.keyboard.press('Escape');page.wait_for_timeout(400)
  log.emit('settled-escape-closes-dialog',actual=not dialog.is_visible());shot('narrow-after-escape')
  page.set_viewport_size({'width':1440,'height':1000});page.goto(BASE+'/admin/platform/users');page.wait_for_url('**/403');log.emit('tenant-direct-platform-deep-link',actual=page.url,expected='403 route');shot('forbidden')
  page.goto(BASE+'/profile');page.get_by_test_id('user-menu').get_by_role('button').click();page.get_by_role('menuitem',name='退出此设备',exact=True).click()
  page.get_by_role('button',name='退出',exact=True).click();page.wait_for_url('**/login**');log.emit('real-ui-logout-confirmed',actual=page.url);shot('logged-out')
 except Exception as e:
  log.emit('followup-interrupted',error=str(e).split('Call log:')[0][:500],url=page.url);shot('interrupted');raise
 finally:c.close();b.close();log.close()
