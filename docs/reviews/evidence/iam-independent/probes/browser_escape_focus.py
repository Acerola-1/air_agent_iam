#!/usr/bin/env python3
import json
from playwright.sync_api import sync_playwright
from probe_client import BASE,PRIVATE,EVIDENCE,Evidence
log=Evidence('browser-escape-focus');f=json.loads((PRIVATE/'fixtures.json').read_text());images=EVIDENCE/'outputs/browser/escape-focus';images.mkdir()
with sync_playwright() as p:
 b=p.chromium.launch(executable_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',headless=True);c=b.new_context(viewport={'width':390,'height':844},locale='zh-CN');page=c.new_page();page.set_default_timeout(10000)
 try:
  page.goto(BASE+'/profile');page.get_by_placeholder('请输入账号',exact=True).fill(f['users']['dual']['account']);page.get_by_placeholder('请输入密码',exact=True).fill(f['users']['dual']['password']);page.get_by_test_id('login-submit').click();page.locator('label').filter(has_text='独立验收企业-A').click();page.get_by_test_id('ctx-tenant').filter(has_text='企业-A').wait_for()
  page.goto(BASE+'/admin/tenant/departments');page.get_by_role('button',name='新建部门',exact=True).click();page.wait_for_timeout(400)
  focus=[]
  for _ in range(10):
   page.keyboard.press('Tab');focus.append(page.evaluate('''() => ({inside_dialog:!!document.activeElement.closest('.el-dialog'),tag:document.activeElement.tagName})'''))
  log.emit('narrow-modal-tab-focus-trap',actual=focus,expected='all remain inside dialog')
  page.keyboard.press('Escape');page.wait_for_timeout(400)
  log.emit('normal-narrow-dialog-escape',actual={'visible_dialogs':page.locator('.el-dialog').filter(visible=True).count(),'focus':page.evaluate('document.activeElement.innerText')},expected='0 dialogs; focus restores to opening button')
  page.screenshot(path=str(images/'after-normal-escape.png'))
 finally:c.close();b.close();log.close()
