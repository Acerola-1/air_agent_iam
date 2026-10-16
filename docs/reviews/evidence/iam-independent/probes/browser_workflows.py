#!/usr/bin/env python3
import json
import secrets
from pathlib import Path
from playwright.sync_api import sync_playwright
from probe_client import BASE,ENV,PRIVATE,EVIDENCE,Evidence,safe
log=Evidence('browser-independent-workflows-r2');images=EVIDENCE/'outputs/browser/workflows-r2';images.mkdir()
f=json.loads((PRIVATE/'fixtures.json').read_text());suffix=secrets.token_hex(3)
newaccount='ui.'+suffix;newpassword=secrets.token_hex(16);newname='独立浏览器建档-'+suffix
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',headless=True)
    context=browser.new_context(viewport={'width':1440,'height':1000},locale='zh-CN');page=context.new_page();page.set_default_timeout(9000)
    network=[]
    def observed(r):
        if '/web-api/' in r.url:
            network.append({'path':r.url.split('?')[0].removeprefix(BASE),'method':r.request.method,'status':r.status})
    page.on('response',observed)
    def snap(name):page.screenshot(path=str(images/(name+'.png')),full_page=False)
    def login(account,password,path='/profile'):
        page.goto(BASE+path)
        page.get_by_placeholder('请输入账号',exact=True).fill(account);page.get_by_placeholder('请输入密码',exact=True).fill(password)
        page.get_by_test_id('login-submit').click();page.wait_for_url(lambda url:'/login' not in url);page.locator('.header').wait_for()
    def save(path,button='保存'):
        d=page.get_by_role('dialog').filter(visible=True)
        with page.expect_response(lambda r:path in r.url and r.request.method in ['POST','PATCH']) as event:d.get_by_role('button',name=button,exact=True).click()
        r=event.value;log.emit('ui-save-'+path,status=r.status,response=safe(r.json()) if r.headers.get('content-type','').startswith('application/json') else None)
        if r.status<300:d.wait_for(state='hidden')
        return r
    def run(name,fn):
        try:fn();log.emit(name,actual='completed');snap(name)
        except Exception as e:log.emit(name,actual='interrupted',error=str(e).split('Call log:')[0][:400],url=page.url);snap(name+'-interrupted')
    try:
        login(ENV['IAM_BOOTSTRAP_ACCOUNT'],ENV['IAM_BOOTSTRAP_PASSWORD'],'/admin/platform/users')
        def create_user():
            page.get_by_role('button',name='新建用户',exact=True).click();d=page.get_by_role('dialog').filter(visible=True)
            inputs=d.locator('input');inputs.nth(0).fill(newaccount);inputs.nth(1).fill(newname);inputs.nth(2).fill(newpassword)
            save('/web-api/admin/users');page.get_by_placeholder('按账号/显示名搜索').fill(newaccount);page.get_by_role('button',name='搜索',exact=True).click()
            page.locator('.el-table__body-wrapper').get_by_text(newaccount,exact=True).first.wait_for()
            page.reload();page.get_by_placeholder('按账号/显示名搜索').fill(newaccount);page.get_by_role('button',name='搜索',exact=True).click();page.get_by_text(newname,exact=True).first.wait_for()
        run('platform-user-create-refresh',create_user)
        def platform_roles():
            row=page.locator('.el-table__body tr').filter(has_text=newaccount).first
            row.get_by_role('button',name='平台角色',exact=True).click();d=page.get_by_role('dialog').filter(visible=True)
            d.get_by_text('平台审计员',exact=False).click();save('/platform-roles','保存授权')
            page.reload();page.get_by_placeholder('按账号/显示名搜索').fill(newaccount);page.get_by_role('button',name='搜索',exact=True).click()
            page.locator('.el-table__body tr').filter(has_text=newaccount).first.get_by_text('platform_auditor',exact=True).wait_for()
        run('platform-role-grant-refresh',platform_roles)
        def tenant_create():
            page.goto(BASE+'/admin/platform/tenants');page.get_by_role('button',name='新建企业',exact=True).click();d=page.get_by_role('dialog').filter(visible=True)
            d.locator('input').nth(0).fill('UI-'+suffix);d.locator('input').nth(1).fill('浏览器企业-'+suffix);save('/web-api/admin/tenants')
            page.reload();page.get_by_text('浏览器企业-'+suffix,exact=True).first.wait_for()
            row=page.locator('.el-table__body tr').filter(has_text='UI-'+suffix).first;row.get_by_role('button',name='名称/状态').click()
            d=page.get_by_role('dialog').filter(visible=True);d.get_by_text('停用',exact=True).click()
            r=save('/web-api/admin/tenants/');log.emit('tenant-ui-disable-state-mapping',expected='200',actual=r.status)
            page.keyboard.press('Escape')
        run('platform-tenant-create-disable',tenant_create)
        def custom_platform_role():
            page.goto(BASE+'/admin/platform/roles');page.get_by_role('button',name='新建平台角色').click();d=page.get_by_role('dialog').filter(visible=True)
            d.locator('input').nth(0).fill('ui_platform_'+suffix);d.locator('input').nth(1).fill('浏览器平台角色-'+suffix)
            d.get_by_text('平台用户查看',exact=False).click();save('/web-api/admin/roles')
            page.reload();page.get_by_text('浏览器平台角色-'+suffix,exact=True).first.wait_for()
        run('platform-role-create-permission-tree',custom_platform_role)
        def audit():
            page.goto(BASE+'/admin/platform/audit');page.get_by_placeholder('按动作过滤，如 auth.login').fill('admin.user.create');page.get_by_role('button',name='查询',exact=True).click()
            page.locator('.el-table__body').get_by_text('admin.user.create',exact=True).first.wait_for()
        run('platform-audit-filter',audit)
        context.close();context=browser.new_context(viewport={'width':1440,'height':1000},locale='zh-CN');page=context.new_page();page.set_default_timeout(9000);page.on('response',observed)
        login(f['users']['dual']['account'],f['users']['dual']['password'])
        page.locator('label').filter(has_text='独立验收企业-A').click();page.get_by_test_id('ctx-tenant').filter(has_text='企业-A').wait_for()
        depcode='ui-dept-'+suffix;depname='浏览器部门-'+suffix
        def dept():
            page.goto(BASE+'/admin/tenant/departments');page.get_by_role('button',name='新建部门',exact=True).click();d=page.get_by_role('dialog').filter(visible=True)
            d.locator('input').nth(0).fill(depcode);d.locator('input').nth(1).fill(depname);save('/web-api/admin/departments')
            page.reload();page.get_by_text(depname,exact=True).first.wait_for()
        run('tenant-department-create-refresh',dept)
        def member():
            page.goto(BASE+'/admin/tenant/members');page.get_by_role('button',name='新建/关联成员',exact=True).click();d=page.get_by_role('dialog').filter(visible=True)
            ins=d.locator('input').filter(visible=True);ins.nth(0).fill('ui.member.'+suffix);ins.nth(1).fill('浏览器成员-'+suffix);ins.nth(2).fill(secrets.token_hex(16))
            combos=d.get_by_role('combobox');combos.nth(0).click();page.get_by_role('option',name=depname,exact=True).click()
            combos.nth(1).click();page.get_by_role('option',name='企业查询成员',exact=True).click();page.keyboard.press('Escape');save('/web-api/admin/members')
            page.reload();page.get_by_text('ui.member.'+suffix,exact=True).first.wait_for()
        run('tenant-member-create-department-role-refresh',member)
        def tenant_role():
            page.goto(BASE+'/admin/tenant/roles');page.get_by_role('button',name='新建企业角色').click();d=page.get_by_role('dialog').filter(visible=True)
            d.locator('input').nth(0).fill('ui_tenant_'+suffix);d.locator('input').nth(1).fill('浏览器企业角色-'+suffix)
            d.get_by_text('企业部门查看',exact=False).click();save('/web-api/admin/roles');page.reload();page.get_by_text('浏览器企业角色-'+suffix,exact=True).first.wait_for()
        run('tenant-role-create-tree-refresh',tenant_role)
        def stale_form():
            page.goto(BASE+'/admin/tenant/departments');page.get_by_role('button',name='新建部门',exact=True).click();d=page.get_by_role('dialog').filter(visible=True)
            d.locator('input').nth(0).fill('stale-ui-'+suffix);d.locator('input').nth(1).fill('旧A浏览器草稿-'+suffix)
            tab=context.new_page();tab.goto(BASE+'/profile');tab.locator('label').filter(has_text='独立验收企业-B').click();tab.get_by_test_id('ctx-tenant').filter(has_text='企业-B').wait_for()
            r=save('/web-api/admin/departments');log.emit('double-tab-stale-form-write',expected='409; no write to B',actual=r.status)
            tab.goto(BASE+'/admin/tenant/departments');tab.get_by_text('旧A浏览器草稿-'+suffix,exact=True).first.wait_for()
            log.emit('double-tab-wrong-tenant-persistence',expected=False,actual=True);tab.close()
        run('double-tab-stale-form',stale_form)
        def narrow():
            page.reload();page.set_viewport_size({'width':390,'height':844});page.get_by_role('button',name='新建部门',exact=True).click();d=page.get_by_role('dialog').filter(visible=True)
            box=d.bounding_box();log.emit('narrow-dialog-geometry',actual=box,expected='within390x844')
            d.locator('input').nth(1).focus();page.keyboard.insert_text('窄屏中文录入');page.keyboard.press('Tab');page.keyboard.press('Shift+Tab')
            log.emit('narrow-focus',actual=page.evaluate('({tag:document.activeElement.tagName,role:document.activeElement.getAttribute("role")})'))
            snap('narrow-department-dialog');page.keyboard.press('Escape');log.emit('narrow-dialog-escape',actual=not d.is_visible())
        run('narrow-keyboard-dialog',narrow)
        context.close();context=browser.new_context(viewport={'width':1440,'height':1000},locale='zh-CN');page=context.new_page();page.set_default_timeout(9000);page.on('response',observed)
        def password():
            login(newaccount,newpassword);page.locator('input[type=password]').nth(0).fill(newpassword);newpass=secrets.token_hex(16)
            page.locator('input[type=password]').nth(1).fill(newpass);page.locator('input[type=password]').nth(2).fill(newpass)
            with page.expect_response(lambda r:'/web-api/auth/change-password' in r.url) as ev:page.get_by_role('button',name='保存新密码').click()
            log.emit('browser-change-password',status=ev.value.status,expected='204; current page should require login')
            page.reload();log.emit('browser-current-after-password-refresh',actual=page.url,expected='login route')
            page.get_by_test_id('user-menu').get_by_role('button').click();page.get_by_role('menuitem',name='退出此设备',exact=True).click();page.wait_for_url('**/login**')
            log.emit('browser-logout',actual=page.url)
        run('profile-password-logout',password)
    finally:
        log.emit('browser-network-metadata',actual=network);context.close();browser.close();log.close()
