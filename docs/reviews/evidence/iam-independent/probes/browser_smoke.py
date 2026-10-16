#!/usr/bin/env python3
import sys
from playwright.sync_api import sync_playwright
from probe_client import BASE, ENV, EVIDENCE, Evidence, safe

run_label = sys.argv[1] if len(sys.argv) > 1 else 'smoke-r2'
log = Evidence('browser-' + run_label)
images = EVIDENCE / 'outputs/browser' / run_label
images.mkdir()
network = []
with sync_playwright() as playwright:
    browser = playwright.chromium.launch(executable_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', headless=True)
    context = browser.new_context(viewport={'width':1440,'height':1000}, locale='zh-CN')
    page = context.new_page()
    page.set_default_timeout(15000)
    def response_observed(response):
        if '/web-api/' not in response.url:
            return
        try:
            body = response.json()
        except Exception:
            body = None
        network.append({'path':response.url.removeprefix(BASE),'method':response.request.method,'status':response.status,'body':safe(body)})
    page.on('response', response_observed)
    page.on('pageerror', lambda error: log.emit('browser-page-error', actual=str(error)))
    try:
        log.emit('browser-engine', actual={'version':browser.version,'engine':'real Microsoft Edge/Chromium headless','viewport':'1440x1000'})
        page.goto(BASE+'/admin/platform/users')
        page.get_by_placeholder('请输入账号', exact=True).fill(ENV['IAM_BOOTSTRAP_ACCOUNT'])
        page.get_by_placeholder('请输入密码', exact=True).fill('audit-known-account-wrong-password')
        page.get_by_test_id('login-submit').click()
        page.get_by_test_id('login-error').wait_for()
        log.emit('known-account-wrong-password-ui', expected='Chinese login error, stay on login', actual={'url':page.url,'error':page.get_by_test_id('login-error').inner_text()})
        page.screenshot(path=str(images/'desktop-login-negative.png'),full_page=True)
        page.get_by_placeholder('请输入密码', exact=True).fill(ENV['IAM_BOOTSTRAP_PASSWORD'])
        page.get_by_test_id('login-submit').click()
        page.wait_for_url('**/admin/platform/users')
        page.get_by_text('新建用户',exact=True).wait_for()
        page.screenshot(path=str(images/'desktop-users-positive.png'),full_page=True)
        log.emit('deep-link-login-positive', expected='return to requested user page after real UI login', actual={'url':page.url,'heading':page.title()})
        page.reload()
        page.get_by_text('新建用户',exact=True).wait_for()
        log.emit('refresh-persists-session', actual={'url':page.url,'title':page.title()})
        page.get_by_test_id('user-menu').get_by_role('button').click()
        with page.expect_response(lambda response:'/web-api/auth/renew' in response.url) as renewal:
            page.get_by_role('menuitem',name='续期会话').click()
        response=renewal.value
        log.emit('real-browser-renew', expected='200 and success feedback', status=response.status, request_body=response.request.post_data_json,response=response.json())
        page.get_by_text('expected_ctx_version 必填',exact=False).first.wait_for()
        page.screenshot(path=str(images/'desktop-renew-failure.png'),full_page=True)
        log.emit('real-browser-renew-visible-error', actual=page.locator('.el-message').all_text_contents())
        cookies=[{k:v for k,v in cookie.items() if k!='value'} for cookie in context.cookies()]
        storage=page.evaluate('''() => ({localStorageKeys:Object.keys(localStorage),sessionStorageKeys:Object.keys(sessionStorage),jsCookieNames:document.cookie.split(';').map(x=>x.trim().split('=')[0]),url:location.href})''')
        log.emit('browser-credential-boundary', expected='HttpOnly handle invisible to JS; no bearer or internal secret in storage/URL/API', cookies=cookies,storage=storage)
        page.set_viewport_size({'width':390,'height':844})
        page.get_by_role('button',name='展开菜单',exact=True).click()
        opened=page.locator('.sidebar').is_visible()
        page.keyboard.press('Escape')
        log.emit('narrow-drawer-escape', expected='drawer opens then closes on Escape',actual={'opened':opened,'visible_after_escape':page.locator('.sidebar').is_visible()})
        focus=[]
        for _ in range(8):
            page.keyboard.press('Tab')
            focus.append(page.evaluate('''() => ({tag:document.activeElement?.tagName,role:document.activeElement?.getAttribute('role'),label:document.activeElement?.getAttribute('aria-label'),text:(document.activeElement?.innerText||'').slice(0,60)})'''))
        log.emit('narrow-keyboard-focus', actual=focus)
        page.screenshot(path=str(images/'narrow-users-390x844.png'),full_page=True)
        log.emit('narrow-layout', actual=page.evaluate('''() => ({viewport:[innerWidth,innerHeight],document:[document.documentElement.scrollWidth,document.documentElement.scrollHeight]})'''))
    except Exception as error:
        log.emit('browser-smoke-interrupted', actual={'error':str(error),'url':page.url})
        page.screenshot(path=str(images/'smoke-interrupted.png'),full_page=True)
        raise
    finally:
        log.emit('observed-browser-network',actual=network)
        context.close()
        browser.close()
        log.close()
