# 第6组 真实浏览器证据（C27–C30/C17/C26）

时间：2026-10-15（UTC+8 上午）
环境：后端 JDK21 Corretto + Spring Boot 4.0.8 jar，127.0.0.1:19100（回环）；
Vite dev 127.0.0.1:19101（仅 /web-api 代理到 19100，changeOrigin=false）；
自动化浏览器（自动化桥接 Chromium）真实交互；窄屏使用 Playwright 1.58.2 驱动系统 Microsoft Edge（channel=msedge，真实浏览器内核，非 mock）。
账号：platform_boot（平台超管）、uia-browser-001（浏览器内真实建档，中文显示名"浏览器建档用户"）。

## C27 SPA 同源托管（生产 Spring Boot 直供 web/dist）

- `curl` 与真实浏览器双证：
  - 深链直达 `http://127.0.0.1:19100/admin/platform/users` → 200 text/html，`<title>IAM 共享身份管理后台`。
  - 页面引用 `/assets/index-26h61Oc6.js` 与对应 CSS → 200（text/javascript / text/css）。
  - 缺失 JS `/assets/index-nope.js` → 404 application/json 错误信封，不返回 HTML。
  - 未知 API `/web-api/auth/nope` → 404 application/json，不被 history 回退吞掉。
  - `/favicon.svg` → 200 image/svg+xml；`/demo/agent/index.html` → 200（classpath 演示页不受 file 静态目录影响）。
- 生产 bundle 浏览器实测：19100 深链 → 未登录跳登录 → platform_boot 登录 → 直达 `/admin/platform/users`，表头"平台用户"，20 行真实数据。

## C28 浏览器会话/CSRF/秘密隔离

- 登录页初始：localStorage 0 键、sessionStorage 0 键，document.cookie 仅 `air_iam_dev_csrf`（会话句柄 HttpOnly 不可读）。
- 登录成功后 URL/Pinia/localStorage/sessionStorage 均无 access_token/token_type/bearer；登录响应体不含令牌（B2 另有 curl 断言）。
- 错密码登录：停留 `/login`，红色 alert"账号或密码不正确"，不跳转。
- 真实浏览器 fetch 错 CSRF token POST `/web-api/auth/logout` → 403 `forbidden`，会话仍在。
- Playwright 390px 登录后 cookie 列表：`air_iam_dev_session`（HttpOnly）、`air_iam_dev_csrf`；document.cookie 仅见 csrf。
- 刷新保真（本轮修复的真实缺陷）：登录后 SPA bootstrap `GET /web-api/auth/csrf` 曾撤销已登录句柄导致刷新掉登录；修复后（WebApiAuthController#csrf 对有效人类句柄只重发既有 CSRF，不轮换不撤销），curl 断言"句柄保持一致 + me 200"，浏览器深链刷新 200 保持登录。回归脚本段 B2.5。
- 退出：用户菜单 → 确认框 → `/login`，提示"已退出"。

## C30 真实建档/改密/审计/撤销流程

1. 平台用户页"新建用户"对话框：账号 `uia-browser-001`、显示名 `浏览器建档用户`（中文真实输入）、初始密码 → 保存，toast"用户已建档"，列表出现该用户，平台审计出现 `admin.user.create`（detail 含 account/display_name，无密码）。
2. 重复账号再建：对话框不关闭，toast"资源已存在或发生唯一冲突"（保存失败可见、可恢复）。
3. 搜索：输入 uia-browser-001 → 单行（契约参数 `q`；前端原误发 keyword 已修；无搜索参数的企业/成员/服务账号列表已去掉伪搜索框）。
4. 重置密码：toast"密码已重置，旧会话已即时撤销"。退出后旧密码登录被拒（"账号或密码不正确"），新密码登录成功 → 即时撤销真实生效。
5. 平台审计页可见 admin.user.create/admin.user.password_reset/auth.login/auth.logout 事件链，主体类型"人类用户"，平台级标记。
6. 合成 SSO 演示页真实点击：
   - `/demo/agent/index.html` →"使用中央 IAM 登录"→ 303 链服务端兑换完成，BFF 回传身份 `audience=air-agent`、principal.type=human、account=uia-browser-001。
   - `/demo/kb/index.html` 同流程 → `audience=knowledge`；localStorage/sessionStorage 0 键，document.cookie 仅 csrf。
7. 窄屏 390×844（Playwright + Edge，截图 narrow-1-profile.png / narrow-2-drawer.png，结果 narrow-390.json）：
   - 侧栏默认隐藏，汉堡按钮可见；点击后抽屉+遮罩出现，菜单完整（平台用户/企业与组织/平台角色/服务账号/平台审计/个人设置）。
   - Escape 关闭抽屉（本轮补齐的键盘处理），路由切换后抽屉自动关闭。

## C29 作用域/纪元迟到丢弃

- 单测（vitest，17 个全绿）：scope.spec.ts 覆盖 A→B→A 纪元判定、退出后旧响应不写；usePagedList.spec.ts 覆盖切企业后在途响应丢弃、A→B→A 旧 A 响应丢弃、新请求 abort 旧请求；stores/auth.spec.ts 覆盖登录后菜单/企业落库、登录在途被退出推进后迟到数据丢弃、409 冲突条置位与身份刷新。
- **真实浏览器双企业证据已补齐**（夹具经用户交接授权后执行，幂等两次无重复）：同会话双标签真实 409 冲突条（标签2 旧 ctx_version 切换被服务端拒、自动 hydrate 到获胜方、刷新恢复）、3.5s 迟到甲响应在乙上下文被丢弃且乙→甲可恢复、退出时在途响应不污染登录页；连同 C26 企业成员/部门/角色真实保存、A↔B 服务端隔离复核、390px 租户页窄屏，全部见 `tenant-switch/dual-tenant-browser-evidence.md`（含 stage1 18/18、stage2 5/5、stage3 全断言日志与 13 张截图）。
- 本轮浏览器取证先抓出四个前端真实缺陷并修复（登录快照丢菜单/企业、tenant_id 字段错配、409 冲突条被 hydrate 立即清除、成员/部门/审计页切企业不重载），另修窄屏对话框溢出与 OpenAPI tenants 响应形状误写，详见该证据文档 §1。

## 本轮修复清单（第6组联调）

1. 登录表单提交按钮在 el-form 之外，真实浏览器点击不发请求 → 移入 el-form。
2. GET /web-api/auth/csrf 撤销已登录句柄 → 有效人类会话只重发 CSRF，不轮换（含 B2.5 回归段）。
3. 用户搜索前端发 keyword、契约是 q → usersQuery 映射；删除租户/成员/服务账号无契约支持的伪搜索框。
4. 生产静态默认仅 classpath → 默认 `file:./web/dist/,classpath:/static/`。
5. 窄屏抽屉缺 Escape/路由自动关闭 → 已补。
6. 前端工程：tsconfig project reference emit 冲突、el-radio/未用变量等 typecheck 错误全清；vitest forks 单进程（规避本机 sandbox node dyld 问题）。

## 复跑命令

```bash
# 前端
cd web && npm run typecheck && npm test && npm run build
# 黑盒（服务在 19100）
bash scripts/verify-web-session.sh
# 窄屏（系统 Edge；playwright 仅在 /tmp/pw-run，不入工程依赖）
node /tmp/pw-run/narrow.mjs docs/reviews/evidence/group6
```
