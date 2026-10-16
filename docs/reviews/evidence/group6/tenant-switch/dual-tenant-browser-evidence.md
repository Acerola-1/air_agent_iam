# 双企业真实浏览器证据（C26/C29/C30/C07 收尾轮）

- 时间：2026-10-15（UTC+8 下午，14:00–14:35）
- 执行人：接手 Agent（前序 Agent 额度中断，仅剩夹具授权项与 6.5/6.6/6.7 未勾）
- 环境：后端 JDK21 Corretto + Spring Boot 4.0.8 jar，`http://127.0.0.1:19100`（回环），生产同源 bundle `web/dist`（Spring Boot file 静态托管，非 Vite dev）；Playwright 1.58.2 驱动系统 Microsoft Edge（channel=msedge，真实浏览器内核，非 mock）。
- 账号：`uia-082225`（浏览器验收用户，经夹具授予 UIAA-082225/UIAB-082225 双 tenant_admin）；平台侧 `platform_boot` 仅用于 API 建档/重置口令，过程见本目录外的 setup 记录。
- 夹具：用户在交接消息中明确授权后执行 `bash scripts/seed-browser-fixture.sh uia-082225 UIAA-082225 UIAB-082225`，仅向本任务自有 iam 库的 `tenant_memberships/membership_roles` 写入 2 行成员+2 行角色；当日连跑两次验证幂等（`SEED_OK` + `SEED_IDEMPOTENT_OK`，无重复行）。
- 自动化脚本为中间产物，放 `/tmp/pw-run/`（不进工程）：`stage1-flow.mjs`（桌面 1440×900 全流程）、`stage2-cas-late.mjs`（CAS/迟到/退出）、`stage3-narrow.mjs`（390×844）。输出日志已脱敏（CSRF 值替换为 `<redacted>`）后随本目录归档。

## 1. 本轮接手时先发现并修复的真实缺陷（均有修复后反证）

接手时 6.5/6.6/6.7 的企业内浏览器操作实际无法走通；前端存在四个真实功能缺陷（后端隔离与 CAS 始终正确，问题都在浏览器侧状态装配）：

1. **登录后菜单与可进入企业被新鲜度守卫丢弃（严重）**：`auth.login()` 在提交 identity **之前**抓取 epoch 快照，identity 提交后作用域由 `null` 变为真实用户 id，导致登录后 menus/tenants 的 `isFresh` 复核必然失败而整批丢弃。现象：登录后侧边栏菜单为空、个人页"可进入的企业"显示"暂无企业成员关系"，尽管 `GET /web-api/auth/tenants` 真实返回 2 家企业（网络响应与 Pinia 状态对比取证）。此前第 6 组证据因用整页 `goto` 跳转（触发 `hydrate()` 单次原子提交）而掩盖了该缺陷。修复：identity 提交后重取快照；新增 store 回归用例 3 个。
2. **企业列表字段错配**：契约 `TenantMembershipSummary` 与后端返回字段是 `tenant_id`（OpenAPI 1025–1034 行），前端类型却声明 `id`，Profile 单选与顶部切换器的 `:value/:command/:key` 全部取到 `undefined`，即使企业列表加载成功也无法切换。修复：新增 `TenantMembershipOption` 类型并替换两处绑定；`current_tenant` 仍是 `Tenant{id}`，两者分型。
3. **409 冲突条被立即清掉**：`switchTenant` 先置 `contextConflict=true` 再 `hydrate()`，而 `commitIfFresh` 成功后固定复位该标记，用户看不到冲突条。修复：先 hydrate 拉取最新身份，后置冲突条（保留到用户点"立即刷新上下文"整页恢复或下一次显式切换）。
4. **切企业后成员/部门/企业审计页不重载**：顶部"切换企业"成功后 `AdminLayout` 仅做同路径 `router.replace`（Vue Router 不重挂载组件），成员页与部门页缺 `watch(tenantId)`（企业角色页本来就有），切到乙后表格仍显示甲数据——虽然后端按会话作用域返回的是乙数据（脚本内直接 fetch 复核：乙上下文中甲成员/部门均缺席），但 UI 残留违反隔离呈现要求。修复：三个页面补 tenant watch；成员页的部门/角色目录随上下文一起重载。

附带修复：

5. 窄屏 390px 下 el-dialog 固定 520/460/560/640px 宽度溢出 → 全部改为 `min(Npx, 92vw)`（含平台侧 8 处），消息确认框加 ≤768px 全局宽度约束。
6. OpenAPI `/web-api/auth/tenants` 200 响应误写为 `{items:[...]}` 信封，与冻结实现（裸数组）不符 → 订正为 `type: array, items: TenantMembershipSummary`；契约测试器 36/36 仍全绿。

## 2. C26/C07：桌面端真实建档/授权/冲突/隔离（stage1，18/18 PASS，连跑两轮幂等）

日志：`stage1-desktop-flow.log`；截图：`10-A-members.png`、`11-B-departments-after-header-switch.png`、`12-B-members-after-header-switch.png`、`13-A-members-restored.png`。

- 登录后个人页出现两家企业单选；localStorage/sessionStorage 0 键，`document.cookie` 仅 CSRF（会话句柄 HttpOnly 不可读）。
- 企业甲：真实新建部门 `D-RD-0822 研发一部`（中文）；真实新建成员账号 `uia-mbr-a-0822 甲企业成员01`（口令掩码输入、归属研发一部、授内置 `tenant_reader`），toast"成员关系已建立"；重复建档同账号 → 红色 toast"账号已存在；关联既有成员必须显式传 user_id，禁止按同名自动合并"且对话框不关闭（保存失败可见、可恢复）；成员角色 CAS"保存授权"成功（角色标签数=1）。
- 整页刷新：会话恢复、上下文仍是甲、成员/部门/角色数据持久化。
- 甲自定义角色 `tenant_audit_viewer_x 审计查阅员`：勾选"企业审计查看"保存；重开对话框编码框禁用、勾选仍在（内置角色保护与持久化双证）。
- 切企业隔离（顶部切换器+确认框，全部真实 UI 操作）：
  - 停留在部门页直接甲→乙：表格自动换乙（修复前会残留"研发一部"，修复点 4），截图 11 为乙空态/本企数据；
  - 成员页甲→乙：仅见乙成员（含本账号），无 `uia-mbr-a-0822`；
  - 乙真实建档 `D-OPS-0822 运营保障组` 与 `uia-mbr-b-0822 乙企业成员01`（归属运营保障组、tenant_reader）；
  - 浏览器内直接 `fetch('/web-api/admin/members?limit=200')` 与 departments 复核服务端作用域：乙返回 `[uia-082225, uia-mbr-b-0822]` / `[D-OPS-0822]`，零甲数据；
  - 乙→甲：甲数据完整回来且无乙成员（A→B→A 闭环，截图 13）。
- 越权直连：甲 tenant_admin 直接 `fetch('/web-api/admin/users?limit=1')` → 真实 **403**（菜单/按钮之外的后端兜底）。

## 3. C29：真实并发 409 冲突条 + 迟到响应丢弃 + 退出不污染（stage2，5/5 PASS）

日志：`stage2-cas-late.mjs` → `stage2-cas-late.log`；截图：`20-ctx-conflict-409.png`、`21-late-A-response-discarded-in-B.png`、`22-B-to-A-restored.png`、`23-logout-inflight-login-page.png`。

1. **真实 CAS 409（非 mock、非注入状态码）**：同一浏览器会话两个标签页（共享会话句柄 cookie，等同同账号两台设备）。标签 1 先在个人页切甲（陈旧期望版本落败窗口关闭）；标签 2 持有旧 `context_version`，用顶部切换器切乙 → 服务端 `switch_session_context` 真实返回 **409**（响应监听记录 `switchStatuses:[409]`）。标签 2 出现黄色冲突条"企业上下文已被其他操作推进 / 当前页面数据可能已过期 / 立即刷新上下文"（截图 20），并自动 hydrate 为获胜方上下文（顶部标记是甲而非乙，乙切换未生效）；点"立即刷新上下文"整页恢复后仍为甲、冲突条消失。
2. **迟到响应丢弃（真实后端 + 仅注入网络到达延迟）**：甲部门页挂一次性 3.5s 响应延迟，点"刷新"制造在途甲请求（实测延迟 3501ms），250ms 后即切乙；乙的 watch 新请求不被拦截，先到并渲染"运营保障组"；迟到甲响应在切换后约 3249ms 落地，被请求序号 + scope/epoch 双守卫丢弃，乙表格始终无"研发一部"（截图 21）。随后乙→甲新请求正常恢复甲数据（截图 22）。单元层 A→B→A 同路径纪元更落后仍丢弃由 vitest 17/17 中既有 3 个 usePagedList 用例覆盖。
3. **退出时在途响应不污染**：成员列表在途（3s 延迟）时点用户菜单"退出此设备"→ 确认 → 落 `/login`；等待迟到窗口过后仍在登录页，页面无任何成员行，localStorage/sessionStorage 0 键（截图 23）。

## 4. C30：租户页窄屏 390×844 + 键盘/中文输入（stage3，全部断言 true）

输出：`stage3-narrow.json`；截图：`30-narrow-tenant-members.png`、`31-narrow-tenant-drawer.png`、`32-narrow-member-dialog.png`、`33-narrow-department-create.png`、`34-narrow-departments.png`。

- 侧栏默认隐藏、汉堡"展开菜单"可见；抽屉+遮罩出现且含完整租户菜单（成员/部门/角色/审计）；**Escape 关闭抽屉**（escDiagnostics：visible 对话框 0、overlay 0）；点"部门管理"路由后抽屉自动关闭。
- 新建成员对话框在 390px 下完整不溢出（`dialogFitsNarrow=true`，修复点 5），中文"窄屏键盘输入"真实录入成功；Escape 关闭对话框。
- 窄屏部门页真实建档 `D-NR-0822 窄屏建档部`（首轮真实保存，复跑幂等识别 already-exists），表格立即可见（截图 34）。
- 窄屏下 localStorage/sessionStorage 0 键、cookie 无令牌。

## 5. 修复后的质量门与回归

- `npm run typecheck`：0 错；`vitest`：**17/17**（原 14 + 新增 stores/auth.spec.ts 3 用例：登录后菜单/企业落库、登录在途被退出推进则迟到数据丢弃、409 置冲突条并刷新身份）；`npm run build`：干净产出，服务中同源 hash 与 dist 一致（`index-BQ_Ac_GY.js`，200）。
- `scripts/verify-contract.sh`：36/36（含 OpenAPI 订正后 spec-valid/required-paths）。
- `scripts/verify-web-session.sh`：B1–B6 + B2.5 + SPA 段全绿。
- `scripts/verify-acceptance-matrix.sh`：**8/8 段全绿**（`group7/matrix/matrix-20261015T063455Z.txt`，UTC；含 G0/CRYPTO/CONTRACT/DB/SESSION/INTERNAL/ADMIN/WEB；后端 72 测试随各段与本轮无 Java 改动保持原结论）。
- `openspec validate establish-shared-iam-service --strict`：valid。
- 秘密扫描：`tenant-switch/secret-scan.txt` PASS，9 个真实秘密对含本目录在内的全部交付物零命中；本目录日志中的 CSRF 值已脱敏，测试成员口令仅经环境变量传入、不落任何文件。

## 6. 复跑命令

```bash
cd /Users/acerola/Dev/Java/air_agent_iam
# 前端三门
(cd web && npm run typecheck && npm test && npm run build)
# 黑盒/契约/矩阵
bash scripts/verify-web-session.sh && bash scripts/verify-contract.sh
bash scripts/verify-acceptance-matrix.sh
# 浏览器三段（Playwright 仅在 /tmp/pw-run，系统 Edge；服务需在 127.0.0.1:19100）
UIA_ACC=uia-082225 UIA_PW='<本地开发口令，不入库>' node /tmp/pw-run/stage1-flow.mjs /tmp/pw-run/after
UIA_ACC=uia-082225 UIA_PW='<本地开发口令，不入库>' node /tmp/pw-run/stage2-cas-late.mjs /tmp/pw-run/after
UIA_ACC=uia-082225 UIA_PW='<本地开发口令，不入库>' node /tmp/pw-run/stage3-narrow.mjs /tmp/pw-run/after
# 夹具清理（如需恢复双企业授权前状态）
bash scripts/seed-browser-fixture.sh --cleanup uia-082225 UIAA-082225 UIAB-082225
```

说明：浏览器脚本对建档动作全部幂等（重复执行跳过已存在数据并仍全绿，stage1 已连跑两轮验证）；种子企业/用户/成员保留在本任务自有开发库供复验，未触碰任何共享服务。
