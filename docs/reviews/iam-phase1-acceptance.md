# IAM 首期（I1）验收报告

- change：`establish-shared-iam-service`（openspec，`openspec validate establish-shared-iam-service --strict` = valid）
- 报告时间窗：2026-10-15（UTC+8）。结论时间点：第 6 组浏览器适配 + 第 7 组集成/性能/灾备/扫描全部跑完；**当日下午接手轮补齐 C26/C29/C30 双企业真实浏览器证据（6.5/6.6/6.7 勾选，36/36 任务闭合）**，见 group6/tenant-switch/。
- 结论：**I1 范围内 36/36 任务全部有可复跑证据**；一项保留（见 §9）：C25 并发 30 在同机容器上存在超目标轮次，已如实定位，未引入授权缓存。接手轮浏览器取证先抓出并修复 4 个前端真实缺陷（登录丢菜单/企业、tenant_id 错配、409 冲突条被立即清除、切企业列表残留），修复过程与反证均留痕。
- 两 Python 仓库（`/Users/acerola/Dev/Python/air_agent`、`.../RAG/env-rag-final`）全程只读；本工作区非 git 仓库，未 commit/push/归档。

## 1. 环境与本地地址

| 项 | 值 |
|---|---|
| JDK | Amazon Corretto 21.0.12.1（`/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home`） |
| 框架 | Spring Boot 4.0.8 WebMVC + Sa-Token 1.46.0（有状态不透明 token，显式 Redis）+ Jackson3 |
| 数据库 | PostgreSQL 17，Apple Container `iam-pg17`，127.0.0.1:19132（仅回环），库 `iam`（另有测试库 `iam_test`、一次性 scratch 库） |
| Redis | 7，Container `iam-redis7`，127.0.0.1:19179（仅回环） |
| IAM HTTP | http://127.0.0.1:19100（生产形态：Spring Boot 同源直供 `web/dist`） |
| Vite dev | http://127.0.0.1:19101（仅代理 `/web-api`，changeOrigin=false，非生产 BFF） |
| 健康检查 | `GET http://127.0.0.1:19100/healthz` → `{"status":"ok","postgres":true,"redis":true}` |
| 平台引导账号 | `platform_boot`（口令来自 `.env.local` 的 `IAM_BOOTSTRAP_*`，不写入任何证据） |
| 前端 | Vue 3.5 / Vite 7 / vue-router 4 / Pinia 3 / Element Plus 2.14 / TypeScript 5.9，锁版本不追新主版本 |

秘密来源仅 `.env.local`（不进版本库）；证据只存状态码、UUID 前缀、修订号、计数。

## 2. 一键复跑命令

```bash
cd /Users/acerola/Dev/Java/air_agent_iam
set -a && . ./.env.local && set +a
export JAVA_HOME=/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home

# 后端全量：72 测试（真实 PG iam_test + Redis）
(cd server && ./mvnw test)

# 前端三门
(cd web && npm run typecheck && npm test && npm run build)   # vitest 17/17

# I1 场景矩阵 C01–C17（汇总调用下列 8 个脚本，真实 HTTP/PG/Redis）
bash scripts/verify-acceptance-matrix.sh
# C25 性能与依赖故障（自带 19103 专用实例，主实例不重启）
bash scripts/verify-perf-introspection.sh
# 备份/恢复/撤销重施（自带 19102 恢复实例与 scratch 库，结束即销毁）
bash scripts/verify-dr-restore.sh
# 秘密零命中扫描（9 个真实秘密 vs 全部交付物/证据/日志）
bash scripts/verify-secret-scan.sh docs/reviews/evidence/group7/secret-scan.txt
# 浏览器黑盒 + SSO 合成双消费者 + 同源 SPA（矩阵第 8 段）
bash scripts/verify-web-session.sh
# 双企业真实浏览器三段（Playwright 仅在 /tmp/pw-run，系统 Edge；建档动作幂等可重复）
# 脚本与详细复跑见 group6/tenant-switch/dual-tenant-browser-evidence.md §6
```

## 3. 场景索引（C01–C17 / C25–C30）

| ID | 结果 | 证据（docs/reviews/evidence/ 下相对路径） |
|---|---|---|
| C01 | 通过 | gate0/c01-build-start.txt；group7/matrix G0 段 |
| C02 | 通过 | group1/c02-c03-crypto-vectors.txt；group4/c02-c03-cross-language-vectors.txt；矩阵 CRYPTO |
| C03 | 通过 | group1/… + 矩阵 CRYPTO；rt-v1 Java/Python 双向见 group4 c12-c13-c03-c15-internal-principals.txt B3 |
| C04 | 通过 | 矩阵 CONTRACT/DB/SESSION；group3/c05-c06-c07-c11-c16-session-authority.txt |
| C05 | 通过 | group3（B1–B3、B7–B9）；浏览器即时撤销 group6/browser-evidence.md §C30 |
| C06 | 通过 | group3（停用/角色移除 A 受影响 B 不污染）；group6/dependency-failure-503.txt |
| C07 | 通过 | group3：并发切企业恰一胜（FOR UPDATE）、A→B→A 旧页拒绝；前端 epoch 守卫 web vitest |
| C08 | 通过 | group2/c04-c08-c09-c10-c16-db-isolation.txt；矩阵 DB/ADMIN |
| C09 | 通过 | group2 + group5/admin-apis.txt（可授树/平台专属企业不可授/内置角色保护） |
| C10 | 通过 | group2（iam_app 非 owner GUC/RLS、异常取消后无残留） |
| C11 | 通过 | group3（503 失败关闭/授权+审计同事务/outbox 重放）；group6/dependency-failure-503.txt；group7/perf-introspection.txt（Redis 503、PG 停 503x30） |
| C12 | 通过 | 矩阵 CONTRACT 36/36（含本轮修复：format-checker 回归）+ INTERNAL（垃圾主体 200 inactive 等 23 用例） |
| C13 | 通过 | group4 B1/B4（错凭据/错受众/scope、verification_ref 复查与篡改/撤销） |
| C15 | 通过 | group4 B5：服务账号分型、固定受众、24h 重叠轮换、365 天上界、吊销即时、资源型权限 DB 触发器 23514 + 应用 400 双拒 |
| C16 | 通过 | group2 + group3（续期推进空闲、陈旧拒绝、过期不可复活、不回退） |
| C17 | 通过 | group6/web-session-final.txt B5 + browser-evidence.md（真实点击合成 demo/agent、demo/kb） |
| C25 | 见 §5 | group7/perf-introspection.txt（100 样本×3轮×并发 1/10/30 + 依赖故障） |
| C26 | 通过 | group5/admin-apis.txt；group6/browser-evidence.md §C30（平台侧真实浏览器）；**group6/tenant-switch/（企业侧成员/部门/角色真实建档授权、冲突保存失败、CAS 替换、刷新持久化、A/B 隔离复核，stage1 18/18 + 截图 10–13）** |
| C27 | 通过 | group6/web-session-final.txt SPA 段 + browser-evidence.md（19100 同源深链 200、缺失资源 JSON 404） |
| C28 | 通过 | web-session-final.txt B1–B4；browser-evidence.md（JS 不可见会话令牌、无 Node BFF） |
| C29 | 通过 | web vitest 17/17（scope A→B→A、usePagedList 迟到丢弃/abort、auth store 登录落库/409）；**tenant-switch/stage2-cas-late.log：同会话双标签真实 409 冲突条、3.5s 迟到甲响应在乙丢弃、退出在途不污染（截图 20–23）** |
| C30 | 通过 | group6/narrow-*.png/json（平台侧 390×844）；**tenant-switch/stage3-narrow.json + 截图 30–34（租户成员/部门页窄屏、抽屉 Escape/路由关闭、对话框不溢出、中文窄屏真实建档）**；中文输入、冲突 toast、错 CSRF/401/503 恢复均有证据 |

范围外（I1 不勾，且未冒称完成）：C14（I2）、C18 entitlement（I1a；资源型权限当前默认拒绝，DB 触发器兜底）、C19/C20（I3）、C21/C22（I2/I4 真实六图与 3/5 业务）、C23/C24（I4 拆库；§6 的自有库灾备演练不构成 C24）。

## 4. 后端/前端/黑盒结果汇总

- 后端 JUnit：**72/72 通过，0 失败 0 错误 0 跳过**（Admin 16、SessionAuthority 16、DbIsolation 12、InternalClient 23、CrossLanguageVector 2、RateLimit 2、BrowserSession 9）。
- 前端：`vue-tsc` 0 错；vitest **17/17**（接手轮 14→17，新增 stores/auth.spec.ts 3 用例）；`vite build` 干净产出 `web/dist`。
- 黑盒矩阵：**8/8 段通过**两次（group7/matrix/matrix-20261015T045149Z.txt 与接手轮回归 matrix-20261015T063455Z.txt，UTC）。
- 接手轮真实浏览器三段：stage1 桌面 18/18（连跑两轮幂等）、stage2 CAS/迟到/退出 5/5、stage3 窄屏全部断言 true。
- 秘密扫描：9 个真实秘密在 server/src、scripts、contracts、web（含 dist）、openspec、docs、tools、server/logs **零命中**（接手轮新证据 group6/tenant-switch/secret-scan.txt 再验 PASS）。
- `openspec validate establish-shared-iam-service --strict`：valid。

## 5. C25 性能/故障（实测，不美化）

证据：group7/perf-introspection.txt。方法：同机回环 HTTP/1.1 keep-alive（每工作线程一条持久连接，HikariCP 暖池），100 样本×3 轮，并发 1/10/30；采集实例 19103 与主实例同 PG、独立 Redis 逻辑库 4、关闭准入限流以隔离"核验开销"本身；总核验 900 次、非 200=0、active 与实际一致。

- 并发 1：P50 4.08–5.11ms，P95 5.71–7.96ms（达标，目标 P50≤10/P95≤30ms）。
- 并发 10：P50 7.12–8.80ms，P95 13.79–20.34ms（达标）。
- 并发 30：P50 25.84–95.17ms，P95 40.73–404.77ms（**超目标**），P99 最高 420.39ms，单请求最大 423.28ms。
- 定位：每次 introspection 都以 PG 为权威做多轮实查（会话、四修订、有效权限），**无任何跨请求正向授权结果缓存**；并发 30 时同机容器 PG 的连接/查询排队把尾延迟拉高；前台仍有 JIT/GC 与桌面环境噪声（同机同日另一暖轮 c=30 曾录得 P95 27.1–31.2ms，波动来自环境而非代码路径差异）。
- 结论与取舍：单次暖连接与并发 10 达标；并发 30 尾延迟超 30ms 目标但未突破 500ms 总 deadline。**没有为了数字引入授权 TTL 缓存**（硬约束）。后续优化方向留 I1a/I2：权限装配 SQL 收敛/批量化、连接池与容器资源配额隔离后重测。
- 故障：停 Redis → `/v1/auth/login` 503 `dependency_unavailable`；停 PG → introspect 30/30 全部 503（无一次 200 放行）；容器恢复后 healthz ok、核验 200。限流组件自身在 Redis 故障时失败关闭（RateLimiter，集成测试覆盖）。
- 外部等待：全部回环，无外部网络；未采集队列深度指标（无此埋点）。
- Token 消耗：**未采集**（工具链不提供该计量；不记为 0）。

## 6. 备份/恢复与撤销重施演练（自有 iam 库）

证据：group7/dr-restore.txt（PASS），脚本 scripts/verify-dr-restore.sh（幂等、可复跑、结束自动清理）。

1. 主实例建档演习用户 + 授 `platform_auditor`，登录 T1 经 introspection 确认 active 且含 `platform:audit:read`（4 权限）。
2. `pg_dump -Fc`（超级用户流，规避 RLS 强制）备份 `iam`，229125 字节，文件只在 `/tmp`、不进版本库。
3. 备份后在主库真实撤销：重置密码（T1 立即 `invalid_or_revoked`）+ 移除平台角色。
4. 恢复到一次性 scratch 库 + Redis 逻辑库 3 + 第二实例 19102：备份点状态完整回来（T1 active、auditor 权限在）。
5. 按审计事件顺序**重施撤销**：重置密码后 T1 在恢复实例仍 `invalid_or_revoked`（旧会话不复活）；移除角色后新会话 0 权限、审计接口 403（角色限制仍生效）；陈旧 `expected_revision` 重放 409（不回退）。
6. 主实例全程存活；scratch 库/恢复实例/dump 全部销毁，演习用户置 disabled。
7. 边界：这是新项目**自有库**的恢复演练，不代表旧业务库拆库迁移（C24 归 I4）。

## 7. 第 6/7 组实际修复轮次（留痕）

1. 登录真实提交：提交按钮在 el-form 外，浏览器点击不发请求 → 移入 el-form。
2. **刷新掉登录严重缺陷**：`GET /web-api/auth/csrf` 对已登录人类句柄无条件撤销/换匿名 → 改为有效人类会话只重发既有 CSRF（Redis+PG 双验），新增黑盒回归段 B2.5。
3. 用户搜索契约不一致：前端发 keyword，契约为 `q` → `usersQuery()` 映射；租户/成员/服务账号列表无服务端搜索契约 → 删除伪搜索框。
4. 生产静态默认仅 classpath → `file:./web/dist/,classpath:/static/`；补 `/favicon.svg` 资源映射。
5. 窄屏抽屉补 Escape 关闭、路由切换自动关闭。
6. 前端工程修复：tsconfig project reference emit 冲突（TS6310，合并单配置）、el-radio/未用变量类型错误、vitest jsdom 线程 simdutf 崩溃（固定 forks 单进程）。
7. **契约测试回归修复**：协议消费者测试器构造 validator 时漏传 `FormatChecker`，导致 `format: uuid` 反例（non-uuid-user.json）未被拦截（35 过 1 失败）→ 恢复 format checker 后 36/36。
8. 验证脚本健壮性：限流 600/60s 干扰性能采集（专用实例关闭限流）、pg_dump RLS（改超级用户备份）、bash 3.2 关联数组/中文字节邻接变量名等复跑问题，均已修入脚本。
9. 真实误操作留痕：浏览器联调中误对既有用户 `b5ext-060539382` 触发一次重置密码（审计 00c3d195，auth_revision=2）。无法回滚，已在 browser-evidence.md 标注且不再触碰该用户。
10. **接手轮（双企业浏览器取证）修复 4 个真实前端缺陷 + 2 个附带项**（详见 group6/tenant-switch/dual-tenant-browser-evidence.md §1）：
    1. `auth.login()` 在 identity 提交前取快照，登录后 menus/tenants 被 isFresh 守卫整批丢弃（整页 goto 走 hydrate 原子提交而长期掩盖）→ identity 提交后重取快照，加 3 个 store 回归用例。
    2. `/web-api/auth/tenants` 返回 `tenant_id`（TenantMembershipSummary），前端误用 `id` → 新增 TenantMembershipOption 类型，修 Profile 单选与顶部切换器绑定。
    3. 409 冲突条先置位后被 hydrate 的 commitIfFresh 立即复位 → 调整为先 hydrate 后置位。
    4. 成员/部门/企业审计页缺 tenant watch，顶部切企业后表格残留上一企业数据（后端作用域始终正确）→ 三页补 watch，成员页部门/角色目录随上下文重载。
    5. el-dialog 固定像素宽度 390px 溢出 → min(Npx,92vw)（含平台侧共 13 处）+ 窄屏消息框约束。
    6. OpenAPI `/web-api/auth/tenants` 响应误写 `{items}` 信封 → 订正为裸数组（与实现/前端一致，36/36 契约测试仍绿）。

## 8. 耗时、环境等待（如实记录）

- 无统一计时埋点；以下为证据文件本地时间（UTC+8）跨度，不等于纯人工操作时长：Gate0 首证 2026-10-15 01:05；第 6 组证据跨度约 08:19–12:42（约 4h23m，含 mvn/vite 构建等待、容器停启等待、浏览器自动化反复取 ref）；第 7 组约 12:47–13:18（约 31m，含性能采集两次复跑、scratch 恢复实例启动约 20–40s/次）；接手轮约 13:56–14:35（约 39m，含状态核实、双企业建档/夹具、浏览器三段反复取证与两轮前端重建回归）。
- 环境等待：Apple Container 停启后 healthz 轮询（PG 恢复最长约 10–20s）、第二 Spring Boot 实例启动、Maven 全量测试、Playwright/Edge 启动。均为本机自有容器，无外部协调等待。
- 协调者接管次数：1（前序 Agent 额度中断后由接手 Agent 完成 6.5/6.6/6.7 收尾）。
- 平台 Token/费用计量：**未采集**。

## 9. 保留项与风险

1. ~~C29/C26/C30 企业内真实浏览器证据待授权~~ **已闭环**（2026-10-15 下午，用户在交接消息中授权夹具）：夹具幂等执行两次无重复；证据见 group6/tenant-switch/；种子账号/企业（uia-082225、UIAA/UIAB-082225、uia-mbr-a/b-0822 等）保留在本任务自有开发库供复验，可用 `seed-browser-fixture.sh --cleanup` 清理成员关系。
2. C25 c=30 尾延迟超目标（见 §5），属环境与 SQL 轮次问题，不得在后续用正向授权缓存"修数字"。
3. 生产部署注意：jar 工作目录须为项目根（`file:./web/dist/` 默认相对路径）；生产 cookie 为 `__Host-air_iam_*`（Secure），dev 为 `air_iam_dev_*`；域名未定，外部 Origin/回调默认不放行。
4. 平台管理员无法通过 API 授企业角色（设计如此）；企业首位 admin 只在开通/迁移流程落库。
5. `/demo/{agent,kb}` 是合成消费者演示页，不代表六图/知识库两个真实系统已接入；不得对外宣称整体迁移完成。
6. 接手轮在浏览器取证中抓出的登录丢菜单/企业、tenant_id 错配等四缺陷说明：平台侧既有浏览器证据多用整页跳转，掩盖了 SPA 内部登录/切换路径；后续前端回归应包含"登录后不刷新直接 SPA 导航"与"停留当前页顶部切企业"两类路径。

## 10. HTTP 契约版本摘要（冻结于 I1）

- OpenAPI：`contracts/openapi/iam-identity-v1.openapi.yaml`，version **1.0.0**，openapi 3.1 自校验通过、required paths 齐全、不含 password_hash/令牌/密钥字段。
- 信封 schema 版本：身份 `iam.identity.v1`；inactive `iam.introspection.v1`；错误信封 `{error:{code,message,request_id}}`。
- 稳定约定：UUID 字符串、RFC3339 UTC、修订号非负整数（拒绝 bool/字符串伪整数）、分页默认 20 最大 200、`Cache-Control: no-store`、DTO 全 SNAKE_CASE、管理端点双前缀 `/v1/admin` 与 `/web-api/admin` 同权。
- 兼容性策略：1.0.0 已冻结，字段只增不删/枚举只增；破坏性变更须升 schema_version 与消费者协议测试器反例。

## 11. 后续交接

- **I1a（entitlement/资源型权限）**：资源开通/回收/重新开通；落地后放开资源型权限组（当前整组缺席 + DB 触发器 23514 兜底）；重测服务账号资源边界。
- **I2**：C14 主模型/摘要/子 Agent/MCP 重试的发送边界与中间撤销；C21 真实六图矩阵；接入后再做消费方侧 C25。
- **I3**：C19 知识库混合授权、C20 remote/local 分离；真实知识库前端。
- **I4**：C23 旧数据/偏好锁/混合审计、C24 真实拆库快照/回退；在旧库演练前不得复用本验收结论。
- tasks.md 6.1–6.7、7.1–7.5 已全部勾选（36/36）；夹具授权与双企业浏览器证据在接手轮闭环。等待用户独立验收后再决定同步主规格/归档，不自动开启 I1a 等后续 change。
