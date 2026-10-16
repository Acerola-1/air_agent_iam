# 首期任务（36/36 项完成：第1–7组）

只实施I1独立IAM。I1a资源开通、Agent/KB切换、物理拆库另立change；未获新授权不改两Python仓库或其数据库/服务。每个任务有自己的验证，不能最后才补授权测试。

## 1. Gate0：契约与工程初始化

- [x] 1.1 核实JDK21、构建工具、Boot4专用starter/Redis插件/Jackson3依赖并锁版本，交版本说明；验收：Maven Wrapper干净构建和真实服务启动，C01。
- [x] 1.2 将http-contract.md固化为OpenAPI3.1/JSON Schema、身份正反样本与协议消费者测试器；验收：样本校验及缺字段/错类型/aud/inactive反例，C04/C12。
- [x] 1.3 建server/web/contracts与环境配置形状，启动端口检查及自有PG/Redis说明；验收：只回环监听、无默认生产密码、未读源.env、未停共享服务。
- [x] 1.4 创建合成bcrypt双向固定向量及rt-v1 Java/Python签验工具；验收：C02/C03，ASCII/中文/错误口令/字节边界、kid/aud/过期/篡改均有结果，秘密不进报告。

## 2. 身份模型与数据库防护

- [x] 2.1 实现users/tenants/departments/memberships及同租户复合FK/无环约束，记录DDL映射；验收：空库迁移、重复迁移与跨企业直写拒绝，C08。
- [x] 2.2 实现角色/权限/关联、scope唯一性和可授标记，保留资源关联预留且无entitlement默认拒绝；验收：企业不能授平台/他企业/资源未开通权限，C09。
- [x] 2.3 分离owner/request角色，事务本地GUC/行策略/列权限与连接池清理；验收：真实非owner A/B/无作用域/异常取消回收对照，C10。
- [x] 2.4 实现显式bootstrap与合成UUID导入/预检、幂等种子，说明旧表不会被本迁移接管；验收：重复执行无重复且不重置密码，C04及无源库写入证明。

## 3. 会话、修订与实时核验

- [x] 3.1 实现有状态Sa-Token+独立Redis与PG会话权威、用户登录/退出/全退；验收：C04/C05，旧Redis残留不得放行，token不落日志。证据：docs/reviews/evidence/group3/c05-c06-c07-c11-c16-session-authority.txt（B1-B3、B7-B9 + c05 三用例）。
- [x] 3.2 实现/me、本人企业列表、未选择/停用上下文DTO与实时权限；验收：同用户A/B、多企业不自动选首家、platform角色不变成员，C04/C06。证据：B4 + c06_suspendedTenant/c05_identitySerialization。
- [x] 3.3 实现switch-tenant CAS及四修订推进规则，交修订触发表；验收：并发200/409与A→B→A旧页拒绝，C07。证据：c07_switchTenantCasHappyPathAndStaleCtx、c07_concurrentSwitchWithSameExpectedExactlyOneWins（两条真实iam_app连接FOR UPDATE决胜）。
- [x] 3.4 实现改密/重置/账号停用与角色撤销后的会话失效；验收：权威事务提交后下一次introspection拒绝，C05/C06。证据：c06_passwordChangeRevokesOtherSessionsButKeepsCurrentAligned、c06_disabledUser、c06_roleRemoval。管理员重置入口随5.1提供，撤销原语（revoke_user_sessions+修订对齐）已在本组验证。
- [x] 3.5 实现绝对/空闲到期及renew，交期限说明；验收：C16边界、过期/撤销不可复活、并发不回退期限。证据：c16_renewAdvancesIdleAndRejectsStaleCtx、c16_expiredSessionCannotBeResurrectedByRenew + B5。
- [x] 3.6 实现PG与Redis部分失败/崩溃窗口清理outbox；验收：C11，审计/权威事务失败回滚，清Redis失败不恢复已撤销许可。证据：c11_auditFailureRollsBackRevocationAndOutbox、c11_outboxRelayDeletesRedisKeyAndMarksDone、c11_outboxFailureIsRetriedWithBackoffThenCompletes + B8（Redis键实删、outbox done）。

## 4. 内部客户端、运行票据和服务主体

- [x] 4.1 实现受众/scope受限内部client凭据及introspection，保持不透明token；验收：C12错client/aud/类型/依赖失败语义，原始凭据不返回普通/me。证据：InternalClientIntegrationTest 23 用例 + evidence/group4/c12-c13-c03-c15-internal-principals.txt A段/B1/B2（错密钥401、scope不足403、受众白名单403、垃圾主体200 inactive schema iam.introspection.v1）。
- [x] 4.2 实现绑定client/受众/原会话/四修订的verification_ref及实时复查；验收：C13，错服务/伪造/越权换票拒绝，短入口过期仍可核验长运行，撤销后拒绝。证据：c13_* 6 用例（revisionChangeAfterIssuanceRejectsRecheck、verificationRefHappyPathAndAudienceBinding、stored/supplied/current三修订比对）+ B4（复查active/篡改revision_mismatch/未知ref invalid_or_revoked/登出即时撤销）；ref TTL 12h 与 60s rt 票独立，valid_until=min(ttl, 会话绝对到期)，凭据零持久化（仅 sha256 摘要的会话引用）。
- [x] 4.3 实现rt-v1内部签票与兼容门面设计，不接管Agent内部业务端点；验收：C03/C13，target/ctx冲突409，浏览器无内部client不能签发，rs/mt不通用化。证据：c03_* 用例（ctxMismatch 409、机器令牌签票401、exp夹至会话上界）+ B3 Python 真实 IAM_RT_KEYS_SECRET 原字节验签 + evidence/group4/c02-c03-cross-language-vectors.txt 双向6向量；端点仅 /v1/internal/runtime-tickets（Basic+scope runtime-ticket:issue），未新增任何业务端点。
- [x] 4.4 实现服务账号/令牌和internal_client主体分型、期限/轮换/立即撤销；验收：C15，不能切企业、伪装membership或调用平台管理，资源权限默认不可用。证据：c15_* 5 用例 + B5（主体type=service_account/realm=service、user/session/membership=null、四修订整体null、知识受众绑定、24h重叠轮换、365天上界、吊销inactive、应用层400+DB触发器23514双重拒绝资源型权限）。
- [x] 4.5 实现无正向授权缓存的超时/限流/错误映射，并交调用方接入说明；验收：C11/C12，断网503，无旧身份或local回退。证据：RateLimitIntegrationTest 2 用例（登录2/min、内部3/min真实429）+ B6（第11次429）+ B7（停Redis登录503 dependency_unavailable失败关闭，恢复轮询后200自愈未重启）；introspection 每次读PG主库load_*_identity，无任何正向授权TTL缓存；接入契约以 http-contract.md 第4–6节为准（Basic客户端→introspect/复查；rt票仅langgraph-runtime受众；429/503由调用方退避而非本地放行）。

## 5. 企业管理与审计API

- [x] 5.1 实现平台用户建档/详情/停用/改密/平台角色及企业建档/状态，文档列权限；验收：平台与企业正负例，账号冲突、全局越权拒绝。证据：AdminApiIntegrationTest#userLifecyclePasswordResetAndLastAdmin、#tenantCreateStatusAndRevision（8 测试全绿，全量 63/63）；弱口令 400/重复 409/资料 CAS 不推进修订/重置密码即时撤会话 401/最后超管 409/企业管理员越权 403。
- [x] 5.2 实现成员关联/部门/状态/角色和部门树API，保持显式关联与同租户；验收：C08/C09，A修改不影响B，不按同名账号自动关联。证据：#memberIsolationNoAutoMergeAndOptimisticRevision、#departmentTreeRejectsCycleAndCrossTenant；同名不合并 409（查重先于口令校验）、显式 user_id 关联、角色全量替换 DELETE+INSERT 推进修订、停用成员 introspection 即时 403；停用成员用户摘要经 V9 SECURITY DEFINER 函数受控读取。
- [x] 5.3 实现企业/平台角色与权限可授树、最后管理员并发保护；验收：C08/C09并发，内置角色不构成授权旁路。证据：#customRoleBoundaryBuiltinProtectionAndGrantableTree；越 scope 授权 409、内置角色 PATCH 403、可授树企业上下文无平台组、资源型权限整组缺席；最后管理员由 DB 触发器+应用层双保护。
- [x] 5.4 实现身份审计与授权修改同事务、日志分页/计数隔离；证据：#auditLogsArePartitionScoped（平台见 NULL 租户/企业仅本租户，RLS 强制）、#whenAuditCannotBeWrittenAuthorizationChangeRollsBack（REVOKE write_audit 后建档回滚行数 0，finally GRANT 恢复）；AdminSupport.audit 失败抛 IllegalState 回滚，detail 去 null。
- [x] 5.5 实现应用菜单与管理写入tenant/ctx并发声明，固定管理API契约；验收：C07/C09与分页最大200、直接调用拒绝越权。证据：契约 iam-identity-v1.openapi.yaml 管理端占位已全部细化（45 paths/52 schemas，引用一致性校验通过，不含 password_hash/令牌/密钥）；limit 1–200 钳制、坏游标 400；企业令牌访问平台接口 403；黑盒脚本 scripts/verify-admin-apis.sh（A 段 8 集成测试 + B1–B8 真实 curl）全绿，证据 docs/reviews/evidence/group5/admin-apis.txt（含秘密零命中扫描）。

## 6. Vue中文后台与Java浏览器适配

- [x] 6.1 初始化Vue3/TypeScript/Vite/Router/Pinia/Element Plus与唯一依赖锁，建立中文页面壳、history路由与API客户端；验收：vue-tsc、单测、干净build及生产深链接/缺失资源反例，C27；提交可复跑命令和模块说明。
  - 证据：web/（vue3.5/vite7/router4/pinia3/EP2.14，锁版本不追新主版本）；`npm run typecheck` 0 错；vitest 14/14（scope A→B→A 纪元、usePagedList 迟到丢弃/abort、LoginView 401/503/成功）；`npm run build` 干净产出 web/dist；生产同源深链 200 HTML、缺失 assets 返回 JSON 404（verify-web-session-final.sh SPA 段 + browser-evidence.md C27）。
- [x] 6.2 在Spring Boot实现/web-api会话句柄/安全DTO/CSRF及授权转接，不新增Node BFF；验收：真实浏览器登录/刷新/空企业/403/503/退出、JS无会话Bearer、内网端点不被代理，C17/C28；更新HTTP样本。
  - 证据：BrowserSessionIntegrationTest(9) + scripts/verify-web-session.sh B1-B4（回环监听/CSRF四闸/登录响应无令牌/句柄轮换/双挂载同权/重置密码即时401/未知路径JSON404），docs/reviews/evidence/group6/web-session.txt。
- [x] 6.3 实现中央登录到自有合成BFF双客户端的一次性ticket/白名单/state/兑换，Java接收服务端回调并保留中央session与ctx；验收：C17，ticket重放/错回调/CSRF拒绝，全局登出下一请求拒绝。
  - 证据：verify-web-session.sh B5（start 303→回调服务端兑换→BFF cookie/me 受众 air-agent/knowledge、独立会话 id、回调重放拒绝、exchange 重放 401、错密钥 401、错回调 start/exchange 400、agent↔kb 不互通）；合成演示页 server/src/main/resources/static/demo/{agent,kb}/index.html。真实浏览器点击证据随 6.7 补。
- [x] 6.4 固定生产/dev cookie和同源静态资源、CORS/回调配置，交部署示例；验收：HttpOnly/生产Secure/host-only、无通配凭证或默认外部Origin，域名未定不开放外部跳转，C27/C28。
  - 实现：WebCookies（dev air_iam_dev_*；生产 __Host-air_iam_* 仅 Secure）、SameSite=Lax/host-only、Origin 精确白名单（无通配）、回环回调断言、同源 classpath/file 静态托管（无 /** 兜底）。部署示例在验收文档第7组汇总。
- [x] 6.5 用Vue实现账号/企业/部门/成员/角色/权限/审计、资料改密/会话页面，仅复用原字段/契约/行为；验收：C26真实建档授权、保存失败/冲突、刷新持久化，源React页面和业务页面未改，提交页面-权限映射。
  - 证据：docs/reviews/evidence/group6/tenant-switch/dual-tenant-browser-evidence.md。真实浏览器（生产同源 19100 + 系统 Edge）：甲企业真实新建中文部门/成员（新账号+部门+tenant_reader 授权）/自定义角色勾选企业可授权限；重复建档红色错误且对话框不关闭可恢复；角色 CAS 全量替换；整页刷新上下文与数据持久化；乙企业独立建档；A/B 服务端作用域 fetch 复核零串数据；tenant_admin 直连平台用户接口真实 403。平台侧证据见 browser-evidence.md §C30；搜索参数对齐契约 q，无契约搜索的列表已去伪搜索框；源 React/Next 页面与业务页面未改。
- [x] 6.6 实现Vue会话/菜单/草稿scope与epoch、请求取消和上下文冲突刷新；验收：C07/C29，A→B→A迟到、并发切企业、退出后旧响应不污染，未授权直连后端仍拒绝；更新状态规则说明。
  - 证据：vitest 17/17（scope 8、usePagedList 3、auth store 3、LoginView 3）+ tenant-switch/stage2-cas-late.log。夹具经用户交接授权执行（幂等两次无重复）：同一会话双标签真实切企业，旧 ctx_version 标签收到服务端真实 409，冲突条出现且自动 hydrate 到获胜方，"立即刷新上下文"整页恢复；甲部门在途响应延迟 3.5s 在切乙后到达被序号+scope/epoch 双守卫丢弃，乙→甲正常恢复；退出时在途响应后到仍停留登录页；未授权直连后端 403。
  - 接手修复（浏览器取证抓出的真实缺陷）：①login() 快照早于 identity 提交导致登录后菜单/企业列表被新鲜度守卫丢弃（此前被整页 goto 掩盖）；②TenantMembershipSummary 字段 tenant_id 与前端 id 错配导致单选/切换器失效；③409 冲突条被随后 hydrate 的成功提交立即清除；④成员/部门/企业审计页缺 tenant watch，顶部切企业后表格残留上一企业数据。OpenAPI /web-api/auth/tenants 响应形状由误写的 {items} 信封订正为裸数组（与冻结实现一致，契约 36/36 仍绿）。
- [x] 6.7 完成加载/空态/错误/冲突、键盘/焦点/窄屏与权限按钮交互；验收：C26/C30真实浏览器390×844和桌面、键盘/IME/错误恢复，Vue组件测试及无秘密证据。
  - 证据：tenant-switch/stage3-narrow.json + 截图 30–34；desktop stage1 18/18；browser-evidence.md 既有错 CSRF 403/错密码 401/依赖故障 503。390×844 系统 Edge：租户页侧栏隐藏/汉堡抽屉含完整租户菜单/Escape 关闭/路由自动关；新建成员对话框不溢出且中文真实录入、Escape 关闭；窄屏真实新建"窄屏建档部"；localStorage/sessionStorage 0 键。接手修复：全部 el-dialog 固定像素宽度改 min(Npx,92vw)（含平台侧 8 处）+ ≤768px 消息框宽度约束。秘密扫描 tenant-switch/secret-scan.txt PASS（9 秘密零命中，日志 CSRF 已脱敏）。

## 7. 首期独立集成与交付

- [x] 7.1 建真实HTTP+PG+Redis的C01–C17相关首期矩阵，沿稳定ID映射旧断言；验收：逐项正反证据，不以mock冒充实际两Python服务接入。
  - 证据：scripts/verify-acceptance-matrix.sh 8/8 段全绿（gate0/crypto/contract/db/session/internal/admin/web），docs/reviews/evidence/group7/matrix/matrix-20261015T045149Z.txt；C-ID→证据映射见矩阵文件尾注与 docs/reviews/iam-phase1-acceptance.md §3。联修：契约测试漏传 FormatChecker 导致 UUID 反例未拦，恢复后 36/36。
- [x] 7.2 测暖连接核验至少100样本×3轮及并发1/10/30，模拟顺序多次调用与依赖故障；验收：C25报告P50/P95/P99/错误/调用数，超标如实定位、不改成授权缓存。
  - 证据：scripts/verify-perf-introspection.sh + tools/perf_introspection.py + docs/reviews/evidence/group7/perf-introspection.txt。c=1 P95≤8ms、c=10 P95≤20.4ms 达标；c=30 P95 40.7–404.8ms 超目标（同机容器 PG 排队，如实定位，未加授权缓存，未破 500ms deadline）；停 Redis 登录 503、停 PG introspect 30/30=503、恢复后 200。
- [x] 7.3 做新项目自有数据备份/恢复与撤销重施演练，交运行/恢复说明；验收：恢复前撤销不复活，角色限制仍生效，明确不代表源库拆库演练。
  - 证据：scripts/verify-dr-restore.sh + docs/reviews/evidence/group7/dr-restore.txt（PASS）：pg_dump -Fc 备份→恢复到一次性 scratch 库+19102 实例→按审计重施重置密码/撤角色，旧会话仍 invalid_or_revoked、新会话 403、陈旧修订 409；scratch/实例/dump 即毁；明确不构成 C24。
- [x] 7.4 核对本包任务与spec场景、秘密扫描、构建/静态/浏览器证据，写docs/reviews/iam-phase1-acceptance.md；验收：逐项证据索引，未实现/依赖阻塞不勾选，记录分阶段实际耗时/修复轮次。
  - 交付：docs/reviews/iam-phase1-acceptance.md（环境/复跑命令/C01–C30 证据索引/72 后端+14 前端+8 矩阵段结果/C25 实测与超标/灾备/修复轮次/耗时/保留项/契约摘要/交接）。
- [x] 7.5 发布固定HTTP契约版本/摘要与后续I1a/I2/I3/I4交接清单；验收：旧仓库源码/配置/正式数据未改，未commit/push/归档，不能宣称整体迁移完成。
  - 证据：`openspec validate establish-shared-iam-service --strict` valid；契约 1.0.0 / iam.identity.v1 / iam.introspection.v1 摘要与交接清单在验收报告 §10–§11；秘密扫描 scripts/verify-secret-scan.sh 9 秘密零命中（group7/secret-scan.txt）。两 Python 仓库只读，工作区非 git 仓库无 commit。

## Workflow follow-up

- 用户独立验收后再决定同步主规格/归档；本包不自动创建或实施entitlement/消费方/拆库change。
- 资源目录/开通在I1a实现，知识库remote上线依赖它；接管真实身份写者必须由后续I2明确维护窗口与回退，不在本包试切。
