# I1 阶段工作日志（过程记录）

时间均为 Asia/Shanghai。Token 计量：工具未提供，**未采集**。最终验收报告另见 `docs/reviews/iam-phase1-acceptance.md`。

## Gate0（第1组）

| 时间 | 事项 | 结果 |
|---|---|---|
| 2026-10-15 ~00:40 | 阅读全部规划文件（README/proposal/design/http-contract/2 份 spec/tasks/vue-admin-plan/reference×3/provenance） | 完成；OpenSpec 根为本项目，`openspec validate establish-shared-iam-service --strict` 通过，0/36 |
| 00:45 | 环境核实：JDK21 Corretto、Maven 3.10、Node 26.11.1、Apple Container 1.5.0、无 docker；端口 19100/19101/19132/19179 空闲（5432 为共享 PG，未触碰）；源仓库 HEAD=8620cf7、工作区干净，与授权描述一致 | 完成 |
| 00:50 | Maven Central 元数据核实：Boot 4.0.8（4.0 线最新补丁，不追 4.1/4.2-M）、Sa-Token `sa-token-spring-boot4-starter` 1.45.0/1.46.0，锁定 1.46.0 | 版本锁定 |
| 00:52 | 自有卷 iam-pg17-data/iam-redis7-data + 容器 iam-pg17/iam-redis7，仅 `127.0.0.1:19132/19179`；角色 iam_migrate/iam_app 四 NO；LAN IP 不可达实测 | 完成（修复见下 #1/#2 为脚本侧） |
| 00:58 | JDK21 Maven Wrapper 干净构建成功（Spring 7.0.9/Tomcat 11/Jackson3 3.1.5/Flyway 11.14/PG JDBC 42.7.13） | C01 构建证据 |
| 01:02 | 首次真实启动失败：hikari max-lifetime 单位 | 修复 #3（配置） |
| 01:10–01:40 | 1.4 双向固定向量：bcrypt（6 salt/6 用例/3 错口令，ASCII/中文/空/72B/73B 截断）+ rt-v1（6 向量），Python 生成→Java 核验→Python 复核闭环 | C02/C03 通过，证据 group1/c02-c03 |
| 01:15 | spring-security-crypto 枚举/72B 差异 | 修复 #5、#6 |
| 02:00–02:30 | 1.2 契约冻结：OpenAPI 3.1（全端点+错误信封+安全方案）、4 份 JSON Schema 2020-12、4 身份正样本/10 反例/13 请求样本、协议消费者测试器 | 36 项断言全绿，C04/C12 证据 group1/c04-c12-contract-freeze.txt；修复 #11 |
| 02:31–02:37 | 1.3 `.env.example` 形状（秘密全空）+ verify-gate0-env.sh：回环监听/无硬编码/600 权限/无源仓库引用/HEAD 基线/容器清单 | GATE0-ENV ALL PASS，证据 gate0/c13-loopback-env-shape.txt；修复 #12 |

### 第2组（身份模型与数据库防护）

| 时间 | 事项 | 结果 |
|---|---|---|
| 01:20–01:50 | V1 身份模型 25 表（users/tenants/departments/memberships/roles/permissions/会话机器表/outbox/审计）+ iam_auth 函数族；V2 幂等种子（20 权限/4 角色/27 映射/1 资源目录，固定 UUID 前缀） | 空库迁移 + 二次启动 "up to date" 证幂等 |
| 01:50–02:20 | DbIsolationIntegrationTest：profile it、Hikari pool=1 证 GUC 不泄漏；A/B/无上下文、跨租户复合 FK、自定义角色跨租户、授权边界、资源闸门默认拒绝、无环、最后管理员（含交错并发）、平台超管、outbox SECURITY DEFINER 函数、机器表 RLS 拒绝 | **12/12 绿**，证据 group2/c04-c08-c09-c10-c16-db-isolation.txt；修复 #2/#4/#7/#8/#9/#10 |

### 第3组（会话、修订与实时核验）

| 时间 | 事项 | 结果 |
|---|---|---|
| 02:40–03:10 | V3 会话修订基线/推进触发器/iam_auth 权威网关（create/revoke/revoke_user/switch CAS/renew/set_password/align/load_authority_snapshot）；V4 write_audit+ensure_bootstrap_user；V5 引导平台上下文；V6 摘除 auth_sessions 误挂 updated_at 触发器 | 空库迁移到 V6 幂等 |
| 02:50–03:25 | Sa-Token 1.46 摘要适配（DigestStpLogic：Redis 仅存 SHA-256 摘要）、OpaqueTokens 32B 随机不透明令牌、SessionService 全链路（登录补偿/登出/全退/me/menus/tenants/切企业 CAS/续期/改密）、IdentityAssembler、BearerAuthInterceptor、GlobalExceptionHandler（依赖故障 503 失败关闭）、OutboxRelay 定时中继、BootstrapRunner 弱口令拒绝 | 真实 HTTP 冒烟全链路通过 |
| 03:26–03:42 | SessionAuthorityIntegrationTest 首轮 16 用例：5F+7E → 定位修复（见修复轮次 #13–#20）→ **16/16 绿**；全量回归 30/30 绿 | 证据 group3/c05-c06-c07-c11-c16-session-authority.txt |
| 03:43–03:56 | verify-session-authority.sh：A 段真实 PG/Redis JUnit 16 用例；B 段黑盒 HTTP（错口令信封/无令牌/垃圾令牌/登录四修订/me/menus/tenants/续期/陈旧 ctx 409/非成员 403/登出 204→401/Redis 键实删/outbox done/审计无秘密/日志零命中） | 一次复跑全绿（脚本自管实例，含日志扫描） |

### 第4组（内部客户端、运行票据和服务主体）

| 时间 | 事项 | 结果 |
|---|---|---|
| 04:05–04:25 | V7：service_tokens.credential_revision+重叠窗 CHECK；authenticate/ensure_internal_client；create/find/touch_verification_ref；issue/revoke_service_token、load_service_identity（权限过滤 resource_code IS NULL）；load_authority_snapshot_for_session | 两库干净重建到 V7；修复 #22 |
| 04:10–04:35 | Java：InternalClient 记录/Basic 认证器（28000/28P01→401）、RateLimiter（Lua 固定窗口+503 失败关闭）、InternalClientInterceptor、IntrospectionService（token/ref 两形、audience 白名单、409 context_changed、revision_mismatch）、RuntimeTicketService（仅人类、rt-v1、60s 夹会话上界）、ServiceAccountService/AdminController（同事务授权+审计、365d/24h 上界、一次性明文） | main 编译+jar 打包通过；修复 #23–#25 |
| 04:30–04:40 | RateLimitIntegrationTest 2 用例（低阈值 profile、主体名 UUID 化防跨复跑污染）；application-it.yml 限流调宽避免高频 IT 429 | 2/2 绿；修复 #26 |
| 04:36–04:50 | InternalClientIntegrationTest 23 用例首轮 1F+4E → 读真实堆栈定位（不猜）→ 修复 #29–#33 | **23/23 绿**；全量 **55/55 绿**（2+12+16+23+2） |
| 04:50–04:53 | rt-v1 Java→Python 反向验签（Python 用真实 IAM_RT_KEYS_SECRET 原字节）+ bcrypt Java→Python 复核 | 6+6 向量 0 失败，证据 group4/c02-c03-cross-language-vectors.txt |
| 04:53–05:05 | scripts/verify-internal-principals.sh：A 段 25 JUnit；B 段黑盒 B1–B8（认证反例/人类 introspect/切企业签票 Python 验票/ref 复查三态/SA 分型+触发器 23514/429/停 Redis 503→恢复 200/秘密零命中） | 首轮起 5 轮脚本修复（#30/#33/引号/STDOUT/口令长度/Lettuce 重连窗口），终轮一次全绿；证据 group4/c12-c13-c03-c15-internal-principals.txt |

### 修复轮次

1. `container run -c listen_addresses=*` 与 Apple Container `-c/--cpus` 冲突 → 删除（postgres 镜像默认监听全部，端口发布限定回环）。
2. Apple Container 命名卷根目录含 `lost+found`，PG initdb 拒绝 → 卷挂到 `/var/lib/postgresql` 父目录；service_accounts 补 `(tenant_id,id)` 唯一键供复合 FK；membership_roles DELETE 触发器拆 delete/update 两个。
3. Hikari `max-lifetime: 30m` 绑定为 long 失败 → 改毫秒 `1800000`；加 commons-pool2；显式引 `spring-boot-flyway`；iam_migrate 补 GRANT CREATE ON DATABASE。
4. 内置企业角色 tenant_id=NULL（全局模板）无法匹配原复合 FK → 改普通 role_id FK，同租户约束移入 `guard_role_assignment_boundary` 触发器（SQLSTATE 23514）；触发器内 uuid/text 变量须分型。
5. spring-security-crypto 7 枚举为 `BCryptPasswordEncoder.BCryptVersion.$2B` → 最终直接用 BCrypt 静态方法。
6. Spring BCrypt 严格拒 >72 字节，Python bcrypt 截断 → PasswordHasher 手工按 UTF-8 截 72 字节，73B 用例两侧等价。
7. 测试清理 `TRUNCATE tenants CASCADE` 会清空角色种子 → @BeforeEach 改 migrate 连接 TRUNCATE users/tenants 后从 classpath 重放 V2（单一事实源）。
8. 同事务连续断言失败语句进入 25P02 aborted → `expectDenied` 用 SAVEPOINT/ROLLBACK TO SAVEPOINT。
9. 并发最后管理员初版死锁挂起 → 两线程 CountDownLatch 交错 + lock_timeout=5000，t2 在 t1 commit 后被 AFTER 触发器拒 23514。
10. surefire 输出经 `| head/grep` 管道被 SIGPIPE 杀 Maven 留孤儿 JVM → 重定向文件再 grep。
11. 协议消费者测试器：jsonschema format checker 须在 Validator 构造期注入（非 iter_errors 参数）；OpenAPI web-tenants 缺 properties.items；inactive 泄漏样本映射修正；语义断言改为返回值收集避免污染全局。
12. gate0 环境脚本：自引用扫描误报（排除自身）；口令正则允许占位前空白；源仓库工作区存在外部并发改动（HEAD 8620cf7 不变）→ 改 HEAD 强一致 + 工作区漂移仅 INFO 记录（本包沙箱不可写源路径）。
13. audit_logs FORCE RLS 拒绝无上下文的引导插入 → V5 在 ensure_bootstrap_user 内提权后写审计；SessionService 每个程序化事务开头显式 `set_request_context`（platform 仅当 tenant 为空）。
14. JDBC 调 `SELECT iam_auth.xxx()` 用 update 报"传回预期之外的结果"→ 所有 void 函数调用统一 queryForObject（PG 函数调用恒返回结果集）。
15. /tenants 500：text block 占位符漏传 userId 被 pgjdbc 当字面量 → 补参数。
16. renew 500 `record "new" has no field "updated_at"`：V1 通用 touch 触发器误挂 auth_sessions（无 updated_at）→ V6 DROP TRIGGER。
17. **FORCE RLS 对表 owner 同样生效**：load_authority_snapshot 在空 GUC 下读 tenants/memberships/membership_roles 零行，切企业后快照恒 membership_disabled → 快照加载前先用非 FORCE 的 find_session_by_digest 取会话身份，在同一事务内 set_request_context(user,current_tenant) 再取快照；测试并发 rawSwitch 也必须先建上下文（SECURITY DEFINER 不豁免 FORCE）。
18. 改密后当前会话被误撤销：revoke_user_sessions 与 set_user_password 各推进一次 auth_revision，旧顺序基线差一 → 重排为 revoke→set_password（返回最终修订号）→ align 到最终修订。
19. outbox 删除的 Redis 键与 Sa-Token 实际键不同构：真实键是 `Authorization:login:token:<digest>`（super.splicingKeyTokenValue），自构 `Authorization:<digest>` 删不到 → DigestStpLogic.keyByDigest 改走 super 键构，避免二次摘要。
20. 测试管理侧 DML 无 GUC 时对 FORCE 表静默命中 0 行（租户停用/角色撤销反例因此"不抛异常"）→ migrateUpdate 改单事务内置平台上下文并断言 affected>0；其余：P0010/P0012 在服务边界翻译为 ApiException（PgErrorTranslator 与 @RestControllerAdvice 共用）；登出断言适配 Sa-Token 1.46 键缺失返回 null；测试种子补平台超管占位满足最后管理员保护；outbox mock 测试两轮都返回待投递行；macOS date/container CLI 兼容性修正。
21. Shell 单条调用内 `java -jar &` 会在调用结束被收掉 → 证据脚本统一"自管实例+trap kill"模式（组3脚本定型，组4沿用）。
22. V7 `create_verification_ref` 的 `WHERE id = p_session` 报 `column reference "id" is ambiguous`（OUT 参数名与列名冲突）→ 全部列名加表名限定。
23. Jackson3 无 `tools.jackson.annotation` 包（`JsonInclude` 编译失败）→ 复查响应拆 RecheckActive/RecheckInactive 两 record 形态，不用注解控空；服务层直接返回具体 record，删除多余包装。
24. `ResponseEntity.noContent().contentLength(0)` 编译失败 → 去掉（204 本无实体）。
25. 内部客户端认证失败的 28000 被 PgErrorTranslator 误译成"会话无效"消息 → PgErrorTranslator 增 sqlStateOf(UncategorizedSQLException)，认证器对 28000/28P01 显式返 401「内部客户端凭据无效或客户端已停用」，与"主体失效 200 inactive"语义分离。
26. 限流默认 10/min 使 SessionAuthorityIntegrationTest 高频登录触发 429 → application-it.yml 调宽 100000，429 语义交给独立 RateLimitIntegrationTest 低阈值覆盖；该测试主体名每轮 UUID 唯一，防固定窗口跨复跑 flaky。
27. run_in_background 下 `$JAVA_HOME/bin/java` 展开成 `/bin/java`（127）→ 一律 Corretto 绝对路径。
28. V7 首版修改后 iam/iam_test 两库 DROP SCHEMA 重建（V7 当时仅开发期首次应用；之后迁移已固化，不再轻改）。
29. InternalClientIntegrationTest 五连失败（读 surefire 真实堆栈，非猜测）：(a) JdbcTemplate 单参数传 String[] 被 Java varargs 展开成多个标量参数，`ANY(?::text[])` 报 malformed array literal → 强转 `(Object) array`；(b) codesOf 的 `?::uuid[]` 经 Spring/pgjdbc 绑定为 varchar 标量同样 malformed → 删除该反查，创建响应直接回显已校验码；(c) c13 测试 adminA 从 T_A 切 T_B 但种子漏 adminA∈T_B 成员 → 补 M_ADMIN_A_IN_B(...3006)+T_B reader 角色；(d) service_accounts 无 updated_at 列却被 V1 通用触发器循环误挂（同 #16 auth_sessions）→ V7 DROP TRIGGER；(e) 服务令牌 introspect 需 knowledge 受众客户端，而测试仅注册 langgraph-runtime → 补 it-knowledge-client（scope introspect/audience knowledge）。
30. SA 轮换 overlapHours=24 整点被 DB 拒（应用 now 早于 SQL issued_at，24h 硬上界差毫秒级）→ 应用侧 overlap 减 1 秒（23:59:59，语义仍 ≤24h）。
31. 契约一致性：SA introspection 的 revisions 序列化成全 null 字段对象，与"四修订不适用为 null"不符 → ServiceIdentityResponse.revisions 直接给 JSON null，测试断言同步。
32. 证据脚本两处 `python3 -c` 单行中中英文案+嵌套引号导致 bash 引号不配对（line 406 unexpected EOF）→ 统一改写 `<<'PY'` heredoc + 环境变量传参。
33. 证据脚本黑盒细节：psql NOTICE 走 stderr 未进 tee 文件导致 23514 grep 失败（加 `2>&1`）；B6 错口令 5 字符被 validateLogin 以 400 拦在限流之前（换 ≥8 字符错口令，第 11 次准时 429）；B7 Redis PONG 后 Lettuce 重连有 ~3s 窗口，首次登录仍 503 → 恢复轮询（失败关闭期间持续 503 是正确行为，第 4 次轮询 200 自愈，未重启服务）。
34. AdminSupport 漏 `java.util.List` import 编译失败；lambda 捕获非 final 局部变量（RoleAdminService/SA 列表 tenantId）→ 改 final-else-null 形态。
35. roles 列名是 `is_builtin` 非 builtin；description 插入用 `COALESCE(CAST(? AS text),'')`；企业上下文 INSERT iam.users 被 RLS WITH CHECK 拒（users 仅平台/自身可插）→ createMembership 单事务两段：平台上下文建全局用户，切回租户上下文插成员/角色。
36. CHECK/层级成环被 Spring 包成 DataIntegrityViolationException/DuplicateKeyException，catch 不住 UncategorizedSQLException → PgErrorTranslator 加宽 `toApiException(DataAccessException)`，admin 服务统一切换；23514 消息覆盖最后管理员/成环/可授边界。
37. service_tokens 对 iam_app ENABLE RLS 无 policy 直读零行 → V8 SECURITY DEFINER `list_service_tokens(uuid)`（不返 token_digest）GRANT iam_app。
38. 成员角色修订号想当然：建成员带角色触发器即推进（1→2），全量替换 DELETE+INSERT 各推进一次（2→4），测试 expected 两轮修正；users.auth_revision 新建=0（改资料不推进）、tenants/memberships 新建=1。
39. 停用成员后 memberView 500 EmptyResultDataAccessException：membership USING 可见但 users_policy 的"同租户活跃成员"分支随停用失效 → V9 SECURITY DEFINER `member_user_brief(uuid)` 经成员键受控读取摘要（不含口令列），授权仍由服务层+memberships RLS 把关。V8 已在 iam_test 应用，新增函数必须放 V9 避免 Flyway checksum 漂移。
40. 审计回滚测试初版只 REVOKE iam_app 无效（函数默认 EXECUTE 给 PUBLIC）→ 必须 `REVOKE EXECUTE ... FROM PUBLIC, iam_app`；组件把写入失败包成 IllegalStateException（非 ApiException），断言 RuntimeException + 用户行回滚 0，finally `GRANT EXECUTE ... TO PUBLIC` 恢复。

### 第5组阶段记录（企业管理与审计 API）

- 新增：admin 包 6 控制器 + 4 服务 + AdminDtos/AdminSupport；V8（SA 列表 SECURITY DEFINER）、V9（停用成员用户摘要）迁移；AdminApiIntegrationTest 8 用例；scripts/verify-admin-apis.sh（A 段 8 集成测试 + B1–B8 真实 HTTP 黑盒）；OpenAPI 管理端占位全部细化（45 paths/52 schemas，Python YAML+引用一致性校验通过）。
- 结果：AdminApiIntegrationTest 8/8 绿；全量回归 63/63（前 55 无破坏）。
- 黑盒脚本覆盖：用户全生命周期/重置即时撤会话/最后超管 409、企业 CAS/停用、成员不自动合并/显式关联/停用 403/平台-企业越权 403、部门成环 409、角色可授边界/内置保护/可授树无平台组无资源码、审计隔离/坏游标/页宽钳制、SA 列表详情无明文/停用即时 inactive/恢复、证据与日志秘密零命中。
- 黑盒结果：scripts/verify-admin-apis.sh 全绿（A 段 8 集成测试 + B1–B8 真实 HTTP），证据 docs/reviews/evidence/group5/admin-apis.txt（161 行）；B8 证据文件+服务日志秘密扫描零命中。iam 开发库经自管服务启动时 Flyway 自动迁移到 V9。修复 #41–#42 后全量回归仍 63/63。
41. 权限目录 listPermissions 漏 resource_code 过滤，企业目录泄漏 knowledge 资源型权限码——黑盒 B5 抓到（单测只断言无 platform: 前缀，未覆盖资源码）→ SQL 加 `resource_code IS NULL`（平台视角 I1 同样不展示，entitlement 留 I1a）。
42. 黑盒脚本三处断言/语法问题：嵌套 heredoc 放进 `$(...)` bash 报 bad substitution（改写临时文件+read）；审计 id DESC 首页 5 条恰全是 B3–B5 租户事件导致 NULL 平台事件断言误报（改为 limit=200 满页集合断言 NULL 与租户事件共存，企业侧仍逐条断言零泄漏）；limit=999 实现是 400 硬拒绝而非钳制（契约参数 maximum=200，语义一致），断言改 400 + limit=200 边界 200。
- 第5组阶段实际投入约 05:12–06:15（约 63 分钟，修复轮次 #34–#42 共 9 类）；Token 未采集。

### 环境等待

- 首次 Maven 构建下载依赖与 Maven 发行包：约 18s（部分中央仓库限速 8–45 kB/s，元数据串行下载）。
- PG 镜像已在本地；容器首次启动含 initdb，约 10s 内就绪。
- jsonschema/openapi-spec-validator 等 Python 依赖安装：约 15s。

### 任务勾选状态

- 1.1–1.4 完成（C01 构建启动、C02/C03 固定向量、C04/C12 契约反例、回环/无默认口令/只读边界证据齐备）。
- 2.1–2.4 完成（12/12 DB 隔离集成测试绿；资源 entitlement 预留且默认拒绝；旧表不接管由"仅自有 iam/iam_auth schema + 独立 iam_pg17 容器"保证）。
- 3.1–3.6 完成（16/16 会话权威集成测试绿 + HTTP 黑盒证据；PG 权威每次主库快照无正向授权 TTL 缓存；改密后当前会话对齐、其他会话即时撤销；outbox 失败退避重放且不恢复许可）。第3组阶段实际投入约 02:40–03:56（约 76 分钟，含两轮 12 项修复）；Token 未采集。
- 4.1–4.5 完成（25/25 第4组集成测试绿，全量 55/55；rt-v1/bcrypt 双向向量 0 失败；黑盒脚本 B1–B8 全绿，含真实停 Redis 503→恢复 200 失败关闭演练；V7 已固化，iam/iam_test 重建到 V7）。第4组阶段实际投入约 04:05–05:05（约 60 分钟，含 12 项修复轮次 #22–#33）；Token 未采集。
- 5.1–5.5 完成（AdminApiIntegrationTest 8/8，全量 63/63；SA 列表/详情/停用已补齐；契约管理端占位全部细化；黑盒 B1–B8 全绿证据 docs/reviews/evidence/group5/admin-apis.txt；iam 开发库 Flyway 到 V9）。第5组阶段实际投入约 05:12–06:15（约 63 分钟，修复轮次 #34–#42）；Token 未采集。
- 已知技术债（不阻塞，第7组处理）：证据脚本会在 iam 库留下 verify-*/b5-* 客户端/企业/用户种子（唯一后缀、无秘密复用风险），最终验收前干净库重建时自然清除。

### 接手轮记录（2026-10-15 下午，第6组 6.5/6.6/6.7 收尾，36/36 闭合）

- 背景：前序 Agent 额度中断，仅剩夹具授权项。接手先核实环境（iam-pg17/iam-redis7 存活、19100 服务存活、51 用户、双企业经平台 API 已建），平台 API 重置 uia-082225 口令后，经用户交接消息授权执行 seed-browser-fixture.sh（连跑两次幂等），登录验证 needs_tenant_selection + 双企业可见。
- 浏览器取证（Playwright 1.58.2 + 系统 Edge，生产同源 19100，非 Vite dev）先抓出 4 个真实前端缺陷：①stores/auth.login() 快照早于 identity 提交，登录后 menus/tenants 被 isFresh 丢弃（整页 goto 走 hydrate 原子提交，长期掩盖）；②TenantMembershipSummary 是 tenant_id，前端 TenantBrief 用 id，Profile 单选/顶部切换器全失效；③switchTenant 的 409 冲突条被随后 hydrate 的 commitIfFresh 立即复位；④成员/部门/企业审计页缺 tenant watch，顶部切企业后表格残留上一企业（后端作用域始终正确，页面内 fetch 复核为证）。附带：el-dialog 固定像素 390px 溢出（13 处改 min(Npx,92vw)+消息框约束）；OpenAPI /web-api/auth/tenants 误写 {items} 信封，订正裸数组。
- 修复后证据：vitest 14→17（新增 stores/auth.spec.ts 3 用例），typecheck 0 错，生产 build 干净且服务中 hash 与 dist 一致；桌面 stage1 18/18（双企业真实部门/成员/角色建档、重复冲突可见可恢复、CAS 角色替换、刷新持久化、A↔B 服务端零串数据、tenant_admin 直连平台 403），连跑两轮幂等；stage2 5/5（同会话双标签真实 409 冲突条+hydrate 获胜方+刷新恢复、3.5s 迟到甲响应在乙被双守卫丢弃、退出在途不污染）；stage3 390×844 全断言（抽屉 Escape/路由关闭、对话框不溢出、中文窄屏建档、零令牌存储）。
- 回归：verify-contract 36/36、verify-web-session 全绿、verify-acceptance-matrix 8/8（matrix-20261015T063455Z）、openspec validate --strict valid、秘密扫描 PASS（新证据 CSRF 值已脱敏）。
- 环境备注：本机 homebrew node 26.11.1 因 simdutf 9.3.0（libsimdutf.37）升级 dyld 崩溃，统一改用 /opt/homebrew/Cellar/node/26.11.1_1/bin/node 跑 Playwright/openspec。
- 接手轮实际投入约 13:56–14:35（约 39 分钟）；Token 未采集。
