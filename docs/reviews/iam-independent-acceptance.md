# IAM 整改前独立验收报告

**本文记录整改前版本，原验收结论为未通过，不能作为当前代码的逐项状态表。** 用户随后授权“连审带改、MVC 分层、阿里巴巴编码规范、MyBatis”；整改与最新复验见 [MVC / MyBatis 整改记录](iam-remediation-validation.md)。本报告中的失败输入与原证据保留，源码行号对应冻结的整改前副本。首期范围仍为 I1；I1a/I2/I3/I4 不计为首期缺失。

## 范围、输入与方法

目录 `/Users/acerola/Dev/Java/air_agent_iam` 不是 Git 仓库；没有分支、HEAD、Git diff，不初始化 Git。`evidence/iam-independent/outputs/input-baseline.json` 冻结 282 个文件，checkpoint-2 对照无新增、删除、内容改动及敏感配置元数据改动。审计探针/报告排除在产品输入指纹之外；依赖和构建产物排除，真实 `.env.local` 只记录元数据。未修改两个 Python 项目及其服务。

按批准的 proposal/design/http-contract 和两项 specs 验收，tasks 勾选与作者报告只作为定位信息。`http-contract.md` 和跨服务矩阵仍有“尚未实现”等历史状态文字，不能据此否认当前实现，也不能据作者 36/36 声明判定通过。tasks 3.4 的“改密保留当前会话”测试语义与 HTTP 契约“撤销所有本人会话”冲突，以后者为验收依据。

原始证据和可复跑探针：`evidence/iam-independent/{outputs,probes}/`。合成秘密只放 `/tmp/iam-independent-20261015-5ohAEo/` 的受限文件，报告不附令牌、口令、Cookie、哈希或 dump。探针内部加载秘密，禁止将环境文件内容打印出来。

本轮请求环境：自建、带 `audit.run=iam-independent-20261015-5ohaeo` 标签的 PostgreSQL/Redis，回环端口 29132/29179；IAM 使用字节一致副本与其构建 JAR，端口 29100，非 owner `iam_app`。原开发环境 191xx 未作为可故障注入对象。资源清单 `outputs/resources.json`。最终清理仍待全项取证后执行。

## 已证实问题

### F01 高：成员管理与角色管理可借内置角色扩大权限

- 文件：`server/src/main/java/com/airagent/iam/admin/TenantAdminService.java:199`、`:254`、`:346`、`:512`。创建成员只要求 `tenant:member:write`；角色解析只检查存在、scope、status、tenant，没有将角色权限与操作者可授集合求交。
- 复现：用仅有 member read/write 的合成账号调用角色替换端点，403（反对照）；同账号创建新成员并附 `role_codes=[tenant_admin]`，201。另用仅有 role read/write 的账号给自己替换为 tenant_admin，200；修订使旧 token 401，但重新登录后实际创建部门 201。
- 预期：内置模板不构成旁路，授予操作者可授集合以外的能力必须拒绝。
- 影响：低权企业操作者可授予或获取全部企业管理权限。
- 建议：所有授角色入口统一执行角色展开后的可授子集检查；创建成员与替换角色执行相同策略，独立验证内置模板及自定义角色。
- 证据：`outputs/independent-tenant-boundaries.jsonl`、`outputs/independent-db-boundaries.jsonl`；探针 `tenant_boundaries.py`、`db_boundaries.py`。

### F02 高：旧企业创建请求在切换后写入新企业

- 文件：`server/src/main/java/com/airagent/iam/admin/TenantAdminController.java:122`、`TenantAdminService.java:416`、`:483`；`admin/dto/AdminDtos.java` 的 CreateDepartmentRequest 不含 tenant/CAS 字段。
- 复现：A→B→A 后保留 A 版本，再切到 B；向 `/v1/admin/departments` 提交旧 A `tenant_id`、`expected_ctx_version`，得到 201；随后读取 B 部门，旧 A 名称实际持久化在 B。
- 预期：409，旧操作不得写到新企业。当前正文声明被未知字段忽略，query 缺省直接采用新会话企业。
- 影响：双标签页、在飞表单可能污染新企业。真实HTTP和浏览器双标签均已证实，见 browser-independent-workflows-r2.jsonl 的 double-tab-wrong-tenant-persistence。
- 建议：租户写接口要求可信的显式 tenant/ctx 声明并在写事务内校验；前端同时保护草稿与在飞提交。
- 证据：`outputs/independent-tenant-boundaries.jsonl` 的 stale-a-create-after-switch-b 与 b-persistence-after-stale-write。

### F03 高：企业操作者可关联任意已知全局账号

- 文件：`server/src/main/java/com/airagent/iam/admin/TenantAdminService.java:212`。只校验用户存在，没有平台专属关联权限或受控邀请授权。
- 复现：企业 A 管理员 POST `/v1/admin/members`，提交原来没有 A 成员关系的合成 outsider `user_id` 与 tenant_reader，201。
- 预期：按 iam-tenant-administration 的平台/企业授权分离要求拒绝企业自关联任意全局用户。同名账号建档反对照得到 409，未自动合并。
- 影响：企业管理员可擅自扩张全局用户的成员关系；“显式 UUID”本身不是授权依据。
- 建议：分离平台关联、企业新账号建档及邀请接受流程；现有用户关联需额外授权。
- 证据：`outputs/independent-tenant-boundaries.jsonl`。

### F04 高：改密保留原调用会话，且可续期

- 文件：`server/src/main/java/com/airagent/iam/auth/SessionService.java:344`、`:352`；`server/src/main/resources/db/migration/V3__session_revisions_and_authority.sql:227` 附近的当前会话修订对齐函数。
- 复现：同一新建账号登录两个会话；t1 改密返回 204，紧接首次 introspection：t1 active=true、t2 active=false；t1 再 renew 得到 200。
- 预期：HTTP 契约 §3 规定改密撤销所有本人会话并使所有 BFF 退出。作者测试“仅撤销其他会话”不能代替规格。
- 影响：原调用凭据在口令变更后继续授权，与批准的撤销语义不符。
- 建议：同事务撤销全部本人会话并使当前句柄失效，移除改密后的旧会话对齐续命。
- 证据：`outputs/independent-revocation-lifecycle.jsonl`。

### F05 高：RLS 未隔离当前企业部门，密码列未实施列权限

- 文件：`server/src/main/resources/db/migration/V1__identity_schema.sql:531`、`:566`。部门 USING 允许“用户属于该企业”，不要求当前企业；请求角色被授整表 SELECT/UPDATE。
- 复现：真实 iam_app（super=false，bypass=false）同一用户双成员，事务上下文设 A，省略 API 租户过滤直接 SELECT departments，能读 A/B；设 B 或仅 user 无 tenant 也能读 A/B。全空上下文读不到部门（正反对照）。`has_column_privilege` 对 password_hash SELECT/UPDATE 均 true，A 上下文成功读取 6 行密码列，探针只记录计数不记录哈希。
- 预期：数据库对 API 遗漏过滤提供当前租户防护；任务 2.3 明确要求列权限。
- 影响：数据库防线依赖所有上层查询一直正确；SQL 漏过滤可跨活动企业读组织数据，普通请求连接可读取密码材料。
- 建议：本人企业枚举走受限专用函数；业务表 RLS 按当前 tenant 防护；撤销密码敏感列直接权限，仅受控认证函数可访问。
- 证据：`outputs/independent-rls-scope-detail.jsonl`。`independent-db-boundaries.jsonl` 的本人 membership 可见性不单独算泄漏，后续以部门业务行作为反例。

### F06 高：rt-v1 与原 Python 消费者签名字节不兼容

- 文件：`server/src/main/java/com/airagent/iam/security/rt/RtV1Codec.java:30`、`:42`。
- 复现：从实际构建 JAR 导出真实类，与只读复制的原 Python ticket/security 模块双向签验，各自自验成功，互验失败。Java 3 段签 header.payload；原 rt-v1 两段签原 body 文本。
- 预期：C03 明确固定字节、原 body 文本及旧格式兼容。
- 影响：作者新写 Java/Python 工具互验通过不能证明原消费者兼容。
- 建议：保持批准 rt-v1 外形和签名字节，或另立破坏性协议版本与迁移计划，不能同名改变语义。
- 证据：`outputs/independent-rt-cross-consumer.jsonl`；HTTP实际签票送原消费者也失败，见 independent-internal-principals.jsonl 的 real-http-ticket-original-python-consumer。

### F07 高：Redis 会话丢失后，内部核验仍给出有效许可

- 文件：`server/src/main/java/com/airagent/iam/internal/IntrospectionService.java:73`、`:254`。
- 复现：只删除一个本次合成会话 Redis token 键，`/me` 401；同 token 内部 introspection 200、active=true。事务 logout 后再恢复旧 Redis 键则 active=false（撤销正对照）。
- 预期：规格要求实时同一会话权威、依赖失败关闭，浏览器适配明确 PG 修订与 Sa-Token 状态双验。
- 影响：入口与运行内部核验对同一凭据有效性结论不一致。全 Redis 故障含准入限流影响仍需独立测，不能以单键丢失代替断网测试。
- 建议：统一会话权威核验语义，确认 Sa-Token 状态与 PG 状态均满足；故障返回 503。
- 证据：`outputs/independent-initial-http.jsonl`。

### F08 中：真实浏览器“续期会话”必然缺少 CAS 字段

- 文件：`web/src/api/endpoints.ts:38`、`web/src/stores/auth.ts:157`；`server/src/main/java/com/airagent/iam/webapi/WebApiAuthController.java:151`。
- 复现：真实 Edge 点击续期，400 expected_ctx_version 必填；直接 HTTP 补正确版本则 200。
- 建议：浏览器提交当前版本，并对冲突/过期使用一致上下文恢复流程。
- 证据：`outputs/browser-smoke-r2.jsonl`、`outputs/independent-initial-http.jsonl`。

### F09 中：未知账号登录 500，已知账号错密 401

- 文件：`server/src/main/java/com/airagent/iam/auth/SessionService.java:75`；`server/src/main/java/com/airagent/iam/web/error/GlobalExceptionHandler.java:85`。
- 影响：错误语义不符合统一401，且形成账号存在性差异。
- 建议：未知账号同样走安全口令失败路径，统一状态及错误信封，保留限流。
- 证据：`outputs/independent-initial-http.jsonl`、`outputs/browser-smoke-r2.jsonl`。

### F10 高：人类 introspection 未绑定请求受众，身份响应返回另一受众

- 文件：`server/src/main/java/com/airagent/iam/internal/IntrospectionService.java:73`、`:95`；`server/src/main/java/com/airagent/iam/auth/IdentityAssembler.java:57`、`:73`。服务账号分支检查自身 audiences，人类分支未作等价绑定或权限受众过滤。
- 复现：iam-admin 登录 token 交给仅注册 langgraph-runtime 的内部 client，请求 langgraph-runtime；实际200/active=true且返回audience=iam-admin、平台管理权限。900个样本均如此，单次探针亦可复现。
- 预期：响应与请求受众一致，permissions为当前受众可用集合；不匹配受众须失败关闭，不得将管理权限带入其他受众身份。
- 建议：明确人类会话合法受众转换规则；按请求受众核验并过滤有效权限，固定协议反例断言；消费者仍须拒绝aud不符DTO。
- 证据：`outputs/independent-c25-r2.jsonl`、`outputs/independent-revocation-lifecycle.jsonl`。

### F11 高：服务凭据轮换的重叠限制没有实际失效旧凭据

- 文件：`server/src/main/resources/db/migration/V7__internal_clients_and_service_principals.sql:164`、`:198`；`server/src/main/java/com/airagent/iam/serviceaccount/ServiceAccountService.java:146`。签新凭据只新增行，未为旧凭据设置退役；核验也不使用 overlap_until。
- 复现：先签 t1，再 POST tokens `overlap_hours=0` 签 t2；t1/t2 下一次 knowledge introspection 均 active=true。显式 revoke t1 后才失效，停用主体后t2失效（正反对照）。25小时参数400、366天账号400、资源型权限400均正常。
- 影响：配置的“零重叠”不限制旧凭据；仅有时间字段和参数校验不能证明24小时退役语义。
- 建议：区分新增独立token与轮换；轮换事务明确旧凭据退役上界，每次核验执行上界，提供并发/边界验证。
- 证据：`outputs/independent-internal-principals.jsonl`。

### F12 高：SSO签发独立应用会话，中央退出后仍能访问两个应用

- 文件：`server/src/main/java/com/airagent/iam/webapi/sso/SsoExchangeService.java:52`、`server/src/main/java/com/airagent/iam/auth/SessionService.java:134`；`server/src/main/resources/db/migration/V11__sso_clients_and_mint.sql:64`。
- 复现：浏览器适配建立中央会话，合成 agent/kb 真实ticket授权/服务端兑换/BFF cookie，me均200；中央logout204后保留两端cookie，首次BFF me仍200。
- 预期：http-contract §8和SSO全局登出场景要求共享中央会话及ctx，下一请求拒绝。
- 影响：中央退出不能撤销已派生SSO应用许可；这是本项目合成真实HTTP，不冒称两个原Python应用已接入。
- 建议：应用句柄绑定共享会话权威或受控父子会话撤销图，并共享ctx代次；核验不可只读独立子会话。
- 对照：错回调400、错client401、票据重放401；BFF错state回调在兑换前拒绝。未把这些成功边界扩大为SSO整体通过。
- 证据：`outputs/independent-sso-boundaries.jsonl`。

### F13 高：最后管理员保护漏全局停用及平台真实并发

- 文件：`server/src/main/resources/db/migration/V1__identity_schema.sql:454`、`:499`，`server/src/main/java/com/airagent/iam/admin/UserAdminService.java:112`。
- 复现一：拥有1个有效管理员的合成企业，平台通过用户停用API返回200；实际有效企业管理员1→0。随后恢复该合成账号。
- 复现二：两条真实 iam_app 事务各停用一名平台超级管理员；用屏障确保两边AFTER触发器已通过再同时提交，两边committed，平台有效管理员=0。随后已恢复合成账号。
- 局限：复现二是数据库真实非owner并发，并非声称特定HTTP调度稳定触发；它直接否证数据库兜底并发不变量。企业内成员停用API的200/409正对照仍成立。
- 影响：管理员可能全部丢失；用户状态变更绕开企业管理员检查，平台检查缺共享串行化点。
- 建议：覆盖所有影响有效管理员的用户/成员/角色/权限状态路径，使用稳定的企业/平台公共锁或等价可证明事务策略；有效性包含用户与角色启用状态。
- 证据：`outputs/independent-global-admin-guards.jsonl`、`outputs/independent-db-boundaries.jsonl`。

### F14 中：浏览器企业停用提交disabled，后端只接受suspended

- 文件：`web/src/views/platform/PlatformTenantsView.vue:64`，`server/src/main/java/com/airagent/iam/admin/TenantAdminService.java:130`。
- 复现：真实Edge新建企业201并刷新存在；点击名称/状态→停用→保存，PATCH400，中文错误提示status仅支持active/suspended。
- 影响：后台必需企业停用功能无法完成，不能以直接HTTP手工传suspended代替浏览器流程通过。
- 建议：页面状态枚举与契约一致并覆盖实际点击持久化。
- 证据：`outputs/browser-independent-workflows-r2.jsonl` 及 `outputs/browser/workflows-r2/`。

### F15 高：迟到切企业响应跨退出和换账号覆盖新身份

- 文件：`web/src/stores/auth.ts:125`、`:130`。switchTenant响应提交缺少请求启动时scope/epoch新鲜度检查。
- 复现：真实浏览器dual在A发起切B，服务器已提交，探针仅延迟该真实响应送达；UI退出并登录平台root；释放旧B响应后，Pinia实际identity变成audit.dual/企业B/active=true。未注入或修改产品store。
- 影响：新账号cookie与界面身份/权限/草稿不一致。不能以列表usePagedList的代次守卫单测替代身份store竞态。
- 建议：身份、菜单、企业清单所有异步提交统一校验原scope/epoch；退出、换账号与上下文冲突均使旧请求无效。
- 证据：`outputs/browser-response-races.jsonl`，`outputs/browser/races/late-switch-new-user.png`。A→B→A列表首次“table_unchanged=false”可能含新A正常加载，不据此另外认定列表守卫失败，须补稳定时点/标记物对照。

### F16 中：真实API把字符串修订/布尔值强制转换，偏离冻结类型契约

- 文件：`server/src/main/java/com/airagent/iam/auth/dto/AuthRequests.java:15`，`server/src/main/java/com/airagent/iam/internal/dto/InternalDtos.java:16`；全局Jackson未禁止标量转换。
- 复现：expected_ctx_version使用当前数字的字符串，switch200；include_execution_context传字符串true，introspection200并创建引用。bool修订反例400（正反对照）。
- 预期：冻结契约要求修订号严格整数且拒绝字符串；不能将样本Schema校验36/36视为实际服务器类型校验通过。
- 建议：禁止相关请求标量强制转换，并把Schema反例送真实HTTP端点验证。
- 证据：`outputs/independent-live-contract.jsonl`。真实正常登录identity通过冻结Schema与format检查。

### F17 高：总deadline未执行，PG中断错误语义也不稳定

- 文件：`server/src/main/resources/application.yml:10`、`:18`、`:41`；`server/src/main/java/com/airagent/iam/web/error/GlobalExceptionHandler.java:46`、`:85`。
- 复现：只锁自建库auth_sessions，观察真实iam_app后端等待relation锁；等待约1.2秒再释放，introspection实际1214.722ms后仍200/active=true。正常前后对照均有效。设计总deadline500ms没有执行。
- 另用有效token的/me200正对照后停止自建PG，首次introspection和/me均500/conflict，而不是规定503；另一次故障轮次得到503。两种情况均没有拿到正向许可，但协议失败语义不稳定。
- 影响：受保护核验可能无限/过长占住连接；故障不按契约503反馈。当前配置Hikari连接等待3000ms、Redis1s，PG JDBC connectTimeout=3000/socketTimeout=10000的单位还是秒，均不能实现100/50/500ms预算。
- 建议：建立贯穿连接池、连接、查询与调用链的可取消deadline；按预算设置驱动参数并正确翻译连接中断异常。不要用HTTP200或短拒绝路径性能掩盖等待。
- 证据：`outputs/independent-request-deadline-r2.jsonl`、`outputs/independent-final-http-boundaries.jsonl`；首轮deadline的application_name过滤未命中已保留，但最终结论用实际等待PID已确认的r2。

### F18 中：冻结HTTP路由/菜单/幂等退出与当前实现不一致

- 文件：`server/src/main/java/com/airagent/iam/auth/AuthController.java:41`、`:58`；`server/src/main/java/com/airagent/iam/webapi/WebApiAuthController.java:56`；`server/src/main/java/com/airagent/iam/webapi/sso/SsoController.java:31`；`server/src/main/java/com/airagent/iam/security/internal/InternalClientAuthenticator.java:33`。
- 复现：冻结OpenAPI声明的 `/web-api/csrf`、`/v1/sso/authorize` 实际404；可工作的是 `/web-api/auth/csrf`、`/web-api/sso/start`。`/v1/auth/menus`实际只返回platform_admin和permissions，不返回HTTP契约items菜单树。logout204后重复同token返回401，偏离已失效也幂等204约定。
- 静态一致性：批准设计/HTTP契约规定内部client Bearer，实现与OpenAPI改为Basic；没有独立的已批准v2迁移证据。双主体分型本身通过，传输契约仍漂移。
- 建议：对批准契约做明确版本决策，不让示例/OpenAPI/服务器各自定义v1；用契约请求直接打运行服务，而不只检查YAML含路径。
- 证据：`outputs/independent-final-http-boundaries.jsonl`、`outputs/independent-expiry-surface.jsonl`、`outputs/independent-live-contract.jsonl`。

### F19 高：权限撤销未推进四修订，旧执行引用继续有效

- 文件：`server/src/main/resources/db/migration/V3__session_revisions_and_authority.sql:15`（修订触发器集合缺角色权限/角色状态的关联推进），`server/src/main/java/com/airagent/iam/admin/RoleAdminService.java:157`，`server/src/main/java/com/airagent/iam/internal/IntrospectionService.java:205`。
- 复现：新建A企业只含department read的角色与成员；真实introspection产生执行引用。撤空该角色权限200后，普通introspection权限确实变空，但四修订逐项不变；携原四修订的旧引用复查仍active=true、context_matches=true。
- 影响：已持有旧权限快照的执行上下文不会被I1引用复查拦下；这直接违反权限收回后的长运行修订门禁。没有实际调用原Agent或模型，不冒称已验证I2发送数。
- 建议：角色权限/角色状态/权限状态及平台关联变更同事务推进受影响主体/企业修订；引用复查必须能识别所有授权收缩。
- 正对照：拒绝审计函数执行时，相同角色权限删除返回500并全部回滚，原权限仍在；恢复审计ACL后才成功撤权。审计同事务并不弥补修订缺口。
- 证据：`outputs/independent-permission-reference-atomicity.jsonl`；A撤权B不污染另见 `outputs/independent-permission-revocations.jsonl`。

### F20 高：空企业首位管理员缺可用建档授权入口

- 文件：`server/src/main/java/com/airagent/iam/admin/TenantAdminService.java:199`、`:201`、`:483`；`server/src/main/java/com/airagent/iam/admin/TenantAdminController.java:80`。
- 复现：平台root用真实API创建空企业201，再尝试关联并授首位tenant_admin，403缺tenant:member:write；平台身份没有企业成员不能切入新企业；当前路由无独立开通/首管理员授权入口。
- 预期：批准的“创建用户并加入企业/平台建档并授权成员角色”流程可从空企业完整完成。
- 影响：新企业创建后无法仅靠交付的API/浏览器开始企业管理。作者报告称首位管理员由开通/迁移落库，不是独立IAM已交付的可用入口。
- 验收处理：为继续测试下游边界，主审只在自建库显式SQL种了合成成员，已标记为测试夹具，绝不把SQL夹具当作产品流程通过。
- 建议：实现有平台授权、事务审计和并发保护的首管理员开通流程；企业内成员管理与平台开通分别裁决。
- 证据：`outputs/independent-fixture-setup.jsonl` 的 platform-establish-first-admin-via-api（403），以及该文件的 isolated-sql-fixture-provisioning说明。

### F21 中：旧续期事务晚提交可回退空闲期限

- 文件：`server/src/main/resources/db/migration/V3__session_revisions_and_authority.sql:203`。
- 复现：新正常会话，iam_app旧事务先开始，另一新事务调用renew并提交；旧事务随后调用同一renew函数并提交。没有伪造到期时间，最终idle deadline比已提交值回退94.137ms，因为now()固定在事务起点且更新未取原期限最大值。
- 影响：违反并发续期不回退期限约定。此为两个真实非owner事务对产品函数的交错验证，不声称特定HTTP调度一定触发。
- 建议：在绝对上限内保证新空闲期限不小于已提交期限，并检查过期/撤销；以真实事务交错验证。
- 证据：`outputs/independent-renew-transaction-order.jsonl`。先前10天人工deadline案例只作为探索证据，最终问题依据本次正常会话事务反例。

## C25 独立性能结果

同机隔离PG/Redis、字节一致JAR专属29103 JVM、Hikari最大12；仅该JVM关闭准入限流，不改授权查询或加缓存。每工作线程持有独立HTTP/1.1连接并先暖3次；每并发100样本×3轮，共900次测量核验。延迟包含发送到完整读取响应，不含线程队列、启动与暖连接。外部等待无（回环）；Token未采集。

| 并发 | 轮 | P50 ms | P95 ms | P99 ms | 传输/active/会话/权限错误 | 受众契约错误 |
|---|---|---|---|---|---|---|
|1|1|7.845|15.059|40.891|0/100|100/100|
|1|2|6.804|15.096|20.327|0/100|100/100|
|1|3|5.191|6.667|6.943|0/100|100/100|
|10|1|8.771|13.826|22.392|0/100|100/100|
|10|2|9.046|17.535|29.264|0/100|100/100|
|10|3|6.799|9.760|20.403|0/100|100/100|
|30|1|25.488|37.986|43.787|0/100|100/100|
|30|2|23.254|35.838|38.115|0/100|100/100|
|30|3|23.292|33.190|34.909|0/100|100/100|

并发30全部超P50≤10/P95≤30目标，不放宽阈值。受众错误导致不能把HTTP200/active=true记作完整协议授权成功。该数据证明当前代码路径延迟，不证明消费者能接受其身份。无SQL/队列埋点，不能独立断言PG排队是唯一根因。

原始900样本及每项授权对照在 `outputs/independent-c25-r2.jsonl`。首轮 `independent-c25.jsonl` 误用未注册iam-admin受众得到900次403，已作废但保留原始证据，不以拒绝路径的较低延迟计成绩。两次专属JVM均已自动终止，resources有退出记录。顺序5次真实核验三轮总耗时37.014/40.264/46.448ms；显式合成等待201.234ms与总221.565ms分别记录，不是模型调用测量。依赖故障见 independent-dependency-faults-r2.jsonl / independent-final-http-boundaries.jsonl。

## 已完成的独立正向控制与局限

- 干净 Maven 仓库 JDK21 构建/启动、Boot4.0.8/Sa-Token1.46.0/Jackson 依赖树；作者后端 72/72、前端 17/17、Vue 类型检查与 build 已复跑。它们不覆盖上述安全反例。
- 自建空库 V1–V11 迁移成功；请求角色非owner/non-super/nonBYPASS。跨企业复合 FK 写入拒绝；部门成环409；显式跨企业 query403。
- 真实同时 CAS 一个200一个409。两个企业管理员同时停用对方，一个200一个409，最终仍1个有效管理员；这不证明平台最后管理员或通过全局停用账号移除企业最后管理员路径。
- 同一受限连接事务提交、SQL异常和 statement_timeout 取消后，无上下文 membership 计数均0；随后在专属29106实际Hikari单连接后端PID148复验A/B/匿名、SQL异常及取消后复用；同一PID保持，A/B不串、匿名401，取消请求503。见 independent-hikari-runtime-reuse-r2.jsonl。
- 管理员重置、logout-all、账号停用/重新启用旧 token、A成员停用与B不污染、B企业停用：提交后首次实际 introspection 拒绝或相应对照有效。
- 一致设置 idle_expires_at 与 expires_at 已过期，以及 absolute 已过期，renew 均401；两个合法续期同时200且响应期限相同。仅改 idle_expires_at 而不改 expires_at 的注入得到有效，不把这个不一致夹具直接写成普通运行可达的过期绕过。
- 合成会话原 idle 设置10天后 renew变7天，说明SQL没有 monotonic guard；属于人工未来期限边界，正常配置可达性待核实，不与已证实安全缺陷混淆。
- 浏览器真实登录、深链、刷新、无JS可读人类令牌、CSRF/Origin反例、390×844抽屉Escape及Tab已有证据；用户/企业/部门/成员/平台和企业角色/权限树/审计/改密/退出均有真实点击，刷新持久化、双标签409与错误写入、迟到响应、空态、真实503/恢复及过期已补。CDP真实浏览器中文组合输入已测，未声称物理macOS输入法或触屏设备实测。

## 未完成要求（保持开放）

C01–C30 最终逐项矩阵及全量规格/作者原始证据审阅；全部内部client/服务账号/verification_ref绑定撤销；HTTP rt-v1原消费者与独立bcrypt固定向量；角色/权限撤销细分；平台最后管理员；权限修改审计同事务与outbox故障；PG/Redis部分故障及提交窗口；新库复跑/存量升级/备份恢复撤销重施；完整真实浏览器CRUD与竞态；SSO白名单/state/ticket一次消费与生产Cookie；C25有效900样本及顺序调用/外部等待分项；最终秘密扫描、资源关闭与源码完整性复核。

阶段外 C14/C18–C24 中 I1a/I2/I3/I4 部分标记不适用，不要求本项目提前实现，也没有真实跨服务切换证据。

## 修复顺序建议（仅建议，不执行）

1. 封堵角色模板提权、任意账号关联、租户写入缺CAS、RLS/密码列防线。
2. 统一改密全会话撤销、内部会话权威、rt-v1既有兼容协议。
3. 修复浏览器续期、未知账号错误及其余已证实契约问题。
4. 完成剩余审计并独立复测全部反例，最后判断性能与上线门禁；不以缓存替代授权查询。

Token 使用：未采集。测试耗时、应用延迟和环境等待分开保留在原始证据；不由文件时间跨度推断应用延迟。
