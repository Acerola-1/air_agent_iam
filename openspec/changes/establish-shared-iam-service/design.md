# 独立IAM首期设计

## Context

目标目录已由用户确认为air_agent_iam。源项目事实与整体抽取方案分别见`docs/reference/source-audit.md`及`full-extraction-design.md`；完整HTTP草案见本目录http-contract.md。原项目已有企业组织/可撤销会话，不是从Sa-Token示例开始重新发明角色语义。本轮只交方案，用户评审后再实施。

## Goals / Non-Goals

**Goals：**独立可运行的用户/企业/组织/RBAC/身份审计与中文后台；HTTP不透明Bearer、四修订及即时撤销；续期、服务账号、内部客户端、rt-v1兼容、受限执行复查与SSO基础；隔离环境独立验收。

**Non-Goals：**不修改两Python仓库/现有数据库/现有容器；不导入真实用户或密码；不实现知识库技术存储或local模式；不迁台账、反馈、价格、MCP连接绑定；不实施entitlement管理（另包I1a）、真实消费者切换或物理拆库。不能为展示擅自开放外部监听或未核验企业MCP。

## Decisions

### 1. 工程边界与版本

拟定单仓双模块：`server/`为Maven Wrapper的Spring Boot4 WebMVC服务，JDK21；`web/`为Vue 3 + TypeScript + Vite + Vue Router + Pinia + Element Plus中文管理前端，重建Vue组件并保留已核实的权限/UX行为；`contracts/`为OpenAPI/JSON Schema/合成兼容向量与消费者测试器。Maven多模块不是首期必须，先避免空壳模块过度拆分。

首个Gate先核实本机JDK/Maven和依赖再锁版本：Sa-Token 1.46.0候选，**Boot4专用starter**，RedisTemplate插件同版本，Jackson3依赖树核对。Boot4与JDK21官方支持已核实（来源见reference完整设计），未做本机Java编译。具体Boot4补丁在Gate0记录，不无条件追最新大版本、不混用Boot3 starter。仅用Spring Security crypto校验存量bcrypt，不无意引入第二Web过滤链。

数据库PG，Flyway只管理本项目自有隔离库；从现有DDL重建身份域约束及索引，不把旧Alembic迁移整包在生产库跑。旧数据兼容以合成UUID/哈希/会话fixture检验。先不开发真实用户导入执行器：这里只交只读预检/映射方案和幂等合成导入测试。

### 2. 服务内部边界

身份/组织/RBAC/会话/内部客户端/机器主体/审计分清服务职责，但运行在同一个Spring Boot服务内。一个权威事务完成授权修改、相关修订推进、审计和必要outbox。公开DTO不返回ORM敏感列。

账号保留UUID、ASCII account、display_name、bcrypt和auth_revision；企业/成员/角色关系与原scope相同。数据库复合FK/无环防护、最后有效管理员并发锁必须存在。请求连接非owner/nonBYPASS，事务开始设置全量可信GUC并在提交/回滚清除；建议对新IAM租户表启用FORCE RLS，不只在代码加WHERE。

平台权限与企业可授集合分开，用户不能用平台角色绕过业务成员/entitlement。资源型Permission预留resource_code；I1没有实际entitlement时该类型一律不可授/不可用。资源实现I1a另开change，禁止只检查字符串权限就给知识库放行。

### 3. 会话与令牌

采用Sa-Token有状态不透明随机令牌，显式接独立Redis。**默认Sa-Token使用内存，不是默认Redis。** PG是会话撤销/状态/四修订/权限的最终权威，introspection每次读主库；Redis不能成为带TTL的旧权限正向缓存。Sa-Token登录态检查后仍走统一权威核验，所有管理API也一样。

PG会话/服务令牌存摘要。Sa-Token标准Redis可能有原始token索引，按凭据存储保护，不能声称天然全部摘要化。登录PG/Redis非原子时不返回未可靠建立的会话；撤销PG事务提交后，即使Redis清理失败/滞后也必须拒绝旧授权，清理使用事务outbox可重放。Redis故障/缺会话失败关闭，首期允许清晰要求重新登录，不能从旧快照复活。

会话普通30天绝对/7天空闲为评审建议；renew只延空闲不越过绝对上限，不接受过期/撤销会话。旧fixture可保留原到期、idle=null。新服务账号固定企业/受众/permission allowlist，建议90天/硬上限365天、不永久；内部客户端独立realm/scope/credential，不把知识库脚本发成管理员。

### 4. HTTP、执行上下文与签票

完整字段、状态码和接口以http-contract.md为准；先生成OpenAPI3.1、JSON Schema和合成样本，再按其写Java与协议消费者测试。Authorization的用户Bearer和内部client Bearer分型，内部subject_token只在传输中出现。

执行上下文verification_ref由合法token首次核验生成并存IAM，绑定client/受众/原会话/修订；它不独立授权。runtime可通过内部HTTP每个发送边界复查而不持久化token；本包用合成消费者证明60秒短票据到期但会话有效不误杀、撤销立即阻断。真实LangGraph改造属于I2，不能在本包写回Python。

rt-v1原格式保留，签名输入是base64url原body文本；使用合成密钥与双向Python/Java固定向量，测试kid轮换/受众/时效/篡改及四修订。rs-v1/mt-v1保留独立受众/密钥与权限边界；I1不将它们换成全能用户token，不接管Agent内部confirm/claim/health。

### 5. UI、SSO与启动

独立IAM web只迁身份功能与行为，不迁business/regions、business/followed、enterprise/mcp及Agent运营页。用户于2026-10-15确认Vue技术栈；不复制React/TSX/radix组件或Next.js API routes，不增加Nuxt/Node生产BFF。只读参考原页面字段/校验/菜单/权限和错误态，在Vue重建，原Agent聊天及后台代码保持不变。

Vue SPA采用Router history模式，路由守卫和按钮权限仅改善体验，后端仍逐请求实时授权。Pinia只存当前非秘密身份/菜单/草稿，作用域绑定user/tenant/ctx_version及单调epoch；切换/退出清理，A→B→A迟到响应不能覆盖。依赖使用一个前端锁文件，提供typecheck/test/build；不能只交静态演示页面。

Spring Boot提供/web-api同源浏览器适配层和SSO回调，调用同一权威身份用例，不成为第二身份源。HttpOnly浏览器句柄在服务端关联Sa-Token会话；login/renew/me等只返回安全DTO，不向JS透传人类Bearer或内部client凭据。cookie写操作保留Origin/CSRF校验，包括登录/退出/续期/切企业；/v1/internal/*不经浏览器代理。Vite开发代理与生产反代只转发路由，不核验权限；生产构建静态资源由Spring Boot同源提供，history回退不能吞掉/web-api、/v1或缺失资源。详细路由/验收见http-contract第9节及docs/vue-admin-plan.md。

同源BFF为默认入口，中央/各应用host-only HttpOnly cookie，生产Secure/Lax/Path=/且无Domain；dev使用单独普通cookie名，不能在HTTP伪造__Host-。SSO采用注册callback+state+一次性30秒ticket/服务端兑换，验证两个**自有合成BFF客户端**的共享中央session和ctx_version。真实聊天/知识库前端切换留I2/I3，域名未定不开放外部callback/Origin。

本机Apple Container，不依赖Docker Engine API/Testcontainers默认Docker socket。测试可使用任务自有容器或独立测试PG/Redis；回环端口默认可拟19100/19101、PG19132、Redis19179，启动前查占用，冲突改本项目配置且记录，不停原进程。容器发布端口需实际验证回环限制，若工具不能做到则不发布数据库端口、用隔离网络测试，禁止声称绑定0.0.0.0也是回环。

bootstrap账号由环境显式输入，示例无真实默认密码；测试使用合成账号。提供.env.example、README和可验证启动脚本，脚本不能扫描读取旧.env或复用既有服务凭据。

### 6. 逐组证据和完成边界

tasks每组连同本组测试/说明一起交付。C01–C26在reference/cross-service-acceptance.md映射，Vue补充C27–C30见docs/vue-admin-plan.md；本包实际接受C01–C13相关IAM部分、C15/C16/C17基础、C25/C26及C27–C30。C18 entitlement、C19/C20知识库及C21/C22真实六图/3/5、C23/C24拆库不能在I1勾完成。

性能目标是同机暖连接P50≤10ms/P95≤30ms、单核验开销P95≤50ms；总deadline500ms、连接100ms、pool50ms，无跨请求授权结果缓存。至少100样本×3轮及并发1/10/30，分别报告真实HTTP/主库/Redis、外部等待、错误/队列；不是先承诺已达标。

## Risks / Trade-offs

- [Sa组件与PG状态两处存储] → PG即时权威+事务outbox；实测各崩溃点，Redis残留不能放行。
- [bcrypt及票据跨语言差异] → 固定向量先验，无法兼容则停止切换，不重置用户口令或改旧断言。
- [把旧模型当纯CRUD] → 无环、同租户FK、最后管理员、可授边界/修订/审计并发测试逐项保留。
- [HTTP正向缓存引入撤销窗口] → 结果TTL=0，连接缓存与权限缓存区分；timeout503无本地兜底。
- [去掉Next.js后遗漏服务端会话/CSRF] → Java浏览器适配层、token不进JS、跨源/重放和静态回退负例，不能拿Vite proxy当BFF。
- [Vue store/路由守卫替代真实授权] → 每个API实时核验，跨企业迟到响应与直接API负例；错误不伪装保存成功。
- [完成本包被误读为整体迁移] → 独立报告标注合成消费者，明确后续I1a/I2/I3/I4未实施。

## Migration Plan

首期仅在自有空库初始化和合成fixture验证；启动失败可停自己的服务，源Agent/KB不受影响。完成后先独立验收，再创建I1a资源开通包；Agent与知识库客户端可据固定契约各自实现，但真实接管/物理拆库须后续单独授权/change。具体写者切换与新写保全回退见reference/full-extraction-design.md阶段表。

## Open Questions

域名、正式部署端口、真实密钥供应方式、生产Redis容量/HA留部署阶段填写。首期默认回环、无外部callback、无生产凭据，不用这些未知值阻塞隔离开发。
