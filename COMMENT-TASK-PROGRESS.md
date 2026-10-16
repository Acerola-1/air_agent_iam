# 注释与 API 文档任务进度记录

任务：server/src/main/java 全量 Javadoc + Swagger/OpenAPI 注解（168 个文件）。模式：主智能体统筹，子智能体按模块并行。
状态标记：待处理 / 已修改(子智能体完成) / 已审查(主智能体核对 diff 与 SQL 一致) / 已验证(编译+DocLint 通过)。

## 基线事实

- Spring Boot 4.0.8 / JDK21 / MyBatis starter 4.0.0 / Sa-Token 1.46.0（boot4 starter）
- springdoc 官方 FAQ：3.x 兼容 Boot 4（已确认，来源 springdoc.org）
- 鉴权面（WebMvcConfiguration）：Bearer → /v1/auth/**、/v1/admin/**（除 login/logout）；内部客户端 → /v1/internal/sso/exchange；CSRF Origin → /web-api/**、/v1/sso/authorize；浏览器会话 → /web-api/auth/**、/web-api/admin/**、/web-api/sso/start、/v1/sso/authorize（除 csrf/login）
- Swagger UI /v3/api-docs、/swagger-ui/** 不在任何拦截器路径内，无需改动鉴权
- 业务规则部分位于 PostgreSQL 函数与 RLS（db/migration V1-V19），Mapper XML 在 resources/mapper/

## 模块清单与状态

| 模块 | 文件数 | 负责方 | 状态 |
|---|---|---|---|
| 示范链：UserAdminController → UserAdminService(+Impl) → UserMapper(+XML) → UserDO | 6 | 主智能体 | 待处理 |
| admin（其余：3 controller、13 DTO、5 entity、2 mapper、2 svc+2 impl、7 VO、AdminSupport 等） | ~34 | 子智能体 A | 待处理 |
| auth（controller/DTO/DO/mapper/SessionService/OutboxRelay/IdentityAssembler/BootstrapRunner/VO） | 24 | 子智能体 B | 待处理 |
| webapi 核心（拦截器/cookies/menu/csrf/staticui/controller/service/mapper/vo/synthetic） | 16 | 子智能体 C | 待处理 |
| webapi/sso | 13 | 子智能体 C（第二批） | 待处理 |
| internal | 19 | 子智能体 D | 待处理 |
| serviceaccount | 14 | 子智能体 E | 待处理 |
| security（internal/password/rt/satoken/token） | 11 | 子智能体 E | 待处理 |
| audit | 7 | 子智能体 F | 待处理 |
| health | 5 | 子智能体 F | 待处理 |
| common | 5 | 主智能体（公共类型） | 待处理 |
| config | 4 | 主智能体（含 WebMvc/SaToken 鉴权面说明） | 待处理 |
| web（错误信封/拦截器/过滤器/executor） | 7 | 主智能体（跨模块公共） | 待处理 |
| IamApplication | 1 | 主智能体 | 待处理 |

## 统一要求（发给每个子智能体）

1. 只改分配文件；可任意读上下游代码、Mapper XML、db/migration SQL、测试；禁止按名称猜语义，不确定写入交接疑点。
2. /** */ Javadoc：类（职责/分层/协作+@author Acerola）、所有显式方法（含 private/包级/static/default；@param/@return/@throws 按真实行为，void 不写 @return）、所有声明字段与常量、record 组件用类型级 @param。
3. Swagger：controller 加 @Tag/@Operation/@Parameter/@ApiResponse（区分 Cookie 会话+CSRF / 人类 Bearer / 内部客户端 Bearer+Basic / 公开端点）；对外 DTO/VO 加 @Schema；持久化 DO 不加 Swagger 注解。
4. 不改业务逻辑/路由/SQL/权限；{@link} 必须指向真实符号；泛型转义正确；中文自然、保留英文术语；不编造作者/日期/保证。
5. 完成后交回：修改文件列表、关键业务语义摘要、疑点、跨模块事项。不贴全源码。

## 交接与审查记录

### 主智能体已完成
- springdoc-openapi-starter-webmvc-ui 3.1.1 加入 server/pom.xml；官方 FAQ 确认 3.x 兼容 Boot 4；首次编译通过
- 新增 config/OpenApiDocsConfiguration.java：声明 humanBearer / browserCookie / internalClient 三个文档 securityScheme（仅描述现状，不改鉴权）
- 示范链已注释并编译验证：UserAdminController、UserAdminService、UserAdminServiceImpl、UserMapper、UserDO
  - 已核实的关键语义：bump_user_auth_revision 触发器仅在 password_hash 或 status 变化时 +1；
    revoke_user_sessions(p_keep=NULL)=全撤含当前会话+额外+1；set_user_password 为 SECURITY DEFINER（iam_app 无列直写权限）；
    set_request_context 是事务级 set_config(app.user_id/app.tenant_id/app.is_platform)；
    iam_app 对 users 无 password_hash 读权限（V15）；guard_last_admin 触发器兜底最后管理员
- AdminSupport 移入子智能体 A1 清单（此前标"主智能体"有误）

### 批次 1（已审查+已验证：编译通过，删除行仅签名换行，抽查 P0010/P0012/28000/23514 映射与 OutboxRelay 退避断言均与代码一致）
- A1 admin控制器/VO/AdminSupport 10 文件 ✔；A2 admin DTO/DO/Mapper/Service 25 文件 ✔；B auth 24 文件 ✔
- 子智能体记录的疑点已收集（最终报告呈现，不在本任务修复）：成员 PATCH department_id 省略即清空；部门 PATCH 不校验 name；updateTenant name 空校验块；role 线无行锁/CAS；停用超管角色不受最后管理员保护；V3 迁移注释与实际"改密全撤"不一致（以 F04 整改为准）；findContext 无调用方；listPermissions 返回 Map 包装；23503 不在翻译器映射（理论不可达）
- 待主智能体处理：`{@code ...<Sa-Token>}` 等尖括号 DocLint 统一核查；IdentityVO 与 contracts/schemas 一致性核对

### 批次 2（已审查+已验证：编译通过；修复 InternalApiController 两处 @Parameter(in=ParameterMode.HEADER) 误用并移除，认证说明由 internalClient scheme 承担）
- C webapi核心+synthetic 18 ✔ ｜ D internal 19 ✔ ｜ E serviceaccount 14 ✔
- 新增疑点：catch-all 500 返回 code=conflict（按状态为准，文档已如实标注）；InternalClientInterceptor 已注入但当前未挂载任何路径；OpaqueTokens 注释 128 位 vs 32 字节（F 修正）；serviceaccount 六项疑点；identity 生成"context_required"保留值；touch_reference 无调用方

### 主智能体公共文件（已完成+编译通过）
- common 5（AdminEventMapper/RequestContextMapper/PageVO/两个 TypeHandler）✔
- config 4（IamProperties/SaTokenConfiguration/WebMvcConfiguration/RedisConfig）+OpenApiDocsConfiguration ✔（SaTokenConfiguration 曾被误改为构造注入，已当场恢复 new DigestStpLogic()，与原始行为逐字一致）
- web 7（RequestIdFilter/BearerAuthInterceptor/error 四类/IdentityDeadlineExecutor）✔；ErrorEnvelope 加 @Schema
- IamApplication ✔
- 核查：IdentityVO 与 contracts/schemas/identity.schema.json 字段完全一致；error.schema.json 含 details 属性而 ErrorEnvelope.Error 无 → 疑点入报告

### 批次 3（全部完成）
- F security 11 ✔（DocLint 参与全量校验；修正 OpaqueTokens"128 位"→32 字节/256 位、RtV1VerifyResult reason 清单两处失实旧注释）
- 全量 javadoc -Xdoclint:all -private：0 错误；剩余 12 条全部为"隐式默认构造器无注释"——修复需新增显式构造器代码，超出纯文档范围，保留并报告

### 最终验证（2026-10-16）
- mvn compile/package：通过（springdoc 3.1.1 + Boot 4.0.8）
- 服务已启动 19100（JAVA_OPTS 需外部提供——run-server.sh 的 $JAVA_OPTS 未做默认值，属脚本既有小缺陷）
- /v3/api-docs：77 paths、64 schemas、12 tags、3 securitySchemes（humanBearer/browserCookie/internalClient）
- /swagger-ui/index.html 200；无凭据访问 /v1/admin/users、/web-api/admin/users 均 401——鉴权未放宽
- 未 commit/push（任务边界），全部改动留在 dev 工作区
### 批次 3（待）：F security 11 ｜ G webapi/sso 13 ｜ H audit7+health5 ｜ 主智能体 common5+config4+web7+IamApplication1
