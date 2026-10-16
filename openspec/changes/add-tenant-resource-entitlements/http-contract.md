# I1a HTTP 与授权契约草案

状态：供本包实施与评审使用，当前接口尚未实现。协议以本文件、能力规格和落地后的 OpenAPI/Schema 一致为准，不以本 Markdown 代表服务器已支持。沿用 I1 的 issuer、受众登记、IdentityVO、ServiceIdentityVO、错误信封和内部认证；实施前锁定当前契约摘要。

## 1. 主体、管理资格与上下文

- 直接管理 API 使用人类 Bearer，浏览器使用同源 HttpOnly Cookie，经现有 `/web-api` 安全适配；不把人类 token/内部 client 凭据交给页面。机器主体和内部 client 不得冒充平台操作者。
- 平台目录与开通：精确要求 `entitlement:manage`，不因拥有 `platform:tenant:write`、菜单可见或请求自报平台标记而放行。
- 企业资源只读：有效当前企业 + `tenant:role:read`；没有企业上下文不能枚举租户资源。平台读取指定企业走平台端点。
- 企业资源授权：原角色/成员操作权限 + `tenant:resource:grant`，或原操作权限 + 自身有效资源码子集；目标企业必须已开通。非资源权限规则不变。
- 服务账号创建：沿用 `platform:service:write`；仍受目标企业/资源开通、tenant scope、可下放与受众约束。第一使用方是 `knowledge` 受众的无人值守合成验收脚本。

所有新写接口要求 `expected_context` 对象，包含 `session_id`（UUID）、`tenant_id`（当前会话企业 UUID 或显式 null）与 `ctx_version`（非负 JSON 整数，拒绝字符串/bool）。服务器与本次实时身份逐项比较，差异返回 409；缺字段/类型错误 400。这里的 tenant_id 是操作者上下文，不是平台正在管理的目标企业，目标以路径指定，不得混用。

现有角色权限/成员授角/服务账号创建涉及资源码，以及编辑含既有资源码配置时，同样要求该对象；对应页面和协议测试一起升级。无资源的旧请求维持原契约，不默默把缺失字段补为“当前身份”。服务账号本身不支持人类 expected_context 或切企业。

## 2. 字段与分页

资源 VO：`id` UUID、`code`、`name_zh`、`sort` 整数、`status=active|disabled`、`kind=leaf`、`parent_code` 可空分组字符串、`revision` 正整数、`permissions` 数组（code/name_zh/scope/grantable_to_tenants/status/resource_code）。不返回秘密。

资源 code：长度 3–160，冒号分段的小写 ASCII 标识，每段 `[a-z][a-z0-9_-]*`，至少两段；不得含斜杠、点路径、空段、通配符或空白。权限 code 必须精确以所属 `resource_code + ':'` 为前缀、动作段匹配 `[a-z][a-z0-9_-]*`，不得冒充另一个资源；知识库 read 的完整码不靠相似前缀匹配。permission scope 固定 tenant；至少一项、每资源至多 32 项，代码不能重名。name_zh 去首尾空白后 1–100 字，sort 为 32 位整数；字段超限/未知写字段拒绝 400。

列表沿用当前 PageVO 的 `items/next_cursor`，不新增 has_more；next_cursor=null 表示结束。默认 limit=20、范围 1–200，越界与坏游标 400；目录按 sort/code，企业列表按 resource_code 稳定排序。游标绑定查询过滤与授权范围，不能跨企业复用泄露状态。

企业开通 VO：`tenant_id`、`resource_code`、`status=active|revoked`、`revision`（无记录显示 0）、`exists`、`resource_status`、`effective`、`granted_at`/`revoked_at`/`updated_at` 可空、`updated_by` 可空、`tenant_auth_revision`。effective 仅表示资源在该企业可授，不等于当前用户有读取权限。资源不存在返回 404，存在但无开通行投影 revoked/exists=false/revision=0；不能写入 revision=0 的伪持久行。

## 3. 新增接口

| 方法与路径 | 权限 | 请求/响应 |
|---|---|---|
| GET `/v1/admin/resources` | entitlement:manage | 分页、status 可选，200 目录含明确权限绑定 |
| POST `/v1/admin/resources` | entitlement:manage | expected_context + code/name_zh/sort/parent_code/permissions，201；kind=leaf、status=active 由服务端生成 |
| PATCH `/v1/admin/resources/{resource_code}` | entitlement:manage | expected_context + expected_revision + 可选 name_zh/sort/status；200 最新 VO；不接收 code/权限绑定修改 |
| GET `/v1/admin/tenants/{tenant_id}/entitlements` | entitlement:manage | 按目录投影开通/未开通状态并分页，含 tenant_auth_revision；目标不存在 404 |
| PUT `/v1/admin/tenants/{tenant_id}/entitlements/{resource_code}` | entitlement:manage | expected_context + expected_revision + expected_tenant_revision + status，200 VO 与 changed |
| GET `/v1/admin/tenant/resources` | 当前企业 + tenant:role:read | 仅本企业已存在开通记录（active/revoked）与有效状态，分页，不列其他企业或未公开资源 |

资源 code 放单个 URL 路径段，客户端正常编码，服务端按同一规则验证，禁止拼接任意后缀路径。后台登记不包含连接 URL、MCP 密钥、知识库凭据或就绪探测。

浏览器安全适配新增 `/web-api/admin/resources`、`/web-api/admin/resources/{resource_code}`、`/web-api/admin/tenants/{tenant_id}/entitlements`、`/web-api/admin/tenants/{tenant_id}/entitlements/{resource_code}`、`/web-api/admin/tenant/resources`，方法/字段/状态与对应 v1 一致，必须显式受控映射而非任意内部代理。写请求检查 Origin+CSRF，分页请求继承实时身份校验。

开通 PUT 示例（全部为说明占位符，不作为可发送的测试凭据）：

```json
{
  "expected_context": {"session_id": "<当前会话UUID>", "tenant_id": null, "ctx_version": 3},
  "expected_revision": 0,
  "expected_tenant_revision": 7,
  "status": "active"
}
```

并发规则：先验证操作者身份与 expected_context，在同一事务锁目标资源/企业并比较两个 revision；缺记录 expected_revision=0 仅用于首次创建。真实变更两项权威修订均推进；CAS 先于同状态幂等判断，旧 revision 一律 409。用最新 revision 重复相同状态返回 changed=false，不新增授权变更审计、不推进安全修订；普通访问日志可记录。首次设置 revoked 可创建 revoked 记录，但不能成为有效开通。

disabled 资源不能新开通（409），可回收；suspended 企业不能新开通（409），仍可由平台回收。新开通后仍需另外创建/配置角色与成员或服务账号，不自动填读权限。全局 disabled→active 仅恢复原有效开通，不凭空创建记录。

## 4. 现有授权接口的窄扩展

- 权限目录 GET `/v1/admin/permissions`、可授树 GET `/v1/admin/grantable-tree`、角色 POST `/v1/admin/roles` / PATCH `/v1/admin/roles/{id}`、权限替换 POST `/v1/admin/roles/{id}/permissions` 沿用当前路由及对应 `/web-api/admin` 别名，不另造第二套角色接口。角色详情来自现有列表/角色 VO，实施时一并扩展，不能凭空宣称已有单条 GET 路由。
- 角色详情原 `permission_codes` 继续表达持久化集合；增量字段 `permission_states` 按 code 给出 configured/effective/grantable/reason，页面按实际目标企业解析。可授树只允许新增当前可授码，已配置的失效码由详情补齐且不可当作新授权。
- 资源操作请求新增 `expected_context` 和 `expected_tenant_revision`；检查角色/成员实际 tenant_id 与可信当前企业一致。对全量替换先读取原集合后判断新增/保留/删除，不能按客户端自报集合绕过。
- 回收后不得因普通角色名称保存删除原失效码；原码移除是显式减权。无法新增的码可以保留在原目标，但不能挪给另一个角色/主体。
- 原平台角色/全局企业模板资源码默认拒绝保持。企业管理资格新码只改变资源授权的管理规则，不自动赋予资源读权限，也不把普通平台码下放。
- 服务账号创建请求的 `permissions` 可含开通资源的可下放企业权限；涉及资源时增加 expected_context/expected_tenant_revision。只允许全部成功或全部失败；不改原登录/轮换/过期/吊销规则。未开通权限拒绝，不能忽略后返回部分账号。

## 5. 实时核验与下游消费

沿用 POST `/v1/internal/identity/introspect`，`Authorization: Bearer <登记内部client凭据>` 与请求 `subject_token` 分别代表调用者和主体；合法的人类/机器 token、受众、执行引用严格按 I1 分型。

- 不新增必填 identity 字段或第五修订号；`permissions` 只含当前有效码，保持现有 schema_version/issuer/audience 和四修订字段语义。
- 主体有效但无资源许可：可返回 active=true，permissions 不含目标码。消费者必须再要求精确读码才调用资源。IAM 不接受浏览器自报 tenant/permissions 替代核验。
- 回收后旧人类会话可能按原修订策略 active=false，需要重新认证；新会话权限仍需明确授权。不能为了 active=true 隐藏 revision mismatch。
- 旧 verification_ref 复查遇到修订变化返回原 inactive/context_matches=false 形态，不签新许可。回收再开通后依然拒绝旧 ref。
- 机器 token 每次核验实时求交，无人类 session/revisions，企业/资源回收后不含对应码；凭据永久撤销/过期仍 inactive。
- `knowledge` 最小脚本：先核验再对本任务受控端点发资源读取；仅 A/air 正对照有请求，water/错企业/错受众/回收后请求数为 0。此证据只验证协议消费方式，不代表真实 RAG 已接入。

## 6. 错误与原子性

| 状态 | 语义 |
|---|---|
| 400 | 缺/错字段、字符串或布尔修订、坏 code/游标、非法绑定 |
| 401 | 未认证/过期/撤销的人类管理会话；introspection 主体无效沿用原 inactive 信封 |
| 403 | 有效调用者缺平台/企业管理资格、跨企业访问或越界授予；企业路径不暴露他企业目标详情 |
| 404 | 经相应授权后目标企业/资源/角色不存在，或原接口按不可见对象返回 404 |
| 409 | code 冲突、修订/上下文冲突、资源/企业状态不允许开通、新增不可授配置 |
| 503 | 数据库/必需 Redis/核验后端故障或超时，拒绝放行，不使用旧正向缓存 |

沿用统一错误信封与 request_id；不要把数据库堆栈、口令摘要、Cookie/token、内部原文回给客户端。审计失败可按当前明确 5xx 语义，但任何失败都不得返回成功或部分提交。授权变化审计记录动作、actor、目标企业/资源、前后状态/修订与结果，不记录主体 token。

## 7. 实施契约产物

实施者在 `contracts/` 更新现有 OpenAPI3.1、请求/身份 Schema 和消费者测试器，新增资源/开通/授权请求的正反 JSON 样本，与 Java Swagger 和 TS 类型对齐，给出文件 SHA-256 清单。请求类型反例必须送实际服务，不只做离线 Schema 校验。Markdown 中含占位符的展示示例不能当合法 fixture。原 rt-v1 与内部认证/主体受众样本继续复跑；跨服务接入包 I2/I3 使用此固定交接契约。
