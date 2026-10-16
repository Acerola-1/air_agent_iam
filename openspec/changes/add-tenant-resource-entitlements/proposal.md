# 企业资源开通（I1a）

## Why

独立 IAM 已有用户、企业、成员和 RBAC，但目前资源型权限仍被 API、数据库触发器和机器身份查询主动禁止，无法表达“平台允许企业使用哪些资源、企业再授权哪些成员”。本变更补齐通用资源开通闭环，为后续 Agent/RAG 通过 HTTP 接入提供可靠授权结果；不实施消费者切换。

## What Changes

- 复用 `iam.resource_catalog`、`iam.tenant_entitlements`、`iam.permissions.resource_code`，新增资源登记、目录维护、企业开通/回收及只读企业资源清单接口。首个资源为知识库，权限码固定为 `knowledge:lib:<library_code>:read`。
- 资源开通只扩大企业可授范围，不自动授予任何成员、角色或服务账号；有效资源权限必须同时满足主体有效、明确授予、权限有效、目录启用与企业开通。
- 用显式管理权限 `tenant:resource:grant` 解决企业首轮授权：它与角色/成员写权限共同裁决资源权限配置，不赋予知识读取能力；普通管理权限仍保持现有可授子集规则。
- 让企业独有角色、成员授角色和服务账号建档使用同一开通检查，禁止全局企业模板或平台角色携带资源读权限；收回时保留已有授权配置、下一次实时核验立即失效。
- 授权改变、租户修订、审计同事务；覆盖人类 Bearer、Cookie、执行引用和机器令牌，保持四修订字段、受众与 rt-v1 格式。
- 在现有 Vue 后台增加资源目录、企业资源开通及企业只读资源页面，完善角色编辑中的可授/已配置但失效呈现，服务账号支持最小知识库读权限建档。
- 交付增量 Flyway 迁移、HTTP/Schema/样本、真实 PostgreSQL/Redis/浏览器反例与独立验收入口。保留既有压力性能问题，不以本包功能完成宣称全系统可上线。

## Capabilities

### New Capabilities

- `tenant-resource-entitlements`：通用资源登记、平台企业开通、受限下放、实时有效权限与回收、租户隔离、审计及中文管理交互。

### Modified Capabilities

无已发布主规格需要直接修改：当前 `openspec list --specs` 为空，I1 两份规格仍位于活动 change。本能力引用 I1 的身份与管理基线，并将其“资源开通未实施时默认拒绝”的条件推进为有明确开通证据才允许；不提前归档或改写 I1 历史产物。实施时检查是否出现新主规格，若已归档则先协调 delta 路径，不能复制近似能力或删改旧证据。

## Impact

- 后端：Spring Boot 4 / JDK 21 / MyBatis MVC；资源域新增 Controller/Service/Mapper/DTO/VO/DO，接入现有角色、成员授角、服务账号、权威快照和内部核验。
- 数据库：当前源码迁移最高 V19；新迁移从实施时实际 head 之后追加，复用已存在资源表，不修改 V1–V19，不重建表或重置既有账号/UUID。
- 前端：现有 Vue 3 / TypeScript / Vite / Pinia / Element Plus、菜单目录及 Cookie/CSRF 适配；不引入 Next.js、独立 Node BFF 或新认证源。
- 契约：在现有 `/v1/admin` 与 `/web-api` 体系内增量扩展；身份 JSON 既有必填字段、rt-v1 与内部客户端 Bearer 语义保持。
- 参考仓库只读：`/Users/acerola/Dev/Python/air_agent` 与 `/Users/acerola/Dev/Python/RAG/env-rag-final`。不迁真实用户、不修改消费者、不动共享数据库/容器、不物理拆库、不自动 commit/push/合并/归档。

配套：`design.md`、`http-contract.md`、`acceptance.md`、`tasks.md`、`implementation-goal.md`。本轮仅生成计划，任务全部未实施。
