# 独立共享IAM服务首期

## Why

Agent与知识库需要唯一的账号、企业和访问控制服务；现有Agent身份语义可复用，但身份与业务库/页面耦合。本项目先在隔离环境实现可独立验收的IAM，消费者切换和正式拆库作为后续跨仓库变更。

## What Changes

- 待用户评审的首期实施包：Spring Boot4 + JDK21 + Sa-Token有状态令牌，显式Redis适配、PG权威状态/修订与受限数据库角色。
- 实现账号建档、企业/部门/成员、平台/企业角色、可授权限、身份审计、登录/续期/实时introspection/切企业CAS/内部签票及执行上下文复查。
- 提供Vue 3 + TypeScript + Vite + Vue Router + Pinia + Element Plus独立中文管理前端；按原身份流程重建Vue页面，复用HTTP契约/字段/权限和UX行为，不直接复制React组件。Spring Boot承接同源浏览器会话、CSRF与SSO回调；业务关注城市/MCP连接配置/Agent运营页不搬入。
- 预留并实现受众受限的服务账号与内部客户端；保留rt-v1跨语言兼容与旧接口兼容适配能力，不在本包启用真实旧会话接管。
- 资源entitlement契约随包冻结；资源开通功能另立紧邻I1a变更，未实现时资源型权限默认拒绝。知识库remote上线依赖I1a。
- **本包仅在新项目、自有测试库/Redis/端口中实施。不得修改Agent/知识库源码、正式身份库、现有容器或迁移其用户。**

## Capabilities

### New Capabilities

- `shared-iam-http-contract`：实现无关的HTTP身份、续期、实时撤销、执行复查、内部票据、服务主体和SSO基础契约。
- `iam-tenant-administration`：独立用户与企业组织/RBAC/审计后台，数据库同租户防护及隔离环境交付。

### Modified Capabilities

无。本项目是新OpenSpec根，没有既有主规格；原项目未归档身份规格已作为只读来源核实，相关语义以参考快照与契约一致性用例保留，不在此替旧项目归档。

## Impact

- 本项目未来`server/`、`web/`、`contracts/`、`docs/`与隔离部署配置；当前只有规划文档，没有Java业务实现。
- 只读来源：`/Users/acerola/Dev/Python/air_agent`和`/Users/acerola/Dev/Python/RAG/env-rag-final`。原项目参考指纹记录2026-10-14当时状态；2026-10-15已归档并提交3/5，产品基线2d6f7c8，Agent Change4规划提交8620cf7。参考快照不重写；只读核实当前源码，不能将旧HEAD当作当前全部现状。
- Agent HTTP适配、知识库remote模式、通用entitlement和物理拆库各用后续change，不允许一次goal跨越全部阶段。
- 本轮只是编写/严格校验规划。用户评审本包后再使用启动提示词实施；规划完成不是产品验收。
