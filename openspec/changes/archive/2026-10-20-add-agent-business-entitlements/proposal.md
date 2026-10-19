# Proposal

## Why

Agent 的企业和人员授权统一收敛为业务，管理员不再配置 Skill/MCP 工具权限。IAM 已有资源目录、企业开通及企业角色资源授权，应复用该机制提供稳定业务权限，并在交付时给现有 root 完成真实测试授权及旧授权残留清理。

## What Changes

- 注册 Agent 当前三项业务资源及对应 `:use` 权限，企业开通与本企业角色授权求交，复用实时身份/执行引用复查和修订机制。
- Vue 后台提供中文业务开通和角色业务选择，明确未开通、角色未授权、停用状态；不增加 Skill/MCP 勾选界面。
- 为现有 root 在当前有效企业建立明确成员/专用企业角色、授予当前已注册 Agent 业务及必要业务数据查看权限；保留现有登录凭据，不用平台管理员自动放行。
- **BREAKING**：清除本项目实际存在的旧 Agent Skill/MCP 人员授权定义、角色/服务账号授权边、无效缓存及兼容种子；不复制知识库授权，不建立重复的业务关系表。
- 根据用户要求，不生成或保留本次旧授权备份、dump、快照和备份表；与 Agent 协调一次发布，在新体系验证后完成旧体系物理清除。

## Capabilities

### New Capabilities

- `agent-business-entitlements`：Agent 业务资源、角色授权、实时求交与中文配置。
- `agent-root-test-access`：通过普通授权链路为指定现有 root 完成可验证测试权限与旧授权清理。

### Modified Capabilities

无。`tenant-resource-entitlements` 当前仍在活动 change 中，尚非主规格；本项复用其已实现行为、不复制同名新能力，不修改其历史任务与验收事实。

## Impact

- 配套 Agent change：`/Users/acerola/Dev/Python/air_agent/openspec/changes/archive/2026-10-20-simplify-agent-business-authorization/`。
- 涉及资源目录、企业开通、角色可授树、有效身份查询、权限变更修订、Vue 企业/角色页面、Flyway 后续迁移与一次性 root 配置工具。
- 保持 `iam.identity.v1` 的现有 `permissions` 集合和执行引用复查响应，优先不扩展令牌或新增专门的业务令牌。
- 正式身份库为19132/iam_identity；本规划不恢复旧环境，不操作 Agent/RAG 数据库，不调整知识库权限，不改变 root 密码或增加无限期会话。
- 本轮只写计划，任务全部未完成；开始实施需用户后续指令。每仓负责自己的代码和清理，共同发布由同一协调者完成。
