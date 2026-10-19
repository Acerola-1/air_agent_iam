# Agent 业务授权与 root 正式配置交付报告

日期：2026-10-19（Asia/Shanghai）。Change：`add-agent-business-entitlements`。本轮在 `dev` 工作区实施代码与计划明确的正式 root 授权；未 commit、未 push、未 archive。

## 1. 结论摘要

| 项目 | 结果 |
|---|---|
| 三项 Agent 业务目录与使用权限 | 已完成（Flyway V24，幂等） |
| 企业开通 ∩ 本企业角色授予 | 已完成并通过真实 PG/Redis 测试与浏览器验证 |
| 实时修订与旧执行引用失效 | 已完成；新增权限启停修订触发器 |
| Vue 中文开通/角色业务选择 | 已完成；未新增 Skill/MCP 勾选 |
| root 运维计划/执行/复验命令 | 已完成并做空库与正式库验证；不挂启动流程 |
| 旧 MCP 授权清点/清理命令 | 已完成并做空库删除、回滚、幂等验证；正式清理未执行 |
| 正式 root 授权（19132/iam_identity） | 已完成：4 个当前 active 企业全部成功 |
| root 正常登录读回 | **未完成（外部阻塞）**：现有 4 字符口令不满足登录 8..256 字符策略，未改口令 |
| 联合验收（Agent 运行/旧表删除后清理） | 未执行，任务保持未完成 |

## 2. 代码与迁移

- `server/src/main/resources/db/migration/V24__agent_business_entitlements.sql:1`
  - 登记 `agent:business:basic-qa|data-analysis|intelligent-tracing` 叶子资源与各自唯一 `:use` 权限。
  - 幂等登记 `agent:operations:read`、`agent:metrics:read`、`agent:content:read`（既有环境保留原 id/名称）。
  - 新增 `permissions_bump_affected`：权限启停时推进受影响用户、成员与已开通企业的修订。
- `server/src/main/java/com/airagent/iam/ops/`
  - `OpsApplication` / `OpsConfiguration`：独立非 Web 运维上下文，不进入正常启动流程，不暴露 HTTP。
  - `OpsService`：root 计划/执行/复验、旧 MCP 清点/清理；逐企业事务、写前冲突检查、审计与检查点。
  - 活跃代码扫描仅命中 `OpsService` 的清理目标常量；`MenuCatalog`、V2/V24 种子与前端无旧 MCP/Skill 菜单或兼容读取（`legacy-code-scan.txt`）。
  - `OpsMapper` + `mapper/ops/OpsMapper.xml`：显式 SQL 与 RLS/触发器边界。
- `server/src/main/java/com/airagent/iam/admin/`
  - `EntitlementVO` 增加 `resource_name_zh`；`GrantableTreeVO.Leaf` 增加 `resource_name_zh`。
  - `ResourceGrantSupport.resourceNameZh`；角色可授树与开通投影返回中文业务名。
- `web/src/`
  - `api/business.ts` + `business.spec.ts`：业务分组、中文名与状态文案。
  - `TenantEntitlementDialog.vue`：中文业务名/编码、目录/开通/可授状态与回收确认。
  - `RoleEditDialog.vue`：单列「Agent 业务（仅显示本企业已开通业务）」；保留失效配置原因。
  - `TenantRolesView.vue`、`PlatformResourcesView.vue`：中文提示与 Agent 业务标识。
- `contracts/`
  - OpenAPI 同步 `resource_name_zh` 与业务权限说明；新增 `agent-business-with-tenant.json` 正样本。
- `scripts/`
  - `iam-ops.sh`、`iam-release-check.sh`、`iam-final-cleanup.sh`、`verify-root-entitlements.py`。
- 文档：`docs/agent-business-entitlements.md`（配置路径、新增业务步骤、第二阶段命令）。

## 3. 测试与证据

### 3.1 全量测试

- 基线（改动前）：87 项 Maven 测试通过（`evidence/.../baseline-maven-tests.log`）。
- 本轮最终：99 项 Maven 测试通过（0 failures / 0 errors，01:40 min；`evidence/.../full-maven-tests-final.log`）；新增 `AgentBusinessEntitlementIntegrationTest` 7 项、`OpsCommandIntegrationTest` 5 项。
- Vue：`npm test` 28 项通过（含新增 5 项业务分组/状态测试）；`npm run build` 通过。
- 契约：`python3 contracts/consumer/protocol_consumer_test.py` 45 项通过。
- 密钥扫描：`scripts/verify-secret-scan.sh` PASS（771 个交付路径，真实秘密零命中）。
- 关键反例：未开通授角 409、平台角色携带业务码 409、未知码 400、企业自开通被 RLS 拒绝、全局模板资源授权被触发器拒绝、资源/权限停用与角色撤权使旧会话/旧执行引用失效、A/B 企业隔离、root 平台管理员撤权后同样失去业务码。

### 3.2 正式 root 配置

- 目标：`dd5ca3c0-a454-466e-b2f7-a7fc5191867e`（账号 `root`，active）。
- 企业：alpha-env、beta-env、gamma-env、root-acceptance（执行时全部 active 企业）。
- 结果：4/4 成功；每企业一条 root 成员关系、一个 `tenant_agent_test_admin` 角色、3 项业务开通、6 项权限、审计 1 条；第二次执行 0 applied / 4 unchanged，未重复推进修订。
- root UUID、`auth_revision=7`、口令摘要 SHA-256 前后一致；知识库 7 条开通保持不变；旧 MCP 权限与 94 条角色关联未提前删除。
- 证据：`formal-baseline-before-v24.json`、`formal-root-plan.json`、`formal-root-apply.json`、`formal-root-verify.json`、`formal-baseline-after-root.json`、`formal-root-apply-second.json`。

### 3.3 浏览器

见 `browser-verification.md` 与 `browser/` 截图。覆盖平台中文开通/回收、企业角色业务选择、成员实时业务码、回收后角色保留但权限为空、A→B→A 迟到保存 409、390×844 窄屏与 Escape。

## 4. 未完成项与阻塞

1. **root 正常登录读回（6.1 部分未完成）**：正式 root 现有口令为 4 字符；IAM 登录路径强制 8..256 字符，`/v1/auth/login` 返回 `400 password 不合法`。按用户要求未修改口令、未创建替身、未伪造会话。`scripts/verify-root-entitlements.py` 已准备好，待用户提供/批准满足策略的认证方式后执行。
2. **联合验收（6.2）**：Agent 新模型运行、root Agent 数据查看、外部 MCP 范围未验证；未宣称全数据隔离完成。
3. **最终旧授权清理（6.3）**：按用户要求未执行。正式库当前旧 MCP 清点为 3 个定义、94 条角色关联、0 条服务账号关联；清理命令与空库回滚/幂等验证已完成。
4. **正式服务进程**：19100 当前仍运行上一版 jar；V24 与 root 授权已在数据库生效，新前端/后端代码需由协调者按标准入口重启后生效。本轮未重启共享正式服务。
5. **键盘提交**：IAB 后端下 Enter 未触发登录表单提交，已用点击完成登录；Tab 焦点与 Escape 已验证。未把工具级现象当作应用缺陷或纯键盘提交通过。

## 5. 失败与修复记录

- V24 首跑被 `resource_catalog` FORCE RLS 拒绝 → 迁移内增加事务级平台上下文。
- V24 触发器多一个右括号 → 修正后直接执行验证。
- MyBatis 构造器映射对 `long/int` 需 `_long/_int` → 修正 Ops 结果映射。
- 测试库截断 `tenants/users` CASCADE 会清空角色，导致后续 Spring 上下文 BootstrapRunner 失败 → 新测试在截断事务内重建 V2/V20/V24 种子；截断移入事务，失败可回滚。
- MockMvc 调内部异步端点返回空体 → 测试使用 `asyncDispatch`。
- 浏览器资源开通弹窗初次不显示业务 → 测试库缺少 V20 已给 `tenant_admin` 追加的 `tenant:resource:grant`；补回后业务选项正常，代码边界未放宽。

## 6. 第二阶段命令（可直接执行）

目标：现有 root `dd5ca3c0-a454-466e-b2f7-a7fc5191867e`；默认覆盖执行时全部 active 企业，可用 `IAM_OPS_TENANT_IDS=<UUID,UUID>` 限定。命令可重入，不创建备份/快照/影子库/备份表，不保留旧鉴权回退。

```bash
# 1) 发布前只读检查：root 授权复验 + 旧 MCP 清点（证据写入 Git 忽略目录）
IAM_OPS_ROOT_USER_ID=dd5ca3c0-a454-466e-b2f7-a7fc5191867e \
  bash scripts/iam-release-check.sh

# 2) Agent 切换新模型、停止旧码请求后，执行 IAM 最终清理与自动复验
IAM_OPS_ROOT_USER_ID=dd5ca3c0-a454-466e-b2f7-a7fc5191867e \
  bash scripts/iam-final-cleanup.sh --apply

# 3) 单独复验（可重复执行；清理后旧码应为零项）
bash scripts/iam-ops.sh verify \
  --iam.ops.root-user-id=dd5ca3c0-a454-466e-b2f7-a7fc5191867e
bash scripts/iam-ops.sh inventory

# 4) root 正常登录/切企业读回（待口令或认证方式满足 8..256 字符策略）
IAM_ROOT_PASSWORD='<受保护输入>' python3 scripts/verify-root-entitlements.py \
  --output docs/reviews/evidence/run/agent-business-20261019/formal-root-readback.json
```

清理范围固定为 `enterprise:mcp`、`mcp:binding:read`、`mcp:binding:manage` 的命中定义与关联；知识库、通用 IAM 表、有效业务配置、审计与历史迁移保留。

## 7. 耗时与口径

- 本轮实施与验证约 2026-10-19 16:38–17:31（Asia/Shanghai，约 53 分钟），以命令时间戳为准。
- Token 用量：本会话工具未提供可核对的计量值，报告不编造 Token 数。
- 未执行：commit、push、archive、正式旧授权删除、Agent 联合验收。

## 8. 证据索引

`docs/reviews/evidence/run/agent-business-20261019/`（Git 忽略）：

- `contract-and-baseline.md`、`browser-verification.md`
- `baseline-maven-tests.log`、`full-maven-tests-final.log`、`web-tests.log`、`web-build.log`、`contract-consumer-test.log`、`secret-scan-final.txt`、`legacy-code-scan.txt`
- `formal-baseline-before-v24.json`、`formal-baseline-after-root.json`
- `formal-root-plan.json`、`formal-root-apply.json`、`formal-root-apply-second.json`、`formal-root-verify.json`
- `inventory-formal-before-cleanup.json`、`formal-root-readback-blocked.json`
- `browser/01-platform-entitlements.png`、`browser/02-tenant-role-business-options.png`
- `test-db-smoke/`：隔离测试库上的 CLI 计划/执行/复验/清点/清理脚本原始输出。
