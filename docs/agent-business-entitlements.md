# Agent 业务授权与 root 测试配置

日期：2026-10-19。本文件描述 IAM 侧已实施的 Agent 业务资源、企业开通、角色授权、root 一次性配置与第二阶段清理命令。共同契约见 `openspec/changes/archive/2026-10-20-add-agent-business-entitlements/business-authorization-contract.md`（两仓 SHA-256 一致）。

## 1. 当前业务目录

| 稳定业务编码 | 中文名 | 资源码 | 唯一使用权限 |
|---|---|---|---|
| basic-qa | 基础问答 | `agent:business:basic-qa` | `agent:business:basic-qa:use` |
| data-analysis | 数据分析 | `agent:business:data-analysis` | `agent:business:data-analysis:use` |
| intelligent-tracing | 智能溯源 | `agent:business:intelligent-tracing` | `agent:business:intelligent-tracing:use` |

业务目录由 Flyway `V24__agent_business_entitlements.sql` 幂等登记，复用 `resource_catalog`、`permissions`、`tenant_entitlements`、企业角色与成员角色，不新增业务关系表。

Agent 运营查看使用既有非业务权限码，按原分级授予：

- `agent:operations:read`
- `agent:metrics:read`
- `agent:content:read`

## 2. 有效权限口径

业务使用码出现在 `iam.identity.v1.permissions` 中必须同时满足：

1. 账号、会话、企业、成员关系有效；
2. 企业当前有效开通该业务资源；
3. 成员在当前企业内通过有效企业角色获得该业务的使用权限；
4. 权限定义与资源目录均启用。

平台角色、全局企业模板和用户名（包括 root）都不能绕过上述求交；没有企业上下文时没有业务使用权。企业回收开通、角色撤权/停用、资源或权限停用都会推进对应修订，使旧执行引用复查失败。

## 3. 中文管理界面

- 平台「企业与组织 → 资源开通」：按中文业务名展示三项 Agent 业务，区分未开通、已回收、已开通（可授/不可授）与目录停用。
- 企业「企业角色 → 新建/编辑角色」：在「Agent 业务（仅显示本企业已开通业务）」中勾选使用权限；未开通业务不会出现在可授列表。已配置但失效的权限继续显示原因，可显式取消。
- 企业「企业资源」：只读查看本企业开通状态。
- 不新增 Skill/MCP 人员授权页面；平台开通不自动赋予任何成员权限。

## 4. root 一次性配置（本轮已在正式库执行）

命令默认只读；`apply` 必须显式给出目标企业清单或 `--all-active-tenants=true`。精确定位现有 root UUID，校验账号为 `root` 且状态 `active`；不修改口令、不创建替身、不启用停用成员。

```bash
# 只读计划（全部当前 active 企业）
bash scripts/iam-ops.sh plan --iam.ops.root-user-id=<ROOT_UUID>

# 显式执行全部当前 active 企业（可重复执行；无变化不推进修订、不重复审计）
bash scripts/iam-ops.sh apply \
  --iam.ops.root-user-id=<ROOT_UUID> \
  --iam.ops.all-active-tenants=true

# 复验
bash scripts/iam-ops.sh verify --iam.ops.root-user-id=<ROOT_UUID>
```

每个企业创建缺失的成员关系与专属角色 `tenant_agent_test_admin`，开通当前全部已注册 Agent 业务并授予三项使用码与三项运营查看码。企业事务包含开通、成员、角色、授权、审计与修订；单企业失败只回滚该企业。

## 5. 第二阶段：发布检查、最终清理与复验

以下命令在 Agent 已切换新模型、旧表/旧接口/旧码请求停止后执行。命令可重入，不创建 dump、快照、影子库、备份表或旧表改名，不保留旧鉴权回退。

```bash
# 1) 只读发布检查：root 授权复验 + 旧 MCP 授权清点
IAM_OPS_ROOT_USER_ID=<ROOT_UUID> bash scripts/iam-release-check.sh

# 2) 最终清理（单一事务删除 enterprise:mcp、mcp:binding:read、mcp:binding:manage
#    的定义/角色关联/服务账号关联，推进修订并写审计）
IAM_OPS_ROOT_USER_ID=<ROOT_UUID> bash scripts/iam-final-cleanup.sh --apply

# 3) 单独复验（脚本已自动执行，可再次运行）
bash scripts/iam-ops.sh verify --iam.ops.root-user-id=<ROOT_UUID>
bash scripts/iam-ops.sh inventory
```

可选显式目标企业：`IAM_OPS_TENANT_IDS=<UUID,UUID>`；账号默认 `root`，可用 `IAM_OPS_EXPECTED_ACCOUNT` 覆盖。所有证据写入 `docs/reviews/evidence/run/`（Git 忽略）。

清理范围仅限实际命中的旧 Agent MCP 权限定义及关联；知识库资源/开通/角色配置、通用身份/角色/权限表、有效业务配置、审计与历史迁移均保留。无专用旧表时清点结果为零项，不删除通用表。

## 6. 实际浏览器复验记录（2026-10-19）

在隔离测试库（`iam_test`）与独立 `19200` 端口实例上使用真实浏览器完成：

- 平台「企业与组织 → 资源开通」显示中文业务名、编码、目录/开通/可授状态；回收「数据分析」后状态变为「已回收」，企业修订推进，重新开通后恢复。
- 企业管理员在「企业角色」中只看到当前已开通业务；回收数据分析后，新建角色对话框不再显示该业务，仅保留基础问答与智能溯源。
- 创建含数据分析使用码的企业角色并授予成员后，成员 `/web-api/auth/me` 的权限精确为 `["agent:business:data-analysis:use"]`；企业回收该业务后，成员仍保留角色配置但实时权限为空，证明开通与角色求交生效。
- 键盘：登录输入、Tab 焦点与 Escape 关闭弹窗可用；390×844 窄屏下资源开通弹窗全部业务行与操作按钮可见可操作。
- A→B→A 迟到保存：两个同会话标签页中，一个标签页把会话切到企业 B 后，另一标签页在旧上下文提交新建角色，后端返回「表单上下文已变化，请重新打开」，页面不显示成功、输入保留，角色未创建。

截图与命令输出保存在 `docs/reviews/evidence/run/agent-business-ui-20261019/`（Git 忽略）。

## 7. 新增业务步骤

1. 在后续 Flyway 迁移中登记新的 `agent:business:<code>` 叶子资源与同前缀 `:use` 权限（`grantable_to_tenants=true`，scope `tenant`）。
2. 更新并冻结共同契约中的稳定编码、中文名与 Agent Graph 映射。
3. 平台管理员显式开通；企业管理员在本企业独有角色中显式授予。
4. 不自动授予既有企业、既有角色或 root；需要时重新执行显式 root 配置命令。

## 8. 外部范围边界

IAM 只负责本系统内的业务开通与人员授权。外部 MCP/数据源的企业隔离或全数据范围必须由实际连接与服务端能力证明；没有可验证协议时如实报告为未证实，不用 root 特判或万能令牌宣称完成。
