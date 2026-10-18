## Context

当前基线（计划时）：IAM dev 8da8ba1127b7ea7aa9c0a9f7289d90cbcc96a368；Agent dev 8e172de724709ac970e0fa0939d75d6c7dcdf0f5；RAG dev 1aa52b04976a94ad6e969775ced07cf1828ca81e 加现有 I3 未提交文件。精确工作区文件摘要单独冻结。根 openspec/config.yaml 的首期“其他仓库只读”仅适用于 I1，本次用户已明确授权跨仓库 I4 实施。

Java 表 iam.users 为 realm/account/status，Python users 为 account/is_active 且有不同 CHECK；禁止直接把 Python dump restore 进 Java schema。当前 Java IAM 是本轮身份复制源，未知旧 Python 身份需要人工对账后另行迁入，不假装其已完成迁移。原身份库只读保存，业务新库不放旧身份凭据。

## Goals / Non-Goals

**Goals:** 完整可复跑的隔离库演练；真实 Alembic/Flyway schema；remote 业务路径完全不依赖旧身份 SQL/行锁；UUID/FK/RLS/撤销/删除/保全新写；可审计操作和恢复门禁。

**Non-Goals:** 自动迁移现用账号、自动替用户处理身份冲突、生产流量切换、RAG 语料重建、UI重设计、重新验证所有未受影响的模型任务、修改 I2/I3 历史分数或强行关闭其保留项。

## Decisions

### 1. 单一协调 change 与写集合

实施者负责：IAM 新 scripts/i4/（或职责等价的小包）、新迁移/恢复说明、必要的 Java 迁移守卫和相关测试；Agent admin/api 的新增前向准备迁移、独立分离命令、remote_identity、followed_regions、必要的业务展示查询/ORM兼容和专项测试；RAG 仅 deployment/ 的新配置样例与专项契约测试/交接文档（若无代码需求可不改）。不得改旧迁移、历史评审、中央评分表、规划验收标准、AGENTS、原私有配置或现用数据。主评审者只负责规划、独立测试和评分，首次交付前不写产品代码。

### 2. 迁移与部署形态

不得让常规 Alembic upgrade head 在 local 部署上无条件撤销身份权限或替换其 FK。推荐新增兼容准备迁移，物理分离仅由显式 remote-only 目标命令执行，并持久标记版本/模式/来源指纹；local 应用误连已分离库必须启动失败。remote 配置不能以未迁移业务库成功启动后晚到500代替明确诊断。

可使用 pg_dump/pg_restore 或同等可验证复制；凭据只经环境/0600文件，不能出现在命令行/清单/日志。写入必须验证不同数据库身份、目标为空或具有本 run 所有权，拒绝源=目标、别名指向同库、非空无所有权目标、版本不符和意外依赖。dry-run 不执行 DDL/DML。执行中断应保留证据、失败关闭并可安全继续，不能自动清空非本 run 数据。禁止全局 prune、drop database 或 CASCADE 扫平依赖。

### 3. 本地引用与业务边界

复用 iam_reference_users/tenants/memberships，保留 UUID 和 membership 的 tenant/user 绑定；允许仅为展示的字段，不能用其 status/revision 进行授权。复合唯一约束和 FK 必须保留同租户条件，成员重绑必须拒绝，不能 ON CONFLICT 仅改修订而掩盖绑定冲突。业务内部 request/attempt/answer/feedback/selection FK 不动。

迁移对业务所需身份做全量 UUID 对账；同名不同 UUID、未知身份明确列为阻断，不删除业务行、不改归属。引用删除不得级联清除账本/费用/审计。业务和身份审计按事件域保留，混合旧 audit_logs/migration_ledger 不得整体当身份垃圾丢弃。

remote_identity 仅在可信实时 IAM 回复后建立本地引用，不能再写 public.users/tenants/tenant_memberships、设置 platform=on 或查询旧 users.created_at。偏好锁改本地聚合根/事务级 advisory lock；同成员并发替换原子且最多5个。remote 的用户/成员/审计展示查询不能隐含 JOIN 旧身份。local 旧数据库路径仍可工作。

运行/worker角色非owner、非BYPASSRLS；保留 FORCE RLS 和事务本地GUC。盘点完整依赖（含函数/视图/触发器/列授权/角色继承/默认权限），撤销旧身份表与安全定义函数旁路；仅 REVOKE 表级权限不算完成。分离后业务运行角色不具有 IAM 库连接/读取能力。

### 4. 单写、快照、增量与恢复

迁移阶段必须由持久状态和真实数据库权限/栅栏证据驱动，不能用 --frozen=true 或手写 JSON 代表停止写者。以 Java IAM 现有表为身份源，只允许 Java 单写；演练中先在线快照，再制造新账号/修订/撤销和业务墓碑/新写，然后冻结旧运行写者，排空存量事务，最终差异复制核对。可采用停写后的全量差异重算来实现最终增量，不强求 CDC，但必须包含删除、不能漏仅凭时间戳无法发现的变化，并报告实际范围/停写代价。

验收后生成明确的部署候选配置/清单，不自动改现用 DSN。新目标接收写入后，旧 DSN 回退必须被阻断；恢复旧快照需要合并最新身份修订/撤销/服务凭据状态和业务删除清单及全部新写，核对后才可解栅栏。无法安全合并时继续拒绝开放，不能仅打印提醒后成功。业务删除后不能通过备份恢复复活。

### 5. 演练与环境所有权

实施者只使用新建 `i4-luna-*` 自有容器/库；主评审者用 `i4-review-*`，端口分开。实施端口 50432(PG)/50479(Redis)/50400(IAM)；主评审 50532/50579/50500。先确认空闲。使用 macOS container 技能，已有 postgres:17-alpine / redis:7 镜像；只监听回环。禁止操作501xx/502xx/503xx服务、现有业务库和RAG数据；需要权限时说明确切自有资源。现成 Python venv 可使用，避免重复安装依赖。

## Risks / Trade-offs

- 纯业务库与 local 旧 ORM 共存：不能用全局改表名让 local silently broken；用明确模式选择或独立引用读取辅助层，并验证两种数据库。
- schema 往返复制 owner/RLS/函数ACL：必须查实际 catalog 和非owner实测，不能以 schema 文本或owner查询作证明。
- 真实存量可能有未迁到 Java 的身份：明确阻断清单，保留数据，不要求本轮替用户决定账号合并。
- 当前 I2/I3 保留项不重新包装成已全验；本轮不受影响的历史失败记录原测试身份。

## Migration Plan

盘点与只读计划 → 新目标/版本校验 → 在线快照 → 自有源新增/撤销/删除 → 停旧写排空 → 最终差异与FK/行级核对 → 非owner业务回归 → 隔离候选启用 → 新写与旧备份恢复反例 → 独立复验。任何门禁失败不开放新目标，不自动切旧写者。

## Open Questions

无阻塞实现的产品问题。生产部署地址、真实账号差异处置及维护窗口在真实切换前另行确定；本轮不能伪造这些值或当作已经放行。
