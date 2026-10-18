## Why

I2、I3 已由用户接受。Java IAM 已有独立的 iam/iam_auth schema，Agent 的 remote 请求仍向 public.users/tenants/tenant_memberships 写技术占位行，偏好锁和部分业务 FK 仍依赖它们。旧设计中的“Java直接接管Python同schema”与实际实现不符，不能按原图机械复制。

本 change 交付可运行的物理分离工具、Agent remote 纯业务库适配及真实隔离数据库迁移/恢复演练；以当前 Java IAM 为唯一身份权威，保留 UUID、业务约束和撤销/删除状态。正式用户数据与流量的切换是验收后的独立运维放行，不在本次自动执行。

## What Changes

- 跨库只读盘点 FK、视图、函数、触发器、RLS、角色授权和代码身份依赖；生成可审查清单，未知依赖阻断。
- 复用 iam_reference_* 最小引用，替换业务到旧身份表的 FK、身份父行锁和 remote ORM 查询；保留本地部署模式，在独立旧形态数据库上继续可用。
- 提供显式选择源/目标、默认 dry-run、目标所有权检查、单写冻结、快照与最终增量核对、校验和、恢复门禁及旧权限撤销的工具。既有数据库一律不自动修改；工具仅对显式声明的目标/自有演练源执行写操作。
- Java IAM 到独立 IAM 目标采用实际 Flyway schema；Agent 纯业务目标不保留口令/角色/旧会话身份表。未能在权威找到的历史 UUID 和同名不同 UUID 明确阻断并给出隔离报告，禁止重 seed/自动合并。
- RAG 仅证明 IAM URL/显式 UUID 映射与现有记录边界不变，不搬迁 RAG 数据和检索索引。
- 保存首次交付、独立验收、修复轮次及五维评分；不把评审者补修计为实施模型成果。

## Capabilities

### New Capabilities
- `iam-physical-separation`: 分库、引用、迁移和恢复门禁。

### Modified Capabilities
无；本协调 change 不改 I2/I3 冻结的 HTTP 身份协议或资源授权语义。

## Impact

协调根为本仓库；写边界见 design.md。Agent 当前 dev 基线已提交 I2；RAG 仍有 I3 未提交工作，必须逐文件保留。不会切换现用服务 DSN、修改原用户、调用计费模型、commit/push/archive。


## 验收后单独授权的部署

原实施/隔离评估范围按上文冻结。用户后续明确要求真正提交与切库，协调者在独立运维窗口执行实际迁移；部署新增适配与证据单列在docs/reviews/iam-i4-live-cutover.md，不追改首次计划、作者报告或评分。
