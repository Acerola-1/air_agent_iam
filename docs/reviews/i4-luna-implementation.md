# IAM I4 物理拆库实施首交

**Run:** `i4-luna-20261018` / `b6627831-3cfc-4b36-8168-e74d53243964`

**工作区:** IAM、Agent、RAG 的 `dev` checkout；模型调用未执行。模型/token遥测未提供。

**时间:** 实施起点 `2026-10-18T03:23:15Z`；准确结束时间与可采集阶段墙钟见本 run 的 `author/time-log.json`。

**独立验收:** 待主评审者冻结与复验；本文是作者报告，不是验收或评分。

## 结果与边界

已实现并在自有 Apple Container PostgreSQL 17、真实 Java IAM Flyway V22 和 Agent Alembic `0020_i4_reference_cleanup` 夹具上演练 IAM 身份引用与 Agent 业务库的隔离候选路径。运行角色访问、tenant RLS、真实 remote 登录/切换/登出、身份撤销、偏好并发、冻结排空、业务删除墓碑和旧快照恢复门禁均有本 run 证据。I4 CLI 的只读盘点和带显式 `--execute` 的快照、冻结、最终对齐流程可从隔离环境复跑。

这不是生产迁移完成声明。仅使用同一合成 UUID 演练 Java IAM 权威身份复制；没有将任何未知历史 Python 身份自动映射或声称已搬迁。生产 UUID 对账、账号冲突处理、生产 DSN/流量切换和正式解栅栏均未执行，也未获授权。新目标已有演练写入；恢复探针返回 `BLOCKED_forward_merge_required_keep_source_frozen`，旧源仍冻结。不要对本 run 执行 `recover --execute`。

本次只使用 `i4-luna-*` 自有资源与 50432/50479/50400 回环端口。证据与数据库快照放在本 run 的 `author/`，私有环境文件留在仓库之外且为 0600。RAG checkout 的冻结基线文件哈希完全未变；本轮只运行了离线合成远程 IAM 契约测试，没有写 RAG 源数据、索引或配置。

## OpenSpec tasks 状态

`openspec/changes/separate-iam-business-databases/tasks.md` 只勾选本轮已有实际证据的 1–4 项；第 5 节保持未勾选。

| 项目 | 状态 | 依据或未完成原因 |
|---|---|---|
| 1.1、1.2 | 完成 | 五份规划/验收文档已读取；冻结三仓 HEAD/文件摘要及只读 catalog、UUID 对账、阻断与无写入结果见 `baseline.json`、`author/latest-inventory.json`。 |
| 2.1–2.3 | 完成 | 0019/0020 前向迁移、目标模式/版本守卫、最小引用与绑定拒绝、远程偏好锁和 5 项并发上限均有真实 PG/API/本地回归证据；144 项业务约束语义比较一致。 |
| 3.1 | 完成 | 只读默认盘点、DB OID/owner/版本、权限/catalog/UUID 检查及目标 run 所有权证据已保存。 |
| 3.2 | 部分，未勾选 | 合成同 UUID 源到目标复制与旧源保留已演练；实现含未知 ID 阻断。但真实存量 UUID 未完整核对，演练中没有未知身份反例，不能将生产身份对账视为完成。 |
| 3.3 | 部分，未勾选 | 在线快照、delta、真实权限撤销/连接排空、最终对齐和 ACL 隔离已执行；尚未端到端制造进程中断并验证继续恢复。 |
| 3.4 | 完成 | 目标端真实新写、修订、会话/服务凭据撤销与业务删除墓碑均已验证；恢复检查拒绝直接回切并保持旧源冻结。 |
| 4.1 | 完成 | 自有真实 PostgreSQL/Flyway/Alembic 空库和存量夹具、非 owner/无 ctx/A-B/RLS/身份连通正反例均有证据。 |
| 4.2 | 部分，未勾选 | Agent remote/local API、偏好并发和退出撤销通过；RAG 仅有 58 个离线合成契约测试，没有实际 RAG→IAM 地址、UUID、记录边界运行验证。 |
| 4.3 | 完成 | I4 适用探针、格式/静态检查、秘密扫描及诊断边界记录见本 run 证据。额外误跑的 Agent 全管理套件是未与统一环境对比的诊断，结果单独保留，不当作基线也不声称通过。 |
| 4.4 | 完成 | 本文、可复跑步骤、证据路径、计时与保留门禁已交付；交付后停止编辑。 |
| 5.1–5.3 | 未勾选 | 主评审者独立职责。 |

## 实现改动

Agent 产品代码与迁移改动：

- `admin/api/app/main.py`：启动时检查本地/remote 数据库模式。
- `admin/api/app/routers/iam_remote.py`、`admin/api/app/schemas.py`：remote 展示不依赖旧身份 `created_at` 或敏感字段。
- `admin/api/app/services/remote_identity.py`：仅从可信 IAM 回复建立最小 `iam_reference_*` 引用；取消旧 `users/tenants/tenant_memberships` 占位写及 `air_agent.platform=on`；拒绝 membership 重绑。
- `admin/api/app/services/followed_regions.py`：remote 偏好使用事务级锁及可信 tenant 校验；保持 local 路径；原子执行最多 5 项限制。
- `admin/api/app/services/physical_separation.py`：持久模式/状态启动守卫。
- `admin/api/migrations/versions/0019_i4_separation_state.py`、`0020_i4_reference_cleanup.py`：前向准备状态及引用清理迁移；既有迁移未改。
- `admin/api/scripts/i4_separation.py`：显式隔离库 inventory、snapshot、freeze、finalize、recover CLI。
- `admin/api/scripts/i4_agent_local_regression.py`、`i4_agent_runtime_probe.py`、`i4_remote_api_probe.py`：本轮隔离路径探针。

所有改动文件的完整清单（含报告、任务清单、私有证据与快照）见 `author/changed-paths.txt`。三个仓库的原 HEAD 未移动，未提交、推送或归档。

## 主要验证与证据

所有作者证据位于 `docs/reviews/evidence/run/i4-luna-20261018/author/`，目录为 0700、文件为 0600。原始快照文件位于该目录下 run UUID 子目录。最终秘密扫描结果见 `author/secret-scan-final.txt`。主要结果：

- Flyway IAM V22 与 Alembic 0020 实际建库；只读盘点覆盖 189 functions、26 identity FKs、78 policies、53 RLS entries、53 table/column ACL entries、1 trigger、0 views，并记录 7 roles。该合成夹具无 catalog/UUID 阻断，`write_effect=false`；它不代表生产 UUID 无未知项。
- Agent 目标 runtime 为非 owner、非 superuser、无 `BYPASSRLS`；4 张引用/会话表启用 FORCE RLS。无 context 和无关 tenant 均读不到引用，正确 tenant 可读；旧 `public.users` 不存在，Agent runtime 无 IAM DB CONNECT 权限。绑定重绑及错误 tenant 被拒绝；5 项接受、第 6 项拒绝，6 个并发替换全部完成且最终不超过 5 项。
- Agent remote 登录、tenant 切换、`/auth/me`、登出后 401 与持久撤销通过；local 回归保留原本地路径和限额行为。
- Java IAM 目标真实登录/tenant 枚举通过；快照后禁用用户登录返回 401、revision=2、人类 session 已撤销。服务凭据先 introspect active，撤销后 inactive 且目标持久状态 revoked。
- 在线快照后加入新业务行，再删除快照 ownership/audit 行并增加新行；最终目标保留新行、移除被删行、department 保留。源业务角色被撤销并排空到 0 连接，目标 ACL 与运行角色独立。
- 144 个非身份业务约束逐项语义相同；原始 catalog 文本差异另存 `business-constraints-raw-catalog.json`，不是业务约束失败。
- 旧快照/旧 DSN 恢复探针因目标端后续写入而明确阻断，IAM 与 Agent 目标运行会话数为 0，源继续冻结；没有执行源重新开放。
- RAG 定向契约测试 `58 passed in 2.60s`，原始输出在 `rag-contract-tests.log`。不代表 live RAG 地址或记录边界验收。
- 实施过程中 Java Maven `86/86`、Web `23/23` 与构建成功、Agent Ruff check/format check 通过；这些先前命令的原始 stdout 未保存到本 run。Web 构建有大 chunk 提示。按本轮要求没有重跑未变更的通过项。
- 最终静态收尾 `git diff --check`（Agent）及 21 个本轮文本文件的 UTF-8/结尾换行/尾随空白检查通过，结果见 `author/static-checks-final.txt`。

**单独记录的未对比套件诊断：**实施中曾在 Agent `admin/api/.venv` 运行全管理 API pytest，结果 123 passed、42 skipped、14 failed、9 errors（48.187 秒）。该运行环境未与用户提供的统一基线对齐：失败涉及合成区划 seed 不完整、反馈采集关闭导致 422、事件配置差异；9 个 ledger-selection setup errors 为 `ModuleNotFoundError: common`。因此该次结果不归因为基线、不归因为 I4，也不称全套件通过。未修改或删除 I2/I3 旧测试。用户提供的独立 Agent 冻结基线为 root `.venv`、两个新 local 测试库及完整 conftest 区划 seed + 指定功能开关：管理 API 189 passed/7 skipped、root remote 49 passed、RAG remote 90 passed；实施者未在本轮重跑该基线。主评审可在统一环境独立对比。

## 复跑方式

复跑写操作必须新建主评审或实施者自有空库、固定回环端口、准备 0600 env 文件；不得复用生产库、已冻结源库或已分离 remote 目标库。命令只读取 env 文件路径，不把 DSN 放入参数或日志。只读盘点：

```bash
export I4_PRIVATE_ENV=/path/to/private-0600.env
PY=/Users/acerola/Dev/Python/air_agent/admin/api/.venv/bin/python
$PY /Users/acerola/Dev/Python/air_agent/admin/api/scripts/i4_separation.py \
  --env-file "$I4_PRIVATE_ENV" inventory
```

在全新隔离夹具上，先用 Java IAM API 运行作者的 `seed_java_iam.py`，再用 `seed_agent_source.py seed` 建立相同 UUID 的合成身份及业务行；对 IAM/Agent source 和 target 分别用真实 Flyway V22/Alembic 0020 建库。迁移器阶段命令如下（每个写阶段仅对该 run 自有目标执行）：

```bash
$PY /Users/acerola/Dev/Python/air_agent/admin/api/scripts/i4_separation.py --env-file "$I4_PRIVATE_ENV" snapshot --run-id b6627831-3cfc-4b36-8168-e74d53243964 --execute
# 快照后：运行作者 exercise_iam_delta.py、exercise_service_token.py 和 seed_agent_source.py delta
$PY /Users/acerola/Dev/Python/air_agent/admin/api/scripts/i4_separation.py --env-file "$I4_PRIVATE_ENV" freeze --run-id b6627831-3cfc-4b36-8168-e74d53243964 --execute
$PY /Users/acerola/Dev/Python/air_agent/admin/api/scripts/i4_separation.py --env-file "$I4_PRIVATE_ENV" finalize --run-id b6627831-3cfc-4b36-8168-e74d53243964 --execute
$PY /Users/acerola/Dev/Python/air_agent/admin/api/scripts/i4_separation.py --env-file "$I4_PRIVATE_ENV" recover --run-id b6627831-3cfc-4b36-8168-e74d53243964
$PY /Users/acerola/Dev/Java/air_agent_iam/docs/reviews/evidence/run/i4-luna-20261018/author/verify_business_tombstones.py --env-file "$I4_PRIVATE_ENV" --output /path/to/private-evidence/tombstones.json
$PY /Users/acerola/Dev/Java/air_agent_iam/docs/reviews/evidence/run/i4-luna-20261018/author/verify_business_constraints.py --env-file "$I4_PRIVATE_ENV" --output /path/to/private-evidence/constraints.json
```

首次复跑应使用新 run UUID 并重新建立全新库，不能在本文所列 run 上重复 snapshot/freeze/finalize。`recover` 默认仅检查；只有已验证零 delta 且另有明确恢复授权时才允许讨论 `--execute`。本轮目标已有新写，必须保持阻断。

Agent 三个专项探针可在相同自有 fixture 中运行 `i4_agent_runtime_probe.py`、`i4_remote_api_probe.py`、`i4_agent_local_regression.py`；业务 tombstone/constraint 验证脚本与 RAG 定向 pytest 命令留在 author 证据目录及 `rag-contract-tests.log`。RAG 测试命令：

```bash
cd /Users/acerola/Dev/Python/RAG/env-rag-final
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider \
  tests/test_remote_iam.py tests/test_remote_boundaries.py -q
```

## 部署候选形状与保留门禁

候选 Agent 配置仅为 `AGENT_IDENTITY_BACKEND=remote`、新业务 PostgreSQL URI、授权 IAM base URL 与服务端注入的 IAM runtime client credentials。实际生产值、账号差异、授权范围和维护窗口均待用户/运营方确认；本报告不把 `127.0.0.1:50400` 演练地址当作生产配置，也未改现用 env/DSN。

继续保持以下门禁：生产未知身份/同名异 UUID 对账、真实 RAG 地址/UUID/记录边界、进程中断续跑、统一环境下的 Agent 管理套件对比、主评审独立反例与冻结。生产流量切换、旧源解栅栏、恢复执行与正式身份迁移均未获授权。
