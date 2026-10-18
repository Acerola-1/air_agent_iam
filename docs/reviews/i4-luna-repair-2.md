# I4 Repair 2

修复范围仅限 reconcile ticket 的 IAM 实时租户核验、I4 CLI 四库客户端身份预检，以及 Agent 转换阶段的 CONNECT owner 豁免。

部署前，必须为 Agent 校准路径使用的**独立、持久登记** IAM 内部客户端显式配置 `tenant:status:read`，并将该客户端凭据配置给 Agent。不要把该 scope 加给所有内部客户端，也不要依赖 `BootstrapRunner.ensureRuntimeClient` 管理的 runtime client：它每次启动都会把 scopes 固定写回 `identity:introspect` 与 `runtime-ticket:issue`，手工追加的状态读取 scope 会在重启时丢失。缺少 scope 时端点返回 403；未建立受控持久登记路径前，不应启用校准调用。

IAM 新合同由 Flyway V23 提供，因此 I4 CLI 明确要求源与目标为唯一 Flyway head V23；V22 或未知 head 在预检拒绝，避免切换到缺少状态端点的 IAM。业务校准只读取该 IAM 实时状态，不以 `iam_reference` 授权，不生成 platform context 或旧身份表查询。local 模式仍沿用旧本地逻辑。

I4 CLI 在 snapshot claim/fence、freeze、finalize、recover check 前，经实际 `psql` 工具链探测 IAM/Agent 四个 DSN 的数据库名、OID、集群标识和连接角色，并与只读预检身份逐一比对。Agent 转换期间撤销 `agent_migrator` CONNECT；转换态检查只豁免实际 `expected_owner`，其他运行角色仍以 `has_database_privilege` 检查，继承的 CONNECT 仍会阻断。

验证结果：

- Python 本轮定向单测：28 passed；在临时副本运行以避开项目 `conftest.py` 的共享库自动 seed。Ruff check 与格式检查通过。
- PostgreSQL 17.10 自有临时库：owner=`agent_migrator` 时 owner CONNECT 为 true，`air_agent_runtime` CONNECT 为 false、无 owner membership；验证后已删除该临时库。
- Java `./mvnw -q -DskipTests test-compile`：通过，编译包含 V23 endpoint 及新增真实客户端 scope/status 集成测试。
- 未运行 Java 集成测试、Flyway V23 在 IAM 夹具上的迁移、四库全链 snapshot/freeze/finalize 或真实 HTTP 端到端；交由主控在其 repair2 自有夹具验收。一次普通 pytest 启动被沙箱拒绝连接共享 15432，未建立连接或修改数据库；随后隔离运行本轮 28 项单测通过。

修复2最初开始时间未采集；本次续接时已在进行。续接记录起点 2026-10-18 12:48:27 UTC，封笔时间 2026-10-18 13:05:01 UTC。模型 token 与完整工具成本未采集。生产 IAM/业务库未迁移或切流。

秘密扫描未取得结果：本轮在扫描运行中途被停止，不据此声称 PASS。

改动路径与 SHA-256 见本次交付记录；本报告不包含凭据。
