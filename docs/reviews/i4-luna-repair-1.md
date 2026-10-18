# I4 repair 1 实施报告

## 时间与状态

- 修复开始：2026-10-18 07:38:37 UTC。
- 产品代码与定向验证停止编辑：2026-10-18 09:17:36 UTC；总墙钟 1 小时 38 分 59 秒，含协调暂停，不代表纯编码时间。
- 可定位阶段：初始实施 07:38:37–09:08:32 UTC，1 小时 29 分 55 秒；最后版本号、旧身份 FK 与 CLI 收口 09:08:32–09:17:36 UTC，9 分 04 秒。更细分的阶段计时未可靠记录。
- 工具及 Token 用量：未采集。
- 这是实施者报告，等待主评审独立全路径复验；首交冻结和 66/100 原分未改。本轮未执行生产迁移、存量身份搬运或流量切换。

## 完成的定向修复

Agent 的远程 `/auth/menus` 现在只用可信 IAM 权限码生成非授权性展示目录；不再查询已移除的本地 `permissions`，展示结果不会授予权限。

I4 inventory 现在枚举所有指向 `LEGACY_IDENTITY` 九张待删除表的入站 FK，并按 schema、表、约束名、目标核对白名单。白名单包含当前 Alembic head 的旧角色/权限内部约束；未审查的业务 FK（包括指向 `roles`、`permissions`、`auth_sessions`）在 snapshot 写入前阻断，不创建角色或权限副本。自定义旧身份触发器及不能完整分类的函数引用同样阻断。

资源绑定在各写阶段重新检查四库实际集群/数据库身份、源目标互异及目标 run 绑定。实际 `pg_dump`/`pg_restore` 连接参数必须与已检查端点和数据库身份一致；不支持或会改变 libpq 连接目标的参数拒绝执行。service 文件值遵循 libpq 原生语法并拒绝控制字符。snapshot 先撤销目标 `PUBLIC`/应用角色 CONNECT，再检查存量会话，之后才允许 restore。freeze 先持久撤销源应用 CONNECT 再排空连接；排空超时保留栅栏和阶段事实。

finalize 在任何开放目标 ACL 前持久写入不可覆盖的发布意图。转换提交后和 `remote/ready` marker 提交后的重试，会验证 run/source 绑定、目标封闭状态、列、ACL、投影和 14 条 FK，禁止回到旧 dump/restore。跨库部分发布保留已提交阶段并 fail closed。自动 `recover --execute` 永久拒绝；只读 check 明确是瞬时观察，不能授权重开源库。CLI help 与该策略一致，要求后续人工 forward merge/最终对账。PG `170010` 现显示为 `17.10`。

## 实测与验证

- 自有 Apple Container `i4-luna-pg17`、50432 夹具：真实 CLI 对未知 `public.i4_review_unknown_role_fk(role_id REFERENCES roles(id))` 返回退出码 2、`unknown_identity_foreign_key`、`ready_for_snapshot=false`；目标身份指纹及对象数不变。删除临时表后 inventory 返回 0、无 blocker、可 snapshot。四库实际 inventory 均显示 PostgreSQL `17.10`。证据在 `docs/reviews/evidence/run/i4-luna-20261018/author/repair-1/repair1f/`。
- 真实 PG 负例还覆盖 users 上未知触发器、PL/pgSQL 逗号 `FROM` 和 `DELETE ... USING` 引用；未知角色/权限 FK 测试及干净正例均在 snapshot 写入前完成。测试过程中曾发现并清除了本轮早先遗留的合成函数 `i4_luna_repair_delete_using_probe()`；首次 inventory 对该残留正确 fail closed，相关前后证据保留。
- P08 中断实测：转换提交后 kill、Agent `remote/ready` marker 提交后 kill，以及双方 ACL 开放后的硬退出。最终复跑在后两种状态均未调用 dump/restore；IAM 非 owner 停用写和 Agent runtime 线程写保留，重试到 ready。转换复跑中一次早期合成 Agent 写缺少同事务 tenant GUC，按设计 fail closed；该次不计为成功路径，随后以正确 GUC 重跑完整发布窗口。证据在 `repair1b/`、`repair1c/`、`repair1e/`。
- `pytest --noconftest -q tests/test_i4_separation_safety.py tests/test_i4_remote_menu_catalog.py`：16 passed；Ruff 与 `py_compile` 通过。真实 `recover --execute` 返回 2 且 `write_effect=not_started`，当前 help 和拒绝输出证据在 `repair1f/`。
- 报告和证据的秘密扫描已通过：18 个配置秘密值零命中；扫描结果保存在 author evidence 目录。
- 同一修复早些阶段的独立本地管理回归为 198 passed、5 skipped（71.51 秒）；root remote 为 49 passed（0.58 秒）。最终小改动限于 I4 inventory/CLI 与其测试，因此没有重复整套管理回归。主控另报的 192/7 与 49 中间回归由主控保管；我没有复跑 Java/Web，也没有扩修 I2/I3。
- 两次最初的 targeted pytest 尝试都被项目 `tests/conftest.py` 自动 fixture 拦在测试 setup：一次尝试 `.env` 的 15432，另一次 `--confcutdir` 仍加载该 fixture、尝试隔离占位端口 59999；均为连接被系统拒绝、未进入测试主体。没有改旧测试掩盖该误跑，最终用 `--noconftest` 隔离后 16 项通过。

## 未完成及边界

生产存量 UUID 对账、授权用户搬运和流量切换未获授权，也未执行；未知历史 UUID 仍须先由权威 IAM 源核验。自动回切保持禁用，实际恢复必须在双边持久栅栏下人工 forward merge 并最终对账。主评审独立全路径验收尚未完成；本报告、测试通过和任务标记都不代表验收通过。RAG 产品、数据及索引未改。

## 产品文件与 SHA-256

| 文件 | SHA-256 |
|---|---|
| `admin/api/app/routers/auth.py` | `48ade208ebf0b0d89e0ed39f8fd4371e7fef749bf37f4196671881b78a61e2c5` |
| `admin/api/app/services/permission_catalog.py` | `e0ef349ca925f050079fa66d1a9dcbd44d61ce628c62a0e3e5dd5c4b7565a23a` |
| `admin/api/scripts/seed.py` | `758b25ca6857af48386e02d4116b18e1fd1280e76e677d89f84bbde611a9de81` |
| `admin/api/scripts/i4_separation.py` | `1ff6853973579d7d6f9b3c67de845d739ebed860bb6be71abd42ed63177bd155` |
| `admin/api/tests/test_i4_remote_menu_catalog.py` | `e99d69df38d8ee0394d3201d7ca9cd58fc60f7fa826e9ed55e0dcd0f4ae6e069` |
| `admin/api/tests/test_i4_separation_safety.py` | `921af639212d0a9812a74791fc8f544f614ea197afceda4348b0f89eb71e4977` |
