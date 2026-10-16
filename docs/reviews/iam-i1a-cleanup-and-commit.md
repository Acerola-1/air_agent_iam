# I1a 提交前清理

日期：2026-10-16。用户授权清理过程产物并本地提交到dev；不包含push、main合并或启动I2/I3。

## 盘点与处理

未发现大量应删除的过程文件。MIMO留下的3个一次性脚本合计16,918字节，已删除：

- `web/e23-debug.cjs`：固定39100地址的HTML调试输出。
- `web/e23-browser-test.cjs`：一次性截图流程，未接入项目测试入口，已由独立浏览器复验取代。
- `scripts/verify-i1a-e01-e16.sh`：固定本机路径/环境/端口，不能作为完整E01–E16验收依据。

上述文件尚未进入Git，不会作为删除文件出现在本次commit中。原始首交副本已冻结保留在本机私有验收目录，未丢弃评测依据。移除仅被上述脚本使用的`playwright`/`playwright-core`开发依赖后，package.json和lock恢复至本轮修改前的依赖集合；本地安装的2个包亦已卸载。

删除3个无跟踪Python缓存目录，合计40,880字节。没有清空数据库或审计记录，也未停止原作者/其他项目服务。

MIMO的19份本地运行证据合计1,840,870字节（约1.76MiB）；独立审查和接管证据分别约1.39MiB。它们支撑模型评价，保留在已忽略的`docs/reviews/evidence/run/`，不进入commit。`node_modules`、工具虚拟环境和构建目录属于正常依赖/可生成产物，保留并继续忽略。`.env.i1a`与`.env.local`保留在本地，不进入Git。

## 文档一致性

- 原实现者报告标注为历史交付声明，链接独立评分与当前复验，保留原43分及原声明，不把历史PASS当当前事实。
- OpenSpec任务清单撤回连接取消复用、完整退出换账号浏览器矩阵、兼容拒绝回退版本及完整资源负载性能的完成勾选，保留待验范围。
- README补入I1a当前实现、复验和I2/I3的HTTP交接边界，避免仍将资源开通写成未实施。
- 不归档change，不降低历史性能门禁；dev提交表示保存当前可用成果，不表示完整生产发布通过。

## 提交前检查

检查在当前工作区执行；后端使用既有自有49132 PostgreSQL的`iam_test`库与49179 Redis测试DB1，不写运行库`iam_repair`或共享实例。

- `cd server && ./mvnw test`（使用既有隔离配置及Maven缓存）：86/86通过，0失败/错误/跳过，结果见本机[后端统计](evidence/run/i1a-cleanup-20261016/backend-summary.json)。
- `cd web && npm test && npm run build`（含vue-tsc）：23/23及构建通过，结果见[前端记录](evidence/run/i1a-cleanup-20261016/web.json)。
- 契约消费者、Python复核Java固定向量、OpenSpec strict、差异空白检查及秘密扫描另行记录在同一忽略证据目录。
- 暂存区确认不含环境文件、node_modules、构建目录或本机运行证据；配置秘密实际值不回显。

功能与模型评价详见[接管复验](iam-i1a-takeover-validation.md)和[首次独立评分](flash-blind-iam-i1a-mimo-2-6-pro-first-delivery.md)。
