# Agent业务开通：联合最终验收收尾

日期：2026-10-19验收，2026-10-20收尾。结论：本轮`add-agent-business-entitlements`联合验收通过，23/23任务完成，已同步主规格并归档。配套Agent变更为`simplify-agent-business-authorization`；不等于其他活动change或整个企业级后台路线图已完成。

## 独立确认与证据

Codex接手AGY超时后独立复跑`AgentBusinessEntitlementIntegrationTest`（7项）和`OpsCommandIntegrationTest`（5项），12项均通过、0失败/错误/跳过。使用全新自有aa-codex-iamfinal-pg（25435/iam_test）和aa-codex-iamfinal-redis（26382），不加载正式.env.local，不访问正式19132。iam_app、iam_migrate均非superuser、非BYPASSRLS，Flyway在空库执行；临时资源已回收。

证据位于Agent仓库`docs/reviews/evidence/run/codex-business-final-20261019/iam-owned-tests-02/`（result.json、maven.log）。仅保存测试汇总，未导出含进程环境的surefire XML。原有作者99项及AGY协议/Vue测试属于原执行记录，本轮不将未重跑全量记成本轮全绿。

本机root正常登录、四家企业切换/me、六项精确权限读回均通过；Agent端四企业运行/统计200，有root自有正文样本的两家企业读取200，另两家无样本不伪造读取通过。口令未传AGY，验证前后摘要相同，临时会话已退出。早期交付报告的短口令阻塞保留为历史来源，不覆盖原报告或推断历史口令。

Agent原始真实三业务native/BFF×stream/wait共12项，首次9项有实质回答，数据分析3项整理失败后重试成功。Codex补修原生选择冲突未返回409的问题，并完成真实受理、checkpoint、换图/改选择/撤权恢复负例和合法恢复9个检查；使用受控IAM/模型，不能冒充Java IAM/正式模型测试。

正式库本机只读核对确认：Agent为air_agent_business/0022，旧mcp_identity_bindings不存在；IAM为iam_identity，enterprise:mcp及mcp:binding:read/manage三个旧码定义为零。实际清理/重启记录保留在原交付证据，本轮未重启正式服务，也未创建旧授权备份。

详细矩阵、来源与局限见[Agent联合最终验收](../../../../Python/air_agent/docs/reviews/agent-business-authorization-final-acceptance-20261019.md)。新增修复与验收归属Codex，不倒算给AGY或原实施模型。

## 状态与边界

- IAM企业开通∩本企业有效角色授权仍是唯一普通业务使用资格，root走明确企业角色，无用户名旁路或未来业务通配授权。
- 外部MCP数据范围由外部服务承担；共享只读查询通过不代表已完成外部企业数据隔离或可证明的全数据范围。
- 已回填6.1—6.3并保留原始失败/限制；归档按用户明确授权执行，早期config上下文“不自动archive”不覆盖本轮明确授权。
- 两仓已有工作区改动完整保留；无commit/push，不将归档描述为Git交付或新补丁正式部署。主规格同步和严格校验结果见后续归档验证。

## 2026-10-20 归档与提交前收尾

本节更新前述10月19日时点：两仓主规格已经同步，Agent `2026-10-20-simplify-agent-business-authorization`（29/29）与IAM `2026-10-20-add-agent-business-entitlements`（23/23）已归档。可随Git提交的[脱敏验收摘要](evidence/business-authorization-acceptance-20261020.json)在两个仓库各保留一份；原始日志位于Agent的忽略目录，不纳入提交。

本次另在自建空PG/Redis完整复跑IAM Maven：99项通过，0失败、错误、跳过；Vue 28项测试通过且生产构建成功。Vue单测有既有生命周期提示，构建有包体积提示，均不是零警告结果。Agent89项定向回归及9项官方API恢复检查保持前述来源，未重复计数或冒充全仓重跑。涉及的7份主规格校验通过；Agent13项既有规格失败集合未增加，IAM全部主规格通过。

测试结束后回收本任务所有临时容器，删除已退役Change3/5的两份测试库备份、过期探针日志、测试缓存、IAM Surefire报告/测试类和临时协调脚本。保留失败轮次结果摘要、测试源码、最终证据和历史评分；没有删除正式配置、共享卷、镜像或其他项目资源。清理条目、字节数见摘要及本机 `codex-business-closeout-20261020/cleanup-*.json`。

两仓仍是dev工作区，未commit、push或重启共享正式服务；最新补丁通过隔离官方API验证。最终秘密扫描、diff检查及归档列表核对见同目录提交准备证据。外部MCP服务端仍按用户要求不纳入本次工作。
