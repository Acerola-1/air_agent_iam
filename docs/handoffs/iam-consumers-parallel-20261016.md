# I2 / I3并行实施交接与规划复盘

日期：2026-10-16。这里的“二、三”对应I2 Agent消费者接入和I3 Knowledge API remote接入，不是旧企业路线图的Change2事件台账/Change3反馈。

## 可以开始什么
可以从已提交IAM dev@8da8ba1127b7ea7aa9c0a9f7289d90cbcc96a368开始两个独立消费者的接入开发与隔离环境验收。不是切换现有用户或共享实例，不表示I1a的资源负载性能/兼容回退等剩余发布验证已经通过。
- I2：/Users/acerola/Dev/Python/air_agent，产品HEAD 319dab499585e640d0d216699cd767a3a1c567e1。提示词docs/handoffs/agent-remote-iam-apply.md，change switch-agent-to-remote-iam。
- I3：/Users/acerola/Dev/Python/RAG/env-rag-final，产品HEAD 1aa52b04976a94ad6e969775ced07cf1828ca81e。提示词docs/handoffs/knowledge-remote-iam-apply.md，change connect-knowledge-remote-iam。
- 每包固定proposal/design/spec/tasks/acceptance/contract/baseline；本轮只写文档，产品代码未实现，测试基线需实施启动时新跑。模型身份不作为输入。

## 对前几轮问题的判断
不能用五个不同任务的失败量化“规划占几成、模型占几成”，也不能由分数推出普遍模型能力。能确定的是：
1. 规划交付包偏大：身份、迁移、并发、多个页面、图运行和恢复常被放在一轮；验收条件散在多个长文档中，读完不等于知道先打通哪条正例。
2. 旧假设已经漂移：原I2蓝图假设Java直接接同一Python身份表；实际Python使用users.is_active等字段，Java是iam.users.status/realm，权限命名与业务FK也不同。原Change4暂缓等时间性文字已经过期。
3. 协议存在接缝：当前rt-v1没有execution reference，而远程长运行复查需要真实引用；SSO OpenAPI的部分字段/状态与实际代码不同；IAM内置权限尚不包含全部Agent业务权限。不能把这些架构决定临时留给实施者猜。
4. 已复现的硬编码秘密、正常授权不通、旧企业请求写新企业、全量测试损坏、未跑场景标PASS，不能仅用计划太长解释。这些属于实施、自测与证据纪律问题。
5. 评估设计也应改善：分离“代码接入完成/本地真实联调/生产切换”和外部材料缺失，不要求模型在没有权限或映射清单时完成真实迁移；不能把正常阻塞算虚报，也不能把未实现核心流程算环境问题。

## 本次已做的改进
- 固定实际源码HEAD及契约SHA，两边收到同一份contract.md，不按匿名模型身份优化。
- 先G0基线/协议探针，再G1最小真实闭环，之后扩展发送/资料出口、页面、全矩阵；正常工程选择自主推进，不逐阶段停下来要确认。
- 把上述协议桥接、数据引用、权限清单、机器分型、SSO实际字段写成明确设计。
- 每个验收ID同时给正例和相邻拒绝例，实施前公开；首次交付后新增要求另记计划变更，不偷偷补题扣分。
- 标准OpenSpec apply以tasks.md及短实施备注续接、一份最终报告、唯一run目录保存原始证据，不生成大量过程报告。
- 核心授权要求不降低；正式身份接管/资料迁移与生产发布保持独立门禁。本轮不是只交stub或模拟：必须真实IAM，实际业务/SDK/存储与受控模型分别证明。

本轮不使用goal模式；实施入口为客户端标准apply工作流，归档archive是验收后独立动作，不用归档命令执行开发。

## 并行资源与责任
两项目不能共同写一个IAM测试库或对49103/391xx等既有实例建测试用户。各自导出IAM冻结提交到本项目忽略目录，构建/启动独立副本，使用自己的PG/Redis/数据库/端口/客户端/随机秘密/浏览器context。I2建议501xx、I3建议502xx，实际占用核实后登记，cookie不按端口隔离。
I2只改Agent，I3只改RAG；IAM原仓库只读。I2所需业务权限注册只在自有IAM测试迁移中做实证，输出中央发布清单给后续协调，不擅改共享IAM。I3可以独立用合法服务账号和人类IAM会话测试，不等待I2交付。
两边完成后另做I2→I3组合验收。不同项目/阶段的用时不直接比较；如果同一个匿名模型承担两边，分别保存两份首交与总投入，不能合并两次成绩掩盖一个失败。

## 正式切换前置（不是本轮自动授权）
- Agent历史UUID/外键投影审查及IAM同UUID导入方式、业务权限目录发布、维护窗口唯一身份写者。
- IAM剩余发布验证、实际运行地址/回调/client注册及相关密钥供应。
- Knowledge API的正式tenant/resource/workspace映射与历史记录归属政策。
- 跨服务消费者token受众/权限、真实企业MCP和资源负载性能、受控前向修复/兼容回退。
禁止把“本轮隔离接入通过”写成这些前置已经完成。

## 匿名评审入口
实施报告分别为Agent的docs/reviews/agent-remote-iam-acceptance.md和RAG的docs/reviews/knowledge-remote-iam-acceptance.md。首交先冻结再审，不先让协调者补修。
评审者读取对应baseline/公开acceptance和实际diff，自行复跑正负例；五维仍为契约30/权限25/验证20/维护15/交付10。评分按已冻结的本轮范围，不因正式切换未授权而扣“没上线”，也不因模型未透露身份猜供应商。
稳定性、模型实际实施耗时、应用运行性能分开；Token无来源写未采集。首交、模型返修、协调者接管分别记，不改原五个模型成绩。
