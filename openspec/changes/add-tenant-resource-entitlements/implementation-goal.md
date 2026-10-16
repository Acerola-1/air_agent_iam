# I1a 通用实施提示词

用法：用户评审本计划并决定实施后，在 `/Users/acerola/Dev/Java/air_agent_iam` 工作区把分隔线以下正文完整交给实现 Agent。有原生 goal 功能时使用其持续目标模式；若工具不识别 `/goal`，将正文作为普通持续任务执行。本文件不依赖某一模型、IDE 或特定插件。不要运行根目录旧 START-GOAL.md 的 I1 从零初始化任务。

---

/goal 在 /Users/acerola/Dev/Java/air_agent_iam 完整实施 OpenSpec change `add-tenant-resource-entitlements`（I1a：企业资源开通），交付可独立验收的 Spring Boot + Vue 功能与证据。持续推进至本包任务完成；不是只写建议、画页面或修改checkbox。

先读取 AGENTS.md、README.md、openspec/config.yaml，以及本change的 proposal.md、design.md、specs/tenant-resource-entitlements/spec.md、http-contract.md、acceptance.md、tasks.md。根START-GOAL是I1历史提示，不作为本次目标；旧验收报告为历史证据，以当前源码/HEAD和新基线核实事实。规划时分支dev、HEAD为8b40d702ca85798cb8f113202e240bcd0d62bb2d、迁移最高V19，实施时重新确认，不能假设未变。按可用OpenSpec apply流程逐组实现。遇到本包可解决的常规问题自行推进；有实质契约冲突时记录并协调，不能自行降低授权标准。

本次粘贴授权在IAM项目内实施此包：资源目录登记、平台给企业开通/回收、有效权限求交、资源授权管理、企业角色/成员授角及服务账号窄扩展、Vue页面、增量迁移、契约与自有环境验证。沿现有JDK21/Spring Boot4 WebMVC/MyBatis/Hikari/Flyway/Sa-Token/Redis、Vue3+TS+Vite+Pinia+Element Plus开发，不从零初始化、不换框架、不再造身份源。所有产品修改在dev分支；若当前main先遵守项目分支规范，保留别人的未提交改动，不reset/clean。

几个必须实现的区别：
1. 企业开通仅给可授资格，不自动给管理员/成员/机器账号读码。有效资源权限需主体有效+明确授予+权限启用+目录启用+该企业active开通。首库码knowledge:lib:<library_code>:read，资源引擎不能硬编码air/water。
2. tenant:resource:grant是授权管理资格，仍需角色/成员原写权限，只能管理本企业已开通且可下放的资源；不自动获得读取能力、不豁免非资源可授子集。禁止全局模板或平台角色携带资源读码，成员建档附角色也不能旁路。
3. 回收保留配置，实时核验失效；角色编辑能保留原失效码、显式删除，但不能新增/搬运失效码。重新开通不复活旧verification_ref、已撤销会话或凭据。
4. 资源状态/企业修订/审计同事务，覆盖人类Bearer、Cookie、机器token、长运行引用与ABA；失败关闭、非owner/nonBYPASS与FORCE RLS、事务本地app.*上下文、受众隔离与CSRF均保持。没有正向授权TTL缓存，没有新增必填第五修订号，不改变原rt-v1字节/内部client Bearer契约。
5. 新写入使用expected_context与目标revision，平台目标企业与操作者当前企业分开；旧表单和迟到响应不能写进新上下文。Vue不能只靠菜单隐藏保护，资源回收也不能只靠页面刷新生效。

边界：本包只改IAM。AirAgent和RAG两个Python仓库、配置、正式库/容器仅只读参考，不实施I2/I3消费者切换、真实账号迁移或I4拆库，不改模型或用mock替代声明的E2E。机器最小脚本与受控资源只是协议消费者，不能写成真实RAG已接入。收费、配额、检索逻辑、知识库就绪探测不在范围。

本机用Apple Container；只创建带本次所有权的PG/Redis/库/回环端口，先核实占用，不假设Docker socket或固定空闲端口。不要停共享15432、既有IAM/知识库/Langfuse服务，不全局prune、flushall、TRUNCATE共享库或downgrade。已执行迁移不改，只追加接实际head；空库、合成V19存量升级、重复迁移和兼容拒绝回退都要验证。只清理自己创建的资源，证据和验收入口按报告保留。

按tasks每组补实现、测试、契约/使用说明并更新进度。执行acceptance E01–E26，用真实HTTP/受限PG/Redis/浏览器正反例证明结果；负例必须有正对照。UI需要实际桌面/390×844、键盘、保存刷新、409/503、双标签与迟到响应，组件测试不替代。完整后端回归、前端test/typecheck/build、原Python rt-v1互验与请求Schema对照均要执行，不删断言/扩大skip。原压力性能未闭环要保留，按同环境前后采样报告，不以本包功能验收冒称生产放行，不能用缓存或改阈值掩盖。

不自动commit/push/合并/归档，不初始化或重建整个仓库。交付保留可审查diff；如需产物或截图，严格脱敏，密码/哈希/token/cookie/内部凭据/真实dump不写报告和证据。凭据只提供本机安全位置，不贴出值。

最终交付 docs/reviews/tenant-resource-entitlements-acceptance.md、按轮次新建的证据目录、E01–E26逐项状态与复跑步骤、契约摘要、当前入口/凭据位置、资源所有权与清理清单、已知基线与限制，以及I2/I3后续交接。记录实施、验证、环境等待的实际用时与修复轮次；Token无法取得写“未采集”，模型代号未知不猜测。

遇到真实外部阻塞，完成不依赖部分，保持对应任务未完成并写明复验条件；不要用替身冒充、编造全绿或无限重启。完成后等待用户独立验收，不自行开始下一个change。
