# 新Agent启动提示词

用法：先评审本项目proposal/design/http-contract/tasks。**仅在用户认可方案并决定实施后**，将下方从`/goal`开始的正文复制给新Agent；这是I1独立项目实施授权，不是授权修改旧项目或正式数据。本提示词不依赖Gemini、Flash、ZCode或Antigravity的特定工具名。

---

/goal 在 /Users/acerola/Dev/Java/air_agent_iam 工作区完成 OpenSpec change `establish-shared-iam-service`：从当前只有规划文件的干净目录，初始化并实现可独立运行、可独立验收的共享用户/企业/IAM服务及Vue中文管理后台。

先阅读 README.md、该change的proposal.md、design.md、http-contract.md、specs/**/spec.md、tasks.md及docs/reference/source-audit.md、full-extraction-design.md、cross-service-acceptance.md，以及docs/vue-admin-plan.md。docs/reference是历史快照；其中旧Next.js组件复用建议由当前Vue方案覆盖，保留哈希不改写历史。核实OpenSpec根目录是本项目，再进入apply；如工具没有原生/goal命令，把本消息视为持续目标执行，保持任务进度到完成，不停在只给建议或只初始化空壳。

本次粘贴表示用户授权实施**I1独立服务**，包含本项目内的骨架、契约、Java后端、数据库迁移、服务账号、内部客户端、中文前端、合成SSO消费者、测试和自有环境验证。按tasks逐组实现，并随组补本组测试和说明；日常可逆实现不反复询问许可。计划有冲突时先核实，能在本包解决的继续解决，不偷改安全承诺/验收断言。

技术选择：JDK21、Spring Boot4 WebMVC、Sa-Token有状态不透明token与显式Redis适配、PG权威身份/修订/撤销、Maven Wrapper；独立web固定Vue 3 + TypeScript + Vite + Vue Router + Pinia + Element Plus；不用React/Next.js/Nuxt，不搭Node生产BFF。只读参考原页面字段/权限/交互，在Vue重建；Spring Boot实现/web-api浏览器会话适配、CSRF和SSO回调，浏览器不持有人类会话Bearer/内部凭据，Vite proxy不代替服务端鉴权。先核实Boot4专用starter/Redis/Jackson3依赖、bcrypt $2b$与rt-v1双向向量再展开。具体补丁锁定并记录，不擅自改成Boot3或Stateless JWT。

前端交付细节：/web-api与/v1契约按http-contract第9节区分。生产由Spring Boot同源提供web/dist，Vite只用于开发/构建；GET/HEAD的HTML history回退不得吞API错误或返回HTML给缺失JS。Router守卫/菜单/按钮不能替代后端权限；Pinia按user/tenant/ctx_version/epoch隔离，切换/退出清理，A→B→A迟到响应丢弃。不要把会话Bearer存Pinia/localStorage/sessionStorage/URL，服务端兑换SSO ticket且即时复核。设计细节和验收以docs/vue-admin-plan.md为准。

不可降低：多企业完整隔离、即时撤销、用户/企业/成员/session四修订、切企业CAS、平台/企业可授分离、同租户数据库约束、最后管理员保护、授权修改与审计同事务、非owner/nonBYPASS请求角色、无正向授权TTL缓存、异常503失败关闭、服务账号/内部client/人类主体分型、回环监听、秘密不进响应详情/日志/Trace/checkpoint。

范围边界：
1. /Users/acerola/Dev/Python/air_agent 与 /Users/acerola/Dev/Python/RAG/env-rag-final 仅可只读核实和复用资料，不修改其文件、配置、数据库、既有服务或容器，不读取复制它们的.env/实际凭据。原Agent 3/5在2026-10-15已归档提交，产品基线2d6f7c8，后续Agent规划8620cf7；来源指纹为当时历史快照，只读核实当前HEAD，不回写源仓库。
2. 不接管真实身份写者、不迁现有用户、不切Agent/知识库消费者、不物理拆库、不搬关注城市/台账/反馈/观测/价格/MCP绑定。资源entitlement另包I1a，当前资源型权限默认拒绝；不能跳过开通检查启用知识库。
3. 本机使用Apple Container，不假设Docker Desktop/docker.sock/Testcontainers可用。只创建本任务自有隔离PG/Redis/端口，先查占用，不能停/重置共享服务或flush既有Redis。配置/端口冲突通过本项目配置解决。
4. 域名未定；只用本机回环合成SSO客户端，精确回调/Origin，不开放0.0.0.0、宽Domain或通配credentials。无默认生产口令。
5. 不commit/push/合并/归档；保留diff/未跟踪文件供独立验收。

交付必须包含：真实JDK21构建和启动；空库迁移/幂等；真实受限PG角色的A/B/无上下文与并发反例；登录/建档/企业组织/角色权限/审计完整流程；Cookie/CSRF/SSO重放；实时撤销/改密/切企业/依赖故障；bcrypt/rt-v1双向兼容；服务账号最小受众/权限；长运行verification_ref无凭据持久化；Vue后台真实浏览器保存/失败/刷新/键盘/窄屏，vue-tsc类型检查、前端单测和干净生产构建，C27–C30的SPA直达/CSRF/秘密隔离/企业切换迟到响应；实测introspection性能与独立恢复演练。不能用HTTP200、mock、截图或checkbox代替对应真实证据。

每完成一组，更新tasks和可复跑证据。开始记录阶段实际时间、修复次数、环境等待，Token无法计量写“未采集”。最终在docs/reviews/iam-phase1-acceptance.md列验证命令、环境、结果、场景索引、风险和后续未做事项，提供可直接打开的本地地址及下一阶段交接；不要把协议合成消费者写成现有六图/知识库已经接入。

如果外部依赖确实阻塞，保留相应任务未完成，完成不依赖它的部分，准确写阻塞条件与复验步骤；不得换成弱授权、删反例、编造通过或无限反复重启。先独立交付本包，再等待用户验收后开启下个change。
