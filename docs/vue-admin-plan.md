# IAM Vue后台实施补充计划

日期：2026-10-15（Asia/Shanghai）。用户已确认“IAM后台用Vue”。当前仅规划修订，尚无Java/Vue业务实现；实施仍使用START-GOAL.md，本次不提前启动apply。

## 技术与职责

| 模块 | 固定方案 | 职责 |
|---|---|---|
| web/ | Vue 3、TypeScript、Vite、Vue Router、Pinia、Element Plus | 中文后台页面、非秘密状态、交互与权限呈现 |
| server/ | JDK21、Spring Boot4 WebMVC、Sa-Token+Redis、PG权威 | 既有/v1契约、/web-api浏览器会话、实时授权、CSRF与SSO回调 |
| contracts/ | OpenAPI3.1/JSON Schema/合成样本 | 独立于UI框架的HTTP协议与一致性验证 |

不用Next.js/React/Nuxt或Node生产BFF。原Agent聊天和现有admin/web不迁Vue、不修改；只读参考页面字段、DTO、校验、权限及交互规则。在本项目重建Vue组件，不直接复制TSX/radix。初版不引入完整后台模板及其自带用户/权限体系，以免与IAM权威重复；复用Element Plus表单、表格、树、弹层即可。

建议web/src下按app/router、stores、api、views及共享components组织，权限逻辑集中于API/会话适配层，避免每个表单自行解析身份。平台账号/企业、部门/成员/企业角色、平台角色/可授树、审计、个人资料/改密/会话按既定权限开放；业务城市/MCP配置/运营统计不搬入。菜单和按钮控制不能替代后端权限。

Spring Boot承担原Next.js服务端职责，具体接口已冻结到本change http-contract第9节；不以“后端已有API”为由省略浏览器适配。服务端关联HttpOnly句柄与真实会话，Vue只拿安全DTO；全部写操作（包含登录/退出/续期）有CSRF与Origin防护。SSO由服务端校验state/兑换ticket，Bearer和内部client凭据不出现在JS/URL。授权始终读当前权威，无正向TTL缓存。

开发Vite回环代理到Java；生产web/dist由Java同源提供。README应给出唯一前端包管理器/锁文件与安装、typecheck、test、build、前后端启动及产物整合命令。推荐npm+package-lock，Gate0锁定实际兼容Node/Vue/Element Plus版本。Node用于开发/构建，不是新增线上鉴权服务。

前端验证使用vue-tsc、Vitest+Vue Test Utils及Playwright或等价真实浏览器工具；这些是后续实现应建立的命令/证据，本次没有安装依赖或生成脚手架。

## 实施顺序

1. Gate0固定HTTP契约与版本，初始化Vue/Java目录、独立测试资源与构建命令。
2. 先打通Java/web-api登录→me→企业选择→刷新→退出，验证cookie/CSRF/即时撤销，再扩管理页面。
3. 用真实API完成建档/组织/RBAC/审计及错误态，逐组补测试；与I1其他后端任务依赖联动。
4. 验证双合成SSO应用、scope/epoch、生产静态资源、窄屏/键盘和既定C01–C26的I1部分，再交独立验收。

任务编号以tasks.md为准，现为36项、全部未实施；原第6组扩为7项，其他任务和C01–C26稳定ID保留，不因此变更授权或验收完成状态。

## Vue补充验收（C27–C30，全部属于I1）

| ID | 题目 | 验收结果 |
|---|---|---|
| C27 | Vue构建与生产history回退 | 干净安装锁定依赖，vue-tsc/单测/build通过；Java实际提供dist，/admin深链接刷新正常，未知API与缺失JS不返回HTML；构建环境无秘密 |
| C28 | Java浏览器适配与凭据边界 | 真浏览器登录/刷新/退出/续期；JS/store/storage/URL无会话Bearer；缺错CSRF/外部Origin/伪造Authorization/内部端点代理均拒绝；真实撤销下一请求失败，登录失败不显示成功 |
| C29 | 菜单/草稿与迟到响应 | 同用户A/B、A→B→A、切账号/退出、并发切换409和迟到保存；旧结果不覆盖当前页，不跨scope写入；直接管理API无权仍拒绝 |
| C30 | 完整中文交互 | 真实建档/组织/角色/权限/审计与资料流程，加载/空态/错误/冲突/503清晰；390×844/桌面、键盘焦点/Escape/IME可用；刷新后真实持久化，无静态演示冒充 |

记录每项版本、命令、实际API/PG/Redis环境、正反对照、浏览器步骤与脱敏证据。C17/C26继续有效，C27–C30是补充，不削减即时撤销、角色与租户隔离。报告记录未完成格子和实际耗时，不能只用截图/HTTP200代替联调。

## 历史来源与后续边界

docs/reference及agent-identity-specs是2026-10-14来源快照，保留原始字节与sha256；source-audit/full-extraction-design中的React/Next.js建议是历史事实，当前前端技术以本文件、change设计及用户决定为准。http-contract是由原快照派生的本项目契约，新增第9节；provenance保留原hash并标注后续派生，不冒充与原文件逐字一致。

I1a entitlement、I2 Agent切换、I3知识库remote、I4物理拆库仍另开变更。Vue选择不要求改它们的HTTP身份协议，不修改Agent Change4实施包。当前项目尚未初始化Git，本次也不自动init/commit/push/归档。
