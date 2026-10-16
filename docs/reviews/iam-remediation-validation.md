# MVC / MyBatis 整改与复验记录

日期：2026-10-16。范围：当前 IAM 学习项目的分层改造、数据库访问迁移及已确认问题修复。两个 Python 项目仅作只读参考；未初始化 Git、commit、push 或切换消费者。

**MVC / MyBatis 改造已落地，功能回归通过；完整原验收仍不能判为通过，压力性能与压力下的总响应时限尚未闭环。** 整改前失败记录保留在 `iam-independent-acceptance.md`，不能用本文件覆盖历史失败事实。

## 当前实现

数据库访问原来使用 Spring JDBC 的 `JdbcTemplate`；现在生产代码的数据访问均使用 MyBatis 接口和 XML。MyBatis 仍通过 PostgreSQL JDBC 驱动连接数据库，HikariCP 负责连接池，Flyway 负责迁移。

交付 JAR 实际依赖：MyBatis 3.5.19、MyBatis-Spring / Boot starter 4.0.0、HikariCP 7.0.2、PostgreSQL JDBC 42.7.13、Flyway 11.14.1；应用为 Spring Boot 4.0.8 / JDK21。

- 按业务域拆分 Controller、Service 接口、ServiceImpl、Mapper、DTO、VO、DO；当前 12 个业务 Service 接口、14 份 Mapper XML。
- Controller 不导入 Mapper / entity；Service 不编写 SQL；数据库行不再通过通用 Map 转换。审计 detail 与导航目录等 JSON 元数据不等同于数据库行模型。
- SQL 使用绑定参数与显式结果映射，UUID / PostgreSQL text[] 有专用类型处理；授权查询关闭二级缓存，一级缓存为 STATEMENT。
- 保持权限裁决、授权变更、审计、失效事件的事务边界。Redis 网络检查在完成数据库权威读取后执行，避免等待 Redis 时占用数据库连接。
- 入参使用 DTO，出参使用 VO，持久化数据使用 DO；保留构造注入、统一错误信封及敏感参数 toString 脱敏。
- 阿里巴巴规约检查覆盖分层依赖、主要命名、参数/空值边界、异常、事务、SQL 参数绑定与敏感字段；未把这些局部检查宣称为完整手册认证。当前目录不是 Git 仓库，没有伪造 Git diff / OCR 检查结果。

## 已修复反例及其边界

| 原编号 | 实施与复验证据 |
|---|---|
| F01 | 创建成员授角色、替换角色均检查可授权限子集；真实 HTTP 自提权与创建越界管理员返回 403。 |
| F02 | 部门 HTTP 写入要求表单打开时的 tenant_id / expected_ctx_version；真实双标签旧表单返回 409，缺省上下文返回 400。 |
| F03 | 企业权限不再足以关联任意全局用户；关联已有账号另需平台账号读取权限。集成测试验证有限授权人被拒；这不等同于实现邀请/用户同意系统。 |
| F04 | 改密撤销全部旧会话，包含当前会话；集成测试同时验证新口令可登录。 |
| F05 | 部门 RLS 限定当前企业；iam_app 不再直接 SELECT / UPDATE 口令摘要列。真实非 owner 测试覆盖多企业成员读取与口令列拒绝。 |
| F06 | rt-v1 恢复 `{kid,p}` 信封的两段协议，HMAC 覆盖第一段原文。交付 JAR 与原 Python 签/验实现双向通过，实际 HTTP 票据亦通过原消费者验签。 |
| F07 | 人类 token 与执行引用复查都检查 Redis 会话存活；删除真实键后均拒绝。 |
| F08 | 浏览器续期提交当前上下文版本；真实菜单续期返回 200。 |
| F09 | 不存在账号与错误口令统一 401；真实 HTTP 不存在账号不再 500。 |
| F10 | 核验响应使用请求受众，非管理受众不返回平台角色、平台管理标记与平台权限；普通应用受众校验登录绑定，runtime 作为显式服务端派生受众处理。 |
| F11 | 轮换窗口写在旧凭据上，零窗口立即撤销；窗口从轮换时刻起算。测试覆盖已签发两天的旧凭据、窗口到期、零重叠及新凭据可用。 |
| F12 | 应用会话通过 central_session_id 关联中央权威，中央切换/续期/撤销同步到派生会话；真实 Agent / KB 两个 BFF 都随中央切换，中央退出后旧 Cookie 均 401。 |
| F13 | 跨表最后管理员保护使用共享事务锁并计入全局用户状态；两个真实 iam_app 停用事务一笔提交、一笔 23514，最终保留一名有效平台管理员；原授权已恢复。 |
| F14 | 前端企业停用提交 suspended；真实界面停用、恢复都返回 200。 |
| F15 | 切换响应提交前检查会话纪元，后续菜单/企业响应也检查新快照；真实已提交切换响应被延迟到退出、新账号登录后释放，新账号身份保持正确。 |
| F16 | 禁止标量宽松转换；真实 HTTP 字符串版本号、字符串布尔值均 400。 |
| F17 | **部分修复**：JDBC 超时单位已修正，数据库语句有界、连接池等待有界；内部业务预算 450ms，预留响应时间。锁等待、Redis 暂停、PG 停机及恢复已实测失败关闭。但压力下仍有总响应超过 500ms，不能判此项全通过。 |
| F18 | 已恢复 /web-api/csrf、/v1/sso/authorize、登记客户端 Bearer、菜单 items 及当前 Bearer 重复退出 204；保留既有别名 / Basic。证据仅支持这些已列反例，不宣称所有契约字段形态均已独立遍历。 |
| F19 | 角色权限/状态、平台角色授撤推进关联主体修订；真实 HTTP 撤权后旧执行引用 active=false / context_matches=false。 |
| F20 | 新企业事务内建立首位管理员，默认创建人，也可显式指定启用账号；无需直接改库才能继续操作。真实 HTTP 验证创建人可进入新企业。 |
| F21 | 续期使用锁后实时时间并与旧截止时间取大，仍受绝对上界约束；真实旧事务晚提交未产生截止时间倒退。 |

另修复部门窄屏弹窗在选择框焦点下 Escape 无法关闭的问题：真实 390×844 浏览器验证弹窗宽度、10 次 Tab 焦点约束、Escape 关闭和焦点返回打开按钮。

## 验证结果

- 最终后端完整回归：81 项，0 failures / 0 errors / 0 skipped；`evidence/iam-remediation/connection-release-backend-tests.json`。
- 前端：19 项通过，类型检查及生产构建通过；`frontend-keyboard-tests.json` / `frontend-keyboard-build.json`。
- 单独临时库：空库 V1→V19、已有 V5→V19、重复迁移全部通过；业务 UUID / 摘要保持；两个临时库已移除。V1–V11 原迁移未修改，新增迁移为 V12–V19；`real-migration-acceptance.json`。
- 最终构建 HTTP：37 个正/反对照检查；`real-http-acceptance-delivery.jsonl`。原消费者双向签验：`original-cross-language-accepted-delivery.json`。
- 真实 Edge：`real-browser-acceptance-delivery.jsonl`、`real-browser-sso-status-delivery.jsonl`，截图在 `browser-delivery/`。没有把浏览器自动化等同于实体设备、实体输入法或公开 TLS 部署验收。
- 依赖故障：`real-dependency-failures-delivery.json`；明确故障时 503，解锁/恢复后正对照 200，错误信封 request_id 与响应头一致。
- 数据库并发：`real-database-races-delivery.json`；请求角色 iam_app，非 owner；原平台授权在 finally 恢复。

早期构建/探针失败与修正后结果均保留，包括跨语言测试文件缺失、SSO 映射列错误、测试 Cookie 构造错误、Base64 非规范尾位、旧凭据轮换起算点和迁移约束名称错误。只以最后一轮结果为交付证据，不以删除失败记录制造全绿。

## 未闭环：性能与压力下总响应时限

最新交付 JAR 顺序预热 30 次后，每档并发三轮、每轮 100 次，共 900 次。关闭限流仅用于隔离压力采样，生产默认限流仍开启；每个样本核对 active、受众、session 与权限集合，未引入正向授权缓存。

| 并发 | 三轮 P50 ms | 三轮 P95 ms | 失败样本 |
|---|---|---|---|
| 1 | 5.883 / 6.094 / 5.867 | 7.681 / 7.563 / 7.122 | 0 |
| 10 | 41.596 / 17.160 / 17.793 | 1101.567 / 35.633 / 47.403 | 1 个 503 |
| 30 | 84.307 / 67.709 / 76.157 | 197.141 / 195.964 / 213.897 | 0 |

899 个成功样本的身份、受众与权限均匹配；另 1 个 503 作为失败计入，不能宣称 900 个全通过。并发 10/30 未达到原 P50≤10ms / P95≤30ms 目标，压力下还出现超过 500ms 的端到端耗时。保留原阈值与全部样本，不排除首轮以凑成绩，原因尚未独立定位。已修复不必要的数据库连接占用，不能因此声称性能问题已解决。

## 可运行入口与变更边界

当前交付实例：`http://127.0.0.1:29107/admin`；健康检查 `/healthz`。专用库 **iam_remediation**、Redis DB2，与集成测试的 iam_test / Redis DB1 分开。测试资源均为本任务创建的隔离 PostgreSQL / Redis，端口 29132 / 29179；没有暂停、修改两个 Python 项目的服务。

本次合成登录配置在本机受限文件 `/tmp/iam-independent-20261015-5ohAEo/environment.json` 的 IAM_BOOTSTRAP_ACCOUNT / IAM_BOOTSTRAP_PASSWORD 字段，值不写入报告。日常开发按 README 使用自己的 `.env.local` 与 `scripts/run-server.sh --build`。

`runtime-resources.json` 记录当前 PID、JAR 指纹与数据库；旧 29100 审计 JVM 已停止，其原源码/JAR保留。`delivery-source-manifest.json` 对比整改前产品指纹并证明 server/src 与测试构建副本一致；原 `.env.local` 的大小及修改时间未变，内容没有读取或改写。没有 Git 仓库，因此没有虚构提交、分支或 PR。
