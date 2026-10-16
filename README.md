# Air Agent IAM

用于学习企业账号、组织与鉴权的独立项目，提供中文管理后台、人类会话、企业/成员/部门、角色权限、审计、服务账号与 SSO。

后端采用 **JDK 21 + Spring Boot 4 MVC + MyBatis + Boot starter 4.0.0 + PostgreSQL + HikariCP + Flyway + Sa-Token + Redis**；前端采用 Vue 3、TypeScript、Vite、Pinia 和 Element Plus。MyBatis 负责 SQL 映射，HikariCP 管理连接池，PostgreSQL 保存身份及修订权威状态，Flyway 管理增量迁移。

## 分支规范

本地开发与测试均在 `dev` 分支进行；只有功能完好（自测通过、构建与测试通过、密钥扫描零命中）的代码才会合并并推送到 `main` 分支，`main` 始终保持可交付状态。详见 [AGENTS.md](AGENTS.md)。

## 分层结构

按业务域组织，HTTP 入参、出参和数据库对象分别命名为 DTO、VO 和 DO：

```text
server/src/main/java/com/airagent/iam/
  admin/              企业、成员、部门、账号与角色
    controller/       HTTP 路由与参数边界
    service/          业务接口
      impl/           权限、规则和事务编排
    mapper/           MyBatis 数据访问接口
    dto/ vo/ entity/  入参、出参和持久化数据
  auth/               登录、会话、身份
  audit/              审计查询
  internal/           主体实时核验与运行票据
  serviceaccount/     服务账号及凭据
  webapi/             浏览器 Cookie、CSRF 和 SSO 适配
  common/             共用类型映射、事务上下文与事件 Mapper
server/src/main/resources/
  mapper/             对应 Mapper 的显式 XML SQL
  db/migration/       Flyway 迁移
```

Controller 不访问数据库，Service 不编写 SQL；SQL 使用绑定参数。MyBatis 关闭二级缓存并采用 STATEMENT 级一级缓存。授权变更、审计与 Redis 清理事件在同一事务中提交。请求数据库角色与迁移角色分离，数据库 RLS 约束租户范围。

命名、分层依赖、集合/空值、异常、事务和敏感字段处理按阿里巴巴 Java 规约整理；检查范围及剩余验收事项见[整改记录](docs/reviews/iam-remediation-plan.md)，不将局部自动检查等同于完整规约认证。

## 本地运行

需要 JDK 21、Node.js 20.19+、PostgreSQL 17 和 Redis 7。按 `.env.example` 在本机配置 `.env.local`，分别设置请求与迁移数据库角色；账号和密钥只放本地配置。已有基础设施时：

```sh
cd web
npm ci
npm run build
cd ..
bash scripts/run-server.sh --build
```

默认服务地址为 `http://127.0.0.1:19100`，后台路径为 `/admin`，健康检查为 `/healthz`。首次管理员由本机 `IAM_BOOTSTRAP_ACCOUNT` / `IAM_BOOTSTRAP_PASSWORD` 配置创建。新企业默认以创建人为首位企业管理员，可在建立后切换企业继续管理。

```sh
cd server
./mvnw test
cd ../web
npm test
npm run build
```

数据库集成测试使用 `it` 配置，连接独立的 `iam_test` 数据库及 Redis DB1；只对专用测试环境执行，端口可通过 `IAM_PG_PORT` / `IAM_REDIS_PORT` 设置。跨语言固定向量见 `scripts/verify-crypto-vectors.sh`。

部门创建/修改必须提交表单打开时的 `tenant_id` 和 `expected_ctx_version`，过期表单返回 409。内部端点以登记的客户端 Bearer 凭据认证调用服务，`subject_token` 表示待核验主体；保留 Basic 兼容入口。原 rt-v1 采用 `{kid,p}` 信封的两段格式。

## 测试凭据在哪里

真实账号与密钥一律只存本地、不入库（入库前由 `scripts/verify-secret-scan.sh` 强制零命中）。日常开发环境凭据在 `.env.local`；2026-10-15 独立验收环境（HTTP 29100 / PG 29132 / Redis 29179，bootstrap 账号 `audit.root`）的凭据保存在项目根目录被忽略的本地文件 `iam-audit-20261015.local`（匹配 `*.local` 规则）。若该文件缺失，它最初来自验收 harness 的 `/tmp` 临时目录，可能已被系统清理，只能重建环境后重新生成。

## 设计与证据

- [HTTP 契约](openspec/changes/establish-shared-iam-service/http-contract.md)
- [整改前独立审计](docs/reviews/iam-independent-acceptance.md)
- [分层迁移与整改](docs/reviews/iam-remediation-plan.md)
- [最新复验与已知性能项](docs/reviews/iam-remediation-validation.md)
- [I1a资源开通与授权修复复验](docs/reviews/iam-i1a-takeover-validation.md)
- [I1a资源授权HTTP契约与I2/I3边界](openspec/changes/add-tenant-resource-entitlements/http-contract.md)
- [原设计与阶段划分](openspec/changes/establish-shared-iam-service/design.md)

I1a通用资源开通、角色/成员及服务账号资源授权已实现，核心流程复验通过；完整资源负载性能、兼容回退版本及部分竞争矩阵仍待验证，详见I1a复验报告。Python消费者切换（I2/I3）与物理拆库仍属于后续阶段。
