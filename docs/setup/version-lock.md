# Gate0 版本锁定说明（I1）

记录日期：2026-10-15（Asia/Shanghai）。以下版本经 Maven Central 元数据与本机真实依赖树核实，并以 JDK21 完成干净构建；不是仅凭文档声称兼容。

## 本机环境

| 项 | 实测值 | 说明 |
|---|---|---|
| JDK | Amazon Corretto 21.0.12（`/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home`） | 构建与运行均显式 `JAVA_HOME` 指向 21；本机默认 `java` 为 25，不用于本项目 |
| Maven | Apache Maven 3.10.0 | 项目自带 Maven Wrapper（`server/mvnw`，distribution 3.10.0），不依赖全局 mvn |
| Node / npm | v26.11.1 / 12.2.0 | 仅用于 web 构建/测试 |
| 容器 | Apple Container CLI 1.5.0（无 Docker Desktop / docker.sock） | 自有镜像 `postgres:17-alpine`、`redis:7-alpine` |
| PG / Redis | PostgreSQL 17（容器）/ Redis 7（容器，appendonly） | 仅发布 `127.0.0.1:19132`、`127.0.0.1:19179`；LAN 地址不可达已实测 |

## 锁定依赖（server/pom.xml）

| 依赖 | 版本 | 核实要点 |
|---|---|---|
| Spring Boot parent | 4.0.8 | 4.0.x 最新补丁；不使用 4.1/4.2 里程碑线，不回退 Boot3 |
| Spring Framework / WebMVC | 7.0.9（BOM 管理） | WebMVC（非 WebFlux），Tomcat embed 11.0.24 / Servlet 6.1 |
| Jackson | tools.jackson 3.1.5（Boot4 web 链路） | Boot4 默认 Jackson3；Sa-Token 使用 `sa-token-jackson3`。Flyway 自身传递 Jackson2 仅其内部使用 |
| Sa-Token | 1.46.0 | `sa-token-spring-boot4-starter`（Boot4 专用 starter，非 Boot3 starter）+ 同版本 `sa-token-redis-template` 显式 Redis 适配 |
| Spring Data Redis / Lettuce | 4.0.7 / 6.8.2 | 独立 Redis 实例、有密码；连接/命令超时失败关闭 |
| Flyway | 11.14.1 + flyway-database-postgresql | 仅管理本项目自有库；迁移连接使用 iam_migrate，与请求角色 iam_app 分离 |
| PostgreSQL JDBC | 42.7.13 | SCRAM 密码认证已实测 |
| spring-security-crypto | 7.0.7 | 只取 BCryptPasswordEncoder；不引入 spring-security-web/第二过滤链 |

## 关键决定

- 令牌：Sa-Token 有状态不透明随机令牌（random-128），**显式** Redis 持久化（非框架默认内存）；PG 是会话/修订/撤销权威，introspection 每次读主库，Redis 不作为带 TTL 的正向授权缓存。
- 数据库角色：`iam_migrate`（NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOBYPASSRLS，schema 属主，仅迁移用）与 `iam_app`（同四 NO，请求连接，仅持表 DML/函数 EXECUTE）分离。
- 端口：服务固定 `127.0.0.1:19100`（IAM HTTP），Vite 开发 `127.0.0.1:5173`；PG/Redis 见上。全部先查占用再绑定。
- 秘密：仅来自 `.env.local`（不入库）；无默认生产口令；bootstrap 管理员仅空库种子时按环境变量创建。

干净构建命令（复跑）：

```bash
cd server
JAVA_HOME=/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home ./mvnw -DskipTests package
```
