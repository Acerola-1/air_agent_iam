# IAM 分层与 MyBatis 整改计划

## 授权与验收基线

2026-10-15，用户将本轮要求由“只验收、不改产品”更新为“连审带改”，并明确标准 MVC 分层、阿里巴巴 Java 编码规范、数据库访问使用 MyBatis。本次授权允许修改当前 IAM 产品；两个 Python 参考仓库与其服务仍只读，不 commit/push/合并/归档。

原始审计证据保持不覆盖。整改前产品指纹见 `evidence/iam-independent/outputs/input-remediation-baseline.json`，与最初 282 文件基线内容一致。`iam-independent-acceptance.md` 记录整改前问题，整改后逐项另记复验，不能抹去已证实反例。

## 目标结构

按业务域组织代码，每个域清楚分层：

- controller：HTTP 路由、参数校验、DTO/VO 转换、统一状态码；不编写 SQL。
- service / service.impl：业务规则、授权与事务编排；不直接使用 JdbcTemplate 或 SqlSession 拼装查询。
- mapper：MyBatis 接口；所有值参数使用绑定参数。
- resources/mapper：显式 SQL 与 resultMap，不使用字符串替换拼接外部值。
- model/entity、dto、vo：持久化数据、入参及安全出参分开，密码摘要等敏感字段不得进入普通 VO。

保留 HikariCP、PostgreSQL 与 Flyway 的职责。MyBatis 使用与 Spring 事务一致的 DataSource；授权相关查询禁用二级缓存并将一级缓存范围设为 STATEMENT。迁移和请求数据库角色继续分离。

## 实施与复验顺序

1. 固定 Spring Boot4/JDK21 兼容的 MyBatis starter，建立 Mapper/XML 与事务集成，先完成一个实际模块的分层迁移并在隔离库运行。
2. 分域迁移账号、企业/成员/部门、角色/权限、审计、会话、内部主体、SSO。统一命名、常量、异常、校验、分页及事务风格；避免继续使用通用 Map 作为业务模型。
3. 修复独立审计确认的权限提升、租户/CAS、四修订与执行引用、管理员保护、会话撤销、票据兼容、轮换、协议及浏览器问题。每项保留原失败输入并新增整改后证据。
4. 复跑作者测试及独立反例，完成真实 HTTP/PG/Redis、跨语言、真实浏览器与性能复验。MyBatis 接入或测试通过本身不代表授权边界通过。

按阿里巴巴规范核对命名、分层依赖、方法职责、异常/日志、参数校验、集合与空值、事务、SQL 参数绑定及敏感出参。自动规则只覆盖可自动检查的部分，不宣称自动扫描等于完整规范符合。

## 官方依据

- MyBatis Boot starter 4.0 系列支持 Spring Boot4、Java17+：https://mybatis.org/spring-boot-starter/mybatis-spring-boot-autoconfigure/
- 阿里巴巴 Java 编码规约及 P3C：https://github.com/alibaba/p3c

当前状态（2026-10-16）：主要分层与数据库访问迁移已完成，功能复验通过；性能及压力下总响应预算未闭环。详见 [整改与复验记录](iam-remediation-validation.md)。生产代码已迁入 14 份 MyBatis XML，12 个业务 Service 接口；DTO / VO / DO 分开。最后完整后端回归 81 项、前端 19 项通过。
