# iam-physical-separation Specification

## Purpose
TBD - created by archiving change separate-iam-business-databases. Update Purpose after archive.

## Requirements

### Requirement: 真实依赖盘点与可审查迁移
系统 SHALL 对实际源库盘点身份关联的 FK、视图、函数、触发器、RLS、ACL及运行代码路径；所有写操作 MUST 显式指定资源并验证数据库实际身份、版本和所有权，默认只读。

#### Scenario: 无写计划
- **WHEN** 在有效源目标上运行默认 dry-run
- **THEN** 输出依赖、差异、阻断和计划，源目标行及catalog不变且日志无凭据。

#### Scenario: 危险目标拒绝
- **WHEN** 源目标为同一实际数据库、目标非空无所有权、未知依赖或版本不符
- **THEN** 在任何修改前拒绝并给出非秘密原因，已有数据保持。

### Requirement: 最小引用与纯业务数据库
remote 业务数据库 SHALL 仅存非授权身份引用并保留UUID、同租户FK和业务内部FK；remote业务热路径 MUST 不读写旧身份表或锁其父行，local独立部署保持可用。

#### Scenario: 同UUID业务继续使用
- **WHEN** 有效IAM用户进入分离业务库并读写偏好、归属、账本和反馈
- **THEN** 同UUID引用幂等建立且功能可用，旧身份表不存在也不影响，最多5城市及并发原子性保持。

#### Scenario: 未知或冲突身份
- **WHEN** 存量UUID不在权威、同名不同UUID、成员UUID试图重绑企业或用户
- **THEN** 阻断或隔离报告且不删除业务数据、不自动合并、不改变归属。

#### Scenario: 真实最小权限
- **WHEN** 非owner业务角色在A/B/无上下文访问或尝试读写旧身份/IAM数据
- **THEN** 仅合法本企业业务操作成功，其余无数据或拒绝，FORCE RLS、列ACL及函数旁路无越权。

### Requirement: 单写与最终增量完整性
系统 SHALL 在隔离真实库上演练在线快照、源变化、真实写栅栏及事务排空、最终差异对齐和权限撤销；Java IAM MUST 为唯一身份写者，启用依赖实际核验。

#### Scenario: 快照后变化
- **WHEN** 快照后发生新身份/新业务写、修订、会话或服务凭据撤销和业务删除
- **THEN** 冻结后最终核对涵盖所有变化/删除并保留UUID与约束，旧运行写者真实写入失败。

#### Scenario: 中断不误放行
- **WHEN** 复制或冻结中途异常并重试
- **THEN** 状态/证据持久保留，不重复覆盖异run目标、不存在两写者，不将未核对状态标成可启用。

### Requirement: 恢复保全新写与撤销删除
系统 SHALL 以可执行门禁阻止新目标写入后直接切回旧DSN；旧快照恢复 MUST 保全后续新写、最新撤销/修订和删除清单，未完成核对时保持不可开放。

#### Scenario: 旧备份不能复活
- **WHEN** 新目标已接收新写后尝试恢复旧快照
- **THEN** 恢复不丢后续业务行、不会恢复被撤销凭据或已删除内容；无法合并则命令失败且目标继续封闭。

### Requirement: RAG与独立验收归属
系统 SHALL 保留RAG UUID映射/记录边界，保持知识数据及索引不变；首次模型交付和评审者修改 MUST 分开冻结、测试和评分。

#### Scenario: 地址变化不改变授权
- **WHEN** IAM基地址指向同UUID权威的新隔离库，或旧记录主体/凭据绑定不匹配
- **THEN** 合法访问与撤销规则保持，旧绑定不能借迁移获得访问；RAG源数据不变。
