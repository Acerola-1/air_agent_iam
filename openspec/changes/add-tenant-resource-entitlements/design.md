# 企业资源开通设计

## Context

2026-10-16 只读核实：IAM 为 Git 仓库，分支 `dev`，HEAD `8b40d702ca85798cb8f113202e240bcd0d62bb2d`，本包创建前工作区干净。旧复验报告“没有 Git”的描述属于历史，不能作为当前事实。当前源码迁移最高 V19，未连接数据库读取运行 head；实施前再核实。

| 已有实现 | 本包衔接点 |
|---|---|
| V1 定义 resource_catalog、tenant_entitlements、permissions.resource_code；V2 种 air 资源与读码、entitlement:manage | 复用原表、原 code/UUID，补约束与受限读写；不再建同义表 |
| V1 两个授权触发器禁止资源型权限 | 用新迁移替换为按目标企业、目录、开通、可下放性检查，不能简单删除防护 |
| RoleAdminServiceImpl、RoleMapper.xml 隐藏/拒绝资源码 | 扩展可授树、持久化权限详情和授角边界，保留普通权限规则 |
| ServiceAccountServiceImpl 仅接受非资源企业权限；V14 load_service_identity 筛 resource_code IS NULL | 建档支持受控资源权限，核验实时求交；账号更新仍仅状态更新，不顺带重做凭据系统 |
| V12 load_authority_snapshot 合并角色权限，V18 包装可信上下文；IntrospectionServiceImpl 复查四修订 | 在权威数据读取中统一求交，不能只在返回 DTO 时删除权限而漏掉 verification_ref |
| Vue PlatformTenantsView、RoleEditDialog、ServiceAccountsView，MenuCatalog 与 scope/epoch 工具 | 延续 Element Plus 和服务端 Cookie/CSRF，补页面及异步隔离 |
| openspec 主规格尚为空，I1 活动包 36/36 | 本包新增一个能力规格，保留 I1 历史；不把 checkbox 当独立验收 |

现有 `docs/reviews/iam-remediation-validation.md` 保留压力性能/总 deadline 未闭环；本次不重审或覆盖其历史结论。最新代码、实际构建与复跑结果应另记，不能把旧报告测试数硬编码成当前基线。

## Goals / Non-Goals

**Goals:** 在 IAM 内交付“登记资源→给企业开通→明确授权角色/机器主体→实时核验→回收→原配置保留→重新开通”闭环，使用同一授权事实和同一租户边界。

**Non-Goals:** 收费/订阅/额度、自动开通全企业、文档级 ACL、RAG 资源就绪探测、业务检索/下载实现、Agent/RAG 源码与配置修改、真实身份接管、物理拆库、SSO 重构、另造 JWT、修完全部既有性能问题。合成消费者只证明协议，不宣称两个现有业务系统已接入。

## Decisions

### 1. 通用资源目录与显式映射

资源 code 为稳定业务标识，知识库固定 `knowledge:lib:<library_code>`，对应读码 `knowledge:lib:<library_code>:read`。目录保存中文名、排序、active/disabled、kind、parent_code、revision；开通记录沿用 tenant_id × resource_code × active/revoked × revision。不存在记录等价未开通，不自动补 active。

首期只允许 `kind=leaf` 实际开通。现有 air.parent_code=knowledge 是历史展示分组字符串；兼容保留，不把它当成现存父行或授权继承关系，不强加会破坏该记录的父外键。目录分组和前缀都不赋权。

平台登记叶子资源时同时显式提交至少一项权限绑定（code/name_zh/grantable_to_tenants），统一登记为 tenant scope、active、指向该资源。普通平台管理码、其他资源前缀、重复权限和重复目录整体拒绝。知识库首期只登记 read；通用引擎按映射求交，不硬编码 air/water，也不开放任意写操作的执行实现。资源 code 与绑定权限码/归属创建后不可改；中文名/排序/目录状态可变，资源不硬删除。现存 air 种子增量复用，重复登记返回 409；water 或其他合成资源通过相同 API 登记，不要求预置真实知识库连接。

选择复用和明确登记，避免并行资源体系及服务自报权限自动获得信任。无需新基础设施或权限表达式引擎。

### 2. 可授资格与可用权限分开

有效资源读权限 = 明确的角色/机器主体授予 ∩ 活跃权限目录 ∩ 活跃资源目录 ∩ 目标企业 active entitlement，并要求用户、企业、成员/机器主体和凭据等原身份条件有效。开通本身绝不自动赋予任何资源读码；平台管理员身份也不能绕过企业开通读取业务资源。

新增 `tenant:resource:grant`，scope=tenant、grantable_to_tenants=true、resource_code=null，增量赋给现有内置 tenant_admin 模板，作为企业资源授权管理资格。它只与原操作权限组合使用：改角色仍需 tenant:role:write，成员授角仍需 tenant:member:write；拥有它的人可配置本企业当前已开通且可下放的资源权限，不要求自己已经有该资源读码。没有它的角色管理员仅能在自身有效资源读码的子集内下放。它不自动进入资源读取 permissions，也不豁免普通非资源权限可授子集；无管理操作权限者单独持有此码不能改角色/成员。

该规则是显式设计决策，解决“所有人都没读码，首轮无人可授”的死锁。替代方案“把资源读码自动发给管理员/凭角色名放行全部资源”会把管理权和读取权混为一谈，故不采用。

资源权限只允许写入明确 tenant_id 的企业独有角色。全局 tenant_id=null 的内置企业模板、所有平台角色禁止携带资源读码；管理员在开通后创建企业角色再分配给成员。授角的展开权限也执行同一可授检查，不能借创建成员、内置模板或全量替换角色绕过。

服务账号资源授权继续限定平台 platform:service:write 管理入口，平台管理权不会豁免目标企业开通；不引入企业管理服务账号的新入口。创建时须核验所有申请码，不接受部分成功；保留已有受众白名单、到期/轮换/撤销与主体分型。首期不新增服务账号权限替换端点，建档可配置，现有状态/凭据撤销仍可回收整个主体。

### 3. 配置保留和可授集合

角色/机器详情返回持久化的配置权限；introspection.permissions 仅返回实时有效权限。可授树区分可新增叶子与已配置但当前失效叶子，失效原因明确为 resource_disabled、not_entitled、permission_disabled 等。

资源回收不删除 role_permissions、membership_roles、service_account_permissions，不删除企业数据。编辑角色时，服务端读取原集合：允许保留原来已有但当前失效的码，也允许删除它们；拒绝新增或重新加入当前不可授的码。不能要求客户端重送的配置一律属于“当前可新增”集合，否则普通名称修改会清掉保留配置。并发比较与授权在同一事务，客户端声称“原配置”不构成证据。

重新开通后，原配置在新的有效身份核验中恢复；资源回收前的旧执行引用始终不能重新有效，避免 ABA。重新开通不复活被撤销的会话、成员、角色、凭据或被明确移除的权限。

### 4. 权威读、修订与事务

在 PG 权威快照和机器主体读取中统一求交，Java 受众裁剪仍按 I1 现有规则执行；禁止通过 resource 列表、JWT、本地缓存或浏览器参数自证许可。不改变 identity.v1 与 introspection.v1 已有字段形态，不新增必填第五修订号。

每次实际 active/revoked 转换、资源安全状态改变或相关授权变更，在同一事务完成状态写入、相应修订推进与审计。企业开通改变至少推进目标 tenant.auth_revision，目录停用/恢复推进所有受影响企业修订；有明确授权引用但异常缺开通行的企业也纳入检查。显示名/排序等无授权含义的修改只推进目录 revision。未关联 B 企业不推进修订、不掉登录。

旧人类会话在 tenant revision 变化后按原 I1 策略可能直接失效；不得为显示“自动刷新成功”偷偷对齐旧 session。管理界面遵循现有失效/重新登录流程，重新取得身份后看新权限。四修订不变而只裁剪 permissions 不能满足旧 verification_ref 拦截要求。

机器主体没有人类四修订，仍每次从 PG 重算，不用旧 permissions 放行；保留既有 DTO，不伪造人类 session/membership。资源收回不等于凭据永久吊销，重新开通时仍有效的机器令牌可按当前授权重新工作。

事务锁次序统一：资源行（多资源按 code 排序）→受影响企业行（按 UUID 排序）→目标角色/主体及权限行。开通、资源停用、资源权限新增和角色分配都遵循共同串行化点，授权检查不得发生在写事务之外后直接使用。全局停用以目录行和受影响企业修订同一事务提交，不能先返回成功再异步补修订。审计失败则全部回滚；拒绝与回滚不遗留半配置。撤销提交前已经开始的核验可按其线性化点完成，提交后才开始的新核验必须观察撤销；不承诺回收已经发送的外部字节。

PG/Redis/超时异常保持 503 失败关闭；有效主体缺少某资源读码不等于主体无效，introspection 可 active=true 且不含该码，下游应据此 403。无跨请求正向授权缓存；不新增内省写回或逐权限远程查询。

### 5. 数据库约束与 RLS

沿用 app.user_id/app.tenant_id/app.is_platform 的事务本地上下文，不混用 AirAgent 的 air_agent.*。资源映射加受控约束/FK，需先检查存量异常，不能靠删数据让迁移通过。resource_catalog 平台写、授权用户受限读；tenant_entitlements 企业仅能读自身且不能自开通，平台写仍须 entitlement:manage；无上下文无租户行。相关租户表 ENABLE + FORCE RLS、请求 iam_app 非owner/nonsuper/nonBYPASS。

触发器与 MyBatis 查询同时检查目标企业，不因 API 漏 WHERE 或平台上下文误配而给共享模板加资源。SECURITY DEFINER 固定 search_path、显式 owner、最小 EXECUTE、事务上下文恢复。有效开通/资源映射 join 加必要索引；连接复用、异常和取消后的无上下文读取必须复验。不能把平台 GUC 当作浏览器可传的开关。

### 6. API 与 Vue

接口细节固定于 http-contract.md。平台目录/开通由 entitlement:manage 管理，与普通平台企业读写权限独立；只持有后者不自动获得开通权。企业资源只读入口需要企业上下文和 tenant:role:read，不能操作其他企业；资源目录存在不等于本企业可用。

Vue 增加平台资源目录 `/admin/platform/resources`、企业页“资源开通”入口、企业资源 `/admin/tenant/resources`。平台开通详情用明确的目标企业，不借当前会话企业隐式推导。表单快照包含 user/session/ctx_version/目标企业/目标 revision/epoch，切换、退出、开新目标后丢弃迟到响应和旧草稿。401/403/409/503 和空/加载/保存状态显示真实中文反馈；409 不自动重放写操作。

延续现有 Element Plus 视觉与组件，不重做全后台。角色编辑明确展示“已配置，资源未开通/已停用”，不会随加载树丢掉勾选。服务账号页可以创建仅有单库读码的账号，凭据仍仅安全的一次性呈现、不进证据。浏览器实际保存/刷新、键盘焦点/Escape、390×844、迟到响应必须有真实证据，组件测试不能替代。

## Risks / Trade-offs

- [历史报告滞后] → 冻结实际 HEAD/diff/迁移与证据摘要；不覆写旧报告或把 I1 自动归档。
- [tenant revision 使企业用户重新登录] → 保留既有严格语义，页面提示并提供重新认证；优化会话策略另立变更，不能顺手降低撤销。
- [新增授权管理码扩大管理员配置范围] → 仅企业已开通可下放资源，仍需原写权限，不授任何资源读码；覆盖只有管理码/只有角色写/仅成员写的反例。
- [全局资源状态变更修订扇出] → 同事务、按序锁，记录影响企业数/耗时；本阶段不做异步开放窗口，规模问题另议。
- [保留失效配置误当有效] → 配置详情与有效 permissions 分开，回收/恢复/角色编辑全链路验收。
- [现有压力性能仍未闭环] → 同隔离环境先测旧基线再测新版本，报告授权语义与延迟；不改原阈值、不用缓存隐藏，不借本包功能验收宣称生产门禁关闭。
- [多 Agent 竞争迁移号或接口] → 仅一个实现负责人；开始核实 HEAD 和实际 Flyway head，冲突重新编号追加，禁止改已执行迁移。

## Migration Plan

1. 实施前冻结分支、HEAD、产品 diff/文件指纹、现有 I1 测试与当前构建；仅在 dev 开发，原工作区若有其他任务改动须保留隔离，不强制清理。
2. 创建本任务独占 PG/Redis/库/回环端口并记录所有权。空库从 V1 全迁移；再用仅 V1–V19 的合成存量库升级到新 head，比较 UUID、授权、会话、资源记录摘要，复跑迁移应无新变化。
3. 增量添加约束/策略/权限种子/原子授权与修订规则，升级时所有既有未开通企业保持未开通；不分配默认资源读码。
4. 部署匹配的 Java/Vue/契约版本，在隔离数据完成 acceptance.md；控制消费者只做实时权限判定，既有 Agent/RAG 保持原运行。
5. 回退先停止新写，保存新配置与审计，部署已验证的“资源默认拒绝”兼容版本，资源不可用优先；不 Flyway downgrade、不删除新表/列、不回退已推进修订或复活旧 token。旧版本 schema 不兼容则前向修复。全程 IAM 仍唯一身份权威，不转回 JSON/旧 HMAC。
6. 用户独立验收后再决定归档与提交。交接 I2/I3 时冻结 OpenAPI/Schema/样本摘要、有效权限/错误语义/数据映射说明；I4 另行规划。
