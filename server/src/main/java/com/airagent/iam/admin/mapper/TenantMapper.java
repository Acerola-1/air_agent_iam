package com.airagent.iam.admin.mapper;

import com.airagent.iam.admin.entity.DepartmentDO;
import com.airagent.iam.admin.entity.MembershipDO;
import com.airagent.iam.admin.entity.TenantDO;
import com.airagent.iam.admin.entity.UserDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 企业、成员与部门的数据访问（Mapper 层，SQL 见 mapper/admin/TenantMapper.xml）。
 *
 * <p>运行在 iam_app 请求角色下，覆盖 iam.tenants / iam.tenant_memberships / iam.departments /
 * iam.membership_roles 四张 FORCE ROW LEVEL SECURITY 表。调用前必须在同一事务内通过
 * {@link com.airagent.iam.common.mapper.RequestContextMapper#setContext} 设置
 * {@code app.user_id / app.tenant_id / app.is_platform}，否则结果为空。三张组织表的写入分支
 * 各不相同：企业只允许平台上下文写入，部门与企业成员要求 {@code tenant_id} 等于上下文企业，
 * 平台线在为企业建档外一般以企业上下文操作后两者。部门可见性自 V15 起收紧为
 * “上下文企业或平台上下文”，跨企业成员资格不再扩展部门读权限。
 *
 * <p>本接口还承担少量账号侧读取：iam.users 的列级权限不含 {@code password_hash}，
 * 停用账号在纯企业上下文下行不可见，成员视图因此改走 SECURITY DEFINER 函数
 * {@code iam_auth.member_user_brief}（见 {@link #selectMemberUser}）。
 * 所有查询关闭二级缓存、一级缓存为 STATEMENT，避免授权与修订号读到过期值。
 *
 * @author Acerola
 */
@Mapper
public interface TenantMapper {

    // ------------------------------------------------------------ 企业

    /**
     * keyset 分页：按 id 升序取 {@code afterId} 之后的至多 {@code fetchSize} 行企业。
     *
     * <p>平台上下文可见全部企业；纯企业上下文只见到目标企业自身与自己所在活跃成员关系的企业。
     * 服务层以 fetchSize = limit+1 探测是否还有下一页。
     *
     * @param afterId   游标 id，仅返回 id 大于它的行；{@code null} 从头开始
     * @param fetchSize 实际取行数上限（含多取的一条探测行）
     * @return 按 id 升序的企业列表；无匹配时为空列表，不返回 {@code null}
     */
    List<TenantDO> selectTenants(@Param("afterId") UUID afterId, @Param("fetchSize") int fetchSize);

    /**
     * 按主键读取企业（无行锁）。
     *
     * @param id 企业 UUID
     * @return 企业行；不存在或 RLS 不可见时返回 {@code null}
     */
    TenantDO selectTenant(@Param("id") UUID id);

    /**
     * 按主键读取企业并加行级排他锁（SELECT ... FOR UPDATE）。
     *
     * <p>必须在开启的事务内调用，锁随提交/回滚释放；企业写路径以它串行化并发修改，
     * 并在持锁后读取 auth_revision 做修订比对。注意最后管理员保护自 V15 起改用事务级
     * advisory lock 串行化跨行、跨表检查、不再锁企业行，因此两把锁互不相干。
     *
     * @param id 企业 UUID
     * @return 已持锁的企业行；不存在或不可见时返回 {@code null}（此时未持锁）
     */
    TenantDO lockTenant(@Param("id") UUID id);

    /**
     * 插入新企业，status 取表默认 active，auth_revision 取表默认 1。
     *
     * <p>企业写 RLS 只放行平台上下文，调用前必须已把上下文切为平台。
     * 编码全库唯一，重复以 23505 抛出并由调用方翻译为 409。
     *
     * @param code    企业编码（2..64 位字母数字/_/-，调用方已校验）
     * @param name    企业显示名
     * @param actorId 建档人 UUID，入 created_by 审计列
     * @return 数据库生成的新企业 id
     */
    UUID insertTenant(@Param("code") String code, @Param("name") String name, @Param("actorId") UUID actorId);

    /**
     * 局部更新企业名称与状态（两列均为 COALESCE 语义）。
     *
     * <p>状态实际变化时由触发器 {@code tenants_bump_auth_revision} 将 auth_revision +1，
     * 使落在该企业的会话在下次权威核验被拒；仅改名不推进代次。
     * 两个参数都为 {@code null} 时语句仍会执行，只刷新 updated_at。
     *
     * @param id     企业 UUID
     * @param name   新显示名；{@code null} 保持原值（无法借 {@code null} 清空）
     * @param status 新状态；{@code null} 保持原值；调用方须先行校验仅取 active/suspended
     * @return 受影响行数；0 表示行不存在或 RLS 不可见（调用方一般已由加锁查询给出 404）
     */
    int updateTenant(@Param("id") UUID id, @Param("name") String name, @Param("status") String status);

    // ------------------------------------------------------------ 成员

    /**
     * keyset 分页：按 id 升序取指定企业的至多 {@code fetchSize} 行成员关系。
     *
     * <p>SQL 显式按 tenant_id 过滤，叠加 RLS 后企业间完全隔离。
     * 服务层以 fetchSize = limit+1 探测下一页。
     *
     * @param tenantId  企业 UUID，取会话当前企业
     * @param afterId   游标 id，仅返回 id 大于它的行；{@code null} 从头开始
     * @param fetchSize 实际取行数上限（含多取的一条探测行）
     * @return 按 id 升序的成员关系列表；该企业暂无成员时为空列表
     */
    List<MembershipDO> selectMembers(
            @Param("tenantId") UUID tenantId,
            @Param("afterId") UUID afterId,
            @Param("fetchSize") int fetchSize);

    /**
     * 按企业 + 成员 id 复合条件读取成员关系（无行锁）。
     *
     * <p>租户归属写在 WHERE 里，因此他企业的成员 id 一律查不到，调用方可安全地统一回 404，
     * 不泄露“该 id 是否存在”。
     *
     * @param tenantId 企业 UUID，必须等于会话当前企业
     * @param id       成员关系 UUID
     * @return 成员行；不存在、不属于该企业或 RLS 不可见时返回 {@code null}
     */
    MembershipDO selectMembership(@Param("tenantId") UUID tenantId, @Param("id") UUID id);

    /**
     * 按企业 + 成员 id 读取成员关系并加行级排他锁（SELECT ... FOR UPDATE）。
     *
     * <p>成员写路径以它串行化同一成员的并发修改，并在持锁后读取 revision 做修订比对；
     * 未命中时不持锁，调用方按 404 处理。
     *
     * @param tenantId 企业 UUID，必须等于会话当前企业
     * @param id       成员关系 UUID
     * @return 已持锁的成员行；不存在或不可见时返回 {@code null}
     */
    MembershipDO lockMembership(@Param("tenantId") UUID tenantId, @Param("id") UUID id);

    /**
     * 统计某账号在指定企业内已有的成员关系数，用于插入前的显式查重。
     *
     * <p>与 {@code (tenant_id, user_id)} 唯一键构成“先友好提示、后数据库兜底”两道防线，
     * 二者之间仍存在并发窗口，最终一致性由唯一键保证。
     *
     * @param tenantId 企业 UUID
     * @param userId   待关联账号 UUID
     * @return 命中行数；0 表示尚非本企业成员（count 聚合不会返回 {@code null}）
     */
    int countMembership(@Param("tenantId") UUID tenantId, @Param("userId") UUID userId);

    /**
     * 按登录账号精确查找 workforce 域的账号 id，用于“禁止同名合并”的查重。
     *
     * <p>iam.users 的 RLS 要求平台上下文才能看到他人行，调用方须先切平台上下文，
     * 否则恒为空列表而漏判重名。realm 固定 {@code workforce}，不含服务主体账号。
     *
     * @param account 登录账号，精确匹配（非模糊）
     * @return 命中的账号 id；(realm, account) 唯一，故至多 1 个；无匹配时为空列表
     */
    List<UUID> findUserIds(@Param("account") String account);

    /**
     * 插入成员关系，status 取表默认 active，revision 取表默认 1。
     *
     * <p>企业写 RLS 要求 {@code tenant_id} 等于上下文企业（平台上下文亦可）。
     * 同一企业内账号至多一条关系，重复以 23505 抛出（调用方识别后回 409）；
     * 部门挂靠由 {@code (tenant_id, department_id)} 复合外键校验，跨租户部门直接报错。
     *
     * @param tenantId      企业 UUID
     * @param userId        账号 UUID（须已存在；本服务不允许隐式建档）
     * @param departmentId  挂靠部门 UUID；{@code null} 表示不挂靠
     * @param actorId       操作者 UUID，入 created_by 审计列
     * @return 数据库生成的新成员关系 id
     */
    UUID insertMembership(
            @Param("tenantId") UUID tenantId,
            @Param("userId") UUID userId,
            @Param("departmentId") UUID departmentId,
            @Param("actorId") UUID actorId);

    /**
     * 授予成员单个企业角色并记录授权人。
     *
     * <p>插入成功后触发器把该成员的 revision +1（旧权限快照立即失效）；
     * guard_role_assignment_boundary 以 23514 拒绝平台角色或他企业角色，
     * 这两个域约束不依赖调用方校验。
     *
     * @param tenantId     企业 UUID，与 membershipId 共同构成复合外键
     * @param membershipId 成员关系 UUID
     * @param roleId       角色 UUID（须为活跃的企业域角色：内置全局模板或本租户自定义）
     * @param actorId      授权人 UUID，入 granted_by 审计列
     * @return 插入行数（恒为 1；主键重复或边界违例会抛异常）
     */
    int insertMemberRole(
            @Param("tenantId") UUID tenantId,
            @Param("membershipId") UUID membershipId,
            @Param("roleId") UUID roleId,
            @Param("actorId") UUID actorId);

    /**
     * 删除成员当前全部角色关联（配合 {@link #insertMemberRole} 实现全量替换）。
     *
     * <p>逐行触发最后管理员保护：若删除会使企业失去最后一名有效 tenant_admin，
     * 以 23514 抛出（调用方翻译为 409）；同时每删一行都把成员 revision +1。
     *
     * @param tenantId     企业 UUID
     * @param membershipId 成员关系 UUID
     * @return 删除的关联行数（成员原本无角色时为 0）
     */
    int deleteMemberRoles(@Param("tenantId") UUID tenantId, @Param("membershipId") UUID membershipId);

    /**
     * 更新成员的企业内归属：部门为全量赋值，状态为 COALESCE 局部更新。
     *
     * <p>语义不对称是有意的——{@code departmentId} 传 {@code null} 会把成员从部门中摘出，
     * 调用方若只想改状态必须回传当前部门；{@code status} 传 {@code null} 则保持原值。
     * 部门或状态实际变化时触发器把 revision +1；停用最后一名有效 tenant_admin
     * 会由 guard_last_admin 以 23514 拒绝。
     *
     * @param tenantId      企业 UUID，与成员 id 共同限定更新范围
     * @param membershipId  成员关系 UUID
     * @param departmentId  新挂靠部门 UUID；{@code null} 表示清空挂靠（不是“保持不变”）
     * @param status        新状态；{@code null} 保持原值；调用方须先行校验仅取 active/disabled
     * @return 受影响行数；0 表示成员不存在、不属于该企业或不可见
     */
    int updateMembership(
            @Param("tenantId") UUID tenantId,
            @Param("membershipId") UUID membershipId,
            @Param("departmentId") UUID departmentId,
            @Param("status") String status);

    /**
     * 删除成员关系（企业内移除成员，不删除账号本身）。
     *
     * <p>该成员的角色关联经 {@code (tenant_id, membership_id)} 复合外键 ON DELETE CASCADE 一并清除；
     * 若被删者是企业最后一名有效 tenant_admin，guard_last_admin 以 23514 拒绝（调用方回 409）。
     *
     * @param tenantId     企业 UUID，与成员 id 共同限定删除范围
     * @param membershipId 成员关系 UUID
     * @return 受影响行数；0 表示成员不存在或不属于当前企业（调用方据此回 404）
     */
    int deleteMembership(@Param("tenantId") UUID tenantId, @Param("membershipId") UUID membershipId);

    // ------------------------------------------------------------ 部门

    /**
     * keyset 分页：按 id 升序取指定企业的至多 {@code fetchSize} 个部门。
     *
     * <p>SQL 显式按 tenant_id 过滤，叠加收紧后的部门 RLS，企业间组织树互不可见。
     * 服务层以 fetchSize = limit+1 探测下一页。
     *
     * @param tenantId  企业 UUID，取会话当前企业
     * @param afterId   游标 id，仅返回 id 大于它的行；{@code null} 从头开始
     * @param fetchSize 实际取行数上限（含多取的一条探测行）
     * @return 按 id 升序的部门列表（扁平结果，层级由 parent_id 在调用方还原）；无部门时为空列表
     */
    List<DepartmentDO> selectDepartments(
            @Param("tenantId") UUID tenantId,
            @Param("afterId") UUID afterId,
            @Param("fetchSize") int fetchSize);

    /**
     * 按主键读取部门（无行锁，SQL 不带企业过滤）。
     *
     * <p>租户边界由 RLS 与调用方双重保证：服务层在校验上级部门时会显式比对返回行的
     * {@code tenantId}，不等即按 400 拒绝，不能只依赖本方法“查得到就等于同企业”。
     *
     * @param id 部门 UUID
     * @return 部门行；不存在或当前上下文不可见时返回 {@code null}
     */
    DepartmentDO selectDepartment(@Param("id") UUID id);

    /**
     * 插入部门，status 取表默认 active。
     *
     * <p>部门写 RLS 要求 {@code tenant_id} 等于上下文企业（平台上下文亦可）；
     * 同企业内 code 唯一，重复以 23505 抛出（调用方翻译为 409）；
     * 跨租户挂父由复合外键拒绝，层级成环由 reject_department_cycle 触发器以 23514 拒绝。
     *
     * @param tenantId 企业 UUID
     * @param parentId 上级部门 UUID；{@code null} 表示建为顶级部门
     * @param code     部门编码（1..64 位字母数字/_/-，调用方已校验）
     * @param name     部门显示名
     * @return 数据库生成的新部门 id
     */
    UUID insertDepartment(
            @Param("tenantId") UUID tenantId,
            @Param("parentId") UUID parentId,
            @Param("code") String code,
            @Param("name") String name);

    /**
     * 局部更新部门：名称与状态走 COALESCE，上级按开关位决定是否替换。
     *
     * <p>{@code replaceParent} 为 {@code false} 时 {@code parentId} 被忽略——因此
     * 本方法无法把部门降级为顶级节点，置空上级需要数据订正。部门表没有修订列，
     * 并发守卫由调用方使用会话上下文版本完成。成环由触发器以 23514 拒绝（调用方翻译为 409）；
     * 跨租户挂父由复合外键以 23503 拒绝，服务层已先行按企业比对故理论不可达，
     * 且该状态不在错误翻译器的 4xx 映射内。
     *
     * @param tenantId      企业 UUID，与部门 id 共同限定更新范围
     * @param id            部门 UUID
     * @param name          新显示名；{@code null} 保持原值
     * @param replaceParent 是否替换上级；{@code false} 时保持原上级
     * @param parentId      新上级部门 UUID；仅在 replaceParent 为 {@code true} 时生效
     * @param status        新状态；{@code null} 保持原值；调用方须先行校验仅取 active/disabled
     * @return 受影响行数；0 表示部门不存在、不属于该企业或不可见（调用方据此回 404）
     */
    int updateDepartment(
            @Param("tenantId") UUID tenantId,
            @Param("id") UUID id,
            @Param("name") String name,
            @Param("replaceParent") boolean replaceParent,
            @Param("parentId") UUID parentId,
            @Param("status") String status);

    /**
     * 按码解析可授予成员的企业角色 id。
     *
     * <p>过滤条件为 {@code scope='tenant'} 且 {@code status='active'} 且
     * 企业为空（内置全局模板）或等于入参企业；平台角色、他企业角色与停用角色一律不返回。
     * 命中数少于 codes 数量即表示存在未知、停用、平台专属或他企业角色。
     *
     * @param tenantId 企业 UUID，取会话当前企业
     * @param codes    角色码列表，必须非空（空列表会生成非法的 IN 空集合）；调用方已消毒去重
     * @return 命中的角色 id；{@code (tenant_id, code)} 唯一，故与 codes 一一对应
     */
    List<UUID> selectTenantRoleIds(@Param("tenantId") UUID tenantId, @Param("codes") List<String> codes);

    // ------------------------------------------------ 成员视图装配与角色码回读

    /**
     * 经 SECURITY DEFINER 函数 {@code iam_auth.member_user_brief} 按成员关系读取账号摘要。
     *
     * <p>存在理由：成员停用后 iam.users 的“同企业活跃成员”可见分支失效，纯企业上下文直读
     * 会取不到行，管理端便无法展示停用成员。函数只用于越过行可见性，
     * 授权仍由服务层（成员必须属于会话当前企业）与成员表 RLS 把关；
     * 返回列不含 {@code password_hash}，复用 UserMapper 的 resultMap，其中 id 取自 user_id 列。
     *
     * @param membershipId 成员关系 UUID（调用方须已确认其属于当前企业上下文）
     * @return 该成员对应账号的视图；成员不存在或账号行缺失时返回 {@code null}
     */
    UserDO selectMemberUser(@Param("membershipId") UUID membershipId);

    /**
     * 读取成员当前持有的角色码，用于 MemberVO 装配。
     *
     * @param membershipId 成员关系 UUID
     * @return 按 code 升序的角色码列表；成员暂无角色时为空列表，不返回 {@code null}
     */
    List<String> selectMemberRoleCodes(@Param("membershipId") UUID membershipId);
}
